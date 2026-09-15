/*
 * sync.c — terminal state sync engine
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * See sync.h for the model. Implementation notes:
 *
 *  - sync_backlog owns the ring of SYNC_TX_CHUNK slots addressed by absolute
 *    chunk number modulo nchunks (= quota/CHUNK + 1). A slot claims its
 *    chunk number on WRITE only; colliding chunk numbers differ by at least
 *    nchunks, i.e. more than quota bytes, so a reclaimed slot's previous
 *    content is older than even the base-1 persist byte. Merely advancing
 *    base does not reclaim a slot: that acknowledged byte may still be read.
 *
 *  - The rx blockmap holds one received-prefix length (0..64) per 64-byte
 *    block, nblocks = ring_size/64 + 1 because an unaligned `delivered`
 *    makes the live window straddle ring_size/64 + 1 consecutive blocks.
 *    Slots are zeroed eagerly as `delivered` passes them (cleared_below),
 *    which guarantees a block entering the window always starts at 0.
 *
 *  - All timer decisions use the clock injected via sync_tick (now_cache),
 *    so the unit harness fully controls time.
 */
#include "sync.h"
#include "sync_repair_plan.h"
#include "sync_monitor.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "frame.h"
#include "session.h"

/* Channel byte for all sync frames: channel 1, FF=1/MF=0 (never fragmented;
 * every body fits the single-frame plaintext budget). */
#define SYNC_CHAN ((uint8_t)((1U << 4) | CHAN_FF_BIT))

_Static_assert(SYNC_GRID == SYNC_PLAN_GRID, "repair bitmap grid drift");
_Static_assert(SYNC_ACK_BITMAP_MAX == SYNC_PLAN_BITMAP_MAX,
               "repair bitmap capacity drift");
_Static_assert(SYNC_ACK_BITS_MAX == SYNC_PLAN_BITS_MAX,
               "repair bit capacity drift");
_Static_assert(SYNC_DATA_PAYLOAD_MAX == SYNC_PLAN_PAYLOAD_MAX,
               "repair payload capacity drift");
_Static_assert(sizeof(sync_monitor_binding_t) == 80,
               "external sync binding budget drift");

int sync_monitor_bind(struct session *s, sync_monitor_binding_t *binding,
                      sync_source_t *source, sync_work_carriage_t *work,
                      const sync_source_reader_t *reader,
                      sync_monitor_publication_fn publication,
                      const void *publication_context)
{
    const sync_monitor_binding_t empty = {0};
    size_t slots, records, bytes;

    if (!s || !binding || !source || !work || !reader || !publication ||
        !publication_context || !reader->context || !reader->read_unit ||
        !s->is_server || s->services_started || s->sync_monitor ||
        s->sync_tx.active || s->sync_rx.active ||
        memcmp(binding, &empty, sizeof(empty)) != 0 ||
        source->initialized != 1U || source->failed || source->tip != 0 ||
        source->incarnation == 0 || source->direction != 1U ||
        !source->records || !source->workspace || !source->cache_tags ||
        source->pending.append_length != 0 || source->pending.operation != 0 ||
        sync_source_geometry(source->quota, &slots, &records, &bytes) != 0 ||
        records != source->nrecords || reader->nrecords != records ||
        work->control.initialized != 1U || work->control.failure != 0 ||
        work->control.role != SYNC_WORK_MONITOR ||
        work->control.direction != source->direction ||
        work->control.incarnation != source->incarnation ||
        work->control.serial != 0 || work->control.in_step ||
        work->control.probe_used != 0 ||
        work->control.cell[0].state != 0 || work->control.cell[1].state != 0 ||
        work->control.cell[0].operation != 0 ||
        work->control.cell[1].operation != 0)
        return -1;
    binding->session = s;
    binding->source = source;
    binding->work = work;
    binding->reader = *reader;
    binding->publication = publication;
    binding->publication_context = publication_context;
    binding->life = SYNC_MONITOR_PREBOUND;
    s->sync_monitor = binding;
    return 0;
}

static sync_monitor_binding_t *sync_monitor_slot(const session_t *s,
                                                uint8_t slot)
{
    /* A stopped binding must remain distinguishable from an unbound stream:
     * it can never fall back to ordinary backing after sync_free. */
    return s && slot == 1U ? s->sync_monitor : NULL;
}

static int sync_monitor_live(const session_t *s,
                              const sync_monitor_binding_t *binding)
{
    return binding && binding->session == s &&
           binding->life == SYNC_MONITOR_LIVE &&
           !binding->source->failed && !sync_work_failure(binding->work);
}

void sync_monitor_stop(struct session *s)
{
    sync_monitor_binding_t *binding = sync_monitor_slot(s, 1U);

    if (!binding || binding->life == SYNC_MONITOR_STOPPED)
        return;
    binding->life = SYNC_MONITOR_STOPPED;
    binding->fin_deferred = 0;
    binding->fin_have_code = 0;
    binding->fin_code = 0;
    if (binding->plan_operation != 0) {
        /* Terminal stop cannot recursively turn a cancellation error into
         * another close. The external owner still retains exact drainage. */
        (void)sync_work_cancel_plan(binding->work, binding->plan_operation);
        binding->plan_operation = 0;
    }
    if (binding->source->initialized == 1U && !binding->source->failed)
        (void)sync_source_abandon(binding->source);
}

static int sync_slot_valid(uint8_t slot)
{
    return slot > 0U && slot < CHANNEL_SESSION_SLOTS;
}

static sync_tx_t *sync_tx_slot(session_t *s, uint8_t slot)
{
    if (!s || !sync_slot_valid(slot))
        return NULL;
    return slot == 1U ? &s->sync_tx : &s->sync_tx_instances[slot];
}

static const sync_tx_t *sync_tx_slot_const(const session_t *s, uint8_t slot)
{
    if (!s || !sync_slot_valid(slot))
        return NULL;
    return slot == 1U ? &s->sync_tx : &s->sync_tx_instances[slot];
}

static sync_rx_t *sync_rx_slot(session_t *s, uint8_t slot)
{
    if (!s || !sync_slot_valid(slot))
        return NULL;
    return slot == 1U ? &s->sync_rx : &s->sync_rx_instances[slot];
}

static const sync_rx_t *sync_rx_slot_const(const session_t *s, uint8_t slot)
{
    if (!s || !sync_slot_valid(slot))
        return NULL;
    return slot == 1U ? &s->sync_rx : &s->sync_rx_instances[slot];
}

static sync_instance_binding_t *sync_binding_slot(session_t *s,
                                                  uint8_t slot)
{
    if (!s || !sync_slot_valid(slot))
        return NULL;
    return &s->sync_binding[slot];
}

static const sync_instance_binding_t *sync_binding_slot_const(
    const session_t *s, uint8_t slot)
{
    if (!s || !sync_slot_valid(slot))
        return NULL;
    return &s->sync_binding[slot];
}

/* -------------------------------------------------------------------------
 * Small helpers
 * ---------------------------------------------------------------------- */

static int64_t mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static uint64_t align64_up(uint64_t v)
{
    return (v + (SYNC_GRID - 1)) & ~(uint64_t)(SYNC_GRID - 1);
}

static uint16_t load16le(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t load32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t load64le(const uint8_t *p)
{
    return (uint64_t)load32le(p) | ((uint64_t)load32le(p + 4) << 32);
}

static void store16le(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)(v >> 8);
}

static void store32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)((v >> 8) & 0xff);
    p[2] = (uint8_t)((v >> 16) & 0xff);
    p[3] = (uint8_t)((v >> 24) & 0xff);
}

static void store64le(uint8_t *p, uint64_t v)
{
    store32le(p, (uint32_t)(v & 0xffffffffu));
    store32le(p + 4, (uint32_t)(v >> 32));
}

/* Largest DATA payload for the session's plaintext budget. */
static size_t sync_payload_max(const session_t *s)
{
    size_t envelope = session_channelised_active(s)
        ? CHANNEL_SESSION_HANDLE_BYTES : 0U;
    size_t overhead = SYNC_DATA_OVERHEAD + envelope;
    size_t m = s->current_mtu > overhead
             ? (size_t)(s->current_mtu - overhead) : 1;
    return m < SYNC_DATA_PAYLOAD_MAX ? m : SYNC_DATA_PAYLOAD_MAX;
}

static void sync_fatal(session_t *s, const char *msg)
{
    if (s->sync_monitor)
        s->sync_monitor->in_service = 0;
    fprintf(stderr, "unmoor sync: FATAL: %s — closing session\n", msg);
    s->run_failed = 1;
    session_close(s);
}

int sync_monitor_plan_barrier(struct session *s)
{
    sync_monitor_binding_t *binding = sync_monitor_slot(s, 1U);
    uint64_t operation;

    if (!binding || binding->plan_operation == 0)
        return 0;
    operation = binding->plan_operation;
    binding->plan_operation = 0;
    if (sync_work_cancel_plan(binding->work, operation) != SYNC_WORK_OK) {
        sync_fatal(s, "local repair-plan cancellation failed");
        return -1;
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * TX backlog chunk ring
 * ---------------------------------------------------------------------- */

/* ACK authority stays here: storage supplies only a synchronously borrowed
 * span. Preserve the original per-chunk absorption boundaries. */
static int tx_absorb_range_into(const sync_tx_t *tx,
                                sync_monitor_binding_t *binding,
                                crypto_sync_chain_t *chain,
                                uint64_t from, uint64_t to)
{
    if (binding) {
        if (binding->life != SYNC_MONITOR_LIVE || to < from)
            return -1;
        return sync_source_chain_absorb_with_reader(
            binding->source, &binding->reader, tx->base, from,
            (size_t)(to - from), chain);
    }
    while (from < to) {
        const uint8_t *data;
        size_t n;
        if (sync_backlog_span(&tx->backlog, from, (size_t)(to - from),
                              &data, &n) != 0)
            return -1;
        crypto_sync_chain_absorb(chain, data, n);
        from += n;
    }
    return 0;
}

static int tx_absorb_range(sync_tx_t *tx, sync_monitor_binding_t *binding,
                           uint64_t from, uint64_t to)
{
    return tx_absorb_range_into(tx, binding, &tx->chain, from, to);
}

/* -------------------------------------------------------------------------
 * TX frame emission
 * ---------------------------------------------------------------------- */

/* Build a trusted view without publishing normalization. Asynchronous PLAN
 * issuance commits cursor/pass only after the actual carriage accepts it.
 * A completed result rebuilds the current view without starting another pass. */
static int tx_repair_view(const session_t *s, const sync_tx_t *tx,
                          int64_t now, int normalize,
                          sync_repair_view_t *view, int64_t *pass_out)
{
    uint64_t map_base, map_end;
    uint64_t limit = tx->tip;
    uint64_t cursor = tx->repair_cursor;
    int64_t pass = tx->repair_pass_ms;

    if (!tx->repair_plan_valid || tx->repair_attempts_left == 0 ||
        tx->recovery_send_pending || tx->fin_send_pending)
        return 0;
    if (sync_repair_plan_extent(tx->repair_frontier, tx->repair_bits,
                                &map_base, &map_end) != 0)
        return -1;
    if (tx->peer_credit < limit)
        limit = tx->peer_credit;
    if (tx->sent < limit)
        limit = tx->sent;
    if (normalize && (cursor >= map_end || cursor >= limit)) {
        if (now < pass + tx->rto_ms)
            return 0;
        cursor = tx->repair_frontier;
        pass = now;
    }
    if (cursor < tx->repair_frontier)
        cursor = tx->repair_frontier;
    memset(view, 0, sizeof(*view));
    view->frontier = tx->repair_frontier;
    view->cursor = cursor;
    view->limit = limit;
    view->bits = tx->repair_bits;
    view->payload_max = (uint16_t)sync_payload_max(s);
    memcpy(view->bitmap, tx->repair_bitmap, ((size_t)view->bits + 7U) / 8U);
    if (pass_out)
        *pass_out = pass;
    return 1;
}

/* Admit stream bytes [off, off+len). Send-scheduler advances every transport-owned
 * cursor only from sync_send_result() after an actual terminal result.
 * Bound REPAIR borrows its caller's existing view/result for the post-read
 * check, not an additional retained snapshot or duplicate selector. */
static int send_sync_data_range(session_t *s, uint8_t slot, sync_tx_t *tx,
                                uint64_t off, size_t len,
                                uint8_t recovery_kind,
                                sync_repair_view_t *current_view,
                                const sync_repair_result_t *repair_result)
{
    uint8_t body[SYNC_DATA_OVERHEAD + SYNC_DATA_PAYLOAD_MAX];
    sync_monitor_binding_t *binding = sync_monitor_slot(s, slot);
    session_tx_done_t done;
    uint64_t arg0;
    uint64_t arg1;
    int rc;

    if (binding) {
        if (!sync_monitor_live(s, binding) ||
            !session_application_send_eligible(s))
            return 1;
        if (len == 0 || len > sync_payload_max(s) || off > UINT64_MAX - len ||
            sync_source_load_with_reader(binding->source, &binding->reader,
                tx->base, off, body + SYNC_DATA_OVERHEAD, len) != 0) {
            crypto_memzero(body, sizeof(body));
            sync_fatal(s, "retained source readback failed");
            return -1;
        }
        /* Trusted readback is synchronous. Keep its authority boundary
         * explicit even if a future reader adds local work before return. */
        if (!sync_monitor_live(s, binding) ||
            !session_application_send_eligible(s)) {
            crypto_memzero(body, sizeof(body));
            return 1;
        }
        if (recovery_kind == SYNC_RECOVERY_REPAIR &&
            (!current_view || !repair_result || off < tx->base ||
             tx_repair_view(s, tx, tx->now_cache, 0, current_view, NULL) != 1 ||
             sync_repair_plan_check(current_view, repair_result) != 0)) {
            crypto_memzero(body, sizeof(body));
            return 1;
        }
    }

    if (recovery_kind == SYNC_RECOVERY_NONE) {
        if (tx->new_send_pending)
            return 1;
        done = SESSION_TX_DONE_SYNC_NEW;
        arg0 = off + len;
        arg1 = 0;
        tx->new_send_pending = 1;
        tx->new_pending_end = arg0;
    } else {
        if (tx->recovery_send_pending || tx->fin_send_pending)
            return 1;
        done = recovery_kind == SYNC_RECOVERY_REPAIR
             ? SESSION_TX_DONE_SYNC_REPAIR
             : SESSION_TX_DONE_SYNC_PROBE;
        arg0 = recovery_kind == SYNC_RECOVERY_REPAIR
             ? tx->repair_generation : off + len;
        arg1 = recovery_kind == SYNC_RECOVERY_REPAIR
             ? off + len : 0;
        tx->recovery_send_pending = 1;
        tx->recovery_pending_kind = recovery_kind;
        tx->recovery_pending_generation = arg0;
        tx->recovery_pending_end = off + len;
    }

    body[0] = 1;
    body[1] = 0;
    body[2] = 0;
    body[3] = 0;
    store64le(body + 4, off);
    if (!binding && sync_backlog_load(&tx->backlog, off,
                                      body + SYNC_DATA_OVERHEAD, len) < 0) {
        if (recovery_kind == SYNC_RECOVERY_NONE)
            tx->new_send_pending = 0;
        else
            tx->recovery_send_pending = 0;
        sync_fatal(s, "tx backlog slot invariant violated");
        return -1;
    }
    rc = session_send_lane_tracked_instance(
        s, slot, recovery_kind == SYNC_RECOVERY_NONE
               ? SEND_LANE_NEW : SEND_LANE_RECOVERY,
        SYNC_CHAN, PTY_SYNC_DATA, body, SYNC_DATA_OVERHEAD + len,
        done, arg0, arg1);
    if (binding)
        crypto_memzero(body, sizeof(body));
    if (rc != 0) {
        /* An immediate fake-wire FAILED already issued the callback. Only
         * roll back an admission that never acquired a terminal owner. */
        if (recovery_kind == SYNC_RECOVERY_NONE) {
            if (tx->new_send_pending)
                tx->new_send_pending = 0;
        } else if (tx->recovery_send_pending) {
            tx->recovery_send_pending = 0;
            tx->recovery_pending_kind = SYNC_RECOVERY_NONE;
        }
        return -1;
    }
    return 0;
}

static int send_sync_fin(session_t *s, uint8_t slot, sync_tx_t *tx,
                         int probe_attempt)
{
    uint8_t body[SYNC_DATA_OVERHEAD + 4];
    size_t len = SYNC_DATA_OVERHEAD;
    int rc;

    if (tx->fin_send_pending || tx->recovery_send_pending)
        return 1;

    body[0] = 1;
    body[1] = SYNC_DATA_FIN;
    body[2] = 0;
    body[3] = 0;
    store64le(body + 4, tx->fin_offset);
    if (tx->have_code) {
        store32le(body + SYNC_DATA_OVERHEAD, (uint32_t)tx->code);
        len += 4;
    }
    tx->fin_send_pending = 1;
    tx->fin_pending_generation = tx->fin_generation;
    rc = session_send_lane_tracked_instance(
        s, slot, SEND_LANE_RECOVERY, SYNC_CHAN,
        PTY_SYNC_DATA, body, len, SESSION_TX_DONE_SYNC_FIN,
        ((uint64_t)tx->fin_generation << 1) |
            (probe_attempt ? 1U : 0U), tx->fin_offset);
    if (rc != 0 && tx->fin_send_pending) {
        tx->fin_send_pending = 0;
        tx->fin_pending_generation = 0U;
    }
    return rc;
}

/* Push fresh bytes up to min(tip, peer_credit). Uncharged: the pacer billed
 * these bytes when they were read from the source. */
static int tx_pump(session_t *s, uint8_t slot, sync_tx_t *tx)
{
    size_t pmax = sync_payload_max(s);
    uint64_t limit = tx->tip < tx->peer_credit ? tx->tip : tx->peer_credit;

    size_t len;

    if (tx->new_send_pending || tx->sent >= limit)
        return 0;
    len = (size_t)(limit - tx->sent);
    if (len > pmax)
        len = pmax;
    {
        int rc = send_sync_data_range(s, slot, tx, tx->sent, len,
                                      SYNC_RECOVERY_NONE, NULL, NULL);
        return rc == 0 ? 1 : (rc < 0 ? -1 : 0);
    }
}

/* Repair from a peer bitmap, lowest-missing-first, at most SYNC_ACK_FRAMES
 * frames per ack. The byte cursor persists across acks; a full pass
 * restarts at the frontier — covering the sub-block tail the bitmap cannot
 * express — at most once per current RTO. */
static int tx_repair_try(session_t *s, uint8_t slot, sync_tx_t *tx,
                         int64_t now)
{
    sync_monitor_binding_t *binding = sync_monitor_slot(s, slot);
    uint64_t map_base, map_end;
    sync_repair_view_t view = {0};
    sync_repair_result_t result;
    int64_t pass;
    int rc;

    if (binding && (!sync_monitor_live(s, binding) ||
                    !session_application_send_eligible(s)))
        return 0;
    rc = tx_repair_view(s, tx, now,
                        !binding || binding->plan_operation == 0, &view, &pass);
    if (rc == 0)
        return 0;
    if (rc < 0) {
        sync_fatal(s, "invalid repair planning geometry");
        return -1;
    }

    if (binding) {
        sync_repair_view_t issued;
        if (binding->plan_operation == 0) {
            uint64_t operation;
            rc = sync_work_begin_plan(binding->work, &view, &operation);
            if (rc == SYNC_WORK_BUSY)
                return 0;
            if (rc != SYNC_WORK_OK) {
                sync_fatal(s, "local repair-plan issuance failed");
                return -1;
            }
            binding->plan_operation = operation;
            tx->repair_cursor = view.cursor;
            tx->repair_pass_ms = pass;
            /* The cell is not a send-scheduler owner: another recovery producer may
             * use this turn while W computes or withholds its answer. */
            return 0;
        }
        rc = sync_work_take_planned(binding->work, binding->plan_operation,
                                     &issued, &result);
        if (rc == SYNC_WORK_NOT_READY)
            return 0;
        binding->plan_operation = 0;
        if (rc != SYNC_WORK_OK) {
            sync_fatal(s, "local repair-plan result failed");
            return -1;
        }
        if (result.kind == SYNC_PLAN_NONE)
            return 0;
        if (result.kind == SYNC_PLAN_EXHAUSTED) {
            if (issued.frontier != view.frontier || issued.cursor != view.cursor ||
                issued.limit != view.limit || issued.bits != view.bits ||
                issued.payload_max != view.payload_max ||
                memcmp(issued.bitmap, view.bitmap, sizeof(view.bitmap)) != 0)
                return 0;
        } else if (result.offset < tx->base ||
                   sync_repair_plan_check(&view, &result) != 0) {
            return 0; /* stale RANGE: no trimming, selector or completion */
        }
    } else {
        tx->repair_cursor = view.cursor;
        tx->repair_pass_ms = pass;
        if (sync_repair_plan_choose(&view, &result) != 0 ||
            sync_repair_plan_check(&view, &result) != 0) {
            sync_fatal(s, "invalid repair planning result");
            return -1;
        }
    }
    if (result.kind == SYNC_PLAN_EXHAUSTED) {
        if (sync_repair_plan_extent(view.frontier, view.bits,
                                    &map_base, &map_end) != 0) {
            sync_fatal(s, "invalid exhausted repair geometry");
            return -1;
        }
        tx->repair_cursor = map_end; /* scan hint only, never completion */
        return 0;
    }
    if (result.kind == SYNC_PLAN_NONE)
        return 0;
    {
        int rc = send_sync_data_range(s, slot, tx, result.offset,
                                      result.length, SYNC_RECOVERY_REPAIR,
                                      binding ? &view : NULL,
                                      binding ? &result : NULL);
        return rc == 0 ? 1 : (rc < 0 ? -1 : 0);
    }
}

/* -------------------------------------------------------------------------
 * RX ring
 * ---------------------------------------------------------------------- */

static void rx_clear_blocks(sync_rx_t *rx, uint64_t upto)
{
    while ((rx->cleared_below + 1) * SYNC_GRID <= upto) {
        rx->blockmap[rx->cleared_below % rx->nblocks] = 0;
        rx->cleared_below++;
    }
}

static void rx_bump_generation(sync_rx_t *rx)
{
    rx->ack_generation++;
    if (rx->ack_generation == 0)
        rx->ack_generation = 1;
}

static void rx_count_frame(sync_rx_t *rx, int64_t now)
{
    rx_bump_generation(rx);
    rx->frames_since_ack++;
    if (rx->ack_first_pending_ms == 0)
        rx->ack_first_pending_ms = now != 0 ? now : 1;
    if (rx->frames_since_ack >= SYNC_ACK_FRAMES)
        rx->ack_due = 1;
}

static void rx_force_ack(sync_rx_t *rx)
{
    rx_bump_generation(rx);
    rx->ack_due = 1;
}

/* Server receives the codeless client->server end-of-input marker. Client
 * receives the server->client stream end, whose exit status is mandatory.
 * Keeping FIN_SEEN clear until that code arrives makes the grammar's legal
 * codeless-then-coded upgrade reliable without adding another wire bit. */
static int rx_fin_ackable(const session_t *s, const sync_rx_t *rx)
{
    return rx->fin_seen && rx->frontier == rx->fin_offset &&
           rx->delivered == rx->fin_offset && rx->fin_delivered &&
           (s->is_server || rx->have_code);
}

uint32_t sync_channel_sink_error_code(int sink_errno)
{
    return sink_errno == EPROTO ? CHANNEL_CODE_PROTOCOL
                                : CHANNEL_CODE_RESOURCE;
}

int sync_ack_snapshot_instance(session_t *s, uint8_t slot,
                               uint8_t *body, size_t body_cap,
                               size_t *body_len, uint64_t *generation_out,
                               uint64_t *credit_out)
{
    sync_rx_t *rx;
    uint64_t credit;
    uint64_t map_base;
    uint32_t bits = 0;
    uint8_t flags = 0;
    size_t bmlen;
    uint32_t i;
    size_t total_len;

    if (!s || !body || !body_len || !generation_out || !credit_out)
        return -1;
    rx = sync_rx_slot(s, slot);
    if (rx == NULL || !rx->active)
        return -1;
    credit = rx->delivered + rx->ring_size;
    map_base = align64_up(rx->frontier);

    if (credit > rx->last_advertised_credit)
        flags |= SYNC_ACK_CREDIT;
    if (rx->sink_blocked)
        flags |= SYNC_ACK_SINK_BLOCKED;
    if (rx_fin_ackable(s, rx))
        flags |= SYNC_ACK_FIN_SEEN;

    if (rx->highest > map_base) {
        uint64_t nb = (rx->highest - map_base + SYNC_GRID - 1) / SYNC_GRID;
        bits = nb > SYNC_ACK_BITS_MAX ? SYNC_ACK_BITS_MAX : (uint32_t)nb;
    }
    if (body_cap < SYNC_ACK_OVERHEAD)
        return -1;
    if ((size_t)bits > (body_cap - SYNC_ACK_OVERHEAD) * 8U)
        bits = (uint32_t)((body_cap - SYNC_ACK_OVERHEAD) * 8U);
    bmlen = ((size_t)bits + 7) / 8;
    total_len = SYNC_ACK_OVERHEAD + bmlen;
    if (total_len > body_cap)
        return -1;

    body[0] = 1;
    body[1] = flags;
    store16le(body + 2, (uint16_t)bits);
    store64le(body + 4, rx->frontier);
    store64le(body + 12, credit);
    crypto_sync_chain_value(&rx->chain, body + 20);
    memset(body + SYNC_ACK_OVERHEAD, 0, bmlen);
    for (i = 0; i < bits; i++) {
        uint64_t block = map_base / SYNC_GRID + i;
        if (rx->blockmap[block % rx->nblocks] == SYNC_GRID)
            body[SYNC_ACK_OVERHEAD + (i >> 3)] |= (uint8_t)(1U << (i & 7));
    }

    *body_len = total_len;
    *generation_out = rx->ack_generation;
    *credit_out = credit;
    rx->ack_pending_generation = *generation_out;
    rx->ack_pending_credit = credit;
    return 0;
}

int sync_ack_snapshot(session_t *s, uint8_t *body, size_t body_cap,
                      size_t *body_len, uint64_t *generation_out,
                      uint64_t *credit_out)
{
    return sync_ack_snapshot_instance(s, 1U, body, body_cap, body_len,
                                      generation_out, credit_out);
}

static int rx_send_ack(session_t *s, uint8_t slot, sync_rx_t *rx,
                       int64_t now)
{
    uint64_t generation;
    uint64_t credit;
    int rc;

    if (rx->ack_send_pending)
        return 1;

    /* Admit only the bounded logical due state. wire_encode_slot() calls
     * sync_ack_snapshot() after the FEEDBACK grant, so frontier, bitmap,
     * chain, flags and credit cannot go stale while waiting behind another
     * retained frame or scheduler debt. */
    generation = rx->ack_generation;
    credit = rx->delivered + rx->ring_size;
    rx->ack_send_pending = 1;
    rx->ack_pending_generation = generation;
    rx->ack_pending_credit = credit;
    rc = session_send_lane_tracked_instance(
        s, slot, SEND_LANE_FEEDBACK, SYNC_CHAN,
        PTY_SYNC_ACK, NULL, 0, SESSION_TX_DONE_SYNC_ACK,
        generation, credit);
    if (rc != 0 && rx->ack_send_pending) {
        /* Admission refusal has no callback. A synchronous fake transport
         * failure does, and has already cleared the flag/set the floor. */
        rx->ack_send_pending = 0;
        rx->ack_retry_ms = now + SYNC_ACK_DELAY_MS;
    }
    return rc;
}

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

int sync_active_instance(const struct session *s, uint8_t slot)
{
    const sync_tx_t *tx = sync_tx_slot_const(s, slot);

    return tx != NULL && tx->active;
}

int sync_active(const struct session *s)
{
    return sync_active_instance(s, 1U);
}

size_t sync_tx_room_instance(const struct session *s, uint8_t slot)
{
    const sync_tx_t *tx = sync_tx_slot_const(s, slot);
    sync_monitor_binding_t *binding = sync_monitor_slot(s, slot);
    uint64_t used;

    if (tx == NULL || !tx->active)
        return 0;
    if (slot == 1U && session_classic_pty_source_ended(s))
        return 0;
    if (binding) {
        uint64_t room;
        if (!sync_monitor_live(s, binding) || binding->fin_deferred ||
            tx->fin_pending ||
            sync_source_available(binding->source, tx->base, &room) != 0)
            return 0;
        return (size_t)room;
    }
    used = tx->tip - tx->base;
    return used >= tx->quota ? 0 : (size_t)(tx->quota - used);
}

size_t sync_tx_room(const struct session *s)
{
    return sync_tx_room_instance(s, 1U);
}

size_t sync_tx_read_limit_instance(const struct session *s, uint8_t slot)
{
    size_t room = sync_tx_room_instance(s, slot);
    size_t pmax;

    if (room == 0)
        return 0;
    pmax = sync_payload_max(s);
    return room < pmax ? room : pmax;
}

size_t sync_tx_read_limit(const struct session *s)
{
    return sync_tx_read_limit_instance(s, 1U);
}

int sync_rx_pending_instance(const struct session *s, uint8_t slot)
{
    const sync_rx_t *rx = sync_rx_slot_const(s, slot);

    return rx != NULL && rx->active && rx->delivered < rx->frontier;
}

int sync_rx_pending(const struct session *s)
{
    return sync_rx_pending_instance(s, 1U);
}

static int tx_source_published(session_t *s, uint8_t slot, sync_tx_t *tx)
{
    /* If the prior stream prefix became fully acknowledged while its last
     * advertised credit stayed exactly at that frontier, a lost credit-open
     * ACK leaves no NEW byte eligible for first transmission.  There is
     * nevertheless one safe already-delivered byte at base-1.  Arm the same
     * bounded persist-probe timer here so appending after an idle interval
     * cannot wedge waiting for an event that the sender otherwise has no way
     * to create. */
    if (!tx->was_outstanding && tx->base > 0U && tx->tip > tx->base &&
        tx->peer_credit <= tx->base) {
        if (tx->rto_ms < SYNC_RTO_MIN_MS)
            tx->rto_ms = SYNC_RTO_MIN_MS;
        tx->was_outstanding = 1;
        tx->next_probe_ms = tx->now_cache + tx->rto_ms;
    }
    if (!session_channelised_active(s) &&
        (!sync_monitor_slot(s, slot) || session_application_send_eligible(s)))
        (void)tx_pump(s, slot, tx);
    /* An ordinary failed datagram still leaves accepted bytes owned and
     * retryable. Failed source verification is different: it has stopped
     * this binding, and the local service must not report healthy success. */
    return sync_monitor_slot(s, slot) &&
           !sync_monitor_live(s, s->sync_monitor) ? -1 : 0;
}

int sync_tx_append_instance(struct session *s, uint8_t slot,
                            const uint8_t *data, size_t len)
{
    sync_tx_t *tx = sync_tx_slot(s, slot);
    sync_monitor_binding_t *binding = sync_monitor_slot(s, slot);

    if (tx && tx->active && len != 0 && slot == 1U &&
        session_classic_pty_source_ended(s)) {
        sync_fatal(s, "source read after terminal end");
        return -1;
    }
    if (binding && len != 0) {
        int rc;
        if (!tx || !tx->active || !sync_monitor_live(s, binding) ||
            !data || len > sync_tx_read_limit_instance(s, slot)) {
            sync_fatal(s, "source read exceeded monitored admission");
            return -1;
        }
        rc = sync_source_prepare(binding->source, tx->base, data, len);
        if (rc == SYNC_SOURCE_PENDING)
            return 0; /* owned original bytes; not yet published or sent */
        if (rc != SYNC_SOURCE_OK) {
            sync_fatal(s, "retained source admission failed");
            return -1;
        }
        tx->tip = sync_source_tip(binding->source);
        return tx_source_published(s, slot, tx);
    }
    if (tx == NULL || !tx->active || len == 0)
        return 0;
    if (len > sync_tx_room_instance(s, slot)) {
        sync_fatal(s, "source read overran backlog quota");
        return -1;
    }
    if (sync_backlog_store(&tx->backlog, tx->tip, data, len) < 0) {
        sync_fatal(s, "backlog chunk allocation failed");
        return -1;
    }
    tx->tip += len;
    (void)tx_source_published(s, slot, tx);
    return 0;
}

int sync_tx_append(struct session *s, const uint8_t *data, size_t len)
{
    return sync_tx_append_instance(s, 1U, data, len);
}

void sync_tx_fin_instance(struct session *s, uint8_t slot,
                          int have_code, int32_t code)
{
    sync_tx_t *tx = sync_tx_slot(s, slot);
    sync_monitor_binding_t *binding = sync_monitor_slot(s, slot);
    int changed = 0;

    if (tx == NULL || !tx->active)
        return;
    if (binding && !sync_monitor_live(s, binding))
        return;
    /* End is accepted before publication can be deferred or FIN state can
     * be cleaned up. Only new source admission closes; pending STORE and
     * already-owned byte/FIN delivery continue through their existing paths. */
    if (slot == 1U)
        session_classic_pty_source_end(s);
    if (binding) {
        if (binding->source->pending.append_length != 0) {
            binding->fin_deferred = 1;
            if (have_code) {
                binding->fin_have_code = 1;
                binding->fin_code = code;
            }
            return;
        }
    }
    if (!tx->fin_pending) {
        tx->fin_pending = 1;
        tx->fin_offset = tx->tip;
        changed = 1;
    }
    if (have_code && (!tx->have_code || tx->code != code)) {
        tx->have_code = 1;
        tx->code = code;
        changed = 1;
    }
    if (changed) {
        tx->fin_generation++;
        if (tx->fin_generation == 0) {
            sync_fatal(s, "FIN operation generation exhausted");
            return;
        }
    }
}

void sync_tx_fin(struct session *s, int have_code, int32_t code)
{
    sync_tx_fin_instance(s, 1U, have_code, code);
}

int sync_monitor_service(struct session *s, const sync_work_io_t *io)
{
    sync_monitor_binding_t *binding = sync_monitor_slot(s, 1U);
    const char *failure = NULL;
    int published = 0;

    if (!s)
        return -1;
    if (!binding)
        return 0;
    if (binding->in_service || binding->life != SYNC_MONITOR_LIVE)
        return -1;
    binding->in_service = 1;
    if (!sync_monitor_live(s, binding)) {
        failure = "local source or carriage already failed";
        goto out;
    }
    if (binding->source->pending.append_length != 0 &&
        binding->source->pending.operation == 0) {
        sync_source_store_t view;
        uint64_t operation;
        int rc;

        if (sync_source_pending_view(binding->source, &view) != 0) {
            failure = "local pending source view failed";
            goto out;
        }
        rc = sync_work_begin_store(binding->work, view.offset, view.unit,
                                    &operation);
        if (rc != SYNC_WORK_BUSY) {
            if (rc != SYNC_WORK_OK ||
                sync_source_bind_once(binding->source, operation) != 0) {
                failure = "local source operation issuance failed";
                goto out; /* no step may expose an unbound request */
            }
        }
    }
    if (sync_work_step(binding->work, io, NULL) != SYNC_WORK_OK) {
        failure = "local source carriage failed";
        goto out;
    }
    if (binding->source->pending.operation != 0) {
        sync_work_header_t header;
        uint8_t status;
        uint64_t publication = 0;
        int rc = sync_work_take_stored(binding->work,
            binding->source->pending.operation, &header, &status);
        if (rc == SYNC_WORK_NOT_READY)
            goto out;
        if (rc != SYNC_WORK_OK) {
            failure = "local stored result failed";
            goto out;
        }
        if (status == 0 && binding->publication(binding->publication_context,
                                                &publication) != 0) {
            failure = "local source publication read failed";
            goto out;
        }
        if (!sync_monitor_live(s, binding) ||
            sync_source_finish(binding->source, &header, status,
                                publication) != SYNC_SOURCE_OK) {
            failure = "local source completion did not match publication";
            goto out;
        }
        published = 1;
    }
out:
    if (failure) {
        binding->in_service = 0;
        sync_fatal(s, failure);
        return -1;
    }
    if (published) {
        s->sync_tx.tip = sync_source_tip(binding->source);
        if (tx_source_published(s, 1U, &s->sync_tx) != 0) {
            binding->in_service = 0;
            return -1;
        }
        if (binding->fin_deferred && sync_monitor_live(s, binding)) {
            int have_code = binding->fin_have_code;
            int32_t code = binding->fin_code;
            binding->fin_deferred = 0;
            binding->fin_have_code = 0;
            binding->fin_code = 0;
            sync_tx_fin(s, have_code, code);
        }
    }
    binding->in_service = 0;
    return sync_monitor_live(s, binding) ? 0 : -1;
}

/* Receive-side grammar/state checks used by the epoch-rekey implicit-proof boundary.
 * They do not log, allocate, advance the session chain, mutate replay/delivery
 * state or invoke a sink. Bound ACK readback may update the separate trusted
 * source cache or sticky failure; staged session authority remains unchanged. */
int sync_prevalidate_data_instance(const struct session *s, uint8_t slot,
                                   const uint8_t *body, size_t len)
{
    const sync_rx_t *rx;
    uint64_t off;
    uint64_t end;
    size_t plen;
    uint8_t flags;

    if (!s || !body)
        return -1;
    rx = sync_rx_slot_const(s, slot);
    if (rx == NULL || !rx->active || len < SYNC_DATA_OVERHEAD || body[0] != 1)
        return -1;
    flags = body[1];
    if ((flags & (uint8_t)~SYNC_DATA_FIN) != 0 ||
        body[2] != 0 || body[3] != 0)
        return -1;
    off = load64le(body + 4);
    if (off > (UINT64_C(1) << 62))
        return -1;
    plen = len - SYNC_DATA_OVERHEAD;
    if ((flags & SYNC_DATA_FIN) != 0) {
        int32_t code = 0;
        if (plen != 0 && plen != 4)
            return -1;
        if (rx->fin_seen && rx->fin_offset != off)
            return -1;
        if (rx->frontier > off || rx->highest > off)
            return -1;
        if (plen == 4) {
            code = (int32_t)load32le(body + SYNC_DATA_OVERHEAD);
            if (rx->have_code && rx->exit_code != code)
                return -1;
        }
        return 0;
    }
    if (plen == 0 || plen > sync_payload_max(s))
        return -1;
    end = off + (uint64_t)plen;
    if (end < off || (rx->fin_seen && end > rx->fin_offset))
        return -1;
    return 0;
}

int sync_prevalidate_data(const struct session *s,
                          const uint8_t *body, size_t len)
{
    return sync_prevalidate_data_instance(s, 1U, body, len);
}

int sync_prevalidate_ack_instance(const struct session *s, uint8_t slot,
                                  const uint8_t *body, size_t len)
{
    const sync_tx_t *tx;
    crypto_sync_chain_t chain;
    uint8_t value[32];
    uint64_t frontier;
    uint64_t map_base;
    uint32_t bits;
    uint8_t flags;
    int rc = -1;

    if (!s || !body)
        return -1;
    tx = sync_tx_slot_const(s, slot);
    if (tx == NULL || !tx->active || len < SYNC_ACK_OVERHEAD || body[0] != 1)
        return -1;
    if (sync_monitor_slot(s, slot) &&
        !sync_monitor_live(s, s->sync_monitor))
        return -1;
    bits = load16le(body + 2);
    if (bits > SYNC_ACK_BITS_MAX ||
        len != SYNC_ACK_OVERHEAD + ((size_t)bits + 7U) / 8U)
        return -1;
    flags = body[1];
    if ((flags & (uint8_t)~(SYNC_ACK_CREDIT | SYNC_ACK_SINK_BLOCKED |
                            SYNC_ACK_FIN_SEEN)) != 0)
        return -1;
    if ((bits & 7U) != 0) {
        uint8_t valid = (uint8_t)((1U << (bits & 7U)) - 1U);
        if ((body[len - 1] & (uint8_t)~valid) != 0)
            return -1;
    }
    frontier = load64le(body + 4);
    if (frontier > tx->tip)
        return -1;
    if (frontier < tx->base)
        return 0;

    map_base = align64_up(frontier);
    for (uint32_t i = 0; i < bits; i++)
        if (((body[SYNC_ACK_OVERHEAD + (i >> 3)] >> (i & 7U)) & 1U) != 0 &&
            map_base + (uint64_t)i * SYNC_GRID >= tx->tip)
            return -1;

    chain = tx->chain;
    if (frontier > tx->base &&
        tx_absorb_range_into(tx, sync_monitor_slot(s, slot), &chain,
                             tx->base, frontier) != 0)
        goto out;
    crypto_sync_chain_value(&chain, value);
    if (memcmp(value, body + 20, sizeof(value)) != 0)
        goto out;
    rc = 0;
out:
    crypto_memzero(value, sizeof(value));
    crypto_memzero(&chain, sizeof(chain));
    return rc;
}

int sync_prevalidate_ack(const struct session *s,
                         const uint8_t *body, size_t len)
{
    return sync_prevalidate_ack_instance(s, 1U, body, len);
}

void sync_handle_data_instance(struct session *s, uint8_t slot,
                               const uint8_t *body, size_t len)
{
    sync_rx_t *rx = sync_rx_slot(s, slot);
    sync_tx_t *tx = sync_tx_slot(s, slot);
    int64_t now;
    uint64_t off, end, win_end;
    const uint8_t *p;
    size_t plen;
    uint8_t flags;

    if (rx == NULL || tx == NULL || !rx->active)
        return;
    now = tx->now_cache;
    if (len < SYNC_DATA_OVERHEAD || body[0] != 1)
        goto malformed;
    flags = body[1];
    if ((flags & (uint8_t)~SYNC_DATA_FIN) != 0 || body[2] != 0 || body[3] != 0)
        goto malformed;
    off = load64le(body + 4);
    if (off > (1ULL << 62))
        goto malformed; /* sanity: no real stream gets near this */
    plen = len - SYNC_DATA_OVERHEAD;

    if (flags & SYNC_DATA_FIN) {
        int32_t code = 0;

        if (plen != 0 && plen != 4)
            goto malformed;
        if (rx->fin_seen && rx->fin_offset != off) {
            sync_fatal(s, "conflicting FIN offset");
            return;
        }
        if (rx->frontier > off || rx->highest > off) {
            sync_fatal(s, "FIN below already-received stream bytes");
            return;
        }
        rx->fin_seen = 1;
        rx->fin_offset = off;
        if (plen == 4) {
            code = (int32_t)load32le(body + SYNC_DATA_OVERHEAD);
            if (rx->have_code && rx->exit_code != code) {
                sync_fatal(s, "conflicting FIN exit status");
                return;
            }
            rx->have_code = 1;
            rx->exit_code = code;
        }
        rx_count_frame(rx, now);
        rx_force_ack(rx);
        sync_rx_deliver_instance(s, slot);
        /* FIN state is reasserted immediately. This is also the final ACK
         * attempt before a completed client stream sets should_exit. */
        if (rx->ack_due && now >= rx->ack_retry_ms)
            (void)rx_send_ack(s, slot, rx, now);
        return;
    }

    if (plen == 0 || plen > sync_payload_max(s))
        goto malformed; /* non-FIN frames carry at least one byte */
    end = off + plen;
    if (rx->fin_seen && end > rx->fin_offset) {
        sync_fatal(s, "stream bytes past FIN offset");
        return;
    }
    if (end <= rx->frontier) {
        rx_count_frame(rx, now); /* full duplicate still counts */
        return;
    }
    p = body + SYNC_DATA_OVERHEAD;
    if (off < rx->frontier) { /* clip below the chain-absorbed frontier */
        p += (size_t)(rx->frontier - off);
        off = rx->frontier;
    }
    win_end = rx->delivered + rx->ring_size;
    if (end > win_end) {
        if (!(rx->log_once & 2U)) {
            rx->log_once |= 2U;
            fprintf(stderr, "unmoor sync: peer exceeded advertised credit — "
                            "excess dropped\n");
        }
        end = win_end;
    }
    if (end > off && end > rx->highest)
        rx->highest = end; /* extent of the known stream, holes included */

    while (off < end) {
        uint64_t bstart = (off / SYNC_GRID) * SYNC_GRID;
        uint64_t bcap = bstart + SYNC_GRID < end ? bstart + SYNC_GRID : end;
        size_t bs = (size_t)(off - bstart);
        size_t be = (size_t)(bcap - bstart);
        size_t slot = (size_t)((off / SYNC_GRID) % rx->nblocks);
        uint8_t prefix = rx->blockmap[slot];

        if (bs <= (size_t)prefix) {
            /* Extends (or overlaps) the block's contiguous prefix. */
            memcpy(rx->ring + (size_t)(bstart % rx->ring_size) + bs, p, be - bs);
            if (be > (size_t)prefix)
                rx->blockmap[slot] = (uint8_t)be;
        }
        /* bs > prefix: mid-block gap — drop; the bitmap repairs it whole. */
        p += be - bs;
        off = bcap;
    }

    for (;;) { /* advance the contiguous frontier through filled prefixes */
        uint64_t bstart = (rx->frontier / SYNC_GRID) * SYNC_GRID;
        size_t slot = (size_t)((rx->frontier / SYNC_GRID) % rx->nblocks);
        size_t inpos = (size_t)(rx->frontier - bstart);
        uint8_t prefix = rx->blockmap[slot];
        size_t n;

        if ((size_t)prefix <= inpos)
            break;
        n = (size_t)prefix - inpos;
        crypto_sync_chain_absorb(&rx->chain,
                                 rx->ring + (size_t)(bstart % rx->ring_size) + inpos,
                                 n);
        rx->frontier += n;
    }

    rx_count_frame(rx, now);
    sync_rx_deliver_instance(s, slot);
    return;

malformed:
    if (!(rx->log_once & 1U)) {
        rx->log_once |= 1U;
        fprintf(stderr, "unmoor sync: malformed sync data frame dropped "
                        "(len=%zu)\n", len);
    }
}

void sync_handle_data(struct session *s, const uint8_t *body, size_t len)
{
    sync_handle_data_instance(s, 1U, body, len);
}

void sync_handle_ack_instance(struct session *s, uint8_t slot,
                              const uint8_t *body, size_t len)
{
    sync_tx_t *tx = sync_tx_slot(s, slot);
    int64_t now;
    uint64_t frontier, credit;
    uint32_t bits;
    uint8_t flags;
    int stale = 0, progress = 0, linger_progress = 0;

    if (tx == NULL || !tx->active)
        return;
    if (sync_monitor_slot(s, slot) &&
        !sync_monitor_live(s, s->sync_monitor)) {
        sync_fatal(s, "ACK reached a failed retained source");
        return;
    }
    now = tx->now_cache;
    if (len < SYNC_ACK_OVERHEAD || body[0] != 1)
        goto malformed;
    bits = load16le(body + 2);
    if (bits > SYNC_ACK_BITS_MAX || len != SYNC_ACK_OVERHEAD + ((size_t)bits + 7) / 8)
        goto malformed;
    flags = body[1];
    if ((flags & (uint8_t)~(SYNC_ACK_CREDIT | SYNC_ACK_SINK_BLOCKED |
                            SYNC_ACK_FIN_SEEN)) != 0)
        goto malformed;
    if ((bits & 7U) != 0) {
        uint8_t valid = (uint8_t)((1U << (bits & 7U)) - 1U);
        if ((body[len - 1] & (uint8_t)~valid) != 0)
            goto malformed;
    }
    frontier = load64le(body + 4);
    credit = load64le(body + 12);

    if (frontier > tx->tip) {
        sync_fatal(s, "peer acked past stream tip");
        return;
    }

    if (frontier < tx->base) {
        /* Reordered stale ack: its chain/bitmap describe a past state;
         * only the monotonic credit may be taken from it. */
        stale = 1;
    } else {
        uint8_t val[32];
        uint64_t map_base = align64_up(frontier);
        uint32_t i;

        /* A full block beginning at or beyond tip claims possession of bytes
         * this sender has never appended. Treat it like frontier-past-tip. */
        for (i = 0; i < bits; i++) {
            if (((body[SYNC_ACK_OVERHEAD + (i >> 3)] >> (i & 7)) & 1U) &&
                map_base + (uint64_t)i * SYNC_GRID >= tx->tip) {
                sync_fatal(s, "peer bitmap acknowledged past stream tip");
                return;
            }
        }

        if (frontier > tx->base &&
            tx_absorb_range(tx, sync_monitor_slot(s, slot),
                             tx->base, frontier) < 0) {
            sync_fatal(s, "tx backlog slot invariant violated");
            return;
        }
        crypto_sync_chain_value(&tx->chain, val);
        if (memcmp(val, body + 20, 32) != 0) {
            /* Absorb-before-compare is safe: divergence is terminal. */
            sync_fatal(s, "stream chain divergence");
            return;
        }
        if (frontier > tx->base) {
            tx->base = frontier;
            tx->repair_cursor = frontier;
            tx->repair_pass_ms = now;
            progress = 1;
        }
        if (flags & SYNC_ACK_FIN_SEEN) {
            if (!tx->fin_seen_observed) {
                tx->fin_seen_observed = 1;
                linger_progress = 1;
            }
            if (tx->fin_pending && frontier == tx->fin_offset)
                tx->fin_acked = 1;
        }
    }

    if (credit > tx->peer_credit) {
        tx->peer_credit = credit;
        progress = 1;
    }
    if (!stale && (flags & SYNC_ACK_SINK_BLOCKED))
        linger_progress = 1; /* peer alive, deliberately blocked */

    if (progress) {
        tx->last_progress_ms = now;
        tx->last_linger_progress_ms = now;
        tx->rto_ms = SYNC_RTO_MIN_MS;
        tx->next_probe_ms = now + tx->rto_ms;
    } else if (linger_progress) {
        tx->last_linger_progress_ms = now;
    }

    if (!stale) {
        size_t bmlen = ((size_t)bits + 7U) / 8U;
        tx->repair_generation++;
        if (tx->repair_generation == 0)
            tx->repair_generation = 1;
        tx->repair_frontier = frontier;
        tx->repair_bits = bits;
        memset(tx->repair_bitmap, 0, sizeof(tx->repair_bitmap));
        if (bmlen != 0)
            memcpy(tx->repair_bitmap, body + SYNC_ACK_OVERHEAD, bmlen);
        tx->repair_plan_valid = bits != 0;
        tx->repair_attempts_left = bits != 0 ? SYNC_ACK_FRAMES : 0;
        if (tx->repair_cursor < frontier)
            tx->repair_cursor = frontier;
    }
    /* Receive dispatch installs absolute work only. The next event-loop
     * turn exposes at most one repair and one NEW record to the arbiter. */
    return;

malformed:
    if (!(tx->log_once & 1U)) {
        tx->log_once |= 1U;
        fprintf(stderr, "unmoor sync: malformed sync ack dropped (len=%zu)\n",
                len);
    }
}

void sync_handle_ack(struct session *s, const uint8_t *body, size_t len)
{
    sync_handle_ack_instance(s, 1U, body, len);
}

void sync_rx_deliver_instance(struct session *s, uint8_t slot)
{
    sync_rx_t *rx = sync_rx_slot(s, slot);
    sync_tx_t *tx = sync_tx_slot(s, slot);
    sync_instance_binding_t *binding = sync_binding_slot(s, slot);
    int fd;

    if (rx == NULL || tx == NULL || binding == NULL || !rx->active)
        return;
    fd = binding->configured ? binding->sink_fd
         : (s->is_server ? s->pty_master_fd : STDOUT_FILENO);

    while (rx->delivered < rx->frontier) {
        size_t rpos, n;
        ssize_t w;

        if (s->is_server && fd < 0 && binding->write_sink == NULL &&
            slot == 1U && !session_channelised_active(s)) {
            /* Shell is gone; input has nowhere to go. Discard so the
             * stream stays verified and acked. */
            rx->delivered = rx->frontier;
            rx_clear_blocks(rx, rx->delivered);
            break;
        }
        rpos = (size_t)(rx->delivered % rx->ring_size);
        n = (size_t)(rx->frontier - rx->delivered);
        if (n > rx->ring_size - rpos)
            n = rx->ring_size - rpos;
        if (binding->write_sink != NULL)
            w = binding->write_sink(binding->sink_context,
                                    rx->ring + rpos, n);
        else if (fd >= 0)
            w = write(fd, rx->ring + rpos, n);
        else {
            errno = EAGAIN;
            w = -1;
        }
        if (w < 0) {
            int sink_errno = errno;

            if (sink_errno == EINTR)
                continue;
            if (sink_errno == EAGAIN || sink_errno == EWOULDBLOCK) {
                if (!rx->sink_blocked) {
                    rx->sink_blocked = 1;
                    rx_force_ack(rx);
                }
                return;
            }
            fprintf(stderr, "unmoor sync: sink write failed: %s\n",
                    strerror(sink_errno));
            if (session_channelised_active(s))
                session_channel_stream_io_failed(
                    s, slot, sync_channel_sink_error_code(sink_errno));
            else {
                s->run_failed = 1;
                session_close(s);
            }
            return;
        }
        if (w == 0)
            return;
        rx->delivered += (uint64_t)w;
        rx_bump_generation(rx);
        rx_clear_blocks(rx, rx->delivered);
        if (rx->highest >= rx->last_advertised_credit)
            rx_force_ack(rx); /* window was full — reopen credit promptly */
        if ((size_t)w < n) {
            if (!rx->sink_blocked) {
                rx->sink_blocked = 1;
                rx_force_ack(rx);
            }
            return;
        }
    }

    if (rx->sink_blocked && rx->delivered == rx->frontier) {
        rx->sink_blocked = 0;
        rx_force_ack(rx);
    }

    if (rx->fin_seen && rx->frontier == rx->fin_offset
        && rx->delivered == rx->fin_offset && !rx->fin_delivered
        && (s->is_server || rx->have_code)) {
        rx->fin_delivered = 1;
        rx_force_ack(rx);
        if (!s->is_server) {
            rx->exit_after_ack_attempt = 1;
            rx->exit_ack_generation = rx->ack_generation;
        }
        /* The client may set should_exit below, so there may be no next
         * ESTABLISHED tick. Make the final FIN_SEEN attempt now. */
        if (!session_channelised_active(s))
            (void)rx_send_ack(s, slot, rx, tx->now_cache);
    }
}

void sync_rx_deliver(struct session *s)
{
    sync_rx_deliver_instance(s, 1U);
}

/* RTO probe: retransmit from the base (lowest unacked bytes) so a stall
 * always attacks the exact bytes blocking the frontier. With the credit
 * window closed, fall back to the persist probe — one already-delivered
 * byte the peer clips but still counts, eliciting an ack with fresh credit. */
static int tx_probe_try(session_t *s, uint8_t slot, sync_tx_t *tx,
                        int64_t now)
{
    int outstanding = tx->tip > tx->base || (tx->fin_pending && !tx->fin_acked);

    if (!outstanding) {
        tx->was_outstanding = 0;
        return 0;
    }
    if (!tx->was_outstanding) {
        /* No frame has reached a terminal handoff yet. NEW/FIN completion
         * arms the network timer; scheduler residence is not path time. */
        return 0;
    }
    if (now < tx->next_probe_ms || tx->recovery_send_pending ||
        tx->fin_send_pending)
        return 0;

    if (tx->tip > tx->base) {
        uint64_t end = tx->base + 3 * SYNC_GRID;
        size_t pmax = sync_payload_max(s);

        if (end > tx->tip)
            end = tx->tip;
        if (end > tx->peer_credit)
            end = tx->peer_credit;
        if (end > tx->base + pmax)
            end = tx->base + pmax;
        if (end > tx->base) {
            int rc = send_sync_data_range(s, slot, tx, tx->base,
                                          (size_t)(end - tx->base),
                                          SYNC_RECOVERY_PROBE, NULL, NULL);
            return rc == 0 ? 1 : (rc < 0 ? -1 : 0);
        }
        if (tx->base > 0) {
            int rc = send_sync_data_range(s, slot, tx, tx->base - 1, 1,
                                          SYNC_RECOVERY_PROBE, NULL, NULL);
            return rc == 0 ? 1 : (rc < 0 ? -1 : 0);
        }
    }
    return 0;
}

static int tx_fin_try(session_t *s, uint8_t slot, sync_tx_t *tx,
                      int64_t now)
{
    int probe_attempt;
    int rc;

    if (!tx->fin_pending || tx->fin_acked || tx->fin_send_pending ||
        tx->recovery_send_pending)
        return 0;
    if (now < tx->fin_retry_ms)
        return 0;
    if (!tx->fin_first_attempted) {
        probe_attempt = 0;
    } else if (tx->fin_completed_generation != tx->fin_generation) {
        /* A codeless FIN may later gain the server exit code.  Reassert the
         * new absolute FIN state without waiting for the network RTO. */
        probe_attempt = 0;
    } else {
        if (!tx->was_outstanding || now < tx->next_probe_ms)
            return 0;
        probe_attempt = 1; /* repeated FIN */
    }
    rc = send_sync_fin(s, slot, tx, probe_attempt);
    return rc == 0 ? 1 : (rc < 0 ? -1 : 0);
}

/* send-scheduler fixed round robin inside RECOVERY.  The cursor moves only when one
 * bounded logical producer is accepted (or synchronously reaches its fake
 * transport terminal result); idle producers are skipped work-conservingly.
 * A single recovery slot means no later producer can overtake the accepted
 * record before its COMPLETE/FAILED callback. */
static int tx_recovery_tick(session_t *s, uint8_t slot, sync_tx_t *tx,
                            int64_t now)
{

    if (tx->recovery_send_pending || tx->fin_send_pending)
        return 0;
    for (uint8_t n = 0; n < SYNC_RECOVERY_RR_COUNT; n++) {
        uint8_t producer = (uint8_t)((tx->recovery_cursor + n) %
                                     SYNC_RECOVERY_RR_COUNT);
        int rc;

        if (producer == SYNC_RECOVERY_RR_REPAIR)
            rc = tx_repair_try(s, slot, tx, now);
        else if (producer == SYNC_RECOVERY_RR_PROBE)
            rc = tx_probe_try(s, slot, tx, now);
        else
            rc = tx_fin_try(s, slot, tx, now);
        if (rc == 0)
            continue;
        if (rc > 0)
            tx->recovery_cursor = (uint8_t)((producer + 1U) %
                                             SYNC_RECOVERY_RR_COUNT);
        return rc;
    }
    return 0;
}

static void tx_arm_first_network_timer(sync_tx_t *tx, int64_t now_ms)
{
    if (!tx->was_outstanding) {
        tx->was_outstanding = 1;
        tx->next_probe_ms = now_ms + tx->rto_ms;
    }
}

static void tx_advance_probe_timer(sync_tx_t *tx, int64_t now_ms)
{
    if (tx->rto_ms < SYNC_RTO_MAX_MS) {
        tx->rto_ms *= 2;
        if (tx->rto_ms > SYNC_RTO_MAX_MS)
            tx->rto_ms = SYNC_RTO_MAX_MS;
    }
    tx->next_probe_ms = now_ms + tx->rto_ms;
}

void sync_send_result_instance(struct session *s, uint8_t slot,
                               int done, int completed,
                               int64_t now_ms, uint64_t arg0, uint64_t arg1)
{
    sync_tx_t *tx;
    sync_rx_t *rx;

    if (!s)
        return;
    tx = sync_tx_slot(s, slot);
    rx = sync_rx_slot(s, slot);
    if (tx == NULL || rx == NULL)
        return;

    switch ((session_tx_done_t)done) {
    case SESSION_TX_DONE_SYNC_ACK:
        if (!rx->active)
            return;
        rx->ack_send_pending = 0;
        if (completed) {
            if (arg1 > rx->last_advertised_credit)
                rx->last_advertised_credit = arg1;
            if (rx->ack_generation == arg0) {
                rx->frames_since_ack = 0;
                rx->ack_first_pending_ms = 0;
                rx->ack_due = 0;
            }
            rx->ack_retry_ms = 0;
            rx->next_repeat_ms = now_ms + SYNC_ACK_REPEAT_MS;
        } else {
            /* Absolute state remains due. A local hard failure is retried
             * from a fresh SEQ after the same bounded 25 ms floor. */
            rx->ack_retry_ms = now_ms + SYNC_ACK_DELAY_MS;
        }
        if (rx->exit_after_ack_attempt &&
            arg0 >= rx->exit_ack_generation) {
            if (session_channelised_active(s)) {
                if (!completed)
                    session_channel_stream_io_failed(
                        s, slot, CHANNEL_CODE_STALLED);
                else
                    session_channel_stream_receive_complete(
                        s, slot, rx->have_code, rx->exit_code);
            } else {
                ssize_t wr = write(STDOUT_FILENO, "\r\n", 2);
                (void)wr;
                if (!completed)
                    s->run_failed = 1;
                s->client_exit_code = (int)rx->exit_code;
                s->pty_eof_seen = 1;
                s->should_exit = 1;
            }
            rx->exit_after_ack_attempt = 0;
        }
        break;

    case SESSION_TX_DONE_SYNC_NEW:
        if (!tx->active)
            return;
        tx->new_send_pending = 0;
        if (completed) {
            if (arg0 > tx->sent)
                tx->sent = arg0;
            tx_arm_first_network_timer(tx, now_ms);
        }
        break;

    case SESSION_TX_DONE_SYNC_REPAIR:
        if (!tx->active)
            return;
        tx->recovery_send_pending = 0;
        tx->recovery_pending_kind = SYNC_RECOVERY_NONE;
        if (tx->repair_plan_valid && tx->repair_generation == arg0) {
            if (tx->repair_attempts_left != 0)
                tx->repair_attempts_left--;
            if (completed && arg1 > tx->repair_cursor)
                tx->repair_cursor = arg1;
        }
        break;

    case SESSION_TX_DONE_SYNC_PROBE:
        if (!tx->active)
            return;
        tx->recovery_send_pending = 0;
        tx->recovery_pending_kind = SYNC_RECOVERY_NONE;
        tx_advance_probe_timer(tx, now_ms);
        break;

    case SESSION_TX_DONE_SYNC_FIN:
        if (!tx->active)
            return;
        tx->fin_send_pending = 0;
        tx->fin_pending_generation = 0U;
        if (completed) {
            uint32_t generation = (uint32_t)(arg0 >> 1);

            tx->fin_retry_ms = 0;
            if (generation == tx->fin_generation)
                tx->fin_completed_generation = generation;
            if (!tx->fin_first_attempted) {
                tx->fin_first_attempted = 1;
                tx->last_linger_progress_ms = now_ms;
                tx_arm_first_network_timer(tx, now_ms);
            } else if ((arg0 & 1U) != 0) {
                tx_advance_probe_timer(tx, now_ms);
            }
        } else {
            /* A failed local handoff consumes its SEQ but no network/linger
             * authority. Keep FIN logical state due with a bounded floor. */
            tx->fin_retry_ms = now_ms + SYNC_ACK_DELAY_MS;
        }
        break;

    default:
        break;
    }
}

/*
 * channel-session retains one immutable operation owner per exact-stream lane.  The
 * channel handle is checked by session.c; this second boundary binds the
 * callback to the precise ACK/NEW/RECOVERY/FIN generation that acquired the
 * wire owner.  A mismatch is mutation-free so a delayed terminal result can
 * never clear a newer operation belonging to the same still-live handle.
 */
int sync_send_result_owned_instance(struct session *s, uint8_t slot,
                                    int done, int completed,
                                    int64_t now_ms, uint64_t arg0,
                                    uint64_t arg1,
                                    uint64_t operation_generation)
{
    sync_tx_t *tx;
    sync_rx_t *rx;
    int matches = 0;

    if (!s || operation_generation == 0U)
        return -1;
    tx = sync_tx_slot(s, slot);
    rx = sync_rx_slot(s, slot);
    if (tx == NULL || rx == NULL || !tx->active || !rx->active)
        return -1;

    switch ((session_tx_done_t)done) {
    case SESSION_TX_DONE_SYNC_ACK:
        matches = rx->ack_send_pending &&
                  rx->ack_pending_generation == operation_generation &&
                  arg0 == operation_generation &&
                  arg1 == rx->ack_pending_credit;
        break;
    case SESSION_TX_DONE_SYNC_NEW:
        matches = tx->new_send_pending &&
                  tx->new_pending_end == operation_generation &&
                  arg0 == operation_generation && arg1 == 0U;
        break;
    case SESSION_TX_DONE_SYNC_REPAIR:
        matches = tx->recovery_send_pending &&
                  tx->recovery_pending_kind == SYNC_RECOVERY_REPAIR &&
                  tx->recovery_pending_generation == operation_generation &&
                  arg0 == operation_generation &&
                  tx->recovery_pending_end == arg1;
        break;
    case SESSION_TX_DONE_SYNC_PROBE:
        matches = tx->recovery_send_pending &&
                  tx->recovery_pending_kind == SYNC_RECOVERY_PROBE &&
                  tx->recovery_pending_generation == operation_generation &&
                  arg0 == operation_generation &&
                  tx->recovery_pending_end == arg0 && arg1 == 0U;
        break;
    case SESSION_TX_DONE_SYNC_FIN:
        matches = tx->fin_send_pending &&
                  tx->fin_pending_generation == operation_generation &&
                  (arg0 >> 1) == operation_generation &&
                  arg1 == tx->fin_offset;
        break;
    default:
        return -1;
    }
    if (!matches)
        return -1;
    sync_send_result_instance(s, slot, done, completed, now_ms, arg0, arg1);
    return 0;
}

void sync_send_result(struct session *s, int done, int completed,
                      int64_t now_ms, uint64_t arg0, uint64_t arg1)
{
    sync_send_result_instance(s, 1U, done, completed, now_ms, arg0, arg1);
}

void sync_path_changed_instance(struct session *s, uint8_t slot,
                                int64_t now_ms,
                                int reassert_rx_feedback)
{
    sync_tx_t *tx = sync_tx_slot(s, slot);
    sync_rx_t *rx = sync_rx_slot(s, slot);

    if (tx == NULL || rx == NULL || !tx->active)
        return;
    if (sync_monitor_slot(s, slot) && sync_monitor_plan_barrier(s) != 0)
        return;
    /* The session authority names whether this transition came from a frame
     * that warrants an absolute RX reassertion.  In particular, a multipath
     * primary change caused by PTY_SYNC_ACK must not force a reciprocal ACK:
     * that ACK changes only our TX view, and two crossed selectors otherwise
     * echo freshly sequenced unchanged feedback forever.  Non-ACK changes and
     * every legacy one-path roam retain the historical reassertion. */
    if (reassert_rx_feedback)
        rx_force_ack(rx);
    if (tx->repair_plan_valid)
        tx->repair_cursor = tx->repair_frontier;
    if (tx->was_outstanding) {
        tx->next_probe_ms = now_ms;
        tx->recovery_cursor = SYNC_RECOVERY_RR_REPAIR;
    }
}

void sync_path_changed(struct session *s, int64_t now_ms,
                       int reassert_rx_feedback)
{
    uint8_t slot;

    if (!s)
        return;
    if (!session_channelised_active(s)) {
        sync_path_changed_instance(s, 1U, now_ms, reassert_rx_feedback);
        return;
    }
    for (slot = 1U; slot < CHANNEL_SESSION_SLOTS; slot++)
        sync_path_changed_instance(s, slot, now_ms, reassert_rx_feedback);
}

static int sync_feedback_due(const sync_rx_t *rx, int64_t now)
{
    int holes;

    if (rx == NULL || !rx->active || rx->ack_send_pending ||
        now < rx->ack_retry_ms)
        return 0;
    holes = rx->highest > rx->frontier ||
            (rx->fin_seen && rx->frontier < rx->fin_offset);
    return rx->ack_due || rx->frames_since_ack >= SYNC_ACK_FRAMES ||
           (rx->ack_first_pending_ms != 0 &&
            now - rx->ack_first_pending_ms >= SYNC_ACK_DELAY_MS) ||
           (holes && now >= rx->next_repeat_ms);
}

static void sync_maintain_instance(struct session *s, uint8_t slot,
                                   int64_t now)
{
    sync_tx_t *tx = sync_tx_slot(s, slot);
    sync_rx_t *rx = sync_rx_slot(s, slot);
    unsigned gs = 0;

    if (tx == NULL || rx == NULL || !tx->active)
        return;
    tx->now_cache = now;

    if (sync_monitor_slot(s, slot)) {
        const sync_source_t *source = s->sync_monitor->source;
        /* A pending seal/FIN also shuts the source gate, but is not quota
         * exhaustion. Include exactly the admitted unpublished bytes. */
        if (source->tip >= tx->base &&
            source->tip - tx->base + source->pending.append_length >= tx->quota)
            gs |= 1U;
    } else if (tx->tip - tx->base >= tx->quota) {
        /* Admission closes at source end even with storage remaining.
         * Report actual occupancy, not every reason the read gate is closed. */
        gs |= 1U;
    }
    if (tx->tip > tx->sent && tx->sent >= tx->peer_credit)
        gs |= 2U;
    if ((gs & 1U) && !(tx->gate_state & 1U))
        fprintf(stderr, "unmoor sync: backlog quota full — pausing source "
                        "reads until the peer catches up\n");
    if ((gs & 2U) && !(tx->gate_state & 2U))
        fprintf(stderr, "unmoor sync: peer receive window full — transmit "
                        "paused, backlog absorbing\n");
    tx->gate_state = gs;

    if (s->is_server && tx->fin_pending && tx->fin_first_attempted &&
        !tx->close_started) {
        if (tx->fin_acked) {
            tx->close_started = 1;
            if (session_channelised_active(s)) {
                session_channel_stream_send_complete(
                    s, slot, tx->have_code ? (uint32_t)tx->code : 0U);
            } else {
                session_close(s);
            }
        } else if (now - tx->last_linger_progress_ms >= tx->linger_ms) {
            fprintf(stderr, "unmoor sync: peer unreachable %lld ms after "
                            "exit — closing with %llu bytes undelivered\n",
                    (long long)tx->linger_ms,
                    (unsigned long long)(tx->fin_offset - tx->base));
            /* The FIN was never acknowledged at the stream frontier. Even
             * when the peer happened to display everything, this endpoint
             * cannot prove a clean handoff; terminal-state-sync owns that ambiguity as a
             * loud nonzero close, never success. */
            tx->close_started = 1;
            if (session_channelised_active(s)) {
                session_channel_stream_send_complete(
                    s, slot, CHANNEL_CODE_STALLED);
            } else {
                s->run_failed = 1;
                session_close(s);
            }
        }
    }
}

static int sync_service_lane(struct session *s, send_lane_t lane,
                             int64_t now)
{
    uint8_t ordinal;

    for (ordinal = 0U; ordinal < CHANNEL_SESSION_DATA_SLOTS; ordinal++) {
        uint8_t candidate = (uint8_t)(1U +
            ((unsigned int)s->sync_lane_cursor[lane] + ordinal) %
                CHANNEL_SESSION_DATA_SLOTS);
        sync_tx_t *tx = sync_tx_slot(s, candidate);
        sync_rx_t *rx = sync_rx_slot(s, candidate);
        int rc = 0;

        if (tx == NULL || rx == NULL || !tx->active || !rx->active)
            continue;
        if (lane == SEND_LANE_FEEDBACK) {
            if (!sync_feedback_due(rx, now))
                continue;
            rc = rx_send_ack(s, candidate, rx, now) == 0 ? 1 : -1;
        } else if (lane == SEND_LANE_RECOVERY) {
            rc = tx_recovery_tick(s, candidate, tx, now);
            if (rc == 0)
                continue;
        } else if (lane == SEND_LANE_NEW) {
            rc = tx_pump(s, candidate, tx);
            if (rc == 0)
                continue;
        } else {
            return -1;
        }
        if (rc > 0)
            s->sync_lane_cursor[lane] = (uint8_t)(candidate %
                                                  CHANNEL_SESSION_DATA_SLOTS);
        /* Once a due producer is attempted, a globally retained owner may
         * be the reason it cannot admit.  Do not scan on and accidentally
         * let a later handle overtake that one-producer-per-lane boundary. */
        return rc;
    }
    return 0;
}

void sync_tick_instance(struct session *s, uint8_t slot, int64_t now)
{
    sync_tx_t *tx = sync_tx_slot(s, slot);
    sync_rx_t *rx = sync_rx_slot(s, slot);

    if (tx == NULL || rx == NULL || !tx->active)
        return;
    sync_maintain_instance(s, slot, now);
    if (sync_monitor_slot(s, slot) &&
        (!sync_monitor_live(s, s->sync_monitor) ||
         !session_application_send_eligible(s)))
        return;
    if (sync_feedback_due(rx, now))
        (void)rx_send_ack(s, slot, rx, now);
    (void)tx_recovery_tick(s, slot, tx, now);
    (void)tx_pump(s, slot, tx);
}

void sync_tick(struct session *s, int64_t now)
{
    uint8_t slot;

    if (!s)
        return;
    if (!session_channelised_active(s)) {
        sync_tick_instance(s, 1U, now);
        return;
    }

    /* Timers and fail-loud channel completion are maintained for every live
     * instance.  Logical admission is then independently round-robin per
     * applicable send-scheduler lane, with one retained session producer per lane. */
    for (slot = 1U; slot < CHANNEL_SESSION_SLOTS; slot++)
        if (sync_active_instance(s, slot))
            sync_maintain_instance(s, slot, now);
    if (s->state != SESSION_ESTABLISHED)
        return;
    (void)sync_service_lane(s, SEND_LANE_FEEDBACK, now);
    (void)sync_service_lane(s, SEND_LANE_RECOVERY, now);
    (void)sync_service_lane(s, SEND_LANE_NEW, now);
}

int64_t sync_next_deadline_instance(struct session *s, uint8_t slot,
                                    int64_t now)
{
    sync_tx_t *tx = sync_tx_slot(s, slot);
    sync_rx_t *rx = sync_rx_slot(s, slot);
    sync_monitor_binding_t *binding = sync_monitor_slot(s, slot);
    int64_t d = INT64_MAX;
    int holes, outstanding;
    int64_t ack_d = INT64_MAX;

    if (tx == NULL || rx == NULL || !tx->active)
        return -1;
    if (binding) {
        if (!sync_monitor_live(s, binding))
            return -1;
        if (!session_application_send_eligible(s))
            goto linger; /* paused app work cannot force repeated poll(0) */
    }
    if (!rx->ack_send_pending &&
        (rx->ack_due || rx->frames_since_ack >= SYNC_ACK_FRAMES))
        ack_d = now;
    if (!rx->ack_send_pending && rx->ack_first_pending_ms != 0
        && rx->ack_first_pending_ms + SYNC_ACK_DELAY_MS < ack_d)
        ack_d = rx->ack_first_pending_ms + SYNC_ACK_DELAY_MS;
    holes = rx->highest > rx->frontier
         || (rx->fin_seen && rx->frontier < rx->fin_offset);
    if (!rx->ack_send_pending && holes && rx->next_repeat_ms < ack_d)
        ack_d = rx->next_repeat_ms;
    if (ack_d != INT64_MAX) {
        if (rx->ack_retry_ms > ack_d)
            ack_d = rx->ack_retry_ms;
        if (ack_d < d)
            d = ack_d;
    }
    outstanding = tx->tip > tx->base || (tx->fin_pending && !tx->fin_acked);
    if (outstanding && tx->was_outstanding) {
        if (tx->next_probe_ms < d)
            d = tx->next_probe_ms;
    }
    if (tx->fin_pending && !tx->fin_acked && !tx->fin_first_attempted &&
        !tx->fin_send_pending && tx->fin_retry_ms < d)
        d = tx->fin_retry_ms;
linger:
    if (s->is_server && tx->fin_pending && !tx->close_started
        && (!binding || tx->fin_first_attempted)
        && tx->last_linger_progress_ms + tx->linger_ms < d)
        d = tx->last_linger_progress_ms + tx->linger_ms;
    if (d == INT64_MAX)
        return -1;
    return d > now ? d - now : 0;
}

int64_t sync_next_deadline(struct session *s, int64_t now)
{
    int64_t wait = -1;
    uint8_t slot;

    if (!s)
        return -1;
    if (!session_channelised_active(s))
        return sync_next_deadline_instance(s, 1U, now);
    for (slot = 1U; slot < CHANNEL_SESSION_SLOTS; slot++) {
        int64_t candidate = sync_next_deadline_instance(s, slot, now);

        if (candidate >= 0 && (wait < 0 || candidate < wait))
            wait = candidate;
    }
    return wait;
}

/* -------------------------------------------------------------------------
 * Lifecycle
 * ---------------------------------------------------------------------- */

static uint64_t env_bytes(const char *name, uint64_t def, uint64_t min,
                          uint64_t max)
{
    const char *v = getenv(name);
    unsigned long long x;
    char *endp = NULL;

    if (v == NULL || *v == '\0')
        return def;
    errno = 0;
    x = strtoull(v, &endp, 10);
    if (errno != 0 || endp == v || *endp != '\0') {
        fprintf(stderr, "unmoor: invalid %s value — using default\n", name);
        return def;
    }
    if (x < min)
        return min;
    if (x > max)
        return max;
    return (uint64_t)x;
}

uint64_t sync_classic_backlog_quota(void)
{
    uint64_t quota = env_bytes("UNMOOR_SYNC_BACKLOG_BYTES", SYNC_BACKLOG_DEFAULT,
                               SYNC_BACKLOG_MIN, SYNC_BACKLOG_MAX);
    return (quota + SYNC_TX_CHUNK - 1U) / SYNC_TX_CHUNK * SYNC_TX_CHUNK;
}

static int sync_storage_init(session_t *s, uint8_t slot, uint64_t quota,
                             uint64_t pending, uint32_t handle, uint8_t kind,
                             int source_fd, int sink_fd,
                             sync_instance_read_fn read_source,
                             void *source_context,
                             sync_instance_write_fn write_sink,
                             void *sink_context, int bind_instance)
{
    sync_tx_t *tx = sync_tx_slot(s, slot);
    sync_rx_t *rx = sync_rx_slot(s, slot);
    sync_instance_binding_t *binding = sync_binding_slot(s, slot);
    uint8_t txdir;
    int backlog_rc;

    if (tx == NULL || rx == NULL || binding == NULL || tx->active ||
        rx->active || quota == 0U || pending == 0U ||
        quota % SYNC_TX_CHUNK != 0U || pending % SYNC_GRID != 0U) {
        errno = EINVAL;
        return -1;
    }
    memset(tx, 0, sizeof(*tx));
    memset(rx, 0, sizeof(*rx));
    tx->quota = quota;
    backlog_rc = sync_monitor_slot(s, slot) ? 0 :
        sync_backlog_init(&tx->backlog, (size_t)(quota / SYNC_TX_CHUNK) + 1);
    rx->ring_size = (size_t)pending;
    rx->ring = malloc(rx->ring_size);
    rx->nblocks = rx->ring_size / SYNC_GRID + 1;
    rx->blockmap = calloc(rx->nblocks, 1);
    if (backlog_rc != 0 || rx->ring == NULL || rx->blockmap == NULL) {
        sync_backlog_free(&tx->backlog);
        free(rx->ring);
        free(rx->blockmap);
        memset(tx, 0, sizeof(*tx));
        memset(rx, 0, sizeof(*rx));
        fprintf(stderr, "unmoor sync: buffer allocation failed\n");
        return -1;
    }

    txdir = s->is_server ? 0x01 : 0x00;
    crypto_sync_chain_init(&tx->chain, txdir);
    crypto_sync_chain_init(&rx->chain, (uint8_t)(txdir ^ 0x01));

    tx->peer_credit = SYNC_INITIAL_CREDIT;
    tx->rto_ms = SYNC_RTO_MIN_MS;
    tx->linger_ms = (int64_t)env_bytes("UNMOOR_SYNC_LINGER_MS", SYNC_LINGER_MS,
                                       1000, 86400000ULL * 30);
    tx->now_cache = mono_ms();
    tx->last_progress_ms = tx->now_cache;
    tx->last_linger_progress_ms = tx->now_cache;
    tx->active = 1;
    rx->active = 1;
    if (bind_instance) {
        memset(binding, 0, sizeof(*binding));
        binding->handle = handle;
        binding->slot = slot;
        binding->kind = kind;
        binding->configured = 1U;
        binding->source_fd = source_fd;
        binding->sink_fd = sink_fd;
        binding->read_source = read_source;
        binding->write_sink = write_sink;
        binding->source_context = source_context;
        binding->sink_context = sink_context;
    }
    return 0;
}

static int sync_d36_geometry(session_t *s, uint64_t *quota_out,
                             uint64_t *pending_out)
{
    uint64_t quota;
    uint64_t pending;

    if (!s || !quota_out || !pending_out) {
        errno = EINVAL;
        return -1;
    }
    if (!s->sync_d36_quotas_parsed) {
        quota = env_bytes("UNMOOR_SYNC_BACKLOG_BYTES",
                          SYNC_D36_BACKLOG_DEFAULT, SYNC_BACKLOG_MIN,
                          SYNC_D36_BACKLOG_MAX);
        if (quota > UINT64_MAX - (SYNC_TX_CHUNK - 1U)) {
            errno = EOVERFLOW;
            return -1;
        }
        quota = (quota + SYNC_TX_CHUNK - 1U) /
                    SYNC_TX_CHUNK * SYNC_TX_CHUNK;
        pending = env_bytes("UNMOOR_SYNC_PENDING_BYTES",
                            SYNC_D36_PENDING_DEFAULT, SYNC_PENDING_MIN,
                            SYNC_D36_PENDING_MAX);
        pending -= pending % SYNC_GRID;
        s->sync_d36_tx_quota = quota;
        s->sync_d36_rx_quota = pending;
        s->sync_d36_quotas_parsed = 1U;
    }
    *quota_out = s->sync_d36_tx_quota;
    *pending_out = s->sync_d36_rx_quota;
    return 0;
}

int sync_reserve_instance(struct session *s, uint8_t slot, uint8_t kind)
{
    sync_instance_binding_t *binding;
    uint64_t quota;
    uint64_t pending;

    if (!s || !session_channelised_active(s) || slot == 0U ||
        slot >= CHANNEL_SESSION_SLOTS ||
        (kind != CHANNEL_KIND_TERMINAL && kind != CHANNEL_KIND_EXEC)) {
        errno = EINVAL;
        return -1;
    }
    if (sync_d36_geometry(s, &quota, &pending) != 0)
        return -1;
    if (s->sync_admitted_tx > SYNC_D36_BACKLOG_AGGREGATE ||
        s->sync_admitted_rx > SYNC_D36_PENDING_AGGREGATE ||
        quota > SYNC_D36_BACKLOG_AGGREGATE - s->sync_admitted_tx ||
        pending > SYNC_D36_PENDING_AGGREGATE - s->sync_admitted_rx) {
        errno = ENOSPC;
        return -1;
    }
    if (sync_storage_init(s, slot, quota, pending, 0U, kind,
                          -1, -1, NULL, NULL, NULL, NULL, 0) != 0)
        return -1;
    binding = sync_binding_slot(s, slot);
    memset(binding, 0, sizeof(*binding));
    binding->slot = slot;
    binding->kind = kind;
    binding->admitted = 1U;
    binding->source_fd = -1;
    binding->sink_fd = -1;
    s->sync_admitted_tx += quota;
    s->sync_admitted_rx += pending;
    return 0;
}

int sync_bind_reserved_instance(
    struct session *s, uint8_t slot, uint32_t handle, uint8_t kind,
    int source_fd, int sink_fd, sync_instance_read_fn read_source,
    void *source_context, sync_instance_write_fn write_sink,
    void *sink_context)
{
    sync_instance_binding_t *binding;
    uint8_t decoded_slot;
    uint32_t generation;

    binding = sync_binding_slot(s, slot);
    if (!s || binding == NULL || !sync_active_instance(s, slot) ||
        !binding->admitted || binding->configured || binding->slot != slot ||
        binding->kind != kind ||
        channel_session_handle_decode(handle, &decoded_slot, &generation) !=
            0 || decoded_slot != slot || generation == 0U) {
        errno = EINVAL;
        return -1;
    }
    binding->handle = handle;
    binding->configured = 1U;
    binding->source_fd = source_fd;
    binding->sink_fd = sink_fd;
    binding->read_source = read_source;
    binding->write_sink = write_sink;
    binding->source_context = source_context;
    binding->sink_context = sink_context;
    return 0;
}

int sync_init_instance(struct session *s, uint8_t slot, uint32_t handle,
                       uint8_t kind, int source_fd, int sink_fd,
                       sync_instance_read_fn read_source,
                       void *source_context,
                       sync_instance_write_fn write_sink,
                       void *sink_context)
{
    uint8_t decoded_slot;
    uint32_t generation;
    int saved_errno;

    if (!s || !session_channelised_active(s) ||
        channel_session_handle_decode(handle, &decoded_slot, &generation) !=
            0 || decoded_slot != slot || generation == 0U ||
        (kind != CHANNEL_KIND_TERMINAL && kind != CHANNEL_KIND_EXEC)) {
        errno = EINVAL;
        return -1;
    }
    if (sync_reserve_instance(s, slot, kind) != 0)
        return -1;
    if (sync_bind_reserved_instance(
            s, slot, handle, kind, source_fd, sink_fd,
            read_source, source_context, write_sink, sink_context) != 0) {
        saved_errno = errno;
        (void)sync_free_instance(s, slot);
        errno = saved_errno;
        return -1;
    }
    return 0;
}

int sync_init(struct session *s)
{
    sync_tx_t *tx;
    sync_rx_t *rx;
    uint64_t quota;
    uint64_t pending;

    if (!s)
        return -1;
    tx = &s->sync_tx;
    rx = &s->sync_rx;
    if (s->sync_monitor &&
        (s->sync_monitor->life != SYNC_MONITOR_PREBOUND ||
         s->sync_monitor->session != s || !s->is_server ||
         tx->active || rx->active || s->services_started ||
         s->channelised_requested || session_channelised_active(s) ||
         s->bulk_enabled || !s->channels[1] ||
         s->sync_monitor->source->failed ||
         sync_work_failure(s->sync_monitor->work) ||
         (session_selected_capabilities(s) &
            (UNMOOR_CAP_PTY_V1 | UNMOOR_CAP_PTY_SYNC_V1)) !=
            (UNMOOR_CAP_PTY_V1 | UNMOOR_CAP_PTY_SYNC_V1))) {
        fprintf(stderr, "unmoor sync: monitored source activation refused\n");
        sync_monitor_stop(s);
        return -1;
    }
    if (tx->active || rx->active)
        sync_free(s); /* re-establishment guard */

    /* A session with no PTY registry or no PTY capability has no exact
     * stream. This preserves the fragment-probe harness shape. */
    if (s->channels[1] == NULL ||
        !(session_selected_capabilities(s) & UNMOOR_CAP_PTY_V1))
        return 0;
    if (!(session_selected_capabilities(s) & UNMOOR_CAP_PTY_SYNC_V1)) {
        fprintf(stderr, "unmoor: state sync not negotiated — legacy PTY path "
                        "(output can drop under packet loss)\n");
        return 0;
    }

    if (session_channelised_active(s)) {
        int source_fd = s->is_server ? s->pty_master_fd : STDIN_FILENO;
        int sink_fd = s->is_server ? s->pty_master_fd : STDOUT_FILENO;

        return sync_init_instance(s, 1U, s->terminal_channel_handle,
                                  CHANNEL_KIND_TERMINAL,
                                  source_fd, sink_fd, NULL, NULL, NULL, NULL);
    }

    quota = s->sync_monitor ? s->sync_monitor->source->quota :
                              sync_classic_backlog_quota();
    pending = env_bytes("UNMOOR_SYNC_PENDING_BYTES", SYNC_PENDING_DEFAULT,
                        SYNC_PENDING_MIN, SYNC_PENDING_MAX);
    pending -= pending % SYNC_GRID;
    if (sync_storage_init(s, 1U, quota, pending, 0U, 0U, -1, -1,
                          NULL, NULL, NULL, NULL, 0) != 0) {
        sync_monitor_stop(s);
        return -1;
    }
    if (s->sync_monitor)
        s->sync_monitor->life = SYNC_MONITOR_LIVE;
    fprintf(stderr, "unmoor: state sync active (backlog %llu MiB, "
                    "pending %llu KiB)\n",
            (unsigned long long)(quota >> 20),
            (unsigned long long)(pending >> 10));
    return 0;
}

static void sync_legacy_drain(session_t *s, sync_rx_t *rx)
{
    if (!s->is_server && rx->active && !rx->fin_delivered) {
        /* The session is ending before the remote stream completed.
         * Drain what is already verified (bounded), then say so loudly —
         * silently missing output is the exact defect this engine removes. */
        int64_t deadline = mono_ms() + 2000;

        while (rx->delivered < rx->frontier && mono_ms() < deadline) {
            struct pollfd p;
            size_t rpos, n;
            ssize_t w;
            int pr;

            p.fd = STDOUT_FILENO;
            p.events = POLLOUT;
            p.revents = 0;
            pr = poll(&p, 1, 100);
            if (pr < 0) {
                if (errno == EINTR)
                    continue;
                break;
            }
            if (pr == 0)
                continue; /* timeout — retry until the drain deadline */
            rpos = (size_t)(rx->delivered % rx->ring_size);
            n = (size_t)(rx->frontier - rx->delivered);
            if (n > rx->ring_size - rpos)
                n = rx->ring_size - rpos;
            w = write(STDOUT_FILENO, rx->ring + rpos, n);
            if (w > 0) {
                rx->delivered += (uint64_t)w;
                continue;
            }
            if (w < 0 && (errno == EINTR || errno == EAGAIN
                          || errno == EWOULDBLOCK))
                continue;
            break;
        }
        fprintf(stderr, "unmoor sync: session ended before the remote stream "
                        "completed — output may be incomplete\n");
        s->run_failed = 1;
    }
}

static int checked_sum_u64(uint64_t total, uint64_t value,
                           uint64_t *result_out)
{
    if (result_out == NULL || total > UINT64_MAX - value)
        return -1;
    *result_out = total + value;
    return 0;
}

static int sync_storage_free(session_t *s, uint8_t slot, int retire,
                             int enforce_owner)
{
    sync_tx_t *tx = sync_tx_slot(s, slot);
    sync_rx_t *rx = sync_rx_slot(s, slot);
    sync_instance_binding_t *binding = sync_binding_slot(s, slot);
    uint64_t retired_tx;
    uint64_t retired_delivered;
    uint64_t retired_highest;

    if (tx == NULL || rx == NULL || binding == NULL ||
        (!tx->active && !rx->active))
        return 0;

    if (enforce_owner && binding->configured &&
        (rx->ack_send_pending || tx->new_send_pending ||
         tx->recovery_send_pending || tx->fin_send_pending ||
         session_stream_owner_active(s, binding->handle))) {
        errno = EBUSY;
        return -1;
    }

    if (retire && binding->admitted) {
        if (checked_sum_u64(s->sync_retired_tx_tip, tx->tip,
                            &retired_tx) != 0 ||
            checked_sum_u64(s->sync_retired_rx_delivered, rx->delivered,
                            &retired_delivered) != 0 ||
            checked_sum_u64(s->sync_retired_rx_highest, rx->highest,
                            &retired_highest) != 0) {
            sync_fatal(s, "channel-session cumulative sync counter overflow");
            errno = EOVERFLOW;
            if (enforce_owner)
                return -1;
        } else if (s->sync_admitted_tx < tx->quota ||
                   s->sync_admitted_rx < (uint64_t)rx->ring_size) {
            sync_fatal(s, "channel-session sync quota accounting underflow");
            errno = EOVERFLOW;
            if (enforce_owner)
                return -1;
        } else {
            s->sync_retired_tx_tip = retired_tx;
            s->sync_retired_rx_delivered = retired_delivered;
            s->sync_retired_rx_highest = retired_highest;
            s->sync_admitted_tx -= tx->quota;
            s->sync_admitted_rx -= (uint64_t)rx->ring_size;
        }
    }

    sync_backlog_free(&tx->backlog);
    if (rx->ring != NULL) {
        crypto_memzero(rx->ring, rx->ring_size);
        free(rx->ring);
    }
    free(rx->blockmap);
    /* Chains hash terminal data; the structs may hold offsets of interest.
     * Wipe rather than plain-clear. */
    crypto_memzero(tx, sizeof(*tx));
    crypto_memzero(rx, sizeof(*rx));
    crypto_memzero(binding, sizeof(*binding));
    binding->source_fd = -1;
    binding->sink_fd = -1;
    return 0;
}

int sync_free_instance(struct session *s, uint8_t slot)
{
    if (sync_monitor_slot(s, slot))
        sync_monitor_stop(s);
    return sync_storage_free(s, slot, 1, 1);
}

void sync_free(struct session *s)
{
    uint8_t slot;
    int legacy;

    if (!s)
        return;
    sync_monitor_stop(s);
    legacy = sync_active_instance(s, 1U) &&
             !s->sync_binding[1].configured;
    if (legacy)
        sync_legacy_drain(s, &s->sync_rx);
    for (slot = 1U; slot < CHANNEL_SESSION_SLOTS; slot++)
        (void)sync_storage_free(s, slot,
                                s->sync_binding[slot].admitted, 0);
}

int sync_instance_set_io(struct session *s, uint8_t slot, uint32_t handle,
                         int source_fd, int sink_fd,
                         sync_instance_read_fn read_source,
                         void *source_context,
                         sync_instance_write_fn write_sink,
                         void *sink_context)
{
    sync_instance_binding_t *binding = sync_binding_slot(s, slot);

    if (binding == NULL || !binding->configured ||
        !sync_active_instance(s, slot) || binding->handle != handle) {
        errno = EINVAL;
        return -1;
    }
    binding->source_fd = source_fd;
    binding->sink_fd = sink_fd;
    binding->read_source = read_source;
    binding->source_context = source_context;
    binding->write_sink = write_sink;
    binding->sink_context = sink_context;
    return 0;
}

int sync_instance_detach_io(struct session *s, uint8_t slot,
                            uint32_t handle)
{
    return sync_instance_set_io(s, slot, handle, -1, -1,
                                NULL, NULL, NULL, NULL);
}

int sync_instance_source_fd(const struct session *s, uint8_t slot)
{
    const sync_instance_binding_t *binding = sync_binding_slot_const(s, slot);

    return binding != NULL && binding->configured ? binding->source_fd : -1;
}

int sync_instance_sink_fd(const struct session *s, uint8_t slot)
{
    const sync_instance_binding_t *binding = sync_binding_slot_const(s, slot);

    return binding != NULL && binding->configured ? binding->sink_fd : -1;
}

ssize_t sync_instance_read_source(struct session *s, uint8_t slot,
                                  uint8_t *buffer, size_t capacity)
{
    sync_instance_binding_t *binding = sync_binding_slot(s, slot);
    ssize_t result;

    if (binding == NULL || !binding->configured || buffer == NULL ||
        capacity == 0U) {
        errno = EINVAL;
        return -1;
    }
    if (binding->source_eof)
        return 0;
    if (binding->read_source != NULL)
        result = binding->read_source(binding->source_context, buffer,
                                      capacity);
    else if (binding->source_fd >= 0)
        result = read(binding->source_fd, buffer, capacity);
    else {
        errno = EAGAIN;
        return -1;
    }
    if (result == 0)
        binding->source_eof = 1U;
    return result;
}

const sync_tx_t *sync_tx_state_instance(const struct session *s,
                                        uint8_t slot)
{
    return sync_tx_slot_const(s, slot);
}

const sync_rx_t *sync_rx_state_instance(const struct session *s,
                                        uint8_t slot)
{
    return sync_rx_slot_const(s, slot);
}

int sync_aggregate_snapshot(const struct session *s,
                            uint64_t *tx_tip_out,
                            uint64_t *rx_delivered_out,
                            uint64_t *rx_highest_out,
                            int *sink_blocked_out)
{
    uint64_t tx_tip;
    uint64_t rx_delivered;
    uint64_t rx_highest;
    int sink_blocked = 0;
    uint8_t slot;

    if (!s || !tx_tip_out || !rx_delivered_out || !rx_highest_out ||
        !sink_blocked_out)
        return -1;
    tx_tip = s->sync_retired_tx_tip;
    rx_delivered = s->sync_retired_rx_delivered;
    rx_highest = s->sync_retired_rx_highest;
    for (slot = 1U; slot < CHANNEL_SESSION_SLOTS; slot++) {
        const sync_tx_t *tx = sync_tx_slot_const(s, slot);
        const sync_rx_t *rx = sync_rx_slot_const(s, slot);

        if (tx == NULL || rx == NULL || !tx->active)
            continue;
        if (tx_tip > UINT64_MAX - tx->tip ||
            rx_delivered > UINT64_MAX - rx->delivered ||
            rx_highest > UINT64_MAX - rx->highest)
            return -1;
        tx_tip += tx->tip;
        rx_delivered += rx->delivered;
        rx_highest += rx->highest;
        sink_blocked = sink_blocked || rx->sink_blocked;
    }
    *tx_tip_out = tx_tip;
    *rx_delivered_out = rx_delivered;
    *rx_highest_out = rx_highest;
    *sink_blocked_out = sink_blocked;
    return 0;
}
