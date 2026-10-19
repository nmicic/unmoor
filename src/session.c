/*
 * session.c — full session state machine
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * Implements:
 *   - CTRL_HELLO retransmit schedule (1s/2s/4s/8s + 16s wait → IDLE, 5 total)
 *   - CTRL_HELLO_ACK: derive hello_key, then session_key, send CTRL_READY
 *   - KEY_DERIVING: wait for peer CTRL_READY (10s timeout)
 *   - ESTABLISHED: keepalive every 2s, liveness watchdog 6s
 *   - Replay window (additive form, 256-entry bitmap)
 *   - AEAD failure policy
 *   - Idempotent CTRL_HELLO in KEY_DERIVING (same nonce_a = re-send ACK)
 *   - CTRL_CLOSE retransmit (3 frames, 1s/2s/force)
 */

#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#include "monocypher.h"
#include "session.h"
#include "sync_monitor.h"
#include "monitor_session_backend.h"
#include "confine.h"
#include "frame.h"
#include "crypto.h"
#include "epoch_crypto.h"
#include "pq_epoch_crypto.h"
#include "pq_rekey.h"
#include "channel.h"
#include "channel_pty.h"

#define READY_RETRY_MS 500
#define DELIVERY_STATE_REPEAT_MS 500
#define SESSION_BULK_PATH_LOG_LIMIT 1024U
#define CHANNEL_CONTROL_RETRY_FLOOR_MS 25
#define SESSION_POLL_CAPACITY 96U
#define CHANNEL_PROCESS_TERM_GRACE_MS INT64_C(1000)
#define CHANNEL_PROCESS_REAP_HORIZON_MS INT64_C(2000)

static const int64_t channel_retry_offsets_ms[4] = {
    INT64_C(1000), INT64_C(3000), INT64_C(7000), INT64_C(15000)
};

_Static_assert(DELIVERY_CTRL_RD_DATA_TYPE == CTRL_RD_DATA,
               "delivery-class reliable DATA type drift");
_Static_assert(DELIVERY_CTRL_RD_STATUS_TYPE == CTRL_RD_STATUS,
               "delivery-class reliable STATUS type drift");
_Static_assert(DELIVERY_LATEST_HEAD_TYPE == LATEST_HEAD,
               "delivery-class latest HEAD type drift");
_Static_assert(DELIVERY_LATEST_BLOCK_TYPE == LATEST_BLOCK,
               "delivery-class latest BLOCK type drift");
_Static_assert(DELIVERY_LATEST_STATUS_TYPE == LATEST_STATUS,
               "delivery-class latest STATUS type drift");
_Static_assert(UNMOOR_LATEST_BLOCK_D31_MIN_MTU ==
                   DELIVERY_LATEST_BLOCK_WIRE_MAX,
               "delivery-class latest MTU contract drift");
_Static_assert(UNMOOR_RELIABLE_DGRAM_D31_MIN_MTU ==
                   DELIVERY_RELIABLE_DATA_WIRE_MAX,
               "delivery-class reliable MTU contract drift");
_Static_assert(BULK_CAPABILITY == UNMOOR_CAP_BULK_FILE_D33_V1,
               "bulk-transfer capability contract drift");
_Static_assert(PQ_REKEY_SHARE_LEN == PQ_MLKEM_PUBLIC_LEN,
               "pq-hybrid public share length drift");
_Static_assert(PQ_REKEY_SHARE_LEN == PQ_MLKEM_CIPHERTEXT_LEN,
               "pq-hybrid ciphertext share length drift");
_Static_assert(ATTACH_LOCAL_BULK_RESULT_CONFINED == CHANNEL_CODE_CONFINED,
               "client-confinement local confinement result drift");

/* CTRL_ERROR payload (4 bytes) */
typedef struct {
    uint16_t error_code;
    uint16_t reserved;
} ctrl_error_t;

/* Client tick hook (see session.h) */
session_tick_fn session_run_tick = NULL;
session_established_fn session_on_established = NULL;
session_status_ui_fn session_status_ui = NULL;

/* Static assert on stored_hello_ack sizing.
 * body grew by 24 bytes for the cleartext hello_nonce.
 * The encrypted plaintext remains exactly 32 bytes under NEG1. */
_Static_assert(sizeof(((struct session *)0)->stored_hello_ack)
                   >= 12 + 24 + NEGOTIATION_PLAIN_LEN + 16,
               "stored_hello_ack too small for hdr(12)+nonce(24)+ack_pt+tag(16)");

/* -------------------------------------------------------------------------
 * Monotonic clock helper (returns ms)
 * ---------------------------------------------------------------------- */
static int64_t mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int64_t physical_mono_ms(void *context)
{
    (void)context;
    return mono_ms();
}

static int64_t session_physical_now_ms(session_t *s, int64_t fallback_ms)
{
    int64_t observed;

    if (!s || !s->physical_clock_now)
        return fallback_ms;
    observed = s->physical_clock_now(s->physical_clock_context);
    return observed >= 0 ? observed : fallback_ms;
}

static uint16_t load16le(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | (uint16_t)((uint16_t)p[1] << 8));
}

static uint32_t load32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void store32le(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
    p[2] = (uint8_t)(value >> 16);
    p[3] = (uint8_t)(value >> 24);
}

/* -------------------------------------------------------------------------
 * Chaos engineering : random frame drops, both directions.
 *
 * Compiled ONLY with `make UNMOOR_CHAOS=1` — production binaries carry zero
 * chaos code, same discipline as UNMOOR_TEST_INJECT. In chaos builds every
 * frame has a drop probability on tx and on rx, so the protocol is
 * exercised under loss at all times during development, not only when a
 * lossy network happens to be available. netem/tc equivalent, but
 * in-binary: works on macOS, over any transport, no root.
 *
 * Env knobs (chaos builds only):
 *   UNMOOR_CHAOS_DROP_PCT   fixed drop rate in percent, default 1.0; 0 disables
 *   UNMOOR_CHAOS_VARY_PCT   if set, rate is re-rolled uniformly in [0, this]
 *                         every UNMOOR_CHAOS_VARY_SECS (default 5) — models
 *                         bursty fading rather than uniform loss
 *   UNMOOR_CHAOS_SEED       uint32 PRNG seed for reproducible runs
 *   UNMOOR_CHAOS_DROP_TX    targeted deterministic drop: "chan:type[:count]"
 *   UNMOOR_CHAOS_DROP_RX    (e.g. "1:0x01:1" = drop the first PTY_OPEN).
 *                         The netem-filter equivalent: kill an exact frame
 *                         type N times to test a specific recovery path.
 *                         CHAN and TYPE are cleartext header bytes 8/9.
 *   UNMOOR_CHAOS_DELAY_MS         tx delay base in ms (netem "delay")
 *   UNMOOR_CHAOS_DELAY_JITTER_MS  ± uniform jitter on the delay
 *   UNMOOR_CHAOS_DELAY_PCT        fraction of tx frames delayed (default 100
 *                               when DELAY_MS is set)
 *   UNMOOR_CHAOS_REORDER_PCT      tx reorder: hold a frame and let the NEXT
 *                               frame overtake it (netem "reorder gap 1");
 *                               a held frame nothing overtakes is flushed
 *                               after 500ms
 *
 * Delay + jitter produce natural reordering too (like netem): two frames
 * sent 1ms apart with ±30ms jitter frequently swap. Shaping is tx-only —
 * each peer shapes its own tx, which covers both directions of the link.
 * The delay queue is 1024 slots (sized to swallow a whole PTY-read burst);
 * when full, frames are tail-dropped and logged — netem's `limit`
 * behavior, and what any real bottleneck queue does under a flood.
 * ---------------------------------------------------------------------- */

#if defined(UNMOOR_CHAOS) && UNMOOR_CHAOS
static uint32_t chaos_rng_state;
static uint32_t chaos_bp;             /* current drop rate, basis points */
static uint32_t chaos_vary_max_bp;    /* 0 = fixed mode */
static int64_t  chaos_vary_period_ms = 5000;
static int64_t  chaos_next_vary_ms;
static int      chaos_inited;
static uint64_t chaos_drops;

/* Targeted deterministic drops, one slot per direction (0=tx, 1=rx). */
static struct {
    int     active;
    uint8_t chan;
    uint8_t type;
    int     left;
} chaos_tgt[2];

static uint32_t chaos_rng(void)
{
    uint32_t x = chaos_rng_state;
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    chaos_rng_state = x;
    return x;
}

static uint32_t chaos_pct_to_bp(const char *env, double dflt)
{
    const char *v = getenv(env);
    double pct = v ? strtod(v, NULL) : dflt;
    if (pct < 0.0)   pct = 0.0;
    if (pct > 100.0) pct = 100.0;
    return (uint32_t)(pct * 100.0 + 0.5);
}

static void chaos_parse_target(const char *env, int idx, const char *dir)
{
    const char *v = getenv(env);
    if (!v) return;
    unsigned chan = 0; int type = 0, count = 1;
    if (sscanf(v, "%u:%i:%d", &chan, &type, &count) < 2 ||
        chan > 15 || type < 0 || type > 255 || count < 1) {
        fprintf(stderr, "chaos: bad %s='%s' (want chan:type[:count])\n", env, v);
        return;
    }
    chaos_tgt[idx].active = 1;
    chaos_tgt[idx].chan   = (uint8_t)chan;
    chaos_tgt[idx].type   = (uint8_t)type;
    chaos_tgt[idx].left   = count;
    fprintf(stderr, "chaos: targeted %s drop chan=%u type=0x%02X count=%d\n",
            dir, chan, (unsigned)type, count);
}

static void chaos_init_shape(void);

static void chaos_init(void)
{
    chaos_inited = 1;
    chaos_parse_target("UNMOOR_CHAOS_DROP_TX", 0, "tx");
    chaos_parse_target("UNMOOR_CHAOS_DROP_RX", 1, "rx");
    const char *seed = getenv("UNMOOR_CHAOS_SEED");
    chaos_rng_state = seed ? (uint32_t)strtoul(seed, NULL, 0)
                           : (uint32_t)(time(NULL) ^ getpid());
    if (chaos_rng_state == 0) chaos_rng_state = 1; /* xorshift fixpoint */

    chaos_bp = chaos_pct_to_bp("UNMOOR_CHAOS_DROP_PCT", 1.0);
    if (getenv("UNMOOR_CHAOS_VARY_PCT")) {
        chaos_vary_max_bp = chaos_pct_to_bp("UNMOOR_CHAOS_VARY_PCT", 0.0);
        const char *p = getenv("UNMOOR_CHAOS_VARY_SECS");
        if (p) {
            double secs = strtod(p, NULL);
            if (secs >= 0.1) chaos_vary_period_ms = (int64_t)(secs * 1000.0);
        }
        chaos_next_vary_ms = 0; /* re-roll on first frame */
        fprintf(stderr, "chaos: ON, varying rate in [0, %.2f%%] every %llds\n",
                chaos_vary_max_bp / 100.0,
                (long long)(chaos_vary_period_ms / 1000));
    } else {
        fprintf(stderr, "chaos: ON, fixed drop rate %.2f%%\n", chaos_bp / 100.0);
    }
    chaos_init_shape();
}

static int chaos_drop(const char *dir, const uint8_t *frame, size_t len)
{
    if (!chaos_inited) chaos_init();

    /* Targeted deterministic drop first — independent of the random rate. */
    int idx = (dir[0] == 't') ? 0 : 1;
    if (chaos_tgt[idx].active && chaos_tgt[idx].left > 0 && len >= 10 &&
        (frame[8] >> 4) == chaos_tgt[idx].chan &&
        frame[9] == chaos_tgt[idx].type) {
        chaos_tgt[idx].left--;
        fprintf(stderr, "chaos: targeted drop %s chan=%u type=0x%02X (%d left)\n",
                dir, chaos_tgt[idx].chan, chaos_tgt[idx].type,
                chaos_tgt[idx].left);
        return 1;
    }

    if (chaos_vary_max_bp) {
        int64_t now = mono_ms();
        if (now >= chaos_next_vary_ms) {
            chaos_bp = chaos_rng() % (chaos_vary_max_bp + 1);
            chaos_next_vary_ms = now + chaos_vary_period_ms;
            fprintf(stderr, "chaos: drop rate now %.2f%%\n", chaos_bp / 100.0);
        }
    }
    if (chaos_bp == 0) return 0;
    if (chaos_rng() % 10000 >= chaos_bp) return 0;
    chaos_drops++;
    fprintf(stderr, "chaos: dropped %s frame (#%llu, rate %.2f%%)\n",
            dir, (unsigned long long)chaos_drops, chaos_bp / 100.0);
    return 1;
}

/* --- tx shaping: delay + reorder (netem "delay"/"reorder" parity) ------- */

#define CHAOS_QLEN     1024
#define CHAOS_SLOT_MAX (FRAME_MAX_LEN)
#define CHAOS_HOLD_MS  500   /* rescue deadline for a reorder hold */

typedef struct {
    int     used;
    int64_t release_ms;
    size_t  len;
    uint8_t buf[CHAOS_SLOT_MAX];
} chaos_slot_t;

static chaos_slot_t chaos_q[CHAOS_QLEN];   /* delayed frames */
static chaos_slot_t chaos_hold;            /* reorder hold (1 frame) */
static int64_t  chaos_delay_ms;            /* 0 = delay off */
static int64_t  chaos_delay_jitter_ms;
static uint32_t chaos_delay_bp;
static uint32_t chaos_reorder_bp;          /* 0 = reorder off */
static uint64_t chaos_delayed, chaos_reordered, chaos_q_bypass;

static void chaos_init_shape(void)
{
    const char *p = getenv("UNMOOR_CHAOS_DELAY_MS");
    if (p) {
        chaos_delay_ms = (int64_t)strtoll(p, NULL, 0);
        if (chaos_delay_ms < 0) chaos_delay_ms = 0;
    }
    p = getenv("UNMOOR_CHAOS_DELAY_JITTER_MS");
    if (p) {
        chaos_delay_jitter_ms = (int64_t)strtoll(p, NULL, 0);
        if (chaos_delay_jitter_ms < 0) chaos_delay_jitter_ms = 0;
    }
    if (chaos_delay_ms || chaos_delay_jitter_ms) {
        chaos_delay_bp = chaos_pct_to_bp("UNMOOR_CHAOS_DELAY_PCT", 100.0);
        fprintf(stderr, "chaos: tx delay %lldms \xc2\xb1%lldms on %.2f%% of frames\n",
                (long long)chaos_delay_ms, (long long)chaos_delay_jitter_ms,
                chaos_delay_bp / 100.0);
    }
    chaos_reorder_bp = chaos_pct_to_bp("UNMOOR_CHAOS_REORDER_PCT", 0.0);
    if (chaos_reorder_bp)
        fprintf(stderr, "chaos: tx reorder %.2f%% (hold one frame, next "
                        "overtakes; %dms rescue)\n",
                chaos_reorder_bp / 100.0, CHAOS_HOLD_MS);
}

static void chaos_raw_send(session_t *s, const uint8_t *frame, size_t len)
{
    s->transport->ops->send(s->transport, frame, len);
}

/* Returns 1 if the frame was consumed (held or queued) or already sent. */
static int chaos_tx_shape(session_t *s, const uint8_t *frame, size_t len)
{
    if ((!chaos_delay_bp && !chaos_reorder_bp) || len > CHAOS_SLOT_MAX)
        return 0;

    /* Reorder: hold this frame; the NEXT tx frame overtakes it. */
    if (chaos_hold.used) {
        chaos_raw_send(s, frame, len);              /* overtaker goes first */
        chaos_hold.used = 0;
        chaos_raw_send(s, chaos_hold.buf, chaos_hold.len);
        chaos_reordered++;
        fprintf(stderr, "chaos: reordered tx pair (#%llu)\n",
                (unsigned long long)chaos_reordered);
        return 1;
    }
    if (chaos_reorder_bp && chaos_rng() % 10000 < chaos_reorder_bp) {
        memcpy(chaos_hold.buf, frame, len);
        chaos_hold.len        = len;
        chaos_hold.release_ms = mono_ms() + CHAOS_HOLD_MS;
        chaos_hold.used       = 1;
        return 1;
    }

    /* Delay: park the frame until its release time. */
    if (chaos_delay_bp && chaos_rng() % 10000 < chaos_delay_bp) {
        int i;
        for (i = 0; i < CHAOS_QLEN && chaos_q[i].used; i++)
            ;
        if (i == CHAOS_QLEN) {
            /* Queue full: tail-drop, exactly like netem's limit. Sending
             * early instead would leapfrog the whole queue — a mega-
             * reorder real networks don't produce; they drop. */
            chaos_q_bypass++;
            if (chaos_q_bypass == 1 || chaos_q_bypass % 64 == 0)
                fprintf(stderr, "chaos: delay queue full — %llu frames "
                                "tail-dropped (netem limit behavior)\n",
                        (unsigned long long)chaos_q_bypass);
            return 1;
        }
        int64_t d = chaos_delay_ms;
        if (chaos_delay_jitter_ms)
            d += (int64_t)(chaos_rng() % (2 * chaos_delay_jitter_ms + 1))
                 - chaos_delay_jitter_ms;
        if (d < 0) d = 0;
        memcpy(chaos_q[i].buf, frame, len);
        chaos_q[i].len        = len;
        chaos_q[i].release_ms = mono_ms() + d;
        chaos_q[i].used       = 1;
        chaos_delayed++;
        return 1;
    }
    return 0;
}

/* Called from the session_run loop: release due delayed frames (in release
 * order), rescue a stranded reorder hold, clamp poll_ms to the next event. */
static void chaos_pump(session_t *s, int64_t now, int *poll_ms)
{
    if (!chaos_inited) return;

    if (chaos_hold.used && now >= chaos_hold.release_ms) {
        chaos_hold.used = 0;
        chaos_raw_send(s, chaos_hold.buf, chaos_hold.len);
        fprintf(stderr, "chaos: reorder hold rescued (nothing overtook it "
                        "within %dms)\n", CHAOS_HOLD_MS);
    }

    for (;;) {
        int best = -1;
        for (int i = 0; i < CHAOS_QLEN; i++)
            if (chaos_q[i].used &&
                (best < 0 || chaos_q[i].release_ms < chaos_q[best].release_ms))
                best = i;
        if (best < 0) break;
        if (chaos_q[best].release_ms > now) {
            int64_t wait = chaos_q[best].release_ms - now;
            if (wait < *poll_ms) *poll_ms = (int)wait;
            break;
        }
        chaos_q[best].used = 0;
        chaos_raw_send(s, chaos_q[best].buf, chaos_q[best].len);
    }

    if (chaos_hold.used) {
        int64_t wait = chaos_hold.release_ms - now;
        if (wait > 0 && wait < *poll_ms) *poll_ms = (int)wait;
    }
}
#endif /* UNMOOR_CHAOS */

_Static_assert(BULK_LEGS_MAX == MULTIPATH_PATHS_MAX,
               "bulk and multipath leg ceilings diverged");

static int wire_encode_slot(session_t *s, int slot_index);
static int channel_server_decide_stage1(session_t *s, uint8_t slot);
static void session_channel_application_tick(session_t *s, int64_t now_ms,
                                             int *poll_ms,
                                             unsigned int *source_budget);
static void session_channel_application_cleanup_all(session_t *s);
static int channel_application_begin_close(session_t *s, uint8_t slot,
                                           uint32_t code, int64_t now_ms);
static void channel_application_cancel_process(session_t *s, uint8_t slot,
                                               int64_t now_ms);
static void channel_application_reset(session_channel_application_t *app);
static void channel_application_drive_attach_completion(session_t *s,
                                                        uint8_t slot);
static void session_child_lease_fail(session_t *s, uint8_t slot,
                                     int64_t now_ms);
static void session_child_lease_maybe_close(session_t *s);
static int channel_kind_capability_selected(const session_t *s,
                                            uint8_t kind);
static int wire_encode_message(session_t *s);
static int wire_encode_delivery(session_t *s, send_lane_t lane,
                                int64_t now_ms);
static int wire_materialize_delivery(session_t *s, send_lane_t lane,
                                     int64_t now_ms);
static int wire_encode_rekey_work(session_t *s, int64_t now_ms);
static int wire_encode_bulk(session_t *s, send_lane_t lane,
                            int64_t now_ms);
static int wire_materialize_bulk(session_t *s, send_lane_t lane,
                                 int64_t now_ms);
static int rekey_flight_eligible(const session_t *s, int64_t now_ms);
static int rekey_work_eligible(const session_t *s, int64_t now_ms);
static void pq_rekey_metrics_report(session_t *s, int64_t now_ms);
static void rekey_flight_transport_result(session_t *s, int completed,
                                          int64_t now_ms);
static void rekey_work_transport_result(session_t *s, int completed,
                                        int64_t now_ms);
static int delivery_status_combined(const session_t *s);
static uint8_t session_delivery_eligible_lanes(const session_t *s,
                                               int64_t now_ms);
static void session_delivery_attempt_result(session_t *s, int completed,
                                            int64_t now_ms);
static void wire_notify_result(session_t *s, session_tx_done_t done,
                               int completed, int64_t now_ms,
                               uint64_t arg0, uint64_t arg1,
                               uint32_t stream_handle,
                               uint64_t operation_generation,
                               const multipath_handle_t *path_target);
static void pause_for_epoch_sequence_reserve(session_t *s, int64_t now_ms);
static void maybe_start_deferred_rekey(session_t *s, int64_t now_ms);
static int session_bulk_pause_for_epoch(session_t *s, int64_t now_ms);
static int session_multipath_start(session_t *s, int64_t now_ms);
static int session_refresh_path_legs(session_t *s, int64_t now_ms);
static int session_bulk_refresh_paths(session_t *s, int64_t now_ms);
static void maybe_finish_deferred_bulk_activation(session_t *s);
static void session_event_emit(session_t *s, event_log_event_t event,
                               event_log_scope_t scope,
                               event_log_reason_t reason, int leg,
                               uint64_t generation, int64_t now_ms);
static void session_event_latch_close_reason(session_t *s,
                                             event_log_reason_t reason);

static send_mode_t wire_mode(const session_t *s)
{
    /* CLOSING must win even before services_started: it is the only mode
     * whose rate exemption is bounded by abort_remaining. */
    if (s->state == SESSION_CLOSING)
        return SEND_MODE_ABORT;
    if (s->state == SESSION_CONNECTING ||
        s->state == SESSION_KEY_DERIVING)
        return SEND_MODE_PRE_SERVICE;
    /* Mandatory bootstrap epoch-rekey is deliberately pre-service, but it is still
     * REKEY scheduler work.  State must win over services_started or the
     * exact INIT owner can never become eligible. */
    if (s->state == SESSION_REKEYING ||
        (s->state == SESSION_ESTABLISHED &&
         (s->rekey_request_pending ||
          s->rekey_phase == REKEY_S_WAIT_INIT)))
        return SEND_MODE_REKEY;
    if (!s->services_started)
        return SEND_MODE_PRE_SERVICE;
    return SEND_MODE_ESTABLISHED;
}

int session_application_send_eligible(const session_t *s)
{
    return s && s->state == SESSION_ESTABLISHED &&
           wire_mode(s) == SEND_MODE_ESTABLISHED;
}

static uint8_t wire_abort_epoch_bit(session_tx_epoch_t epoch_source)
{
    switch (epoch_source) {
    case SESSION_TX_EPOCH_CURRENT:   return UINT8_C(0x01);
    case SESSION_TX_EPOCH_PENDING:   return UINT8_C(0x02);
    case SESSION_TX_EPOCH_HELLO_KEY: return UINT8_C(0x04);
    default:                         return 0;
    }
}

static unsigned int wire_mask_count(uint8_t mask)
{
    unsigned int count = 0;
    while (mask != 0) {
        count += mask & 1U;
        mask >>= 1;
    }
    return count;
}

static uint8_t wire_mode_mask(send_mode_t mode)
{
    switch (mode) {
    case SEND_MODE_ESTABLISHED: return SESSION_TX_MODE_ESTABLISHED;
    case SEND_MODE_REKEY:       return SESSION_TX_MODE_REKEY;
    case SEND_MODE_PRE_SERVICE: return SESSION_TX_MODE_PRE_SERVICE;
    case SEND_MODE_ABORT:       return SESSION_TX_MODE_ABORT;
    }
    return 0;
}

static unsigned int wire_lane_capacity(send_lane_t lane)
{
    /* The fallback sync-status composition can retain five distinct feedback
     * owners: terminal-state-sync ACK, periodic status, local poll, peer-poll reply, and a
     * compatibility KEEPALIVE_ACK. Multipath path validation is pulled from its
     * fixed table: at most one response and one challenge intent are admitted
     * regardless of the configured 2/4/8/16/32-path capacity. Two successor
     * generations cover the sole immutable in-flight frame and its bounded
     * follow-up; no O(N) wire-intent allocation is permitted. */
    static const uint8_t caps[SEND_LANE_COUNT] = { 1, 10, 7, 1, 1 };
    return lane < SEND_LANE_COUNT ? caps[lane] : 0;
}

static unsigned int wire_lane_count(const session_t *s, send_lane_t lane)
{
    unsigned int count = 0;
    for (size_t i = 0; i < SESSION_TX_SLOT_COUNT; i++)
        if (s->wire_intents[i].valid && s->wire_intents[i].lane == lane)
            count++;
    return count;
}

static session_tx_sequence_class_t wire_sequence_class(
    session_tx_epoch_t epoch_source, uint8_t chan_byte, uint8_t type)
{
    if (epoch_source == SESSION_TX_RAW_FRAME)
        return SESSION_TX_SEQ_NONE;
    if (epoch_source == SESSION_TX_EPOCH_PENDING)
        return SESSION_TX_SEQ_EPOCH_CONTROL;
    if (epoch_source == SESSION_TX_EPOCH_CURRENT &&
        (chan_byte >> 4) == 0U &&
        (rekey_control_type(type) || type == CTRL_CLOSE ||
         type == CTRL_ERROR))
        return SESSION_TX_SEQ_EPOCH_CONTROL;
    return SESSION_TX_SEQ_NORMAL;
}

#define WIRE_PRODUCER_COUNT 8U
#define WIRE_MESSAGE_PRODUCER 2U
#define WIRE_REKEY_PRODUCER    0U
#define WIRE_DELIVERY_PRODUCER 6U
#define WIRE_BULK_PRODUCER     6U
#define WIRE_REKEY_RESPONSE_PRODUCER 7U
#define WIRE_ACTIVE_NONE      (-1)
#define WIRE_ACTIVE_MESSAGE   (-2)
#define WIRE_ACTIVE_DELIVERY  (-3)
#define WIRE_ACTIVE_REKEY     (-4)
#define WIRE_ACTIVE_BULK      (-5)

#define PQ_REKEY_WORK_NONE   0U
#define PQ_REKEY_WORK_BITMAP 1U
#define PQ_REKEY_WORK_BASE   2U
#define PQ_REKEY_WORK_SHARE  3U

static uint8_t *wire_frame_storage(session_t *s, size_t *capacity_out)
{
    uint8_t *storage = s ? s->wire_frame : NULL;
    size_t capacity = s ? sizeof(s->wire_frame) : 0U;

    if (s && s->wire_frame_bulk && s->bulk) {
        storage = bulk_engine_encoded_buffer(s->bulk, &capacity);
    }
    if (capacity_out)
        *capacity_out = capacity;
    return storage;
}

static int64_t wire_bulk_retry_wait(const session_t *s, int64_t now_ms)
{
    if (!s || s->wire_active_slot != WIRE_ACTIVE_BULK ||
        s->wire_frame_len == 0U || !s->bulk)
        return -1;
    return bulk_engine_transport_retry_wait(s->bulk, now_ms);
}

static void wire_frame_reset(session_t *s)
{
    size_t capacity = 0U;
    uint8_t *storage;

    if (!s)
        return;
    storage = wire_frame_storage(s, &capacity);
    if (storage && capacity != 0U)
        crypto_memzero(storage, capacity);
    s->wire_frame_len = 0U;
    s->wire_frame_bulk = 0U;
}

/* Stable producer identities within each lane. They are deliberately
 * independent of queue order: repeated work from one producer cannot keep a
 * different producer behind it. Same-producer exact records remain FIFO. */
static uint8_t wire_producer_id(send_lane_t lane, uint8_t chan_byte,
                                uint8_t type, session_tx_done_t done)
{
    switch (lane) {
    case SEND_LANE_CONTROL:
        return 0;
    case SEND_LANE_FEEDBACK:
        if (done == SESSION_TX_DONE_SYNC_ACK)
            return 0;
        if ((chan_byte >> 4) == 0U && type == CTRL_STATUS_HEARTBEAT)
            return 1;
        if ((chan_byte >> 4) == 0U &&
            (type == CTRL_KEEPALIVE || type == CTRL_KEEPALIVE_ACK))
            return 2;
        if ((chan_byte >> 4) == 0U && type == CTRL_PATH_RESPONSE)
            return 4;
        if ((chan_byte >> 4) == 0U && type == CTRL_PATH_CHALLENGE)
            return 5;
        return 3;
    case SEND_LANE_INTERACTIVE:
        if ((chan_byte >> 4) == 0U && rekey_control_type(type))
            return WIRE_REKEY_RESPONSE_PRODUCER;
        if ((chan_byte >> 4) == 1U && type == PTY_RESIZE)
            return 1;
        if ((chan_byte >> 4) == 1U && type == PTY_SIGNAL)
            return 2;
        if ((chan_byte >> 4) == 1U || done == SESSION_TX_DONE_PTY_OPEN)
            return 3;
        if ((chan_byte >> 4) == 0U &&
            (type == CTRL_HELLO || type == CTRL_HELLO_ACK ||
             type == CTRL_READY))
            return 4;
        return 5;
    case SEND_LANE_RECOVERY:
        /* channel-session has one session-level terminal-state-sync RECOVERY producer.  The sync
         * engine's own recovery cursor arbitrates REPAIR/PROBE/FIN before
         * this layer, so assigning three send-scheduler identities here would let one
         * exact-stream producer occupy three places in the same lane. */
        if (done == SESSION_TX_DONE_SYNC_REPAIR ||
            done == SESSION_TX_DONE_SYNC_PROBE ||
            done == SESSION_TX_DONE_SYNC_FIN)
            return 0;
        return 1;
    case SEND_LANE_NEW:
        return done == SESSION_TX_DONE_SYNC_NEW ? 0 : 1;
    case SEND_LANE_COUNT:
        break;
    }
    return 0;
}

static int wire_target_snapshot(const session_t *s,
                                const multipath_handle_t *target,
                                multipath_token_t *token_out)
{
    multipath_snapshot_t snapshot;

    if (!s || !target || !token_out || !s->multipath_active ||
        target->index >= MULTIPATH_PATHS_MAX || target->generation == 0U ||
        multipath_get_snapshot(&s->multipath, &snapshot) != 0 ||
        snapshot.entry[target->index].state == MULTIPATH_PATH_EMPTY ||
        snapshot.entry[target->index].generation != target->generation)
        return -1;
    for (size_t i = 0; i < sizeof(target->reserved); i++)
        if (target->reserved[i] != 0U)
            return -1;
    *token_out = snapshot.entry[target->index].token;
    return multipath_token_valid(token_out) ? 0 : -1;
}

static int wire_enqueue(session_t *s, send_lane_t lane,
                        session_tx_epoch_t epoch_source,
                        session_tx_sequence_class_t sequence_class,
                        uint8_t mode_mask,
                        uint8_t chan_byte, uint8_t type,
                        const uint8_t *bytes, size_t length,
                        session_tx_done_t done, uint64_t arg0, uint64_t arg1,
                        uint32_t coalesce_key,
                        session_tx_path_policy_t path_policy,
                        const multipath_handle_t *path_target,
                        uint32_t stream_handle,
                        uint64_t operation_generation,
                        uint64_t *ticket_out)
{
    int free_slot = -1;
    session_tx_intent_t *intent;
    multipath_token_t target_token;

    memset(&target_token, 0, sizeof(target_token));

    if (!s || lane < SEND_LANE_CONTROL || lane >= SEND_LANE_COUNT ||
        epoch_source < SESSION_TX_EPOCH_CURRENT ||
        epoch_source > SESSION_TX_RAW_FRAME ||
        sequence_class < SESSION_TX_SEQ_NORMAL ||
        sequence_class > SESSION_TX_SEQ_NONE || mode_mask == 0 ||
        path_policy < SESSION_TX_PATH_PRIMARY ||
        path_policy > SESSION_TX_PATH_TARGET ||
        (path_policy == SESSION_TX_PATH_TARGET && !path_target) ||
        length > FRAME_MAX_LEN || (!bytes && length != 0))
        return -1;
    if (path_policy == SESSION_TX_PATH_TARGET &&
        wire_target_snapshot(s, path_target, &target_token) != 0)
        return -1;

    /* White-box harnesses historically fabricate session_t with memset
     * instead of session_create(). Preserve that deterministic seam while
     * keeping -1 as the real no-active-source sentinel. */
    if (s->wire_next_ticket == 0 && s->wire_next_order == 0 &&
        s->wire_frame_len == 0)
        s->wire_active_slot = -1;

    for (size_t i = 0; i < SESSION_TX_SLOT_COUNT; i++) {
        intent = &s->wire_intents[i];
        if (!intent->valid) {
            if (free_slot < 0)
                free_slot = (int)i;
            continue;
        }
        if (coalesce_key != 0 && intent->inflight &&
            intent->coalesce_key == coalesce_key &&
            intent->lane == (uint8_t)lane &&
            intent->epoch_source == (uint8_t)epoch_source &&
            intent->sequence_class == (uint8_t)sequence_class &&
            intent->mode_mask == mode_mask &&
            intent->chan_byte == chan_byte && intent->type == type &&
            intent->done == (uint8_t)done &&
            intent->stream_handle == stream_handle &&
            intent->operation_generation == operation_generation &&
            intent->length == length && intent->arg0 == arg0 &&
            intent->arg1 == arg1 &&
            intent->path_policy == (uint8_t)path_policy &&
            (path_policy != SESSION_TX_PATH_TARGET ||
             memcmp(&intent->path_target, path_target,
                    sizeof(*path_target)) == 0) &&
            (path_policy != SESSION_TX_PATH_TARGET ||
             multipath_token_equal(&intent->path_token,
                                   &target_token)) &&
            (length == 0 || memcmp(intent->bytes, bytes, length) == 0)) {
            /* A completion-owned retry deadline can remain due while its
             * first immutable frame is blocked or partial.  Re-admitting the
             * identical logical record must mean "already pending", not a
             * second slot that can outlive the state transition caused by
             * the first completion (most critically epoch-rekey's final ACK).
             * Differing absolute/latest state still gets one bounded
             * successor slot because the in-flight ciphertext is immutable. */
            if (ticket_out)
                *ticket_out = intent->ticket;
            return 0;
        }
        /* channel-session has one session-level terminal-state-sync producer per lane. A retained
         * absolute record for one handle cannot be overwritten by another
         * handle or admitted beside it under the same producer identity. */
        if (stream_handle != 0U && coalesce_key != 0U &&
            intent->coalesce_key == coalesce_key &&
            intent->lane == (uint8_t)lane &&
            intent->stream_handle != stream_handle)
            return -1;
        if (coalesce_key != 0 && !intent->inflight &&
            intent->coalesce_key == coalesce_key &&
            intent->lane == (uint8_t)lane) {
            /* Absolute/latest-state records replace only a record that has
             * not been selected. An in-flight ciphertext is immutable. */
            intent->epoch_source = (uint8_t)epoch_source;
            intent->mode_mask = mode_mask;
            intent->chan_byte = chan_byte;
            intent->type = type;
            intent->done = (uint8_t)done;
            intent->stream_handle = stream_handle;
            intent->operation_generation = operation_generation;
            intent->sequence_class = (uint8_t)sequence_class;
            intent->producer_id = wire_producer_id(
                lane, chan_byte, type, done);
            intent->path_policy = (uint8_t)path_policy;
            if (path_target)
                intent->path_target = *path_target;
            else
                memset(&intent->path_target, 0,
                       sizeof(intent->path_target));
            intent->path_token = target_token;
            intent->length = (uint16_t)length;
            intent->arg0 = arg0;
            intent->arg1 = arg1;
            if (length != 0)
                memcpy(intent->bytes, bytes, length);
            if (ticket_out)
                *ticket_out = intent->ticket;
            return 0;
        }
    }

    if (free_slot < 0 || wire_lane_count(s, lane) >= wire_lane_capacity(lane)) {
        fprintf(stderr,
                "session: send-scheduler %s lane logical slots full — send refused loudly\n",
                lane == SEND_LANE_CONTROL ? "control" :
                lane == SEND_LANE_FEEDBACK ? "feedback" :
                lane == SEND_LANE_INTERACTIVE ? "interactive" :
                lane == SEND_LANE_RECOVERY ? "recovery" : "new");
        return -1;
    }

    intent = &s->wire_intents[free_slot];
    memset(intent, 0, sizeof(*intent));
    intent->valid = 1;
    intent->lane = (uint8_t)lane;
    intent->epoch_source = (uint8_t)epoch_source;
    intent->mode_mask = mode_mask;
    intent->chan_byte = chan_byte;
    intent->type = type;
    intent->done = (uint8_t)done;
    intent->sequence_class = (uint8_t)sequence_class;
    intent->producer_id = wire_producer_id(lane, chan_byte, type, done);
    intent->path_policy = (uint8_t)path_policy;
    if (path_target)
        intent->path_target = *path_target;
    intent->path_token = target_token;
    intent->length = (uint16_t)length;
    intent->coalesce_key = coalesce_key;
    intent->stream_handle = stream_handle;
    intent->ticket = ++s->wire_next_ticket;
    intent->order = ++s->wire_next_order;
    intent->operation_generation = operation_generation;
    intent->arg0 = arg0;
    intent->arg1 = arg1;
    if (length != 0)
        memcpy(intent->bytes, bytes, length);
    if (ticket_out)
        *ticket_out = intent->ticket;
    return 0;
}

static int wire_slot_eligible(const session_tx_intent_t *intent,
                              uint8_t mode_mask)
{
    return intent->valid && !intent->inflight &&
           (intent->mode_mask & mode_mask) != 0;
}

static uint8_t wire_eligible_mask(session_t *s, int64_t now_ms)
{
    uint8_t mask = 0;
    uint8_t mode_mask = wire_mode_mask(wire_mode(s));

    for (size_t i = 0; i < SESSION_TX_SLOT_COUNT; i++)
        if (wire_slot_eligible(&s->wire_intents[i], mode_mask))
            mask |= (uint8_t)SEND_LANE_BIT(s->wire_intents[i].lane);
    if (s->wire_message.valid && !s->wire_message.inflight &&
        (mode_mask & SESSION_TX_MODE_ESTABLISHED) != 0)
        mask |= (uint8_t)SEND_LANE_BIT(SEND_LANE_NEW);
    if ((mode_mask & SESSION_TX_MODE_REKEY) != 0 &&
        rekey_work_eligible(s, now_ms))
        mask |= (uint8_t)SEND_LANE_BIT(SEND_LANE_INTERACTIVE);
    /* The delivery-class service normally contributes only in ESTABLISHED.  Its
     * candidate filter additionally exposes the single object-1 feedback
     * producer needed to heal a lost bootstrap-rekey final ACK. */
    mask |= session_delivery_eligible_lanes(s, now_ms);
    if (s->bulk_activated &&
        session_bulk_refresh_paths(s, now_ms) != 0) {
        fprintf(stderr,
                "session: FATAL: bulk-transfer path eligibility diverged from multipath\n");
        s->run_failed = 1;
        s->wire_protocol_failure = 1;
        return 0;
    }
    if (s->bulk_activated &&
        (mode_mask & SESSION_TX_MODE_ESTABLISHED) != 0)
        mask |= bulk_engine_eligible_mask(s->bulk, now_ms);
    return mask;
}

static int wire_select_slot(const session_t *s, send_lane_t lane,
                            int64_t now_ms)
{
    int selected = -1;
    unsigned int best_distance = WIRE_PRODUCER_COUNT;
    uint64_t best_order = UINT64_MAX;
    uint8_t mode_mask = wire_mode_mask(wire_mode(s));
    uint8_t cursor = s->wire_producer_cursor[lane];

    for (size_t i = 0; i < SESSION_TX_SLOT_COUNT; i++) {
        const session_tx_intent_t *intent = &s->wire_intents[i];
        unsigned int distance;
        if (!wire_slot_eligible(intent, mode_mask) || intent->lane != lane)
            continue;
        distance = ((unsigned int)intent->producer_id +
                    WIRE_PRODUCER_COUNT - cursor) % WIRE_PRODUCER_COUNT;
        if (distance < best_distance ||
            (distance == best_distance && intent->order < best_order)) {
            selected = (int)i;
            best_distance = distance;
            best_order = intent->order;
        }
    }
    if (lane == SEND_LANE_NEW && s->wire_message.valid &&
        !s->wire_message.inflight &&
        (mode_mask & SESSION_TX_MODE_ESTABLISHED) != 0) {
        unsigned int distance =
            (WIRE_MESSAGE_PRODUCER + WIRE_PRODUCER_COUNT - cursor) %
            WIRE_PRODUCER_COUNT;
        if (distance < best_distance ||
            (distance == best_distance && s->wire_message.order < best_order))
            return -2;
    }
    if (lane == SEND_LANE_INTERACTIVE &&
        (mode_mask & SESSION_TX_MODE_REKEY) != 0 &&
        rekey_work_eligible(s, now_ms)) {
        unsigned int distance =
            (WIRE_REKEY_PRODUCER + WIRE_PRODUCER_COUNT - cursor) %
            WIRE_PRODUCER_COUNT;
        if (distance < best_distance ||
            (distance == best_distance &&
             s->rekey_flight.order < best_order))
            return WIRE_ACTIVE_REKEY;
    }
    if ((session_delivery_eligible_lanes(s, now_ms) &
         (uint8_t)SEND_LANE_BIT(lane)) != 0) {
        unsigned int distance =
            (WIRE_DELIVERY_PRODUCER + WIRE_PRODUCER_COUNT - cursor) %
            WIRE_PRODUCER_COUNT;
        if (distance < best_distance)
            return WIRE_ACTIVE_DELIVERY;
    }
    if (s->bulk_activated &&
        (bulk_engine_eligible_mask(s->bulk, now_ms) &
         (uint8_t)SEND_LANE_BIT(lane)) != 0) {
        unsigned int distance =
            (WIRE_BULK_PRODUCER + WIRE_PRODUCER_COUNT - cursor) %
            WIRE_PRODUCER_COUNT;
        if (distance < best_distance)
            return WIRE_ACTIVE_BULK;
    }
    return selected;
}

static void wire_path_plan_clear(session_t *s)
{
    if (!s)
        return;
    memset(&s->wire_path_plan, 0, sizeof(s->wire_path_plan));
    s->wire_path_plan_active = 0;
    s->wire_path_ordinal = 0;
    s->wire_path_blocked_mask = 0;
    s->wire_path_terminal_mask = 0;
    s->wire_path_success_mask = 0U;
    s->wire_path_need_replica_begin = 0;
}

static session_tx_path_policy_t wire_active_path_policy(const session_t *s)
{
    if (s->wire_active_slot >= 0)
        return (session_tx_path_policy_t)
            s->wire_intents[(size_t)s->wire_active_slot].path_policy;
    if (s->wire_active_slot == WIRE_ACTIVE_REKEY && s->services_started)
        return SESSION_TX_PATH_CRITICAL;
    if (s->wire_active_slot == WIRE_ACTIVE_DELIVERY &&
        delivery_status_combined(s) &&
        s->wire_delivery.owner_id == DELIVERY_LATEST_SYSTEM_OBJECT_ID) {
        switch ((session_delivery_attempt_kind_t)s->wire_delivery.kind) {
        case SESSION_DELIVERY_ATTEMPT_LATEST_HEAD:
        case SESSION_DELIVERY_ATTEMPT_LATEST_BLOCK:
        case SESSION_DELIVERY_ATTEMPT_LATEST_STATUS:
            return SESSION_TX_PATH_CRITICAL;
        case SESSION_DELIVERY_ATTEMPT_RELIABLE_DATA:
        case SESSION_DELIVERY_ATTEMPT_RELIABLE_STATUS:
        case SESSION_DELIVERY_ATTEMPT_NONE:
            break;
        }
    }
    return SESSION_TX_PATH_PRIMARY;
}

static int wire_prepare_path_plan(session_t *s)
{
    session_tx_path_policy_t policy;
    int rc;

    wire_path_plan_clear(s);
    if (!s->multipath_active)
        return 0;
    if (s->wire_active_slot == WIRE_ACTIVE_BULK) {
        bulk_engine_attempt_view_t attempt;
        bulk_engine_path_snapshot_t bulk_paths;
        multipath_snapshot_t snapshot;
        uint8_t selected_leg;
        uint32_t bit;
        unsigned int leg;

        memset(&attempt, 0, sizeof(attempt));
        memset(&bulk_paths, 0, sizeof(bulk_paths));
        if (bulk_engine_active_attempt(s->bulk, &attempt) != BULK_RC_OK ||
            bulk_engine_path_snapshot(s->bulk, &bulk_paths) != BULK_RC_OK ||
            multipath_get_snapshot(&s->multipath, &snapshot) != 0 ||
            snapshot.path_limit != bulk_paths.path_count)
            return -1;
        if (attempt.valid) {
            /* sender_leg is the source's local scheduling-table index.  It
             * selects exactly one immutable multipath token/generation here; the
             * receiver never maps the authenticated label onto its own
             * table, fd, replay state, or delivery bitmap. */
            if (attempt.sender_leg >= snapshot.path_limit)
                return -1;
            selected_leg = attempt.sender_leg;
        } else {
            /* A fixed-size bulk-transfer control record also obeys the per-generation
             * MTU view. Prefer the current primary while usable, otherwise
             * take the lowest usable validated slot. */
            selected_leg = bulk_paths.primary_leg;
            /* primary_leg may be BULK_ENGINE_NO_LEG, so range-check before
             * shifting by it; out of range is never eligible either way. */
            if (selected_leg >= snapshot.path_limit ||
                (bulk_paths.eligible_mask &
                 (UINT32_C(1) << selected_leg)) == 0U) {
                selected_leg = snapshot.path_limit;
                for (leg = 0U; leg < snapshot.path_limit; leg++) {
                    if ((bulk_paths.eligible_mask &
                         (UINT32_C(1) << leg)) != 0U) {
                        selected_leg = (uint8_t)leg;
                        break;
                    }
                }
                if (selected_leg >= snapshot.path_limit)
                    return -1;
            }
        }
        bit = UINT32_C(1) << selected_leg;
        if ((bit & (snapshot.validated_mask | snapshot.primary_mask)) == 0U ||
            snapshot.entry[selected_leg].generation !=
                bulk_paths.generation[selected_leg])
            return -1;
        rc = multipath_plan_target(
            &s->multipath, &snapshot.entry[selected_leg].token,
            &s->wire_path_plan);
        if (rc != 1 || s->wire_path_plan.count != 1U) {
            fprintf(stderr,
                    "session: FATAL: bulk-transfer could not bind one record to one multipath generation\n");
            wire_path_plan_clear(s);
            return -1;
        }
        s->wire_path_plan_active = 1;
        return 0;
    }
    policy = wire_active_path_policy(s);
    if (policy == SESSION_TX_PATH_TARGET) {
        const session_tx_intent_t *intent;
        if (s->wire_active_slot < 0)
            return -1;
        intent = &s->wire_intents[(size_t)s->wire_active_slot];
        if (intent->path_target.index >= s->multipath.path_limit)
            return -1;
        s->wire_path_plan.slot_mask =
            UINT32_C(1) << intent->path_target.index;
        s->wire_path_plan.count = 1U;
        s->wire_path_plan.item[0].handle = intent->path_target;
        s->wire_path_plan.item[0].token = intent->path_token;
        rc = 1;
    } else if (policy == SESSION_TX_PATH_CRITICAL) {
        rc = multipath_plan_critical(&s->multipath,
                                     &s->wire_path_plan);
    } else {
        rc = multipath_plan_primary(&s->multipath,
                                    &s->wire_path_plan);
    }
    if (rc <= 0 || s->wire_path_plan.count == 0U ||
        s->wire_path_plan.count > MULTIPATH_PLAN_COPIES_MAX) {
        fprintf(stderr,
                "session: FATAL: multipath could not snapshot a send path\n");
        wire_path_plan_clear(s);
        return -1;
    }
    s->wire_path_plan_active = 1;
    return 0;
}

static int wire_transport_step(session_t *s,
                               const multipath_token_t *path,
                               int64_t now_ms)
{
    const uint8_t *frame;
    size_t capacity = 0U;
    int64_t attempt_now_ms;

    frame = wire_frame_storage(s, &capacity);
    if (!frame || s->wire_frame_len == 0U ||
        s->wire_frame_len > capacity)
        return TRANSPORT_SEND_FAILED;
    /* Re-sample at the syscall boundary. A loop timestamp taken before
     * producer/timer work can be arbitrarily stale and would shorten traffic-profile's
     * promised spacing between physical flow-creating sends. */
    attempt_now_ms = session_physical_now_ms(s, now_ms);
#if defined(UNMOOR_CHAOS) && UNMOOR_CHAOS
    if (!s->wire_chaos_applied) {
        s->wire_chaos_applied = 1;
        if (chaos_drop("tx", frame, s->wire_frame_len))
            return TRANSPORT_SEND_COMPLETE;
        if (chaos_tx_shape(s, frame, s->wire_frame_len))
            return TRANSPORT_SEND_COMPLETE; /* copied/held/queued/sent */
    }
#endif
    if (!path && s->multipath_requested &&
        (s->event_path_open_mask & UINT32_C(1)) == 0U) {
        /* The bootstrap leg is already carrying negotiation before multipath can
         * activate. Its first physical send is therefore the only truthful
         * leg-0 open edge; service activation must not synthesize one later. */
        s->event_path_open_mask |= UINT32_C(1);
        session_event_emit(
            s, EVENT_LOG_EVENT_OPEN, EVENT_LOG_SCOPE_LEG,
            EVENT_LOG_REASON_PATH_FIRST_ATTEMPT, 0, 0U, attempt_now_ms);
    }
    if (path) {
        if (!s->is_server && s->multipath_stagger_initialized) {
            int opened = traffic_stagger_note_physical_attempt(
                &s->multipath_stagger, path->local_leg, attempt_now_ms);

            if (opened < 0)
            {
                fprintf(stderr,
                        "session: FATAL: traffic-profile attempted an unadmitted client path\n");
                s->run_failed = 1;
                s->wire_protocol_failure = 1;
                return TRANSPORT_SEND_FAILED;
            }
            (void)opened;
        }
        if (s->wire_path_plan_active &&
            s->wire_path_ordinal < s->wire_path_plan.count) {
            const multipath_handle_t *handle =
                &s->wire_path_plan.item[s->wire_path_ordinal].handle;
            uint32_t bit = UINT32_C(1) << handle->index;

            if ((s->event_path_open_mask & bit) == 0U) {
                s->event_path_open_mask |= bit;
                session_event_emit(
                    s, EVENT_LOG_EVENT_OPEN, EVENT_LOG_SCOPE_LEG,
                    EVENT_LOG_REASON_PATH_FIRST_ATTEMPT,
                    (int)handle->index, handle->generation,
                    attempt_now_ms);
            }
        }
        if (!s->transport->ops->send_step_to)
            return TRANSPORT_SEND_FAILED;
        return s->transport->ops->send_step_to(s->transport, path,
                                                frame,
                                                s->wire_frame_len);
    }
    if (s->transport->ops->send_step)
        return s->transport->ops->send_step(s->transport,
                                             frame,
                                             s->wire_frame_len);
    return s->transport->ops->send(s->transport,
                                   frame,
                                   s->wire_frame_len) == 0
        ? TRANSPORT_SEND_COMPLETE : TRANSPORT_SEND_FAILED;
}

static int wire_release_active(session_t *s, int completed, int64_t now_ms)
{
    int message_terminal = 0;

    if (s->wire_active_slot >= 0) {
        session_tx_intent_t saved;
        session_tx_intent_t *intent =
            &s->wire_intents[(size_t)s->wire_active_slot];
        saved = *intent;
        crypto_memzero(intent, sizeof(*intent));
        s->wire_producer_cursor[saved.lane] =
            (uint8_t)((saved.producer_id + 1U) % WIRE_PRODUCER_COUNT);
        if (!completed)
            s->wire_failed_ticket = saved.ticket;
        wire_notify_result(s, (session_tx_done_t)saved.done, completed,
                           now_ms, saved.arg0, saved.arg1,
                           saved.stream_handle,
                           saved.operation_generation,
                           &saved.path_target);
        crypto_memzero(&saved, sizeof(saved));
    } else if (s->wire_active_slot == WIRE_ACTIVE_MESSAGE) {
        session_tx_message_t *message = &s->wire_message;
        s->wire_producer_cursor[SEND_LANE_NEW] =
            (uint8_t)((WIRE_MESSAGE_PRODUCER + 1U) %
                      WIRE_PRODUCER_COUNT);
        if (completed) {
            message->index++;
            message->inflight = 0;
            if (message->index >= message->count) {
                crypto_memzero(message, sizeof(*message));
                message_terminal = 1;
            }
        } else {
            s->wire_failed_ticket = message->ticket;
            crypto_memzero(message, sizeof(*message));
            message_terminal = 1;
        }
    } else if (s->wire_active_slot == WIRE_ACTIVE_DELIVERY) {
        s->wire_producer_cursor[s->wire_delivery.lane] =
            (uint8_t)((WIRE_DELIVERY_PRODUCER + 1U) %
                      WIRE_PRODUCER_COUNT);
        session_delivery_attempt_result(s, completed, now_ms);
    } else if (s->wire_active_slot == WIRE_ACTIVE_REKEY) {
        s->wire_producer_cursor[SEND_LANE_INTERACTIVE] =
            (uint8_t)((WIRE_REKEY_PRODUCER + 1U) % WIRE_PRODUCER_COUNT);
        rekey_work_transport_result(s, completed, now_ms);
    } else if (s->wire_active_slot == WIRE_ACTIVE_BULK) {
        bulk_engine_attempt_view_t attempt;
        send_lane_t lane = SEND_LANE_NEW;

        memset(&attempt, 0, sizeof(attempt));
        if (bulk_engine_active_attempt(s->bulk, &attempt) == 0 &&
            attempt.valid && attempt.lane < SEND_LANE_COUNT)
            lane = attempt.lane;
        s->wire_producer_cursor[lane] =
            (uint8_t)((WIRE_BULK_PRODUCER + 1U) % WIRE_PRODUCER_COUNT);
        if (bulk_engine_transport_result(
                s->bulk,
                completed ? SEND_STEP_COMPLETE : SEND_STEP_FAILED,
                now_ms) != 0) {
            fprintf(stderr,
                    "session: FATAL: bulk-transfer transport owner rejected its terminal result\n");
            s->run_failed = 1;
            s->wire_protocol_failure = 1;
        }
        s->bulk_tx_type = 0U;
        s->bulk_tx_lane = 0U;
        s->bulk_tx_plaintext_len = 0U;
        /* A deferred epoch transition may start only after this exact
         * old-epoch bulk-transfer record reaches COMPLETE/FAILED. */
        message_terminal = 1;
    }
    s->wire_active_slot = WIRE_ACTIVE_NONE;
    return message_terminal;
}

/* A hard UDP failure emitted no partial frame, even though send-scheduler charged its
 * physical syscall.  When close/transport/app-result authority ends the
 * retry, retire both owners without asking the transport to cancel bytes it
 * never retained.  A terminal engine has already cleared its tx owner; a
 * running engine still receives exactly one FAILED callback. */
static int wire_retire_bulk_retry(session_t *s, int64_t now_ms,
                                  int engine_running)
{
    int callback_failed = 0;

    if (!s || s->wire_active_slot != WIRE_ACTIVE_BULK ||
        s->wire_frame_len == 0U || !s->wire_scheduler.in_flight)
        return -1;
    if (send_scheduler_fail_retained(&s->wire_scheduler) != 0)
        return -1;
    if (engine_running) {
        (void)wire_release_active(s, 0, now_ms);
        if (s->wire_protocol_failure)
            callback_failed = 1;
    } else {
        s->wire_active_slot = WIRE_ACTIVE_NONE;
        s->bulk_tx_type = 0U;
        s->bulk_tx_lane = 0U;
        s->bulk_tx_plaintext_len = 0U;
    }
    wire_frame_reset(s);
    s->wire_chaos_applied = 0;
    wire_path_plan_clear(s);
    return callback_failed ? -1 : 0;
}

static int wire_record_bulk_send_failure(session_t *s, int64_t now_ms)
{
    if (!s || s->wire_active_slot != WIRE_ACTIVE_BULK || !s->bulk ||
        bulk_engine_transport_retryable_failure(s->bulk, now_ms) !=
            BULK_RC_OK ||
        send_scheduler_retryable_failure(&s->wire_scheduler, now_ms) != 0) {
        if (s) {
            fprintf(stderr,
                    "session: FATAL: bulk-retry could not retain failed bulk datagram\n");
            s->run_failed = 1;
            s->wire_protocol_failure = 1;
        }
        return -1;
    }
    return 0;
}

static uint32_t wire_path_ordinal_mask(uint8_t count)
{
    if (count == 0U || count > MULTIPATH_PLAN_COPIES_MAX)
        return 0U;
    return (UINT32_C(1) << count) - UINT32_C(1);
}

static int wire_path_select_next(session_t *s, int honor_blocked)
{
    uint32_t all_mask;
    uint32_t candidate_mask;
    unsigned int offset;

    if (!s || !s->wire_path_plan_active ||
        s->wire_path_plan.count == 0U)
        return -1;
    all_mask = wire_path_ordinal_mask(s->wire_path_plan.count);
    candidate_mask = all_mask & ~s->wire_path_terminal_mask;
    if (honor_blocked)
        candidate_mask &= ~s->wire_path_blocked_mask;
    if (candidate_mask == 0U && honor_blocked) {
        s->wire_path_blocked_mask = 0;
        candidate_mask = all_mask & ~s->wire_path_terminal_mask;
    }
    if (candidate_mask == 0U)
        return 0;
    for (offset = 1U; offset <= s->wire_path_plan.count; offset++) {
        uint8_t candidate = (uint8_t)
            ((s->wire_path_ordinal + offset) %
             s->wire_path_plan.count);
        if ((candidate_mask & (UINT32_C(1) << candidate)) != 0U) {
            s->wire_path_ordinal = candidate;
            return 1;
        }
    }
    return -1;
}

static int wire_attempt(session_t *s, int64_t now_ms)
{
    int tr;
    int had_partial;
    send_step_result_t sr;
    int message_terminal = 0;
    multipath_token_t path;

    if (!s->wire_frame_len)
        return -1;
    if (s->wire_path_plan_active) {
        int resolve_rc;
        int logical_terminal;
        int logical_completed;

        if (s->wire_path_ordinal >= s->wire_path_plan.count) {
            fprintf(stderr,
                    "session: FATAL: multipath path-plan ordinal escaped its bound\n");
            s->run_failed = 1;
            s->wire_protocol_failure = 1;
            return -1;
        }
        resolve_rc = multipath_plan_resolve(
            &s->multipath, &s->wire_path_plan,
            s->wire_path_ordinal, &path);
        if (resolve_rc == MULTIPATH_IGNORED) {
            int next_rc;
            uint32_t all_mask =
                wire_path_ordinal_mask(s->wire_path_plan.count);
            s->wire_path_terminal_mask |=
                UINT32_C(1) << s->wire_path_ordinal;
            if (s->wire_path_success_mask != 0U)
                s->wire_path_blocked_mask = 0;
            logical_terminal = s->wire_path_terminal_mask == all_mask;
            logical_completed = logical_terminal &&
                                s->wire_path_success_mask != 0U;
            if (send_scheduler_replica_skip(
                    &s->wire_scheduler, logical_terminal,
                    logical_completed) != 0) {
                s->run_failed = 1;
                s->wire_protocol_failure = 1;
                return -1;
            }
            if (!logical_terminal) {
                next_rc = wire_path_select_next(
                    s, s->wire_path_success_mask == 0U);
                if (next_rc != 1) {
                    s->run_failed = 1;
                    s->wire_protocol_failure = 1;
                    return -1;
                }
                s->wire_path_need_replica_begin = 1U;
                return 0;
            }
            message_terminal = wire_release_active(
                s, logical_completed, now_ms);
            wire_frame_reset(s);
            s->wire_chaos_applied = 0;
            wire_path_plan_clear(s);
            if (message_terminal)
                maybe_start_deferred_rekey(s, now_ms);
            return logical_completed ? 0 : -1;
        }
        if (resolve_rc != MULTIPATH_ACCEPTED) {
            fprintf(stderr,
                    "session: FATAL: malformed multipath retained path plan\n");
            s->run_failed = 1;
            s->wire_protocol_failure = 1;
            return -1;
        }

        tr = wire_transport_step(s, &path, now_ms);
        if (tr == TRANSPORT_SEND_TOO_LARGE &&
            s->wire_active_slot == WIRE_ACTIVE_BULK &&
            bulk_engine_transport_mtu_failure(
                s->bulk,
                s->wire_path_plan.item[s->wire_path_ordinal].handle.index,
                now_ms) !=
                BULK_RC_OK) {
            fprintf(stderr,
                    "session: FATAL: bulk-transfer rejected a typed EMSGSIZE result\n");
            s->run_failed = 1;
            s->wire_protocol_failure = 1;
            return -1;
        }
        switch (tr) {
        case TRANSPORT_SEND_WOULD_BLOCK:
            sr = SEND_STEP_WOULD_BLOCK;
            break;
        case TRANSPORT_SEND_COMPLETE:
            sr = SEND_STEP_COMPLETE;
            break;
        case TRANSPORT_SEND_PROGRESS:
            sr = SEND_STEP_PROGRESS;
            break;
        default:
            sr = SEND_STEP_FAILED;
            break;
        }
        if (sr == SEND_STEP_FAILED && tr != TRANSPORT_SEND_TOO_LARGE &&
            s->wire_active_slot == WIRE_ACTIVE_BULK)
            return wire_record_bulk_send_failure(s, now_ms);
        if (sr == SEND_STEP_PROGRESS) {
            (void)send_scheduler_copy_result(
                &s->wire_scheduler, sr, 0, 0, now_ms);
            fprintf(stderr,
                    "session: FATAL: UDP multipath reported a partial datagram\n");
            s->wire_transport_broken = 1;
            s->run_failed = 1;
            s->wire_protocol_failure = 1;
            return -1;
        }
        if (sr == SEND_STEP_WOULD_BLOCK) {
            uint32_t all_mask =
                wire_path_ordinal_mask(s->wire_path_plan.count);
            uint32_t current_bit =
                UINT32_C(1) << s->wire_path_ordinal;
            int next_rc;

            if (send_scheduler_copy_result(
                    &s->wire_scheduler, sr, 0, 0, now_ms) != 0)
                return -1;
            if (s->wire_path_success_mask != 0U) {
                s->wire_path_terminal_mask |= current_bit;
                logical_terminal =
                    s->wire_path_terminal_mask == all_mask;
                if (send_scheduler_replica_skip(
                        &s->wire_scheduler, logical_terminal,
                        logical_terminal) != 0)
                    return -1;
                if (logical_terminal) {
                    message_terminal = wire_release_active(s, 1, now_ms);
                    wire_frame_reset(s);
                    s->wire_chaos_applied = 0;
                    wire_path_plan_clear(s);
                    if (message_terminal)
                        maybe_start_deferred_rekey(s, now_ms);
                    return 0;
                }
                next_rc = wire_path_select_next(s, 0);
            } else {
                s->wire_path_blocked_mask |= current_bit;
                if (send_scheduler_replica_rotate(
                        &s->wire_scheduler) != 0)
                    return -1;
                next_rc = wire_path_select_next(s, 1);
            }
            if (next_rc != 1) {
                fprintf(stderr,
                        "session: FATAL: multipath retained no retryable path\n");
                s->run_failed = 1;
                s->wire_protocol_failure = 1;
                return -1;
            }
            s->wire_path_need_replica_begin = 1U;
            return 0;
        }

        if (sr == SEND_STEP_COMPLETE) {
            s->wire_path_success_mask |=
                UINT32_C(1) << s->wire_path_ordinal;
            /* A path that blocked before the first success now receives its
             * one required post-success best-effort attempt. */
            s->wire_path_blocked_mask = 0;
        }
        s->wire_path_terminal_mask |=
            UINT32_C(1) << s->wire_path_ordinal;
        {
            uint32_t all_mask =
                wire_path_ordinal_mask(s->wire_path_plan.count);
            logical_terminal = s->wire_path_terminal_mask == all_mask;
        }
        logical_completed = logical_terminal &&
                            s->wire_path_success_mask != 0U;
        if (send_scheduler_copy_result(&s->wire_scheduler, sr,
                                       logical_terminal,
                                       logical_completed, now_ms) != 0)
            return -1;
        if (!logical_terminal) {
            int next_rc = wire_path_select_next(
                s, s->wire_path_success_mask == 0U);
            if (next_rc != 1) {
                s->run_failed = 1;
                s->wire_protocol_failure = 1;
                return -1;
            }
            s->wire_path_need_replica_begin = 1U;
            return 0;
        }
        message_terminal = wire_release_active(
            s, logical_completed, now_ms);
        wire_frame_reset(s);
        s->wire_chaos_applied = 0;
        wire_path_plan_clear(s);
        if (message_terminal)
            maybe_start_deferred_rekey(s, now_ms);
        return logical_completed ? 0 : -1;
    }

    had_partial = s->wire_scheduler.in_flight_charged != 0;
    tr = wire_transport_step(s, NULL, now_ms);
    if (tr == TRANSPORT_SEND_TOO_LARGE &&
        s->wire_active_slot == WIRE_ACTIVE_BULK &&
        bulk_engine_transport_mtu_failure(s->bulk, 0U, now_ms) !=
            BULK_RC_OK) {
        fprintf(stderr,
                "session: FATAL: bulk-transfer rejected a typed EMSGSIZE result\n");
        s->run_failed = 1;
        s->wire_protocol_failure = 1;
        return -1;
    }
    switch (tr) {
    case TRANSPORT_SEND_WOULD_BLOCK:
        sr = SEND_STEP_WOULD_BLOCK;
        break;
    case TRANSPORT_SEND_PROGRESS:
        sr = SEND_STEP_PROGRESS;
        break;
    case TRANSPORT_SEND_COMPLETE:
        sr = SEND_STEP_COMPLETE;
        break;
    default:
        sr = SEND_STEP_FAILED;
        break;
    }
    if (sr == SEND_STEP_FAILED && tr != TRANSPORT_SEND_TOO_LARGE &&
        s->wire_active_slot == WIRE_ACTIVE_BULK)
        return wire_record_bulk_send_failure(s, now_ms);
    if (send_scheduler_step_result(&s->wire_scheduler, sr, now_ms) != 0)
        return -1;
    if (sr == SEND_STEP_FAILED && had_partial) {
        /* A length-prefixed stream cannot be reused after a prefix/body was
         * partially emitted and the continuation failed. Close that exact
         * transport before any later session could append a new frame. UDP
         * never reports PROGRESS, so ordinary datagram send errors retain
         * the roaming/later-retry behavior. */
        fprintf(stderr,
                "session: transport failed after partial frame — closing transport\n");
        s->wire_transport_broken = 1;
        s->run_failed = 1;
        /* The caller owns the transport object. session_run observes this
         * flag and unwinds before another I/O; its outer owner then closes
         * and frees the transport exactly once. */
    }
    if (sr == SEND_STEP_COMPLETE || sr == SEND_STEP_FAILED) {
        message_terminal = wire_release_active(
            s, sr == SEND_STEP_COMPLETE, now_ms);
        wire_frame_reset(s);
        s->wire_chaos_applied = 0;
        if (message_terminal)
            maybe_start_deferred_rekey(s, now_ms);
    }
    return sr == SEND_STEP_FAILED ? -1 : 0;
}

/* A poll/recv terminal condition means the outer owner will close this exact
 * transport. No retained frame can legally continue on a later transport.
 * Abandon an untouched/EAGAIN attempt quietly at that ownership boundary;
 * a prefix/body that made partial progress is a loud framing failure. */
void session_transport_closed(session_t *s)
{
    int64_t now_ms;
    int completed;

    if (!s || s->wire_frame_len == 0)
        return;
    now_ms = mono_ms();
    if (s->wire_active_slot == WIRE_ACTIVE_BULK && s->bulk) {
        bulk_engine_result_t result = bulk_engine_result(s->bulk, NULL);
        if (result != BULK_ENGINE_RESULT_RUNNING ||
            wire_bulk_retry_wait(s, now_ms) >= 0) {
            if (wire_retire_bulk_retry(
                    s, now_ms, result == BULK_ENGINE_RESULT_RUNNING) != 0) {
                s->run_failed = 1;
                s->wire_protocol_failure = 1;
            }
            fprintf(stderr,
                    "session: transport ended with a retained bulk datagram retry — discarded\n");
            return;
        }
    }
    if (s->wire_path_plan_active) {
        uint32_t all_mask;
        unsigned int skipped = 0;

        completed = s->wire_path_success_mask != 0U;
        all_mask = wire_path_ordinal_mask(s->wire_path_plan.count);
        while (s->wire_path_terminal_mask != all_mask) {
            uint32_t bit = UINT32_C(1) << s->wire_path_ordinal;
            int begin_rc;
            int terminal;

            if ((s->wire_path_terminal_mask & bit) != 0U) {
                if (wire_path_select_next(s, 0) != 1)
                    break;
                continue;
            }
            send_scheduler_begin_turn(&s->wire_scheduler);
            if (s->wire_scheduler.replica_ready)
                begin_rc = send_scheduler_replica_begin(
                    &s->wire_scheduler);
            else
                begin_rc = send_scheduler_retry_begin(
                    &s->wire_scheduler);
            if (begin_rc != 1) {
                s->run_failed = 1;
                s->wire_protocol_failure = 1;
                break;
            }
            s->wire_path_terminal_mask |= bit;
            terminal = s->wire_path_terminal_mask == all_mask;
            if (send_scheduler_replica_skip(
                    &s->wire_scheduler, terminal,
                    terminal && completed) != 0) {
                s->run_failed = 1;
                s->wire_protocol_failure = 1;
                break;
            }
            skipped++;
            if (!terminal && wire_path_select_next(s, 0) != 1) {
                s->run_failed = 1;
                s->wire_protocol_failure = 1;
                break;
            }
        }
        (void)wire_release_active(s, completed, now_ms);
        fprintf(stderr,
                completed
                    ? "session: transport ended after multipath delivery — %u unresolved copy/copies skipped\n"
                    : "session: transport ended with unsent multipath frame — %u copy/copies discarded\n",
                skipped);
        wire_frame_reset(s);
        s->wire_active_slot = -1;
        s->wire_chaos_applied = 0;
        wire_path_plan_clear(s);
        return;
    }
    if (s->wire_scheduler.in_flight_charged) {
        fprintf(stderr,
                "session: transport ended after partial frame — closing loudly\n");
        s->run_failed = 1;
    } else {
        fprintf(stderr,
                "session: transport ended with an unsent retained frame — discarded\n");
    }
    wire_frame_reset(s);
    s->wire_active_slot = -1;
    s->wire_chaos_applied = 0;
    wire_path_plan_clear(s);
}

/* Terminal close is an exclusive scheduler mode. An ordinary frame for
 * which the transport returned only WOULD_BLOCK has emitted zero bytes and
 * can be abandoned safely; letting it retry after CLOSING would violate the
 * abort boundary. A charged/partial stream frame is deliberately retained
 * and must finish its exact prefix/body before terminal control can run. */
static void wire_abandon_untouched_on_close(session_t *s, int64_t now_ms)
{
    int message_terminal;

    if (!s || s->wire_frame_len == 0 || !s->wire_scheduler.in_flight)
        return;
    if (s->wire_active_slot == WIRE_ACTIVE_BULK && s->bulk) {
        bulk_engine_result_t result = bulk_engine_result(s->bulk, NULL);
        if (result != BULK_ENGINE_RESULT_RUNNING ||
            wire_bulk_retry_wait(s, now_ms) >= 0) {
            if (wire_retire_bulk_retry(
                    s, now_ms, result == BULK_ENGINE_RESULT_RUNNING) != 0) {
                fprintf(stderr,
                        "session: FATAL: could not retire failed bulk datagram retry on close\n");
                s->run_failed = 1;
                s->wire_protocol_failure = 1;
            }
            return;
        }
    }
    if (s->wire_scheduler.in_flight_charged)
        return;
    if (!s->transport->ops->send_cancel_untouched ||
        s->transport->ops->send_cancel_untouched(s->transport) != 0) {
        fprintf(stderr,
                "session: FATAL: transport could not cancel untouched frame on close\n");
        s->wire_transport_broken = 1;
        s->run_failed = 1;
        s->wire_protocol_failure = 1;
        return;
    }
    if (send_scheduler_abandon_untouched(&s->wire_scheduler) != 0) {
        fprintf(stderr,
                "session: FATAL: could not abandon untouched frame on close\n");
        s->run_failed = 1;
        s->wire_protocol_failure = 1;
        return;
    }
    message_terminal = wire_release_active(s, 0, now_ms);
    wire_frame_reset(s);
    s->wire_chaos_applied = 0;
    wire_path_plan_clear(s);
    if (message_terminal)
        maybe_start_deferred_rekey(s, now_ms);
}

static uint32_t wire_normal_sequence_limit(const session_t *s)
{
    return s->epoch_rekey_enabled
         ? REKEY_SEQ_RESERVE_START : UINT32_MAX - 1000U;
}

static uint64_t wire_message_remaining(const session_tx_message_t *message)
{
    if (!message->valid || message->index >= message->count)
        return 0;
    return (uint64_t)message->count - message->index;
}

static uint64_t wire_message_sequence_budget(const session_t *s,
                                             uint64_t remaining)
{
    uint64_t lanes;

    if (remaining == 0U)
        return 0U;
    /* The fifth lane is deliberately empty in every legacy profile. Keep
     * fragmentation's historical F-I-R-N near-wrap boundary byte-for-byte there;
     * only a selected channel session can consume the additional C grant. */
    lanes = session_channelised_active(s)
          ? (uint64_t)SEND_LANE_COUNT
          : (uint64_t)SEND_LANE_COUNT - 1U;
    return lanes * remaining - (lanes - 1U);
}

static int wire_sequence_failure(session_t *s, const char *reason)
{
    fprintf(stderr, "session: FATAL: %s — closing before sequence use\n",
            reason);
    s->run_failed = 1;
    s->wire_protocol_failure = 1;
    session_close(s);
    return -1;
}

/* Selection-time boundary, after no frame is retained and before a grant.
 * Admission-time checks are only a fast refusal: other lanes may consume
 * sequence values while a record waits.  The first fragmentation selection reserves
 * the exact worst legal interleave: legacy F-I-R-N uses 4*n-3; selected
 * channel-session C-F-I-R-N uses 5*n-4 current-epoch frames. */
static int wire_prepare_sequence_boundary(session_t *s, int64_t now_ms)
{
    session_tx_message_t *message = &s->wire_message;
    uint64_t limit = wire_normal_sequence_limit(s);
    uint64_t remaining;
    uint64_t required;
    int normal_pending = 0;

    if (wire_mode(s) != SEND_MODE_ESTABLISHED)
        return 0;

    if (message->valid && message->started) {
        remaining = wire_message_remaining(message);
        if (message->started_epoch != s->epoch ||
            (uint64_t)s->tx_seq + remaining > limit)
            return wire_sequence_failure(
                s, "started authenticated message lost its epoch reserve");
    } else if (message->valid) {
        remaining = wire_message_remaining(message);
        required = wire_message_sequence_budget(s, remaining);
        if ((uint64_t)s->tx_seq + required > limit) {
            if (s->epoch_rekey_enabled) {
                pause_for_epoch_sequence_reserve(s, now_ms);
                return s->state == SESSION_CLOSING ? -1 : 1;
            }
            return wire_sequence_failure(
                s, "legacy message lacks close-before-wrap headroom");
        }
    }

    for (size_t i = 0; i < SESSION_TX_SLOT_COUNT; i++) {
        const session_tx_intent_t *intent = &s->wire_intents[i];
        if (intent->valid && !intent->inflight &&
            intent->epoch_source == SESSION_TX_EPOCH_CURRENT &&
            intent->sequence_class == SESSION_TX_SEQ_NORMAL) {
            normal_pending = 1;
            break;
        }
    }
    if (session_delivery_eligible_lanes(s, now_ms) != 0)
        normal_pending = 1;
    if (s->bulk_activated &&
        bulk_engine_eligible_mask(s->bulk, now_ms) != 0)
        normal_pending = 1;
    if (normal_pending && (uint64_t)s->tx_seq >= limit) {
        if (s->epoch_rekey_enabled) {
            pause_for_epoch_sequence_reserve(s, now_ms);
            return s->state == SESSION_CLOSING ? -1 : 1;
        }
        return wire_sequence_failure(
            s, "legacy queued record reached close-before-wrap boundary");
    }
    return 0;
}

static int wire_drive_turn(session_t *s, int64_t now_ms)
{
    send_lane_t lane;
    uint8_t eligible;
    int selected;
    int grant;
    int boundary;
    int message_terminal;
    int materialize_rc = 0;
    int encode_rc;
    int drive_rc;

    if (!s)
        return -1;
    if (s->wire_frame_len) {
        int begin_rc;
        int64_t retry_wait = wire_bulk_retry_wait(s, now_ms);
        if (retry_wait > 0)
            return 0;
        if (s->wire_path_plan_active &&
            s->wire_path_need_replica_begin) {
            begin_rc = send_scheduler_replica_begin(
                &s->wire_scheduler);
            if (begin_rc == 1)
                s->wire_path_need_replica_begin = 0;
        } else {
            begin_rc = send_scheduler_retry_begin(&s->wire_scheduler);
        }
        if (begin_rc != 1)
            return -1;
        drive_rc = wire_attempt(s, now_ms);
        if (s->wire_frame_len == 0U)
            maybe_finish_deferred_bulk_activation(s);
        return drive_rc;
    }

    boundary = wire_prepare_sequence_boundary(s, now_ms);
    if (boundary < 0)
        return -1;

    eligible = wire_eligible_mask(s, now_ms);
    if (eligible == 0)
        return 0;
    grant = send_scheduler_grant(&s->wire_scheduler, eligible,
                                 wire_mode(s), now_ms, &lane);
    if (grant <= 0)
        return grant;
    selected = wire_select_slot(s, lane, now_ms);
    if (selected == -1) {
        (void)send_scheduler_step_result(&s->wire_scheduler,
                                         SEND_STEP_FAILED, now_ms);
        return -1;
    }
    s->wire_active_slot = selected;
    if (selected >= 0)
        s->wire_intents[(size_t)selected].inflight = 1;
    else if (selected == WIRE_ACTIVE_MESSAGE)
        s->wire_message.inflight = 1;

    if (selected == WIRE_ACTIVE_DELIVERY)
        materialize_rc = wire_materialize_delivery(s, lane, now_ms);
    else if (selected == WIRE_ACTIVE_BULK)
        materialize_rc = wire_materialize_bulk(s, lane, now_ms);
    if (materialize_rc != 0) {
        if (send_scheduler_abandon_untouched(
                &s->wire_scheduler) != 0)
            s->wire_protocol_failure = 1;
        if (selected == WIRE_ACTIVE_DELIVERY)
            crypto_memzero(&s->wire_delivery, sizeof(s->wire_delivery));
        else if (selected == WIRE_ACTIVE_BULK) {
            (void)bulk_engine_transport_result(
                s->bulk, SEND_STEP_FAILED, now_ms);
            s->bulk_tx_type = 0U;
            s->bulk_tx_lane = 0U;
            s->bulk_tx_plaintext_len = 0U;
        }
        s->wire_active_slot = WIRE_ACTIVE_NONE;
        fprintf(stderr,
                "session: FATAL: %s pretransport materialization failed (%d)\n",
                selected == WIRE_ACTIVE_BULK ? "bulk-transfer" : "delivery-class",
                materialize_rc);
        s->run_failed = 1;
        s->wire_protocol_failure = 1;
        return -1;
    }

    /* multipath snapshots route generations before any AEAD/SEQ use. Delivery-class has
     * already materialized enough owner identity to classify only its
     * reserved system-object liveness family; no retry owner is claimed. */
    if (wire_prepare_path_plan(s) != 0) {
        if (send_scheduler_abandon_untouched(
                &s->wire_scheduler) != 0)
            s->wire_protocol_failure = 1;
        if (selected >= 0)
            s->wire_intents[(size_t)selected].inflight = 0;
        else if (selected == WIRE_ACTIVE_MESSAGE)
            s->wire_message.inflight = 0;
        else if (selected == WIRE_ACTIVE_DELIVERY)
            crypto_memzero(&s->wire_delivery, sizeof(s->wire_delivery));
        else if (selected == WIRE_ACTIVE_BULK) {
            (void)bulk_engine_transport_result(
                s->bulk, SEND_STEP_FAILED, now_ms);
            s->bulk_tx_type = 0U;
            s->bulk_tx_lane = 0U;
            s->bulk_tx_plaintext_len = 0U;
        }
        s->wire_active_slot = WIRE_ACTIVE_NONE;
        s->run_failed = 1;
        s->wire_protocol_failure = 1;
        return -1;
    }
    encode_rc = selected >= 0 ? wire_encode_slot(s, selected) :
                selected == WIRE_ACTIVE_MESSAGE ? wire_encode_message(s) :
                selected == WIRE_ACTIVE_DELIVERY
                    ? wire_encode_delivery(s, lane, now_ms)
                : selected == WIRE_ACTIVE_BULK
                    ? wire_encode_bulk(s, lane, now_ms)
                    : wire_encode_rekey_work(s, now_ms);
    if (encode_rc != 0) {
        wire_path_plan_clear(s);
        if (selected == WIRE_ACTIVE_DELIVERY) {
            if (send_scheduler_abandon_untouched(
                    &s->wire_scheduler) != 0) {
                fprintf(stderr,
                        "session: FATAL: could not cancel failed delivery-class "
                        "pretransport encode\n");
                s->run_failed = 1;
                s->wire_protocol_failure = 1;
            }
            crypto_memzero(&s->wire_delivery,
                           sizeof(s->wire_delivery));
            wire_frame_reset(s);
            s->wire_active_slot = WIRE_ACTIVE_NONE;
            if (!s->wire_protocol_failure) {
                fprintf(stderr,
                        "session: FATAL: delivery-class pretransport materialization "
                        "failed (%d)\n", encode_rc);
                s->run_failed = 1;
                s->wire_protocol_failure = 1;
            }
            return -1;
        }
        if (selected == WIRE_ACTIVE_REKEY) {
            if (send_scheduler_abandon_untouched(
                    &s->wire_scheduler) != 0)
                fprintf(stderr,
                        "session: FATAL: could not cancel failed epoch-rekey "
                        "pretransport encode\n");
            wire_frame_reset(s);
            s->wire_active_slot = WIRE_ACTIVE_NONE;
            fprintf(stderr,
                    "session: FATAL: epoch-rekey pretransport materialization "
                    "failed (%d)\n", encode_rc);
            s->run_failed = 1;
            s->wire_protocol_failure = 1;
            return -1;
        }
        if (selected == WIRE_ACTIVE_BULK) {
            if (send_scheduler_abandon_untouched(
                    &s->wire_scheduler) != 0)
                s->wire_protocol_failure = 1;
            (void)bulk_engine_transport_result(
                s->bulk, SEND_STEP_FAILED, now_ms);
            wire_frame_reset(s);
            s->bulk_tx_type = 0U;
            s->bulk_tx_lane = 0U;
            s->bulk_tx_plaintext_len = 0U;
            s->wire_active_slot = WIRE_ACTIVE_NONE;
            fprintf(stderr,
                    "session: FATAL: bulk-transfer pretransport encode failed (%d)\n",
                    encode_rc);
            s->run_failed = 1;
            s->wire_protocol_failure = 1;
            return -1;
        }
        (void)send_scheduler_step_result(&s->wire_scheduler,
                                         SEND_STEP_FAILED, now_ms);
        message_terminal = wire_release_active(s, 0, now_ms);
        wire_frame_reset(s);
        if (message_terminal)
            maybe_start_deferred_rekey(s, now_ms);
        return -1;
    }
    drive_rc = wire_attempt(s, now_ms);
    if (s->wire_frame_len == 0U)
        maybe_finish_deferred_bulk_activation(s);
    return drive_rc;
}

/* send-scheduler F1 seam: the scheduler paces REKEY only once service has started and
 * learns that fact from the session.  A re-init (session create, enter-idle,
 * a paced test fixture) wipes the scheduler, so every re-init must re-apply
 * the session's services_started here or a post-service rekey retry would
 * silently run rate-exempt. */
int session_wire_scheduler_reset(session_t *s, int64_t rate_bps,
                                 uint16_t effective_mtu, int64_t now_ms)
{
    int rc;

    if (!s)
        return -1;
    rc = send_scheduler_init(&s->wire_scheduler, rate_bps, effective_mtu,
                             now_ms);
    if (rc == 0 && s->services_started)
        send_scheduler_service_started(&s->wire_scheduler);
    return rc;
}

void session_send_scheduler_turn(session_t *s, int64_t now_ms)
{
    if (!s)
        return;
    send_scheduler_begin_turn(&s->wire_scheduler);
    s->wire_driving = 1;
    (void)wire_drive_turn(s, now_ms);
    s->wire_driving = 0;
}

int session_set_physical_clock(session_t *s, session_clock_now_fn now_fn,
                               void *context)
{
    if (!s || !now_fn || s->wire_driving || s->wire_frame_len != 0U)
        return -1;
    s->physical_clock_now = now_fn;
    s->physical_clock_context = context;
    return 0;
}

int session_send_scheduler_pending(session_t *s)
{
    return s && (s->wire_frame_len != 0 ||
                 wire_eligible_mask(s, mono_ms()) != 0);
}

/* -------------------------------------------------------------------------
 * Forward declarations
 * ---------------------------------------------------------------------- */
static int  send_ctrl_error(session_t *s, uint16_t code);
static void track_err_session(session_t *s);
void session_replay_stashed_frame(session_t *s);
static void enter_idle(session_t *s);
static event_log_reason_t channel_code_event_reason(uint32_t code);
int session_close_tick(session_t *s, int64_t now_ms);
static int  session_activate_services(session_t *s);
static void session_delivery_reset(session_t *s);
static int  session_delivery_initialize_context(session_t *s);
static int  session_delivery_bind(session_t *s);
static int  session_delivery_prepare_context(session_t *s);
static void session_delivery_start(session_t *s, int64_t now_ms);
static int  send_ready_frame(session_t *s, uint8_t flags,
                             session_tx_done_t done);
static void rekey_fail(session_t *s, const char *reason);
static void establish_session(session_t *s);
static void finish_epoch_barrier(session_t *s);
static void maybe_complete_deferred_epoch_adoption(session_t *s,
                                                   int64_t now_ms);
static void rekey_flight_reset(session_t *s);
static void rekey_flight_semantic_retire(session_t *s, uint8_t type,
                                         uint32_t epoch);
static int pq_rekey_selected(const session_t *s);
static void pq_rekey_exchange_reset(session_t *s);

/* -------------------------------------------------------------------------
 * Replay window
 * ---------------------------------------------------------------------- */

static int replay_accept(replay_window_t *r, uint32_t seq)
{
    /* Assert the replay window fits in the 31-bit modular newness
     * comparison used below. Any replay window that exceeds 2^31 - 1 makes
     * (seq - hwm) < 0x80000000 ambiguous between "newer" and "old enough to
     * wrap". Place adjacent to the use site so a future widener of
     * REPLAY_WINDOW trips the assert immediately. */
    _Static_assert(REPLAY_WINDOW <= 0x7FFFFFFF,
        "replay window must fit in 31 bits for modular comparison");

    if (!r->initialized) {
        r->hwm = seq;
        memset(r->bitmap, 0, sizeof(r->bitmap));
        r->bitmap[seq % REPLAY_WINDOW] = 1;
        r->initialized = 1;
        return 1;
    }
    /* Use modular comparison: seq is newer if (seq - hwm) < 0x80000000 */
    if ((uint32_t)(seq - r->hwm) < 0x80000000U && seq != r->hwm) {
        /* seq > hwm (modular) */
        uint32_t advance = seq - r->hwm;
        if (advance >= REPLAY_WINDOW) {
            /* Whole-window wipe: every existing slot is now older than
             * the window. */
            memset(r->bitmap, 0, sizeof(r->bitmap));
        } else if (advance >= 16) {
            /* Clear `advance` consecutive circular slots starting
             * at (hwm+1) % REPLAY_WINDOW with at most two memsets, instead
             * of walking up to 255 individual bytes. The bitmap is a
             * circular array of 1-byte flags indexed by seq%W, so a memset
             * on the cleared range is logically equivalent to the per-slot
             * loop in the else branch below — just much faster. */
            uint32_t start = (r->hwm + 1) % REPLAY_WINDOW;
            uint32_t end_excl = start + advance;
            if (end_excl <= REPLAY_WINDOW) {
                memset(r->bitmap + start, 0, advance);
            } else {
                memset(r->bitmap + start, 0, REPLAY_WINDOW - start);
                memset(r->bitmap, 0, end_excl - REPLAY_WINDOW);
            }
        } else {
            /* Small advance: keep the per-slot loop with the
             * underflow guard for the early-window phase (hwm+i < W,
             * slot was never written, and is already 0). */
            for (uint32_t i = 1; i <= advance; i++) {
                if ((uint64_t)r->hwm + i >= REPLAY_WINDOW) {
                    uint32_t evict = r->hwm + i - REPLAY_WINDOW;
                    r->bitmap[evict % REPLAY_WINDOW] = 0;
                }
            }
        }
        r->hwm = seq;
        r->bitmap[seq % REPLAY_WINDOW] = 1;
        return 1;
    }
    /* seq < hwm (modular): accept only if within REPLAY_WINDOW behind hwm.
     * Use modular distance, not (uint64_t)seq+W>hwm — that widening
     * ignores wrap and accepts seq=0xFFFFFFFE when hwm=5. * requires all replay comparisons to be modular. */
    uint32_t back = r->hwm - seq;
    if (back < REPLAY_WINDOW) {
        if (r->bitmap[seq % REPLAY_WINDOW]) return 0;  /* already seen */
        r->bitmap[seq % REPLAY_WINDOW] = 1;
        return 1;
    }
    return 0; /* below window */
}

/* -------------------------------------------------------------------------
 * session_create
 * ---------------------------------------------------------------------- */

session_t *session_create(transport_t *t,
                          const uint8_t psk[32],
                          const uint8_t pair_id[4])
{
    session_t *s = calloc(1, sizeof(*s));
    if (!s) {
        fprintf(stderr, "session_create: calloc failed\n");
        return NULL;
    }

    s->transport = t;
    memcpy(s->psk,     psk,     32);
    memcpy(s->pair_id, pair_id, 4);

    /* mlock key material */
    crypto_mlock(s->psk,         32);
    crypto_mlock(s->hello_key,   32);
    crypto_mlock(s->session_key, 32);
    crypto_mlock(s->pending_key, 32);
    crypto_mlock(s->rekey_private, 32);
    crypto_mlock(s->pq_mlkem_private, sizeof(s->pq_mlkem_private));
    crypto_mark_dontdump(s, sizeof *s);

    s->state = SESSION_IDLE;
    s->supported_caps = UNMOOR_CAP_DEFAULT_SUPPORTED;
    s->required_caps = UNMOOR_CAP_DEFAULT_REQUIRED;
    s->offered_caps = s->supported_caps;
    s->keepalive_period_ms = 2000;
    s->liveness_timeout_ms = 8000;  /* 4 × keepalive */

    /* PTY defaults */
    s->pty_master_fd      = -1;
    s->pty_child_pid      = 0;
    s->current_mtu        = UNMOOR_TERMINAL_PLAINTEXT_MAX;
    s->client_exit_code   = 0;
    s->should_exit        = 0;
    s->raw_mode_active    = 0;
    s->pty_open_ack_seen  = 0;
    s->is_client_pty      = 0;
    s->wire_active_slot   = -1;
    event_log_sink_init(&s->event_sink);
    preauth_budget_init(&s->preauth_budget);
    channel_session_table_init(&s->channel_table);
    attach_manager_init(&s->attach_manager);
    channel_process_table_init(&s->channel_processes);
    child_transfer_table_init(&s->child_transfers);
    for (uint8_t slot = 1U; slot < CHANNEL_SESSION_SLOTS; slot++)
        s->channel_application[slot].session = s;
    if (multipath_init(&s->multipath, MULTIPATH_PATHS_MIN) != 0) {
        session_destroy(s);
        return NULL;
    }
    client_escape_init(&s->client_escape);

    /* Producer-overrun mitigation: UNMOOR_PACE_BPS caps how fast this endpoint
     * reads bulk data (PTY master on the server, stdin on the client)
     * into the tunnel. Symmetric — each side paces its own sending
     * direction from its own environment. */
    const char *pace_env = getenv("UNMOOR_PACE_BPS");
    if (pace_env && *pace_env) {
        char *end = NULL;
        errno = 0;
        long long bps = strtoll(pace_env, &end, 10);
        if (errno == 0 && end != pace_env && *end == '\0' && bps > 0) {
            const int64_t mtu = s->current_mtu ? s->current_mtu
                                               : UNMOOR_TERMINAL_PLAINTEXT_MAX;
            const int64_t max_burst = 16 * mtu;
            int64_t burst = (int64_t)bps / 4;
            if (burst < 1) burst = 1;
            if (burst > max_burst) burst = max_burst;
            s->pace_bps             = (int64_t)bps;
            s->pace_burst_milli     = burst * 1000;
            s->pace_credit_milli    = s->pace_burst_milli;
            s->pace_last_refill_ms  = mono_ms();
            fprintf(stderr, "session: pacing enabled (%lld B/s), "
                            "burst=%lld datagram-equivalent bytes\n",
                    bps, (long long)burst);
        }
        errno = 0;
    }

    if (session_wire_scheduler_reset(s, s->pace_bps,
                            s->current_mtu, mono_ms()) != 0) {
        fprintf(stderr, "session_create: wire scheduler init failed\n");
        session_wipe_secrets(s);
        crypto_munlock(s->psk,         32);
        crypto_munlock(s->hello_key,   32);
        crypto_munlock(s->session_key, 32);
        crypto_munlock(s->pending_key, 32);
        crypto_munlock(s->rekey_private, 32);
        crypto_munlock(s->pq_mlkem_private,
                       sizeof(s->pq_mlkem_private));
        free(s);
        return NULL;
    }
    rekey_flight_reset(s);

    return s;
}

static int session_has_latest_configuration(const session_t *s)
{
    unsigned int slot;

    if (!s)
        return 0;
    for (slot = 0; slot < DELIVERY_LATEST_OBJECTS; slot++)
        if (s->delivery_latest_tx_config[slot].configured ||
            s->delivery_latest_rx_config[slot].configured)
            return 1;
    return 0;
}

static int session_has_reliable_configuration(const session_t *s)
{
    unsigned int slot;

    if (!s)
        return 0;
    for (slot = 0; slot < DELIVERY_RELIABLE_FLOWS; slot++)
        if (s->delivery_reliable_tx_config[slot].configured ||
            s->delivery_reliable_rx_config[slot].configured)
            return 1;
    return 0;
}

static int latest_status_slot_reserved(uint32_t supported)
{
    const uint32_t combined = UNMOOR_CAP_STATUS_HEARTBEAT_V1 |
                              UNMOOR_CAP_LATEST_BLOCK_D31_V1;
    return (supported & combined) == combined;
}

static int delivery_configuration_fits_capabilities(const session_t *s,
                                                    uint32_t capabilities)
{
    if (!s)
        return 0;
    return !latest_status_slot_reserved(capabilities) ||
           (!s->delivery_latest_tx_config[0].configured &&
            !s->delivery_latest_rx_config[0].configured);
}

int session_set_capabilities(session_t *s, uint32_t supported,
                             uint32_t required)
{
    uint32_t multipath_cap;
    const uint32_t d36_bundle =
        UNMOOR_CAP_CHANNEL_SESSION_D36_V1 |
        UNMOOR_CAP_CHANNEL_TERMINAL_D36_V1 |
        UNMOOR_CAP_PTY_V1 | UNMOOR_CAP_FRAGMENT_D21_V1 |
        UNMOOR_CAP_PTY_SYNC_V1;
    const uint32_t terminal_caps =
        UNMOOR_CAP_PTY_V1 | UNMOOR_CAP_FRAGMENT_D21_V1 |
        UNMOOR_CAP_PTY_SYNC_V1 | UNMOOR_CAP_STATUS_HEARTBEAT_V1 |
        UNMOOR_CAP_LATEST_BLOCK_D31_V1 |
        UNMOOR_CAP_RELIABLE_DGRAM_D31_V1;

    if (!s || s->state != SESSION_IDLE || s->configuration_frozen ||
        (required & ~supported) != 0)
        return -1;
    if (((supported | required) &
         (UNMOOR_CAP_CHANNEL_SESSION_D36_V1 |
          UNMOOR_CAP_CHANNEL_KINDS_D36_MASK)) != 0U) {
        if (!s->channelised_requested || s->bulk_enabled ||
            (supported & d36_bundle) != d36_bundle ||
            (required & d36_bundle) != d36_bundle ||
            (supported & UNMOOR_CAP_CHANNEL_KINDS_D36_MASK) !=
                (UNMOOR_CAP_CHANNEL_TERMINAL_D36_V1 |
                 UNMOOR_CAP_CHANNEL_EXEC_D36_V1) ||
            (required & UNMOOR_CAP_CHANNEL_KINDS_D36_MASK) !=
                UNMOOR_CAP_CHANNEL_TERMINAL_D36_V1 ||
            ((supported | required) &
             (UNMOOR_CAP_LATEST_BLOCK_D31_V1 |
              UNMOOR_CAP_RELIABLE_DGRAM_D31_V1 |
              UNMOOR_CAP_BULK_FILE_D33_V1)) != 0U)
            return -1;
    } else if (s->channelised_requested) {
        return -1;
    }
    if (((supported | required) & UNMOOR_CAP_BULK_FILE_D33_V1) != 0U) {
        if (!s->bulk_enabled ||
            (supported & UNMOOR_CAP_BULK_FILE_D33_V1) == 0U ||
            (required & UNMOOR_CAP_BULK_FILE_D33_V1) == 0U ||
            (supported & terminal_caps) != 0U ||
            (required & terminal_caps) != 0U)
            return -1;
    } else if (s->bulk_enabled) {
        return -1;
    }
    if (((required & UNMOOR_CAP_LATEST_BLOCK_D31_V1) != 0 &&
         s->current_mtu < UNMOOR_LATEST_BLOCK_D31_MIN_MTU) ||
        ((required & UNMOOR_CAP_RELIABLE_DGRAM_D31_V1) != 0 &&
         s->current_mtu < UNMOOR_RELIABLE_DGRAM_D31_MIN_MTU))
        return -1;
    if ((session_has_latest_configuration(s) &&
         (supported & UNMOOR_CAP_LATEST_BLOCK_D31_V1) == 0) ||
        (session_has_reliable_configuration(s) &&
         (supported & UNMOOR_CAP_RELIABLE_DGRAM_D31_V1) == 0) ||
        !delivery_configuration_fits_capabilities(s, supported))
        return -1;
    if (s->epoch_rekey_enabled) {
        const uint32_t needed = s->bulk_enabled
            ? (UNMOOR_CAP_BULK_FILE_D33_V1 |
               UNMOOR_CAP_EPOCH_REKEY_D28_V1)
            : (UNMOOR_CAP_PTY_V1 | UNMOOR_CAP_PTY_SYNC_V1 |
               UNMOOR_CAP_EPOCH_REKEY_D28_V1 |
               UNMOOR_CAP_STATUS_HEARTBEAT_V1);
        if ((supported & needed) != needed || (required & needed) != needed)
            return -1;
    } else if ((supported | required) & UNMOOR_CAP_EPOCH_REKEY_D28_V1) {
        /* The bit is not a generic control capability. Only the explicit
         * epoch-engine setup API may advertise it. */
        return -1;
    }
    if (((supported | required) & UNMOOR_CAP_PQ_HYBRID_D45_V1) != 0U) {
        if (!s->pq_hybrid_enabled || !s->epoch_rekey_enabled ||
            (supported & UNMOOR_CAP_PQ_HYBRID_D45_V1) == 0U ||
            (required & UNMOOR_CAP_PQ_HYBRID_D45_V1) == 0U)
            return -1;
    } else if (s->pq_hybrid_enabled) {
        return -1;
    }
    multipath_cap = negotiation_multipath_capability(
        s->multipath_path_count);
    if (s->multipath_requested) {
        if (multipath_cap == 0U ||
            (supported & UNMOOR_CAP_MULTIPATH_D32_MASK) != multipath_cap ||
            (required & UNMOOR_CAP_MULTIPATH_D32_MASK) !=
                (s->multipath_required ? multipath_cap : 0U))
            return -1;
    } else if (((supported | required) &
                UNMOOR_CAP_MULTIPATH_D32_MASK) != 0U) {
        /* Like epoch-rekey, these bits own one exact local engine and transport
         * contract. Generic capability mutation cannot advertise them. */
        return -1;
    }
    s->supported_caps = supported;
    s->required_caps = required;
    s->offered_caps = supported;
    return 0;
}

int session_enable_channelised_terminal(session_t *s, uint16_t rows,
                                        uint16_t columns,
                                        const char *label)
{
    const uint32_t supported_bundle =
        UNMOOR_CAP_CHANNEL_SESSION_D36_V1 |
        UNMOOR_CAP_CHANNEL_TERMINAL_D36_V1 |
        UNMOOR_CAP_CHANNEL_EXEC_D36_V1 |
        UNMOOR_CAP_PTY_V1 | UNMOOR_CAP_FRAGMENT_D21_V1 |
        UNMOOR_CAP_PTY_SYNC_V1;
    const uint32_t required_bundle =
        UNMOOR_CAP_CHANNEL_SESSION_D36_V1 |
        UNMOOR_CAP_CHANNEL_TERMINAL_D36_V1 |
        UNMOOR_CAP_PTY_V1 | UNMOOR_CAP_FRAGMENT_D21_V1 |
        UNMOOR_CAP_PTY_SYNC_V1;
    const uint32_t incompatible =
        UNMOOR_CAP_LATEST_BLOCK_D31_V1 |
        UNMOOR_CAP_RELIABLE_DGRAM_D31_V1 |
        UNMOOR_CAP_BULK_FILE_D33_V1 |
        UNMOOR_CAP_CHANNEL_KINDS_D36_MASK |
        UNMOOR_CAP_CHANNEL_SESSION_D36_V1;
    channel_session_open_t descriptor;
    uint8_t canonical[CHANNEL_SESSION_OPEN_BYTES];
    size_t label_length = label ? strlen(label) : 0U;
    uint32_t old_supported;
    uint32_t old_required;

    if (!s || s->state != SESSION_IDLE || s->configuration_frozen ||
        s->bulk_enabled || rows == 0U || columns == 0U ||
        label_length > CHANNEL_SESSION_LABEL_MAX)
        return -1;
    memset(&descriptor, 0, sizeof(descriptor));
    descriptor.version = 1U;
    descriptor.kind = CHANNEL_KIND_TERMINAL;
    descriptor.label_length = (uint8_t)label_length;
    descriptor.handle = UINT32_C(0x11); /* validate template canonically */
    descriptor.parameter0 = (uint32_t)rows | ((uint32_t)columns << 16);
    if (label_length != 0U)
        memcpy(descriptor.label, label, label_length);
    if (channel_session_open_encode(&descriptor, canonical) != 0)
        return -1;
    descriptor.handle = 0U;

    old_supported = s->supported_caps;
    old_required = s->required_caps;
    s->channelised_requested = 1;
    s->channel_first_template = descriptor;
    if (session_set_capabilities(
            s, (old_supported & ~incompatible) | supported_bundle,
            (old_required & ~incompatible) | required_bundle) != 0) {
        s->channelised_requested = 0;
        memset(&s->channel_first_template, 0,
               sizeof(s->channel_first_template));
        return -1;
    }
    channel_session_table_init(&s->channel_table);
    memset(s->channel_runtime, 0, sizeof(s->channel_runtime));
    s->channel_first_open_valid = 0U;
    s->terminal_channel_handle = 0U;
    return 0;
}

int session_enable_attach_socket(session_t *s, const char *absolute_path)
{
    size_t length;

    if (!s || !absolute_path || absolute_path[0] != '/' ||
        s->state != SESSION_IDLE || s->configuration_frozen ||
        !s->channelised_requested || s->bulk_enabled)
        return -1;
    length = strnlen(absolute_path, sizeof(s->attach_socket_path));
    if (length == 0U || length >= sizeof(s->attach_socket_path) ||
        !attach_local_path_fits(absolute_path))
        return -1;
    memcpy(s->attach_socket_path, absolute_path, length + 1U);
    s->attach_socket_configured = 1U;
    return 0;
}

/*
 * client-confinement: perform the attach socket's path work before the client installs its
 * Landlock domain. Nothing is created here, so the socket still appears only
 * when the session reaches the unchanged bind point below. The prepared
 * object retains path-only directory/cwd descriptors, so its later bind does
 * not need directory-listing authority. Safe to skip for unconfined callers,
 * which fall back to the original open-and-bind path.
 */
int session_prepare_attach_socket(session_t *s)
{
    if (!s || !s->attach_socket_configured || s->attach_socket_open ||
        s->attach_socket_prepared)
        return 0;
    if (attach_manager_prepare_path(&s->attach_manager, s->attach_socket_path,
                                    geteuid()) != ATTACH_LOCAL_OK)
        return -1;
    s->attach_socket_prepared = 1U;
    return 0;
}

static int session_child_text_length(const char *text, size_t *length_out)
{
    size_t length;

    if (!text || !length_out)
        return -1;
    length = strnlen(text, SESSION_CHILD_TRANSFER_TEXT_MAX);
    if (length == 0U || length >= SESSION_CHILD_TRANSFER_TEXT_MAX)
        return -1;
    *length_out = length;
    return 0;
}

int session_enable_child_transfers(
    session_t *s, const session_child_transfer_config_t *config)
{
    static const uint8_t dummy_path[] = "x";
    child_transfer_launch_policy_t policy;
    child_transfer_command_t command;
    child_transfer_argv_t arguments;
    traffic_profile_result_t resolved;
    uint8_t resolved_exact_paths;
    size_t program_length;
    size_t host_length;
    size_t command_length;
    size_t bind_length = 0U;

    if (!s || !config || s->state != SESSION_IDLE ||
        s->configuration_frozen || !s->channelised_requested ||
        !s->attach_socket_configured || s->bulk_enabled ||
        s->child_transfer_configured ||
        (config->log_format != EVENT_LOG_FORMAT_TEXT &&
         config->log_format != EVENT_LOG_FORMAT_JSON) ||
        session_child_text_length(config->program_path, &program_length) != 0 ||
        session_child_text_length(config->udp_host, &host_length) != 0 ||
        session_child_text_length(config->remote_command,
                                  &command_length) != 0 ||
        (config->remote_bind_host != NULL &&
         session_child_text_length(config->remote_bind_host,
                                   &bind_length) != 0) ||
        traffic_profile_inherit_option(
            config->traffic_profile, TRAFFIC_APPLICATION_TERMINAL,
            TRAFFIC_APPLICATION_BULK, 1, config->multipath_option,
            config->exact_paths, &resolved_exact_paths, &resolved) != 0) {
        errno = EINVAL;
        return -1;
    }
    memset(&policy, 0, sizeof(policy));
    policy.program_path = config->program_path;
    policy.attach_socket_path = s->attach_socket_path;
    policy.udp_host = config->udp_host;
    policy.remote_command = config->remote_command;
    policy.remote_bind_host = config->remote_bind_host;
    policy.traffic_profile = config->traffic_profile;
    policy.multipath_option = config->multipath_option;
    policy.port_mask = config->port_mask;
    policy.timeout_seconds = config->timeout_seconds;
    policy.exact_paths = resolved_exact_paths;
    policy.configured_paths = resolved.configured_paths == 0U
        ? 1U : resolved.configured_paths;
    policy.log_json = config->log_format == EVENT_LOG_FORMAT_JSON ? 1U : 0U;
    policy.port_layout = config->port_layout;
    policy.port_mask_explicit = config->port_mask_explicit;
    policy.pq_carrier_required = config->pq_carrier_required;
    policy.confine_level = config->confine_level;
    policy.server_confine_level = config->server_confine_level;
    memset(&command, 0, sizeof(command));
    command.local_path = dummy_path;
    command.remote_path = dummy_path;
    command.local_path_length = 1U;
    command.remote_path_length = 1U;
    command.transfer_id = 1U;
    command.wire_budget = BULK_WIRE_DEFAULT;
    command.stall_seconds = ATTACH_LOCAL_BULK_STALL_DEFAULT;
    command.kind = CHILD_TRANSFER_KIND_PUSH;
    if (child_transfer_argv_build(&policy, &command, &arguments) != 0)
        return -1;

    memcpy(s->child_transfer_program, config->program_path,
           program_length + 1U);
    memcpy(s->child_transfer_udp_host, config->udp_host,
           host_length + 1U);
    memcpy(s->child_transfer_remote_command, config->remote_command,
           command_length + 1U);
    if (config->remote_bind_host != NULL) {
        memcpy(s->child_transfer_remote_bind_host, config->remote_bind_host,
               bind_length + 1U);
        s->child_transfer_remote_bind_configured = 1U;
    }
    s->child_transfer_policy = policy;
    s->child_transfer_policy.program_path = s->child_transfer_program;
    s->child_transfer_policy.attach_socket_path = s->attach_socket_path;
    s->child_transfer_policy.udp_host = s->child_transfer_udp_host;
    s->child_transfer_policy.remote_command =
        s->child_transfer_remote_command;
    s->child_transfer_policy.remote_bind_host =
        s->child_transfer_remote_bind_configured
            ? s->child_transfer_remote_bind_host : NULL;
    s->child_transfer_configured = 1U;
    return 0;
}

int session_channelised_active(const session_t *s)
{
    return s &&
        (s->selected_caps & UNMOOR_CAP_CHANNEL_SESSION_D36_V1) != 0U;
}

int session_stream_owner_active(const session_t *s, uint32_t handle)
{
    size_t i;

    if (!s || handle == 0U)
        return 0;
    for (i = 0U; i < SESSION_TX_SLOT_COUNT; i++)
        if (s->wire_intents[i].valid &&
            s->wire_intents[i].stream_handle == handle)
            return 1;
    return 0;
}

uint32_t session_terminal_channel_handle(const session_t *s)
{
    return session_channelised_active(s) ? s->terminal_channel_handle : 0U;
}

int session_enable_bulk(session_t *s,
                        const bulk_engine_config_t *config)
{
    size_t remote_limit;
    bulk_engine_t *engine = NULL;

    if (!s || !config || !s->transport || !s->transport->ops ||
        s->state != SESSION_IDLE || s->configuration_frozen ||
        s->bulk_enabled ||
        strcmp(s->transport->ops->name, "udp") != 0 ||
        !bulk_wire_budget_valid(config->wire_budget) ||
        (config->stall_ms != 0 &&
         (config->stall_ms < BULK_ENGINE_STALL_MIN_MS ||
          config->stall_ms > BULK_ENGINE_STALL_MAX_MS)))
        return -1;
    if (s->pace_bps > 0 &&
        s->pace_bps < (int64_t)config->wire_budget * INT64_C(2))
        return -1;
    remote_limit = bulk_request_path_limit(config->wire_budget);
    if (config->endpoint == BULK_ENGINE_ENDPOINT_CLIENT) {
        if ((config->operation != BULK_OPERATION_PUT &&
             config->operation != BULK_OPERATION_GET) ||
            config->transfer_id == 0U || !config->local_path ||
            config->local_path_length == 0U ||
            config->local_path_length > BULK_PATH_MAX ||
            !config->remote_path || config->remote_path_length == 0U ||
            config->remote_path_length > remote_limit)
            return -1;
    } else if (config->endpoint == BULK_ENGINE_ENDPOINT_SERVER) {
        if (config->operation != 0 || config->transfer_id != 0U ||
            config->local_path != NULL || config->local_path_length != 0U ||
            config->remote_path != NULL || config->remote_path_length != 0U ||
            config->force != 0)
            return -1;
    } else {
        return -1;
    }
    if (bulk_engine_create(&engine) != 0 || !engine)
        return -1;
    s->bulk = engine;
    s->bulk_config = *config;
    s->bulk_config.pace_bps = s->pace_bps;
    s->bulk_enabled = 1;
    s->supported_caps = UNMOOR_CAP_BULK_FILE_D33_V1;
    s->required_caps = UNMOOR_CAP_BULK_FILE_D33_V1;
    s->offered_caps = s->supported_caps;
    return 0;
}

static int session_bulk_prepare_receive_arena(session_t *s)
{
    void *storage = NULL;

    if (!s || !s->bulk_enabled)
        return -1;
    if (s->bulk_prebarrier_receive)
        return 0;
    if (posix_memalign(&storage, 64U,
                       BULK_ENGINE_TX_BUFFER_BYTES) != 0)
        return -1;
    memset(storage, 0, BULK_ENGINE_TX_BUFFER_BYTES);
    s->bulk_prebarrier_receive = storage;
    s->bulk_prebarrier_receive_capacity =
        BULK_ENGINE_TX_BUFFER_BYTES;
    return 0;
}

static void session_bulk_release_receive_arena(session_t *s)
{
    if (!s || !s->bulk_prebarrier_receive)
        return;
    crypto_memzero(s->bulk_prebarrier_receive,
                   s->bulk_prebarrier_receive_capacity);
    free(s->bulk_prebarrier_receive);
    s->bulk_prebarrier_receive = NULL;
    s->bulk_prebarrier_receive_capacity = 0U;
}

static void session_bulk_retire_receive_arena(session_t *s)
{
    if (s && s->bulk_activated && s->frame_dispatch_depth == 0U)
        session_bulk_release_receive_arena(s);
}

static uint8_t *session_bulk_receive_storage(session_t *s,
                                             size_t *capacity_out)
{
    uint8_t *storage = NULL;
    size_t capacity = 0U;

    if (s && s->bulk_activated && s->bulk)
        storage = bulk_engine_receive_buffer(s->bulk, &capacity);
    else if (s && s->bulk_enabled) {
        storage = s->bulk_prebarrier_receive;
        capacity = s->bulk_prebarrier_receive_capacity;
    }
    if (capacity_out)
        *capacity_out = capacity;
    return storage;
}

int session_bulk_prevalidate(const session_t *s, uint8_t type,
                             const uint8_t *plaintext,
                             size_t plaintext_len)
{
    bulk_request_t request;
    bulk_manifest_t manifest;
    bulk_status_t status;
    int result = -1;

    if (!s || !s->bulk_enabled || !s->bulk || !plaintext)
        return -1;
    if (s->bulk_activated)
        return bulk_engine_prevalidate(
                   s->bulk, type, plaintext, plaintext_len) == 0
             ? 0 : -1;

    /* During the mandatory bootstrap barrier the server has deliberately
     * not allocated fixed bulk-transfer state yet.  The first adopted-epoch REQUEST
     * may still prove the client's final epoch-rekey ACK, so validate its complete
     * canonical grammar against the configured profile without binding or
     * opening any path. */
    if (!s->is_server)
        return -1;
    memset(&request, 0, sizeof(request));
    memset(&manifest, 0, sizeof(manifest));
    memset(&status, 0, sizeof(status));
    if (type == BULK_REQUEST &&
        bulk_request_decode(plaintext, plaintext_len, &request) ==
            BULK_RC_OK &&
        request.wire_budget == s->bulk_config.wire_budget &&
        request.path_length != 0U &&
        request.path_length <=
            bulk_request_path_limit(s->bulk_config.wire_budget)) {
        result = 0;
    } else if (type == BULK_MANIFEST &&
               bulk_manifest_decode(plaintext, plaintext_len, &manifest) ==
                   BULK_RC_OK &&
               manifest.wire_budget == s->bulk_config.wire_budget &&
               bulk_manifest_validate(&manifest) == BULK_RC_OK) {
        /* A PUT MANIFEST may beat its repeated REQUEST. It proves possession
         * of the adopted epoch key, but the activated engine still ignores
         * it as NOT_READY: it never implies REQUEST or opens a destination. */
        result = 0;
    } else if (type == BULK_STATUS &&
               bulk_status_decode(plaintext, plaintext_len, &status) ==
                   BULK_RC_OK &&
               status.phase == BULK_PHASE_PREPARING &&
               status.code == BULK_CODE_NONE) {
        /* Same pre-binding PUT reorder rule as MANIFEST. */
        result = 0;
    }
    crypto_memzero(&request, sizeof(request));
    crypto_memzero(&manifest, sizeof(manifest));
    crypto_memzero(&status, sizeof(status));
    return result;
}

int session_bulk_receive(session_t *s, uint8_t type,
                         const uint8_t *plaintext,
                         size_t plaintext_len)
{
    bulk_engine_receive_result_t rc;
    bulk_result_code_t terminal_code = BULK_CODE_NONE;

    if (!s || !s->bulk_activated || !s->bulk ||
        s->state != SESSION_ESTABLISHED)
        return -1;
    /* A final absolute STATUS can already be queued under a fresh SEQ when
     * its predecessor makes the local engine terminal.  It has passed AEAD,
     * replay and channel prevalidation, and completion is immutable, so an
     * exact canonical late record is a harmless semantic duplicate.  Calling
     * bulk_engine_receive() here would classify every post-result record as
     * FATAL solely because the engine is no longer RUNNING. */
    if (bulk_engine_result(s->bulk, &terminal_code) !=
        BULK_ENGINE_RESULT_RUNNING) {
        if (bulk_engine_prevalidate(s->bulk, type, plaintext,
                                    plaintext_len) == BULK_RC_OK)
            return 0;
        fprintf(stderr,
                "session: FATAL: invalid authenticated bulk-transfer record after terminal result\n");
        session_protocol_error_close(s, ERR_CAPS);
        return -1;
    }
    rc = bulk_engine_receive(s->bulk, type, plaintext, plaintext_len,
                             mono_ms());
    if (rc == BULK_ENGINE_RX_FATAL) {
        fprintf(stderr,
                "session: FATAL: authenticated bulk-transfer record violated the selected transfer\n");
        session_protocol_error_close(s, ERR_CAPS);
        return -1;
    }
    return 0;
}

bulk_engine_result_t session_bulk_result(const session_t *s,
                                         bulk_result_code_t *code_out)
{
    if (!s || !s->bulk_enabled || !s->bulk) {
        if (code_out)
            *code_out = BULK_CODE_PROTOCOL;
        return BULK_ENGINE_RESULT_FAILED;
    }
    return bulk_engine_result(s->bulk, code_out);
}

int session_bulk_cancel(session_t *s)
{
    if (!s || !s->bulk_activated || !s->bulk)
        return -1;
    return bulk_engine_cancel(s->bulk, mono_ms());
}

uint32_t session_selected_capabilities(const session_t *s)
{
    return s ? s->selected_caps : 0;
}

int session_peer_is_legacy(const session_t *s)
{
    return s ? s->peer_legacy : 0;
}

int session_set_traffic_profile(session_t *s, traffic_profile_t profile)
{
    if (!s || s->state != SESSION_IDLE || s->configuration_frozen ||
        (profile != TRAFFIC_PROFILE_ENTERPRISE &&
         profile != TRAFFIC_PROFILE_LAB))
        return -1;
    s->traffic_profile = profile;
    return 0;
}

int session_enable_json_events(session_t *s, int fd)
{
    if (!s || fd < 0 || s->state != SESSION_IDLE ||
        s->configuration_frozen || s->event_log_enabled)
        return -1;
    if (event_log_sink_arm(&s->event_sink, fd) != 0)
        return -1;
    s->event_log_enabled = 1U;
    return 0;
}

static int session_configure_multipath_paths(session_t *s,
                                             unsigned int path_count,
                                             int required)
{
    const transport_ops_t *ops;
    uint32_t capability;

    if (!s || !s->transport || s->state != SESSION_IDLE ||
        s->configuration_frozen || s->multipath_requested ||
        !multipath_path_count_valid(path_count))
        return -1;
    capability = negotiation_multipath_capability(path_count);
    if (capability == 0U)
        return -1;
    ops = s->transport->ops;
    if (!ops || strcmp(ops->name, "udp") != 0 || !ops->recv_from ||
        !ops->send_step_to || !ops->peer_confirm_from ||
        !ops->configured_paths || !ops->configured_path_limit ||
        !ops->get_recv_fds || !ops->get_path_send_fd ||
        ops->configured_path_limit(s->transport) != (int)path_count)
        return -1;
    s->multipath_requested = 1;
    s->multipath_required = required != 0;
    s->multipath_path_count = (uint8_t)path_count;
    if (session_set_capabilities(
            s, s->supported_caps | capability,
            required ? s->required_caps | capability
                     : s->required_caps & ~UNMOOR_CAP_MULTIPATH_D32_MASK) !=
        0) {
        s->multipath_requested = 0;
        s->multipath_required = 0;
        s->multipath_path_count = 0U;
        return -1;
    }
    if (multipath_init(&s->multipath, path_count) != 0) {
        s->multipath_requested = 0;
        s->multipath_required = 0;
        s->multipath_path_count = 0U;
        s->supported_caps &= ~capability;
        s->required_caps &= ~capability;
        s->offered_caps = s->supported_caps;
        return -1;
    }
    return 0;
}

int session_enable_multipath_paths(session_t *s, unsigned int path_count)
{
    return session_configure_multipath_paths(s, path_count, 1);
}

int session_offer_multipath_paths(session_t *s, unsigned int path_count)
{
    return session_configure_multipath_paths(s, path_count, 0);
}

int session_enable_multipath(session_t *s)
{
    return session_enable_multipath_paths(s, MULTIPATH_PATHS_DEFAULT);
}

int session_multipath_snapshot(const session_t *s,
                               multipath_snapshot_t *snapshot_out)
{
    if (!s || !snapshot_out || !s->multipath_active)
        return -1;
    return multipath_get_snapshot(&s->multipath, snapshot_out);
}

int session_path_legs_snapshot(session_t *s,
                               path_leg_t legs[MULTIPATH_PATHS_MAX],
                               size_t leg_capacity,
                               uint8_t *leg_count_out)
{
    if (leg_count_out != NULL)
        *leg_count_out = 0U;
    if (s == NULL || legs == NULL || leg_count_out == NULL ||
        session_refresh_path_legs(s, mono_ms()) != 0 ||
        leg_capacity < s->path_leg_count)
        return -1;
    memcpy(legs, s->path_leg,
           (size_t)s->path_leg_count * sizeof(legs[0]));
    *leg_count_out = s->path_leg_count;
    return 0;
}

int session_path_metrics_snapshot(
    session_t *s, path_leg_metrics_t metrics[MULTIPATH_PATHS_MAX],
    size_t metric_capacity, uint8_t *leg_count_out)
{
    uint8_t count;
    unsigned int leg;

    if (leg_count_out != NULL)
        *leg_count_out = 0U;
    if (s == NULL || metrics == NULL || leg_count_out == NULL)
        return -1;
    if (s->multipath_active || s->path_leg_count != 0U) {
        if (session_refresh_path_legs(s, mono_ms()) != 0)
            return -1;
        count = s->path_leg_count;
        if (metric_capacity < count)
            return -1;
        for (leg = 0U; leg < count; leg++)
            path_leg_metrics_snapshot(&s->path_leg[leg], &metrics[leg]);
    } else {
        count = s->path_leg_final_count;
        if (metric_capacity < count)
            return -1;
        memcpy(metrics, s->path_leg_final_metrics,
               (size_t)count * sizeof(metrics[0]));
    }
    *leg_count_out = count;
    return 0;
}

int session_multipath_primary_log_due(uint64_t primary_changes)
{
    return primary_changes != 0U &&
           primary_changes <= SESSION_MULTIPATH_PRIMARY_LOG_LIMIT;
}

int session_replay_log_due(uint64_t replay_drops)
{
    return replay_drops != 0U && replay_drops <= SESSION_REPLAY_LOG_LIMIT;
}

int session_multipath_mismatch_log_due(uint64_t mismatches)
{
    return mismatches != 0U &&
           mismatches <= SESSION_MULTIPATH_MISMATCH_LOG_LIMIT;
}

uint32_t session_multipath_validation_log_bit(unsigned int validated_count)
{
    if (validated_count == 0U || validated_count > MULTIPATH_PATHS_MAX ||
        (validated_count & (validated_count - 1U)) != 0U)
        return 0U;
    return UINT32_C(1) << (validated_count - 1U);
}

static void session_multipath_log_snapshot(session_t *s,
                                           const char *event,
                                           int64_t now_ms)
{
    multipath_snapshot_t snapshot;
    uint32_t validation_log_bit;

    if (!s || !event || now_ms < 0 ||
        multipath_get_snapshot(&s->multipath, &snapshot) != 0)
        return;
    /* Replacement can make validation revisit a frontier indefinitely.
     * Publish each power-of-two frontier only once per live session. */
    if (strcmp(event, "response") == 0) {
        validation_log_bit = session_multipath_validation_log_bit(
            snapshot.validated_count);
        if (validation_log_bit == 0U ||
            (s->multipath_validation_log_mask & validation_log_bit) != 0U)
            return;
        s->multipath_validation_log_mask |= validation_log_bit;
    }
    /* The counters and structured event sink remain authoritative. Text is
     * only a convenience diagnostic, and writing it to the same TTY after
     * the client enters raw mode corrupts the peer-owned screen. A redirected
     * stderr still receives the complete bounded record. */
    if (session_async_terminal_text_suppressed(s))
        return;
    /* A peer can alternate fresh HWM traffic across validated paths forever.
     * stderr is deliberately fail-loud and blocking, so an event-per-change
     * diagnostic would turn an unread pipe into transport backpressure. Keep
     * a hard lifetime cap and use a compact record; state/counters continue. */
    if (strcmp(event, "primary-change") == 0) {
        if (!session_multipath_primary_log_due(
                snapshot.counters.primary_changes))
            return;
        fprintf(stderr,
                "session: multipath paths event=primary-change changes=%llu limit=%u primary=%u validated=%u validated-mask=0x%08x at-ms=%lld\n",
                (unsigned long long)snapshot.counters.primary_changes,
                (unsigned int)snapshot.path_limit,
                (unsigned int)snapshot.primary_index,
                (unsigned int)snapshot.validated_count,
                snapshot.validated_mask, (long long)now_ms);
        return;
    }
    fprintf(stderr,
            "session: multipath paths event=%s limit=%u count=%u validated=%u primary=%u occupied=0x%08x configured=0x%08x provisional=0x%08x validated-mask=0x%08x primary-mask=0x%08x at-ms=%lld\n",
            event, (unsigned int)snapshot.path_limit,
            (unsigned int)snapshot.path_count,
            (unsigned int)snapshot.validated_count,
            (unsigned int)snapshot.primary_index,
            snapshot.occupied_mask, snapshot.configured_mask,
            snapshot.provisional_mask, snapshot.validated_mask,
            snapshot.primary_mask, (long long)now_ms);
}

static int session_multipath_start(session_t *s, int64_t now_ms)
{
    multipath_token_t configured[MULTIPATH_PATHS_MAX];
    multipath_handle_t handle;
    uint8_t selected_path_count = 0U;
    int count;
    int i;

    if (!s || now_ms < 0)
        return -1;
    if (negotiation_multipath_path_count(
            s->selected_caps, &selected_path_count) != 0) {
        fprintf(stderr,
                "session: FATAL: selected a noncanonical multipath path count\n");
        return -1;
    }
    if (selected_path_count == 0U) {
        if (s->multipath_requested) {
            if (s->multipath_required) {
                fprintf(stderr,
                        "session: FATAL: required multipath was not selected\n");
                return -1;
            }
            if (!s->transport || !s->transport->ops ||
                !s->transport->ops->quiesce_unselected_paths ||
                s->transport->ops->quiesce_unselected_paths(
                    s->transport) != 0) {
                fprintf(stderr,
                        "session: FATAL: optional multipath fallback could not retire unused paths\n");
                return -1;
            }
            multipath_reset(&s->multipath);
            s->multipath_requested = 0;
            s->multipath_required = 0;
            s->multipath_path_count = 0U;
        }
        return 0;
    }
    if (!s->multipath_requested || !s->transport ||
        !s->transport->ops->configured_paths ||
        selected_path_count != s->multipath_path_count) {
        fprintf(stderr,
                "session: FATAL: multipath selected without its local engine\n");
        return -1;
    }
    if (s->multipath_active)
        return 0;

    memset(configured, 0, sizeof(configured));
    count = s->transport->ops->configured_paths(s->transport, configured);
    if (count < 1 || count > (int)s->multipath_path_count ||
        (!s->is_server && count != (int)s->multipath_path_count)) {
        fprintf(stderr,
                "session: FATAL: multipath configured-path count is inconsistent\n");
        return -1;
    }
    for (i = 0; i < count; i++) {
        if (!multipath_token_valid(&configured[i]) ||
            configured[i].local_leg >= s->multipath_path_count) {
            fprintf(stderr,
                    "session: FATAL: multipath has a noncanonical configured path\n");
            return -1;
        }
    }
    multipath_reset(&s->multipath);
    if (multipath_bootstrap_primary(&s->multipath, &configured[0], now_ms,
                                    &handle) !=
        MULTIPATH_ACCEPTED) {
        fprintf(stderr,
                "session: FATAL: multipath could not install bootstrap path\n");
        multipath_reset(&s->multipath);
        return -1;
    }
    for (i = 1; i < count; i++) {
        if (multipath_configure_alternate(
                &s->multipath, &configured[i], now_ms, &handle) !=
            MULTIPATH_ACCEPTED) {
            fprintf(stderr,
                    "session: FATAL: multipath could not install configured path %d\n",
                    i);
            multipath_reset(&s->multipath);
            return -1;
        }
    }
    s->multipath_active = 1;
    s->multipath_challenge_cursor = 0U;
    s->multipath_response_cursor = 0U;
    s->multipath_keepalive_initialized = 0U;
    s->multipath_keepalive_anchor_ms = 0;
    s->multipath_keepalive_phase_serial = 0U;
    memset(&s->multipath_stagger, 0, sizeof(s->multipath_stagger));
    s->multipath_stagger_initialized = 0U;
    s->path_leg_final_count = 0U;
    if (session_refresh_path_legs(s, now_ms) != 0) {
        fprintf(stderr,
                "session: FATAL: multipath common leg snapshot failed at start\n");
        multipath_reset(&s->multipath);
        s->multipath_active = 0;
        return -1;
    }
    fprintf(stderr,
                "session: multipath engine active (limit=%u configured=%d)\n",
            (unsigned int)s->multipath_path_count, count);
    session_multipath_log_snapshot(s, "start", now_ms);
    return 0;
}

static int session_multipath_contract_selected(const session_t *s)
{
    uint8_t selected_path_count = 0U;

    return s != NULL && s->multipath_requested &&
           multipath_path_count_valid(s->multipath_path_count) &&
           negotiation_multipath_path_count(
               s->selected_caps, &selected_path_count) == 0 &&
           selected_path_count == s->multipath_path_count;
}

/* Compose the existing layer-owned path facts into one value snapshot. This
 * function creates no authority: multipath remains the source of remote identity,
 * validation, and incarnation; UDP supplies local ports; bulk-transfer supplies only
 * counters. Missing optional transport observation leaves local_port zero. */
static int session_refresh_path_legs(session_t *s, int64_t now_ms)
{
    path_leg_t next[MULTIPATH_PATHS_MAX];
    multipath_token_t configured[MULTIPATH_PATHS_MAX];
    uint16_t local_port[MULTIPATH_PATHS_MAX];
    uint8_t local_family[MULTIPATH_PATHS_MAX];
    uint8_t count = 0U;
    int configured_count = 0;
    int local_port_count = 0;
    int local_family_count = 0;
    int topology_changed;
    unsigned int leg;

    if (s == NULL || now_ms < 0)
        return -1;
    memset(next, 0, sizeof(next));
    memset(configured, 0, sizeof(configured));
    memset(local_port, 0, sizeof(local_port));
    memset(local_family, 0, sizeof(local_family));
    if (s->multipath_active) {
        multipath_snapshot_t snapshot;

        if (multipath_get_snapshot(&s->multipath, &snapshot) != 0)
            return -1;
        count = snapshot.path_limit;
        for (leg = 0U; leg < count; leg++) {
            int rc = multipath_describe_leg(&s->multipath, leg,
                                             &next[leg]);

            if (rc != MULTIPATH_ACCEPTED && rc != MULTIPATH_IGNORED)
                return -1;
        }
    } else if (s->bulk_activated && s->bulk != NULL) {
        count = bulk_engine_path_count(s->bulk);
        if (count != 1U)
            return -1;
        next[0].fd_generation = 1U;
        next[0].validation = PATH_LEG_VALIDATION_VALIDATED;
        next[0].envelope = PATH_LEG_ENVELOPE_DIRECT;
        if (s->transport != NULL && s->transport->ops != NULL &&
            s->transport->ops->configured_paths != NULL) {
            configured_count = s->transport->ops->configured_paths(
                s->transport, configured);
            if (configured_count == 1 &&
                multipath_token_valid(&configured[0]))
                next[0].remote = configured[0];
        }
    }

    topology_changed = s->path_leg_count != count;
    for (leg = 0U; leg < count; leg++) {
        int identity_unchanged = leg < s->path_leg_count &&
            next[leg].fd_generation == s->path_leg[leg].fd_generation &&
            memcmp(&next[leg].remote, &s->path_leg[leg].remote,
                   sizeof(next[leg].remote)) == 0;

        if (identity_unchanged) {
            next[leg].local_interface =
                s->path_leg[leg].local_interface;
            next[leg].local_port = s->path_leg[leg].local_port;
            next[leg].local_family =
                s->path_leg[leg].local_family;
            next[leg].keepalive_at_ms =
                s->path_leg[leg].keepalive_at_ms;
            next[leg].keepalive_tx = s->path_leg[leg].keepalive_tx;
            next[leg].observation =
                s->path_leg[leg].observation;
        } else {
            topology_changed = 1;
        }
    }
    /* Port discovery may call getsockname() once per socket. Repeat it only
     * when multipath changed the endpoint/socket generation, never from the
     * hot scheduler refresh. */
    if (topology_changed && count != 0U && s->transport != NULL &&
        s->transport->ops != NULL &&
        s->transport->ops->configured_local_ports != NULL)
        local_port_count =
            s->transport->ops->configured_local_ports(s->transport,
                                                       local_port);
    if (topology_changed && count != 0U && s->transport != NULL &&
        s->transport->ops != NULL &&
        s->transport->ops->configured_local_families != NULL)
        local_family_count =
            s->transport->ops->configured_local_families(s->transport,
                                                          local_family);
    for (leg = 0U; topology_changed && leg < count; leg++) {
        uint8_t physical_leg = next[leg].remote.local_leg;

        if (leg == 0U && !multipath_token_valid(&next[leg].remote) &&
            local_port_count == 1)
            next[leg].local_port = local_port[0];
        else if (local_port_count > 0 &&
                 multipath_token_valid(&next[leg].remote) &&
                 physical_leg < (uint8_t)local_port_count)
            next[leg].local_port = local_port[physical_leg];
        if (leg == 0U && !multipath_token_valid(&next[leg].remote) &&
            local_family_count == 1)
            next[leg].local_family = local_family[0];
        else if (local_family_count > 0 &&
                 multipath_token_valid(&next[leg].remote) &&
                 physical_leg < (uint8_t)local_family_count)
            next[leg].local_family = local_family[physical_leg];
        if (next[leg].local_family != 0U &&
            next[leg].local_family != 4U &&
            next[leg].local_family != 6U)
            return -1;
    }
    if (s->bulk_activated && s->bulk != NULL &&
        bulk_engine_copy_leg_counters(s->bulk, next, count) != BULK_RC_OK)
        return -1;
    for (leg = 0U; leg < count; leg++) {
        path_leg_counters_t counters = next[leg].counters;

        if (path_leg_counters_observe(
                &next[leg], &counters, now_ms,
                SYNC_STATUS_HEARTBEAT_MS) != 0)
            return -1;
    }
    memcpy(s->path_leg, next, sizeof(next));
    s->path_leg_count = count;
    return 0;
}

static uint64_t event_counter_add(uint64_t left, uint64_t right)
{
    return UINT64_MAX - left < right ? UINT64_MAX : left + right;
}

static event_log_session_state_t event_session_state(session_state_t state)
{
    switch (state) {
    case SESSION_IDLE:         return EVENT_LOG_STATE_IDLE;
    case SESSION_CONNECTING:   return EVENT_LOG_STATE_CONNECTING;
    case SESSION_KEY_DERIVING: return EVENT_LOG_STATE_KEY_DERIVING;
    case SESSION_ESTABLISHED:  return EVENT_LOG_STATE_ESTABLISHED;
    case SESSION_REKEYING:     return EVENT_LOG_STATE_REKEYING;
    case SESSION_CLOSING:      return EVENT_LOG_STATE_CLOSING;
    }
    return EVENT_LOG_STATE_CLOSING;
}

static void event_endpoint_from_remote(event_log_endpoint_t *endpoint,
                                       const path_leg_remote_t *remote)
{
    if (!endpoint || !remote || !multipath_token_valid(remote))
        return;
    if (remote->family == 4U)
        (void)event_log_endpoint_ipv4(endpoint, remote->address,
                                      remote->port);
    else if (remote->family == 6U)
        (void)event_log_endpoint_ipv6(endpoint, remote->address,
                                      remote->port, remote->scope);
}

/* Observation only: this routine neither creates path authority nor retries
 * diagnostic output. Missing per-leg transport counters and local-address
 * bytes remain JSON null exactly as traffic-profile requires. */
static void session_event_emit(session_t *s, event_log_event_t event,
                               event_log_scope_t scope,
                               event_log_reason_t reason, int leg,
                               uint64_t generation, int64_t now_ms)
{
    event_log_record_t record;
    multipath_snapshot_t paths;
    transport_stats_t transport_stats;
    const bulk_engine_stats_t *bulk_stats = NULL;
    uint8_t path_count = 1U;
    uint8_t validated_count = 0U;
    unsigned int index;

    if (!s || !s->event_log_enabled || now_ms < 0)
        return;
    memset(&paths, 0, sizeof(paths));
    if (s->multipath_active &&
        multipath_get_snapshot(&s->multipath, &paths) == 0) {
        path_count = paths.path_limit;
        validated_count = paths.validated_count;
    } else if (s->bulk_activated && s->bulk) {
        path_count = bulk_engine_path_count(s->bulk);
        if (path_count == 0U)
            path_count = 1U;
        validated_count = path_count;
    } else if (s->state == SESSION_ESTABLISHED ||
               s->state == SESSION_REKEYING ||
               s->state == SESSION_CLOSING) {
        validated_count = 1U;
    }

    event_log_record_init(
        &record, event, scope,
        s->is_server ? EVENT_LOG_ROLE_LISTENER : EVENT_LOG_ROLE_CLIENT,
        s->traffic_profile == TRAFFIC_PROFILE_LAB
            ? EVENT_LOG_PROFILE_LAB : EVENT_LOG_PROFILE_ENTERPRISE,
        event_session_state(s->state), reason);
    /* An explicitly requested channel session selects one event schema for its
     * entire lifetime. Use v2 even for pre-service observations so an early
     * path event cannot lock the sink to v1 before channel events exist. */
    if (s->channelised_requested)
        event_log_record_use_v2(&record);
    record.time_ms = now_ms;
    record.path_count = path_count;
    record.validated_count = validated_count;
    if (scope == EVENT_LOG_SCOPE_LEG && leg >= 0 &&
        leg < (int)path_count) {
        record.leg = leg;
        record.generation = generation;
        if (session_refresh_path_legs(s, now_ms) == 0 &&
            leg < (int)s->path_leg_count)
            event_endpoint_from_remote(&record.remote,
                                       &s->path_leg[leg].remote);
    }

    if (scope == EVENT_LOG_SCOPE_SESSION) {
        memset(&transport_stats, 0, sizeof(transport_stats));
        if (s->transport && s->transport->ops &&
            s->transport->ops->stats &&
            s->transport->ops->stats(s->transport,
                                     &transport_stats) == 0) {
            record.tx_datagrams = event_log_counter_observed(
                transport_stats.tx_ok);
            record.tx_failures = event_log_counter_observed(
                transport_stats.tx_fail);
            record.rx_datagrams = event_log_counter_observed(
                transport_stats.rx_ok);
            record.rx_drops = event_log_counter_observed(
                transport_stats.rx_drop);
        }
        record.replay_drops = event_log_counter_observed(
            s->replay_drop_count);
    }
    if (s->bulk_activated && s->bulk)
        bulk_stats = bulk_engine_stats(s->bulk);
    if (bulk_stats && scope == EVENT_LOG_SCOPE_SESSION) {
        uint64_t sent = 0U;
        uint64_t acked = 0U;
        uint64_t loss = 0U;
        uint64_t rerolls = 0U;

        for (index = 0U; index < path_count; index++) {
            sent = event_counter_add(sent,
                bulk_stats->leg[index].sent_bytes);
            acked = event_counter_add(acked,
                bulk_stats->leg[index].acked_bytes);
            loss = event_counter_add(loss,
                bulk_stats->leg[index].timeout_loss);
            rerolls = event_counter_add(rerolls,
                bulk_stats->leg[index].rerolls);
        }
        record.sent_bytes = event_log_counter_observed(sent);
        record.acked_bytes = event_log_counter_observed(acked);
        record.timeout_loss = event_log_counter_observed(loss);
        record.rerolls = event_log_counter_observed(rerolls);
    } else if (bulk_stats && scope == EVENT_LOG_SCOPE_LEG && leg >= 0 &&
               leg < (int)path_count) {
        index = (unsigned int)leg;
        record.sent_bytes = event_log_counter_observed(
            bulk_stats->leg[index].sent_bytes);
        record.acked_bytes = event_log_counter_observed(
            bulk_stats->leg[index].acked_bytes);
        record.timeout_loss = event_log_counter_observed(
            bulk_stats->leg[index].timeout_loss);
        record.rerolls = event_log_counter_observed(
            bulk_stats->leg[index].rerolls);
    }
    (void)event_log_sink_emit(&s->event_sink, &record);
}

static event_log_channel_kind_t session_event_channel_kind(uint8_t kind)
{
    switch (kind) {
    case CHANNEL_KIND_TERMINAL:
        return EVENT_LOG_CHANNEL_TERMINAL;
    case CHANNEL_KIND_EXEC:
        return EVENT_LOG_CHANNEL_EXEC;
    case CHANNEL_KIND_BULK_PUSH:
        return EVENT_LOG_CHANNEL_BULK_PUSH;
    case CHANNEL_KIND_BULK_PULL:
        return EVENT_LOG_CHANNEL_BULK_PULL;
    default:
        return EVENT_LOG_CHANNEL_KIND_NONE;
    }
}

static void session_event_emit_channel(session_t *s,
                                       event_log_event_t event,
                                       event_log_reason_t reason,
                                       uint32_t handle, uint8_t kind,
                                       uint32_t code, int64_t now_ms)
{
    event_log_record_t record;
    uint8_t path_count;

    if (!s || !s->event_log_enabled || !s->channelised_requested ||
        now_ms < 0 || handle == 0U)
        return;
    event_log_record_init(
        &record, event, EVENT_LOG_SCOPE_CHANNEL,
        s->is_server ? EVENT_LOG_ROLE_LISTENER : EVENT_LOG_ROLE_CLIENT,
        s->traffic_profile == TRAFFIC_PROFILE_LAB
            ? EVENT_LOG_PROFILE_LAB : EVENT_LOG_PROFILE_ENTERPRISE,
        event_session_state(s->state), reason);
    event_log_record_use_v2(&record);
    record.time_ms = now_ms;
    path_count = s->multipath_active ? s->multipath_path_count : 1U;
    record.path_count = path_count == 0U ? 1U : path_count;
    record.validated_count = record.path_count;
    if (event_log_record_set_channel(
            &record, handle, session_event_channel_kind(kind), code) != 0) {
        event_log_sink_note_suppressed(&s->event_sink);
        return;
    }
    (void)event_log_sink_emit(&s->event_sink, &record);
}

/* Preserve the first terminal cause. Later cleanup failures and a peer close
 * cannot rewrite the operator-visible reason for why teardown began. */
static void session_event_latch_close_reason(session_t *s,
                                             event_log_reason_t reason)
{
    if (!s || s->event_close_reason_set ||
        reason < EVENT_LOG_REASON_SESSION_ACTIVE ||
        reason >= EVENT_LOG_REASON_COUNT)
        return;
    s->event_close_reason = reason;
    s->event_close_reason_set = 1U;
}

static event_log_reason_t session_event_bulk_failure_reason(
    bulk_result_code_t code)
{
    switch (code) {
    case BULK_CODE_STALLED:
        return EVENT_LOG_REASON_NO_PROGRESS;
    case BULK_CODE_BUSY:
        return EVENT_LOG_REASON_BUSY;
    case BULK_CODE_QUOTA_SIZE:
        return EVENT_LOG_REASON_QUOTA;
    case BULK_CODE_SOURCE_OPEN:
    case BULK_CODE_DESTINATION:
    case BULK_CODE_SOURCE_CHANGED:
    case BULK_CODE_IO:
        return EVENT_LOG_REASON_IO_ERROR;
    case BULK_CODE_NONE:
    case BULK_CODE_EXISTS:
    case BULK_CODE_UNSUPPORTED_MTU:
    case BULK_CODE_ROOT_MISMATCH:
    case BULK_CODE_CANCELLED:
    case BULK_CODE_PROTOCOL:
    case BULK_CODE_PACE_TOO_LOW:
        return EVENT_LOG_REASON_PROTOCOL_ERROR;
    }
    return EVENT_LOG_REASON_PROTOCOL_ERROR;
}

static void session_event_emit_multipath_roam(
    session_t *s, const multipath_handle_t *handle, int64_t now_ms)
{
    multipath_snapshot_t snapshot;

    if (!s || !handle ||
        multipath_get_snapshot(&s->multipath, &snapshot) != 0)
        return;
    if (!session_multipath_primary_log_due(
            snapshot.counters.primary_changes)) {
        if (s->event_log_enabled)
            event_log_sink_note_suppressed(&s->event_sink);
        return;
    }
    session_event_emit(
        s, EVENT_LOG_EVENT_ROAM, EVENT_LOG_SCOPE_LEG,
        EVENT_LOG_REASON_AUTHENTICATED_HWM, (int)handle->index,
        handle->generation, now_ms);
}

static int session_bulk_refresh_paths(session_t *s, int64_t now_ms)
{
    multipath_snapshot_t snapshot;

    if (!s || !s->bulk_activated || !s->bulk)
        return 0;
    if (session_refresh_path_legs(s, now_ms) != 0)
        return -1;
    if (!s->multipath_active) {
        if (bulk_engine_path_count(s->bulk) != 1U ||
            s->path_leg_count != 1U)
            return -1;
        return bulk_engine_update_legs(
                   s->bulk, s->path_leg, s->path_leg_count, 0U,
                   now_ms) == BULK_RC_OK
            ? 0 : -1;
    }
    if (s->bulk_set_revalidation_active) {
        bulk_engine_observation_t observation;
        bulk_engine_path_snapshot_t bulk_snapshot;
        uint32_t low;
        unsigned int leg;

        memset(&observation, 0, sizeof(observation));
        if (!session_multipath_contract_selected(s) ||
            multipath_get_snapshot(&s->multipath, &snapshot) != 0 ||
            bulk_engine_observe(s->bulk, &observation) != BULK_RC_OK ||
            bulk_engine_path_snapshot(s->bulk, &bulk_snapshot) !=
                BULK_RC_OK ||
            snapshot.path_limit != bulk_engine_path_count(s->bulk) ||
            bulk_snapshot.path_count != snapshot.path_limit ||
            !bulk_snapshot.path_paused ||
            bulk_snapshot.d32_eligible_mask != 0U ||
            bulk_snapshot.primary_leg != BULK_ENGINE_NO_LEG)
            return -1;
        low = multipath_low_mask(snapshot.path_limit);
        if (snapshot.occupied_mask != low)
            return -1;
        for (leg = 0U; leg < snapshot.path_limit; leg++) {
            if (s->path_leg[leg].fd_generation == 0U ||
                s->path_leg[leg].fd_generation !=
                    snapshot.entry[leg].generation ||
                s->path_leg[leg].fd_generation !=
                    s->bulk_set_generation[leg] ||
                s->path_leg[leg].fd_generation !=
                    bulk_snapshot.generation[leg]) {
                fprintf(stderr,
                        "session: FATAL: bulk-transfer whole-set validation cohort diverged at slot=%u\n",
                        leg);
                return -1;
            }
        }
        if (snapshot.validated_mask != low)
            return 0;
        /* epoch-rekey owns the outer pause when the final multipath response arrives
         * during rekey.  Record the authenticated cohort in multipath state,
         * but do not expose DATA or consume the path pause until the epoch
         * barrier has resumed its own engine state. */
        if (observation.paused)
            return 0;
        if (snapshot.primary_index == MULTIPATH_NO_INDEX ||
            snapshot.primary_index >= snapshot.path_limit ||
            snapshot.primary_mask !=
                (UINT32_C(1) << snapshot.primary_index))
            return -1;
        if (bulk_engine_update_legs(s->bulk, s->path_leg,
                                    s->path_leg_count,
                                    snapshot.primary_index,
                                    now_ms) != BULK_RC_OK ||
            bulk_engine_path_resume(s->bulk, now_ms) != BULK_RC_OK)
            return -1;
        fprintf(stderr,
                "session: bulk-transfer whole-set revalidation complete layout=%u paths=%u primary=%u port-mask=0x%04x\n",
                (unsigned int)s->bulk_set_revalidation_layout,
                (unsigned int)snapshot.path_limit,
                (unsigned int)snapshot.primary_index,
                (unsigned int)s->bulk_set_new_port_mask);
        s->bulk_set_revalidation_active = 0U;
        s->bulk_set_revalidation_layout = 0U;
        s->bulk_set_revalidation_trigger = 0U;
        s->bulk_set_old_port_mask = 0U;
        s->bulk_set_new_port_mask = 0U;
        memset(s->bulk_set_generation, 0,
               sizeof(s->bulk_set_generation));
        return 0;
    }
    if (!session_multipath_contract_selected(s) ||
        multipath_get_snapshot(&s->multipath, &snapshot) != 0 ||
        snapshot.path_limit != bulk_engine_path_count(s->bulk) ||
        snapshot.primary_index == MULTIPATH_NO_INDEX ||
        snapshot.primary_index >= snapshot.path_limit)
        return -1;
    if (s->path_leg_count != snapshot.path_limit)
        return -1;
    return bulk_engine_update_legs(s->bulk, s->path_leg,
                                   s->path_leg_count,
                                   snapshot.primary_index,
                                   now_ms) == BULK_RC_OK ? 0 : -1;
}

/* Publish only path-state edges. These endpoint-owned records work as causal
 * barriers for a measurement, so operators get that evidence without a
 * test seam or an unauthenticated control channel. ACK/byte counters are
 * observations carried on an edge, never part of the edge signature, so a
 * long healthy transfer cannot emit one line per packet. */
static void session_bulk_log_path_edges(session_t *s, int64_t now_ms)
{
    bulk_engine_path_snapshot_t paths;
    const bulk_engine_stats_t *stats;
    unsigned int leg;

    if (s == NULL || !s->bulk_activated || s->bulk == NULL || now_ms < 0 ||
        bulk_engine_path_snapshot(s->bulk, &paths) != BULK_RC_OK)
        return;
    stats = bulk_engine_stats(s->bulk);
    if (stats == NULL)
        return;
    for (leg = 0U; leg < paths.path_count; leg++) {
        uint32_t bit = UINT32_C(1) << leg;
        uint8_t previous_share = (uint8_t)
            (s->bulk_path_log_signature[leg] & UINT32_C(0x03));
        int share_reduced =
            (((s->bulk_path_log_seen_mask & bit) == 0U) &&
             paths.share_shift[leg] > 0U) ||
            (((s->bulk_path_log_seen_mask & bit) != 0U) &&
             paths.share_shift[leg] > previous_share);
        int reroll_exhausted =
            (paths.reroll_exhausted_mask & bit) != 0U &&
            (((s->bulk_path_log_seen_mask & bit) == 0U) ||
             (s->bulk_path_log_signature[leg] & UINT32_C(0x10)) == 0U);
        int first_active = paths.outstanding[leg] != 0U &&
            (s->bulk_path_active_seen_mask & bit) == 0U;
        uint32_t signature = (uint32_t)paths.share_shift[leg] |
            (uint32_t)(((paths.reroll_due_mask & bit) != 0U) << 2) |
            (uint32_t)(((paths.reroll_claimed_mask & bit) != 0U) << 3) |
            (uint32_t)(((paths.reroll_exhausted_mask & bit) != 0U) << 4) |
            ((uint32_t)paths.reroll_attempts[leg] << 5);

        if ((s->bulk_path_log_seen_mask & bit) != 0U &&
            s->bulk_path_log_signature[leg] == signature && !first_active)
            continue;
        s->bulk_path_log_seen_mask |= bit;
        if (first_active)
            s->bulk_path_active_seen_mask |= bit;
        s->bulk_path_log_signature[leg] = signature;
        /* Structured events have their own nonblocking lifetime budget and
         * must not disappear merely because the human diagnostic cap filled. */
        if (share_reduced)
            session_event_emit(
                s, EVENT_LOG_EVENT_DEGRADE, EVENT_LOG_SCOPE_LEG,
                EVENT_LOG_REASON_SHARE_REDUCED, (int)leg,
                paths.generation[leg], now_ms);
        if (reroll_exhausted)
            session_event_emit(
                s, EVENT_LOG_EVENT_DEGRADE, EVENT_LOG_SCOPE_LEG,
                EVENT_LOG_REASON_REROLL_EXHAUSTED, (int)leg,
                paths.generation[leg], now_ms);
        if (s->bulk_path_log_count >= SESSION_BULK_PATH_LOG_LIMIT) {
            if (!s->bulk_path_log_suppressed) {
                fprintf(stderr,
                        "session: bulk-transfer path state log limit=%u reached; further edges suppressed\n",
                        SESSION_BULK_PATH_LOG_LIMIT);
                s->bulk_path_log_suppressed = 1U;
            }
            continue;
        }
        s->bulk_path_log_count++;
        fprintf(stderr,
                "session: bulk-transfer path state leg=%u share-shift=%u due=%u claimed=%u exhausted=%u reroll-attempts=%u outstanding=%u acked=%llu acked-bytes=%llu share-recoveries=%llu generation=%llu at-ms=%lld\n",
                leg, (unsigned int)paths.share_shift[leg],
                (paths.reroll_due_mask & bit) != 0U,
                (paths.reroll_claimed_mask & bit) != 0U,
                (paths.reroll_exhausted_mask & bit) != 0U,
                (unsigned int)paths.reroll_attempts[leg],
                (unsigned int)paths.outstanding[leg],
                (unsigned long long)stats->leg[leg].acked_chunks,
                (unsigned long long)stats->leg[leg].acked_bytes,
                (unsigned long long)stats->leg[leg].share_recoveries,
                (unsigned long long)paths.generation[leg],
                (long long)now_ms);
    }
}

static unsigned int bulk_local_leg_owners(
    const multipath_snapshot_t *snapshot, uint8_t local_leg)
{
    unsigned int owners = 0U;
    unsigned int i;

    if (!snapshot)
        return 0U;
    for (i = 0U; i < snapshot->path_limit; i++) {
        if ((snapshot->occupied_mask & (UINT32_C(1) << i)) != 0U &&
            snapshot->entry[i].token.local_leg == local_leg)
            owners++;
    }
    return owners;
}

static int bulk_reroll_finish_failure(session_t *s, uint8_t sender_leg,
                                      uint8_t physical_leg,
                                      uint64_t generation,
                                      int64_t now_ms)
{
    return bulk_engine_reroll_finish(s->bulk, sender_leg, physical_leg,
                                     generation, 0, now_ms) == BULK_RC_OK
        ? 0 : -1;
}

static int bulk_set_snapshot_stable(
    const multipath_snapshot_t *paths,
    const bulk_engine_path_snapshot_t *bulk_paths)
{
    uint32_t low;
    unsigned int leg;

    if (!paths || !bulk_paths || paths->path_limit != bulk_paths->path_count ||
        paths->path_limit < 2U || bulk_paths->path_paused)
        return 0;
    low = multipath_low_mask(paths->path_limit);
    if (paths->occupied_mask != low || paths->validated_mask != low ||
        paths->configured_mask != 0U || paths->provisional_mask != 0U ||
        paths->primary_index == MULTIPATH_NO_INDEX ||
        paths->primary_index >= paths->path_limit ||
        paths->primary_mask !=
            (UINT32_C(1) << paths->primary_index) ||
        bulk_paths->d32_eligible_mask != low ||
        bulk_paths->set_reroll_claimed ||
        bulk_paths->reroll_claimed_mask != 0U)
        return 0;
    for (leg = 0U; leg < paths->path_limit; leg++) {
        if (paths->entry[leg].response_pending ||
            paths->entry[leg].generation == 0U ||
            paths->entry[leg].generation != bulk_paths->generation[leg])
            return 0;
    }
    return 1;
}

static int bulk_set_reroll_finish_failure(session_t *s,
                                          uint8_t trigger_leg,
                                          uint64_t generation,
                                          int64_t now_ms)
{
    return bulk_engine_set_reroll_finish(
               s->bulk, trigger_leg, generation, 0, now_ms) == BULK_RC_OK
        ? 0 : -1;
}

static int session_bulk_set_reroll_tick(
    session_t *s, int64_t now_ms, int layout,
    const multipath_snapshot_t *before,
    const bulk_engine_path_snapshot_t *bulk_paths)
{
    transport_path_reroll_t reroll;
    multipath_snapshot_t after_prepare;
    multipath_handle_t replacement[MULTIPATH_PATHS_MAX];
    bulk_engine_reroll_result_t claim;
    uint32_t low;
    unsigned int offset;
    uint8_t next_cursor;
    uint8_t trigger = BULK_ENGINE_NO_LEG;
    uint64_t trigger_generation = 0U;
    int reconfigure;

    if (!s || !before || !bulk_paths ||
        (layout != TRANSPORT_UDP_PORT_LAYOUT_BLOCK &&
         layout != TRANSPORT_UDP_PORT_LAYOUT_CUBE))
        return -1;
    low = multipath_low_mask(before->path_limit);
    for (offset = 0U; offset < before->path_limit; offset++) {
        uint8_t slot = (uint8_t)((s->bulk_reroll_cursor + offset) &
                                 (before->path_limit - 1U));
        uint32_t bit = UINT32_C(1) << slot;

        if ((bulk_paths->reroll_due_mask & bit) == 0U ||
            (bulk_paths->reroll_exhausted_mask & bit) != 0U)
            continue;
        trigger = slot;
        trigger_generation = bulk_paths->generation[slot];
        break;
    }
    if (trigger == BULK_ENGINE_NO_LEG)
        return 0;
    next_cursor = (uint8_t)((trigger + 1U) &
                            (before->path_limit - 1U));
    if (now_ms < bulk_paths->reroll_defer_ms[trigger])
        return 0;
    if (!bulk_set_snapshot_stable(before, bulk_paths)) {
        if (before->entry[trigger].generation != trigger_generation)
            return -1;
        return bulk_engine_reroll_defer(s->bulk, trigger,
                                        trigger_generation,
                                        now_ms) == BULK_RC_OK ? 0 : -1;
    }
    if (s->wire_frame_len != 0U || s->wire_path_plan_active)
        return bulk_engine_reroll_defer(s->bulk, trigger,
                                        trigger_generation,
                                        now_ms) == BULK_RC_OK ? 0 : -1;

    claim = bulk_engine_set_reroll_claim(s->bulk, trigger,
                                         trigger_generation, now_ms);
    if (claim == BULK_ENGINE_REROLL_NOT_DUE)
        return 0;
    if (claim == BULK_ENGINE_REROLL_EXHAUSTED) {
        s->bulk_reroll_cursor = next_cursor;
        session_bulk_log_path_edges(s, now_ms);
        fprintf(stderr,
                "session: bulk-transfer whole-set reroll quota exhausted layout=%d trigger=%u generation=%llu\n",
                layout, (unsigned int)trigger,
                (unsigned long long)trigger_generation);
        return 0;
    }
    if (claim != BULK_ENGINE_REROLL_CLAIMED)
        return -1;
    /* A temporary witness/quiet denial above never rotates the queue. Once
     * the engine accepts physical work, advance even if shadow preparation
     * later fails: the attempt and common quiet are already charged. */
    s->bulk_reroll_cursor = next_cursor;

    memset(&reroll, 0, sizeof(reroll));
    if (s->transport->ops->path_reroll_prepare(
            s->transport, low, &reroll) != 0) {
        if (bulk_set_reroll_finish_failure(
                s, trigger, trigger_generation, now_ms) != 0)
            return -1;
        fprintf(stderr,
                "session: bulk-transfer whole-set shadow bind failed layout=%d trigger=%u attempt retained\n",
                layout, (unsigned int)trigger);
        return 0;
    }

    memset(&after_prepare, 0, sizeof(after_prepare));
    if (multipath_get_snapshot(&s->multipath, &after_prepare) != 0 ||
        memcmp(before, &after_prepare, sizeof(after_prepare)) != 0 ||
        !s->transport->ops->path_reroll_ready(s->transport, &reroll)) {
        s->transport->ops->path_reroll_abort(s->transport, &reroll);
        if (bulk_set_reroll_finish_failure(
                s, trigger, trigger_generation, now_ms) != 0)
            return -1;
        fprintf(stderr,
                "session: bulk-transfer whole-set shadow became stale layout=%d trigger=%u attempt retained\n",
                layout, (unsigned int)trigger);
        return 0;
    }
    if (bulk_engine_path_pause(s->bulk, now_ms) != BULK_RC_OK) {
        s->transport->ops->path_reroll_abort(s->transport, &reroll);
        if (bulk_set_reroll_finish_failure(
                s, trigger, trigger_generation, now_ms) != 0)
            return -1;
        return -1;
    }

    memset(replacement, 0, sizeof(replacement));
    reconfigure = multipath_reconfigure_local_set(
        &s->multipath, before, now_ms, replacement);
    if (reconfigure != MULTIPATH_ACCEPTED) {
        s->transport->ops->path_reroll_abort(s->transport, &reroll);
        if (bulk_set_reroll_finish_failure(
                s, trigger, trigger_generation, now_ms) != 0 ||
            bulk_engine_path_resume(s->bulk, now_ms) != BULK_RC_OK)
            return -1;
        fprintf(stderr,
                "session: FATAL: bulk-transfer whole-set authority transaction failed (%d)\n",
                reconfigure);
        return -1;
    }

    /* No fallible operation may intervene after the authority transaction:
     * ready() was proven above and commit is an infallible fd-array swap. */
    s->transport->ops->path_reroll_commit(s->transport, &reroll);
    if (bulk_engine_set_reroll_finish(
            s->bulk, trigger, trigger_generation, 1, now_ms) != BULK_RC_OK)
        return -1;
    if (session_refresh_path_legs(s, now_ms) != 0 ||
        s->path_leg_count != before->path_limit)
        return -1;
    for (offset = 0U; offset < before->path_limit; offset++) {
        if (replacement[offset].index != offset ||
            replacement[offset].generation == 0U ||
            s->path_leg[offset].fd_generation !=
                replacement[offset].generation)
            return -1;
    }
    if (bulk_engine_update_legs(s->bulk, s->path_leg,
                                s->path_leg_count,
                                BULK_ENGINE_NO_LEG,
                                now_ms) != BULK_RC_OK)
        return -1;
    s->bulk_set_revalidation_active = 1U;
    s->bulk_set_revalidation_layout = (uint8_t)layout;
    s->bulk_set_revalidation_trigger = trigger;
    s->bulk_set_old_port_mask = reroll.old_port_mask;
    session_event_emit(
        s, EVENT_LOG_EVENT_REROLL, EVENT_LOG_SCOPE_SESSION,
        EVENT_LOG_REASON_WHOLE_SET_REROLL, EVENT_LOG_NO_LEG, 0U, now_ms);
    s->bulk_set_new_port_mask = reroll.new_port_mask;
    memset(s->bulk_set_generation, 0,
           sizeof(s->bulk_set_generation));
    for (offset = 0U; offset < before->path_limit; offset++)
        s->bulk_set_generation[offset] =
            s->path_leg[offset].fd_generation;
    fprintf(stderr,
            "session: bulk-transfer whole-set reroll committed layout=%d paths=%u trigger=%u port-mask=0x%04x->0x%04x; DATA paused for exact revalidation\n",
            layout, (unsigned int)before->path_limit,
            (unsigned int)trigger,
            (unsigned int)reroll.old_port_mask,
            (unsigned int)reroll.new_port_mask);
    return 0;
}

int session_bulk_reroll_tick(session_t *s, int64_t now_ms)
{
    bulk_engine_path_snapshot_t bulk_paths;
    multipath_snapshot_t before;
    unsigned int offset;
    int layout;

    if (!s || now_ms < 0)
        return -1;
    if (!s->bulk_activated || !s->bulk || !s->multipath_active ||
        !s->services_started || s->state != SESSION_ESTABLISHED ||
        !bulk_engine_is_source(s->bulk) ||
        bulk_engine_result(s->bulk, NULL) !=
            BULK_ENGINE_RESULT_RUNNING)
        return 0;
    if (s->bulk_set_revalidation_active)
        return session_bulk_refresh_paths(s, now_ms);
    if (bulk_engine_path_snapshot(s->bulk, &bulk_paths) != BULK_RC_OK ||
        multipath_get_snapshot(&s->multipath, &before) != 0 ||
        before.path_limit != bulk_paths.path_count)
        return -1;
    if (bulk_paths.reroll_due_mask == 0U)
        return 0;
    if (session_refresh_path_legs(s, now_ms) != 0 ||
        s->path_leg_count != before.path_limit)
        return -1;

    /* The remote source in pull mode owns no independently rebound client
     * sockets. Retire one generation-scoped request per turn and report it
     * once; retransmission migration and minimum share remain active. */
    if (s->is_server) {
        for (offset = 0U; offset < before.path_limit; offset++) {
            uint8_t slot = (uint8_t)((s->bulk_reroll_cursor + offset) &
                                     (before.path_limit - 1U));
            uint32_t bit = UINT32_C(1) << slot;

            if ((bulk_paths.reroll_due_mask & bit) == 0U)
                continue;
            s->bulk_reroll_cursor =
                (uint8_t)((slot + 1U) & (before.path_limit - 1U));
            if (bulk_engine_reroll_exhaust(
                    s->bulk, slot, bulk_paths.generation[slot],
                    now_ms) != BULK_RC_OK)
                return -1;
            session_bulk_log_path_edges(s, now_ms);
            fprintf(stderr,
                    "session: bulk-transfer source-port reroll unavailable to pull source slot=%u generation=%llu\n",
                    (unsigned int)slot,
                    (unsigned long long)bulk_paths.generation[slot]);
            return 0;
        }
        return 0;
    }

    if (!s->transport || !s->transport->ops ||
        !s->transport->ops->configured_port_layout ||
        !s->transport->ops->path_reroll_prepare ||
        !s->transport->ops->path_reroll_ready ||
        !s->transport->ops->path_reroll_commit ||
        !s->transport->ops->path_reroll_abort)
        return -1;
    layout = s->transport->ops->configured_port_layout(s->transport);
    if (layout == TRANSPORT_UDP_PORT_LAYOUT_BLOCK ||
        layout == TRANSPORT_UDP_PORT_LAYOUT_CUBE)
        return session_bulk_set_reroll_tick(
            s, now_ms, layout, &before, &bulk_paths);
    if (layout != TRANSPORT_UDP_PORT_LAYOUT_RANDOM)
        return -1;

    /* Never replace an fd underneath a retained immutable wire plan. */
    if (s->wire_frame_len != 0U || s->wire_path_plan_active)
        return 0;

    for (offset = 0U; offset < before.path_limit; offset++) {
        transport_path_reroll_t reroll;
        multipath_snapshot_t after_prepare;
        multipath_handle_t target;
        multipath_handle_t replacement;
        const multipath_entry_t *entry;
        const path_leg_t *leg_state;
        bulk_engine_reroll_result_t claim;
        uint8_t slot = (uint8_t)((s->bulk_reroll_cursor + offset) &
                                 (before.path_limit - 1U));
        uint32_t bit = UINT32_C(1) << slot;
        uint8_t physical_leg;
        uint64_t generation;
        int reconfigure;

        if ((bulk_paths.reroll_due_mask & bit) == 0U ||
            (bulk_paths.reroll_exhausted_mask & bit) != 0U)
            continue;
        if ((bulk_paths.reroll_claimed_mask & bit) != 0U ||
            now_ms < bulk_paths.reroll_defer_ms[slot])
            continue;
        entry = &before.entry[slot];
        leg_state = &s->path_leg[slot];
        generation = leg_state->fd_generation;
        if ((before.occupied_mask & bit) == 0U ||
            entry->generation != generation ||
            bulk_paths.generation[slot] != generation ||
            leg_state->validation != PATH_LEG_VALIDATION_VALIDATED ||
            entry->state != (uint8_t)leg_state->validation ||
            !multipath_token_equal(&entry->token,
                                   &leg_state->remote) ||
            slot == before.primary_index) {
            if (bulk_engine_reroll_defer(s->bulk, slot, generation,
                                         now_ms) != BULK_RC_OK)
                return -1;
            continue;
        }
        physical_leg = leg_state->remote.local_leg;
        if (bulk_local_leg_owners(&before, physical_leg) != 1U) {
            if (bulk_engine_reroll_exhaust(s->bulk, slot, generation,
                                           now_ms) != BULK_RC_OK)
                return -1;
            s->bulk_reroll_cursor =
                (uint8_t)((slot + 1U) & (before.path_limit - 1U));
            session_bulk_log_path_edges(s, now_ms);
            fprintf(stderr,
                    "session: bulk-transfer random reroll exhausted aliased slot=%u local-leg=%u generation=%llu\n",
                    (unsigned int)slot, (unsigned int)physical_leg,
                    (unsigned long long)generation);
            /* The exhaustion mutates engine state, so do not walk the
             * pre-mutation snapshot again in this turn. It also keeps the
             * bounded diagnostic/action rule symmetric with pull. */
            return 0;
        }
        claim = bulk_engine_reroll_claim(s->bulk, slot, physical_leg,
                                         generation, now_ms);
        if (claim == BULK_ENGINE_REROLL_NOT_DUE)
            return 0;
        if (claim == BULK_ENGINE_REROLL_EXHAUSTED) {
            s->bulk_reroll_cursor =
                (uint8_t)((slot + 1U) & (before.path_limit - 1U));
            session_bulk_log_path_edges(s, now_ms);
            fprintf(stderr,
                    "session: bulk-transfer random reroll attempt quota exhausted slot=%u local-leg=%u generation=%llu\n",
                    (unsigned int)slot, (unsigned int)physical_leg,
                    (unsigned long long)generation);
            continue;
        }
        if (claim != BULK_ENGINE_REROLL_CLAIMED)
            return -1;
        s->bulk_reroll_cursor =
            (uint8_t)((slot + 1U) & (before.path_limit - 1U));

        memset(&reroll, 0, sizeof(reroll));
        if (s->transport->ops->path_reroll_prepare(
                s->transport, UINT32_C(1) << physical_leg,
                &reroll) != 0) {
            if (bulk_reroll_finish_failure(s, slot, physical_leg,
                                           generation, now_ms) != 0)
                return -1;
            fprintf(stderr,
                    "session: bulk-transfer random reroll bind failed slot=%u local-leg=%u attempt retained\n",
                    (unsigned int)slot, (unsigned int)physical_leg);
            return 0;
        }

        memset(&after_prepare, 0, sizeof(after_prepare));
        if (multipath_get_snapshot(&s->multipath, &after_prepare) != 0 ||
            after_prepare.path_limit != before.path_limit ||
            after_prepare.primary_index == slot ||
            (after_prepare.occupied_mask & bit) == 0U ||
            after_prepare.entry[slot].generation != generation ||
            after_prepare.entry[slot].state !=
                MULTIPATH_PATH_VALIDATED ||
            !multipath_token_equal(&after_prepare.entry[slot].token,
                                   &entry->token) ||
            bulk_local_leg_owners(&after_prepare, physical_leg) != 1U ||
            !s->transport->ops->path_reroll_ready(s->transport,
                                                  &reroll)) {
            s->transport->ops->path_reroll_abort(s->transport, &reroll);
            if (bulk_reroll_finish_failure(s, slot, physical_leg,
                                           generation, now_ms) != 0)
                return -1;
            fprintf(stderr,
                    "session: bulk-transfer random reroll became stale slot=%u local-leg=%u attempt retained\n",
                    (unsigned int)slot, (unsigned int)physical_leg);
            return 0;
        }

        memset(&target, 0, sizeof(target));
        memset(&replacement, 0, sizeof(replacement));
        target.index = slot;
        target.generation = generation;
        reconfigure = multipath_reconfigure_local_slot(
            &s->multipath, &target, now_ms, &replacement);
        if (reconfigure != MULTIPATH_ACCEPTED) {
            s->transport->ops->path_reroll_abort(s->transport, &reroll);
            if (bulk_reroll_finish_failure(s, slot, physical_leg,
                                           generation, now_ms) != 0)
                return -1;
            fprintf(stderr,
                    "session: FATAL: bulk-transfer exact random reroll transaction failed (%d)\n",
                    reconfigure);
            return -1;
        }
        s->transport->ops->path_reroll_commit(s->transport, &reroll);
        if (bulk_engine_reroll_finish(s->bulk, slot, physical_leg,
                                      generation, 1, now_ms) != BULK_RC_OK ||
            session_bulk_refresh_paths(s, now_ms) != 0) {
            fprintf(stderr,
                    "session: FATAL: bulk-transfer random reroll commit diverged\n");
            return -1;
        }
        session_event_emit(
            s, EVENT_LOG_EVENT_REROLL, EVENT_LOG_SCOPE_LEG,
            EVENT_LOG_REASON_SINGLE_LEG_REROLL, (int)slot,
            replacement.generation, now_ms);
        fprintf(stderr,
                "session: bulk-transfer random reroll complete slot=%u local-leg=%u old-port=%u new-port=%u generation=%llu->%llu\n",
                (unsigned int)slot, (unsigned int)physical_leg,
                (unsigned int)reroll.old_port[physical_leg],
                (unsigned int)reroll.new_port[physical_leg],
                (unsigned long long)generation,
                (unsigned long long)replacement.generation);
        return 0;
    }
    return 0;
}

/* A fixed-format optional service must disappear from the authenticated
 * offer when this endpoint cannot emit its largest mandatory state record.
 * Required service fails before HELLO rather than negotiating a latent
 * oversized-frame failure. */
static int prepare_delivery_capabilities(session_t *s)
{
    struct cap_mtu {
        uint32_t cap;
        uint16_t minimum;
        const char *name;
    } rules[] = {
        { UNMOOR_CAP_LATEST_BLOCK_D31_V1,
          UNMOOR_LATEST_BLOCK_D31_MIN_MTU, "latest-block-v1" },
        { UNMOOR_CAP_RELIABLE_DGRAM_D31_V1,
          UNMOOR_RELIABLE_DGRAM_D31_MIN_MTU, "reliable-dgram-v1" },
    };

    if (!s)
        return -1;
    if (s->bulk_enabled) {
        const uint32_t required = UNMOOR_CAP_BULK_FILE_D33_V1 |
                                  UNMOOR_CAP_EPOCH_REKEY_D28_V1;
        uint8_t path_count = 0U;

        s->offered_caps = s->supported_caps;
        if (!s->epoch_rekey_enabled ||
            (s->supported_caps & required) != required ||
            (s->required_caps & required) != required ||
            negotiation_multipath_path_count(
                s->supported_caps, &path_count) != 0 ||
            (path_count != 0U) != (s->multipath_requested != 0)) {
            fprintf(stderr,
                    "session: invalid exact epoch-rekey/bulk-transfer application bundle\n");
            s->run_failed = 1;
            return -1;
        }
        return 0;
    }
    s->offered_caps = s->supported_caps;
    for (size_t i = 0; i < sizeof(rules) / sizeof(rules[0]); i++) {
        if ((s->offered_caps & rules[i].cap) == 0 ||
            s->current_mtu >= rules[i].minimum)
            continue;
        if ((s->required_caps & rules[i].cap) != 0) {
            fprintf(stderr,
                    "session: required %s needs plaintext mtu >= %u "
                    "(configured %u)\n",
                    rules[i].name, (unsigned int)rules[i].minimum,
                    (unsigned int)s->current_mtu);
            s->run_failed = 1;
            return -1;
        }
        s->offered_caps &= ~rules[i].cap;
        fprintf(stderr,
                "session: withholding optional %s below plaintext mtu %u\n",
                rules[i].name, (unsigned int)rules[i].minimum);
    }
    if ((session_has_latest_configuration(s) &&
         (s->offered_caps & UNMOOR_CAP_LATEST_BLOCK_D31_V1) == 0) ||
        (session_has_reliable_configuration(s) &&
         (s->offered_caps & UNMOOR_CAP_RELIABLE_DGRAM_D31_V1) == 0) ||
        !delivery_configuration_fits_capabilities(s, s->offered_caps)) {
        fprintf(stderr,
                "session: configured delivery class cannot be offered\n");
        s->run_failed = 1;
        return -1;
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * Read pacer
 * ---------------------------------------------------------------------- */

void session_pacer_refill(session_t *s, int64_t now_ms)
{
    if (!s || s->pace_bps <= 0 || now_ms <= s->pace_last_refill_ms)
        return;

    int64_t elapsed = now_ms - s->pace_last_refill_ms;
    s->pace_last_refill_ms = now_ms;
    if (s->pace_credit_milli >= s->pace_burst_milli) {
        s->pace_credit_milli = s->pace_burst_milli;
        return;
    }

    /* B/s is numerically milli-bytes/ms. Compare the elapsed time with the
     * bounded deficit before multiplying, so even LLONG_MAX from the
     * environment saturates safely instead of overflowing signed math. */
    int64_t deficit = s->pace_burst_milli - s->pace_credit_milli;
    int64_t full_ms = deficit / s->pace_bps;
    int64_t needed_ms = full_ms + ((deficit % s->pace_bps) != 0);
    if (elapsed >= needed_ms) {
        s->pace_credit_milli = s->pace_burst_milli;
        return;
    }
    /* elapsed < ceil(deficit / rate), so this product is < deficit. */
    s->pace_credit_milli += s->pace_bps * elapsed;
}

void session_pacer_charge_read(session_t *s, size_t read_len)
{
    if (!s || s->pace_bps <= 0 || read_len == 0)
        return;
    size_t mtu = s->current_mtu ? s->current_mtu
                                : UNMOOR_TERMINAL_PLAINTEXT_MAX;
    size_t equivalent = read_len > mtu ? read_len : mtu;
    /* Current pumps cap reads at 256 bytes. Keep this helper safe if a future
     * caller violates that contract rather than wrapping the credit. */
    if (equivalent > (size_t)(INT64_MAX / 1000)) {
        s->pace_credit_milli = -s->pace_burst_milli;
        return;
    }
    s->pace_credit_milli -= (int64_t)equivalent * 1000;
}

int session_pacer_source_blocked(const session_t *s)
{
    return s && s->pace_bps > 0 && s->pace_credit_milli <= 0;
}

/* -------------------------------------------------------------------------
 * session_destroy
 * ---------------------------------------------------------------------- */

void session_destroy(session_t *s)
{
    if (!s) return;
    session_channel_application_cleanup_all(s);
    /* Always call channel_close_all so channels get a clean shutdown
     * hook even in client mode (where pty state may be stale across reconnect). */
    channel_close_all(s);
    if (monitor_session_backend_is_bound(s) &&
        monitor_session_backend_detach(s) != 0) {
        fprintf(stderr,
                "session: monitored backend detach failed: %s\n",
                strerror(errno));
        s->run_failed = 1;
    }
    sync_free(s);
    if (s->sync_monitor) {
        s->sync_monitor->session = NULL;
        s->sync_monitor = NULL;
    }
    session_wipe_secrets(s);
    session_bulk_release_receive_arena(s);
    bulk_engine_destroy(s->bulk);
    s->bulk = NULL;
    if (s->event_log_enabled) {
        (void)event_log_sink_restore(&s->event_sink);
        s->event_log_enabled = 0U;
    }
    /* Route through crypto_munlock so failures match crypto_mlock semantics
     * and a future audit of mlock/munlock pairing sees a single function
     * name on both sides. */
    crypto_munlock(s->psk,         32);
    crypto_munlock(s->hello_key,   32);
    crypto_munlock(s->session_key, 32);
    crypto_munlock(s->pending_key, 32);
    crypto_munlock(s->rekey_private, 32);
    crypto_munlock(s->pq_mlkem_private, sizeof(s->pq_mlkem_private));
    crypto_memzero(&s->preauth_budget, sizeof(s->preauth_budget));
    free(s);
}

void session_wipe_key_material(session_t *s)
{
    if (!s) return;
    crypto_memzero(s->psk, sizeof(s->psk));
    crypto_memzero(s->hello_key, sizeof(s->hello_key));
    s->have_hello_key = 0;
    crypto_memzero(s->session_key, sizeof(s->session_key));
    s->have_session_key = 0;
    crypto_memzero(s->pending_key, sizeof(s->pending_key));
    crypto_memzero(s->rekey_private, sizeof(s->rekey_private));
    crypto_memzero(s->nonce_a, sizeof(s->nonce_a));
    crypto_memzero(s->nonce_b, sizeof(s->nonce_b));
    crypto_memzero(s->session_context, sizeof(s->session_context));
    crypto_memzero(s->epoch_transcript_digest,
                   sizeof(s->epoch_transcript_digest));
    crypto_memzero(s->epoch_fingerprint, sizeof(s->epoch_fingerprint));
    crypto_memzero(s->completed_rekey_id,
                   sizeof(s->completed_rekey_id));
    s->completed_rekey_valid = 0;
    crypto_memzero(s->pending_transcript_digest,
                   sizeof(s->pending_transcript_digest));
    crypto_memzero(s->pending_epoch_fingerprint,
                   sizeof(s->pending_epoch_fingerprint));
    crypto_memzero(s->rekey_id, sizeof(s->rekey_id));
    crypto_memzero(s->rekey_client_public,
                   sizeof(s->rekey_client_public));
    crypto_memzero(s->rekey_server_public,
                   sizeof(s->rekey_server_public));
    crypto_memzero(&s->pq_rekey_tx, sizeof(s->pq_rekey_tx));
    pq_rekey_rx_wipe(&s->pq_rekey_rx);
    crypto_memzero(s->pq_mlkem_private,
                   sizeof(s->pq_mlkem_private));
    s->pq_base_received = 0U;
    s->pq_rx_bitmap_retired = 0U;
    s->pq_work_cursor = 0U;
    s->pq_active_work = 0U;
}

void session_wipe_secrets(session_t *s)
{
    if (!s) return;
    session_wipe_key_material(s);
    rekey_flight_reset(s);
    session_delivery_reset(s);
}

int session_enable_epoch_rekey(session_t *s, const uint8_t pair_seed[4],
                               int bootstrap_required,
                               int ephemeral_bootstrap_root)
{
    const uint32_t needed = s && s->bulk_enabled
        ? (UNMOOR_CAP_BULK_FILE_D33_V1 |
           UNMOOR_CAP_EPOCH_REKEY_D28_V1)
        : (UNMOOR_CAP_PTY_V1 | UNMOOR_CAP_PTY_SYNC_V1 |
           UNMOOR_CAP_EPOCH_REKEY_D28_V1 |
           UNMOOR_CAP_STATUS_HEARTBEAT_V1);
    uint32_t next_supported;

    if (!s || !pair_seed || s->state != SESSION_IDLE ||
        s->configuration_frozen ||
        memcmp(pair_seed, s->pair_id, 4) != 0 ||
        (ephemeral_bootstrap_root && !bootstrap_required))
        return -1;
    next_supported = s->supported_caps | needed;
    if (!delivery_configuration_fits_capabilities(s, next_supported))
        return -1;
    s->epoch_rekey_enabled = 1;
    s->bootstrap_rekey_required = bootstrap_required ? 1 : 0;
    s->ephemeral_bootstrap_root = ephemeral_bootstrap_root ? 1 : 0;
    memcpy(s->pair_seed, pair_seed, 4);
    s->supported_caps = next_supported;
    s->required_caps |= needed;
    s->offered_caps = s->supported_caps;
    return 0;
}

int session_enable_pq_hybrid(session_t *s)
{
    uint16_t stride;
    uint8_t count;

    if (!s || s->state != SESSION_IDLE || s->configuration_frozen ||
        !s->epoch_rekey_enabled || s->pq_hybrid_enabled ||
        pq_rekey_geometry(PQ_REKEY_CONTROL_MTU, &stride, &count) != 0)
        return -1;
    (void)stride;
    (void)count;
    s->pq_hybrid_enabled = 1;
    s->supported_caps |= UNMOOR_CAP_PQ_HYBRID_D45_V1;
    s->required_caps |= UNMOOR_CAP_PQ_HYBRID_D45_V1;
    s->offered_caps = s->supported_caps;
    return 0;
}

/* -------------------------------------------------------------------------
 * Build frame: encrypt plaintext, encode header, write to transport
 * key_to_use: if NULL, uses s->session_key; else uses supplied key.
 * direction: 0x00 = we are client, 0x01 = we are server
 * ---------------------------------------------------------------------- */

static void build_frame_ad(const uint8_t pair_id[4], uint32_t seq,
                           uint8_t chan_byte, uint8_t type, uint8_t ad[10])
{
    memcpy(ad, pair_id, 4);
    ad[4] = (uint8_t)(seq        & 0xFF);
    ad[5] = (uint8_t)((seq >>  8) & 0xFF);
    ad[6] = (uint8_t)((seq >> 16) & 0xFF);
    ad[7] = (uint8_t)((seq >> 24) & 0xFF);
    ad[8] = chan_byte;
    ad[9] = type;
}

/* Stable coalescing identities. Zero means exact and therefore never
 * overwrites another accepted logical record. */
#define WIRE_COALESCE_HELLO       UINT32_C(0x00000001)
#define WIRE_COALESCE_HELLO_ACK   UINT32_C(0x00000002)
#define WIRE_COALESCE_KEEPALIVE   UINT32_C(0x00000100)
#define WIRE_COALESCE_STATUS      UINT32_C(0x00000200)
#define WIRE_COALESCE_STATUS_POLL UINT32_C(0x00000201)
#define WIRE_COALESCE_STATUS_REPLY UINT32_C(0x00000202)
#define WIRE_COALESCE_READY       UINT32_C(0x00000300)
#define WIRE_COALESCE_READY_ACK   UINT32_C(0x00000301)
#define WIRE_COALESCE_PTY_OPEN    UINT32_C(0x00000400)
#define WIRE_COALESCE_PTY_RESIZE  UINT32_C(0x00000500)
#define WIRE_COALESCE_SYNC_ACK    UINT32_C(0x00000600)
#define WIRE_COALESCE_PATH_CHALLENGE_BASE UINT32_C(0x00000700)
#define WIRE_COALESCE_PATH_RESPONSE_BASE  UINT32_C(0x00000720)
#define WIRE_COALESCE_REKEY_BASE  UINT32_C(0x00010000)
#define WIRE_COALESCE_CLOSE_BASE  UINT32_C(0x00020000)
#define WIRE_COALESCE_CHANNEL_BASE UINT32_C(0x00100000)

static int wire_submit_path(session_t *s, send_lane_t lane,
                            session_tx_epoch_t epoch_source,
                            session_tx_sequence_class_t sequence_class,
                            uint8_t mode_mask,
                            uint8_t chan_byte, uint8_t type,
                            const uint8_t *bytes, size_t length,
                            session_tx_done_t done,
                            uint64_t arg0, uint64_t arg1,
                            uint32_t coalesce_key,
                            session_tx_path_policy_t path_policy,
                            const multipath_handle_t *path_target);
static int wire_submit_path_owned(session_t *s, send_lane_t lane,
                                  session_tx_epoch_t epoch_source,
                                  session_tx_sequence_class_t sequence_class,
                                  uint8_t mode_mask,
                                  uint8_t chan_byte, uint8_t type,
                                  const uint8_t *bytes, size_t length,
                                  session_tx_done_t done,
                                  uint64_t arg0, uint64_t arg1,
                                  uint32_t coalesce_key,
                                  session_tx_path_policy_t path_policy,
                                  const multipath_handle_t *path_target,
                                  uint32_t stream_handle,
                                  uint64_t operation_generation);

static int wire_submit(session_t *s, send_lane_t lane,
                       session_tx_epoch_t epoch_source,
                       session_tx_sequence_class_t sequence_class,
                       uint8_t mode_mask,
                       uint8_t chan_byte, uint8_t type,
                       const uint8_t *bytes, size_t length,
                       session_tx_done_t done, uint64_t arg0, uint64_t arg1,
                       uint32_t coalesce_key)
{
    session_tx_path_policy_t policy = SESSION_TX_PATH_PRIMARY;

    if ((chan_byte >> 4) == 0U) {
        if (type >= CTRL_CHANNEL_OPEN && type <= CTRL_CHANNEL_CLOSE_ACK)
            policy = SESSION_TX_PATH_CRITICAL;
        else if (type == CTRL_STATUS_HEARTBEAT ||
            ((type == CTRL_KEEPALIVE || type == CTRL_KEEPALIVE_ACK) &&
             (s->selected_caps & UNMOOR_CAP_STATUS_HEARTBEAT_V1) == 0U))
            policy = SESSION_TX_PATH_CRITICAL;
        else if (s->services_started && rekey_control_type(type))
            /* multipath: completed epoch-rekey controls can use the bounded intent
             * table instead of the dedicated flight owner.  After service
             * starts they retain the same critical-control fanout. */
            policy = SESSION_TX_PATH_CRITICAL;
    }
    return wire_submit_path(s, lane, epoch_source, sequence_class, mode_mask,
                            chan_byte, type, bytes, length, done,
                            arg0, arg1, coalesce_key, policy, NULL);
}

static int wire_submit_stream(session_t *s, send_lane_t lane,
                              uint8_t chan_byte, uint8_t type,
                              const uint8_t *bytes, size_t length,
                              session_tx_done_t done,
                              uint64_t arg0, uint64_t arg1,
                              uint32_t coalesce_key,
                              uint32_t stream_handle,
                              uint64_t operation_generation)
{
    return wire_submit_path_owned(
        s, lane, SESSION_TX_EPOCH_CURRENT, SESSION_TX_SEQ_NORMAL,
        SESSION_TX_MODE_ESTABLISHED, chan_byte, type, bytes, length,
        done, arg0, arg1, coalesce_key, SESSION_TX_PATH_PRIMARY, NULL,
        stream_handle, operation_generation);
}

static int wire_submit_path(session_t *s, send_lane_t lane,
                            session_tx_epoch_t epoch_source,
                            session_tx_sequence_class_t sequence_class,
                            uint8_t mode_mask,
                            uint8_t chan_byte, uint8_t type,
                            const uint8_t *bytes, size_t length,
                            session_tx_done_t done,
                            uint64_t arg0, uint64_t arg1,
                            uint32_t coalesce_key,
                            session_tx_path_policy_t path_policy,
                            const multipath_handle_t *path_target)
{
    return wire_submit_path_owned(
        s, lane, epoch_source, sequence_class, mode_mask, chan_byte, type,
        bytes, length, done, arg0, arg1, coalesce_key, path_policy,
        path_target, 0U, 0U);
}

static int wire_submit_path_owned(session_t *s, send_lane_t lane,
                                  session_tx_epoch_t epoch_source,
                                  session_tx_sequence_class_t sequence_class,
                                  uint8_t mode_mask,
                                  uint8_t chan_byte, uint8_t type,
                                  const uint8_t *bytes, size_t length,
                                  session_tx_done_t done,
                                  uint64_t arg0, uint64_t arg1,
                                  uint32_t coalesce_key,
                                  session_tx_path_policy_t path_policy,
                                  const multipath_handle_t *path_target,
                                  uint32_t stream_handle,
                                  uint64_t operation_generation)
{
    uint64_t ticket = 0;
    int64_t completion_now;
    if (wire_enqueue(s, lane, epoch_source, sequence_class, mode_mask,
                     chan_byte, type,
                     bytes, length, done, arg0, arg1, coalesce_key,
                     path_policy, path_target,
                     stream_handle, operation_generation,
                     &ticket) != 0)
        return -1;
    if (!s->wire_in_run_loop && !s->wire_driving) {
        /* sync.c deliberately injects its clock so timer tests and replayed
         * schedules are deterministic.  Preserve that clock at this legacy
         * synchronous white-box seam; the product event loop supplies its
         * own monotonic `now` to the arbiter. */
        completion_now = mono_ms();
        if (done >= SESSION_TX_DONE_SYNC_ACK &&
            done <= SESSION_TX_DONE_SYNC_FIN) {
            uint8_t stream_slot = 1U;
            uint32_t generation = 0U;
            const sync_tx_t *tx;

            if (stream_handle != 0U &&
                channel_session_handle_decode(stream_handle, &stream_slot,
                                              &generation) != 0)
                return -1;
            tx = sync_tx_state_instance(s, stream_slot);
            if (tx != NULL && tx->active)
                completion_now = tx->now_cache;
        }
        else if (done == SESSION_TX_DONE_STATUS_PERIODIC &&
                 arg0 <= (uint64_t)INT64_MAX)
            completion_now = (int64_t)arg0;
        session_send_scheduler_turn(s, completion_now);
        if (s->wire_failed_ticket == ticket)
            return -1;
    }
    return 0;
}

static void path_control_encode(uint64_t challenge_id, uint8_t out[16])
{
    unsigned int i;

    memset(out, 0, 16);
    out[0] = 1U;
    for (i = 0; i < 8U; i++)
        out[8U + i] = (uint8_t)(challenge_id >> (8U * i));
}

static int path_control_decode(const uint8_t *wire, size_t length,
                               uint64_t *challenge_id_out)
{
    uint64_t challenge_id = 0;
    unsigned int i;

    if (!wire || !challenge_id_out || length != 16U || wire[0] != 1U)
        return -1;
    for (i = 1U; i < 8U; i++)
        if (wire[i] != 0U)
            return -1;
    for (i = 0; i < 8U; i++)
        challenge_id |= (uint64_t)wire[8U + i] << (8U * i);
    if (challenge_id == 0U)
        return -1;
    *challenge_id_out = challenge_id;
    return 0;
}

static int path_control_intent_present(const session_t *s,
                                       session_tx_done_t done)
{
    size_t slot;

    for (slot = 0U; slot < SESSION_TX_SLOT_COUNT; slot++) {
        const session_tx_intent_t *intent = &s->wire_intents[slot];

        if (intent->valid && intent->done == (uint8_t)done)
            return 1;
    }
    return 0;
}

static int wire_has_free_intent(const session_t *s)
{
    size_t slot;

    for (slot = 0U; slot < SESSION_TX_SLOT_COUNT; slot++)
        if (!s->wire_intents[slot].valid)
            return 1;
    return 0;
}

static int64_t multipath_keepalive_phase_offset(uint8_t path_count,
                                                uint8_t slot)
{
    return ((int64_t)slot * MULTIPATH_VALIDATED_KEEPALIVE_MS) /
           path_count;
}

/* Map one monotonic instant onto the fixed per-slot phase wheel.  `serial`
 * grows once per phase, not once per event-loop turn, so a delayed caller can
 * skip directly to the current opportunity without an O(delay) catch-up. */
static int multipath_keepalive_current_phase(const session_t *s,
                                             uint8_t path_count,
                                             int64_t now_ms,
                                             uint64_t *serial_out,
                                             uint8_t *slot_out)
{
    uint64_t elapsed;
    uint64_t cycle;
    int64_t within;
    uint8_t slot = 0U;
    uint8_t i;

    if (!s || !s->multipath_keepalive_initialized || path_count == 0U ||
        now_ms < s->multipath_keepalive_anchor_ms || !serial_out ||
        !slot_out)
        return -1;
    elapsed = (uint64_t)(now_ms - s->multipath_keepalive_anchor_ms);
    cycle = elapsed / (uint64_t)MULTIPATH_VALIDATED_KEEPALIVE_MS;
    within = (int64_t)(elapsed %
                       (uint64_t)MULTIPATH_VALIDATED_KEEPALIVE_MS);
    for (i = 1U; i < path_count; i++) {
        if (multipath_keepalive_phase_offset(path_count, i) > within)
            break;
        slot = i;
    }
    if (cycle > (UINT64_MAX - slot) / path_count)
        return -1;
    *serial_out = cycle * path_count + slot;
    *slot_out = slot;
    return 0;
}

static int64_t multipath_keepalive_next_phase_wait(const session_t *s,
                                                   uint8_t path_count,
                                                   int64_t now_ms)
{
    uint64_t current_serial;
    uint64_t next_serial;
    uint64_t cycle;
    uint8_t current_slot;
    uint8_t slot;
    int64_t offset;
    int64_t due;

    if (!s || !s->multipath_keepalive_initialized)
        return 0;
    if (multipath_keepalive_current_phase(
            s, path_count, now_ms, &current_serial, &current_slot) != 0)
        return -1;
    (void)current_slot;
    if (current_serial > s->multipath_keepalive_phase_serial)
        return 0;
    if (s->multipath_keepalive_phase_serial == UINT64_MAX)
        return -1;
    next_serial = s->multipath_keepalive_phase_serial + 1U;
    cycle = next_serial / path_count;
    slot = (uint8_t)(next_serial % path_count);
    if (cycle > (uint64_t)INT64_MAX /
                    (uint64_t)MULTIPATH_VALIDATED_KEEPALIVE_MS)
        return -1;
    offset = multipath_keepalive_phase_offset(path_count, slot);
    due = (int64_t)cycle * MULTIPATH_VALIDATED_KEEPALIVE_MS;
    if (due > INT64_MAX - s->multipath_keepalive_anchor_ms ||
        due + s->multipath_keepalive_anchor_ms > INT64_MAX - offset)
        return -1;
    due += s->multipath_keepalive_anchor_ms + offset;
    return due <= now_ms ? 0 : due - now_ms;
}

static int session_multipath_keepalive_phase(session_t *s,
                                             multipath_snapshot_t *snapshot,
                                             int64_t now_ms)
{
    multipath_handle_t target;
    uint64_t serial;
    uint64_t challenge_id = 0U;
    uint8_t slot;
    unsigned int i;
    int arm;

    if (!s || !snapshot || s->is_server)
        return 0;
    if (session_refresh_path_legs(s, now_ms) != 0 ||
        s->path_leg_count != snapshot->path_limit)
        return -1;
    if (!s->multipath_keepalive_initialized) {
        s->multipath_keepalive_initialized = 1U;
        s->multipath_keepalive_anchor_ms = now_ms;
        /* Phase zero is deliberately consumed at activation. Initial
         * validation has already exercised that path; periodic maintenance
         * begins at the next distinct slot phase. */
        s->multipath_keepalive_phase_serial = 0U;
        for (i = 0U; i < snapshot->path_limit; i++)
            if (snapshot->entry[i].state == MULTIPATH_PATH_VALIDATED &&
                s->path_leg[i].keepalive_at_ms == 0)
                s->path_leg[i].keepalive_at_ms = now_ms;
        return 0;
    }
    if (multipath_keepalive_current_phase(
            s, snapshot->path_limit, now_ms, &serial, &slot) != 0)
        return -1;
    if (serial <= s->multipath_keepalive_phase_serial)
        return 0;
    /* Consume only the current phase. Every intervening phase was missed and
     * is skipped; it is never replayed as a burst after pacing, rekey or
     * scheduler residence. */
    s->multipath_keepalive_phase_serial = serial;
    for (i = 0U; i < snapshot->path_limit; i++)
        if (snapshot->entry[i].state == MULTIPATH_PATH_VALIDATED &&
            s->path_leg[i].keepalive_at_ms == 0)
            s->path_leg[i].keepalive_at_ms = now_ms;
    if (path_control_intent_present(s, SESSION_TX_DONE_PATH_CHALLENGE) ||
        snapshot->entry[slot].state != MULTIPATH_PATH_VALIDATED ||
        snapshot->entry[slot].challenge_pending ||
        s->path_leg[slot].fd_generation !=
            snapshot->entry[slot].generation ||
        s->path_leg[slot].keepalive_at_ms > now_ms)
        return 0;
    memset(&target, 0, sizeof(target));
    target.index = slot;
    target.generation = snapshot->entry[slot].generation;
    arm = multipath_validated_keepalive_arm(
        &s->multipath, &target, now_ms, &challenge_id);
    if (arm == MULTIPATH_IGNORED)
        return 0;
    if (arm != MULTIPATH_ACCEPTED || challenge_id == 0U)
        return -1;
    return multipath_get_snapshot(&s->multipath, snapshot);
}

static int path_control_pull_one(session_t *s,
                                 const multipath_snapshot_t *snapshot,
                                 int64_t now_ms, int response)
{
    session_tx_done_t done = response
                           ? SESSION_TX_DONE_PATH_RESPONSE
                           : SESSION_TX_DONE_PATH_CHALLENGE;
    uint8_t *cursor = response ? &s->multipath_response_cursor
                               : &s->multipath_challenge_cursor;
    unsigned int offset;

    if (path_control_intent_present(s, done) ||
        wire_lane_count(s, SEND_LANE_FEEDBACK) >=
            wire_lane_capacity(SEND_LANE_FEEDBACK) ||
        !wire_has_free_intent(s))
        return 0;
    for (offset = 0U; offset < snapshot->path_limit; offset++) {
        unsigned int i = ((unsigned int)*cursor + offset) &
                         (snapshot->path_limit - 1U);
        multipath_handle_t target;
        uint64_t challenge_id = 0U;
        uint8_t body[16];
        int due;
        int submit;

        if (snapshot->entry[i].state == MULTIPATH_PATH_EMPTY)
            continue;
        if (!response && !s->is_server &&
            s->multipath_stagger_initialized) {
            int allowed = traffic_stagger_allow_leg(
                &s->multipath_stagger,
                snapshot->entry[i].token.local_leg, now_ms);

            if (allowed < 0)
                return -1;
            if (!allowed)
                continue;
        }
        memset(&target, 0, sizeof(target));
        target.index = (uint8_t)i;
        target.generation = snapshot->entry[i].generation;
        due = response
            ? multipath_response_due(&s->multipath, &target, now_ms,
                                     &challenge_id)
            : multipath_challenge_due(&s->multipath, &target, now_ms,
                                      &challenge_id);
        if (due != MULTIPATH_ACCEPTED)
            continue;
        path_control_encode(challenge_id, body);
        submit = wire_submit_path(
            s, SEND_LANE_FEEDBACK, SESSION_TX_EPOCH_CURRENT,
            SESSION_TX_SEQ_NORMAL, SESSION_TX_MODE_ESTABLISHED,
            CHAN_FF_BIT,
            response ? CTRL_PATH_RESPONSE : CTRL_PATH_CHALLENGE,
            body, sizeof(body), done, challenge_id,
            response ? 0U : snapshot->entry[i].challenge_maintenance,
            (response ? WIRE_COALESCE_PATH_RESPONSE_BASE
                      : WIRE_COALESCE_PATH_CHALLENGE_BASE) + i,
            SESSION_TX_PATH_TARGET, &target);
        if (submit != 0)
            return -1;
        *cursor = (uint8_t)((i + 1U) &
                            (snapshot->path_limit - 1U));
        return 1;
    }
    return 0;
}

void session_multipath_tick(session_t *s, int64_t now_ms)
{
    multipath_snapshot_t snapshot;
    int response_rc;
    int challenge_rc;

    if (!s || !s->multipath_active || !s->services_started ||
        s->state != SESSION_ESTABLISHED || now_ms < 0 ||
        multipath_get_snapshot(&s->multipath, &snapshot) != 0)
        return;
    if (session_multipath_keepalive_phase(s, &snapshot, now_ms) != 0) {
        fprintf(stderr,
                "session: FATAL: multipath validated-leg maintenance failed\n");
        s->run_failed = 1;
        s->wire_protocol_failure = 1;
        return;
    }
    response_rc = path_control_pull_one(s, &snapshot, now_ms, 1);
    challenge_rc = path_control_pull_one(s, &snapshot, now_ms, 0);
    if (response_rc < 0 || challenge_rc < 0) {
        fprintf(stderr,
                "session: FATAL: multipath pull validation admission failed\n");
        s->run_failed = 1;
        s->wire_protocol_failure = 1;
    }
}

int64_t session_multipath_next_deadline(const session_t *s,
                                        int64_t now_ms)
{
    multipath_snapshot_t snapshot;
    int64_t wait = -1;
    int response_admitted;
    int challenge_admitted;
    int admission_available;
    unsigned int i;

    if (!s || !s->multipath_active || !s->services_started ||
        s->state != SESSION_ESTABLISHED || now_ms < 0 ||
        multipath_get_snapshot(&s->multipath, &snapshot) != 0)
        return -1;
    admission_available =
        wire_lane_count(s, SEND_LANE_FEEDBACK) <
            wire_lane_capacity(SEND_LANE_FEEDBACK) &&
        wire_has_free_intent(s);
    response_admitted = !admission_available || path_control_intent_present(
        s, SESSION_TX_DONE_PATH_RESPONSE);
    challenge_admitted = !admission_available || path_control_intent_present(
        s, SESSION_TX_DONE_PATH_CHALLENGE);
    if (!s->is_server && !challenge_admitted) {
        int64_t candidate = multipath_keepalive_next_phase_wait(
            s, snapshot.path_limit, now_ms);

        if (candidate >= 0 && (wait < 0 || candidate < wait))
            wait = candidate;
        if (s->multipath_stagger_initialized) {
            candidate = traffic_stagger_next_wait(
                &s->multipath_stagger, now_ms);
            if (candidate >= 0 && (wait < 0 || candidate < wait))
                wait = candidate;
        }
    }
    for (i = 0; i < snapshot.path_limit; i++) {
        int64_t candidate;
        if (snapshot.entry[i].state == MULTIPATH_PATH_EMPTY)
            continue;
        if (snapshot.entry[i].response_pending && !response_admitted) {
            candidate = snapshot.entry[i].response_due_ms <= now_ms
                      ? 0 : snapshot.entry[i].response_due_ms - now_ms;
            if (wait < 0 || candidate < wait)
                wait = candidate;
        }
        if (!snapshot.entry[i].challenge_pending)
            continue;
        if (!s->is_server && s->multipath_stagger_initialized &&
            (s->multipath_stagger.admitted_mask &
             (UINT32_C(1) << snapshot.entry[i].token.local_leg)) == 0U)
            continue;
        if (challenge_admitted)
            continue;
        candidate = snapshot.entry[i].challenge_due_ms <= now_ms
                  ? 0 : snapshot.entry[i].challenge_due_ms - now_ms;
        if (wait < 0 || candidate < wait)
            wait = candidate;
    }
    return wait;
}

static int wire_encode_hello(session_t *s, uint8_t type,
                             const uint8_t *plain, size_t plain_len)
{
    uint8_t hello_nonce[24];
    uint8_t ad[10];
    uint8_t body[24 + NEGOTIATION_PLAIN_LEN + FRAME_TAG_LEN];
    size_t ct_len = 0;
    uint32_t seq = s->tx_seq;
    int n;

    if (plain_len != NEGOTIATION_PLAIN_LEN || s->tx_seq == UINT32_MAX ||
        crypto_random_bytes(hello_nonce, sizeof(hello_nonce)) != 0)
        return -1;
    build_frame_ad(s->pair_id, seq, CHAN_FF_BIT, type, ad);
    memcpy(body, hello_nonce, sizeof(hello_nonce));
    if (crypto_encrypt_with_nonce(s->hello_key, hello_nonce, ad,
                                  plain, plain_len,
                                  body + sizeof(hello_nonce), &ct_len) != 0) {
        crypto_memzero(hello_nonce, sizeof(hello_nonce));
        return -1;
    }
    crypto_memzero(hello_nonce, sizeof(hello_nonce));
    n = unmoor_frame_encode(s->pair_id, seq, CHAN_FF_BIT, type,
                            body, sizeof(hello_nonce) + ct_len,
                            s->wire_frame, sizeof(s->wire_frame));
    crypto_memzero(body, sizeof(body));
    if (n < 0)
        return -1;
    s->tx_seq++;
    s->wire_frame_len = (size_t)n;
    if (type == CTRL_HELLO_ACK) {
        if ((size_t)n > sizeof(s->stored_hello_ack))
            return -1;
        memcpy(s->stored_hello_ack, s->wire_frame, (size_t)n);
        s->stored_hello_ack_len = (size_t)n;
    }
    return 0;
}

static int wire_encode_authenticated_intent(session_t *s,
                                            session_tx_intent_t *intent)
{
    const uint8_t *pair_id;
    const uint8_t *key;
    uint32_t *tx_seq;
    uint32_t seq;
    uint8_t ad[10];
    uint8_t ct[FRAME_MAX_LEN];
    size_t ct_len = 0;
    int n;

    if (intent->length > FRAME_MAX_LEN - FRAME_HEADER_LEN - FRAME_TAG_LEN)
        return -1;
    if (intent->epoch_source == SESSION_TX_EPOCH_PENDING) {
        if (!s->pending_epoch_valid)
            return -1;
        pair_id = s->pending_pair_id;
        key = s->pending_key;
        tx_seq = &s->pending_tx_seq;
    } else if (intent->epoch_source == SESSION_TX_EPOCH_HELLO_KEY) {
        if (!s->have_hello_key)
            return -1;
        pair_id = s->pair_id;
        key = s->hello_key;
        tx_seq = &s->tx_seq;
    } else {
        if (!s->have_session_key)
            return -1;
        pair_id = s->pair_id;
        key = s->session_key;
        tx_seq = &s->tx_seq;
    }
    if (intent->epoch_source == SESSION_TX_EPOCH_CURRENT &&
        intent->sequence_class == SESSION_TX_SEQ_NORMAL) {
        uint64_t limit = wire_normal_sequence_limit(s);
        uint64_t remaining = 0;

        if (s->wire_message.valid && s->wire_message.started)
            remaining = wire_message_remaining(&s->wire_message);
        if ((uint64_t)*tx_seq >= limit ||
            (remaining != 0 &&
             (uint64_t)*tx_seq + 1U + remaining > limit))
            return wire_sequence_failure(
                s, "queued record would consume authenticated-message reserve");
    }
    if (*tx_seq == UINT32_MAX) {
        fprintf(stderr, "send_frame: sequence space exhausted\n");
        s->run_failed = 1;
        return -1;
    }
    seq = *tx_seq;
    build_frame_ad(pair_id, seq, intent->chan_byte, intent->type, ad);
    if (crypto_encrypt(key, seq, s->is_server ? 0x01 : 0x00, ad,
                       intent->bytes, intent->length, ct, &ct_len) != 0)
        return -1;
    n = unmoor_frame_encode(pair_id, seq, intent->chan_byte, intent->type,
                            ct, ct_len, s->wire_frame,
                            sizeof(s->wire_frame));
    crypto_memzero(ct, sizeof(ct));
    if (n < 0)
        return -1;
    (*tx_seq)++;
    s->wire_frame_len = (size_t)n;
    return 0;
}

static int wire_encode_slot(session_t *s, int slot_index)
{
    session_tx_intent_t *intent;

    if (!s || slot_index < 0 ||
        (size_t)slot_index >= SESSION_TX_SLOT_COUNT)
        return -1;
    intent = &s->wire_intents[(size_t)slot_index];
    if (!intent->valid || !intent->inflight)
        return -1;
    if (intent->epoch_source == SESSION_TX_RAW_FRAME) {
        if (intent->length == 0)
            return -1;
        memcpy(s->wire_frame, intent->bytes, intent->length);
        s->wire_frame_len = intent->length;
        return 0;
    }
    if (intent->epoch_source == SESSION_TX_HELLO)
        return wire_encode_hello(s, CTRL_HELLO, s->transcript_hello,
                                 NEGOTIATION_PLAIN_LEN);
    if (intent->epoch_source == SESSION_TX_HELLO_ACK_NEW)
        return wire_encode_hello(s, CTRL_HELLO_ACK, intent->bytes,
                                 intent->length);

    if (intent->done == SESSION_TX_DONE_SYNC_ACK) {
        size_t snapshot_len = 0;
        uint64_t generation = 0;
        uint64_t credit = 0;
        uint8_t stream_slot = 1U;
        uint32_t handle_generation = 0U;
        size_t prefix = intent->stream_handle != 0U
            ? CHANNEL_SESSION_HANDLE_BYTES : 0U;
        size_t snapshot_cap = sizeof(intent->bytes) - prefix;

        if (prefix != 0U) {
            if (channel_session_handle_decode(intent->stream_handle,
                                              &stream_slot,
                                              &handle_generation) != 0 ||
                intent->length != prefix ||
                load32le(intent->bytes) != intent->stream_handle ||
                !s->sync_binding[stream_slot].configured ||
                s->sync_binding[stream_slot].handle !=
                    intent->stream_handle)
                return -1;
        }
        if (s->current_mtu > prefix &&
            snapshot_cap > (size_t)s->current_mtu - prefix)
            snapshot_cap = (size_t)s->current_mtu - prefix;

        if (sync_ack_snapshot_instance(s, stream_slot,
                                       intent->bytes + prefix, snapshot_cap,
                                       &snapshot_len, &generation,
                                       &credit) != 0 ||
            snapshot_len + prefix > UINT16_MAX)
            return -1;
        intent->length = (uint16_t)(snapshot_len + prefix);
        intent->arg0 = generation;
        intent->arg1 = credit;
        intent->operation_generation = generation;
    }

    return wire_encode_authenticated_intent(s, intent);
}

static int wire_encode_message(session_t *s)
{
    session_tx_message_t *message = &s->wire_message;
    uint32_t seq;
    size_t off;
    size_t take;
    int last;
    uint8_t flags = 0;
    uint8_t chan_byte;
    fragment_desc_t desc;
    uint8_t desc_wire[FRAGMENT_DESC_LEN];
    uint8_t ad[10 + FRAGMENT_DESC_LEN];
    uint8_t plain[FRAME_MAX_LEN];
    uint8_t ct[FRAME_MAX_LEN];
    uint8_t body[FRAME_MAX_LEN];
    size_t ct_len = 0;
    uint64_t remaining;
    uint64_t required;
    uint64_t limit;
    int n;

    if (!message->valid || !message->inflight ||
        message->index >= message->count)
        return -1;
    remaining = wire_message_remaining(message);
    limit = wire_normal_sequence_limit(s);
    if (message->started) {
        if (message->started_epoch != s->epoch ||
            (uint64_t)s->tx_seq + remaining > limit)
            return wire_sequence_failure(
                s, "authenticated message would cross its pinned epoch");
    } else {
        required = wire_message_sequence_budget(s, remaining);
        if ((uint64_t)s->tx_seq + required > limit)
            return wire_sequence_failure(
                s, "authenticated message first grant lacks lane-interleave reserve");
        message->started = 1;
        message->started_epoch = s->epoch;
    }
    if (!message->hash_ready) {
        message->message_id = s->tx_seq;
        crypto_fragment_hash(message->hash,
                             s->is_server ? 0x01 : 0x00,
                             message->chan_id, message->type,
                             message->message_id, message->count,
                             message->total_length, message->stride,
                             message->bytes, message->total_length);
        message->hash_ready = 1;
    }
    seq = s->tx_seq;
    off = (size_t)message->index * message->stride;
    take = (size_t)message->total_length - off;
    if (take > message->stride)
        take = message->stride;
    last = (uint16_t)(message->index + 1U) == message->count;
    if (message->index == 0)
        flags |= CHAN_FF_BIT;
    if (!last)
        flags |= CHAN_MF_BIT;
    chan_byte = (uint8_t)((message->chan_id << 4) | flags);

    memset(&desc, 0, sizeof(desc));
    desc.version = FRAGMENT_VERSION;
    desc.message_id = message->message_id;
    desc.index = message->index;
    desc.count = message->count;
    desc.total_length = message->total_length;
    desc.stride = message->stride;
    desc.fragment_length = (uint16_t)take;
    fragment_desc_encode(&desc, desc_wire);
    build_frame_ad(s->pair_id, seq, chan_byte, message->type, ad);
    memcpy(ad + 10, desc_wire, sizeof(desc_wire));
    memcpy(plain, message->hash, sizeof(message->hash));
    memcpy(plain + sizeof(message->hash), message->bytes + off, take);
    if (crypto_encrypt_ad(s->session_key, seq,
                          s->is_server ? 0x01 : 0x00,
                          ad, sizeof(ad), plain,
                          sizeof(message->hash) + take,
                          ct, &ct_len) != 0) {
        crypto_memzero(plain, sizeof(plain));
        return -1;
    }
    crypto_memzero(plain, sizeof(plain));
    memcpy(body, desc_wire, sizeof(desc_wire));
    memcpy(body + sizeof(desc_wire), ct, ct_len);
    crypto_memzero(ct, sizeof(ct));
    n = unmoor_frame_encode(s->pair_id, seq, chan_byte, message->type,
                            body, sizeof(desc_wire) + ct_len,
                            s->wire_frame, sizeof(s->wire_frame));
    crypto_memzero(body, sizeof(body));
    if (n < 0)
        return -1;
    s->tx_seq++;
    s->wire_frame_len = (size_t)n;
    return 0;
}

static int send_frame_epoch(session_t *s,
                            const uint8_t pair_id[4],
                            const uint8_t *key, uint32_t *tx_seq,
                            uint8_t chan_byte, uint8_t type,
                            const uint8_t *plaintext, size_t pt_len,
                            int guard_current_sequence,
                            send_lane_t lane)
{
    session_tx_epoch_t epoch_source;
    session_tx_sequence_class_t sequence_class;
    uint8_t mode_mask;
    (void)pair_id;
    (void)key;

    if (pt_len > FRAME_MAX_LEN - FRAME_HEADER_LEN - FRAME_TAG_LEN) {
        fprintf(stderr, "send_frame: plaintext too large (%zu)\n", pt_len);
        return -1;
    }
    epoch_source = tx_seq == &s->pending_tx_seq
                 ? SESSION_TX_EPOCH_PENDING : SESSION_TX_EPOCH_CURRENT;
    sequence_class = guard_current_sequence
                   ? SESSION_TX_SEQ_NORMAL
                   : SESSION_TX_SEQ_EPOCH_CONTROL;
    mode_mask = wire_mode_mask(wire_mode(s));
    return wire_submit(s, lane, epoch_source, sequence_class, mode_mask,
                       chan_byte, type, plaintext, pt_len,
                       SESSION_TX_DONE_NONE, 0, 0, 0);
}

static int send_frame(session_t *s,
                      const uint8_t *key,
                      uint8_t chan_byte, uint8_t type,
                      const uint8_t *plaintext, size_t pt_len,
                      send_lane_t lane)
{
    return send_frame_epoch(s, s->pair_id, key, &s->tx_seq,
                            chan_byte, type, plaintext, pt_len, 1, lane);
}

/* -------------------------------------------------------------------------
 * Convenience: send on channel 0 (control) using hello_key or session_key
 * ---------------------------------------------------------------------- */

static int send_ctrl(session_t *s, uint8_t type,
                     const uint8_t *plaintext, size_t pt_len,
                     const uint8_t *key)
{
    send_lane_t lane = SEND_LANE_INTERACTIVE;
    uint32_t coalesce_key = 0;
    if (type == CTRL_KEEPALIVE || type == CTRL_KEEPALIVE_ACK ||
        type == CTRL_STATUS_HEARTBEAT) {
        lane = SEND_LANE_FEEDBACK;
        coalesce_key = type == CTRL_STATUS_HEARTBEAT
                     ? WIRE_COALESCE_STATUS
                     : WIRE_COALESCE_KEEPALIVE + type;
    }
    /* CHAN byte for control: id=0, FF=1 (single frame), MF=0 */
    uint8_t chan_byte = (0 << 4) | CHAN_FF_BIT; /* 0x02 */
    return wire_submit(s, lane,
                       key == s->hello_key ? SESSION_TX_EPOCH_HELLO_KEY
                                           : SESSION_TX_EPOCH_CURRENT,
                       wire_sequence_class(
                           key == s->hello_key
                               ? SESSION_TX_EPOCH_HELLO_KEY
                               : SESSION_TX_EPOCH_CURRENT,
                           chan_byte, type),
                       wire_mode_mask(wire_mode(s)), chan_byte, type,
                       plaintext, pt_len, SESSION_TX_DONE_NONE, 0, 0,
                       coalesce_key);
}

static int send_ctrl_epoch_tracked(session_t *s, const uint8_t pair_id[4],
                                   const uint8_t key[32], uint32_t *tx_seq,
                                   uint8_t type, const uint8_t *plaintext,
                                   size_t pt_len, session_tx_done_t done,
                                   uint64_t arg0, uint64_t arg1,
                                   uint8_t mode_mask)
{
    session_tx_epoch_t epoch_source = tx_seq == &s->pending_tx_seq
        ? SESSION_TX_EPOCH_PENDING : SESSION_TX_EPOCH_CURRENT;
    uint32_t coalesce_key = rekey_control_type(type)
        ? WIRE_COALESCE_REKEY_BASE |
          ((uint32_t)epoch_source << 8) | type
        : (type == CTRL_CLOSE || type == CTRL_ERROR)
          ? WIRE_COALESCE_CLOSE_BASE |
            ((uint32_t)epoch_source << 8) | type
          : 0;
    (void)pair_id;
    (void)key;
    return wire_submit(s, SEND_LANE_INTERACTIVE, epoch_source,
                       SESSION_TX_SEQ_EPOCH_CONTROL,
                       mode_mask, CHAN_FF_BIT, type,
                       plaintext, pt_len, done, arg0, arg1,
                       coalesce_key);
}

static int send_ctrl_epoch(session_t *s, const uint8_t pair_id[4],
                           const uint8_t key[32], uint32_t *tx_seq,
                           uint8_t type, const uint8_t *plaintext,
                           size_t pt_len)
{
    return send_ctrl_epoch_tracked(s, pair_id, key, tx_seq, type,
                                   plaintext, pt_len,
                                   SESSION_TX_DONE_NONE, 0, 0,
                                   wire_mode_mask(wire_mode(s)));
}

/* -------------------------------------------------------------------------
 * channel-session bounded channel-zero owner
 * ---------------------------------------------------------------------- */

static int channel_control_type_valid(uint8_t type)
{
    return type >= CTRL_CHANNEL_OPEN && type <= CTRL_CHANNEL_CLOSE_ACK;
}

static void channel_runtime_arm_open(session_channel_runtime_t *runtime,
                                     int64_t now_ms, int client)
{
    if (!runtime || runtime->open_armed)
        return;
    runtime->open_armed = 1U;
    runtime->open_retry_index = 0U;
    runtime->open_started_ms = now_ms;
    runtime->open_next_ms = client
        ? now_ms + channel_retry_offsets_ms[0] : 0;
    runtime->open_deadline_ms = now_ms + CHANNEL_SESSION_FIRST_OPEN_MS;
}

static void channel_runtime_arm_close(session_channel_runtime_t *runtime,
                                      int64_t now_ms)
{
    if (!runtime || runtime->close_armed)
        return;
    runtime->close_armed = 1U;
    runtime->close_retry_index = 0U;
    runtime->close_started_ms = now_ms;
    runtime->close_next_ms = now_ms;
    runtime->close_deadline_ms = now_ms + CHANNEL_SESSION_FIRST_OPEN_MS;
}

static int channel_control_submit(session_t *s, uint8_t slot, uint8_t type)
{
    channel_session_slot_t *entry;
    uint8_t body[CHANNEL_SESSION_OPEN_BYTES];
    size_t body_length;
    channel_session_result_t result;
    int rc;

    if (!s || !session_channelised_active(s) ||
        s->channel_control_inflight || slot == 0U ||
        slot >= CHANNEL_SESSION_SLOTS || !channel_control_type_valid(type))
        return -1;
    entry = &s->channel_table.slots[slot];
    if (type == CTRL_CHANNEL_OPEN) {
        if (entry->state != CHANNEL_SLOT_OPENING ||
            channel_session_open_encode(&entry->open, body) != 0)
            return -1;
        body_length = CHANNEL_SESSION_OPEN_BYTES;
    } else {
        memset(&result, 0, sizeof(result));
        result.version = 1U;
        result.kind = entry->open.kind;
        result.handle = entry->handle;
        if (type == CTRL_CHANNEL_ACCEPT || type == CTRL_CHANNEL_REFUSE)
            result.code = entry->decision_code;
        else if (type == CTRL_CHANNEL_CLOSE)
            result.code = entry->close_code;
        else
            result.code = entry->peer_close_code;
        if (channel_session_result_encode(type, &result, body) != 0)
            return -1;
        body_length = CHANNEL_SESSION_RESULT_BYTES;
    }

    /* Mark before admission: deterministic fake transports may complete and
     * call wire_notify_result() synchronously from wire_submit(). */
    s->channel_control_inflight = 1U;
    s->channel_control_type = type;
    s->channel_control_slot = slot;
    s->channel_control_handle = entry->handle;
    /* channel-session lifecycle is ordinary authenticated application state.  It must
     * stop at the epoch-rekey reserve and resume under the next epoch; only rekey,
     * terminal error and bounded outer-session close may spend the carve. */
    rc = wire_submit(s, SEND_LANE_CONTROL, SESSION_TX_EPOCH_CURRENT,
                     SESSION_TX_SEQ_NORMAL,
                     SESSION_TX_MODE_ESTABLISHED,
                     CHAN_FF_BIT, type, body, body_length,
                     SESSION_TX_DONE_CHANNEL_CONTROL, type, entry->handle,
                     0U);
    if (rc != 0 && s->channel_control_inflight &&
        s->channel_control_type == type &&
        s->channel_control_slot == slot) {
        s->channel_control_inflight = 0U;
        s->channel_control_type = 0U;
        s->channel_control_slot = 0U;
        s->channel_control_handle = 0U;
    }
    return rc;
}

static int channel_slot_from_handle(const session_t *s, uint64_t handle,
                                    uint8_t *slot_out)
{
    uint8_t slot;
    uint32_t generation;

    if (!s || !slot_out || handle > UINT32_MAX ||
        channel_session_handle_decode((uint32_t)handle, &slot,
                                      &generation) != 0)
        return -1;
    *slot_out = slot;
    return 0;
}

static void channel_control_complete(session_t *s, uint8_t type,
                                     uint32_t handle, int completed,
                                     int64_t now_ms)
{
    uint8_t slot;
    session_channel_runtime_t *runtime;

    if (!s || channel_slot_from_handle(s, handle, &slot) != 0 ||
        !s->channel_control_inflight ||
        s->channel_control_type != type ||
        s->channel_control_slot != slot ||
        s->channel_control_handle != (uint32_t)handle) {
        if (s) {
            fprintf(stderr,
                    "session: FATAL: channel-session control completion owner mismatch\n");
            s->run_failed = 1;
            s->wire_protocol_failure = 1;
        }
        return;
    }
    runtime = &s->channel_runtime[slot];
    s->channel_control_inflight = 0U;
    s->channel_control_type = 0U;
    s->channel_control_slot = 0U;
    s->channel_control_handle = 0U;
    s->channel_control_cursor = slot;

    if (!completed) {
        if (type == CTRL_CHANNEL_OPEN)
            runtime->open_next_ms = now_ms + CHANNEL_CONTROL_RETRY_FLOOR_MS;
        else if (type == CTRL_CHANNEL_CLOSE)
            runtime->close_next_ms = now_ms + CHANNEL_CONTROL_RETRY_FLOOR_MS;
        else
            runtime->response_next_ms =
                now_ms + CHANNEL_CONTROL_RETRY_FLOOR_MS;
        return;
    }
    if (type == CTRL_CHANNEL_OPEN) {
        if (runtime->open_retry_index < 4U)
            runtime->open_retry_index++;
        runtime->open_next_ms = runtime->open_retry_index < 4U
            ? runtime->open_started_ms +
                  channel_retry_offsets_ms[runtime->open_retry_index]
            : runtime->open_deadline_ms;
    } else if (type == CTRL_CHANNEL_ACCEPT ||
               type == CTRL_CHANNEL_REFUSE) {
        runtime->decision_pending = 0U;
    } else if (type == CTRL_CHANNEL_CLOSE_ACK) {
        runtime->close_ack_pending = 0U;
        runtime->peer_close_ack_completed = 1U;
    } else if (type == CTRL_CHANNEL_CLOSE) {
        if (runtime->close_retry_index < 5U)
            runtime->close_retry_index++;
        runtime->close_next_ms = runtime->close_retry_index <= 4U
            ? runtime->close_started_ms + channel_retry_offsets_ms[
                  runtime->close_retry_index - 1U]
            : runtime->close_deadline_ms;
    }
}

static uint8_t channel_control_candidate(session_t *s, int64_t now_ms,
                                         uint8_t wanted)
{
    unsigned int offset;

    for (offset = 0U; offset < CHANNEL_SESSION_DATA_SLOTS; offset++) {
        uint8_t slot = (uint8_t)(1U +
            ((unsigned int)s->channel_control_cursor + offset) %
                CHANNEL_SESSION_DATA_SLOTS);
        channel_session_slot_t *entry = &s->channel_table.slots[slot];
        session_channel_runtime_t *runtime = &s->channel_runtime[slot];
        int due = 0;

        if (wanted == CTRL_CHANNEL_CLOSE_ACK)
            due = runtime->close_ack_pending &&
                  now_ms >= runtime->response_next_ms;
        else if (wanted == CTRL_CHANNEL_ACCEPT ||
                 wanted == CTRL_CHANNEL_REFUSE)
            due = runtime->decision_pending &&
                  entry->decision_type == wanted &&
                  now_ms >= runtime->response_next_ms;
        else if (wanted == CTRL_CHANNEL_CLOSE)
            due = runtime->close_armed &&
                  entry->state == CHANNEL_SLOT_CLOSING &&
                  now_ms >= runtime->close_next_ms;
        else if (wanted == CTRL_CHANNEL_OPEN)
            due = !s->is_server && runtime->open_armed &&
                  entry->state == CHANNEL_SLOT_OPENING &&
                  runtime->open_retry_index < 4U &&
                  now_ms >= runtime->open_next_ms;
        if (due)
            return slot;
    }
    return 0U;
}

void session_channel_tick(session_t *s, int64_t now_ms)
{
    uint8_t slot;
    unsigned int i;
    static const uint8_t priority[] = {
        CTRL_CHANNEL_CLOSE_ACK, CTRL_CHANNEL_REFUSE, CTRL_CHANNEL_ACCEPT,
        CTRL_CHANNEL_CLOSE, CTRL_CHANNEL_OPEN
    };

    if (!s || !session_channelised_active(s) || now_ms < 0 ||
        (s->state != SESSION_ESTABLISHED &&
         s->state != SESSION_REKEYING))
        return;

    for (slot = 1U; slot < CHANNEL_SESSION_SLOTS; slot++) {
        channel_session_slot_t *entry = &s->channel_table.slots[slot];
        session_channel_runtime_t *runtime = &s->channel_runtime[slot];

        if (runtime->open_armed &&
            now_ms >= runtime->open_deadline_ms &&
            (entry->state == CHANNEL_SLOT_OPENING ||
             channel_session_live_count(&s->channel_table) == 0U)) {
            if (!s->is_server &&
                s->channel_application[slot].child_lease)
                session_child_lease_fail(s, slot, now_ms);
            fprintf(stderr,
                    "session: channel-session first OPEN timed out after 31s\n");
            s->run_failed = 1;
            session_close(s);
            return;
        }
        if (runtime->close_armed &&
            now_ms >= runtime->close_deadline_ms &&
            entry->state == CHANNEL_SLOT_CLOSING) {
            fprintf(stderr,
                    "session: channel-session CLOSE timed out after 31s\n");
            s->run_failed = 1;
            session_close(s);
            return;
        }
        /* A retained/partially written ACK is still an uncompleted handoff.
         * Evaluate the last-channel bound before the global in-flight early
         * return so a permanently blocked transport cannot extend it. */
        if (runtime->peer_close_hold &&
            now_ms >= runtime->peer_close_deadline_ms) {
            if (!runtime->peer_close_ack_completed) {
                fprintf(stderr,
                        "session: channel-session last-channel CLOSE could not hand off an ACK within 31s\n");
                s->run_failed = 1;
            }
            runtime->peer_close_hold = 0U;
            session_close(s);
            return;
        }
    }
    if (s->channel_control_inflight)
        return;
    for (i = 0U; i < sizeof(priority) / sizeof(priority[0]); i++) {
        slot = channel_control_candidate(s, now_ms, priority[i]);
        if (slot != 0U) {
            (void)channel_control_submit(s, slot, priority[i]);
            return;
        }
    }
    if (channel_session_live_count(&s->channel_table) == 0U) {
        int local_close_complete = 0;
        int response_pending = 0;
        int peer_close_hold = 0;

        for (slot = 1U; slot < CHANNEL_SESSION_SLOTS; slot++) {
            channel_session_slot_t *entry = &s->channel_table.slots[slot];
            session_channel_runtime_t *runtime = &s->channel_runtime[slot];

            if (entry->local_close_acked)
                local_close_complete = 1;
            if (runtime->close_ack_pending || runtime->decision_pending)
                response_pending = 1;
            if (runtime->peer_close_hold) {
                peer_close_hold = 1;
            }
        }
        if (local_close_complete && !response_pending && !peer_close_hold)
            session_close(s);
    }
}

int64_t session_channel_next_deadline(const session_t *s, int64_t now_ms)
{
    int64_t deadline = -1;
    uint8_t slot;
    unsigned int live_count;

    if (!s || !session_channelised_active(s) || now_ms < 0 ||
        (s->state != SESSION_ESTABLISHED &&
         s->state != SESSION_REKEYING))
        return -1;
    live_count = channel_session_live_count(&s->channel_table);
    for (slot = 1U; slot < CHANNEL_SESSION_SLOTS; slot++) {
        const channel_session_slot_t *entry = &s->channel_table.slots[slot];
        const session_channel_runtime_t *runtime =
            &s->channel_runtime[slot];
        int64_t candidate = -1;
        int control_owned =
            s->channel_control_inflight &&
            s->channel_control_slot == slot &&
            s->channel_control_handle == entry->handle;

        /* A logical control already retained by the global wire owner is
         * progressed by descriptor readiness, not by re-admitting its
         * already-due retry timestamp. During epoch-rekey that owner is deliberately
         * ineligible; returning zero here would hot-spin until rekey ends.
         * Absolute lifecycle/tombstone horizons remain independently due. */
        if (!control_owned &&
            (runtime->close_ack_pending || runtime->decision_pending))
            candidate = runtime->response_next_ms > now_ms
                ? runtime->response_next_ms : now_ms;
        if (runtime->close_armed &&
            entry->state == CHANNEL_SLOT_CLOSING) {
            int64_t close_candidate = control_owned
                ? runtime->close_deadline_ms
                : (runtime->close_next_ms < runtime->close_deadline_ms
                   ? runtime->close_next_ms
                   : runtime->close_deadline_ms);
            if (candidate < 0 || close_candidate < candidate)
                candidate = close_candidate;
        }
        if (runtime->open_armed &&
            (entry->state == CHANNEL_SLOT_OPENING || live_count == 0U)) {
            int64_t open_candidate = !s->is_server && !control_owned
                ? (runtime->open_next_ms < runtime->open_deadline_ms
                   ? runtime->open_next_ms
                   : runtime->open_deadline_ms)
                : runtime->open_deadline_ms;
            if (candidate < 0 || open_candidate < candidate)
                candidate = open_candidate;
        }
        if (runtime->peer_close_hold &&
            (candidate < 0 || runtime->peer_close_deadline_ms < candidate))
            candidate = runtime->peer_close_deadline_ms;
        if (candidate >= 0 && (deadline < 0 || candidate < deadline))
            deadline = candidate;
    }
    if (deadline < 0)
        return -1;
    return deadline <= now_ms ? 0 : deadline - now_ms;
}

int session_channel_terminal_complete(session_t *s, uint32_t code)
{
    uint8_t slot;
    uint32_t generation;
    int64_t now_ms;

    if (!s || !session_channelised_active(s) ||
        channel_session_handle_decode(s->terminal_channel_handle,
                                      &slot, &generation) != 0)
        return -1;
    if (s->channel_table.slots[slot].state == CHANNEL_SLOT_CLOSING ||
        (s->channel_table.slots[slot].state == CHANNEL_SLOT_RETIRED &&
         s->channel_table.slots[slot].peer_close_seen))
        return 0;
    if (channel_session_begin_close(&s->channel_table,
                                    s->terminal_channel_handle, code) != 0)
        return -1;
    now_ms = mono_ms();
    channel_runtime_arm_close(&s->channel_runtime[slot], now_ms);
    session_event_emit_channel(
        s, EVENT_LOG_EVENT_CLOSE, channel_code_event_reason(code),
        s->terminal_channel_handle,
        s->channel_table.slots[slot].open.kind, code, now_ms);
    session_channel_tick(s, now_ms);
    return 0;
}

static int session_channel_begin_stream_close(session_t *s, uint8_t slot,
                                              uint32_t code)
{
    sync_instance_binding_t *binding;

    if (!s || !session_channelised_active(s) || slot == 0U ||
        slot >= CHANNEL_SESSION_SLOTS)
        return -1;
    binding = &s->sync_binding[slot];
    if (!binding->configured || binding->handle == 0U ||
        s->channel_table.slots[slot].handle != binding->handle)
        return -1;
    return channel_application_begin_close(s, slot, code, mono_ms());
}

void session_channel_stream_receive_complete(session_t *s, uint8_t slot,
                                             int have_code, int32_t code)
{
    session_channel_application_t *app;

    if (!s || !session_channelised_active(s) || slot == 0U ||
        slot >= CHANNEL_SESSION_SLOTS)
        return;
    app = &s->channel_application[slot];

    /* The anchor terminal still reports its process result through the
     * historical CLI return seam. Dynamic attach connections receive the
     * same value as a framed EXIT over the local attach protocol. */
    if (!s->is_server && slot == 1U && have_code) {
        ssize_t written = write(STDOUT_FILENO, "\r\n", 2U);

        (void)written;
        s->client_exit_code = (int)code;
        s->pty_eof_seen = 1;
    } else if (!s->is_server && app->active && app->child_lease &&
               have_code) {
        uint32_t close_code = code == 0
            ? CHANNEL_CODE_OK : CHANNEL_CODE_RESOURCE;
        int64_t now_ms = mono_ms();

        app->terminal_code = (uint32_t)code;
        app->receive_complete = 1U;
        if (!app->child_lease_fin_sent ||
            child_transfer_active_count(&s->child_transfers) != 0U ||
            code != 0)
            session_child_lease_fail(s, slot, now_ms);
        if (channel_application_begin_close(
                s, slot, close_code, now_ms) != 0) {
            fprintf(stderr,
                    "session: child-transfer aggregate child lease could not enter ordinary close\n");
            session_child_lease_fail(s, slot, now_ms);
        }
    } else if (!s->is_server && app->active && app->attach_bound &&
               have_code) {
        app->terminal_code = (uint32_t)code;
        app->receive_complete = 1U;
    }
}

void session_channel_stream_send_complete(session_t *s, uint8_t slot,
                                          uint32_t code)
{
    if (session_channel_begin_stream_close(s, slot, code) != 0) {
        fprintf(stderr,
                "session: FATAL: could not begin channel-session stream close\n");
        if (s) {
            s->run_failed = 1;
            s->wire_protocol_failure = 1;
            session_close(s);
        }
    }
}

void session_channel_stream_io_failed(session_t *s, uint8_t slot,
                                      uint32_t code)
{
    if (!s)
        return;
    if (!session_channelised_active(s) || slot == 0U ||
        slot >= CHANNEL_SESSION_SLOTS) {
        s->run_failed = 1;
        session_close(s);
        return;
    }
    if (s->channel_table.slots[slot].handle ==
        s->terminal_channel_handle)
        s->run_failed = 1;
    if (!s->is_server && s->channel_application[slot].child_lease)
        session_child_lease_fail(s, slot, mono_ms());
    fprintf(stderr,
            "session: channel stream failed "
            "(role=%s slot=%u handle=%u kind=%u code=%u)\n",
            s->is_server ? "listener" : "client",
            (unsigned int)slot,
            (unsigned int)s->channel_table.slots[slot].handle,
            (unsigned int)s->channel_table.slots[slot].open.kind,
            (unsigned int)code);
    channel_application_cancel_process(s, slot, mono_ms());
    session_channel_stream_send_complete(s, slot, code);
}

/* -------------------------------------------------------------------------
 * sync-status truthful status / idle heartbeat
 * ---------------------------------------------------------------------- */

int session_status_active(const session_t *s)
{
    uint8_t slot;

    if (!s || !s->sync_status.active ||
        (s->selected_caps & UNMOOR_CAP_STATUS_HEARTBEAT_V1) == 0U)
        return 0;
    if (!session_channelised_active(s))
        return sync_active(s);
    for (slot = 1U; slot < CHANNEL_SESSION_SLOTS; slot++)
        if (sync_active_instance(s, slot))
            return 1;
    return 0;
}

static int session_status_counters(const session_t *s,
                                   uint64_t *tx_tip,
                                   uint64_t *rx_delivered,
                                   uint64_t *rx_highest,
                                   int *sink_blocked)
{
    if (session_channelised_active(s))
        return sync_aggregate_snapshot(s, tx_tip, rx_delivered, rx_highest,
                                       sink_blocked);
    *tx_tip = s->sync_tx.tip;
    *rx_delivered = s->sync_rx.delivered;
    *rx_highest = s->sync_rx.highest;
    *sink_blocked = s->sync_rx.sink_blocked;
    return 0;
}

int session_async_terminal_text_suppressed(const session_t *s)
{
    return s && s->raw_mode_active && s->shared_raw_display_tty;
}

static void session_status_present(session_t *s, int64_t now_ms)
{
    sync_status_view_t view;
    uint64_t tx_tip, rx_delivered, rx_highest;
    int sink_blocked;
    int announce;
    int refresh;

    if (!session_status_active(s))
        return;
    if (session_status_counters(s, &tx_tip, &rx_delivered, &rx_highest,
                                &sink_blocked) != 0) {
        fprintf(stderr,
                "session: FATAL: sync-status cumulative counter overflow\n");
        session_protocol_error_close(s, ERR_SESSION);
        return;
    }
    (void)sink_blocked;
    (void)sync_status_evaluate(&s->sync_status, now_ms, tx_tip,
                               rx_delivered, rx_highest);
    sync_status_snapshot(&s->sync_status, now_ms, tx_tip,
                         rx_delivered, rx_highest, &view);
    announce = !s->sync_status.state_announced ||
               s->sync_status.announced_state != view.state;
    refresh = announce ||
              (view.state != SYNC_STATUS_SYNC &&
               now_ms >= s->sync_status.next_title_refresh_ms);

    if (announce) {
        char title[160];
        if (!session_async_terminal_text_suppressed(s) &&
            sync_status_format_title(&view, title, sizeof(title)) == 0)
            fprintf(stderr, "%s\n", title);
        s->sync_status.state_announced = 1;
        s->sync_status.announced_state = view.state;
    }
    if (refresh) {
        if (session_status_ui)
            session_status_ui(s, &view);
        s->sync_status.next_title_refresh_ms =
            now_ms + SYNC_STATUS_TITLE_REFRESH_MS;
    }
}

static int send_status_record(session_t *s, uint8_t request_flags,
                              session_tx_done_t done,
                              uint32_t coalesce_key,
                              int64_t now_hint_ms)
{
    sync_status_record_t record;
    uint8_t wire[SYNC_STATUS_WIRE_LEN];
    uint64_t tx_tip;
    uint64_t rx_delivered;
    uint64_t rx_highest;
    int sink_blocked;

    if (!session_status_active(s) ||
        (s->state != SESSION_ESTABLISHED &&
         !(delivery_status_combined(s) &&
           s->state == SESSION_REKEYING)))
        return -1;
    if (s->epoch_rekey_enabled &&
        s->tx_seq >= REKEY_SEQ_RESERVE_START) {
        if (s->rekey_phase == REKEY_NONE)
            (void)session_request_epoch_rekey(s);
        return -1;
    }
    memset(&record, 0, sizeof(record));
    record.flags = request_flags;
    if (session_status_counters(s, &tx_tip, &rx_delivered, &rx_highest,
                                &sink_blocked) != 0) {
        fprintf(stderr,
                "session: FATAL: sync-status cumulative counter overflow\n");
        session_protocol_error_close(s, ERR_SESSION);
        return -1;
    }
    (void)rx_highest;
    if (sink_blocked)
        record.flags |= SYNC_STATUS_FLAG_SINK_BLOCKED;
    record.epoch = s->epoch_rekey_enabled ? s->epoch : 0;
    record.tx_tip = tx_tip;
    record.rx_delivered = rx_delivered;
    if (sync_status_record_encode(&record, wire) != 0)
        return -1;
    if (delivery_status_combined(s)) {
        int rc;
        int64_t publish_now = now_hint_ms >= 0 ? now_hint_ms : mono_ms();

        if (!s->delivery_initialized ||
            !s->delivery_latest_tx.objects[0].configured) {
            fprintf(stderr,
                    "session: FATAL: combined sync-status publisher is unbound\n");
            session_protocol_error_close(s, ERR_SESSION);
            return -1;
        }
        if (done == SESSION_TX_DONE_STATUS_PERIODIC &&
            s->d29_latest_periodic_pending)
            return 0;
        rc = delivery_latest_sender_publish(
            &s->delivery_latest_tx, DELIVERY_LATEST_SYSTEM_OBJECT_ID,
            wire, sizeof(wire));
        if (rc != DELIVERY_RESULT_OK) {
            fprintf(stderr,
                    "session: FATAL: combined sync-status publication refused "
                    "(%d)\n", rc);
            session_protocol_error_close(s, ERR_RESOURCE);
            return -1;
        }
        s->delivery_head_next_ms[0] = publish_now;
        if (done == SESSION_TX_DONE_STATUS_PERIODIC ||
            s->d29_latest_periodic_pending) {
            s->d29_latest_periodic_pending = 1;
            s->d29_latest_periodic_revision =
                s->delivery_latest_tx.objects[0].published_revision;
        }
        return 0;
    }
    return wire_submit(s, SEND_LANE_FEEDBACK,
                       SESSION_TX_EPOCH_CURRENT,
                       SESSION_TX_SEQ_NORMAL,
                       SESSION_TX_MODE_ESTABLISHED,
                       CHAN_FF_BIT, CTRL_STATUS_HEARTBEAT,
                       wire, sizeof(wire), done,
                       now_hint_ms >= 0 ? (uint64_t)now_hint_ms : 0,
                       0, coalesce_key);
}

void session_status_tick(session_t *s, int64_t now_ms)
{
    if (!session_status_active(s) || s->state != SESSION_ESTABLISHED)
        return;
    session_status_present(s, now_ms);
    if (sync_status_heartbeat_due(&s->sync_status, now_ms)) {
        (void)send_status_record(s, 0,
                                 SESSION_TX_DONE_STATUS_PERIODIC,
                                 WIRE_COALESCE_STATUS, now_ms);
        /* COMPLETE or actual FAILED advances cadence in the result callback.
         * Scheduler residence is neither a send nor a retry timer. */
    }
}

int64_t session_status_next_deadline(const session_t *s, int64_t now_ms)
{
    if (!s || !session_status_active(s))
        return -1;
    if (delivery_status_combined(s) && s->d29_latest_periodic_pending)
        return sync_status_next_state_deadline(&s->sync_status, now_ms);
    return sync_status_next_deadline(&s->sync_status, now_ms);
}

void session_status_query(session_t *s)
{
    sync_status_view_t view;
    path_leg_metrics_t metrics[MULTIPATH_PATHS_MAX];
    uint64_t tx_tip, rx_delivered, rx_highest;
    int sink_blocked;
    uint8_t leg_count = 0U;
    char line[SYNC_STATUS_LINE_MAX];
    int64_t now_ms = mono_ms();

    if (!session_status_active(s)) {
        fprintf(stderr,
                "unmoor: status unavailable (peer did not negotiate "
                "status-heartbeat-v1)\n");
        return;
    }
    session_status_present(s, now_ms);
    if (session_status_counters(s, &tx_tip, &rx_delivered, &rx_highest,
                                &sink_blocked) != 0) {
        fprintf(stderr,
                "session: FATAL: sync-status cumulative counter overflow\n");
        session_protocol_error_close(s, ERR_SESSION);
        return;
    }
    (void)sink_blocked;
    sync_status_snapshot(&s->sync_status, now_ms, tx_tip,
                         rx_delivered, rx_highest, &view);
    memset(metrics, 0, sizeof(metrics));
    if (session_path_metrics_snapshot(
            s, metrics, MULTIPATH_PATHS_MAX, &leg_count) != 0)
        leg_count = 0U;
    if (sync_status_format_line_with_legs(
            &view, metrics, leg_count, line, sizeof(line)) == 0) {
        if (session_async_terminal_text_suppressed(s))
            fprintf(stderr, "\r\n%s\r\n", line);
        else
            fprintf(stderr, "%s\n", line);
    }
    (void)send_status_record(s, SYNC_STATUS_FLAG_POLL,
                             SESSION_TX_DONE_NONE,
                             WIRE_COALESCE_STATUS_POLL, now_ms);
}

/* -------------------------------------------------------------------------
 * Explicit operator diagnostic snapshot
 * ---------------------------------------------------------------------- */

#define SESSION_DIAGNOSTIC_LINE_MAX 1024U

typedef struct session_diagnostic_writer {
    int fd;
    int saved_flags;
    unsigned int attempted;
    unsigned int emitted;
    unsigned int dropped;
    uint8_t flags_changed;
    uint8_t raw_terminal;
} session_diagnostic_writer_t;

static const char *session_diagnostic_state_name(session_state_t state)
{
    switch (state) {
    case SESSION_IDLE:         return "idle";
    case SESSION_CONNECTING:   return "connecting";
    case SESSION_KEY_DERIVING: return "key_deriving";
    case SESSION_ESTABLISHED:  return "established";
    case SESSION_REKEYING:     return "rekeying";
    case SESSION_CLOSING:      return "closing";
    }
    return "invalid";
}

static const char *session_diagnostic_path_state_name(uint8_t state)
{
    switch ((multipath_path_state_t)state) {
    case MULTIPATH_PATH_EMPTY:       return "empty";
    case MULTIPATH_PATH_CONFIGURED:  return "configured";
    case MULTIPATH_PATH_PROVISIONAL: return "provisional";
    case MULTIPATH_PATH_VALIDATED:   return "validated";
    }
    return "invalid";
}

static void session_diagnostic_remote_address(
    const multipath_token_t *token, char *out, socklen_t out_size)
{
    int family;

    if (!out || out_size == 0U)
        return;
    (void)snprintf(out, out_size, "unavailable");
    if (!token || !multipath_token_valid(token))
        return;
    family = token->family == 4U ? AF_INET : AF_INET6;
    if (inet_ntop(family, token->address, out, out_size) == NULL)
        (void)snprintf(out, out_size, "unavailable");
}

static int session_diagnostic_writer_open(session_diagnostic_writer_t *writer,
                                          int fd, int raw_terminal)
{
    int flags;

    if (!writer || fd < 0)
        return -1;
    memset(writer, 0, sizeof(*writer));
    writer->fd = fd;
    writer->raw_terminal = raw_terminal != 0;
    do {
        flags = fcntl(fd, F_GETFL, 0);
    } while (flags < 0 && errno == EINTR);
    if (flags < 0)
        return -1;
    writer->saved_flags = flags;
    if ((flags & O_NONBLOCK) == 0) {
        int rc;

        do {
            rc = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        } while (rc < 0 && errno == EINTR);
        if (rc < 0)
            return -1;
        writer->flags_changed = 1U;
    }
    return 0;
}

static void session_diagnostic_writer_close(session_diagnostic_writer_t *writer)
{
    int rc;

    if (!writer || !writer->flags_changed)
        return;
    do {
        rc = fcntl(writer->fd, F_SETFL, writer->saved_flags);
    } while (rc < 0 && errno == EINTR);
    if (rc < 0)
        writer->dropped++;
    writer->flags_changed = 0U;
}

static void session_diagnostic_line(session_diagnostic_writer_t *writer,
                                    const char *format, ...)
#if defined(__GNUC__) || defined(__clang__)
    __attribute__((format(printf, 2, 3)))
#endif
    ;

static void session_diagnostic_line(session_diagnostic_writer_t *writer,
                                    const char *format, ...)
{
    char line[SESSION_DIAGNOSTIC_LINE_MAX];
    va_list arguments;
    size_t offset = 0U;
    size_t length;
    int count;
    ssize_t written;

    if (!writer || !format)
        return;
    writer->attempted++;
    if (writer->raw_terminal) {
        line[0] = '\r';
        line[1] = '\n';
        offset = 2U;
    }
    va_start(arguments, format);
    count = vsnprintf(line + offset, sizeof(line) - offset,
                      format, arguments);
    va_end(arguments);
    if (count < 0 || (size_t)count >= sizeof(line) - offset - 2U) {
        writer->dropped++;
        return;
    }
    length = offset + (size_t)count;
    if (writer->raw_terminal)
        line[length++] = '\r';
    line[length++] = '\n';
    do {
        written = write(writer->fd, line, length);
    } while (written < 0 && errno == EINTR);
    if (written == (ssize_t)length)
        writer->emitted++;
    else
        writer->dropped++;
}

/* Aggregate view of the send-side DATA gate across live instances.  Reason
 * is the union of what is currently shut, `closed_ms` the oldest still-open
 * close, and `frontier_age_ms` the worst delivery age: a reader chasing a
 * stall wants the instance that is furthest behind, not an average that
 * hides it. */
typedef struct {
    uint32_t closes;
    uint32_t opens;
    unsigned reason;
    int64_t  closed_ms;
    int64_t  paused_ms;
    int64_t  frontier_age_ms;
    unsigned instances;
    /* Read-side gate at the instant of the snapshot: the union of what is
     * shut now, and the oldest still-open quota close.  Separate from
     * `reason`, which describes the send-side DATA gate. */
    unsigned source_gate;
    int64_t  source_blocked_open_ms;
} session_diagnostic_gate_t;

static void session_diagnostic_fold_tx(const sync_tx_t *tx, int64_t now_ms,
                                       sync_tx_stats_t *stats,
                                       session_diagnostic_gate_t *gate)
{
    unsigned i;

    for (i = 0U; i < SYNC_TX_CLASS_COUNT; i++) {
        stats->attempts[i] += tx->stats.attempts[i];
        stats->completed[i] += tx->stats.completed[i];
        stats->failed[i] += tx->stats.failed[i];
        stats->payload_attempted[i] += tx->stats.payload_attempted[i];
        stats->payload_completed[i] += tx->stats.payload_completed[i];
    }
    for (i = 0U; i < SYNC_SIZE_BUCKETS; i++)
        stats->size_bucket[i] += tx->stats.size_bucket[i];
    for (i = 0U; i < SYNC_SHORT_COUNT; i++)
        stats->short_reason[i] += tx->stats.short_reason[i];
    stats->at_ceiling += tx->stats.at_ceiling;
    stats->near_ceiling += tx->stats.near_ceiling;
    stats->source_blocked_closes += tx->stats.source_blocked_closes;
    stats->source_blocked_opens += tx->stats.source_blocked_opens;
    stats->source_blocked_ms += tx->stats.source_blocked_ms;
    stats->cliff_arms += tx->stats.cliff_arms;
    stats->cliff_repair_attempts += tx->stats.cliff_repair_attempts;
    stats->cliff_repair_completed += tx->stats.cliff_repair_completed;
    stats->cliff_repair_payload += tx->stats.cliff_repair_payload;
    stats->bitmap_repair_attempts += tx->stats.bitmap_repair_attempts;
    stats->bitmap_repair_completed += tx->stats.bitmap_repair_completed;
    stats->bitmap_repair_payload += tx->stats.bitmap_repair_payload;
    /* Peak occupancy is per instance, so the fold reports the worst one; a
     * sum would invent an occupancy no single backlog ever held. */
    if (tx->stats.retained_peak > stats->retained_peak)
        stats->retained_peak = tx->stats.retained_peak;
    gate->source_gate |= tx->gate_state;
    if (tx->source_blocked_since_ms != 0 &&
        now_ms > tx->source_blocked_since_ms &&
        now_ms - tx->source_blocked_since_ms > gate->source_blocked_open_ms)
        gate->source_blocked_open_ms = now_ms - tx->source_blocked_since_ms;
    if (tx->stats.max_payload > stats->max_payload)
        stats->max_payload = tx->stats.max_payload;
    if (tx->stats.last_ceiling > stats->last_ceiling)
        stats->last_ceiling = tx->stats.last_ceiling;

    gate->instances++;
    gate->closes += tx->data_gate_closes;
    gate->opens += tx->data_gate_opens;
    gate->paused_ms += tx->data_gate_paused_ms;
    if (tx->data_gate_closed_ms != 0) {
        gate->reason |= tx->data_gate_reason;
        if (gate->closed_ms == 0 || tx->data_gate_closed_ms < gate->closed_ms)
            gate->closed_ms = tx->data_gate_closed_ms;
    }
    if (tx->last_frontier_ms > 0 && now_ms > tx->last_frontier_ms) {
        int64_t age = now_ms - tx->last_frontier_ms;

        if (age > gate->frontier_age_ms)
            gate->frontier_age_ms = age;
    }
}

int session_diagnostic_snapshot(session_t *s, int fd,
                                uint64_t snapshot_id, int64_t now_ms)
{
    session_diagnostic_writer_t writer;
    sync_tx_stats_t tx_stats;
    session_diagnostic_gate_t gate;
    multipath_snapshot_t paths;
    transport_stats_t transport_stats;
    uint16_t local_ports[MULTIPATH_PATHS_MAX];
    uint8_t local_families[MULTIPATH_PATHS_MAX];
    uint64_t tx_tip = 0U;
    uint64_t tx_base = 0U;
    uint64_t tx_sent = 0U;
    uint64_t tx_credit = 0U;
    uint64_t tx_quota = 0U;
    uint64_t rx_delivered = 0U;
    uint64_t rx_frontier = 0U;
    uint64_t rx_highest = 0U;
    uint64_t rx_pending = 0U;
    int sink_blocked = 0;
    int have_transport_stats = 0;
    int have_sync = 0;
    int have_paths = 0;
    int local_port_count = 0;
    int local_family_count = 0;
    uint8_t path_count = 1U;
    unsigned int leg;
    int64_t auth_age_ms;
    unsigned int expected;

    if (!s || fd < 0 || snapshot_id == 0U)
        return -1;
    if (s->diagnostic_snapshot_count >=
        SESSION_DIAGNOSTIC_SNAPSHOT_LIMIT)
        return -1;
    s->diagnostic_snapshot_count++;
    if (now_ms < 0)
        now_ms = mono_ms();
    if (now_ms < 0 ||
        session_diagnostic_writer_open(
            &writer, fd, session_async_terminal_text_suppressed(s)) != 0)
        return -1;

    memset(&paths, 0, sizeof(paths));
    memset(&transport_stats, 0, sizeof(transport_stats));
    memset(&tx_stats, 0, sizeof(tx_stats));
    memset(&gate, 0, sizeof(gate));
    memset(local_ports, 0, sizeof(local_ports));
    memset(local_families, 0, sizeof(local_families));
    if (s->transport && s->transport->ops) {
        const transport_ops_t *ops = s->transport->ops;

        if (ops->stats && ops->stats(s->transport, &transport_stats) == 0)
            have_transport_stats = 1;
        if (ops->configured_local_ports)
            local_port_count = ops->configured_local_ports(
                s->transport, local_ports);
        if (ops->configured_local_families)
            local_family_count = ops->configured_local_families(
                s->transport, local_families);
    }
    if (s->multipath_active &&
        multipath_get_snapshot(&s->multipath, &paths) == 0) {
        have_paths = 1;
        path_count = paths.path_limit;
    }
    auth_age_ms = s->last_authenticated_ms > 0 &&
                  now_ms > s->last_authenticated_ms
        ? now_ms - s->last_authenticated_ms : 0;

    session_diagnostic_line(
        &writer,
        "unmoor: diagnostic id=%" PRIu64 " session role=%s state=%s "
        "epoch=%" PRIu32 " auth-age-ms=%" PRId64 " tx-seq=%" PRIu32
        " rx-hwm=%" PRIu32 " replay-drops=%" PRIu64
        " caps=0x%08" PRIx32,
        snapshot_id, s->is_server ? "listener" : "client",
        session_diagnostic_state_name(s->state),
        s->epoch_rekey_enabled ? s->epoch : 0U, auth_age_ms,
        s->tx_seq, s->rx_hwm, s->replay_drop_count, s->selected_caps);

    /* The pre-authentication budget is the one place an unauthenticated
     * sender leaves a trace; a flood shows up here before anything else. */
    session_diagnostic_line(
        &writer,
        "unmoor: diagnostic id=%" PRIu64 " preauth aead-attempts=%" PRIu64
        " aead-failures=%" PRIu64 " budget-drops=%" PRIu64
        " table-full-drops=%" PRIu64,
        snapshot_id,
        s->preauth_budget.counters.aead_attempt,
        s->preauth_budget.counters.aead_failure,
        s->preauth_budget.counters.budget_drop,
        s->preauth_budget.counters.table_full_drop);
    session_diagnostic_line(
        &writer,
        "unmoor: diagnostic id=%" PRIu64 " preauth no-key-drops=%" PRIu64
        " unknown-pair-drops=%" PRIu64 " malformed-drops=%" PRIu64,
        snapshot_id,
        s->preauth_budget.counters.no_key_drop,
        s->preauth_budget.counters.unknown_pair_drop,
        s->preauth_budget.counters.malformed_preauth_drop);

    if (have_transport_stats) {
        session_diagnostic_line(
            &writer,
            "unmoor: diagnostic id=%" PRIu64 " io transport=%u "
            "tx-datagrams=%" PRIu32 " tx-failed=%" PRIu32
            " rx-datagrams=%" PRIu32 " rx-dropped=%" PRIu32,
            snapshot_id, (unsigned int)transport_stats.transport_id,
            transport_stats.tx_ok, transport_stats.tx_fail,
            transport_stats.rx_ok, transport_stats.rx_drop);
    } else {
        session_diagnostic_line(
            &writer, "unmoor: diagnostic id=%" PRIu64
            " io unavailable", snapshot_id);
    }

    if (session_status_active(s) &&
        session_status_counters(s, &tx_tip, &rx_delivered, &rx_highest,
                                &sink_blocked) == 0) {
        sync_status_tracker_t tracker = s->sync_status;
        sync_status_view_t view;

        if (session_channelised_active(s)) {
            uint8_t slot;

            tx_base = s->sync_retired_tx_tip;
            tx_sent = s->sync_retired_tx_tip;
            tx_credit = s->sync_retired_tx_tip;
            rx_frontier = s->sync_retired_rx_delivered;
            for (slot = 1U; slot < CHANNEL_SESSION_SLOTS; slot++) {
                const sync_tx_t *tx = sync_tx_state_instance(s, slot);
                const sync_rx_t *rx = sync_rx_state_instance(s, slot);

                if (!tx || !rx || !tx->active)
                    continue;
                tx_base = event_counter_add(tx_base, tx->base);
                tx_sent = event_counter_add(tx_sent, tx->sent);
                tx_credit = event_counter_add(tx_credit, tx->peer_credit);
                tx_quota = event_counter_add(tx_quota, tx->quota);
                rx_frontier = event_counter_add(rx_frontier, rx->frontier);
                rx_pending = event_counter_add(
                    rx_pending, (uint64_t)rx->ring_size);
                session_diagnostic_fold_tx(tx, now_ms, &tx_stats, &gate);
            }
        } else {
            tx_base = s->sync_tx.base;
            tx_sent = s->sync_tx.sent;
            tx_credit = s->sync_tx.peer_credit;
            tx_quota = s->sync_tx.quota;
            rx_frontier = s->sync_rx.frontier;
            rx_pending = (uint64_t)s->sync_rx.ring_size;
            if (s->sync_tx.active)
                session_diagnostic_fold_tx(&s->sync_tx, now_ms, &tx_stats,
                                           &gate);
        }

        sync_status_snapshot(&tracker, now_ms, tx_tip, rx_delivered,
                             rx_highest, &view);
        session_diagnostic_line(
            &writer,
            "unmoor: diagnostic id=%" PRIu64 " sync=%s "
            "tx-base=%" PRIu64 " tx-tip=%" PRIu64
            " tx-sent=%" PRIu64 " tx-credit=%" PRIu64
            " tx-quota=%" PRIu64 " rx-delivered=%" PRIu64
            " rx-frontier=%" PRIu64 " rx-highest=%" PRIu64
            " rx-pending=%zu sink-blocked=%d behind-known=%d "
            "out-behind=%" PRIu64 " in-behind=%" PRIu64
            /* Per-direction progress ages, so a STALLED line says which side
             * of the stream stopped.  -1 means that direction has nothing
             * outstanding and so has nothing to be late for; stall-dirs is
             * zero when the stall is a path-liveness failure rather than one
             * direction falling behind. */
            " out-progress-age-ms=%" PRId64 " in-progress-age-ms=%" PRId64
            " stall-dirs=0x%02x",
            snapshot_id, sync_status_state_name(view.state),
            tx_base, tx_tip, tx_sent,
            tx_credit, tx_quota, rx_delivered,
            rx_frontier, rx_highest, (size_t)rx_pending,
            sink_blocked, view.behind_known, view.outgoing_behind,
            view.incoming_behind, view.outgoing_progress_age_ms,
            view.incoming_progress_age_ms, view.stalled_directions);
        have_sync = 1;
    }
    if (!have_sync)
        session_diagnostic_line(
            &writer, "unmoor: diagnostic id=%" PRIu64
            " sync=inactive", snapshot_id);

    if (gate.instances > 0U) {
        static const char *const class_name[SYNC_TX_CLASS_COUNT] = {
            "new", "repair", "probe"
        };
        unsigned int cls;
        unsigned int first;

        for (cls = 0U; cls < SYNC_TX_CLASS_COUNT; cls++)
            session_diagnostic_line(
                &writer,
                "unmoor: diagnostic id=%" PRIu64 " data class=%s "
                "attempts=%" PRIu64 " completed=%" PRIu64
                " failed=%" PRIu64 " payload-attempted=%" PRIu64
                " payload-completed=%" PRIu64,
                snapshot_id, class_name[cls], tx_stats.attempts[cls],
                tx_stats.completed[cls], tx_stats.failed[cls],
                tx_stats.payload_attempted[cls],
                tx_stats.payload_completed[cls]);

        /* The one recovery class, split by the producer that asked for it.
         * Every sync payload travels inside the AEAD, so a packet capture can
         * measure datagrams and their sizes but can never say which bytes were
         * first transmissions: the class totals alone leave the network
         * account of a catch-up unfalsifiable.  Bitmap repair names blocks the
         * peer reported missing; cliff repair names an extent the peer's ack
         * grammar has no way to report at all, and is the only line that
         * carries a deliberate duplicate.  The two sums reconcile exactly with
         * the repair row above, which is what makes a capture checkable
         * against the product rather than reverse-engineered from it. */
        session_diagnostic_line(
            &writer,
            "unmoor: diagnostic id=%" PRIu64 " data-repair "
            "bitmap-attempts=%" PRIu64 " bitmap-completed=%" PRIu64
            " bitmap-payload=%" PRIu64 " cliff-attempts=%" PRIu64
            " cliff-completed=%" PRIu64 " cliff-payload=%" PRIu64
            " cliff-arms=%" PRIu64,
            snapshot_id, tx_stats.bitmap_repair_attempts,
            tx_stats.bitmap_repair_completed, tx_stats.bitmap_repair_payload,
            tx_stats.cliff_repair_attempts, tx_stats.cliff_repair_completed,
            tx_stats.cliff_repair_payload, tx_stats.cliff_arms);

        /* The histogram is emitted in fixed groups of eight so one line can
         * never be truncated by a long run of large counts; a dropped line
         * would be counted as dropped, but the reconciliation would still be
         * missing the buckets it needed. */
        for (first = 0U; first < SYNC_SIZE_BUCKETS; first += 8U) {
            char counts[8U * 24U];
            size_t used = 0U;
            unsigned int i;

            counts[0] = '\0';
            for (i = first; i < first + 8U && i < SYNC_SIZE_BUCKETS; i++) {
                int n = snprintf(counts + used, sizeof(counts) - used,
                                 "%s%" PRIu64, i == first ? "" : ",",
                                 tx_stats.size_bucket[i]);

                if (n < 0 || (size_t)n >= sizeof(counts) - used)
                    break;
                used += (size_t)n;
            }
            session_diagnostic_line(
                &writer,
                "unmoor: diagnostic id=%" PRIu64 " data-size from=%u "
                "step=%u counts=%s",
                snapshot_id, first, (unsigned int)SYNC_SIZE_BUCKET_BYTES,
                counts);
        }
        session_diagnostic_line(
            &writer,
            "unmoor: diagnostic id=%" PRIu64 " data-size ceiling=%u "
            "max=%u at-ceiling=%" PRIu64 " near-ceiling=%" PRIu64,
            snapshot_id, (unsigned int)tx_stats.last_ceiling,
            (unsigned int)tx_stats.max_payload, tx_stats.at_ceiling,
            tx_stats.near_ceiling);
        session_diagnostic_line(
            &writer,
            "unmoor: diagnostic id=%" PRIu64 " data-short full=%" PRIu64
            " tail=%" PRIu64 " credit=%" PRIu64 " sink=%" PRIu64
            " bitmap=%" PRIu64 " repair-tail=%" PRIu64 " probe=%" PRIu64
            " other=%" PRIu64,
            snapshot_id,
            tx_stats.short_reason[SYNC_SHORT_NONE],
            tx_stats.short_reason[SYNC_SHORT_TAIL],
            tx_stats.short_reason[SYNC_SHORT_CREDIT],
            tx_stats.short_reason[SYNC_SHORT_SINK],
            tx_stats.short_reason[SYNC_SHORT_BITMAP],
            tx_stats.short_reason[SYNC_SHORT_REPAIR_TAIL],
            tx_stats.short_reason[SYNC_SHORT_PROBE],
            tx_stats.short_reason[SYNC_SHORT_OTHER]);
        session_diagnostic_line(
            &writer,
            "unmoor: diagnostic id=%" PRIu64 " data-gate instances=%u "
            "closes=%" PRIu32 " opens=%" PRIu32 " reason=0x%02x "
            "closed-ms=%" PRId64 " paused-ms=%" PRId64
            " frontier-age-ms=%" PRId64 " source-blocked-closes=%" PRIu32
            " source-blocked-opens=%" PRIu32,
            snapshot_id, gate.instances, gate.closes, gate.opens,
            gate.reason,
            gate.closed_ms != 0 && now_ms > gate.closed_ms
                ? now_ms - gate.closed_ms : (int64_t)0,
            gate.paused_ms, gate.frontier_age_ms,
            tx_stats.source_blocked_closes, tx_stats.source_blocked_opens);
        /* This reports the full-buffer state itself, not a guess from
         * elapsed time.  `retained-peak` against the `tx-quota` on the sync
         * line says whether the cap was met and whether anything got past it;
         * `source-blocked` says whether the source is backpressured at this
         * instant; the two millisecond figures separate intervals that have
         * closed from the one still open, so a reader never has to assume a
         * gate that is shut now was shut for the whole window. */
        session_diagnostic_line(
            &writer,
            "unmoor: diagnostic id=%" PRIu64 " data-quota retained-peak=%"
            PRIu64 " source-blocked=%d credit-blocked=%d"
            " source-blocked-ms=%" PRId64 " source-blocked-open-ms=%" PRId64,
            snapshot_id, tx_stats.retained_peak,
            (gate.source_gate & 1U) != 0U, (gate.source_gate & 2U) != 0U,
            tx_stats.source_blocked_ms, gate.source_blocked_open_ms);
    }

    session_diagnostic_line(
        &writer,
        "unmoor: diagnostic id=%" PRIu64 " wire rate-bps=%" PRId64
        " frame-charge=%" PRId64 " charged-frames=%" PRIu64
        " charged-bytes=%" PRIu64 " would-block=%" PRIu64
        " partial=%" PRIu64 " phys-attempted=%" PRIu64
        " phys-completed=%" PRIu64 " phys-failed=%" PRIu64,
        snapshot_id, s->wire_scheduler.rate_bps,
        s->wire_scheduler.frame_cost_milli / 1000,
        s->wire_scheduler.charged_copies,
        (uint64_t)(s->wire_scheduler.charged_copies *
                   (uint64_t)(s->wire_scheduler.frame_cost_milli / 1000)),
        s->wire_scheduler.would_block, s->wire_scheduler.partial_progress,
        s->wire_scheduler.physical_attempted,
        s->wire_scheduler.physical_completed,
        s->wire_scheduler.physical_failed);

    if (have_transport_stats)
        session_diagnostic_line(
            &writer,
            "unmoor: diagnostic id=%" PRIu64 " io-bytes tx-bytes=%" PRIu64
            " rx-bytes=%" PRIu64 " tx-would-block=%" PRIu32
            " tx-too-large=%" PRIu32,
            snapshot_id, transport_stats.tx_bytes, transport_stats.rx_bytes,
            transport_stats.tx_would_block, transport_stats.tx_too_large);

    if (have_paths) {
        session_diagnostic_line(
            &writer,
            "unmoor: diagnostic id=%" PRIu64 " paths count=%u "
            "validated=%u primary=%u occupied=0x%08" PRIx32
            " configured=0x%08" PRIx32 " provisional=0x%08" PRIx32
            " validated-mask=0x%08" PRIx32 " primary-mask=0x%08" PRIx32
            " hwm=%" PRIu64 " primary-changes=%" PRIu64
            " replacements=%" PRIu64,
            snapshot_id, (unsigned int)paths.path_count,
            (unsigned int)paths.validated_count,
            (unsigned int)paths.primary_index, paths.occupied_mask,
            paths.configured_mask, paths.provisional_mask,
            paths.validated_mask, paths.primary_mask,
            paths.counters.hwm_accepted, paths.counters.primary_changes,
            paths.counters.replacements);
        for (leg = 0U; leg < path_count; leg++) {
            const multipath_entry_t *entry = &paths.entry[leg];
            char remote_address[INET6_ADDRSTRLEN];
            uint8_t physical = entry->token.local_leg;
            uint16_t local_port = physical < (uint8_t)local_port_count
                ? local_ports[physical] : 0U;
            uint8_t local_family = physical < (uint8_t)local_family_count
                ? local_families[physical] : 0U;

            session_diagnostic_remote_address(
                &entry->token, remote_address, sizeof(remote_address));

            session_diagnostic_line(
                &writer,
                "unmoor: diagnostic id=%" PRIu64 " leg=%u "
                "generation=%" PRIu64 " validation=%s local-index=%u "
                "local-family=%u local-port=%u remote-family=%u "
                "remote-address=%s remote-port=%u remote-scope=%" PRIu32
                " challenge=%" PRIu64 " due-ms=%" PRId64,
                snapshot_id, leg, entry->generation,
                session_diagnostic_path_state_name(entry->state),
                (unsigned int)physical, (unsigned int)local_family,
                (unsigned int)local_port,
                (unsigned int)entry->token.family,
                remote_address, (unsigned int)entry->token.port,
                entry->token.scope, entry->challenge_id,
                entry->challenge_due_ms);
        }
    } else {
        session_diagnostic_line(
            &writer,
            "unmoor: diagnostic id=%" PRIu64
            " paths count=1 validated=%u primary=0",
            snapshot_id,
            (unsigned int)(s->state == SESSION_ESTABLISHED ||
                           s->state == SESSION_REKEYING ||
                           s->state == SESSION_CLOSING));
    }

    expected = writer.attempted + 1U;
    session_diagnostic_line(
        &writer,
        "unmoor: diagnostic id=%" PRIu64
        " complete expected=%u emitted=%u dropped=%u",
        snapshot_id, expected, writer.emitted + 1U, writer.dropped);
    session_diagnostic_writer_close(&writer);
    return writer.dropped == 0U && writer.emitted == writer.attempted
        ? 0 : -1;
}

/* -------------------------------------------------------------------------
 * delivery-class bounded delivery producer
 * ---------------------------------------------------------------------- */

static int delivery_latest_selected(const session_t *s)
{
    return s &&
        (s->selected_caps & UNMOOR_CAP_LATEST_BLOCK_D31_V1) != 0;
}

static int delivery_reliable_selected(const session_t *s)
{
    return s &&
        (s->selected_caps & UNMOOR_CAP_RELIABLE_DGRAM_D31_V1) != 0;
}

static int delivery_status_combined(const session_t *s)
{
    const uint32_t both = UNMOOR_CAP_STATUS_HEARTBEAT_V1 |
                          UNMOOR_CAP_LATEST_BLOCK_D31_V1;
    return s && (s->selected_caps & both) == both;
}

static int delivery_barrier_feedback_active(const session_t *s)
{
    return delivery_status_combined(s) && s->is_server &&
           s->state == SESSION_REKEYING &&
           s->rekey_phase == REKEY_S_WAIT_ACK;
}

static void delivery_add_candidate(uint8_t priority, unsigned int candidate,
                                   uint8_t *high_mask, uint8_t *low_mask)
{
    uint8_t bit;

    if (candidate >= 8U)
        return;
    bit = (uint8_t)(1U << candidate);
    if (priority == DELIVERY_PRIORITY_HIGH)
        *high_mask |= bit;
    else
        *low_mask |= bit;
}

/* This function is deliberately read-only. Eligibility is sampled before
 * the send-scheduler grant; only the post-grant selector below may advance a service
 * cursor or claim an exact retry owner. Candidate ids 0..3 are latest
 * objects and 4..7 are reliable flows within the requested lane. */
static void session_delivery_candidate_masks(const session_t *s,
                                             send_lane_t lane,
                                             int64_t now_ms,
                                             uint8_t *high_mask,
                                             uint8_t *low_mask)
{
    unsigned int i;
    int ordinary_service;
    int barrier_feedback;

    *high_mask = 0;
    *low_mask = 0;
    if (!s || !s->delivery_initialized)
        return;
    ordinary_service = s->services_started &&
                       s->state == SESSION_ESTABLISHED;
    barrier_feedback = delivery_barrier_feedback_active(s);
    if (!ordinary_service && !barrier_feedback)
        return;

    /* During any epoch-rekey final-ACK barrier, only the absolute receiver status
     * for system object 1 may enter send-scheduler.  This includes later epochs where
     * services_started remains true from the prior established epoch.  The
     * status is created only after a valid HEAD establishes a target;
     * application objects and reliable flows stay silent until the barrier
     * opens. */
    if (barrier_feedback) {
        const delivery_latest_receiver_object_t *rx;

        if (lane != SEND_LANE_FEEDBACK || !delivery_latest_selected(s))
            return;
        rx = &s->delivery_latest_rx.objects[0];
        /* Absolute status is state, not an event.  A locally COMPLETE send
         * clears the dirty edge, but cannot prove the peer received it.
         * Keep reasserting object 1 on its periodic deadline until the final
         * epoch-rekey ACK opens the barrier. */
        if (rx->configured && rx->target_valid &&
            now_ms >= s->delivery_latest_status_next_ms[0])
            delivery_add_candidate(rx->priority, 0,
                                   high_mask, low_mask);
        return;
    }

    if (delivery_latest_selected(s)) {
        for (i = 0; i < DELIVERY_LATEST_OBJECTS; i++) {
            const delivery_latest_sender_object_t *tx =
                &s->delivery_latest_tx.objects[i];
            const delivery_latest_receiver_object_t *rx =
                &s->delivery_latest_rx.objects[i];
            int eligible = 0;

            if (lane == SEND_LANE_FEEDBACK && rx->configured) {
                eligible = now_ms >=
                    s->delivery_latest_status_next_ms[i];
                if (eligible)
                    delivery_add_candidate(rx->priority, i,
                                           high_mask, low_mask);
            } else if (lane == SEND_LANE_INTERACTIVE && tx->configured &&
                       tx->snapshot_count != 0 &&
                       now_ms >= s->delivery_head_next_ms[i]) {
                delivery_add_candidate(tx->priority, i,
                                       high_mask, low_mask);
            } else if ((lane == SEND_LANE_NEW ||
                        lane == SEND_LANE_RECOVERY) && tx->configured) {
                delivery_latest_block_t block;
                int is_recovery = 0;
                int rc = delivery_latest_sender_next_block(
                    &s->delivery_latest_tx, tx->object_id, now_ms,
                    &block, &is_recovery);
                eligible = rc == DELIVERY_RESULT_OK &&
                    ((lane == SEND_LANE_RECOVERY) == (is_recovery != 0));
                if (eligible)
                    delivery_add_candidate(tx->priority, i,
                                           high_mask, low_mask);
                crypto_memzero(&block, sizeof(block));
            }
        }
    }

    if (delivery_reliable_selected(s)) {
        for (i = 0; i < DELIVERY_RELIABLE_FLOWS; i++) {
            const delivery_reliable_sender_flow_t *tx =
                &s->delivery_reliable_tx.flows[i];
            const delivery_reliable_receiver_flow_t *rx =
                &s->delivery_reliable_rx.flows[i];
            unsigned int candidate = i + DELIVERY_LATEST_OBJECTS;
            int eligible = 0;

            if (lane == SEND_LANE_FEEDBACK && rx->configured) {
                eligible = now_ms >=
                    s->delivery_reliable_status_next_ms[i];
            } else if ((lane == SEND_LANE_INTERACTIVE ||
                        lane == SEND_LANE_RECOVERY) && tx->configured &&
                       delivery_reliable_sender_due(
                           &s->delivery_reliable_tx, tx->flow_id,
                           now_ms)) {
                eligible = (lane == SEND_LANE_INTERACTIVE) ==
                           (tx->retry.attempts == 0);
            }
            if (eligible)
                delivery_add_candidate(
                    lane == SEND_LANE_FEEDBACK ? rx->priority : tx->priority,
                    candidate, high_mask, low_mask);
        }
    }
}

static uint8_t session_delivery_eligible_lanes(const session_t *s,
                                               int64_t now_ms)
{
    uint8_t lanes = 0;
    unsigned int lane;

    for (lane = 0; lane < SEND_LANE_COUNT; lane++) {
        uint8_t high_mask;
        uint8_t low_mask;
        session_delivery_candidate_masks(s, (send_lane_t)lane, now_ms,
                                         &high_mask, &low_mask);
        if ((high_mask | low_mask) != 0)
            lanes |= (uint8_t)SEND_LANE_BIT(lane);
    }
    return lanes;
}

static int session_delivery_select_candidate(session_t *s, send_lane_t lane,
                                             int64_t now_ms,
                                             unsigned int *candidate_out)
{
    session_delivery_service_t *state;
    uint8_t high_mask;
    uint8_t low_mask;
    uint8_t *cursor;
    uint8_t mask;
    unsigned int n;

    if (!s || lane >= SEND_LANE_COUNT || !candidate_out)
        return DELIVERY_RESULT_MALFORMED;
    session_delivery_candidate_masks(s, lane, now_ms,
                                     &high_mask, &low_mask);
    state = &s->delivery_lane_service[lane];
    if (high_mask != 0 && (state->high_streak < 3U || low_mask == 0)) {
        mask = high_mask;
        cursor = &state->high_cursor;
        if (state->high_streak < 3U)
            state->high_streak++;
    } else if (low_mask != 0) {
        mask = low_mask;
        cursor = &state->low_cursor;
        state->high_streak = 0;
    } else if (high_mask != 0) {
        mask = high_mask;
        cursor = &state->high_cursor;
        state->high_streak = 1;
    } else {
        return DELIVERY_RESULT_NOT_READY;
    }
    for (n = 0; n < 8U; n++) {
        unsigned int candidate = ((unsigned int)*cursor + n) % 8U;
        if ((mask & (uint8_t)(1U << candidate)) != 0) {
            *candidate_out = candidate;
            *cursor = (uint8_t)((candidate + 1U) % 8U);
            return DELIVERY_RESULT_OK;
        }
    }
    return DELIVERY_RESULT_NOT_READY;
}

static int wire_materialize_delivery(session_t *s, send_lane_t lane,
                                     int64_t now_ms)
{
    session_delivery_attempt_t *attempt = &s->wire_delivery;
    unsigned int candidate;
    unsigned int slot;
    size_t wire_len = 0;
    int rc;

    memset(attempt, 0, sizeof(*attempt));
    attempt->lane = (uint8_t)lane;
    if (session_delivery_select_candidate(s, lane, now_ms,
                                          &candidate) != DELIVERY_RESULT_OK)
        return -1;
    slot = candidate < DELIVERY_LATEST_OBJECTS
         ? candidate : candidate - DELIVERY_LATEST_OBJECTS;
    attempt->owner_slot = (uint8_t)slot;

    if (candidate < DELIVERY_LATEST_OBJECTS) {
        if (lane == SEND_LANE_FEEDBACK) {
            delivery_latest_status_t status;
            const delivery_latest_receiver_object_t *owner =
                &s->delivery_latest_rx.objects[slot];
            rc = delivery_latest_receiver_status(&s->delivery_latest_rx,
                                                  owner->object_id, &status);
            if (rc != DELIVERY_RESULT_OK ||
                delivery_latest_status_encode(&status,
                                               attempt->bytes) != 0) {
                crypto_memzero(&status, sizeof(status));
                return -1;
            }
            attempt->kind = SESSION_DELIVERY_ATTEMPT_LATEST_STATUS;
            attempt->type = DELIVERY_LATEST_STATUS_TYPE;
            attempt->owner_id = owner->object_id;
            attempt->generation = status.flow_revision;
            wire_len = DELIVERY_LATEST_STATUS_BYTES;
            crypto_memzero(&status, sizeof(status));
        } else if (lane == SEND_LANE_INTERACTIVE) {
            delivery_latest_head_t head;
            const delivery_latest_sender_object_t *owner =
                &s->delivery_latest_tx.objects[slot];
            rc = delivery_latest_sender_head(&s->delivery_latest_tx,
                                             owner->object_id, &head);
            if (rc != DELIVERY_RESULT_OK ||
                delivery_latest_head_encode(&head, attempt->bytes) != 0) {
                crypto_memzero(&head, sizeof(head));
                return -1;
            }
            attempt->kind = SESSION_DELIVERY_ATTEMPT_LATEST_HEAD;
            attempt->type = DELIVERY_LATEST_HEAD_TYPE;
            attempt->owner_id = owner->object_id;
            attempt->generation = head.revision;
            wire_len = DELIVERY_LATEST_HEAD_BYTES;
            crypto_memzero(&head, sizeof(head));
        } else {
            delivery_latest_block_t block;
            const delivery_latest_sender_object_t *owner =
                &s->delivery_latest_tx.objects[slot];
            int is_recovery = 0;
            rc = delivery_latest_sender_next_block(
                &s->delivery_latest_tx, owner->object_id, now_ms,
                &block, &is_recovery);
            if (rc != DELIVERY_RESULT_OK ||
                ((lane == SEND_LANE_RECOVERY) != (is_recovery != 0)) ||
                delivery_latest_block_encode(&block, attempt->bytes,
                                             sizeof(attempt->bytes),
                                             &wire_len) != 0 ||
                wire_len > s->current_mtu) {
                crypto_memzero(&block, sizeof(block));
                return -1;
            }
            attempt->kind = SESSION_DELIVERY_ATTEMPT_LATEST_BLOCK;
            attempt->type = DELIVERY_LATEST_BLOCK_TYPE;
            attempt->owner_id = owner->object_id;
            attempt->block_index = block.block_index;
            attempt->generation = block.revision;
            attempt->length = (uint16_t)wire_len;
            attempt->valid = 1;
            crypto_memzero(&block, sizeof(block));
        }
        attempt->chan_byte =
            (uint8_t)((DELIVERY_CHANNEL_ID << 4) | CHAN_FF_BIT);
    } else {
        if (lane == SEND_LANE_FEEDBACK) {
            delivery_reliable_status_t status;
            const delivery_reliable_receiver_flow_t *owner =
                &s->delivery_reliable_rx.flows[slot];
            rc = delivery_reliable_receiver_status(&s->delivery_reliable_rx,
                                                    owner->flow_id, &status);
            if (rc != DELIVERY_RESULT_OK ||
                delivery_reliable_status_encode(&status,
                                                attempt->bytes) != 0) {
                crypto_memzero(&status, sizeof(status));
                return -1;
            }
            attempt->kind = SESSION_DELIVERY_ATTEMPT_RELIABLE_STATUS;
            attempt->type = DELIVERY_CTRL_RD_STATUS_TYPE;
            attempt->owner_id = owner->flow_id;
            attempt->generation = status.flow_revision;
            wire_len = DELIVERY_RELIABLE_STATUS_BYTES;
            crypto_memzero(&status, sizeof(status));
        } else {
            delivery_reliable_data_t data;
            const delivery_reliable_sender_flow_t *owner =
                &s->delivery_reliable_tx.flows[slot];
            rc = delivery_reliable_sender_data(&s->delivery_reliable_tx,
                                               owner->flow_id, &data);
            if (rc != DELIVERY_RESULT_OK ||
                delivery_reliable_data_encode(&data, attempt->bytes,
                                              sizeof(attempt->bytes),
                                              &wire_len) != 0 ||
                wire_len > s->current_mtu) {
                crypto_memzero(&data, sizeof(data));
                return -1;
            }
            attempt->kind = SESSION_DELIVERY_ATTEMPT_RELIABLE_DATA;
            attempt->type = DELIVERY_CTRL_RD_DATA_TYPE;
            attempt->owner_id = owner->flow_id;
            attempt->generation = data.message_id;
            attempt->length = (uint16_t)wire_len;
            attempt->valid = 1;
            crypto_memzero(&data, sizeof(data));
        }
        attempt->chan_byte = CHAN_FF_BIT;
    }

    if (wire_len > s->current_mtu || wire_len > UINT16_MAX) {
        fprintf(stderr,
                "session: FATAL: negotiated delivery-class record exceeds plaintext MTU\n");
        s->run_failed = 1;
        s->wire_protocol_failure = 1;
        return -1;
    }
    attempt->length = (uint16_t)wire_len;
    attempt->valid = 1;
    return 0;
}

static int wire_encode_delivery(session_t *s, send_lane_t lane,
                                int64_t now_ms)
{
    session_delivery_attempt_t *attempt = &s->wire_delivery;
    session_tx_intent_t intent;
    int rc;

    if (!attempt->valid || attempt->lane != (uint8_t)lane ||
        attempt->length == 0U || attempt->length > s->current_mtu)
        return -1;
    memset(&intent, 0, sizeof(intent));
    intent.epoch_source = SESSION_TX_EPOCH_CURRENT;
    intent.sequence_class = SESSION_TX_SEQ_NORMAL;
    intent.mode_mask = SESSION_TX_MODE_ESTABLISHED;
    intent.chan_byte = attempt->chan_byte;
    intent.type = attempt->type;
    intent.length = attempt->length;
    memcpy(intent.bytes, attempt->bytes, attempt->length);
    rc = wire_encode_authenticated_intent(s, &intent);
    crypto_memzero(&intent, sizeof(intent));
    if (rc != 0)
        return rc;

    /* Claim the exact retry owner only after every fallible plaintext, MTU,
     * AEAD, frame, and sequence step succeeded.  A pretransport encode
     * failure therefore cannot fabricate a terminal transport attempt or
     * start a retry clock. */
    if (attempt->kind == SESSION_DELIVERY_ATTEMPT_LATEST_BLOCK)
        rc = delivery_latest_sender_block_selected(
            &s->delivery_latest_tx, attempt->owner_id,
            attempt->block_index, now_ms);
    else if (attempt->kind == SESSION_DELIVERY_ATTEMPT_RELIABLE_DATA)
        rc = delivery_reliable_sender_selected(
            &s->delivery_reliable_tx, attempt->owner_id, now_ms);
    else
        rc = DELIVERY_RESULT_OK;
    if (rc != DELIVERY_RESULT_OK) {
        fprintf(stderr,
                "session: FATAL: delivery-class selected owner changed after encode "
                "(%d)\n", rc);
        s->run_failed = 1;
        s->wire_protocol_failure = 1;
        return -2;
    }
    return 0;
}

static int wire_materialize_bulk(session_t *s, send_lane_t lane,
                                 int64_t now_ms)
{
    bulk_engine_tx_view_t view;
    uint8_t *scratch;
    size_t capacity = 0U;
    int rc;

    if (!s || !s->bulk_activated || !s->bulk ||
        lane < SEND_LANE_FEEDBACK || lane >= SEND_LANE_COUNT)
        return -1;
    scratch = bulk_engine_receive_buffer(s->bulk, &capacity);
    if (!scratch || capacity == 0U)
        return -1;
    memset(&view, 0, sizeof(view));
    rc = bulk_engine_materialize(s->bulk, lane, now_ms, scratch, capacity,
                                 &view);
    if (rc != 0 || view.lane != lane || view.plaintext != scratch ||
        view.plaintext_length == 0U ||
        view.plaintext_length + BULK_FRAME_OVERHEAD_BYTES >
            bulk_engine_wire_budget(s->bulk)) {
        crypto_memzero(scratch, capacity);
        return -1;
    }
    s->bulk_tx_type = view.type;
    s->bulk_tx_lane = (uint8_t)view.lane;
    s->bulk_tx_plaintext_len = view.plaintext_length;
    return 0;
}

static int wire_encode_bulk(session_t *s, send_lane_t lane,
                            int64_t now_ms)
{
    uint8_t *plaintext;
    uint8_t *encoded;
    size_t plaintext_capacity = 0U;
    size_t encoded_capacity = 0U;
    size_t ct_len = 0U;
    uint8_t ad[10];
    uint8_t chan_byte = (uint8_t)((BULK_CHANNEL_ID << 4) | CHAN_FF_BIT);
    uint32_t seq;
    uint64_t limit;
    int n;

    (void)now_ms;
    if (!s || !s->bulk_activated || !s->bulk ||
        s->bulk_tx_lane != (uint8_t)lane ||
        s->bulk_tx_plaintext_len == 0U)
        return -1;
    plaintext = bulk_engine_receive_buffer(s->bulk, &plaintext_capacity);
    encoded = bulk_engine_encoded_buffer(s->bulk, &encoded_capacity);
    if (!plaintext || !encoded ||
        s->bulk_tx_plaintext_len > plaintext_capacity ||
        s->bulk_tx_plaintext_len + BULK_FRAME_OVERHEAD_BYTES >
            encoded_capacity ||
        s->bulk_tx_plaintext_len + BULK_FRAME_OVERHEAD_BYTES >
            bulk_engine_wire_budget(s->bulk))
        return -1;
    limit = wire_normal_sequence_limit(s);
    if ((uint64_t)s->tx_seq >= limit)
        return wire_sequence_failure(
            s, "bulk-transfer record reached the epoch sequence reserve");
    if (s->tx_seq == UINT32_MAX)
        return wire_sequence_failure(s, "bulk-transfer sequence space exhausted");

    seq = s->tx_seq;
    build_frame_ad(s->pair_id, seq, chan_byte, s->bulk_tx_type, ad);
    if (crypto_encrypt(s->session_key, seq,
                       s->is_server ? 0x01 : 0x00, ad,
                       plaintext, s->bulk_tx_plaintext_len,
                       encoded + FRAME_HEADER_LEN, &ct_len) != 0) {
        crypto_memzero(plaintext, plaintext_capacity);
        return -1;
    }
    crypto_memzero(plaintext, plaintext_capacity);
    n = unmoor_frame_encode(s->pair_id, seq, chan_byte, s->bulk_tx_type,
                            encoded + FRAME_HEADER_LEN, ct_len,
                            encoded, encoded_capacity);
    if (n < 0 || (size_t)n > bulk_engine_wire_budget(s->bulk)) {
        crypto_memzero(encoded, encoded_capacity);
        return -1;
    }
    s->tx_seq++;
    s->wire_frame_bulk = 1U;
    s->wire_frame_len = (size_t)n;
    return 0;
}

static int delivery_attempt_still_current(session_t *s,
                                          const session_delivery_attempt_t *a)
{
    uint8_t wire[DELIVERY_LATEST_BLOCK_WIRE_MAX];
    int same = 0;

    memset(wire, 0, sizeof(wire));
    if (a->kind == SESSION_DELIVERY_ATTEMPT_LATEST_HEAD) {
        delivery_latest_head_t head;
        if (delivery_latest_sender_head(&s->delivery_latest_tx, a->owner_id,
                                        &head) == DELIVERY_RESULT_OK &&
            delivery_latest_head_encode(&head, wire) == 0 &&
            a->length == DELIVERY_LATEST_HEAD_BYTES)
            same = memcmp(wire, a->bytes, a->length) == 0;
        crypto_memzero(&head, sizeof(head));
    } else if (a->kind == SESSION_DELIVERY_ATTEMPT_LATEST_STATUS) {
        delivery_latest_status_t status;
        if (delivery_latest_receiver_status(&s->delivery_latest_rx,
                                            a->owner_id, &status) ==
                DELIVERY_RESULT_OK &&
            delivery_latest_status_encode(&status, wire) == 0 &&
            a->length == DELIVERY_LATEST_STATUS_BYTES)
            same = memcmp(wire, a->bytes, a->length) == 0;
        crypto_memzero(&status, sizeof(status));
    } else if (a->kind == SESSION_DELIVERY_ATTEMPT_RELIABLE_STATUS) {
        delivery_reliable_status_t status;
        if (delivery_reliable_receiver_status(&s->delivery_reliable_rx,
                                              a->owner_id, &status) ==
                DELIVERY_RESULT_OK &&
            delivery_reliable_status_encode(&status, wire) == 0 &&
            a->length == DELIVERY_RELIABLE_STATUS_BYTES)
            same = memcmp(wire, a->bytes, a->length) == 0;
        crypto_memzero(&status, sizeof(status));
    }
    crypto_memzero(wire, sizeof(wire));
    return same;
}

static void session_delivery_attempt_result(session_t *s, int completed,
                                            int64_t now_ms)
{
    session_delivery_attempt_t saved;
    delivery_attempt_result_t result = completed
        ? DELIVERY_ATTEMPT_COMPLETE : DELIVERY_ATTEMPT_FAILED;
    int rc = DELIVERY_RESULT_OK;
    int current;

    if (!s || !s->wire_delivery.valid) {
        if (s) {
            fprintf(stderr,
                    "session: FATAL: missing delivery-class completion identity\n");
            s->run_failed = 1;
            s->wire_protocol_failure = 1;
        }
        return;
    }
    saved = s->wire_delivery;
    current = delivery_attempt_still_current(s, &saved);
    switch ((session_delivery_attempt_kind_t)saved.kind) {
    case SESSION_DELIVERY_ATTEMPT_LATEST_HEAD:
        if (current && saved.owner_slot < DELIVERY_LATEST_OBJECTS)
            s->delivery_head_next_ms[saved.owner_slot] =
                now_ms + DELIVERY_STATE_REPEAT_MS;
        break;
    case SESSION_DELIVERY_ATTEMPT_LATEST_BLOCK:
        rc = delivery_latest_sender_block_result(
            &s->delivery_latest_tx, saved.owner_id, saved.block_index,
            result, now_ms);
        if (rc == DELIVERY_RESULT_OK &&
            saved.owner_id == DELIVERY_LATEST_SYSTEM_OBJECT_ID &&
            s->d29_latest_periodic_pending &&
            saved.generation == s->d29_latest_periodic_revision) {
            sync_status_heartbeat_sent(&s->sync_status, now_ms);
            s->d29_latest_periodic_pending = 0;
            s->d29_latest_periodic_revision = 0;
        }
        break;
    case SESSION_DELIVERY_ATTEMPT_LATEST_STATUS:
        if (saved.owner_slot < DELIVERY_LATEST_OBJECTS) {
            uint8_t bit = (uint8_t)(1U << saved.owner_slot);
            s->delivery_latest_status_next_ms[saved.owner_slot] =
                current ? now_ms + DELIVERY_STATE_REPEAT_MS : now_ms;
            if (completed && current)
                s->delivery_latest_status_dirty &= (uint8_t)~bit;
        }
        break;
    case SESSION_DELIVERY_ATTEMPT_RELIABLE_DATA:
        rc = delivery_reliable_sender_result(
            &s->delivery_reliable_tx, saved.owner_id, saved.generation,
            result, now_ms);
        break;
    case SESSION_DELIVERY_ATTEMPT_RELIABLE_STATUS:
        if (saved.owner_slot < DELIVERY_RELIABLE_FLOWS) {
            uint8_t bit = (uint8_t)(1U << saved.owner_slot);
            s->delivery_reliable_status_next_ms[saved.owner_slot] =
                current ? now_ms + DELIVERY_STATE_REPEAT_MS : now_ms;
            if (completed && current)
                s->delivery_reliable_status_dirty &= (uint8_t)~bit;
        }
        break;
    case SESSION_DELIVERY_ATTEMPT_NONE:
        rc = DELIVERY_RESULT_MALFORMED;
        break;
    }
    if (rc < 0) {
        fprintf(stderr,
                "session: FATAL: delivery-class completion owner mismatch (%d)\n", rc);
        s->run_failed = 1;
        s->wire_protocol_failure = 1;
    }
    crypto_memzero(&s->wire_delivery, sizeof(s->wire_delivery));
    crypto_memzero(&saved, sizeof(saved));
    maybe_complete_deferred_epoch_adoption(s, now_ms);
}

static void session_delivery_reset(session_t *s)
{
    unsigned int slot;

    if (!s)
        return;
    crypto_memzero(s->delivery_context, sizeof(s->delivery_context));
    crypto_memzero(&s->delivery_latest_tx, sizeof(s->delivery_latest_tx));
    crypto_memzero(&s->delivery_latest_rx, sizeof(s->delivery_latest_rx));
    crypto_memzero(&s->delivery_reliable_tx,
                   sizeof(s->delivery_reliable_tx));
    crypto_memzero(&s->delivery_reliable_rx,
                   sizeof(s->delivery_reliable_rx));
    crypto_memzero(s->delivery_lane_service,
                   sizeof(s->delivery_lane_service));
    memset(s->delivery_head_next_ms, 0,
           sizeof(s->delivery_head_next_ms));
    memset(s->delivery_latest_status_next_ms, 0,
           sizeof(s->delivery_latest_status_next_ms));
    memset(s->delivery_reliable_status_next_ms, 0,
           sizeof(s->delivery_reliable_status_next_ms));
    s->delivery_latest_status_dirty = 0;
    s->delivery_reliable_status_dirty = 0;
    s->delivery_callback_fatal = 0;
    s->d29_latest_periodic_pending = 0;
    s->d29_latest_periodic_revision = 0;
    for (slot = 0; slot < DELIVERY_RELIABLE_FLOWS; slot++) {
        session_delivery_reliable_config_t *cfg =
            &s->delivery_reliable_tx_config[slot];
        cfg->result_notified = 0;
        cfg->notified_message_id = 0;
        crypto_memzero(cfg->notified_hash, sizeof(cfg->notified_hash));
        cfg->notified_result = DELIVERY_RESULT_OK;
    }
    crypto_memzero(&s->wire_delivery, sizeof(s->wire_delivery));
    s->delivery_initialized = 0;
}

static int session_delivery_initialize_context(session_t *s)
{
    uint8_t outgoing;
    uint8_t incoming;

    if (!s)
        return -1;
    session_delivery_reset(s);
    if (!delivery_latest_selected(s) && !delivery_reliable_selected(s))
        return 0;
    if (!s->negotiation_neg1) {
        fprintf(stderr,
                "session: FATAL: delivery-class selected outside authenticated NEG1\n");
        return -1;
    }
    delivery_context_derive(s->transcript_hello, s->transcript_ack,
                            s->selected_caps, s->delivery_context);
    outgoing = (uint8_t)(s->is_server ? 1U : 0U);
    incoming = (uint8_t)(s->is_server ? 0U : 1U);
    delivery_latest_sender_init(&s->delivery_latest_tx,
                                s->delivery_context, outgoing);
    delivery_latest_receiver_init(&s->delivery_latest_rx,
                                  s->delivery_context, incoming);
    delivery_reliable_sender_init(&s->delivery_reliable_tx,
                                  s->delivery_context, outgoing);
    delivery_reliable_receiver_init(&s->delivery_reliable_rx,
                                    s->delivery_context, incoming);
    s->delivery_initialized = 1;
    return 0;
}

static int session_delivery_prepare_context(session_t *s)
{
    if (!s)
        return -1;
    if (s->delivery_initialized ||
        (!delivery_latest_selected(s) && !delivery_reliable_selected(s)))
        return 0;
    if (session_delivery_initialize_context(s) != 0)
        return -1;
    return session_delivery_bind(s);
}

static int d29_latest_install(void *arg, uint16_t object_id,
                              uint64_t revision, const uint8_t *bytes,
                              size_t length)
{
    session_t *s = arg;
    sync_status_record_t record;
    uint64_t tx_tip;
    uint64_t rx_delivered;
    uint64_t rx_highest;
    int sink_blocked;
    uint32_t expected_epoch;
    int64_t now_ms;

    (void)revision;
    if (!s || object_id != DELIVERY_LATEST_SYSTEM_OBJECT_ID ||
        !delivery_status_combined(s) ||
        sync_status_record_decode(bytes, length, &record) != 0) {
        if (s)
            s->delivery_callback_fatal = 1;
        return -1;
    }
    /* Installation is post-barrier only.  Enforce that boundary before
     * touching even the telemetry observer so a future caller cannot turn a
     * pre-service BLOCK into externally visible state. */
    if (s->state != SESSION_ESTABLISHED) {
        s->delivery_callback_fatal = 1;
        return -1;
    }
    if (session_status_counters(s, &tx_tip, &rx_delivered, &rx_highest,
                                &sink_blocked) != 0) {
        s->delivery_callback_fatal = 1;
        return -1;
    }
    (void)sink_blocked;
    expected_epoch = s->epoch_rekey_enabled ? s->epoch : 0;
    if (record.epoch != expected_epoch || record.rx_delivered > tx_tip) {
        s->delivery_callback_fatal = 1;
        return -1;
    }
    now_ms = mono_ms();
    if (!s->sync_status.active ||
        sync_status_observe_peer(&s->sync_status, &record, now_ms,
                                 tx_tip, rx_delivered, rx_highest) != 0) {
        s->delivery_callback_fatal = 1;
        return -1;
    }

    /* Epoch authority is decided before channel dispatch, after a pure
     * canonical/configuration prevalidation pass.  Installation is only a
     * sync-status telemetry action and cannot itself advance epoch-rekey state. */
    session_status_present(s, now_ms);
    if ((record.flags & SYNC_STATUS_FLAG_POLL) != 0)
        (void)send_status_record(s, 0, SESSION_TX_DONE_NONE,
                                 WIRE_COALESCE_STATUS_REPLY, now_ms);
    return 0;
}

static uint8_t delivery_reason_bit(delivery_reason_t reason)
{
    if (reason < DELIVERY_REASON_PAUSED ||
        reason > DELIVERY_REASON_NOT_INTERESTED)
        return 0;
    return (uint8_t)(1U << ((unsigned int)reason - 1U));
}

static int session_delivery_apply_reason_mask_latest(
    session_t *s, uint16_t object_id, uint8_t mask)
{
    unsigned int reason;

    for (reason = DELIVERY_REASON_PAUSED;
         reason <= DELIVERY_REASON_NOT_INTERESTED; reason++) {
        uint8_t bit = delivery_reason_bit((delivery_reason_t)reason);
        if ((mask & bit) != 0 &&
            delivery_latest_receiver_set_reason(
                &s->delivery_latest_rx, object_id,
                (delivery_reason_t)reason, 1) != DELIVERY_RESULT_OK)
            return -1;
    }
    return 0;
}

static int session_delivery_apply_reason_mask_reliable(
    session_t *s, uint16_t flow_id, uint8_t mask)
{
    unsigned int reason;

    for (reason = DELIVERY_REASON_PAUSED;
         reason <= DELIVERY_REASON_NOT_INTERESTED; reason++) {
        uint8_t bit = delivery_reason_bit((delivery_reason_t)reason);
        if ((mask & bit) != 0 &&
            delivery_reliable_receiver_set_reason(
                &s->delivery_reliable_rx, flow_id,
                (delivery_reason_t)reason, 1) != DELIVERY_RESULT_OK)
            return -1;
    }
    return 0;
}

/* Bind the immutable, locally configured delivery-class namespace as soon as the
 * authenticated transcript context exists.  Binding is intentionally
 * separate from starting service: a mandatory epoch-rekey bootstrap barrier may
 * need object-1 HEAD/STATUS/BLOCK to heal a lost final ACK, while all
 * application delivery remains invisible until service activation. */
static int session_delivery_bind(session_t *s)
{
    unsigned int slot;
    int rc;

    if (!s || (!delivery_latest_selected(s) &&
               !delivery_reliable_selected(s)))
        return 0;
    if (!s->delivery_initialized)
        return -1;
    if (delivery_status_combined(s) &&
        !s->delivery_latest_tx.objects[0].configured) {
        rc = delivery_latest_sender_reserve_object(
            &s->delivery_latest_tx, DELIVERY_LATEST_SYSTEM_OBJECT_ID,
            SYNC_STATUS_WIRE_LEN);
        if (rc != DELIVERY_RESULT_OK)
            return -1;
        rc = delivery_latest_receiver_reserve_object(
            &s->delivery_latest_rx, DELIVERY_LATEST_SYSTEM_OBJECT_ID,
            SYNC_STATUS_WIRE_LEN);
        if (rc != DELIVERY_RESULT_OK)
            return -1;
        rc = delivery_latest_sender_configure(
            &s->delivery_latest_tx, 0, DELIVERY_LATEST_SYSTEM_OBJECT_ID,
            DELIVERY_PRIORITY_HIGH);
        if (rc != DELIVERY_RESULT_OK)
            return -1;
        rc = delivery_latest_receiver_configure(
            &s->delivery_latest_rx, 0, DELIVERY_LATEST_SYSTEM_OBJECT_ID,
            DELIVERY_PRIORITY_HIGH, d29_latest_install, s);
        if (rc != DELIVERY_RESULT_OK)
            return -1;
    }
    if (delivery_latest_selected(s)) {
        for (slot = 0; slot < DELIVERY_LATEST_OBJECTS; slot++) {
            const session_delivery_latest_config_t *cfg =
                &s->delivery_latest_tx_config[slot];
            if (!cfg->configured)
                continue;
            rc = delivery_latest_sender_configure(
                &s->delivery_latest_tx, slot, cfg->object_id,
                (delivery_priority_t)cfg->priority);
            if (rc != DELIVERY_RESULT_OK)
                return -1;
        }
        for (slot = 0; slot < DELIVERY_LATEST_OBJECTS; slot++) {
            const session_delivery_latest_config_t *cfg =
                &s->delivery_latest_rx_config[slot];
            if (!cfg->configured)
                continue;
            rc = delivery_latest_receiver_configure(
                &s->delivery_latest_rx, slot, cfg->object_id,
                (delivery_priority_t)cfg->priority,
                cfg->install, cfg->install_arg);
            if (rc != DELIVERY_RESULT_OK ||
                session_delivery_apply_reason_mask_latest(
                    s, cfg->object_id, cfg->reason_mask) != 0)
                return -1;
        }
    }
    if (delivery_reliable_selected(s)) {
        for (slot = 0; slot < DELIVERY_RELIABLE_FLOWS; slot++) {
            const session_delivery_reliable_config_t *cfg =
                &s->delivery_reliable_tx_config[slot];
            if (!cfg->configured)
                continue;
            rc = delivery_reliable_sender_configure(
                &s->delivery_reliable_tx, slot, cfg->flow_id,
                (delivery_priority_t)cfg->priority);
            if (rc != DELIVERY_RESULT_OK)
                return -1;
        }
        for (slot = 0; slot < DELIVERY_RELIABLE_FLOWS; slot++) {
            const session_delivery_reliable_config_t *cfg =
                &s->delivery_reliable_rx_config[slot];
            if (!cfg->configured)
                continue;
            rc = delivery_reliable_receiver_configure(
                &s->delivery_reliable_rx, slot, cfg->flow_id,
                (delivery_priority_t)cfg->priority,
                cfg->deliver, cfg->deliver_arg);
            if (rc != DELIVERY_RESULT_OK ||
                session_delivery_apply_reason_mask_reliable(
                    s, cfg->flow_id, cfg->reason_mask) != 0)
                return -1;
        }
    }
    return 0;
}

/* Start ordinary delivery only after the epoch barrier.  Absolute status is
 * made immediately eligible for every bound receiver; nothing from the
 * pre-barrier healing exchange is installed or exposed to an application. */
static void session_delivery_start(session_t *s, int64_t now_ms)
{
    unsigned int slot;

    if (!s || !s->delivery_initialized)
        return;
    if (delivery_latest_selected(s)) {
        for (slot = 0; slot < DELIVERY_LATEST_OBJECTS; slot++) {
            if (s->delivery_latest_tx.objects[slot].configured)
                s->delivery_head_next_ms[slot] = now_ms;
            if (s->delivery_latest_rx.objects[slot].configured) {
                s->delivery_latest_status_dirty |=
                    (uint8_t)(1U << slot);
                s->delivery_latest_status_next_ms[slot] = now_ms;
            }
        }
    }
    if (delivery_reliable_selected(s)) {
        for (slot = 0; slot < DELIVERY_RELIABLE_FLOWS; slot++) {
            if (!s->delivery_reliable_rx.flows[slot].configured)
                continue;
            s->delivery_reliable_status_dirty |=
                (uint8_t)(1U << slot);
            s->delivery_reliable_status_next_ms[slot] = now_ms;
        }
    }
}

static int session_delivery_fail(session_t *s, const char *what, int rc)
{
    fprintf(stderr, "session: FATAL: delivery-class %s (%d) — closing\n", what, rc);
    session_protocol_error_close(s, ERR_CAPS);
    return -1;
}

static void session_delivery_absorb_latest_changes(session_t *s,
                                                   int64_t now_ms)
{
    uint8_t changed;
    unsigned int slot;

    if (!s)
        return;
    changed = delivery_latest_receiver_take_status_changed(
        &s->delivery_latest_rx);
    s->delivery_latest_status_dirty |= changed;
    for (slot = 0; slot < DELIVERY_LATEST_OBJECTS; slot++)
        if ((changed & (uint8_t)(UINT8_C(1) << slot)) != 0)
            s->delivery_latest_status_next_ms[slot] = now_ms;
}

int session_delivery_configure_latest(
    session_t *s, unsigned int slot, session_delivery_direction_t directions,
    uint16_t object_id,
    delivery_priority_t priority, delivery_latest_install_fn install,
    void *install_arg)
{
    session_delivery_latest_config_t *tx_cfg;
    session_delivery_latest_config_t *rx_cfg;
    unsigned int i;

    if (!s || s->state != SESSION_IDLE || s->configuration_frozen ||
        s->delivery_initialized ||
        slot >= DELIVERY_LATEST_OBJECTS ||
        directions < SESSION_DELIVERY_SEND ||
        directions > SESSION_DELIVERY_BOTH ||
        object_id == 0 || object_id == DELIVERY_LATEST_SYSTEM_OBJECT_ID ||
        (((directions & SESSION_DELIVERY_RECEIVE) != 0) !=
         (install != NULL)) ||
        (install == NULL && install_arg != NULL) ||
        (slot == 0 && latest_status_slot_reserved(s->supported_caps)) ||
        (priority != DELIVERY_PRIORITY_LOW &&
         priority != DELIVERY_PRIORITY_HIGH))
        return DELIVERY_RESULT_MALFORMED;
    tx_cfg = &s->delivery_latest_tx_config[slot];
    rx_cfg = &s->delivery_latest_rx_config[slot];
    if (((directions & SESSION_DELIVERY_SEND) != 0 &&
         tx_cfg->configured) ||
        ((directions & SESSION_DELIVERY_RECEIVE) != 0 &&
         rx_cfg->configured))
        return DELIVERY_RESULT_BUSY;
    for (i = 0; i < DELIVERY_LATEST_OBJECTS; i++) {
        if ((directions & SESSION_DELIVERY_SEND) != 0 &&
            s->delivery_latest_tx_config[i].configured &&
            s->delivery_latest_tx_config[i].object_id == object_id)
            return DELIVERY_RESULT_MALFORMED;
        if ((directions & SESSION_DELIVERY_RECEIVE) != 0 &&
            s->delivery_latest_rx_config[i].configured &&
            s->delivery_latest_rx_config[i].object_id == object_id)
            return DELIVERY_RESULT_MALFORMED;
    }
    if ((directions & SESSION_DELIVERY_SEND) != 0) {
        memset(tx_cfg, 0, sizeof(*tx_cfg));
        tx_cfg->configured = 1;
        tx_cfg->priority = (uint8_t)priority;
        tx_cfg->object_id = object_id;
    }
    if ((directions & SESSION_DELIVERY_RECEIVE) != 0) {
        memset(rx_cfg, 0, sizeof(*rx_cfg));
        rx_cfg->configured = 1;
        rx_cfg->priority = (uint8_t)priority;
        rx_cfg->object_id = object_id;
        rx_cfg->install = install;
        rx_cfg->install_arg = install_arg;
    }
    return DELIVERY_RESULT_OK;
}

int session_delivery_publish_latest(session_t *s, uint16_t object_id,
                                    const uint8_t *bytes, size_t length)
{
    unsigned int i;
    int rc;

    if (!s || s->state != SESSION_ESTABLISHED ||
        !s->delivery_initialized || !delivery_latest_selected(s) ||
        object_id == DELIVERY_LATEST_SYSTEM_OBJECT_ID)
        return DELIVERY_RESULT_UNCONFIGURED;
    rc = delivery_latest_sender_publish(&s->delivery_latest_tx, object_id,
                                        bytes, length);
    if (rc != DELIVERY_RESULT_OK)
        return rc;
    for (i = 0; i < DELIVERY_LATEST_OBJECTS; i++)
        if (s->delivery_latest_tx.objects[i].configured &&
            s->delivery_latest_tx.objects[i].object_id == object_id) {
            s->delivery_head_next_ms[i] = mono_ms();
            break;
        }
    return DELIVERY_RESULT_OK;
}

int session_delivery_set_latest_reason(session_t *s, uint16_t object_id,
                                       delivery_reason_t reason, int enabled)
{
    session_delivery_latest_config_t *cfg = NULL;
    uint8_t bit = delivery_reason_bit(reason);
    unsigned int i;
    int rc;

    if (!s || bit == 0 || object_id == DELIVERY_LATEST_SYSTEM_OBJECT_ID)
        return DELIVERY_RESULT_MALFORMED;
    for (i = 0; i < DELIVERY_LATEST_OBJECTS; i++)
        if (s->delivery_latest_rx_config[i].configured &&
            s->delivery_latest_rx_config[i].object_id == object_id) {
            cfg = &s->delivery_latest_rx_config[i];
            break;
        }
    if (!cfg)
        return DELIVERY_RESULT_UNCONFIGURED;
    if (s->state == SESSION_IDLE && !s->configuration_frozen &&
        !s->delivery_initialized) {
        if (enabled)
            cfg->reason_mask |= bit;
        else
            cfg->reason_mask &= (uint8_t)~bit;
        return DELIVERY_RESULT_OK;
    }
    if (!s->delivery_initialized || !delivery_latest_selected(s) ||
        (s->state != SESSION_ESTABLISHED &&
         s->state != SESSION_REKEYING))
        return DELIVERY_RESULT_UNCONFIGURED;
    rc = delivery_latest_receiver_set_reason(&s->delivery_latest_rx,
                                             object_id, reason, enabled);
    session_delivery_absorb_latest_changes(s, mono_ms());
    if (rc != DELIVERY_RESULT_OK)
        return rc;
    if (enabled)
        cfg->reason_mask |= bit;
    else
        cfg->reason_mask &= (uint8_t)~bit;
    return DELIVERY_RESULT_OK;
}

int session_delivery_configure_reliable(
    session_t *s, unsigned int slot, session_delivery_direction_t directions,
    uint16_t flow_id,
    delivery_priority_t priority, delivery_reliable_deliver_fn deliver,
    void *deliver_arg, session_delivery_reliable_result_fn result,
    void *result_arg)
{
    session_delivery_reliable_config_t *tx_cfg;
    session_delivery_reliable_config_t *rx_cfg;
    unsigned int i;

    if (!s || s->state != SESSION_IDLE || s->configuration_frozen ||
        s->delivery_initialized || slot >= DELIVERY_RELIABLE_FLOWS ||
        directions < SESSION_DELIVERY_SEND ||
        directions > SESSION_DELIVERY_BOTH || flow_id == 0 ||
        (((directions & SESSION_DELIVERY_RECEIVE) != 0) !=
         (deliver != NULL)) ||
        (deliver == NULL && deliver_arg != NULL) ||
        (((directions & SESSION_DELIVERY_SEND) != 0) !=
         (result != NULL)) ||
        (result == NULL && result_arg != NULL) ||
        (priority != DELIVERY_PRIORITY_LOW &&
         priority != DELIVERY_PRIORITY_HIGH))
        return DELIVERY_RESULT_MALFORMED;
    tx_cfg = &s->delivery_reliable_tx_config[slot];
    rx_cfg = &s->delivery_reliable_rx_config[slot];
    if (((directions & SESSION_DELIVERY_SEND) != 0 &&
         tx_cfg->configured) ||
        ((directions & SESSION_DELIVERY_RECEIVE) != 0 &&
         rx_cfg->configured))
        return DELIVERY_RESULT_BUSY;
    for (i = 0; i < DELIVERY_RELIABLE_FLOWS; i++) {
        if ((directions & SESSION_DELIVERY_SEND) != 0 &&
            s->delivery_reliable_tx_config[i].configured &&
            s->delivery_reliable_tx_config[i].flow_id == flow_id)
            return DELIVERY_RESULT_MALFORMED;
        if ((directions & SESSION_DELIVERY_RECEIVE) != 0 &&
            s->delivery_reliable_rx_config[i].configured &&
            s->delivery_reliable_rx_config[i].flow_id == flow_id)
            return DELIVERY_RESULT_MALFORMED;
    }
    if ((directions & SESSION_DELIVERY_SEND) != 0) {
        memset(tx_cfg, 0, sizeof(*tx_cfg));
        tx_cfg->configured = 1;
        tx_cfg->priority = (uint8_t)priority;
        tx_cfg->flow_id = flow_id;
        tx_cfg->result = result;
        tx_cfg->result_arg = result_arg;
    }
    if ((directions & SESSION_DELIVERY_RECEIVE) != 0) {
        memset(rx_cfg, 0, sizeof(*rx_cfg));
        rx_cfg->configured = 1;
        rx_cfg->priority = (uint8_t)priority;
        rx_cfg->flow_id = flow_id;
        rx_cfg->deliver = deliver;
        rx_cfg->deliver_arg = deliver_arg;
    }
    return DELIVERY_RESULT_OK;
}

int session_delivery_send_reliable(session_t *s, uint16_t flow_id,
                                   const uint8_t *bytes, size_t length,
                                   uint64_t *message_id_out)
{
    if (!s || s->state != SESSION_ESTABLISHED ||
        !s->delivery_initialized || !delivery_reliable_selected(s))
        return DELIVERY_RESULT_UNCONFIGURED;
    return delivery_reliable_sender_admit(&s->delivery_reliable_tx, flow_id,
                                          bytes, length, mono_ms(),
                                          message_id_out);
}

int session_delivery_set_reliable_reason(session_t *s, uint16_t flow_id,
                                         delivery_reason_t reason,
                                         int enabled)
{
    session_delivery_reliable_config_t *cfg = NULL;
    uint8_t bit = delivery_reason_bit(reason);
    unsigned int i;
    int rc;

    if (!s || bit == 0)
        return DELIVERY_RESULT_MALFORMED;
    for (i = 0; i < DELIVERY_RELIABLE_FLOWS; i++)
        if (s->delivery_reliable_rx_config[i].configured &&
            s->delivery_reliable_rx_config[i].flow_id == flow_id) {
            cfg = &s->delivery_reliable_rx_config[i];
            break;
        }
    if (!cfg)
        return DELIVERY_RESULT_UNCONFIGURED;
    if (s->state == SESSION_IDLE && !s->configuration_frozen &&
        !s->delivery_initialized) {
        if (enabled)
            cfg->reason_mask |= bit;
        else
            cfg->reason_mask &= (uint8_t)~bit;
        return DELIVERY_RESULT_OK;
    }
    if (!s->delivery_initialized || !delivery_reliable_selected(s) ||
        (s->state != SESSION_ESTABLISHED &&
         s->state != SESSION_REKEYING))
        return DELIVERY_RESULT_UNCONFIGURED;
    rc = delivery_reliable_receiver_set_reason(&s->delivery_reliable_rx,
                                               flow_id, reason, enabled);
    if (rc != DELIVERY_RESULT_OK)
        return rc;
    if (enabled)
        cfg->reason_mask |= bit;
    else
        cfg->reason_mask &= (uint8_t)~bit;
    for (i = 0; i < DELIVERY_RELIABLE_FLOWS; i++)
        if (s->delivery_reliable_rx.flows[i].configured &&
            s->delivery_reliable_rx.flows[i].flow_id == flow_id) {
            s->delivery_reliable_status_dirty |= (uint8_t)(1U << i);
            s->delivery_reliable_status_next_ms[i] = mono_ms();
            break;
        }
    return DELIVERY_RESULT_OK;
}

static int session_delivery_latest_phase_allowed(const session_t *s,
                                                 uint8_t type,
                                                 uint16_t object_id)
{
    if (object_id == DELIVERY_LATEST_SYSTEM_OBJECT_ID &&
        !delivery_status_combined(s))
        return 0;
    if (s->state == SESSION_ESTABLISHED)
        return 1;
    /* The server may authenticate and classify any canonical configured
     * latest record while waiting for the final epoch-rekey ACK.  Dispatch still
     * withholds every application record; only object-1 HEAD/BLOCK is given
     * the narrower bootstrap-healing treatment at the outer barrier. */
    (void)type;
    return s->state == SESSION_KEY_DERIVING ||
           s->state == SESSION_REKEYING;
}

/* Pure delivery-class channel prevalidation.  This pass deliberately performs no
 * observer call, reservation, install callback, status mutation, path
 * adoption, or epoch transition.  The adjacent-epoch lost-ACK proof uses it
 * before crossing the epoch-rekey barrier, so malformed or unconfigured object
 * traffic cannot gain authority merely by being AEAD-valid. */
int session_delivery_prevalidate_latest(
    const session_t *s, uint8_t type, const uint8_t *plaintext,
    size_t plaintext_len, uint16_t *object_id_out)
{
    uint16_t object_id = 0;
    int rc;

    if (object_id_out)
        *object_id_out = 0;
    if (!s || !plaintext || !s->delivery_initialized ||
        !delivery_latest_selected(s))
        return DELIVERY_RESULT_UNCONFIGURED;

    if (type == DELIVERY_LATEST_HEAD_TYPE) {
        delivery_latest_head_t head;
        rc = delivery_latest_head_decode(plaintext, plaintext_len, &head);
        if (rc == 0) {
            object_id = head.object_id;
            if (object_id == DELIVERY_LATEST_SYSTEM_OBJECT_ID &&
                (head.total_length != SYNC_STATUS_WIRE_LEN ||
                 head.block_size != DELIVERY_LATEST_BLOCK_BODY_MAX ||
                 head.block_count != 1U))
                rc = DELIVERY_RESULT_MALFORMED;
            if (rc == 0)
                rc = delivery_latest_receiver_validate_head(
                    &s->delivery_latest_rx, &head);
        }
        crypto_memzero(&head, sizeof(head));
        if (rc < 0)
            return rc;
    } else if (type == DELIVERY_LATEST_BLOCK_TYPE) {
        delivery_latest_block_t block;
        rc = delivery_latest_block_decode(plaintext, plaintext_len, &block);
        if (rc == 0) {
            object_id = block.object_id;
            if (object_id == DELIVERY_LATEST_SYSTEM_OBJECT_ID &&
                (block.total_length != SYNC_STATUS_WIRE_LEN ||
                 block.block_index != 0 || block.block_count != 1U ||
                 block.body_length != SYNC_STATUS_WIRE_LEN))
                rc = DELIVERY_RESULT_MALFORMED;
            if (rc == 0 &&
                object_id == DELIVERY_LATEST_SYSTEM_OBJECT_ID) {
                sync_status_record_t record;
                uint64_t tx_tip;
                uint64_t rx_delivered;
                uint64_t rx_highest;
                int sink_blocked;
                uint32_t expected_epoch;

                memset(&record, 0, sizeof(record));
                if (session_status_counters(
                        s, &tx_tip, &rx_delivered, &rx_highest,
                        &sink_blocked) != 0)
                    rc = DELIVERY_RESULT_MALFORMED;
                (void)sink_blocked;
                expected_epoch = s->epoch_rekey_enabled ? s->epoch : 0;
                if (rc == 0 && (sync_status_record_decode(
                        block.body, block.body_length, &record) != 0 ||
                    record.epoch != expected_epoch ||
                    record.rx_delivered > tx_tip))
                    rc = DELIVERY_RESULT_MALFORMED;
                crypto_memzero(&record, sizeof(record));
            }
            if (rc == 0)
                rc = delivery_latest_receiver_validate_block(
                    &s->delivery_latest_rx, &block);
        }
        crypto_memzero(&block, sizeof(block));
        if (rc < 0)
            return rc;
        if (object_id == DELIVERY_LATEST_SYSTEM_OBJECT_ID &&
            s->state == SESSION_REKEYING && s->is_server &&
            s->rekey_phase == REKEY_S_WAIT_ACK &&
            rc != DELIVERY_RESULT_OK &&
            rc != DELIVERY_RESULT_DUPLICATE &&
            rc != DELIVERY_RESULT_COMPLETE) {
            /* A canonical BLOCK may overtake its HEAD.  It authenticates but
             * has no target identity against which to prove content, so it
             * is stale-worthless and cannot open the epoch-rekey barrier.  Preserve
             * that positive classification for the outer pre-service path;
             * malformed/divergent state remains a loud protocol failure. */
            if (rc == DELIVERY_RESULT_NOT_READY ||
                rc == DELIVERY_RESULT_STALE) {
                if (object_id_out)
                    *object_id_out = object_id;
                return rc;
            }
            return DELIVERY_RESULT_MALFORMED;
        }
    } else if (type == DELIVERY_LATEST_STATUS_TYPE) {
        delivery_latest_status_t status;
        rc = delivery_latest_status_decode(plaintext, plaintext_len, &status);
        if (rc == 0) {
            object_id = status.object_id;
            rc = delivery_latest_sender_validate_status(
                &s->delivery_latest_tx, &status);
        }
        crypto_memzero(&status, sizeof(status));
        if (rc < 0)
            return rc;
    } else {
        return DELIVERY_RESULT_MALFORMED;
    }

    if (!session_delivery_latest_phase_allowed(s, type, object_id))
        return DELIVERY_RESULT_MALFORMED;
    if (object_id_out)
        *object_id_out = object_id;
    return DELIVERY_RESULT_OK;
}

int session_delivery_receive_latest(session_t *s, uint8_t type,
                                    const uint8_t *plaintext,
                                    size_t plaintext_len)
{
    uint16_t object_id = 0;
    int64_t now_ms;
    int rc;

    rc = session_delivery_prevalidate_latest(s, type, plaintext,
                                             plaintext_len, &object_id);
    if (rc != DELIVERY_RESULT_OK)
        return session_delivery_fail(s, "latest prevalidation", rc);
    if (type == DELIVERY_LATEST_HEAD_TYPE) {
        delivery_latest_head_t head;
        rc = delivery_latest_head_decode(plaintext, plaintext_len, &head);
        if (rc == 0) {
            rc = delivery_latest_receiver_observe_head(
                &s->delivery_latest_rx, &head);
        } else {
            rc = DELIVERY_RESULT_MALFORMED;
        }
        crypto_memzero(&head, sizeof(head));
    } else if (type == DELIVERY_LATEST_BLOCK_TYPE) {
        delivery_latest_block_t block;
        rc = delivery_latest_block_decode(plaintext, plaintext_len, &block);
        if (rc == 0) {
            rc = delivery_latest_receiver_observe_block(
                &s->delivery_latest_rx, &block);
        } else {
            rc = DELIVERY_RESULT_MALFORMED;
        }
        crypto_memzero(&block, sizeof(block));
    } else if (type == DELIVERY_LATEST_STATUS_TYPE) {
        delivery_latest_status_t status;
        rc = delivery_latest_status_decode(plaintext, plaintext_len, &status);
        if (rc == 0) {
            rc = delivery_latest_sender_observe_status(
                &s->delivery_latest_tx, &status, mono_ms());
        } else {
            rc = DELIVERY_RESULT_MALFORMED;
        }
        crypto_memzero(&status, sizeof(status));
    } else {
        return session_delivery_fail(s, "unknown latest type",
                                     DELIVERY_RESULT_MALFORMED);
    }
    now_ms = mono_ms();
    session_delivery_absorb_latest_changes(s, now_ms);
    if (rc < 0)
        return session_delivery_fail(s, "latest grammar/state", rc);
    if (type != DELIVERY_LATEST_STATUS_TYPE) {
        unsigned int slot;
        for (slot = 0; slot < DELIVERY_LATEST_OBJECTS; slot++)
            if (s->delivery_latest_rx.objects[slot].configured &&
                s->delivery_latest_rx.objects[slot].object_id == object_id) {
                s->delivery_latest_status_dirty |=
                    (uint8_t)(UINT8_C(1) << slot);
                s->delivery_latest_status_next_ms[slot] = now_ms;
                break;
            }
    }
    if (type == DELIVERY_LATEST_BLOCK_TYPE &&
        rc == DELIVERY_RESULT_COMPLETE) {
        rc = delivery_latest_receiver_install(&s->delivery_latest_rx,
                                              object_id);
        session_delivery_absorb_latest_changes(s, now_ms);
        if (s->delivery_callback_fatal)
            return session_delivery_fail(s,
                                         "embedded sync-status validation", rc);
        if (rc < 0 && rc != DELIVERY_RESULT_NOT_READY)
            return session_delivery_fail(s, "latest install", rc);
    }
    return 0;
}

static int session_delivery_prevalidate_reliable(
    const session_t *s, uint8_t type, const uint8_t *plaintext,
    size_t plaintext_len, uint16_t *flow_id_out)
{
    uint16_t flow_id = 0;
    int rc;

    if (flow_id_out)
        *flow_id_out = 0;
    if (!s || !plaintext || !s->delivery_initialized ||
        !delivery_reliable_selected(s))
        return DELIVERY_RESULT_UNCONFIGURED;
    if (type == DELIVERY_CTRL_RD_DATA_TYPE) {
        delivery_reliable_data_t data;

        memset(&data, 0, sizeof(data));
        rc = delivery_reliable_data_decode(plaintext, plaintext_len, &data);
        if (rc == DELIVERY_RESULT_OK) {
            flow_id = data.flow_id;
            rc = delivery_reliable_receiver_validate_data(
                &s->delivery_reliable_rx, &data);
        }
        crypto_memzero(&data, sizeof(data));
        if (rc < 0)
            return rc;
    } else if (type == DELIVERY_CTRL_RD_STATUS_TYPE) {
        delivery_reliable_status_t status;

        memset(&status, 0, sizeof(status));
        rc = delivery_reliable_status_decode(plaintext, plaintext_len,
                                             &status);
        if (rc == DELIVERY_RESULT_OK) {
            flow_id = status.flow_id;
            rc = delivery_reliable_sender_validate_status(
                &s->delivery_reliable_tx, &status);
        }
        crypto_memzero(&status, sizeof(status));
        if (rc < 0)
            return rc;
    } else {
        return DELIVERY_RESULT_MALFORMED;
    }
    if (s->state != SESSION_ESTABLISHED &&
        s->state != SESSION_KEY_DERIVING &&
        s->state != SESSION_REKEYING)
        return DELIVERY_RESULT_MALFORMED;
    if (flow_id_out)
        *flow_id_out = flow_id;
    return DELIVERY_RESULT_OK;
}

static int session_delivery_notify_reliable_result(
    session_t *s, uint16_t flow_id, delivery_result_t result)
{
    unsigned int slot;
    delivery_reliable_sender_flow_t *flow = NULL;
    session_delivery_reliable_config_t *cfg;
    uint8_t notified_hash[DELIVERY_HASH_BYTES];
    uint64_t notified_message_id;

    if (!s || (result != DELIVERY_RESULT_DELIVERED &&
               result != DELIVERY_RESULT_REFUSED))
        return DELIVERY_RESULT_MALFORMED;
    for (slot = 0; slot < DELIVERY_RELIABLE_FLOWS; slot++)
        if (s->delivery_reliable_tx.flows[slot].configured &&
            s->delivery_reliable_tx.flows[slot].flow_id == flow_id) {
            flow = &s->delivery_reliable_tx.flows[slot];
            break;
        }
    if (!flow || slot >= DELIVERY_RELIABLE_FLOWS)
        return DELIVERY_RESULT_UNCONFIGURED;
    cfg = &s->delivery_reliable_tx_config[slot];
    if (!cfg->configured || !cfg->result ||
        cfg->flow_id != flow_id || flow->last_result_id == 0 ||
        flow->last_result != result)
        return DELIVERY_RESULT_DIVERGED;
    if (cfg->result_notified) {
        if (flow->last_result_id < cfg->notified_message_id)
            return DELIVERY_RESULT_DIVERGED;
        if (flow->last_result_id == cfg->notified_message_id) {
            if (cfg->notified_result == result &&
                memcmp(cfg->notified_hash, flow->last_result_hash,
                       DELIVERY_HASH_BYTES) == 0)
                return DELIVERY_RESULT_DUPLICATE;
            return DELIVERY_RESULT_DIVERGED;
        }
    }

    /* Mark before calling out: a result callback may immediately admit the
     * successor while the predecessor transport attempt still owns its exact
     * terminal callback. */
    cfg->result_notified = 1;
    cfg->notified_message_id = flow->last_result_id;
    memcpy(cfg->notified_hash, flow->last_result_hash,
           DELIVERY_HASH_BYTES);
    cfg->notified_result = result;
    notified_message_id = cfg->notified_message_id;
    memcpy(notified_hash, cfg->notified_hash, sizeof(notified_hash));
    cfg->result(cfg->result_arg, flow_id, notified_message_id,
                notified_hash, result);
    crypto_memzero(notified_hash, sizeof(notified_hash));
    return DELIVERY_RESULT_OK;
}

static int session_delivery_receive_reliable(session_t *s, uint8_t type,
                                             const uint8_t *plaintext,
                                             size_t plaintext_len)
{
    uint16_t flow_id = 0;
    unsigned int slot;
    int rc;

    rc = session_delivery_prevalidate_reliable(
        s, type, plaintext, plaintext_len, &flow_id);
    if (rc != DELIVERY_RESULT_OK)
        return session_delivery_fail(s, "reliable prevalidation", rc);
    if (s->state != SESSION_ESTABLISHED) {
        /* The client may start delivery after its exact final-ACK handoff
         * while the server still waits for that ACK.  Canonical configured
         * RD traffic is not an epoch proof and is discarded without state
         * mutation; malformed/unselected traffic failed above. */
        fprintf(stderr,
                "session: valid pre-barrier reliable record withheld until "
                "epoch confirmation\n");
        return 0;
    }
    if (type == DELIVERY_CTRL_RD_DATA_TYPE) {
        delivery_reliable_data_t data;
        rc = delivery_reliable_data_decode(plaintext, plaintext_len, &data);
        if (rc == 0) {
            flow_id = data.flow_id;
            rc = delivery_reliable_receiver_observe_data(
                &s->delivery_reliable_rx, &data);
        } else {
            rc = DELIVERY_RESULT_MALFORMED;
        }
        crypto_memzero(&data, sizeof(data));
        if (rc >= 0 && rc != DELIVERY_RESULT_REFUSED) {
            int deliver_rc = delivery_reliable_receiver_deliver(
                &s->delivery_reliable_rx, flow_id);
            if (deliver_rc == DELIVERY_RESULT_DELIVERED)
                rc = deliver_rc;
            else if (deliver_rc < 0 &&
                     deliver_rc != DELIVERY_RESULT_NOT_READY)
                rc = deliver_rc;
        }
    } else if (type == DELIVERY_CTRL_RD_STATUS_TYPE) {
        delivery_reliable_status_t status;
        rc = delivery_reliable_status_decode(plaintext, plaintext_len,
                                             &status);
        if (rc == 0) {
            flow_id = status.flow_id;
            rc = delivery_reliable_sender_observe_status(
                &s->delivery_reliable_tx, &status);
        } else {
            rc = DELIVERY_RESULT_MALFORMED;
        }
        crypto_memzero(&status, sizeof(status));
        if (rc == DELIVERY_RESULT_DELIVERED ||
            rc == DELIVERY_RESULT_REFUSED) {
            int notify_rc = session_delivery_notify_reliable_result(
                s, flow_id, (delivery_result_t)rc);
            if (notify_rc < 0)
                rc = notify_rc;
        }
    } else {
        return session_delivery_fail(s, "unknown reliable type",
                                     DELIVERY_RESULT_MALFORMED);
    }
    if (rc < 0)
        return session_delivery_fail(s, "reliable grammar/state", rc);
    if (type == DELIVERY_CTRL_RD_DATA_TYPE) {
        for (slot = 0; slot < DELIVERY_RELIABLE_FLOWS; slot++)
            if (s->delivery_reliable_rx.flows[slot].configured &&
                s->delivery_reliable_rx.flows[slot].flow_id == flow_id) {
                s->delivery_reliable_status_dirty |=
                    (uint8_t)(1U << slot);
                s->delivery_reliable_status_next_ms[slot] = mono_ms();
                break;
            }
    }
    return 0;
}

void session_delivery_tick(session_t *s, int64_t now_ms)
{
    unsigned int i;

    if (!s || !s->delivery_initialized ||
        s->state != SESSION_ESTABLISHED)
        return;
    if (delivery_latest_selected(s)) {
        int refresh_rc = delivery_latest_receiver_refresh_reservations(
            &s->delivery_latest_rx);
        session_delivery_absorb_latest_changes(s, now_ms);
        if (refresh_rc < 0) {
            (void)session_delivery_fail(
                s, "aggregate reservation refresh", refresh_rc);
            return;
        }
        for (i = 0; i < DELIVERY_LATEST_OBJECTS; i++) {
            delivery_latest_receiver_object_t *object =
                &s->delivery_latest_rx.objects[i];
            int rc;
            if (!object->configured || !object->target_valid ||
                object->frontier != object->target.block_count)
                continue;
            rc = delivery_latest_receiver_install(&s->delivery_latest_rx,
                                                  object->object_id);
            session_delivery_absorb_latest_changes(s, now_ms);
            if (s->delivery_callback_fatal) {
                (void)session_delivery_fail(
                    s, "deferred embedded sync-status validation", rc);
                return;
            }
            if (rc < 0 && rc != DELIVERY_RESULT_NOT_READY) {
                (void)session_delivery_fail(s, "deferred latest install", rc);
                return;
            }
        }
    }
    if (delivery_reliable_selected(s)) {
        for (i = 0; i < DELIVERY_RELIABLE_FLOWS; i++) {
            delivery_reliable_receiver_flow_t *flow =
                &s->delivery_reliable_rx.flows[i];
            int rc;
            if (!flow->configured || !flow->target_valid)
                continue;
            rc = delivery_reliable_receiver_deliver(
                &s->delivery_reliable_rx, flow->flow_id);
            if (rc == DELIVERY_RESULT_DELIVERED) {
                s->delivery_reliable_status_dirty |= (uint8_t)(1U << i);
                s->delivery_reliable_status_next_ms[i] = now_ms;
            } else if (rc < 0 && rc != DELIVERY_RESULT_NOT_READY) {
                (void)session_delivery_fail(s,
                                            "deferred reliable delivery", rc);
                return;
            }
        }
    }
}

int64_t session_delivery_next_deadline(const session_t *s, int64_t now_ms)
{
    int64_t deadline = INT64_MAX;
    unsigned int i;

    if (!s || !s->delivery_initialized)
        return -1;
    if (delivery_barrier_feedback_active(s)) {
        const delivery_latest_receiver_object_t *rx =
            &s->delivery_latest_rx.objects[0];

        if (!rx->configured || !rx->target_valid ||
            s->delivery_latest_status_next_ms[0] <= now_ms)
            return -1;
        return s->delivery_latest_status_next_ms[0] - now_ms;
    }
    if (s->state != SESSION_ESTABLISHED)
        return -1;
    for (i = 0; i < DELIVERY_LATEST_OBJECTS; i++) {
        const delivery_latest_sender_object_t *tx =
            &s->delivery_latest_tx.objects[i];
        const delivery_latest_receiver_object_t *rx =
            &s->delivery_latest_rx.objects[i];
        if (tx->configured && tx->snapshot_count != 0 &&
            s->delivery_head_next_ms[i] > now_ms &&
            s->delivery_head_next_ms[i] < deadline)
            deadline = s->delivery_head_next_ms[i];
        if (tx->configured && tx->retry.pending && !tx->retry.inflight &&
            tx->retry.next_attempt_ms > now_ms &&
            tx->retry.next_attempt_ms < deadline)
            deadline = tx->retry.next_attempt_ms;
        if (rx->configured &&
            s->delivery_latest_status_next_ms[i] > now_ms &&
            s->delivery_latest_status_next_ms[i] < deadline)
            deadline = s->delivery_latest_status_next_ms[i];
    }
    for (i = 0; i < DELIVERY_RELIABLE_FLOWS; i++) {
        const delivery_reliable_sender_flow_t *tx =
            &s->delivery_reliable_tx.flows[i];
        const delivery_reliable_receiver_flow_t *rx =
            &s->delivery_reliable_rx.flows[i];
        if (tx->configured && tx->retry.pending && !tx->retry.inflight &&
            tx->retry.next_attempt_ms > now_ms &&
            tx->retry.next_attempt_ms < deadline)
            deadline = tx->retry.next_attempt_ms;
        if (rx->configured &&
            s->delivery_reliable_status_next_ms[i] > now_ms &&
            s->delivery_reliable_status_next_ms[i] < deadline)
            deadline = s->delivery_reliable_status_next_ms[i];
    }
    if (deadline == INT64_MAX)
        return -1;
    return deadline - now_ms;
}

/* -------------------------------------------------------------------------
 * epoch-rekey adjacent-epoch engine
 * ---------------------------------------------------------------------- */

static int bytes_all_zero(const uint8_t *bytes, size_t len)
{
    uint8_t aggregate = 0;
    for (size_t i = 0; i < len; i++)
        aggregate |= bytes[i];
    return aggregate == 0;
}

static void pending_epoch_clear(session_t *s)
{
    s->pending_epoch_valid = 0;
    s->pending_epoch = 0;
    crypto_memzero(s->pending_pair_id, sizeof(s->pending_pair_id));
    crypto_memzero(s->pending_key, sizeof(s->pending_key));
    s->pending_tx_seq = 0;
    memset(&s->pending_replay, 0, sizeof(s->pending_replay));
    crypto_memzero(s->pending_transcript_digest,
                   sizeof(s->pending_transcript_digest));
    crypto_memzero(s->pending_epoch_fingerprint,
                   sizeof(s->pending_epoch_fingerprint));
}

static int install_pending_epoch(session_t *s,
                                 uint32_t to_epoch,
                                 const epoch_crypto_rekey_material_t *material)
{
    uint8_t pair_id[4];
    if (!s || !material || s->pending_epoch_valid ||
        epoch_crypto_pair_id(s->pair_seed, to_epoch, pair_id) != 0)
        return -1;
    s->pending_epoch = to_epoch;
    memcpy(s->pending_pair_id, pair_id, sizeof(pair_id));
    memcpy(s->pending_key, material->traffic_key, sizeof(s->pending_key));
    s->pending_tx_seq = 0;
    memset(&s->pending_replay, 0, sizeof(s->pending_replay));
    memcpy(s->pending_transcript_digest, material->transcript_hash,
           sizeof(s->pending_transcript_digest));
    memcpy(s->pending_epoch_fingerprint, material->epoch_fingerprint,
           sizeof(s->pending_epoch_fingerprint));
    s->pending_epoch_valid = 1;
    return 0;
}

static int adopt_pending_epoch(session_t *s)
{
    bulk_engine_observation_t bulk_observation;
    int combined_d29;
    int rc;

    if (!s || !s->pending_epoch_valid || s->pending_epoch != s->epoch + 1U)
        return -1;
    if (s->wire_message.valid && s->wire_message.started) {
        fprintf(stderr,
                "session: FATAL: refusing epoch adoption across a started "
                "authenticated message\n");
        s->run_failed = 1;
        return -1;
    }
    combined_d29 = delivery_status_combined(s) && s->services_started;
    if (s->wire_delivery.valid) {
        fprintf(stderr,
                "session: epoch adoption deferred until active delivery-class record "
                "reaches a terminal boundary\n");
        return 1;
    }
    if (pq_rekey_selected(s) &&
        (s->pq_active_work != PQ_REKEY_WORK_NONE ||
         s->pq_rekey_tx.inflight ||
         s->pq_rekey_rx.bitmap_inflight)) {
        fprintf(stderr,
                "session: epoch adoption deferred until active pq-hybrid record reaches its transport boundary\n");
        return 1;
    }
    if (s->rekey_flight.valid && s->rekey_flight.retry.inflight) {
        fprintf(stderr,
                "session: epoch adoption deferred until predecessor epoch-rekey "
                "flight reaches its transport boundary\n");
        return 1;
    }
    if (s->bulk_activated) {
        memset(&bulk_observation, 0, sizeof(bulk_observation));
        if (bulk_engine_observe(s->bulk, &bulk_observation) != BULK_RC_OK ||
            !bulk_observation.paused ||
            s->wire_active_slot == WIRE_ACTIVE_BULK) {
            fprintf(stderr,
                    "session: FATAL: bulk-transfer epoch adoption crossed an unpaused record\n");
            s->run_failed = 1;
            return -1;
        }
    }
    if (combined_d29) {
        rc = delivery_latest_receiver_cancel_target(
            &s->delivery_latest_rx, DELIVERY_LATEST_SYSTEM_OBJECT_ID);
        session_delivery_absorb_latest_changes(s, mono_ms());
        if (rc != DELIVERY_RESULT_OK && rc != DELIVERY_RESULT_STALE) {
            fprintf(stderr,
                    "session: FATAL: could not cancel old-epoch status "
                    "target (%d)\n", rc);
            s->run_failed = 1;
            return -1;
        }
        rc = delivery_latest_sender_retire_all(
            &s->delivery_latest_tx, DELIVERY_LATEST_SYSTEM_OBJECT_ID);
        if (rc != DELIVERY_RESULT_OK) {
            fprintf(stderr,
                    "session: FATAL: could not retire old-epoch status "
                    "snapshots (%d)\n", rc);
            s->run_failed = 1;
            return -1;
        }
    }

    if (s->multipath_active &&
        multipath_traffic_epoch_adopt(&s->multipath) != 0) {
        fprintf(stderr,
                "session: FATAL: multipath path state invalid at epoch adoption\n");
        s->run_failed = 1;
        return -1;
    }

    if (sync_monitor_plan_barrier(s) != 0)
        return -1;

    crypto_memzero(s->session_key, sizeof(s->session_key));
    memset(&s->replay, 0, sizeof(s->replay));
    memcpy(s->pair_id, s->pending_pair_id, sizeof(s->pair_id));
    memcpy(s->session_key, s->pending_key, sizeof(s->session_key));
    s->tx_seq = s->pending_tx_seq;
    s->replay = s->pending_replay;
    s->epoch = s->pending_epoch;
    memcpy(s->epoch_transcript_digest, s->pending_transcript_digest,
           sizeof(s->epoch_transcript_digest));
    memcpy(s->epoch_fingerprint, s->pending_epoch_fingerprint,
           sizeof(s->epoch_fingerprint));
    memcpy(s->completed_rekey_id, s->rekey_id,
           sizeof(s->completed_rekey_id));
    s->completed_rekey_valid = 1;
    s->rekey_adoption_deferred = 0;
    pending_epoch_clear(s);

    /* fragmentation messages cannot cross an epoch. Terminal-state-sync offset/frontier state does. */
    reasm_reset(&s->reasm);
    for (size_t i = 0; i < SESSION_TX_SLOT_COUNT; i++) {
        session_tx_intent_t *intent = &s->wire_intents[i];
        if (intent->valid && !intent->inflight &&
            intent->type == CTRL_STATUS_HEARTBEAT)
            crypto_memzero(intent, sizeof(*intent));
    }
    sync_status_tracker_set_epoch(&s->sync_status, s->epoch, mono_ms());
    if (combined_d29) {
        s->delivery_latest_status_dirty |= 1U;
        s->delivery_latest_status_next_ms[0] = mono_ms();
        s->d29_latest_periodic_pending = 0;
        s->d29_latest_periodic_revision = 0;
        if (send_status_record(s, 0, SESSION_TX_DONE_STATUS_PERIODIC,
                               WIRE_COALESCE_STATUS, mono_ms()) != 0) {
            fprintf(stderr,
                    "session: FATAL: could not publish adopted-epoch status\n");
            s->run_failed = 1;
            return -1;
        }
    }
    if (pq_rekey_selected(s)) {
        pq_rekey_metrics_report(s, mono_ms());
        pq_rekey_exchange_reset(s);
    }
    crypto_memzero(s->rekey_private, sizeof(s->rekey_private));
    fprintf(stderr, "session: adopted authenticated epoch %u\n", s->epoch);
    return 0;
}

/* epoch-rekey keeps its exact five-flight grammar and route rules, but shares the
 * delivery-class exact transport-owner primitive. One generation is the immutable
 * {attempt epoch, control type}; semantic successors may retire queued work,
 * while an already-started transport attempt survives until its one terminal
 * callback. */
static uint64_t rekey_flight_generation(uint8_t type, uint32_t epoch)
{
    return ((uint64_t)epoch << 8) | (uint64_t)type;
}

static void rekey_flight_reset(session_t *s)
{
    if (!s)
        return;
    crypto_memzero(&s->rekey_flight, sizeof(s->rekey_flight));
    (void)delivery_retry_init(&s->rekey_flight.retry, REKEY_RETRY_MS);
    s->rekey_next_send_ms = 0;
}

static void pq_rekey_exchange_reset(session_t *s)
{
    if (!s)
        return;
    crypto_memzero(&s->pq_rekey_tx, sizeof(s->pq_rekey_tx));
    pq_rekey_rx_wipe(&s->pq_rekey_rx);
    crypto_memzero(s->pq_mlkem_private,
                   sizeof(s->pq_mlkem_private));
    s->pq_base_received = 0U;
    s->pq_rx_bitmap_retired = 0U;
    s->pq_work_cursor = PQ_REKEY_WORK_BITMAP;
    s->pq_active_work = PQ_REKEY_WORK_NONE;
}

static int pq_rekey_selected(const session_t *s)
{
    return s && s->pq_hybrid_enabled &&
           (s->selected_caps & UNMOOR_CAP_PQ_HYBRID_D45_V1) != 0U;
}

static void pq_rekey_metrics_begin(session_t *s, int64_t now_ms)
{
    if (!s)
        return;
    s->pq_rekey_metrics_active = 1U;
    s->pq_share_tx_seen_bitmap = 0U;
    s->pq_share_tx_attempts = 0U;
    s->pq_share_tx_retransmits = 0U;
    s->pq_rekey_started_ms = now_ms;
}

static void pq_rekey_metrics_report(session_t *s, int64_t now_ms)
{
    int64_t elapsed;

    if (!s || !s->pq_rekey_metrics_active)
        return;
    elapsed = now_ms >= s->pq_rekey_started_ms
        ? now_ms - s->pq_rekey_started_ms : 0;
    fprintf(stderr,
            "session: pq-hybrid rekey metrics role=%s epoch=%u elapsed-ms=%lld share-tx=%llu retransmitted=%llu\n",
            s->is_server ? "listener" : "client", s->epoch,
            (long long)elapsed,
            (unsigned long long)s->pq_share_tx_attempts,
            (unsigned long long)s->pq_share_tx_retransmits);
    s->pq_rekey_metrics_active = 0U;
}

static int pq_rekey_tx_arm(session_t *s, uint8_t kind,
                           const uint8_t share[PQ_REKEY_SHARE_LEN],
                           int64_t now_ms)
{
    session_pq_rekey_tx_t *tx;
    uint16_t stride;
    uint8_t count;

    if (!s || !share || !pq_rekey_selected(s) ||
        (kind != PQ_REKEY_KIND_INIT && kind != PQ_REKEY_KIND_REPLY) ||
        pq_rekey_geometry(PQ_REKEY_CONTROL_MTU, &stride, &count) != 0)
        return -1;
    tx = &s->pq_rekey_tx;
    if (tx->active)
        return -1;
    memset(tx, 0, sizeof(*tx));
    tx->active = 1U;
    tx->kind = kind;
    tx->count = count;
    tx->stride = stride;
    tx->from_epoch = s->epoch;
    tx->cycle_remaining = pq_rekey_full_bitmap(count);
    tx->next_send_ms = now_ms;
    tx->order = ++s->wire_next_order;
    memcpy(tx->rekey_id, s->rekey_id, sizeof(tx->rekey_id));
    memcpy(tx->bytes, share, sizeof(tx->bytes));
    return 0;
}

static int pq_rekey_share_eligible(const session_t *s, int64_t now_ms)
{
    const session_pq_rekey_tx_t *tx;

    if (!pq_rekey_selected(s) || s->state != SESSION_REKEYING)
        return 0;
    tx = &s->pq_rekey_tx;
    return tx->active && !tx->retired && !tx->inflight &&
           tx->peer_bitmap != pq_rekey_full_bitmap(tx->count) &&
           now_ms >= tx->next_send_ms;
}

static int pq_rekey_bitmap_eligible(const session_t *s, int64_t now_ms)
{
    return pq_rekey_selected(s) && s->state == SESSION_REKEYING &&
           s->pq_rekey_rx.active && !s->pq_rx_bitmap_retired &&
           !s->pq_rekey_rx.bitmap_inflight &&
           now_ms >= s->pq_rekey_rx.bitmap_due_ms;
}

static int rekey_flight_route_valid(const session_t *s,
                                    const session_rekey_flight_t *flight)
{
    int phase_valid;

    if (!s || !flight || !flight->valid ||
        !rekey_control_type(flight->type) ||
        flight->attempt_epoch != s->epoch)
        return 0;
    switch (flight->type) {
    case CTRL_REKEY_REQUEST:
        phase_valid = s->is_server &&
                      s->state == SESSION_ESTABLISHED &&
                      s->rekey_request_pending &&
                      s->rekey_phase == REKEY_S_WAIT_INIT;
        break;
    case CTRL_REKEY_INIT:
        phase_valid = !s->is_server &&
                      s->state == SESSION_REKEYING &&
                      s->rekey_phase == REKEY_C_WAIT_REPLY;
        break;
    case CTRL_REKEY_REPLY:
        phase_valid = s->is_server &&
                      s->state == SESSION_REKEYING &&
                      s->rekey_phase == REKEY_S_WAIT_CONFIRM;
        break;
    case CTRL_REKEY_CONFIRM:
        phase_valid = !s->is_server &&
                      s->state == SESSION_REKEYING &&
                      s->rekey_phase == REKEY_C_WAIT_COMMIT;
        break;
    case CTRL_REKEY_COMMIT:
        phase_valid = s->is_server &&
                      s->state == SESSION_REKEYING &&
                      s->rekey_phase == REKEY_S_WAIT_ACK;
        break;
    case CTRL_REKEY_ACK:
        phase_valid = !s->is_server &&
                      s->state == SESSION_REKEYING &&
                      s->rekey_phase == REKEY_C_WAIT_ACK_SEND;
        break;
    default:
        phase_valid = 0;
        break;
    }
    if (!phase_valid)
        return 0;
    if (flight->type == CTRL_REKEY_CONFIRM) {
        if (!s->pending_epoch_valid ||
            s->pending_epoch != s->epoch + 1U)
            return 0;
        /* pq-hybrid must carry CONFIRM under the current epoch so an ML-KEM
         * implicit-rejection candidate can reach the explicit comparison.
         * Legacy epoch-rekey retains its pending-epoch route byte-for-byte. */
        return pq_rekey_selected(s)
            ? !flight->pending_epoch : flight->pending_epoch;
    }
    return !flight->pending_epoch;
}

static int rekey_flight_clear(session_t *s)
{
    session_rekey_flight_t *flight;
    int rc;

    if (!s)
        return -1;
    flight = &s->rekey_flight;
    if (flight->retry.pending) {
        rc = delivery_retry_ack(&flight->retry, flight->retry.generation);
        if (rc != DELIVERY_RESULT_OK)
            return -1;
    }
    rekey_flight_reset(s);
    return 0;
}

/* 0 = a logical flight is armed; 1 = an exact predecessor transport owner
 * is still active and the phase/tick will retry; -1 = invariant. */
static int rekey_flight_prepare(session_t *s, uint8_t type,
                                int pending_epoch, int64_t now_ms)
{
    session_rekey_flight_t *flight;
    uint32_t epoch;
    uint64_t generation;
    int rc;

    if (!s || !rekey_control_type(type) ||
        (pending_epoch && type != CTRL_REKEY_CONFIRM))
        return -1;
    epoch = s->epoch;
    generation = rekey_flight_generation(type, epoch);
    flight = &s->rekey_flight;
    if (flight->valid) {
        if (flight->retry.generation == generation &&
            flight->type == type &&
            flight->pending_epoch == (uint8_t)(pending_epoch != 0)) {
            if (flight->semantic_retired || flight->retry.inflight)
                return 1;
            flight->retry.next_attempt_ms = now_ms;
            s->rekey_next_send_ms = now_ms;
            return 0;
        }
        if (flight->retry.inflight) {
            flight->semantic_retired = 1;
            s->rekey_next_send_ms = 0;
            return 1;
        }
        if (rekey_flight_clear(s) != 0)
            return -1;
        flight = &s->rekey_flight;
    }
    flight->valid = 1;
    flight->type = type;
    flight->pending_epoch = (uint8_t)(pending_epoch != 0);
    flight->attempt_epoch = epoch;
    flight->ticket = ++s->wire_next_ticket;
    flight->order = ++s->wire_next_order;
    rc = delivery_retry_arm(&flight->retry, generation, now_ms);
    if (rc != DELIVERY_RESULT_OK)
        return -1;
    if (!rekey_flight_route_valid(s, flight)) {
        (void)rekey_flight_clear(s);
        return -1;
    }
    s->rekey_next_send_ms = now_ms;
    return 0;
}

static int rekey_flight_eligible(const session_t *s, int64_t now_ms)
{
    return s && rekey_flight_route_valid(s, &s->rekey_flight) &&
           !s->rekey_flight.semantic_retired &&
           delivery_retry_due(&s->rekey_flight.retry, now_ms);
}

static int rekey_work_eligible(const session_t *s, int64_t now_ms)
{
    return rekey_flight_eligible(s, now_ms) ||
           pq_rekey_bitmap_eligible(s, now_ms) ||
           pq_rekey_share_eligible(s, now_ms);
}

static void rekey_flight_transport_result(session_t *s, int completed,
                                          int64_t now_ms)
{
    session_rekey_flight_t *flight;
    uint8_t type;
    uint32_t epoch;
    int final_ack;
    int rc;

    if (!s || !s->rekey_flight.valid) {
        if (s) {
            fprintf(stderr,
                    "session: FATAL: missing epoch-rekey completion identity\n");
            s->run_failed = 1;
            s->wire_protocol_failure = 1;
        }
        return;
    }
    flight = &s->rekey_flight;
    type = flight->type;
    epoch = flight->attempt_epoch;
    final_ack = !s->is_server && type == CTRL_REKEY_ACK &&
                s->state == SESSION_REKEYING &&
                s->rekey_phase == REKEY_C_WAIT_ACK_SEND &&
                epoch == s->epoch && !flight->semantic_retired;
    rc = delivery_retry_result(
        &flight->retry, rekey_flight_generation(type, epoch),
        completed ? DELIVERY_ATTEMPT_COMPLETE : DELIVERY_ATTEMPT_FAILED,
        now_ms);
    if (rc != DELIVERY_RESULT_OK) {
        fprintf(stderr,
                "session: FATAL: epoch-rekey terminal owner mismatch (%d)\n", rc);
        s->run_failed = 1;
        s->wire_protocol_failure = 1;
        return;
    }
    if (!completed)
        s->wire_failed_ticket = flight->ticket;
    s->rekey_next_send_ms = flight->retry.next_attempt_ms;
    if (flight->semantic_retired) {
        if (rekey_flight_clear(s) != 0) {
            fprintf(stderr,
                    "session: FATAL: epoch-rekey retired owner release failed\n");
            s->run_failed = 1;
            s->wire_protocol_failure = 1;
            return;
        }
        maybe_complete_deferred_epoch_adoption(s, now_ms);
        return;
    }
    if (final_ack && completed)
        finish_epoch_barrier(s);
}

static void rekey_flight_semantic_retire(session_t *s, uint8_t type,
                                         uint32_t epoch)
{
    session_rekey_flight_t *flight;
    uint64_t generation;

    if (!s)
        return;
    flight = &s->rekey_flight;
    generation = rekey_flight_generation(type, epoch);
    if (!flight->valid || !flight->retry.pending ||
        flight->retry.generation != generation)
        return;
    if (flight->retry.inflight) {
        flight->semantic_retired = 1;
        s->rekey_next_send_ms = 0;
        return;
    }
    if (rekey_flight_clear(s) != 0) {
        fprintf(stderr,
                "session: FATAL: epoch-rekey semantic owner retirement failed\n");
        s->run_failed = 1;
        s->wire_protocol_failure = 1;
    }
}

static void fill_rekey_message(const session_t *s, uint8_t type,
                               rekey_message_t *message)
{
    memset(message, 0, sizeof(*message));
    message->type = type;
    message->from_epoch = s->epoch;
    message->to_epoch = s->epoch + 1U;
    if (type == CTRL_REKEY_REQUEST)
        return;

    if (type == CTRL_REKEY_INIT) {
        memcpy(message->id, s->rekey_id, sizeof(message->id));
        memcpy(message->first, s->rekey_client_public,
               sizeof(message->first));
    } else if (type == CTRL_REKEY_REPLY) {
        memcpy(message->id, s->rekey_id, sizeof(message->id));
        memcpy(message->first, s->rekey_server_public,
               sizeof(message->first));
    } else if (s->pending_epoch_valid) {
        memcpy(message->id, s->rekey_id, sizeof(message->id));
        memcpy(message->first, s->pending_transcript_digest,
               sizeof(message->first));
        memcpy(message->second, s->pending_epoch_fingerprint,
               sizeof(message->second));
    } else {
        /* After adoption, retained current confirmation metadata validates
         * and reasserts duplicate COMMIT/ACK without retaining DH secrets. */
        memcpy(message->id, s->completed_rekey_id, sizeof(message->id));
        memcpy(message->first, s->epoch_transcript_digest,
               sizeof(message->first));
        memcpy(message->second, s->epoch_fingerprint,
               sizeof(message->second));
        message->from_epoch = s->epoch - 1U;
        message->to_epoch = s->epoch;
    }
}

static int wire_encode_rekey_base(session_t *s, int64_t now_ms)
{
    session_rekey_flight_t *flight;
    session_tx_intent_t intent;
    rekey_message_t message;
    uint8_t wire[REKEY_MESSAGE_LEN];
    uint32_t expected_from;
    uint32_t expected_to;
    int rc;

    if (!s || !rekey_flight_eligible(s, now_ms))
        return -1;
    flight = &s->rekey_flight;
    memset(&intent, 0, sizeof(intent));
    memset(&message, 0, sizeof(message));
    memset(wire, 0, sizeof(wire));
    fill_rekey_message(s, flight->type, &message);
    if (flight->type == CTRL_REKEY_COMMIT ||
        flight->type == CTRL_REKEY_ACK) {
        if (flight->attempt_epoch == 0) {
            crypto_memzero(&message, sizeof(message));
            crypto_memzero(wire, sizeof(wire));
            return -1;
        }
        expected_from = flight->attempt_epoch - 1U;
        expected_to = flight->attempt_epoch;
    } else {
        expected_from = flight->attempt_epoch;
        expected_to = flight->attempt_epoch + 1U;
    }
    if (message.from_epoch != expected_from ||
        message.to_epoch != expected_to ||
        rekey_message_encode(wire, &message) != 0 ||
        sizeof(wire) > s->current_mtu) {
        crypto_memzero(&message, sizeof(message));
        crypto_memzero(wire, sizeof(wire));
        return -1;
    }
    intent.epoch_source = flight->pending_epoch
        ? SESSION_TX_EPOCH_PENDING : SESSION_TX_EPOCH_CURRENT;
    intent.sequence_class = SESSION_TX_SEQ_EPOCH_CONTROL;
    intent.mode_mask = SESSION_TX_MODE_REKEY;
    intent.chan_byte = CHAN_FF_BIT;
    intent.type = flight->type;
    intent.length = REKEY_MESSAGE_LEN;
    memcpy(intent.bytes, wire, sizeof(wire));
    rc = wire_encode_authenticated_intent(s, &intent);
    crypto_memzero(&intent, sizeof(intent));
    crypto_memzero(&message, sizeof(message));
    crypto_memzero(wire, sizeof(wire));
    if (rc != 0)
        return rc;

    /* The logical identity is claimed only after canonical materialization,
     * route selection, AEAD, framing, and sequence use have succeeded. */
    rc = delivery_retry_selected(&flight->retry,
                                 rekey_flight_generation(
                                     flight->type, flight->attempt_epoch),
                                 now_ms);
    if (rc != DELIVERY_RESULT_OK) {
        fprintf(stderr,
                "session: FATAL: epoch-rekey selected owner changed after encode "
                "(%d)\n", rc);
        s->run_failed = 1;
        s->wire_protocol_failure = 1;
        return -2;
    }
    return 0;
}

static int wire_encode_pq_share(session_t *s, int64_t now_ms)
{
    session_pq_rekey_tx_t *tx;
    pq_rekey_share_descriptor_t descriptor;
    uint8_t descriptor_wire[PQ_REKEY_SHARE_DESCRIPTOR_LEN];
    uint8_t ad[10U + PQ_REKEY_SHARE_DESCRIPTOR_LEN];
    uint8_t body[PQ_REKEY_SHARE_DESCRIPTOR_LEN +
                 PQ_REKEY_MTU_MAX + FRAME_TAG_LEN];
    uint8_t ciphertext[PQ_REKEY_MTU_MAX + FRAME_TAG_LEN];
    uint32_t remaining;
    uint32_t seq;
    uint8_t index = 0U;
    size_t ciphertext_len = 0U;
    int n;

    if (!s || !pq_rekey_share_eligible(s, now_ms) ||
        s->tx_seq == UINT32_MAX)
        return -1;
    tx = &s->pq_rekey_tx;
    remaining = tx->cycle_remaining;
    if (remaining == 0U) {
        remaining = pq_rekey_full_bitmap(tx->count) & ~tx->peer_bitmap;
        tx->cycle_remaining = remaining;
    }
    if (remaining == 0U)
        return -1;
    for (uint8_t step = 0U; step < tx->count; step++) {
        index = (uint8_t)((tx->cursor + step) % tx->count);
        if ((remaining & (UINT32_C(1) << index)) != 0U)
            break;
    }
    if ((remaining & (UINT32_C(1) << index)) == 0U ||
        pq_rekey_share_descriptor_make(
            &descriptor, tx->kind, tx->from_epoch, tx->rekey_id, index,
            PQ_REKEY_CONTROL_MTU) != 0 ||
        pq_rekey_share_descriptor_encode(descriptor_wire, &descriptor,
                                         PQ_REKEY_CONTROL_MTU) != 0)
        return -1;

    seq = s->tx_seq;
    build_frame_ad(s->pair_id, seq, CHAN_FF_BIT,
                   CTRL_REKEY_PQ_SHARE, ad);
    memcpy(ad + 10U, descriptor_wire, sizeof(descriptor_wire));
    if (crypto_encrypt_ad(
            s->session_key, seq, s->is_server ? 0x01 : 0x00,
            ad, sizeof(ad), tx->bytes + descriptor.offset,
            descriptor.payload_length, ciphertext,
            &ciphertext_len) != 0)
        return -1;
    memcpy(body, descriptor_wire, sizeof(descriptor_wire));
    memcpy(body + sizeof(descriptor_wire), ciphertext, ciphertext_len);
    n = unmoor_frame_encode(
        s->pair_id, seq, CHAN_FF_BIT, CTRL_REKEY_PQ_SHARE,
        body, sizeof(descriptor_wire) + ciphertext_len,
        s->wire_frame, sizeof(s->wire_frame));
    crypto_memzero(ciphertext, sizeof(ciphertext));
    crypto_memzero(body, sizeof(body));
    crypto_memzero(ad, sizeof(ad));
    crypto_memzero(descriptor_wire, sizeof(descriptor_wire));
    crypto_memzero(&descriptor, sizeof(descriptor));
    if (n < 0)
        return -1;
    if ((s->pq_share_tx_seen_bitmap & (UINT32_C(1) << index)) != 0U)
        s->pq_share_tx_retransmits++;
    else
        s->pq_share_tx_seen_bitmap |= UINT32_C(1) << index;
    s->pq_share_tx_attempts++;
    s->tx_seq++;
    s->wire_frame_len = (size_t)n;
    tx->inflight = 1U;
    tx->inflight_index = index;
    s->pq_active_work = PQ_REKEY_WORK_SHARE;
    return 0;
}

static int wire_encode_pq_bitmap(session_t *s, int64_t now_ms)
{
    pq_rekey_bitmap_t bitmap;
    session_tx_intent_t intent;
    uint8_t wire[PQ_REKEY_BITMAP_LEN];
    int claimed;
    int rc;

    memset(&bitmap, 0, sizeof(bitmap));
    memset(&intent, 0, sizeof(intent));
    memset(wire, 0, sizeof(wire));
    if (!s || !pq_rekey_bitmap_eligible(s, now_ms))
        return -1;
    claimed = pq_rekey_rx_bitmap_claim(&s->pq_rekey_rx, now_ms, &bitmap);
    if (claimed != 1 || pq_rekey_bitmap_encode(wire, &bitmap) != 0)
        goto fail;
    intent.epoch_source = SESSION_TX_EPOCH_CURRENT;
    intent.sequence_class = SESSION_TX_SEQ_EPOCH_CONTROL;
    intent.mode_mask = SESSION_TX_MODE_REKEY;
    intent.chan_byte = CHAN_FF_BIT;
    intent.type = CTRL_REKEY_PQ_BITMAP;
    intent.length = sizeof(wire);
    memcpy(intent.bytes, wire, sizeof(wire));
    rc = wire_encode_authenticated_intent(s, &intent);
    if (rc != 0)
        goto fail;
    s->pq_active_work = PQ_REKEY_WORK_BITMAP;
    crypto_memzero(&bitmap, sizeof(bitmap));
    crypto_memzero(&intent, sizeof(intent));
    crypto_memzero(wire, sizeof(wire));
    return 0;

fail:
    if (s && s->pq_rekey_rx.bitmap_inflight)
        (void)pq_rekey_rx_bitmap_complete(&s->pq_rekey_rx, now_ms);
    crypto_memzero(&bitmap, sizeof(bitmap));
    crypto_memzero(&intent, sizeof(intent));
    crypto_memzero(wire, sizeof(wire));
    return -1;
}

static int wire_encode_rekey_work(session_t *s, int64_t now_ms)
{
    uint8_t cursor;
    uint8_t selected = PQ_REKEY_WORK_NONE;
    int rc;

    if (!s || !rekey_work_eligible(s, now_ms) ||
        s->pq_active_work != PQ_REKEY_WORK_NONE)
        return -1;
    cursor = s->pq_work_cursor;
    if (cursor < PQ_REKEY_WORK_BITMAP || cursor > PQ_REKEY_WORK_SHARE)
        cursor = PQ_REKEY_WORK_BITMAP;
    for (uint8_t step = 0U; step < 3U; step++) {
        uint8_t candidate = (uint8_t)(
            ((cursor - PQ_REKEY_WORK_BITMAP + step) % 3U) +
            PQ_REKEY_WORK_BITMAP);
        if ((candidate == PQ_REKEY_WORK_BITMAP &&
             pq_rekey_bitmap_eligible(s, now_ms)) ||
            (candidate == PQ_REKEY_WORK_BASE &&
             rekey_flight_eligible(s, now_ms)) ||
            (candidate == PQ_REKEY_WORK_SHARE &&
             pq_rekey_share_eligible(s, now_ms))) {
            selected = candidate;
            break;
        }
    }
    if (selected == PQ_REKEY_WORK_BITMAP)
        rc = wire_encode_pq_bitmap(s, now_ms);
    else if (selected == PQ_REKEY_WORK_BASE) {
        rc = wire_encode_rekey_base(s, now_ms);
        if (rc == 0)
            s->pq_active_work = PQ_REKEY_WORK_BASE;
    } else if (selected == PQ_REKEY_WORK_SHARE) {
        rc = wire_encode_pq_share(s, now_ms);
    } else {
        return -1;
    }
    if (rc == 0)
        s->pq_work_cursor = (uint8_t)(
            selected == PQ_REKEY_WORK_SHARE
                ? PQ_REKEY_WORK_BITMAP : selected + 1U);
    return rc;
}

static void rekey_work_transport_result(session_t *s, int completed,
                                        int64_t now_ms)
{
    uint8_t work;

    if (!s)
        return;
    work = s->pq_active_work;
    s->pq_active_work = PQ_REKEY_WORK_NONE;
    if (work == PQ_REKEY_WORK_BASE) {
        rekey_flight_transport_result(s, completed, now_ms);
        return;
    }
    if (work == PQ_REKEY_WORK_BITMAP) {
        if (pq_rekey_rx_bitmap_complete(&s->pq_rekey_rx, now_ms) != 0) {
            fprintf(stderr,
                    "session: FATAL: pq-hybrid bitmap completion owner mismatch\n");
            s->run_failed = 1;
            s->wire_protocol_failure = 1;
        }
        maybe_complete_deferred_epoch_adoption(s, now_ms);
        return;
    }
    if (work == PQ_REKEY_WORK_SHARE) {
        session_pq_rekey_tx_t *tx = &s->pq_rekey_tx;
        uint32_t bit;

        if (!tx->active || !tx->inflight ||
            tx->inflight_index >= tx->count) {
            fprintf(stderr,
                    "session: FATAL: pq-hybrid share completion owner mismatch\n");
            s->run_failed = 1;
            s->wire_protocol_failure = 1;
            return;
        }
        bit = UINT32_C(1) << tx->inflight_index;
        if (completed) {
            tx->cycle_remaining &= ~bit;
            tx->cursor = (uint8_t)((tx->inflight_index + 1U) % tx->count);
            tx->next_send_ms = tx->cycle_remaining != 0U
                ? now_ms : now_ms + PQ_REKEY_RETRY_MS;
        } else {
            tx->next_send_ms = now_ms + PQ_REKEY_RETRY_MS;
        }
        tx->inflight = 0U;
        tx->inflight_index = 0U;
        maybe_complete_deferred_epoch_adoption(s, now_ms);
        return;
    }
    fprintf(stderr, "session: FATAL: missing pq-hybrid/epoch-rekey completion owner\n");
    s->run_failed = 1;
    s->wire_protocol_failure = 1;
}

static int send_rekey_message(session_t *s, uint8_t type, int pending_epoch,
                              int64_t now_ms)
{
    uint64_t ticket;
    int rc;

    if (!s)
        return -1;
    rc = rekey_flight_prepare(s, type, pending_epoch, now_ms);
    if (rc > 0)
        return 0;
    if (rc < 0) {
        fprintf(stderr,
                "session: FATAL: epoch-rekey reliable owner preparation failed\n");
        s->run_failed = 1;
        s->wire_protocol_failure = 1;
        return -1;
    }
    ticket = s->rekey_flight.ticket;
    if (!s->wire_in_run_loop && !s->wire_driving)
        session_send_scheduler_turn(s, now_ms);
    if (s->wire_failed_ticket == ticket)
        rc = -1;
    else
        rc = 0;
    if (s->wire_protocol_failure &&
        s->state != SESSION_IDLE && s->state != SESSION_CLOSING)
        session_close(s);
    return rc;
}

static int send_completed_rekey_message(session_t *s, uint8_t type)
{
    rekey_message_t message;
    uint8_t wire[REKEY_MESSAGE_LEN];
    int rc = -1;

    if (!s->completed_rekey_valid || s->epoch == 0 ||
        (type != CTRL_REKEY_COMMIT && type != CTRL_REKEY_ACK))
        return -1;
    memset(&message, 0, sizeof(message));
    message.type = type;
    message.from_epoch = s->epoch - 1U;
    message.to_epoch = s->epoch;
    memcpy(message.id, s->completed_rekey_id, sizeof(message.id));
    memcpy(message.first, s->epoch_transcript_digest,
           sizeof(message.first));
    memcpy(message.second, s->epoch_fingerprint,
           sizeof(message.second));
    if (rekey_message_encode(wire, &message) == 0) {
        rc = send_ctrl_epoch_tracked(
            s, s->pair_id, s->session_key, &s->tx_seq,
            type, wire, sizeof(wire), SESSION_TX_DONE_NONE,
            type, s->epoch,
            wire_mode_mask(wire_mode(s)));
    }
    crypto_memzero(&message, sizeof(message));
    crypto_memzero(wire, sizeof(wire));
    if (rc != 0 && s->run_failed)
        session_close(s);
    return rc;
}

static int active_rekey_base_matches(const session_t *s,
                                     const rekey_message_t *message)
{
    return message->from_epoch == s->epoch &&
           message->to_epoch == s->epoch + 1U &&
           memcmp(message->id, s->rekey_id, sizeof(s->rekey_id)) == 0;
}

static int rekey_confirmation_matches(const session_t *s,
                                      const rekey_message_t *message,
                                      int pending_metadata)
{
    uint8_t received[64];
    uint8_t expected[64];
    const uint8_t *transcript;
    const uint8_t *fingerprint;
    const uint8_t *id;
    uint32_t from_epoch;
    uint32_t to_epoch;

    if (pending_metadata) {
        if (!s->pending_epoch_valid)
            return 0;
        transcript = s->pending_transcript_digest;
        fingerprint = s->pending_epoch_fingerprint;
        id = s->rekey_id;
        from_epoch = s->epoch;
        to_epoch = s->epoch + 1U;
    } else {
        if (!s->completed_rekey_valid || s->epoch == 0)
            return 0;
        transcript = s->epoch_transcript_digest;
        fingerprint = s->epoch_fingerprint;
        id = s->completed_rekey_id;
        from_epoch = s->epoch - 1U;
        to_epoch = s->epoch;
    }
    if (message->from_epoch != from_epoch ||
        message->to_epoch != to_epoch ||
        memcmp(message->id, id, REKEY_ID_LEN) != 0)
        return 0;
    memcpy(received, message->first, 32U);
    memcpy(received + 32U, message->second, 32U);
    memcpy(expected, transcript, 32U);
    memcpy(expected + 32U, fingerprint, 32U);
    int matches = crypto_verify64(received, expected) == 0;
    crypto_memzero(received, sizeof(received));
    crypto_memzero(expected, sizeof(expected));
    return matches;
}

static void finish_epoch_barrier(session_t *s);
static void send_client_ack_and_maybe_resume(session_t *s, int64_t now_ms);

/* One completed public transcript remains live while the next rekey is in
 * progress. A fresh-SEQ duplicate from the preceding barrier must not abort
 * or replace the newer active state. It only reasserts the old response. */
static int handle_completed_rekey_duplicate(session_t *s, uint8_t type,
                                             const rekey_message_t *message,
                                             int pending_frame, int64_t now_ms)
{
    (void)now_ms;
    if (pending_frame ||
        !rekey_confirmation_matches(s, message, 0))
        return 0;

    if (type == CTRL_REKEY_CONFIRM && s->is_server) {
        (void)send_completed_rekey_message(s, CTRL_REKEY_COMMIT);
        return 1;
    }
    if (type == CTRL_REKEY_COMMIT && !s->is_server) {
        if (s->rekey_phase == REKEY_C_WAIT_ACK_SEND)
            send_client_ack_and_maybe_resume(s, now_ms);
        else
            (void)send_completed_rekey_message(s, CTRL_REKEY_ACK);
        return 1;
    }
    if (type == CTRL_REKEY_ACK && s->is_server) {
        if (s->rekey_phase == REKEY_S_WAIT_ACK)
            finish_epoch_barrier(s);
        return 1;
    }
    return 0;
}

static void rekey_fail(session_t *s, const char *reason)
{
    if (!s || s->state == SESSION_IDLE || s->state == SESSION_CLOSING)
        return;
    fprintf(stderr, "session: FATAL: epoch rekey %s — closing\n", reason);
    s->run_failed = 1;
    session_close(s);
}

static void pq_confirmation_fail(session_t *s)
{
    if (!s || s->state == SESSION_IDLE || s->state == SESSION_CLOSING)
        return;
    fprintf(stderr,
            "session: FATAL: PQ epoch confirmation failed — closing\n");
    s->run_failed = 1;
    /* The failed candidate has no terminal-error authority. Wipe it before
     * session_close enumerates valid epochs, so no packet is emitted under
     * material that the peer has just proved it does not share. */
    pending_epoch_clear(s);
    session_close(s);
}

static int random_nonzero_id(uint8_t id[REKEY_ID_LEN])
{
    for (unsigned int attempt = 0; attempt < 8U; attempt++) {
        if (crypto_random_bytes(id, REKEY_ID_LEN) != 0)
            break;
        if (!bytes_all_zero(id, REKEY_ID_LEN))
            return 0;
    }
    crypto_memzero(id, REKEY_ID_LEN);
    return -1;
}

static int derive_pending_epoch(session_t *s, epoch_crypto_role_t role)
{
    epoch_crypto_rekey_material_t material;
    int rc = epoch_crypto_rekey_derive(
        s->session_key, s->rekey_private, role, s->session_context,
        s->selected_caps, s->epoch, s->epoch + 1U, s->rekey_id,
        s->rekey_client_public, s->rekey_server_public, &material);
    crypto_memzero(s->rekey_private, sizeof(s->rekey_private));
    if (rc == 0)
        rc = install_pending_epoch(s, s->epoch + 1U, &material);
    crypto_memzero(&material, sizeof(material));
    return rc;
}

static unsigned int pq_rekey_role_budget(const session_t *s, int server)
{
    uint16_t stride;
    uint8_t count;

    if (!s || pq_rekey_geometry(PQ_REKEY_CONTROL_MTU, &stride, &count) != 0)
        return 0U;
    (void)stride;
    return (unsigned int)(2U * count + (server ? 2U : 3U));
}

static int pq_rekey_sequence_budget_available(const session_t *s,
                                              int server)
{
    unsigned int budget = pq_rekey_role_budget(s, server);

    return budget != 0U &&
           (uint64_t)s->tx_seq + (uint64_t)budget <= UINT32_MAX;
}

static void pq_rekey_tx_retire(session_t *s)
{
    if (!s || !s->pq_rekey_tx.active)
        return;
    s->pq_rekey_tx.retired = 1U;
    s->pq_rekey_tx.next_send_ms = 0;
}

static int derive_pending_epoch_pq(
    session_t *s, epoch_crypto_role_t role,
    const uint8_t mlkem_shared[PQ_MLKEM_SECRET_LEN],
    const uint8_t mlkem_public[PQ_MLKEM_PUBLIC_LEN],
    const uint8_t mlkem_ciphertext[PQ_MLKEM_CIPHERTEXT_LEN])
{
    epoch_crypto_rekey_material_t material;
    int rc;

    crypto_memzero(&material, sizeof(material));
    rc = pq_epoch_crypto_rekey_derive(
        s->session_key, s->rekey_private, role, s->session_context,
        s->transcript_hello, s->transcript_ack, s->selected_caps,
        s->epoch, s->epoch + 1U, s->rekey_id,
        s->rekey_client_public, s->rekey_server_public,
        mlkem_public, mlkem_ciphertext, mlkem_shared, &material);
    crypto_memzero(s->rekey_private, sizeof(s->rekey_private));
    if (rc == 0)
        rc = install_pending_epoch(s, s->epoch + 1U, &material);
    crypto_memzero(&material, sizeof(material));
    return rc;
}

static int pq_client_maybe_derive(session_t *s, int64_t now_ms)
{
    uint8_t shared[PQ_MLKEM_SECRET_LEN];
    int rc = -1;

    crypto_memzero(shared, sizeof(shared));
    if (!pq_rekey_selected(s) || s->is_server ||
        !s->pq_base_received || !s->pq_rekey_rx.complete ||
        s->pending_epoch_valid || !s->pq_rekey_tx.active ||
        s->pq_rekey_tx.kind != PQ_REKEY_KIND_INIT ||
        s->pq_rekey_rx.kind != PQ_REKEY_KIND_REPLY)
        return 0;
    if (pq_mlkem_decapsulate(shared, s->pq_rekey_rx.bytes,
                             s->pq_mlkem_private) != 0 ||
        derive_pending_epoch_pq(
            s, EPOCH_CRYPTO_ROLE_CLIENT, shared,
            s->pq_rekey_tx.bytes, s->pq_rekey_rx.bytes) != 0)
        goto out;
    crypto_memzero(s->pq_mlkem_private,
                   sizeof(s->pq_mlkem_private));
    s->pq_rx_bitmap_retired = 1U;
    s->rekey_phase = REKEY_C_WAIT_COMMIT;
    rc = send_rekey_message(s, CTRL_REKEY_CONFIRM, 0, now_ms);
out:
    crypto_memzero(shared, sizeof(shared));
    if (rc != 0)
        rekey_fail(s, "could not derive fresh client PQ epoch");
    return rc;
}

static int pq_server_maybe_derive(session_t *s, int64_t now_ms)
{
    uint8_t ciphertext[PQ_MLKEM_CIPHERTEXT_LEN];
    uint8_t shared[PQ_MLKEM_SECRET_LEN];
    int rc = -1;

    crypto_memzero(ciphertext, sizeof(ciphertext));
    crypto_memzero(shared, sizeof(shared));
    if (!pq_rekey_selected(s) || !s->is_server ||
        !s->pq_base_received || !s->pq_rekey_rx.complete ||
        s->pending_epoch_valid || s->pq_rekey_tx.active ||
        s->pq_rekey_rx.kind != PQ_REKEY_KIND_INIT)
        return 0;
    if (pq_mlkem_encapsulate(ciphertext, shared,
                             s->pq_rekey_rx.bytes) != 0 ||
        derive_pending_epoch_pq(
            s, EPOCH_CRYPTO_ROLE_SERVER, shared,
            s->pq_rekey_rx.bytes, ciphertext) != 0 ||
        pq_rekey_tx_arm(s, PQ_REKEY_KIND_REPLY, ciphertext, now_ms) != 0)
        goto out;
    s->pq_rx_bitmap_retired = 1U;
    s->rekey_phase = REKEY_S_WAIT_CONFIRM;
    rc = send_rekey_message(s, CTRL_REKEY_REPLY, 0, now_ms);
out:
    crypto_memzero(ciphertext, sizeof(ciphertext));
    crypto_memzero(shared, sizeof(shared));
    if (rc != 0)
        rekey_fail(s, "could not derive fresh server PQ epoch");
    return rc;
}

/* bulk-transfer pauses at the same zero-progress boundary send-scheduler already uses for
 * terminal close.  UDP WOULD_BLOCK has emitted no bytes, so an untouched
 * retained bulk frame can be cancelled, returned to logical eligibility,
 * and then frozen with the rest of the engine.  A charged physical copy is
 * allowed to reach its one terminal callback before the rekey starts. */
static int session_bulk_pause_for_epoch(session_t *s, int64_t now_ms)
{
    bulk_engine_observation_t observation;

    if (!s || !s->bulk_activated)
        return 0;
    memset(&observation, 0, sizeof(observation));
    if (bulk_engine_observe(s->bulk, &observation) != BULK_RC_OK)
        return -1;
    if (observation.paused)
        return 0;

    if (s->wire_active_slot == WIRE_ACTIVE_BULK) {
        if (s->wire_frame_len == 0U ||
            !s->wire_scheduler.in_flight ||
            s->wire_scheduler.in_flight_charged != 0 ||
            s->wire_path_success_mask != 0U)
            return 1;
        if (!s->transport->ops->send_cancel_untouched ||
            s->transport->ops->send_cancel_untouched(s->transport) != 0 ||
            send_scheduler_abandon_untouched(&s->wire_scheduler) != 0)
            return -1;
        (void)wire_release_active(s, 0, now_ms);
        wire_frame_reset(s);
        s->wire_chaos_applied = 0;
        wire_path_plan_clear(s);
    }
    if (s->wire_active_slot == WIRE_ACTIVE_BULK)
        return 1;
    return bulk_engine_epoch_pause(s->bulk, now_ms) == BULK_RC_OK ? 0 : -1;
}

static int start_client_rekey(session_t *s, int64_t now_ms)
{
    int bulk_pause;
    uint8_t mlkem_public[PQ_MLKEM_PUBLIC_LEN];

    crypto_memzero(mlkem_public, sizeof(mlkem_public));

    if (!s || s->is_server || !s->epoch_rekey_enabled ||
        s->epoch == UINT32_MAX || s->rekey_phase != REKEY_NONE)
        return -1;
    if (s->wire_message.valid && s->wire_message.started) {
        s->rekey_deferred = 1;
        fprintf(stderr,
                "session: epoch rekey deferred until authenticated message "
                "reaches a terminal boundary\n");
        return 0;
    }
    bulk_pause = session_bulk_pause_for_epoch(s, now_ms);
    if (bulk_pause > 0) {
        s->rekey_deferred = 1;
        fprintf(stderr,
                "session: epoch rekey deferred until bulk-transfer record reaches a terminal boundary\n");
        return 0;
    }
    if (bulk_pause < 0) {
        rekey_fail(s, "could not pause bulk-transfer at a zero-progress boundary");
        return -1;
    }
    pending_epoch_clear(s);
    if (pq_rekey_selected(s)) {
        pq_rekey_exchange_reset(s);
        pq_rekey_metrics_begin(s, now_ms);
    }
    if (pq_rekey_selected(s) &&
        !pq_rekey_sequence_budget_available(s, 0)) {
        rekey_fail(s, "lacks the pq-hybrid loss-free sequence reserve");
        return -1;
    }
    if (random_nonzero_id(s->rekey_id) != 0 ||
        epoch_crypto_keypair_generate(s->rekey_private,
                                      s->rekey_client_public) != 0) {
        rekey_fail(s, "could not generate fresh client key material");
        return -1;
    }
    if (pq_rekey_selected(s) &&
        (pq_mlkem_keypair(mlkem_public, s->pq_mlkem_private) != 0 ||
         pq_rekey_tx_arm(s, PQ_REKEY_KIND_INIT, mlkem_public,
                         now_ms) != 0)) {
        crypto_memzero(mlkem_public, sizeof(mlkem_public));
        rekey_fail(s, "could not generate fresh client PQ material");
        return -1;
    }
    crypto_memzero(mlkem_public, sizeof(mlkem_public));
    crypto_memzero(s->rekey_server_public,
                   sizeof(s->rekey_server_public));
    s->rekey_deferred = 0;
    s->rekey_request_pending = 0;
    s->rekey_adoption_deferred = 0;
    s->rekey_phase = REKEY_C_WAIT_REPLY;
    s->state = SESSION_REKEYING;
    fprintf(stderr, "session: epoch %u rekey started (client)\n", s->epoch);
    return send_rekey_message(s, CTRL_REKEY_INIT, 0, now_ms);
}

static int prepare_server_rekey(session_t *s,
                                const rekey_message_t *init,
                                int64_t now_ms)
{
    int bulk_pause;

    if (s->wire_message.valid && s->wire_message.started) {
        rekey_fail(s, "INIT collided with a started authenticated message");
        return -1;
    }
    if (init->from_epoch != s->epoch ||
        init->to_epoch != s->epoch + 1U || s->epoch == UINT32_MAX)
        return -1;
    bulk_pause = session_bulk_pause_for_epoch(s, now_ms);
    if (bulk_pause != 0) {
        rekey_fail(s, bulk_pause > 0
            ? "INIT collided with a progressing bulk-transfer record"
            : "could not pause bulk-transfer for received INIT");
        return -1;
    }
    if (s->rekey_phase == REKEY_S_WAIT_INIT)
        rekey_flight_semantic_retire(
            s, CTRL_REKEY_REQUEST, s->epoch);
    pending_epoch_clear(s);
    if (pq_rekey_selected(s))
        pq_rekey_metrics_begin(s, now_ms);
    if (pq_rekey_selected(s) &&
        !pq_rekey_sequence_budget_available(s, 1)) {
        rekey_fail(s, "lacks the pq-hybrid loss-free sequence reserve");
        return -1;
    }
    if (pq_rekey_selected(s) && s->pq_rekey_rx.active &&
        (s->pq_rekey_rx.kind != PQ_REKEY_KIND_INIT ||
         s->pq_rekey_rx.from_epoch != s->epoch ||
         memcmp(s->pq_rekey_rx.rekey_id, init->id,
                REKEY_ID_LEN) != 0)) {
        rekey_fail(s, "INIT conflicts with its pq-hybrid share");
        return -1;
    }
    if (sync_monitor_plan_barrier(s) != 0)
        return -1;
    memcpy(s->rekey_id, init->id, sizeof(s->rekey_id));
    memcpy(s->rekey_client_public, init->first,
           sizeof(s->rekey_client_public));
    if (epoch_crypto_keypair_generate(s->rekey_private,
                                      s->rekey_server_public) != 0 ||
        (!pq_rekey_selected(s) &&
         derive_pending_epoch(s, EPOCH_CRYPTO_ROLE_SERVER) != 0)) {
        rekey_fail(s, "could not derive fresh server epoch");
        return -1;
    }
    s->rekey_request_pending = 0;
    s->rekey_deferred = 0;
    s->rekey_adoption_deferred = 0;
    s->rekey_phase = REKEY_S_WAIT_CONFIRM;
    s->state = SESSION_REKEYING;
    s->pq_base_received = pq_rekey_selected(s) ? 1U : 0U;
    fprintf(stderr, "session: epoch %u rekey accepted (server)\n", s->epoch);
    if (pq_rekey_selected(s))
        return pq_server_maybe_derive(s, now_ms);
    return send_rekey_message(s, CTRL_REKEY_REPLY, 0, now_ms);
}

static void handle_pq_share(session_t *s,
                            const uint8_t descriptor_wire[
                                PQ_REKEY_SHARE_DESCRIPTOR_LEN],
                            const uint8_t *payload, size_t payload_len,
                            int pending_frame, int64_t now_ms)
{
    pq_rekey_share_descriptor_t descriptor;
    uint8_t expected_kind;
    int rc;

    memset(&descriptor, 0, sizeof(descriptor));
    if (!pq_rekey_selected(s)) {
        fprintf(stderr,
                "session: authenticated unselected pq-hybrid SHARE control\n");
        session_protocol_error_close(s, ERR_CAPS);
        return;
    }
    expected_kind = s->is_server ? PQ_REKEY_KIND_INIT
                                 : PQ_REKEY_KIND_REPLY;
    if (pending_frame || !descriptor_wire || !payload ||
        pq_rekey_share_descriptor_decode(
            descriptor_wire, PQ_REKEY_SHARE_DESCRIPTOR_LEN,
            PQ_REKEY_CONTROL_MTU, &descriptor) != 0 ||
        descriptor.kind != expected_kind) {
        rekey_fail(s, "invalid pq-hybrid SHARE grammar, role or epoch");
        return;
    }
    if (s->completed_rekey_valid &&
        s->epoch != 0U && descriptor.from_epoch == s->epoch - 1U &&
        memcmp(descriptor.rekey_id, s->completed_rekey_id,
               REKEY_ID_LEN) == 0) {
        crypto_memzero(&descriptor, sizeof(descriptor));
        return;
    }
    if (descriptor.from_epoch != s->epoch) {
        rekey_fail(s, "invalid pq-hybrid SHARE grammar, role or epoch");
        crypto_memzero(&descriptor, sizeof(descriptor));
        return;
    }
    if (s->state == SESSION_KEY_DERIVING) {
        /* The peer may complete READY first and begin the mandatory bootstrap
         * rekey while our READY acknowledgement is still in flight.  The
         * base INIT is deliberately deferred at this barrier; its associated
         * immutable SHARE must follow the same rule.  Consume this
         * authenticated copy and rely on the sender's absolute retry state. */
        fprintf(stderr, "session: early pq-hybrid SHARE deferred until READY\n");
        crypto_memzero(&descriptor, sizeof(descriptor));
        return;
    }
    if ((s->is_server &&
         !((s->state == SESSION_ESTABLISHED &&
            s->rekey_phase == REKEY_NONE) ||
           (s->state == SESSION_REKEYING &&
            (s->rekey_phase == REKEY_S_WAIT_INIT ||
             s->rekey_phase == REKEY_S_WAIT_CONFIRM)))) ||
        (!s->is_server &&
         !(s->state == SESSION_REKEYING &&
           (s->rekey_phase == REKEY_C_WAIT_REPLY ||
            s->rekey_phase == REKEY_C_WAIT_COMMIT)))) {
        rekey_fail(s, "pq-hybrid SHARE arrived in an invalid phase");
        crypto_memzero(&descriptor, sizeof(descriptor));
        return;
    }
    rc = pq_rekey_rx_accept(&s->pq_rekey_rx, &descriptor,
                            payload, payload_len, PQ_REKEY_CONTROL_MTU, now_ms);
    if (rc == PQ_REKEY_RX_BUSY) {
        fprintf(stderr,
                "session: unrelated pq-hybrid SHARE rejected while busy\n");
        (void)send_ctrl_error(s, ERR_SESSION);
    } else if (rc == PQ_REKEY_RX_INVALID) {
        rekey_fail(s, "conflicting pq-hybrid SHARE geometry or payload");
    } else if (s->pq_rekey_rx.complete) {
        if (s->is_server)
            (void)pq_server_maybe_derive(s, now_ms);
        else
            (void)pq_client_maybe_derive(s, now_ms);
    }
    if (!s->wire_in_run_loop && !s->wire_driving &&
        rekey_work_eligible(s, now_ms))
        session_send_scheduler_turn(s, now_ms);
    crypto_memzero(&descriptor, sizeof(descriptor));
}

static void handle_pq_bitmap(session_t *s, const uint8_t *plaintext,
                             size_t plaintext_len, int pending_frame,
                             int64_t now_ms)
{
    session_pq_rekey_tx_t *tx;
    pq_rekey_bitmap_t bitmap;
    uint32_t full;

    memset(&bitmap, 0, sizeof(bitmap));
    if (!pq_rekey_selected(s)) {
        fprintf(stderr,
                "session: authenticated unselected pq-hybrid BITMAP control\n");
        session_protocol_error_close(s, ERR_CAPS);
        return;
    }
    if (pending_frame ||
        pq_rekey_bitmap_decode(plaintext, plaintext_len, &bitmap) != 0) {
        rekey_fail(s, "invalid pq-hybrid BITMAP grammar or epoch");
        return;
    }
    if (s->completed_rekey_valid && s->epoch != 0U &&
        bitmap.from_epoch == s->epoch - 1U &&
        memcmp(bitmap.rekey_id, s->completed_rekey_id,
               REKEY_ID_LEN) == 0) {
        crypto_memzero(&bitmap, sizeof(bitmap));
        return;
    }
    if (bitmap.from_epoch != s->epoch) {
        rekey_fail(s, "invalid pq-hybrid BITMAP grammar or epoch");
        crypto_memzero(&bitmap, sizeof(bitmap));
        return;
    }
    tx = &s->pq_rekey_tx;
    if (!tx->active) {
        (void)send_ctrl_error(s, ERR_SESSION);
        crypto_memzero(&bitmap, sizeof(bitmap));
        return;
    }
    if (memcmp(bitmap.rekey_id, tx->rekey_id, REKEY_ID_LEN) != 0) {
        fprintf(stderr,
                "session: unrelated pq-hybrid BITMAP rejected while busy\n");
        (void)send_ctrl_error(s, ERR_SESSION);
        crypto_memzero(&bitmap, sizeof(bitmap));
        return;
    }
    if (bitmap.kind != tx->kind || bitmap.count != tx->count ||
        bitmap.from_epoch != tx->from_epoch) {
        rekey_fail(s, "conflicting pq-hybrid BITMAP identity or geometry");
        crypto_memzero(&bitmap, sizeof(bitmap));
        return;
    }
    full = pq_rekey_full_bitmap(tx->count);
    if (bitmap.received_bitmap == 0U ||
        (bitmap.received_bitmap | tx->peer_bitmap) ==
            bitmap.received_bitmap) {
        tx->peer_bitmap = bitmap.received_bitmap;
        tx->cycle_remaining = full & ~tx->peer_bitmap;
        tx->next_send_ms = now_ms;
        if (tx->peer_bitmap == full)
            tx->retired = 1U;
    }
    if (!s->wire_in_run_loop && !s->wire_driving &&
        rekey_work_eligible(s, now_ms))
        session_send_scheduler_turn(s, now_ms);
    crypto_memzero(&bitmap, sizeof(bitmap));
}

static void finish_epoch_barrier(session_t *s)
{
    uint32_t completed = s->epoch;
    int64_t now_ms;
    if (s->is_server && s->rekey_phase == REKEY_S_WAIT_ACK)
        rekey_flight_semantic_retire(s, CTRL_REKEY_COMMIT, s->epoch);
    else if (!s->is_server &&
             s->rekey_phase == REKEY_C_WAIT_ACK_SEND)
        rekey_flight_semantic_retire(s, CTRL_REKEY_ACK, s->epoch);
    s->rekey_phase = REKEY_NONE;
    s->rekey_request_pending = 0;
    s->rekey_deferred = 0;
    s->rekey_adoption_deferred = 0;
    if (!s->rekey_flight.valid)
        s->rekey_next_send_ms = 0;
    crypto_memzero(s->rekey_private, sizeof(s->rekey_private));
    if (session_activate_services(s) != 0)
        return;
    now_ms = mono_ms();
    if (s->bulk_activated) {
        bulk_engine_observation_t observation;

        memset(&observation, 0, sizeof(observation));
        if (bulk_engine_observe(s->bulk, &observation) != BULK_RC_OK) {
            rekey_fail(s, "could not observe bulk-transfer at epoch resume");
            return;
        }
        if (observation.paused &&
            bulk_engine_epoch_resume(s->bulk, now_ms) != BULK_RC_OK) {
            rekey_fail(s, "could not resume bulk-transfer after epoch confirmation");
            return;
        }
    }
    fprintf(stderr, "session: epoch %u confirmation complete\n", completed);
}

/* A bootstrap barrier is semantic state, while the scheduler owns physical
 * completion of one immutable frame.  When the former overtakes a retained
 * COMMIT, finish_epoch_barrier() has already retired the barrier state but
 * activation must not reset the latter's owner.  Resume exactly once at the
 * first terminal wire boundary. */
static void maybe_finish_deferred_bulk_activation(session_t *s)
{
    if (!s || !s->bulk_activation_deferred ||
        s->wire_frame_len != 0U)
        return;
    s->bulk_activation_deferred = 0;
    if (s->state == SESSION_REKEYING &&
        s->rekey_phase == REKEY_NONE)
        finish_epoch_barrier(s);
    else
        (void)session_activate_services(s);
}

static void send_client_ack_and_maybe_resume(session_t *s, int64_t now_ms)
{
    (void)send_rekey_message(s, CTRL_REKEY_ACK, 0, now_ms);
}

static void maybe_complete_deferred_epoch_adoption(session_t *s,
                                                   int64_t now_ms)
{
    rekey_phase_t phase;
    int rc;

    if (!s || !s->rekey_adoption_deferred || s->wire_delivery.valid ||
        (s->rekey_flight.valid && s->rekey_flight.retry.inflight) ||
        s->pq_active_work != PQ_REKEY_WORK_NONE ||
        s->pq_rekey_tx.inflight || s->pq_rekey_rx.bitmap_inflight ||
        s->wire_protocol_failure || s->state != SESSION_REKEYING)
        return;
    phase = s->rekey_phase;
    if (phase != REKEY_S_WAIT_CONFIRM && phase != REKEY_C_WAIT_COMMIT) {
        rekey_fail(s, "deferred adoption lost its exact phase");
        return;
    }
    rc = adopt_pending_epoch(s);
    if (rc != 0) {
        rekey_fail(s, "deferred pending adoption failed");
        return;
    }
    s->rekey_adoption_deferred = 0;
    if (phase == REKEY_S_WAIT_CONFIRM) {
        s->rekey_phase = REKEY_S_WAIT_ACK;
        (void)send_rekey_message(s, CTRL_REKEY_COMMIT, 0, now_ms);
    } else {
        s->rekey_phase = REKEY_C_WAIT_ACK_SEND;
        send_client_ack_and_maybe_resume(s, now_ms);
    }
}

static void wire_notify_result(session_t *s, session_tx_done_t done,
                               int completed, int64_t now_ms,
                               uint64_t arg0, uint64_t arg1,
                               uint32_t stream_handle,
                               uint64_t operation_generation,
                               const multipath_handle_t *path_target)
{
    if (!s)
        return;
    switch (done) {
    case SESSION_TX_DONE_NONE:
        break;

    case SESSION_TX_DONE_HELLO:
        if (!completed) {
            fprintf(stderr, "session: CTRL_HELLO transport failure\n");
            s->run_failed = 1;
            s->wire_protocol_failure = 1;
            break;
        }
        if (s->state == SESSION_CONNECTING && s->hello_tx_count < 5) {
            s->hello_tx_count++;
            s->hello_next_send_ms = now_ms + s->hello_backoff_ms;
            s->hello_backoff_ms *= 2;
            fprintf(stderr, "session: CTRL_HELLO attempt %d/5\n",
                    s->hello_tx_count);
        }
        break;

    case SESSION_TX_DONE_HELLO_ACK:
        if (!completed) {
            fprintf(stderr, "session: CTRL_HELLO_ACK transport failure\n");
            s->run_failed = 1;
            s->wire_protocol_failure = 1;
        } else if (s->state == SESSION_KEY_DERIVING && !s->sent_ready &&
                   s->ready_next_send_ms == 0) {
            /* HELLO_ACK transport completion is the exact ordering
             * boundary.  READY is due on the next scheduler turn; NEG1's
             * repeated state heals simultaneous first-READY loss. */
            s->ready_next_send_ms = now_ms;
        }
        break;

    case SESSION_TX_DONE_READY_INITIAL:
        if (!completed) {
            fprintf(stderr, "session: initial CTRL_READY transport failure\n");
            s->run_failed = 1;
            s->wire_protocol_failure = 1;
            break;
        }
        if (s->state == SESSION_KEY_DERIVING && !s->sent_ready) {
            s->sent_ready = 1;
            if (s->negotiation_neg1) {
                s->ready_tx_count = 1;
                s->ready_next_send_ms = now_ms + READY_RETRY_MS;
            } else {
                s->ready_next_send_ms = 0;
            }
            if (s->ready_ack_pending) {
                s->ready_ack_pending = 0;
                if (send_ready_frame(s, 0,
                                     SESSION_TX_DONE_READY_ACK) != 0) {
                    fprintf(stderr,
                            "session: deferred CTRL_READY acknowledgement failed\n");
                    s->run_failed = 1;
                    s->wire_protocol_failure = 1;
                    break;
                }
            }
            establish_session(s);
        }
        fprintf(stderr,
                "session: sent CTRL_READY flags=0x%02X caps=0x%08X\n",
                (unsigned int)(uint8_t)arg0, (uint32_t)arg1);
        break;

    case SESSION_TX_DONE_READY_RETRY:
        if (!completed) {
            fprintf(stderr, "session: CTRL_READY retransmit failed\n");
            s->run_failed = 1;
            s->wire_protocol_failure = 1;
            break;
        }
        if (s->state == SESSION_KEY_DERIVING && s->negotiation_neg1) {
            s->ready_tx_count++;
            s->ready_next_send_ms = now_ms + READY_RETRY_MS;
            fprintf(stderr, "session: CTRL_READY NEED_ACK attempt %d\n",
                    s->ready_tx_count);
        }
        fprintf(stderr,
                "session: sent CTRL_READY flags=0x%02X caps=0x%08X\n",
                (unsigned int)(uint8_t)arg0, (uint32_t)arg1);
        break;

    case SESSION_TX_DONE_READY_ACK:
        if (!completed) {
            fprintf(stderr, "session: CTRL_READY acknowledgement failed\n");
            break;
        }
        fprintf(stderr,
                "session: sent CTRL_READY flags=0x%02X caps=0x%08X\n",
                (unsigned int)(uint8_t)arg0, (uint32_t)arg1);
        break;

    case SESSION_TX_DONE_PTY_OPEN:
        if (!s->pty_open_ack_seen && !s->pty_open_err_seen &&
            s->state == SESSION_ESTABLISHED) {
            if (s->pty_open_backoff_ms == 0)
                s->pty_open_backoff_ms = 1000;
            s->pty_open_tx_count++;
            s->pty_open_next_send_ms =
                now_ms + s->pty_open_backoff_ms;
            s->pty_open_backoff_ms *= 2;
            if (!completed)
                fprintf(stderr,
                        "session: PTY_OPEN transport attempt failed\n");
        }
        break;

    case SESSION_TX_DONE_STATUS_PERIODIC:
        sync_status_heartbeat_sent(&s->sync_status, now_ms);
        break;

    case SESSION_TX_DONE_REKEY_RETRY:
        /* Retained only for white-box compatibility. Product epoch-rekey flights
         * are the dedicated logical producer and never enter intent slots. */
        break;

    case SESSION_TX_DONE_REKEY_FINAL_ACK:
        if (s->state == SESSION_REKEYING &&
            s->rekey_phase == REKEY_C_WAIT_ACK_SEND &&
            (uint32_t)arg1 == s->epoch) {
            if (completed)
                finish_epoch_barrier(s);
        }
        break;

    case SESSION_TX_DONE_SYNC_ACK:
    case SESSION_TX_DONE_SYNC_NEW:
    case SESSION_TX_DONE_SYNC_REPAIR:
    case SESSION_TX_DONE_SYNC_PROBE:
    case SESSION_TX_DONE_SYNC_FIN: {
        uint8_t slot = 1U;
        uint32_t generation = 0U;
        const sync_instance_binding_t *binding;

        if (stream_handle == 0U) {
            sync_send_result(s, (int)done, completed, now_ms, arg0, arg1);
            break;
        }
        if (channel_session_handle_decode(stream_handle, &slot,
                                          &generation) != 0 ||
            operation_generation == 0U) {
            fprintf(stderr,
                    "session: FATAL: malformed channel-session stream completion owner\n");
            s->run_failed = 1;
            s->wire_protocol_failure = 1;
            break;
        }
        binding = &s->sync_binding[slot];
        if (!binding->configured || binding->handle != stream_handle) {
            const channel_session_slot_t *entry =
                &s->channel_table.slots[slot];

            /* A semantically retired owner may finish after the instance
             * has quiesced. It releases wire state only and cannot address a
             * later generation. Any still-current mismatch is structural. */
            if (entry->handle != stream_handle ||
                entry->state == CHANNEL_SLOT_FREE ||
                entry->state == CHANNEL_SLOT_RETIRED)
                break;
            fprintf(stderr,
                    "session: FATAL: channel-session stream completion owner mismatch\n");
            s->run_failed = 1;
            s->wire_protocol_failure = 1;
            break;
        }
        if (sync_send_result_owned_instance(
                s, slot, (int)done, completed, now_ms, arg0, arg1,
                operation_generation) != 0) {
            fprintf(stderr,
                    "session: FATAL: channel-session stream operation owner mismatch\n");
            s->run_failed = 1;
            s->wire_protocol_failure = 1;
        }
        break;
    }

    case SESSION_TX_DONE_LEGACY_EOF:
        if (!completed) {
            fprintf(stderr,
                    "session: legacy PTY_EOF transport attempt failed\n");
            s->run_failed = 1;
        }
        if (s->state == SESSION_ESTABLISHED)
            session_close(s);
        break;

    case SESSION_TX_DONE_ABORT: {
        uint8_t bit = wire_abort_epoch_bit((session_tx_epoch_t)arg0);
        if (!completed)
            fprintf(stderr,
                    "session: terminal control transport attempt failed\n");
        s->terminal_abort_attempted_mask |= bit;
        if (s->state == SESSION_CLOSING)
            s->close_tx_count = (int)wire_mask_count(
                (uint8_t)(s->terminal_abort_attempted_mask &
                          s->close_epoch_mask));
        break;
    }

    case SESSION_TX_DONE_PATH_CHALLENGE: {
        int rc = multipath_challenge_attempted(
            &s->multipath, path_target, arg0, now_ms, completed);
        if (arg1 > 1U || rc == MULTIPATH_ERROR) {
            fprintf(stderr,
                    "session: FATAL: multipath challenge completion owner mismatch\n");
            s->run_failed = 1;
            s->wire_protocol_failure = 1;
        } else if (rc == MULTIPATH_ACCEPTED && path_target != NULL &&
                   session_refresh_path_legs(s, now_ms) == 0 &&
                   path_target->index < s->path_leg_count) {
            if (completed) {
                (void)path_leg_challenge_attempt(
                    &s->path_leg[path_target->index],
                    path_target->generation, arg0, now_ms, 1);
                if (arg1 == 1U)
                    (void)path_leg_keepalive_complete(
                        &s->path_leg[path_target->index],
                        path_target->generation, now_ms,
                        MULTIPATH_VALIDATED_KEEPALIVE_MS);
            }
        }
        break;
    }

    case SESSION_TX_DONE_PATH_RESPONSE:
        {
            int rc = multipath_response_attempted(
                &s->multipath, path_target, arg0, now_ms, completed);
            if (rc == MULTIPATH_ERROR) {
                fprintf(stderr,
                        "session: FATAL: multipath response completion owner mismatch\n");
                s->run_failed = 1;
                s->wire_protocol_failure = 1;
            }
        }
        break;

    case SESSION_TX_DONE_CHANNEL_CONTROL:
        channel_control_complete(s, (uint8_t)arg0, (uint32_t)arg1,
                                 completed, now_ms);
        break;
    }
}

static void handle_rekey_control(session_t *s, uint8_t type,
                                 const uint8_t *plaintext, size_t pt_len,
                                 int pending_frame)
{
    rekey_message_t message;
    int64_t now = mono_ms();

    if ((s->selected_caps & UNMOOR_CAP_EPOCH_REKEY_D28_V1) == 0) {
        fprintf(stderr, "session: authenticated unselected epoch-rekey control\n");
        fprintf(stderr,
                "session: FATAL: epoch rekey control used without negotiated capability — closing\n");
        session_protocol_error_close(s, ERR_CAPS);
        return;
    }
    if (rekey_message_decode(plaintext, pt_len, type, &message) != 0) {
        rekey_fail(s, "message grammar or redundant type mismatch");
        return;
    }
    if (s->state == SESSION_KEY_DERIVING) {
        /* A fresh-SEQ retry will arrive after the explicit READY barrier.
         * Do not turn packet reordering into an implicit READY rule. */
        fprintf(stderr, "session: early epoch control deferred until READY\n");
        crypto_memzero(&message, sizeof(message));
        return;
    }
    if (handle_completed_rekey_duplicate(s, type, &message,
                                         pending_frame, now)) {
        crypto_memzero(&message, sizeof(message));
        return;
    }

    switch (type) {
    case CTRL_REKEY_REQUEST:
        if (pending_frame || s->is_server ||
            message.from_epoch != s->epoch ||
            message.to_epoch != s->epoch + 1U) {
            rekey_fail(s, "invalid REQUEST role or epoch");
        } else if (s->rekey_phase == REKEY_NONE &&
                   s->state == SESSION_ESTABLISHED) {
            (void)start_client_rekey(s, now);
        } else if (s->rekey_phase == REKEY_C_WAIT_REPLY) {
            (void)send_rekey_message(s, CTRL_REKEY_INIT, 0, now);
        }
        break;

    case CTRL_REKEY_INIT:
        if (pending_frame || !s->is_server) {
            rekey_fail(s, "invalid INIT role or epoch");
        } else if (s->rekey_phase == REKEY_S_WAIT_ACK &&
                   message.from_epoch == s->epoch &&
                   message.to_epoch == s->epoch + 1U) {
            /* A new-epoch INIT proves the client adopted and successfully
             * emitted after its ACK. Complete the preceding barrier, then
             * accept this back-to-back client-led rekey without requiring an
             * unrelated application frame in between. */
            finish_epoch_barrier(s);
            if (s->state == SESSION_ESTABLISHED &&
                prepare_server_rekey(s, &message, now) != 0 &&
                s->state != SESSION_CLOSING)
                rekey_fail(s, "back-to-back INIT epoch mismatch");
        } else if (s->rekey_phase == REKEY_S_WAIT_INIT ||
                   (s->rekey_phase == REKEY_NONE &&
                    s->state == SESSION_ESTABLISHED)) {
            if (prepare_server_rekey(s, &message, now) != 0 &&
                s->state != SESSION_CLOSING)
                rekey_fail(s, "INIT epoch mismatch");
        } else if (s->rekey_phase == REKEY_S_WAIT_CONFIRM) {
            if (!active_rekey_base_matches(s, &message) ||
                crypto_verify32(message.first,
                                s->rekey_client_public) != 0) {
                rekey_fail(s, "conflicting duplicate INIT");
            } else if (pq_rekey_selected(s) &&
                       !s->pending_epoch_valid) {
                (void)pq_server_maybe_derive(s, now);
            } else {
                (void)send_rekey_message(s, CTRL_REKEY_REPLY, 0, now);
            }
        } else {
            fprintf(stderr, "session: unrelated INIT rejected while busy\n");
            (void)send_ctrl_error(s, ERR_SESSION);
        }
        break;

    case CTRL_REKEY_REPLY:
        if (pending_frame || s->is_server ||
            (s->rekey_phase != REKEY_C_WAIT_REPLY &&
             s->rekey_phase != REKEY_C_WAIT_COMMIT)) {
            rekey_fail(s, "invalid REPLY role or phase");
        } else if (!active_rekey_base_matches(s, &message)) {
            rekey_fail(s, "conflicting REPLY identity");
        } else if (s->rekey_phase == REKEY_C_WAIT_REPLY) {
            rekey_flight_semantic_retire(
                s, CTRL_REKEY_INIT, s->epoch);
            memcpy(s->rekey_server_public, message.first,
                   sizeof(s->rekey_server_public));
            if (pq_rekey_selected(s)) {
                s->pq_base_received = 1U;
                pq_rekey_tx_retire(s);
                (void)pq_client_maybe_derive(s, now);
            } else if (derive_pending_epoch(
                           s, EPOCH_CRYPTO_ROLE_CLIENT) != 0) {
                rekey_fail(s, "could not derive fresh client epoch");
                break;
            } else {
                s->rekey_phase = REKEY_C_WAIT_COMMIT;
                (void)send_rekey_message(
                    s, CTRL_REKEY_CONFIRM, 1, now);
            }
        } else if (crypto_verify32(message.first,
                                   s->rekey_server_public) != 0) {
            rekey_fail(s, "conflicting duplicate REPLY");
        } else {
            (void)send_rekey_message(
                s, CTRL_REKEY_CONFIRM,
                pq_rekey_selected(s) ? 0 : 1, now);
        }
        break;

    case CTRL_REKEY_CONFIRM:
        if (!s->is_server ||
            (s->rekey_phase != REKEY_S_WAIT_CONFIRM &&
             s->rekey_phase != REKEY_S_WAIT_ACK)) {
            rekey_fail(s, "invalid CONFIRM role or phase");
        } else if (s->rekey_phase == REKEY_S_WAIT_CONFIRM) {
            if ((pq_rekey_selected(s) ? pending_frame : !pending_frame) ||
                !rekey_confirmation_matches(s, &message, 1)) {
                if (pq_rekey_selected(s))
                    pq_confirmation_fail(s);
                else
                    rekey_fail(s, "CONFIRM fingerprint mismatch");
                break;
            }
            rekey_flight_semantic_retire(
                s, CTRL_REKEY_REPLY, s->epoch);
            if (pq_rekey_selected(s))
                pq_rekey_tx_retire(s);
            {
                int adopt_rc = adopt_pending_epoch(s);
                if (adopt_rc > 0) {
                    s->rekey_adoption_deferred = 1;
                    break;
                }
                if (adopt_rc < 0) {
                    rekey_fail(s, "pending server adoption failed");
                    break;
                }
            }
            s->rekey_phase = REKEY_S_WAIT_ACK;
            (void)send_rekey_message(s, CTRL_REKEY_COMMIT, 0, now);
        } else if (pending_frame ||
                   !rekey_confirmation_matches(s, &message, 0)) {
            rekey_fail(s, "duplicate CONFIRM mismatch");
        } else {
            (void)send_rekey_message(s, CTRL_REKEY_COMMIT, 0, now);
        }
        break;

    case CTRL_REKEY_COMMIT:
        if (s->is_server) {
            rekey_fail(s, "invalid COMMIT role");
        } else if (s->rekey_phase == REKEY_C_WAIT_COMMIT) {
            if (!pending_frame ||
                !rekey_confirmation_matches(s, &message, 1)) {
                if (pq_rekey_selected(s))
                    pq_confirmation_fail(s);
                else
                    rekey_fail(s, "COMMIT fingerprint mismatch");
                break;
            }
            rekey_flight_semantic_retire(
                s, CTRL_REKEY_CONFIRM, s->epoch);
            {
                int adopt_rc = adopt_pending_epoch(s);
                if (adopt_rc > 0) {
                    s->rekey_adoption_deferred = 1;
                    break;
                }
                if (adopt_rc < 0) {
                    rekey_fail(s, "pending client adoption failed");
                    break;
                }
            }
            s->rekey_phase = REKEY_C_WAIT_ACK_SEND;
            send_client_ack_and_maybe_resume(s, now);
        } else if ((s->rekey_phase == REKEY_C_WAIT_ACK_SEND ||
                    (s->rekey_phase == REKEY_NONE &&
                     s->state == SESSION_ESTABLISHED)) &&
                   !pending_frame &&
                   rekey_confirmation_matches(s, &message, 0)) {
            if (s->rekey_phase == REKEY_C_WAIT_ACK_SEND)
                send_client_ack_and_maybe_resume(s, now);
            else
                (void)send_rekey_message(s, CTRL_REKEY_ACK, 0, now);
        } else {
            rekey_fail(s, "unexpected or conflicting COMMIT");
        }
        break;

    case CTRL_REKEY_ACK:
        if (!s->is_server || pending_frame ||
            !rekey_confirmation_matches(s, &message, 0)) {
            rekey_fail(s, "ACK fingerprint or role mismatch");
        } else if (s->rekey_phase == REKEY_S_WAIT_ACK) {
            finish_epoch_barrier(s);
        } else if (!(s->rekey_phase == REKEY_NONE &&
                     s->state == SESSION_ESTABLISHED)) {
            rekey_fail(s, "ACK in invalid phase");
        }
        break;

    default:
        rekey_fail(s, "unknown control type");
        break;
    }
    crypto_memzero(&message, sizeof(message));
}

void session_epoch_rekey_tick(session_t *s, int64_t now_ms)
{
    if (!s || !s->epoch_rekey_enabled)
        return;

    if (pq_rekey_selected(s) && s->pq_rekey_rx.active &&
        pq_rekey_rx_expire(&s->pq_rekey_rx, now_ms) < 0) {
        rekey_fail(s, "could not advance the pq-hybrid assembly deadline");
        return;
    }

    if (s->rekey_request_pending && s->state == SESSION_ESTABLISHED &&
        now_ms >= s->rekey_next_send_ms) {
        (void)send_rekey_message(s, CTRL_REKEY_REQUEST, 0, now_ms);
        return;
    }
    if (s->state != SESSION_REKEYING || s->rekey_phase == REKEY_NONE)
        return;

    /* A base flight is armed by this phase timer; once armed, its own retry
     * owner controls eligibility.  Testing rekey_flight_eligible() here would
     * make the first flight impossible because no owner exists yet.  PQ
     * server REPLY is the sole deferred base: its share must first produce
     * pending epoch material. */
    if (now_ms >= s->rekey_next_send_ms) {
        switch (s->rekey_phase) {
        case REKEY_C_WAIT_REPLY:
            (void)send_rekey_message(s, CTRL_REKEY_INIT, 0, now_ms);
            break;
        case REKEY_C_WAIT_COMMIT:
            (void)send_rekey_message(
                s, CTRL_REKEY_CONFIRM,
                pq_rekey_selected(s) ? 0 : 1, now_ms);
            break;
        case REKEY_C_WAIT_ACK_SEND:
            send_client_ack_and_maybe_resume(s, now_ms);
            break;
        case REKEY_S_WAIT_CONFIRM:
            if (!pq_rekey_selected(s) || s->pending_epoch_valid)
                (void)send_rekey_message(s, CTRL_REKEY_REPLY, 0, now_ms);
            break;
        case REKEY_S_WAIT_ACK:
            (void)send_rekey_message(s, CTRL_REKEY_COMMIT, 0, now_ms);
            break;
        case REKEY_S_WAIT_INIT:
        case REKEY_NONE:
            break;
        }
    }
    if (!s->wire_in_run_loop && !s->wire_driving &&
        rekey_work_eligible(s, now_ms))
        session_send_scheduler_turn(s, now_ms);
}

static int session_request_epoch_rekey_at(session_t *s, int64_t now)
{
    int bulk_pause;

    if (!s || !s->epoch_rekey_enabled || !s->services_started ||
        s->state != SESSION_ESTABLISHED || s->rekey_phase != REKEY_NONE)
        return -1;
    if (s->epoch == UINT32_MAX) {
        fprintf(stderr, "session: epoch counter exhausted — closing\n");
        s->run_failed = 1;
        session_close(s);
        return -1;
    }
    if (s->wire_message.valid && s->wire_message.started) {
        s->rekey_deferred = 1;
        fprintf(stderr,
                "session: local epoch rekey deferred until authenticated "
                "message reaches a terminal boundary\n");
        return 0;
    }
    bulk_pause = session_bulk_pause_for_epoch(s, now);
    if (bulk_pause > 0) {
        s->rekey_deferred = 1;
        fprintf(stderr,
                "session: local epoch rekey deferred until bulk-transfer record reaches a terminal boundary\n");
        return 0;
    }
    if (bulk_pause < 0) {
        rekey_fail(s, "could not pause bulk-transfer for local epoch transition");
        return -1;
    }
    if (!s->is_server)
        return start_client_rekey(s, now);

    if (sync_monitor_plan_barrier(s) != 0)
        return -1;
    s->rekey_request_pending = 1;
    s->rekey_phase = REKEY_S_WAIT_INIT;
    return send_rekey_message(s, CTRL_REKEY_REQUEST, 0, now);
}

int session_request_epoch_rekey(session_t *s)
{
    return session_request_epoch_rekey_at(s, mono_ms());
}

static void maybe_start_deferred_rekey(session_t *s, int64_t now_ms)
{
    if (!s || !s->rekey_deferred ||
        (s->wire_message.valid && s->wire_message.started) ||
        s->wire_active_slot == WIRE_ACTIVE_BULK)
        return;
    if (s->state != SESSION_ESTABLISHED ||
        s->rekey_phase != REKEY_NONE) {
        if (s->state == SESSION_IDLE || s->state == SESSION_CLOSING)
            s->rekey_deferred = 0;
        return;
    }
    s->rekey_deferred = 0;
    if (session_request_epoch_rekey_at(s, now_ms) != 0 &&
        s->state != SESSION_CLOSING) {
        rekey_fail(s, "could not start deferred epoch transition");
    }
}

/* -------------------------------------------------------------------------
 * Send CTRL_ERROR
 * ---------------------------------------------------------------------- */

/* Works in CONNECTING (hello_key) and KEY_DERIVING/ESTABLISHED/
 * CLOSING (session_key). IDLE: no keys available → no-op. */
static int send_ctrl_error(session_t *s, uint16_t code)
{
    const uint8_t *key = NULL;
    if (s->state == SESSION_CONNECTING) {
        if (!s->have_hello_key)
            return 0;
        key = s->hello_key;
    } else if (s->state == SESSION_KEY_DERIVING ||
               s->state == SESSION_ESTABLISHED ||
               s->state == SESSION_REKEYING ||
               s->state == SESSION_CLOSING) {
        if (s->have_session_key)
            key = s->session_key;
        else if (s->have_hello_key)
            key = s->hello_key;
        else
            return 0;
    } else {
        return 0;
    }
    uint8_t buf[4];
    buf[0] = (uint8_t)(code & 0xFF);
    buf[1] = (uint8_t)((code >> 8) & 0xFF);
    buf[2] = 0;
    buf[3] = 0;
    int rc = send_ctrl(s, CTRL_ERROR, buf, 4, key);
    if (s->pending_epoch_valid) {
        int pending_rc = send_ctrl_epoch(s, s->pending_pair_id,
                                         s->pending_key,
                                         &s->pending_tx_seq,
                                         CTRL_ERROR, buf, sizeof(buf));
        if (rc == 0) rc = pending_rc;
    }
    return rc;
}

/* A protocol violation that closes the session must not lose its diagnostic
 * merely because CLOSING quiesces ordinary work. These records survive the
 * mode transition and each consumes its epoch's single terminal-abort
 * attempt. CONNECTING owns a hello-key attempt instead of a session epoch. */
static int send_terminal_error(session_t *s, uint16_t code)
{
    uint8_t buf[4];
    session_tx_epoch_t primary;
    uint8_t modes;
    int rc;

    if (!s || s->state == SESSION_IDLE || s->state == SESSION_CLOSING)
        return -1;
    buf[0] = (uint8_t)(code & 0xFFU);
    buf[1] = (uint8_t)((code >> 8) & 0xFFU);
    buf[2] = 0;
    buf[3] = 0;
    primary = s->state == SESSION_CONNECTING || !s->have_session_key
            ? SESSION_TX_EPOCH_HELLO_KEY
            : SESSION_TX_EPOCH_CURRENT;
    modes = (uint8_t)(wire_mode_mask(wire_mode(s)) |
                      SESSION_TX_MODE_ABORT);
    rc = wire_submit(s, SEND_LANE_INTERACTIVE, primary,
                     SESSION_TX_SEQ_EPOCH_CONTROL, modes,
                     CHAN_FF_BIT, CTRL_ERROR, buf, sizeof(buf),
                     SESSION_TX_DONE_ABORT, primary, code,
                     WIRE_COALESCE_CLOSE_BASE |
                         ((uint32_t)primary << 8) | CTRL_ERROR);
    if (s->pending_epoch_valid) {
        int pending_rc = wire_submit(
            s, SEND_LANE_INTERACTIVE, SESSION_TX_EPOCH_PENDING,
            SESSION_TX_SEQ_EPOCH_CONTROL, modes,
            CHAN_FF_BIT, CTRL_ERROR, buf, sizeof(buf),
            SESSION_TX_DONE_ABORT, SESSION_TX_EPOCH_PENDING, code,
            WIRE_COALESCE_CLOSE_BASE |
                ((uint32_t)SESSION_TX_EPOCH_PENDING << 8) | CTRL_ERROR);
        if (rc == 0)
            rc = pending_rc;
    }
    return rc;
}

void session_protocol_error_close(session_t *s, uint16_t code)
{
    event_log_reason_t reason;

    if (!s || s->state == SESSION_IDLE || s->state == SESSION_CLOSING)
        return;
    reason = code == ERR_CAPS ? EVENT_LOG_REASON_CAPABILITY_MISMATCH
                              : EVENT_LOG_REASON_PROTOCOL_ERROR;
    session_event_latch_close_reason(s, reason);
    session_event_emit(
        s, EVENT_LOG_EVENT_REFUSE, EVENT_LOG_SCOPE_SESSION,
        reason, EVENT_LOG_NO_LEG, 0U, mono_ms());
    s->run_failed = 1;
    if (send_terminal_error(s, code) != 0)
        fprintf(stderr,
                "session: terminal CTRL_ERROR admission failed — closing loudly\n");
    session_close(s);
}

/* -------------------------------------------------------------------------
 * send_hello — used by client (and retransmit)
 *
 * wire body is hello_nonce[24] || ciphertext[48], where
 * hello_nonce is freshly sampled per send and used directly as the AEAD
 * nonce instead of build_nonce(direction, seq). This avoids Poly1305
 * one-time-key reuse across sessions for hello_key (which is deterministic
 * from PSK alone). The canonical 32-byte plaintext is fixed for every retry;
 * only the outer AEAD nonce and frame sequence change.
 *
 * Bypasses send_ctrl/send_frame (which would call crypto_encrypt with
 * build_nonce); does its own AD assembly and frame encode.
 *
 * AUDIT NOTE: frame_test 3-10..3-13 cover the crypto_encrypt_with_nonce
 * wrapper but NOT this caller. If you change the AEAD call below, verify
 * by hand that you are still using crypto_encrypt_with_nonce with a
 * freshly-sampled per-send nonce — silently reverting to crypto_encrypt
 * here would re-open the hello-nonce one-time-key reuse defect, and the
 * regression sentinels would not catch it.
 * ---------------------------------------------------------------------- */

static int send_hello(session_t *s)
{
    return wire_submit(s, SEND_LANE_INTERACTIVE, SESSION_TX_HELLO,
                       SESSION_TX_SEQ_NORMAL,
                       SESSION_TX_MODE_PRE_SERVICE, CHAN_FF_BIT,
                       CTRL_HELLO, NULL, 0, SESSION_TX_DONE_HELLO,
                       0, 0, WIRE_COALESCE_HELLO);
}

/* -------------------------------------------------------------------------
 * Enter IDLE — wipe session key, reset state
 * ---------------------------------------------------------------------- */

static void enter_idle(session_t *s)
{
    unsigned int leg;
    int64_t event_now = mono_ms();

    /* Path authority is erased below. Retain only its operator-local metric
     * projection so a finite bulk command can print one final status after
     * session_run() returns. A failed refresh cannot affect teardown. */
    memset(s->path_leg_final_metrics, 0,
           sizeof(s->path_leg_final_metrics));
    s->path_leg_final_count = 0U;
    if (s->multipath_active || s->bulk_activated ||
        s->path_leg_count != 0U)
        (void)session_refresh_path_legs(s, mono_ms());
    if (s->path_leg_count <= MULTIPATH_PATHS_MAX) {
        s->path_leg_final_count = s->path_leg_count;
        for (leg = 0U; leg < s->path_leg_count; leg++)
            path_leg_metrics_snapshot(
                &s->path_leg[leg], &s->path_leg_final_metrics[leg]);
    }
    if (s->event_session_opened && !s->event_session_closed) {
        event_log_reason_t close_reason = s->event_close_reason_set
            ? s->event_close_reason
            : (s->close_peer_seen ? EVENT_LOG_REASON_PEER_CLOSE
                                  : EVENT_LOG_REASON_LOCAL_CLOSE);

        if (!s->event_close_reason_set && s->bulk_activated && s->bulk) {
            bulk_result_code_t result_code = BULK_CODE_NONE;
            if (bulk_engine_result(s->bulk, &result_code) ==
                BULK_ENGINE_RESULT_SUCCESS)
                close_reason = EVENT_LOG_REASON_COMPLETED;
        }
        if (!s->event_close_reason_set && s->run_failed &&
            close_reason == EVENT_LOG_REASON_LOCAL_CLOSE)
            close_reason = s->wire_transport_broken
                ? EVENT_LOG_REASON_IO_ERROR
                : EVENT_LOG_REASON_PROTOCOL_ERROR;
        s->event_session_closed = 1U;
        session_event_emit(
            s, EVENT_LOG_EVENT_CLOSE, EVENT_LOG_SCOPE_SESSION,
            close_reason, EVENT_LOG_NO_LEG, 0U, event_now);
    }
    if (s->wire_frame_len != 0) {
        fprintf(stderr,
                "session: FATAL: entering IDLE with retained transport frame\n");
        s->run_failed = 1;
    }
    crypto_memzero(s->wire_intents, sizeof(s->wire_intents));
    crypto_memzero(&s->wire_message, sizeof(s->wire_message));
    wire_frame_reset(s);
    s->wire_active_slot = -1;
    s->wire_chaos_applied = 0;
    memset(s->wire_producer_cursor, 0,
           sizeof(s->wire_producer_cursor));
    s->wire_failed_ticket = 0;
    s->wire_transport_broken = 0;
    s->wire_protocol_failure = 0;
    memset(&s->wire_path_plan, 0, sizeof(s->wire_path_plan));
    s->wire_path_plan_active = 0;
    s->wire_path_ordinal = 0;
    s->wire_path_blocked_mask = 0;
    s->wire_path_terminal_mask = 0;
    s->wire_path_success_mask = 0U;
    s->wire_path_need_replica_begin = 0;
    multipath_reset(&s->multipath);
    memset(s->path_leg, 0, sizeof(s->path_leg));
    s->path_leg_count = 0U;
    s->multipath_active = 0;
    s->multipath_challenge_cursor = 0U;
    s->multipath_response_cursor = 0U;
    s->multipath_keepalive_initialized = 0U;
    s->multipath_keepalive_anchor_ms = 0;
    s->multipath_keepalive_phase_serial = 0U;
    memset(&s->multipath_stagger, 0, sizeof(s->multipath_stagger));
    s->multipath_stagger_initialized = 0U;
    s->multipath_validation_log_mask = 0U;
    s->multipath_mismatch_count = 0U;
    crypto_memzero(s->session_key,       32);
    crypto_memzero(s->hello_key,         32);  /* Wipe hello_key too */
    s->have_hello_key = 0;
    crypto_memzero(s->nonce_a,           16);
    crypto_memzero(s->nonce_b,           16);
    pending_epoch_clear(s);
    crypto_memzero(s->session_context, sizeof(s->session_context));
    crypto_memzero(s->epoch_transcript_digest,
                   sizeof(s->epoch_transcript_digest));
    crypto_memzero(s->epoch_fingerprint,
                   sizeof(s->epoch_fingerprint));
    s->completed_rekey_valid = 0;
    crypto_memzero(s->completed_rekey_id,
                   sizeof(s->completed_rekey_id));
    crypto_memzero(s->rekey_private, sizeof(s->rekey_private));
    crypto_memzero(s->rekey_id, sizeof(s->rekey_id));
    crypto_memzero(s->rekey_client_public,
                   sizeof(s->rekey_client_public));
    crypto_memzero(s->rekey_server_public,
                   sizeof(s->rekey_server_public));
    pq_rekey_exchange_reset(s);
    memset(&s->replay, 0, sizeof(s->replay));
    s->replay_drop_count       = 0U;
    s->tx_seq                  = 0;
    s->sent_ready              = 0;
    s->recv_ready              = 0;
    s->ready_ack_pending       = 0;
    s->ready_tx_count          = 0;
    s->ready_next_send_ms      = 0;
    s->hello_tx_count          = 0;
    s->hello_backoff_ms        = 1000;
    s->hello_next_send_ms      = 0;
    s->close_tx_count          = 0;
    s->close_attempts_target   = 0;
    s->close_peer_seen         = 0;
    s->close_epoch_mask        = 0;
    s->terminal_abort_attempted_mask = 0;
    s->stored_hello_ack_len    = 0;
    s->stored_hello_plain_valid = 0;
    s->err_session_count       = 0;
    s->have_session_key        = 0;
    s->selected_caps           = 0;
    s->offered_caps            = s->supported_caps;
    s->configuration_frozen    = 0;
    s->negotiation_neg1        = 0;
    s->peer_legacy             = 0;
    crypto_memzero(s->transcript_hello, sizeof(s->transcript_hello));
    crypto_memzero(s->transcript_ack, sizeof(s->transcript_ack));
    crypto_memzero(s->stored_hello_plain, sizeof(s->stored_hello_plain));
    s->stashed_valid           = 0;
    crypto_memzero(s->stashed_ct, sizeof(s->stashed_ct));
    crypto_memzero(s->stashed_ad, sizeof(s->stashed_ad));
    memset(&s->stashed_source, 0, sizeof(s->stashed_source));
    s->stashed_ct_len          = 0U;
    s->stashed_source_valid    = 0;
    s->stashed_source_required = 0;
    s->services_started        = 0;
    s->bulk_activation_deferred = 0;
    /* Reset only after clearing the session-side service fact.  The reset
     * seam mirrors that fact into the scheduler; doing this earlier leaves
     * the next session's mandatory bootstrap REKEY incorrectly rate-gated. */
    (void)session_wire_scheduler_reset(s, s->pace_bps,
                              s->current_mtu ? s->current_mtu
                                             : UNMOOR_TERMINAL_PLAINTEXT_MAX,
                              mono_ms());
    s->epoch                   = 0;
    s->rekey_phase             = REKEY_NONE;
    s->rekey_request_pending   = 0;
    s->rekey_deferred          = 0;
    s->rekey_adoption_deferred = 0;
    rekey_flight_reset(s);
    if (s->epoch_rekey_enabled)
        memcpy(s->pair_id, s->pair_seed, sizeof(s->pair_id));
    session_channel_application_cleanup_all(s);
    /* Reset stale PTY state so reconnect starts fresh. channel_close_all
     * handles the actual fd/pid reap; here we just clear the handles to -1/0
     * in case close_all was never called. */
    s->pty_master_fd           = -1;
    s->pty_child_pid           = 0;
    s->pty_source_ended        = 0U;
    s->pty_open_ack_seen       = 0;
    s->pty_signal_pending      = 0;
    s->pty_pending_signal      = 0;
    s->pty_resize_pending      = 0;
    s->pty_pending_rows        = 0;
    s->pty_pending_cols        = 0;
    s->raw_mode_active         = 0;
    s->stdin_closed            = 0;
    client_escape_init(&s->client_escape);
    channel_session_table_init(&s->channel_table);
    memset(s->channel_runtime, 0, sizeof(s->channel_runtime));
    memset(&s->channel_first_open, 0, sizeof(s->channel_first_open));
    s->channel_first_open_valid = 0U;
    s->terminal_channel_handle = 0U;
    s->channel_control_inflight = 0U;
    s->channel_control_cursor = 0U;
    s->channel_control_handle = 0U;
    s->channel_control_type = 0U;
    s->channel_control_slot = 0U;
    reasm_reset(&s->reasm);
    /* final client-side drain of undelivered display bytes happens
     * here, before the session forgets the stream existed. */
    sync_free(s);
    sync_status_tracker_reset(&s->sync_status);
    session_delivery_reset(s);
    s->state = SESSION_IDLE;
    fprintf(stderr, "session: → IDLE\n");
}

/* -------------------------------------------------------------------------
 * session_connect — client: send first CTRL_HELLO
 * ---------------------------------------------------------------------- */

int session_connect(session_t *s)
{
    if (!s || s->state != SESSION_IDLE || s->configuration_frozen)
        return -1;
    if (s->bulk_enabled && s->bulk_activated)
        return -1;
    if (prepare_delivery_capabilities(s) != 0)
        return -1;
    s->configuration_frozen = 1;
    s->is_server = 0;
    s->run_failed = 0;
    s->event_session_opened = 0U;
    s->event_session_closed = 0U;
    s->event_path_open_mask = 0U;
    s->selected_caps = 0;
    s->negotiation_neg1 = 0;
    s->peer_legacy = 0;
    s->services_started = 0;
    s->bulk_activation_deferred = 0;
    s->close_epoch_mask = 0;
    s->terminal_abort_attempted_mask = 0;
    s->epoch = 0;
    s->completed_rekey_valid = 0;
    crypto_memzero(s->completed_rekey_id,
                   sizeof(s->completed_rekey_id));
    s->rekey_phase = REKEY_NONE;
    s->rekey_request_pending = 0;
    s->rekey_deferred = 0;
    s->rekey_adoption_deferred = 0;
    rekey_flight_reset(s);
    pending_epoch_clear(s);
    sync_status_tracker_reset(&s->sync_status);
    session_delivery_reset(s);
    client_escape_init(&s->client_escape);
    channel_session_table_init(&s->channel_table);
    memset(s->channel_runtime, 0, sizeof(s->channel_runtime));
    s->channel_first_open_valid = 0U;
    s->terminal_channel_handle = 0U;
    s->channel_control_inflight = 0U;
    s->channel_control_cursor = 0U;
    s->channel_control_handle = 0U;
    if (s->channelised_requested) {
        if (channel_session_client_begin_open(
                &s->channel_table, &s->channel_first_template,
                &s->channel_first_open) != 0) {
            fprintf(stderr,
                    "session: could not allocate channel-session first channel\n");
            enter_idle(s);
            return -1;
        }
        s->channel_first_open_valid = 1U;
        s->terminal_channel_handle = s->channel_first_open.handle;
    }
    if (s->epoch_rekey_enabled)
        memcpy(s->pair_id, s->pair_seed, sizeof(s->pair_id));

    /* Derive hello_key from PSK */
    if (crypto_derive_hello_key(s->psk, s->hello_key) != 0) {
        enter_idle(s);
        return -1;
    }
    s->have_hello_key = 1;

    /* Generate nonce_a for this handshake attempt */
    if (crypto_random_bytes(s->nonce_a, 16) != 0) {
        enter_idle(s);
        return -1;
    }
    negotiation_encode_hello(s->transcript_hello, s->nonce_a,
                             s->offered_caps, s->required_caps);
    crypto_memzero(s->transcript_ack, sizeof(s->transcript_ack));

    s->hello_tx_count      = 0;
    s->hello_backoff_ms    = 1000;
    s->state = SESSION_CONNECTING;
    fprintf(stderr, "session: → CONNECTING\n");

    if (send_hello(s) != 0) {
        enter_idle(s);
        return -1;
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * session_listen — server: prepare to receive CTRL_HELLO
 * ---------------------------------------------------------------------- */

int session_listen(session_t *s)
{
    if (!s || s->state != SESSION_IDLE || s->configuration_frozen)
        return -1;
    if (s->attach_socket_configured)
        return -1;
    if (s->bulk_enabled && s->bulk_activated)
        return -1;
    if (prepare_delivery_capabilities(s) != 0)
        return -1;
    s->configuration_frozen = 1;
    s->is_server = 1;
    s->run_failed = 0;
    s->event_session_opened = 0U;
    s->event_session_closed = 0U;
    s->event_path_open_mask = 0U;
    s->selected_caps = 0;
    s->negotiation_neg1 = 0;
    s->peer_legacy = 0;
    s->services_started = 0;
    s->bulk_activation_deferred = 0;
    s->close_epoch_mask = 0;
    s->terminal_abort_attempted_mask = 0;
    s->epoch = 0;
    s->completed_rekey_valid = 0;
    crypto_memzero(s->completed_rekey_id,
                   sizeof(s->completed_rekey_id));
    s->rekey_phase = REKEY_NONE;
    s->rekey_request_pending = 0;
    s->rekey_deferred = 0;
    s->rekey_adoption_deferred = 0;
    rekey_flight_reset(s);
    pending_epoch_clear(s);
    sync_status_tracker_reset(&s->sync_status);
    session_delivery_reset(s);
    client_escape_init(&s->client_escape);
    channel_session_table_init(&s->channel_table);
    memset(s->channel_runtime, 0, sizeof(s->channel_runtime));
    memset(&s->channel_first_open, 0, sizeof(s->channel_first_open));
    s->channel_first_open_valid = 0U;
    s->terminal_channel_handle = 0U;
    s->channel_control_inflight = 0U;
    if (s->epoch_rekey_enabled)
        memcpy(s->pair_id, s->pair_seed, sizeof(s->pair_id));
    s->stored_hello_plain_valid = 0;
    s->stored_hello_ack_len = 0;
    if (crypto_derive_hello_key(s->psk, s->hello_key) != 0) {
        enter_idle(s);
        return -1;
    }
    s->have_hello_key = 1;
    s->state = SESSION_IDLE;
    fprintf(stderr, "session: server mode, waiting for CTRL_HELLO\n");
    return 0;
}

/* -------------------------------------------------------------------------
 * Handle incoming CTRL_HELLO (server side)
 * ---------------------------------------------------------------------- */

static void confirm_handshake_peer(session_t *s)
{
    if (s->transport->ops->peer_confirm)
        (void)s->transport->ops->peer_confirm(s->transport);
}

static int resend_stored_hello_ack(session_t *s)
{
    /* Coalescing deliberately cannot mutate in-flight ciphertext. A
     * duplicate HELLO still needs no second ACK slot while that exact cached
     * or not-yet-cached ACK is outstanding. */
    for (size_t i = 0; i < SESSION_TX_SLOT_COUNT; i++)
        if (s->wire_intents[i].valid &&
            s->wire_intents[i].coalesce_key == WIRE_COALESCE_HELLO_ACK)
            return 0;
    if (s->stored_hello_ack_len == 0)
        return -1;
    return wire_submit(s, SEND_LANE_INTERACTIVE, SESSION_TX_RAW_FRAME,
                       SESSION_TX_SEQ_NONE,
                       SESSION_TX_MODE_PRE_SERVICE, CHAN_FF_BIT,
                       CTRL_HELLO_ACK, s->stored_hello_ack,
                       s->stored_hello_ack_len,
                       SESSION_TX_DONE_HELLO_ACK, 0, 0,
                       WIRE_COALESCE_HELLO_ACK);
}

/* Encode and cache one HELLO_ACK. Retries resend these exact bytes: they do
 * not re-encrypt under hello_key and therefore cannot accidentally reuse an
 * explicit AEAD nonce with different plaintext. */
static int send_hello_ack_frame(session_t *s,
                                const uint8_t ack_plain[NEGOTIATION_PLAIN_LEN])
{
    return wire_submit(s, SEND_LANE_INTERACTIVE,
                       SESSION_TX_HELLO_ACK_NEW,
                       SESSION_TX_SEQ_NORMAL,
                       SESSION_TX_MODE_PRE_SERVICE, CHAN_FF_BIT,
                       CTRL_HELLO_ACK, ack_plain, NEGOTIATION_PLAIN_LEN,
                       SESSION_TX_DONE_HELLO_ACK, 0, 0,
                       WIRE_COALESCE_HELLO_ACK);
}

static int send_ready_frame(session_t *s, uint8_t flags,
                            session_tx_done_t done)
{
    uint8_t ready_prefix[NEGOTIATION_READY_LEN];
    uint8_t ready[CHANNEL_SESSION_READY_BYTES];
    const uint8_t *plain = NULL;
    size_t plain_len = 0;
    if (s->negotiation_neg1) {
        negotiation_ready_encode(ready_prefix, flags, s->selected_caps);
        if (session_channelised_active(s)) {
            if (channel_session_ready_encode(
                    ready_prefix, !s->is_server,
                    s->is_server ? NULL : &s->channel_first_open,
                    ready) != 0)
                return -1;
            plain = ready;
            plain_len = CHANNEL_SESSION_READY_BYTES;
        } else {
            plain = ready_prefix;
            plain_len = sizeof(ready_prefix);
        }
    }
    return wire_submit(s, SEND_LANE_INTERACTIVE,
                       SESSION_TX_EPOCH_CURRENT,
                       SESSION_TX_SEQ_NORMAL,
                       SESSION_TX_MODE_PRE_SERVICE |
                           SESSION_TX_MODE_REKEY |
                           SESSION_TX_MODE_ESTABLISHED,
                       CHAN_FF_BIT, CTRL_READY, plain, plain_len,
                       done, flags, s->selected_caps,
                       flags == 0 ? WIRE_COALESCE_READY_ACK
                                  : WIRE_COALESCE_READY);
}

static int send_initial_ready(session_t *s)
{
    uint8_t flags = s->negotiation_neg1 ? NEGOTIATION_READY_NEED_ACK : 0;
    return send_ready_frame(s, flags, SESSION_TX_DONE_READY_INITIAL);
}

void session_ready_tick(session_t *s, int64_t now_ms)
{
    if (!s || s->state != SESSION_KEY_DERIVING)
        return;
    if (!s->sent_ready && s->ready_next_send_ms > 0 &&
        now_ms >= s->ready_next_send_ms) {
        if (send_initial_ready(s) != 0)
            s->wire_protocol_failure = 1;
    } else if (s->sent_ready && s->negotiation_neg1 &&
               now_ms >= s->ready_next_send_ms) {
        if (send_ready_frame(s, NEGOTIATION_READY_NEED_ACK,
                             SESSION_TX_DONE_READY_RETRY) != 0)
            s->wire_protocol_failure = 1;
    }
}

static const char *capability_names(uint32_t caps)
{
    const uint32_t d36_terminal =
        UNMOOR_CAP_CHANNEL_SESSION_D36_V1 |
        UNMOOR_CAP_CHANNEL_TERMINAL_D36_V1 |
        UNMOOR_CAP_PTY_V1 | UNMOOR_CAP_FRAGMENT_D21_V1 |
        UNMOOR_CAP_PTY_SYNC_V1 | UNMOOR_CAP_STATUS_HEARTBEAT_V1;
    const uint32_t d36_stage2 =
        d36_terminal | UNMOOR_CAP_CHANNEL_EXEC_D36_V1;

    if (caps == d36_stage2)
        return "channel-session-v1,terminal-channel-v1,exec-channel-v1,"
               "pty-v1,fragment-v1,pty-sync-v1,"
               "status-heartbeat-v1";
    if (caps == (d36_stage2 | UNMOOR_CAP_EPOCH_REKEY_D28_V1))
        return "channel-session-v1,terminal-channel-v1,exec-channel-v1,"
               "pty-v1,fragment-v1,pty-sync-v1,epoch-rekey-v1,"
               "status-heartbeat-v1";
    if (caps == (d36_stage2 | UNMOOR_CAP_EPOCH_REKEY_D28_V1 |
                 UNMOOR_CAP_PQ_HYBRID_D45_V1))
        return "channel-session-v1,terminal-channel-v1,exec-channel-v1,"
               "pty-v1,fragment-v1,pty-sync-v1,epoch-rekey-v1,"
               "status-heartbeat-v1,pq-hybrid-v1";

    if (caps == d36_terminal)
        return "channel-session-v1,terminal-channel-v1,"
               "pty-v1,fragment-v1,pty-sync-v1,"
               "status-heartbeat-v1";
    if (caps == (d36_terminal | UNMOOR_CAP_EPOCH_REKEY_D28_V1))
        return "channel-session-v1,terminal-channel-v1,"
               "pty-v1,fragment-v1,pty-sync-v1,epoch-rekey-v1,"
               "status-heartbeat-v1";
    if (caps == (d36_terminal | UNMOOR_CAP_EPOCH_REKEY_D28_V1 |
                 UNMOOR_CAP_PQ_HYBRID_D45_V1))
        return "channel-session-v1,terminal-channel-v1,"
               "pty-v1,fragment-v1,pty-sync-v1,epoch-rekey-v1,"
               "status-heartbeat-v1,pq-hybrid-v1";
    if (caps == (UNMOOR_CAP_BULK_FILE_D33_V1 |
                 UNMOOR_CAP_EPOCH_REKEY_D28_V1))
        return "bulk-file-v1,epoch-rekey-v1";
    if (caps == (UNMOOR_CAP_BULK_FILE_D33_V1 |
                 UNMOOR_CAP_EPOCH_REKEY_D28_V1 |
                 UNMOOR_CAP_PQ_HYBRID_D45_V1))
        return "bulk-file-v1,epoch-rekey-v1,pq-hybrid-v1";
    if (caps == UNMOOR_CAP_PTY_V1)
        return "pty-v1";
    if (caps == (UNMOOR_CAP_PTY_V1 | UNMOOR_CAP_FRAGMENT_D21_V1))
        return "pty-v1,fragment-v1";
    if (caps == (UNMOOR_CAP_PTY_V1 | UNMOOR_CAP_FRAGMENT_D21_V1 |
                 UNMOOR_CAP_PTY_SYNC_V1))
        return "pty-v1,fragment-v1,pty-sync-v1";
    if (caps == UNMOOR_CAP_DEFAULT_SUPPORTED)
        return "pty-v1,fragment-v1,pty-sync-v1,status-heartbeat-v1,"
               "latest-block-v1,reliable-dgram-v1";
    if (caps == (UNMOOR_CAP_DEFAULT_SUPPORTED |
                 UNMOOR_CAP_EPOCH_REKEY_D28_V1))
        return "pty-v1,fragment-v1,pty-sync-v1,epoch-rekey-v1,"
               "status-heartbeat-v1,latest-block-v1,"
               "reliable-dgram-v1";
    if (caps == (UNMOOR_CAP_DEFAULT_SUPPORTED |
                 UNMOOR_CAP_EPOCH_REKEY_D28_V1 |
                 UNMOOR_CAP_PQ_HYBRID_D45_V1))
        return "pty-v1,fragment-v1,pty-sync-v1,epoch-rekey-v1,"
               "status-heartbeat-v1,latest-block-v1,"
               "reliable-dgram-v1,pq-hybrid-v1";
    return "custom";
}

static int session_activate_services(session_t *s)
{
    int64_t now;

    if (!s || s->state == SESSION_IDLE || s->state == SESSION_CLOSING)
        return -1;

    /* send-scheduler owns a retained frame until the transport reports a terminal
     * result.  Bulk activation changes the effective wire budget by
     * reinitialising that scheduler, so it may not cross this boundary. */
    if (s->bulk_enabled && !s->services_started &&
        s->wire_frame_len != 0U) {
        s->bulk_activation_deferred = 1;
        return 1;
    }

    now = mono_ms();
    s->state = SESSION_ESTABLISHED;
    s->last_authenticated_ms = now;
    s->liveness_hold_announced = 0U;
    s->next_liveness_warn_ms = 0;
    s->next_keepalive_ms = s->last_authenticated_ms + s->keepalive_period_ms;
    if (s->services_started) {
        if (!s->bulk_enabled)
            session_status_present(s, now);
        return 0;
    }

    if (s->multipath_active && !s->multipath_stagger_initialized) {
        if (traffic_stagger_init(
                &s->multipath_stagger, s->traffic_profile,
                s->is_server ? TRAFFIC_ENDPOINT_LISTENER
                             : TRAFFIC_ENDPOINT_CLIENT,
                s->multipath_path_count, now) != 0 ||
            (!s->is_server &&
             traffic_stagger_note_physical_attempt(
                 &s->multipath_stagger, 0U, now) < 0)) {
            fprintf(stderr,
                    "session: traffic-profile path-admission policy could not activate\n");
            s->run_failed = 1;
            session_close(s);
            return -1;
        }
        s->multipath_stagger_initialized = 1U;
    }

    if (s->bulk_enabled) {
        const uint32_t exact = UNMOOR_CAP_BULK_FILE_D33_V1 |
                               UNMOOR_CAP_EPOCH_REKEY_D28_V1 |
                               (s->selected_caps &
                                UNMOOR_CAP_PQ_HYBRID_D45_V1);
        uint32_t without_paths =
            s->selected_caps & ~UNMOOR_CAP_MULTIPATH_D32_MASK;
        uint8_t bulk_path_count = 0U;

        if (!s->bulk || without_paths != exact ||
            negotiation_multipath_path_count(
                s->selected_caps, &bulk_path_count) != 0 ||
            (s->bulk_config.endpoint == BULK_ENGINE_ENDPOINT_SERVER) !=
                (s->is_server != 0)) {
            fprintf(stderr,
                    "session: bulk-transfer service activation failed loudly\n");
            s->run_failed = 1;
            session_close(s);
            return -1;
        }
        s->bulk_config.path_count = bulk_path_count == 0U ?
                                    1U : bulk_path_count;
        if (bulk_engine_activate(s->bulk, &s->bulk_config, now) != 0 ||
            session_wire_scheduler_reset(
                s, s->pace_bps, s->bulk_config.wire_budget, now) != 0) {
            fprintf(stderr,
                    "session: bulk-transfer service activation failed loudly\n");
            s->run_failed = 1;
            session_close(s);
            return -1;
        }
        s->path_leg_final_count = 0U;
        s->bulk_activated = 1;
        if (session_bulk_refresh_paths(s, now) != 0) {
            fprintf(stderr,
                    "session: bulk-transfer initial path eligibility failed loudly\n");
            s->run_failed = 1;
            session_close(s);
            return -1;
        }
        session_bulk_retire_receive_arena(s);
        if (session_on_established && session_on_established(s) != 0) {
            fprintf(stderr,
                    "session: bulk-transfer post-negotiation setup failed\n");
            s->run_failed = 1;
            session_close(s);
            return -1;
        }
        s->services_started = 1;
        s->bulk_activation_deferred = 0;
        send_scheduler_service_started(&s->wire_scheduler);
        s->bootstrap_deadline_ms = 0;
        if (!s->event_session_opened) {
            s->event_session_opened = 1U;
            session_event_emit(
                s, EVENT_LOG_EVENT_OPEN, EVENT_LOG_SCOPE_SESSION,
                EVENT_LOG_REASON_SESSION_ACTIVE, EVENT_LOG_NO_LEG, 0U,
                now);
        }
        fprintf(stderr,
                "session: → ESTABLISHED (bulk-file-v1 wire=%u)\n",
                (unsigned int)s->bulk_config.wire_budget);
        return 0;
    }

    if (session_channelised_active(s)) {
        uint8_t slot;
        uint32_t generation;

        if (!s->channel_first_open_valid ||
            s->channel_first_open.kind != CHANNEL_KIND_TERMINAL ||
            channel_session_handle_decode(s->channel_first_open.handle,
                                          &slot, &generation) != 0 ||
            s->terminal_channel_handle != s->channel_first_open.handle) {
            fprintf(stderr,
                    "session: channel-session first terminal descriptor is unavailable\n");
            s->run_failed = 1;
            session_close(s);
            return -1;
        }
    }

    /* bring up sync before any channel can move PTY bytes. */
    if (sync_init(s) != 0) {
        s->run_failed = 1;
        session_close(s);
        return -1;
    }
    if (session_channelised_active(s)) {
        uint8_t anchor_slot;
        uint32_t anchor_generation;
        session_channel_application_t *anchor_app;

        if (channel_session_handle_decode(
                s->terminal_channel_handle, &anchor_slot,
                &anchor_generation) != 0 ||
            !sync_active_instance(s, anchor_slot)) {
            fprintf(stderr,
                    "session: channel-session anchor stream binding failed\n");
            s->run_failed = 1;
            session_close(s);
            return -1;
        }
        anchor_app = &s->channel_application[anchor_slot];
        channel_application_reset(anchor_app);
        anchor_app->active = 1U;
        anchor_app->handle = s->terminal_channel_handle;
        anchor_app->kind = CHANNEL_KIND_TERMINAL;
    }
    if ((s->selected_caps & UNMOOR_CAP_STATUS_HEARTBEAT_V1) != 0)
        sync_status_tracker_init(&s->sync_status,
                                 s->epoch_rekey_enabled ? s->epoch : 0,
                                 now);
    session_delivery_start(s, now);
    /* Arm the process-owned sink after negotiation but before open. */
    if (session_on_established && session_on_established(s) != 0) {
        fprintf(stderr,
                "session: post-negotiation setup failed before channel open\n");
        s->run_failed = 1;
        session_close(s);
        return -1;
    }
    if (session_channelised_active(s) && !s->is_server &&
        s->attach_socket_configured && !s->attach_socket_open) {
        int attach_status = s->attach_socket_prepared
            ? attach_manager_bind_prepared(&s->attach_manager)
            : attach_manager_open_path(&s->attach_manager,
                                       s->attach_socket_path, geteuid());

        if (attach_status != ATTACH_LOCAL_OK) {
            fprintf(stderr,
                    "session: local channel-session attach socket failed: %s\n",
                    strerror(errno));
            s->run_failed = 1;
            session_close(s);
            return -1;
        }
        s->attach_socket_open = 1U;
    }
    if (session_channelised_active(s) && s->is_server) {
        uint8_t slot;
        uint32_t generation;

        if (channel_session_handle_decode(s->channel_first_open.handle,
                                          &slot, &generation) != 0 ||
            channel_server_decide_stage1(s, slot) != 0) {
            fprintf(stderr,
                    "session: channel-session first terminal decision failed\n");
            s->run_failed = 1;
            session_close(s);
            return -1;
        }
    }
    s->services_started = 1;
    send_scheduler_service_started(&s->wire_scheduler);
    s->bootstrap_deadline_ms = 0;
    if (!s->event_session_opened) {
        s->event_session_opened = 1U;
        session_event_emit(
            s, EVENT_LOG_EVENT_OPEN, EVENT_LOG_SCOPE_SESSION,
            EVENT_LOG_REASON_SESSION_ACTIVE, EVENT_LOG_NO_LEG, 0U, now);
    }
    fprintf(stderr, "session: → ESTABLISHED\n");
    session_status_present(s, now);
    if (session_channelised_active(s))
        session_channel_tick(s, now);
    else
        channel_open_all(s);
    return 0;
}

static void establish_session(session_t *s)
{
    uint8_t multipath_count = 0U;
    int64_t established_now;

    if (s->state != SESSION_KEY_DERIVING ||
        !s->sent_ready || !s->recv_ready)
        return;
    established_now = mono_ms();
    if (session_channelised_active(s)) {
        uint8_t slot;
        uint32_t generation;

        if (!s->channel_first_open_valid ||
            channel_session_handle_decode(s->channel_first_open.handle,
                                          &slot, &generation) != 0) {
            fprintf(stderr,
                    "session: channel-session mutual READY lacks a first OPEN\n");
            s->run_failed = 1;
            session_close(s);
            return;
        }
        /* A datagram may overtake READY.  Only an unresolved OPEN owns the
         * post-READY retry/deadline; an already resolved slot must never
         * acquire a stale first-open timer. */
        if (s->channel_table.slots[slot].state == CHANNEL_SLOT_OPENING)
            channel_runtime_arm_open(&s->channel_runtime[slot],
                                     established_now, !s->is_server);
    }
    if (negotiation_multipath_path_count(
            s->selected_caps, &multipath_count) != 0) {
        fprintf(stderr,
                "session: negotiated a noncanonical multipath count — closing\n");
        s->run_failed = 1;
        session_close(s);
        return;
    }
    if (multipath_count != 0U)
        fprintf(stderr,
                "session: negotiated wire=v%d caps=0x%08X (%s) multipath-paths=%u%s\n",
                UNMOOR_PROTO_VERSION,
                s->selected_caps,
                capability_names(s->selected_caps &
                                 ~UNMOOR_CAP_MULTIPATH_D32_MASK),
                (unsigned int)multipath_count,
                s->peer_legacy ? " peer=legacy" : "");
    else
        fprintf(stderr,
                "session: negotiated wire=v%d caps=0x%08X (%s)%s\n",
                UNMOOR_PROTO_VERSION,
                s->selected_caps, capability_names(s->selected_caps),
                s->peer_legacy ? " peer=legacy" : "");
    if (s->bulk_enabled &&
        session_bulk_prepare_receive_arena(s) != 0) {
        fprintf(stderr,
                "session: could not allocate negotiated bulk-transfer pre-barrier receive arena\n");
        s->run_failed = 1;
        session_close(s);
        return;
    }
    if (session_multipath_start(s, established_now) != 0) {
        s->run_failed = 1;
        session_close(s);
        return;
    }
    if (!s->bulk_enabled && session_delivery_prepare_context(s) != 0) {
        fprintf(stderr,
                "session: delivery-class context binding failed — closing\n");
        s->run_failed = 1;
        session_close(s);
        return;
    }
    if ((s->selected_caps & UNMOOR_CAP_PQ_HYBRID_D45_V1) != 0U &&
        (!s->pq_hybrid_enabled ||
         (s->selected_caps & UNMOOR_CAP_EPOCH_REKEY_D28_V1) == 0U)) {
        rekey_fail(s, "negotiated pq-hybrid without its initialized epoch-rekey engine");
        return;
    }
    if ((s->selected_caps & UNMOOR_CAP_EPOCH_REKEY_D28_V1) != 0) {
        if (!s->epoch_rekey_enabled ||
            epoch_crypto_session_context(s->transcript_hello,
                                         s->transcript_ack,
                                         s->selected_caps, s->pair_seed,
                                         s->session_context) != 0) {
            rekey_fail(s, "negotiated without an initialized epoch engine");
            return;
        }
        s->epoch = 0;
        if (epoch_crypto_pair_id(s->pair_seed, 0, s->pair_id) != 0) {
            rekey_fail(s, "could not initialize epoch-zero pair");
            return;
        }
        if (s->ephemeral_bootstrap_root) {
            /* Both sides have now authenticated READY. The client could erase
             * earlier; this shared boundary is exact and still meets the
             * server's longer retry obligation. */
            crypto_memzero(s->psk, sizeof(s->psk));
            crypto_memzero(s->hello_key, sizeof(s->hello_key));
            s->have_hello_key = 0;
        }
        if (s->bootstrap_rekey_required) {
            s->state = SESSION_REKEYING;
            if (s->is_server) {
                s->rekey_phase = REKEY_S_WAIT_INIT;
                s->rekey_next_send_ms = 0;
                fprintf(stderr,
                        "session: → REKEYING (mandatory bootstrap barrier)\n");
            } else {
                if (start_client_rekey(s, established_now) != 0 &&
                    s->state != SESSION_REKEYING)
                    rekey_fail(s, "could not start bootstrap barrier");
            }
            return;
        }
    }
    (void)session_activate_services(s);
}

static void cache_hello_plain(session_t *s, const uint8_t *plain)
{
    memcpy(s->stored_hello_plain, plain, NEGOTIATION_PLAIN_LEN);
    s->stored_hello_plain_valid = 1;
}

static void send_negotiation_refusal(session_t *s, uint16_t status,
                                     uint32_t selected)
{
    uint8_t zero_nonce[NEGOTIATION_NONCE_LEN] = { 0 };
    event_log_reason_t reason = status == ERR_CAPS
        ? EVENT_LOG_REASON_CAPABILITY_MISMATCH
        : EVENT_LOG_REASON_PROTOCOL_ERROR;

    session_event_emit(s, EVENT_LOG_EVENT_REFUSE,
                       EVENT_LOG_SCOPE_SESSION, reason,
                       EVENT_LOG_NO_LEG, 0U, mono_ms());
    /* handle_hello() pins the exact authenticated offer before decoding it.
     * Both refusal paths arrive here only after that common cache boundary. */
    negotiation_encode_ack(s->transcript_ack, zero_nonce, selected,
                           status == ERR_CAPS ? s->required_caps : 0,
                           status);
    if (send_hello_ack_frame(s, s->transcript_ack) != 0)
        fprintf(stderr, "session: failed to send negotiation refusal\n");
}

static void handle_hello(session_t *s, uint32_t seq,
                         const uint8_t *plaintext, size_t pt_len)
{
    (void)seq;
    /* client must never accept CTRL_HELLO */
    if (!s->is_server) {
        fprintf(stderr, "session: client received CTRL_HELLO — ERR_SESSION\n");
        send_ctrl_error(s, ERR_SESSION);
        track_err_session(s);
        return;
    }
    if (pt_len != NEGOTIATION_PLAIN_LEN) {
        fprintf(stderr, "session: CTRL_HELLO length=%zu (expected %u) — dropped\n",
                pt_len, (unsigned)NEGOTIATION_PLAIN_LEN);
        return;
    }

    /* A completed session never re-enters negotiation. In KEY_DERIVING the
     * first authenticated offer is pinned: byte-identical retry replays the
     * cached ACK, while changed or fresh nonces cannot preempt it. */
    if (s->state == SESSION_ESTABLISHED || s->state == SESSION_REKEYING) {
        return;
    }
    if (s->stored_hello_plain_valid) {
        if (memcmp(plaintext, s->stored_hello_plain,
                   NEGOTIATION_PLAIN_LEN) == 0) {
            fprintf(stderr,
                    "session: idempotent CTRL_HELLO — re-sending cached ACK\n");
            if (resend_stored_hello_ack(s) != 0)
                fprintf(stderr, "session: stored CTRL_HELLO_ACK re-send failed\n");
            return;
        }
        if (memcmp(plaintext + 2, s->stored_hello_plain + 2,
                   NEGOTIATION_NONCE_LEN) == 0) {
            fprintf(stderr,
                    "session: conflicting CTRL_HELLO with reused nonce — dropped\n");
            return;
        }
        if (s->state == SESSION_KEY_DERIVING) {
            fprintf(stderr,
                    "session: fresh CTRL_HELLO cannot preempt KEY_DERIVING — dropped\n");
            return;
        }
        /* A previous refusal is cached while IDLE. A genuinely fresh nonce
         * may replace it and keeps the listener available. */
        s->stored_hello_plain_valid = 0;
        s->stored_hello_ack_len = 0;
    }

    if (s->state != SESSION_IDLE) {
        /* Unexpected state for a fresh CTRL_HELLO */
        fprintf(stderr, "session: CTRL_HELLO in unexpected state %d — ERR_SESSION\n", s->state);
        send_ctrl_error(s, ERR_SESSION);
        track_err_session(s);
        return;
    }

    negotiation_message_t hello;
    uint16_t parse_status = negotiation_decode(plaintext, pt_len, 0, &hello);

    /* The first fresh, authenticated offer pins the handshake return path.
     * HELLO retries do not roam it; a fresh session-key READY may. */
    confirm_handshake_peer(s);
    cache_hello_plain(s, plaintext);

    if (parse_status != 0) {
        fprintf(stderr,
                "session: negotiation failed: unsupported or malformed grammar — ERR_%s\n",
                parse_status == ERR_CAPS ? "CAPS" : "VERSION");
        send_negotiation_refusal(s, parse_status, 0);
        return;
    }

    uint32_t selected = 0;
    uint16_t select_status = 0;
    if (hello.kind == NEGOTIATION_LEGACY) {
        selected = hello.supported_caps & s->offered_caps &
                   UNMOOR_CAP_PTY_V1;
        /* Legacy has exactly one implicit application grammar: PTY_V1. A
         * control-only legacy session would immediately violate its own
         * advertised wire behavior by sending PTY_OPEN. */
        if ((selected & UNMOOR_CAP_PTY_V1) == 0 ||
            (s->required_caps & ~selected) != 0)
            select_status = ERR_CAPS;
    } else {
        select_status = negotiation_select(&hello, s->offered_caps,
                                            s->required_caps, &selected);
    }
    if (select_status != 0) {
        uint32_t client_missing = hello.required_caps & ~selected;
        uint32_t server_missing = s->required_caps & ~selected;
        fprintf(stderr,
                "session: negotiation failed: required caps missing "
                "(client=0x%08X server=0x%08X selected=0x%08X "
                "missing=0x%08X) — ERR_CAPS\n",
                hello.required_caps, s->required_caps, selected,
                client_missing | server_missing);
        send_negotiation_refusal(s, ERR_CAPS, selected);
        return;
    }

    memcpy(s->transcript_hello, plaintext, NEGOTIATION_PLAIN_LEN);
    memcpy(s->nonce_a, hello.nonce, NEGOTIATION_NONCE_LEN);
    s->selected_caps = selected;
    s->negotiation_neg1 = hello.kind == NEGOTIATION_NEG1;
    s->peer_legacy = hello.kind == NEGOTIATION_LEGACY;

    /* Generate nonce_b */
    if (crypto_random_bytes(s->nonce_b, 16) != 0) {
        fprintf(stderr, "session: failed to generate nonce_b\n");
        return;
    }

    if (s->negotiation_neg1) {
        negotiation_encode_ack(s->transcript_ack, s->nonce_b,
                               s->selected_caps, s->required_caps, 0);
    } else {
        negotiation_encode_legacy(s->transcript_ack, s->nonce_b,
                                  (uint8_t)s->selected_caps);
    }

    int kdf_rc = s->negotiation_neg1
        ? crypto_derive_negotiated_session_key(s->psk,
                                               s->transcript_hello,
                                               s->transcript_ack,
                                               s->selected_caps,
                                               s->session_key)
        : crypto_derive_session_key(s->psk, s->nonce_a, s->nonce_b,
                                    s->session_key);
    if (kdf_rc != 0) {
        fprintf(stderr, "session: key derivation failed\n");
        return;
    }
    s->have_session_key = 1;
    if (session_delivery_prepare_context(s) != 0) {
        fprintf(stderr,
                "session: delivery-class context binding failed during handshake\n");
        s->run_failed = 1;
        enter_idle(s);
        return;
    }

    s->state = SESSION_KEY_DERIVING;
    s->key_deriving_deadline_ms = mono_ms() + 10000;
    fprintf(stderr, "session: → KEY_DERIVING (server)\n");

    if (send_hello_ack_frame(s, s->transcript_ack) != 0) {
        s->run_failed = 1;
        enter_idle(s);
        return;
    }
    /* HELLO_ACK completion makes server READY due without a wall-clock
     * stagger. No receive handler blocks and READY cannot overtake the ACK's
     * transport handoff. */
}

/* -------------------------------------------------------------------------
 * Handle incoming CTRL_HELLO_ACK (client side)
 * ---------------------------------------------------------------------- */

static void handle_hello_ack(session_t *s,
                             const uint8_t *plaintext, size_t pt_len)
{
    /* server must never accept CTRL_HELLO_ACK */
    if (s->is_server) {
        fprintf(stderr, "session: server received CTRL_HELLO_ACK — ERR_SESSION\n");
        send_ctrl_error(s, ERR_SESSION);
        track_err_session(s);
        return;
    }
    if (s->state != SESSION_CONNECTING) {
        if (s->state == SESSION_KEY_DERIVING ||
            s->state == SESSION_ESTABLISHED ||
            s->state == SESSION_REKEYING) {
            /* Silently ignore — may be a retransmit */
            return;
        }
        fprintf(stderr, "session: unexpected CTRL_HELLO_ACK in state %d\n", s->state);
        send_ctrl_error(s, ERR_SESSION);
        track_err_session(s);
        return;
    }
    negotiation_message_t ack;
    uint16_t parse_status = negotiation_decode(plaintext, pt_len, 1, &ack);
    if (parse_status != 0) {
        fprintf(stderr,
                "session: negotiation failed: malformed HELLO_ACK — ERR_%s\n",
                parse_status == ERR_CAPS ? "CAPS" : "VERSION");
        session_event_emit(
            s, EVENT_LOG_EVENT_REFUSE, EVENT_LOG_SCOPE_SESSION,
            parse_status == ERR_CAPS
                ? EVENT_LOG_REASON_CAPABILITY_MISMATCH
                : EVENT_LOG_REASON_PROTOCOL_ERROR,
            EVENT_LOG_NO_LEG, 0U, mono_ms());
        s->run_failed = 1;
        enter_idle(s);
        return;
    }

    uint32_t selected = 0;
    uint16_t status = 0;
    if (ack.kind == NEGOTIATION_LEGACY) {
        selected = ack.supported_caps & s->offered_caps &
                   UNMOOR_CAP_PTY_V1;
        if ((selected & UNMOOR_CAP_PTY_V1) == 0 ||
            (s->required_caps & ~selected) != 0)
            status = ERR_CAPS;
        s->negotiation_neg1 = 0;
        s->peer_legacy = 1;
    } else {
        status = negotiation_validate_ack(&ack, s->offered_caps,
                                          s->required_caps, &selected);
        s->negotiation_neg1 = 1;
        s->peer_legacy = 0;
    }
    if (status != 0) {
        uint32_t missing = (s->required_caps | ack.required_caps) & ~selected;
        if (status == ERR_VERSION) {
            fprintf(stderr,
                    "session: negotiation failed: peer rejected grammar — ERR_VERSION\n");
        } else if ((selected & ~s->offered_caps) != 0) {
            fprintf(stderr,
                    "session: negotiation failed: peer selected unoffered caps "
                    "(offered=0x%08X selected=0x%08X) — ERR_CAPS\n",
                    s->offered_caps, selected);
        } else {
            fprintf(stderr,
                    "session: negotiation failed: required caps missing "
                    "(required=0x%08X peer=0x%08X missing=0x%08X) — ERR_CAPS\n",
                    s->required_caps, selected, missing);
        }
        session_event_emit(
            s, EVENT_LOG_EVENT_REFUSE, EVENT_LOG_SCOPE_SESSION,
            status == ERR_CAPS
                ? EVENT_LOG_REASON_CAPABILITY_MISMATCH
                : EVENT_LOG_REASON_PROTOCOL_ERROR,
            EVENT_LOG_NO_LEG, 0U, mono_ms());
        s->run_failed = 1;
        enter_idle(s);
        return;
    }

    s->selected_caps = selected;
    memcpy(s->nonce_b, ack.nonce, NEGOTIATION_NONCE_LEN);
    memcpy(s->transcript_ack, plaintext, NEGOTIATION_PLAIN_LEN);

    int kdf_rc = s->negotiation_neg1
        ? crypto_derive_negotiated_session_key(s->psk,
                                               s->transcript_hello,
                                               s->transcript_ack,
                                               s->selected_caps,
                                               s->session_key)
        : crypto_derive_session_key(s->psk, s->nonce_a, s->nonce_b,
                                    s->session_key);
    if (kdf_rc != 0) {
        fprintf(stderr, "session: key derivation failed\n");
        s->run_failed = 1;
        enter_idle(s);
        return;
    }
    s->have_session_key = 1;
    if (session_delivery_prepare_context(s) != 0) {
        fprintf(stderr,
                "session: delivery-class context binding failed during handshake\n");
        s->run_failed = 1;
        enter_idle(s);
        return;
    }
    if (s->ephemeral_bootstrap_root) {
        /* The client never needs to authenticate another HELLO_ACK once its
         * transcript-bound session key exists. Erase the bootstrap root at
         * its earliest exact boundary; the server retains its copy until
         * READY proves the cached HELLO_ACK is no longer needed. */
        crypto_memzero(s->psk, sizeof(s->psk));
        crypto_memzero(s->hello_key, sizeof(s->hello_key));
        s->have_hello_key = 0;
    }

    s->state = SESSION_KEY_DERIVING;
    s->key_deriving_deadline_ms = mono_ms() + 10000;
    fprintf(stderr, "session: → KEY_DERIVING (client)\n");

    if (send_initial_ready(s) != 0) {
        fprintf(stderr, "session: CTRL_READY send failed\n");
        s->run_failed = 1;
        enter_idle(s);
        return;
    }

    /* If a CTRL_READY (or other session-keyed frame) arrived early
     * while we were CONNECTING, we stashed it. Replay it now. */
    if (s->stashed_valid) {
        session_replay_stashed_frame(s);
    }
}

/* -------------------------------------------------------------------------
 * Handle incoming CTRL_READY
 * ---------------------------------------------------------------------- */

static void handle_ready(session_t *s, const uint8_t *plaintext, size_t pt_len)
{
    uint8_t flags = 0;
    if (s->negotiation_neg1) {
        uint8_t ready_prefix[NEGOTIATION_READY_LEN];
        channel_session_open_t first_open;
        const uint8_t *ready_plain = plaintext;
        size_t ready_length = pt_len;

        memset(&first_open, 0, sizeof(first_open));
        if (session_channelised_active(s)) {
            if (channel_session_ready_decode(
                    plaintext, pt_len, s->is_server,
                    ready_prefix, s->is_server ? &first_open : NULL) != 0) {
                fprintf(stderr,
                        "session: invalid channel-session CTRL_READY envelope — ERR_CAPS\n");
                session_protocol_error_close(s, ERR_CAPS);
                return;
            }
            ready_plain = ready_prefix;
            ready_length = sizeof(ready_prefix);
        }
        if (negotiation_ready_decode(ready_plain, ready_length,
                                     s->selected_caps, &flags) != 0) {
            fprintf(stderr,
                    "session: invalid NEG1 CTRL_READY tuple — ERR_CAPS\n");
            session_protocol_error_close(s, ERR_CAPS);
            return;
        }
        /* Validate the complete READY tuple before committing its embedded
         * pre-service OPEN to the real lifecycle table.  A malformed NEG1
         * prefix must fail without leaving even bounded bookkeeping behind. */
        if (session_channelised_active(s) && s->is_server) {
            channel_session_observe_t observed;

            if (first_open.kind != CHANNEL_KIND_TERMINAL ||
                !channel_kind_capability_selected(
                    s, CHANNEL_KIND_TERMINAL)) {
                fprintf(stderr,
                        "session: channel-session READY first kind violates the selected terminal bundle — ERR_CAPS\n");
                session_protocol_error_close(s, ERR_CAPS);
                return;
            }
            observed = channel_session_observe_open(
                &s->channel_table, &first_open);
            if (observed == CHANNEL_OBSERVE_ERROR ||
                observed == CHANNEL_OBSERVE_CONFLICT) {
                fprintf(stderr,
                        "session: conflicting channel-session first OPEN — ERR_CAPS\n");
                session_protocol_error_close(s, ERR_CAPS);
                return;
            }
            if (observed == CHANNEL_OBSERVE_NEW) {
                s->channel_first_open = first_open;
                s->channel_first_open_valid = 1U;
                s->terminal_channel_handle = first_open.handle;
            } else if (observed == CHANNEL_OBSERVE_DUPLICATE) {
                uint8_t slot = (uint8_t)(first_open.handle & 0x0fU);
                if (s->channel_table.slots[slot].decision_type != 0U)
                    s->channel_runtime[slot].decision_pending = 1U;
            }
        }
    } else if (pt_len != 0) {
        fprintf(stderr, "session: non-empty legacy CTRL_READY — ERR_VERSION\n");
        session_protocol_error_close(s, ERR_VERSION);
        return;
    }

    /* NEED_ACK is reasserted state, not a one-shot event. A peer that has
     * already established still emits a fresh flags=0 response, healing a
     * lost acknowledgement without creating READY ping-pong. */
    if (s->negotiation_neg1 &&
        (flags & NEGOTIATION_READY_NEED_ACK) != 0) {
        if (!s->sent_ready) {
            /* The peer's READY may race our delayed initial READY.  An ACK
             * before our own handoff would let the peer open application
             * service while we still discard pre-service channel data. */
            s->ready_ack_pending = 1;
        } else if (send_ready_frame(s, 0,
                                    SESSION_TX_DONE_READY_ACK) != 0) {
            fprintf(stderr, "session: CTRL_READY acknowledgement failed\n");
        }
    }
    if (s->state == SESSION_ESTABLISHED)
        return;
    if (s->state != SESSION_KEY_DERIVING) {
        if (!(s->state == SESSION_REKEYING &&
              (flags & NEGOTIATION_READY_NEED_ACK) != 0))
            fprintf(stderr,
                    "session: CTRL_READY in unexpected state %d — ignoring\n",
                    s->state);
        return;
    }
    s->recv_ready = 1;
    fprintf(stderr, "session: received CTRL_READY%s\n",
            s->negotiation_neg1
                ? ((flags & NEGOTIATION_READY_NEED_ACK) ? " NEED_ACK" : " ACK")
                : " legacy");
    establish_session(s);
}

/* -------------------------------------------------------------------------
 * ERR_SESSION rate limit check
 * ---------------------------------------------------------------------- */

static void track_err_session(session_t *s)
{
    int64_t now = mono_ms();
    if (s->err_session_count == 0 ||
        now - s->err_session_window_start_ms > 10000) {
        s->err_session_count = 1;
        s->err_session_window_start_ms = now;
    } else {
        s->err_session_count++;
    }
    if (s->err_session_count >= 3) {
        fprintf(stderr, "session: 3 ERR_SESSION within 10s — closing\n");
        session_close(s);
    }
}

static int channel_kind_capability_selected(const session_t *s, uint8_t kind)
{
    uint32_t capability = 0U;

    if (!s)
        return 0;
    switch (kind) {
    case CHANNEL_KIND_TERMINAL:
        capability = UNMOOR_CAP_CHANNEL_TERMINAL_D36_V1;
        break;
    case CHANNEL_KIND_EXEC:
        capability = UNMOOR_CAP_CHANNEL_EXEC_D36_V1;
        break;
    default:
        return 0;
    }
    return (s->selected_caps & capability) != 0U;
}

static void channel_application_reset(session_channel_application_t *app)
{
    session_t *session;

    if (!app)
        return;
    session = app->session;
    if (session && app->child_lease &&
        session->child_transfer_lease_handle == app->handle) {
        session->child_transfer_lease_handle = 0U;
        session->child_transfer_lease_slot = 0U;
    }
    crypto_memzero(app, sizeof(*app));
    app->session = session;
}

static session_channel_application_t *channel_application_by_owner(
    session_t *s, attach_manager_owner_t owner, uint8_t *slot_out)
{
    uint8_t slot;

    if (!s || owner == ATTACH_MANAGER_LISTENER_OWNER)
        return NULL;
    for (slot = 1U; slot < CHANNEL_SESSION_SLOTS; slot++) {
        session_channel_application_t *app = &s->channel_application[slot];

        if (app->active && app->attach_bound && app->attach_owner == owner) {
            if (slot_out)
                *slot_out = slot;
            return app;
        }
    }
    return NULL;
}

static int channel_collect_child_close_fds(session_t *s, int fds[],
                                           size_t *count_out);

static int session_child_transfer_random_id(
    const child_transfer_table_t *table, uint64_t *transfer_id_out)
{
    unsigned int attempt;

    if (!table || !transfer_id_out)
        return -1;
    for (attempt = 0U; attempt < 4U; attempt++) {
        uint64_t candidate = 0U;
        int duplicate = 0;
        size_t slot;

        if (crypto_random_bytes((uint8_t *)&candidate,
                                sizeof(candidate)) != 0)
            return -1;
        if (candidate == 0U)
            continue;
        for (slot = 0U; slot < CHILD_TRANSFER_SLOT_COUNT; slot++) {
            const child_transfer_instance_t *instance =
                child_transfer_get(table, slot);

            if (instance && instance->transfer_id == candidate) {
                duplicate = 1;
                break;
            }
        }
        if (!duplicate) {
            *transfer_id_out = candidate;
            return 0;
        }
    }
    return -1;
}

static void session_child_transfer_refuse(session_t *s,
                                          attach_manager_owner_t owner,
                                          uint32_t code)
{
    if (!s || owner == ATTACH_MANAGER_LISTENER_OWNER || code < 1U ||
        (code > 4U && code != CHANNEL_CODE_CONFINED))
        return;
    if (attach_manager_queue_bulk_result(
            &s->attach_manager, owner, 0U, code, 0U) != ATTACH_LOCAL_OK)
        fprintf(stderr,
                "session: child-transfer local refusal could not reach attach owner=%llu\n",
                (unsigned long long)owner);
}

static void session_child_transfer_clear_pending(session_t *s,
                                                 uint32_t refusal_code)
{
    attach_manager_owner_t owner;

    if (!s || !s->child_transfer_pending)
        return;
    owner = s->child_transfer_pending_event.owner;
    s->child_transfer_pending = 0U;
    crypto_memzero(&s->child_transfer_pending_event,
                   sizeof(s->child_transfer_pending_event));
    if (refusal_code != CHANNEL_CODE_OK)
        session_child_transfer_refuse(s, owner, refusal_code);
}

static session_channel_application_t *session_child_lease_app(
    session_t *s, uint8_t *slot_out)
{
    uint8_t slot;
    session_channel_application_t *app;

    if (!s || s->child_transfer_lease_handle == 0U)
        return NULL;
    slot = s->child_transfer_lease_slot;
    if (slot == 0U || slot >= CHANNEL_SESSION_SLOTS)
        return NULL;
    app = &s->channel_application[slot];
    if (!app->active || !app->child_lease ||
        app->handle != s->child_transfer_lease_handle)
        return NULL;
    if (slot_out)
        *slot_out = slot;
    return app;
}

static int session_child_lease_ready(session_t *s)
{
    uint8_t slot = 0U;
    session_channel_application_t *app = session_child_lease_app(s, &slot);

    return app && app->child_lease_ready && !app->child_lease_fin_sent &&
           s->channel_table.slots[slot].state == CHANNEL_SLOT_ACTIVE;
}

static ssize_t channel_child_lease_output_write(void *context,
                                                const uint8_t *buffer,
                                                size_t length)
{
    session_channel_application_t *app = context;

    if (!app || !app->active || !app->child_lease || !buffer ||
        length == 0U) {
        errno = EINVAL;
        return -1;
    }
    if (!app->child_lease_ready && buffer[0] == UINT8_C(0x4c)) {
        app->child_lease_ready = 1U;
        return 1;
    }
    /* Exactly one private-stream readiness byte is allowed. Any other output
     * means the helper contract failed; never inject or silently discard it. */
    errno = EPROTO;
    return -1;
}

static int session_child_lease_begin(session_t *s,
                                     const attach_manager_event_t *event,
                                     int64_t now_ms)
{
    const char *arguments[2];
    channel_session_open_t descriptor;
    channel_session_open_t open;
    session_channel_application_t *app;
    size_t preface_length = 0U;
    uint16_t unavailable_mask = 0U;
    uint8_t reserved_slot;
    uint8_t slot;

    if (!s || !event || event->type != ATTACH_MANAGER_EVENT_OPEN ||
        event->version != ATTACH_LOCAL_VERSION_V2 || s->is_server ||
        s->child_transfer_pending || s->child_transfer_lease_handle != 0U ||
        s->channel_table.last_close_started) {
        errno = EBUSY;
        return -1;
    }
    arguments[0] = s->child_transfer_remote_command;
    arguments[1] = "--child-transfer-lease";
    memset(&descriptor, 0, sizeof(descriptor));
    descriptor.version = 1U;
    descriptor.kind = CHANNEL_KIND_EXEC;
    for (slot = 1U; slot < CHANNEL_SESSION_SLOTS; slot++) {
        if (s->channel_application[slot].active ||
            sync_active_instance(s, slot))
            unavailable_mask |= (uint16_t)(1U << slot);
    }
    if (channel_session_live_count(&s->channel_table) >=
            CHANNEL_SESSION_DATA_SLOTS ||
        channel_session_client_candidate_slot_excluding(
            &s->channel_table, unavailable_mask, &reserved_slot) != 0) {
        errno = ENOSPC;
        return -1;
    }
    app = &s->channel_application[reserved_slot];
    channel_application_reset(app);
    if (attach_local_exec_encode(
            2U, arguments, app->exec_preface, &preface_length) !=
            ATTACH_LOCAL_OK ||
        preface_length == 0U || preface_length > sizeof(app->exec_preface)) {
        channel_application_reset(app);
        errno = EINVAL;
        return -1;
    }
    if (sync_reserve_instance(s, reserved_slot, descriptor.kind) != 0) {
        channel_application_reset(app);
        return -1;
    }
    if (channel_session_client_begin_open_at(
            &s->channel_table, &descriptor, reserved_slot, &open) != 0) {
        (void)sync_free_instance(s, reserved_slot);
        channel_application_reset(app);
        return -1;
    }
    slot = reserved_slot;
    app->active = 1U;
    app->child_lease = 1U;
    app->handle = open.handle;
    app->kind = open.kind;
    app->exec_preface_used = preface_length;
    app->exec_preface_expected = preface_length;
    s->child_transfer_lease_slot = slot;
    s->child_transfer_lease_handle = open.handle;
    if (sync_bind_reserved_instance(
            s, slot, open.handle, open.kind, -1, -1,
            NULL, NULL, channel_child_lease_output_write, app) != 0) {
        (void)channel_session_decide_open(
            &s->channel_table, open.handle, 0, CHANNEL_CODE_RESOURCE);
        (void)sync_free_instance(s, slot);
        channel_application_reset(app);
        return -1;
    }
    s->child_transfer_pending_event = *event;
    s->child_transfer_pending = 1U;
    channel_runtime_arm_open(&s->channel_runtime[slot], now_ms, 1);
    session_channel_tick(s, now_ms);
    return 0;
}

static void session_child_lease_fail(session_t *s, uint8_t slot,
                                     int64_t now_ms)
{
    session_channel_application_t *app;

    if (!s || s->is_server || slot == 0U ||
        slot >= CHANNEL_SESSION_SLOTS)
        return;
    app = &s->channel_application[slot];
    if (!app->active || !app->child_lease ||
        app->handle != s->child_transfer_lease_handle)
        return;
    /* Ordinary zero-code retirement after our FIN is the expected handoff
     * between aggregate lease incarnations. A validated next transfer may be
     * waiting for this exact handle to retire; do not misclassify that clean
     * close as lease loss and refuse it with RESOURCE. */
    if (app->child_lease_fin_sent && app->receive_complete &&
        app->terminal_code == 0U &&
        child_transfer_active_count(&s->child_transfers) == 0U)
        return;
    session_child_transfer_clear_pending(s, CHANNEL_CODE_RESOURCE);
    if (child_transfer_active_count(&s->child_transfers) != 0U) {
        fprintf(stderr,
                "session: child-transfer aggregate child lease ended while transfers were active; cancelling children\n");
        (void)child_transfer_cancel_all(
            &s->child_transfers, now_ms, CHANNEL_PROCESS_TERM_GRACE_MS);
    }
}

static void session_child_lease_maybe_close(session_t *s)
{
    uint8_t slot = 0U;
    session_channel_application_t *app;

    if (!s || s->is_server || s->child_transfer_pending ||
        child_transfer_active_count(&s->child_transfers) != 0U)
        return;
    app = session_child_lease_app(s, &slot);
    if (!app || app->child_lease_fin_sent ||
        s->channel_table.slots[slot].state != CHANNEL_SLOT_ACTIVE)
        return;
    app->child_lease_fin_sent = 1U;
    sync_tx_fin_instance(s, slot, 0, 0);
}

/* Name a refused operand on the operator's terminal without echoing
 * whatever bytes the local attach client sent. Only printable ASCII survives;
 * everything else becomes '?', and the text is truncated. */
static void session_child_transfer_print_path(const uint8_t *path,
                                              size_t length)
{
    size_t i;
    size_t limit = length < 200U ? length : 200U;

    for (i = 0U; i < limit; i++) {
        int c = (int)path[i];

        (void)fputc(c >= 0x20 && c < 0x7f ? c : '?', stderr);
    }
    if (limit < length)
        (void)fputs("...", stderr);
}

static int session_child_transfer_start(session_t *s,
                                        const attach_manager_event_t *event,
                                        int64_t now_ms)
{
    attach_local_bulk_open_t open;
    child_transfer_command_t command;
    child_transfer_argv_t arguments;
    int close_fds[CHILD_TRANSFER_MAX_EXTRA_CLOSE_FDS];
    size_t close_fd_count = 0U;
    size_t slot = 0U;
    uint32_t handle = 0U;
    uint64_t transfer_id = 0U;
    uint32_t refusal = CHANNEL_CODE_RESOURCE;

    if (!s || !event || event->type != ATTACH_MANAGER_EVENT_OPEN ||
        event->version != ATTACH_LOCAL_VERSION_V2 || s->is_server ||
        !s->attach_socket_open)
        return -1;
    memset(&open, 0, sizeof(open));
    if (attach_local_bulk_open_decode(&event->record, &open) !=
            ATTACH_LOCAL_OK) {
        session_child_transfer_refuse(
            s, event->owner, CHANNEL_CODE_POLICY);
        return 0;
    }
    if (!s->child_transfer_configured ||
        s->channel_table.last_close_started) {
        session_child_transfer_refuse(
            s, event->owner, CHANNEL_CODE_POLICY);
        return 0;
    }
    /* Refuse an operand outside the confinement roots here, before a
     * handle or a generation is spent and before the fork. The child would
     * otherwise inherit this domain (nested Landlock domains only narrow) and
     * die on an EACCES with its stderr on /dev/null. */
    {
        char local[ATTACH_LOCAL_BULK_PATH_MAX + 1U];
        size_t local_length = open.local_path_length;

        if (local_length > ATTACH_LOCAL_BULK_PATH_MAX)
            local_length = ATTACH_LOCAL_BULK_PATH_MAX;
        memcpy(local, open.local_path, local_length);
        local[local_length] = '\0';
        if (!confine_path_within_roots(local)) {
            fprintf(stderr, "confine: ");
            session_child_transfer_print_path(open.local_path,
                                              open.local_path_length);
            fprintf(stderr,
                    " is outside the confinement roots; restart with "
                    "--confine-root PATH or --confine off\n");
            session_child_transfer_refuse(
                s, event->owner, CHANNEL_CODE_CONFINED);
            crypto_memzero(&open, sizeof(open));
            crypto_memzero(local, sizeof(local));
            return 0;
        }
        crypto_memzero(local, sizeof(local));
    }
    if (child_transfer_direction_active(&s->child_transfers, open.kind)) {
        session_child_transfer_refuse(
            s, event->owner, CHANNEL_CODE_CAPACITY);
        return 0;
    }
    if (child_transfer_active_count(&s->child_transfers) == 0U &&
        s->child_transfer_lease_handle == 0U) {
        if (session_child_lease_begin(s, event, now_ms) != 0)
            session_child_transfer_refuse(
                s, event->owner,
                errno == ENOSPC ? CHANNEL_CODE_CAPACITY
                                : CHANNEL_CODE_RESOURCE);
        crypto_memzero(&open, sizeof(open));
        return 0;
    }
    if (!session_child_lease_ready(s)) {
        if (child_transfer_active_count(&s->child_transfers) == 0U &&
            !s->child_transfer_pending) {
            s->child_transfer_pending_event = *event;
            s->child_transfer_pending = 1U;
        } else {
            session_child_transfer_refuse(
                s, event->owner, CHANNEL_CODE_CAPACITY);
        }
        crypto_memzero(&open, sizeof(open));
        return 0;
    }
    if (child_transfer_next_handle(
            &s->child_transfers, open.kind, &slot, &handle) != 0) {
        refusal = errno == EBUSY ? CHANNEL_CODE_CAPACITY
                                 : CHANNEL_CODE_RESOURCE;
        session_child_transfer_refuse(s, event->owner, refusal);
        return 0;
    }
    if (session_child_transfer_random_id(
            &s->child_transfers, &transfer_id) != 0) {
        session_child_transfer_refuse(
            s, event->owner, CHANNEL_CODE_RESOURCE);
        return 0;
    }
    memset(&command, 0, sizeof(command));
    command.local_path = open.local_path;
    command.local_path_length = open.local_path_length;
    command.remote_path = open.remote_path;
    command.remote_path_length = open.remote_path_length;
    command.transfer_id = transfer_id;
    command.wire_budget = open.wire_budget;
    command.stall_seconds = open.stall_seconds;
    command.kind = open.kind;
    command.options = open.options;
    if (child_transfer_argv_build(
            &s->child_transfer_policy, &command, &arguments) != 0 ||
        channel_collect_child_close_fds(
            s, close_fds, &close_fd_count) != 0) {
        session_child_transfer_refuse(
            s, event->owner, CHANNEL_CODE_RESOURCE);
        crypto_memzero(&open, sizeof(open));
        crypto_memzero(&command, sizeof(command));
        return 0;
    }
    if (child_transfer_spawn(
            &s->child_transfers, slot, open.kind, event->owner, handle,
            transfer_id, arguments.argv, close_fds,
            close_fd_count) != 0) {
        session_child_transfer_refuse(
            s, event->owner, CHANNEL_CODE_RESOURCE);
        crypto_memzero(&open, sizeof(open));
        crypto_memzero(&command, sizeof(command));
        crypto_memzero(&arguments, sizeof(arguments));
        return 0;
    }
    if (attach_manager_queue_bulk_result(
            &s->attach_manager, event->owner, handle,
            CHANNEL_CODE_OK, transfer_id) != ATTACH_LOCAL_OK) {
        (void)child_transfer_cancel(
            &s->child_transfers, slot, handle, now_ms,
            CHANNEL_PROCESS_TERM_GRACE_MS);
        fprintf(stderr,
                "session: child-transfer accepted child lost its local result owner=%llu\n",
                (unsigned long long)event->owner);
    }
    crypto_memzero(&open, sizeof(open));
    crypto_memzero(&command, sizeof(command));
    crypto_memzero(&arguments, sizeof(arguments));
    return 0;
}

static void session_child_lease_start_pending(session_t *s, int64_t now_ms)
{
    attach_manager_event_t pending;

    if (!s || !s->child_transfer_pending)
        return;
    pending = s->child_transfer_pending_event;
    if (s->child_transfer_lease_handle == 0U) {
        session_child_transfer_clear_pending(s, CHANNEL_CODE_OK);
        if (session_child_lease_begin(s, &pending, now_ms) != 0)
            session_child_transfer_refuse(
                s, pending.owner,
                errno == ENOSPC ? CHANNEL_CODE_CAPACITY
                                : CHANNEL_CODE_RESOURCE);
        crypto_memzero(&pending, sizeof(pending));
        return;
    }
    if (!session_child_lease_ready(s)) {
        crypto_memzero(&pending, sizeof(pending));
        return;
    }
    session_child_transfer_clear_pending(s, CHANNEL_CODE_OK);
    if (session_child_transfer_start(s, &pending, now_ms) != 0)
        session_child_transfer_refuse(
            s, pending.owner, CHANNEL_CODE_RESOURCE);
    crypto_memzero(&pending, sizeof(pending));
    session_child_lease_maybe_close(s);
}

static void session_child_transfer_tick(session_t *s, int64_t now_ms)
{
    size_t slot;

    if (!s)
        return;
    if (child_transfer_maintain(&s->child_transfers, now_ms) < 0) {
        if (!s->child_transfer_manager_failed) {
            fprintf(stderr,
                    "session: child-transfer supervisor failed locally: %s\n",
                    strerror(errno));
            s->child_transfer_manager_failed = 1U;
        }
        (void)child_transfer_cancel_all(
            &s->child_transfers, now_ms, CHANNEL_PROCESS_TERM_GRACE_MS);
    }
    for (slot = 0U; slot < CHILD_TRANSFER_SLOT_COUNT; slot++) {
        child_transfer_instance_t *instance = &s->child_transfers.slots[slot];
        attach_manager_connection_info_t info;
        int record_valid = 0;
        uint32_t record_code = (uint32_t)BULK_CODE_PROTOCOL;
        uint32_t process_exit_code = UINT32_MAX;
        uint32_t final_code;
        int complete;
        int info_status;

        if (!instance->active)
            continue;
        complete = child_transfer_result(
            &s->child_transfers, slot, instance->handle, &record_valid,
            &record_code, &process_exit_code);
        if (complete <= 0)
            continue;
        final_code = child_transfer_normalize_result(
            instance, record_valid, record_code, process_exit_code);
        info_status = s->attach_socket_open
            ? attach_manager_connection_info(
                  &s->attach_manager, instance->owner, &info)
            : ATTACH_LOCAL_CLOSED;
        if (info_status == ATTACH_LOCAL_OK && !instance->close_queued) {
            if (info.state == ATTACH_MANAGER_STATE_ACTIVE ||
                info.state == ATTACH_MANAGER_STATE_CLOSING) {
                int close_status = attach_manager_queue_close(
                    &s->attach_manager, instance->owner, final_code);

                if (close_status == ATTACH_LOCAL_OK ||
                    close_status == ATTACH_LOCAL_CLOSED)
                    instance->close_queued = 1U;
            }
        } else if (info_status == ATTACH_LOCAL_CLOSED) {
            instance->close_queued = 1U;
        }
        if (instance->close_queued) {
            int release_status = s->attach_socket_open
                ? attach_manager_release(
                      &s->attach_manager, instance->owner)
                : ATTACH_LOCAL_CLOSED;

            if (release_status == ATTACH_LOCAL_OK ||
                release_status == ATTACH_LOCAL_CLOSED) {
                (void)child_transfer_release(
                    &s->child_transfers, slot, instance->handle);
            }
        }
    }
    session_child_lease_maybe_close(s);
}

static event_log_reason_t channel_code_event_reason(uint32_t code)
{
    switch (code) {
    case CHANNEL_CODE_OK:
        return EVENT_LOG_REASON_COMPLETED;
    case CHANNEL_CODE_POLICY:
    case CHANNEL_CODE_KIND_UNSUPPORTED:
        return EVENT_LOG_REASON_NOT_INTERESTED;
    case CHANNEL_CODE_CAPACITY:
        return EVENT_LOG_REASON_QUOTA;
    case CHANNEL_CODE_RESOURCE:
        return EVENT_LOG_REASON_IO_ERROR;
    case CHANNEL_CODE_TIMEOUT:
    case CHANNEL_CODE_STALLED:
        return EVENT_LOG_REASON_NO_PROGRESS;
    case CHANNEL_CODE_PROTOCOL:
    default:
        return EVENT_LOG_REASON_PROTOCOL_ERROR;
    }
}

static int channel_close_fd_add(int fds[], size_t *count, int fd)
{
    size_t i;

    if (!fds || !count || fd <= STDERR_FILENO)
        return 0;
    for (i = 0U; i < *count; i++)
        if (fds[i] == fd)
            return 0;
    if (*count >= CHANNEL_PROCESS_MAX_EXTRA_CLOSE_FDS) {
        errno = ENOSPC;
        return -1;
    }
    fds[(*count)++] = fd;
    return 0;
}

static int channel_collect_child_close_fds(session_t *s, int fds[],
                                           size_t *count_out)
{
    int receive_fds[MULTIPATH_PATHS_MAX];
    int receive_count = 0;
    size_t count = 0U;
    size_t i;

    if (!s || !fds || !count_out || !s->transport || !s->transport->ops) {
        errno = EINVAL;
        return -1;
    }
    if (s->transport->ops->get_recv_fds) {
        receive_count = s->transport->ops->get_recv_fds(
            s->transport, receive_fds);
        if (receive_count < 0 || receive_count > (int)MULTIPATH_PATHS_MAX)
            return -1;
        for (int n = 0; n < receive_count; n++)
            if (channel_close_fd_add(fds, &count, receive_fds[n]) != 0)
                return -1;
    } else if (s->transport->ops->get_fd &&
               channel_close_fd_add(
                   fds, &count,
                   s->transport->ops->get_fd(s->transport)) != 0) {
        return -1;
    }
    if (s->transport->ops->get_send_fd &&
        channel_close_fd_add(
            fds, &count,
            s->transport->ops->get_send_fd(s->transport)) != 0)
        return -1;
    if (channel_close_fd_add(fds, &count, s->pty_master_fd) != 0)
        return -1;
    if (s->event_log_enabled &&
        channel_close_fd_add(fds, &count, s->event_sink.fd) != 0)
        return -1;
    if (s->attach_socket_open) {
        if (channel_close_fd_add(
                fds, &count, s->attach_manager.listener.listen_fd) != 0 ||
            channel_close_fd_add(
                fds, &count, s->attach_manager.listener.base_fd) != 0 ||
            channel_close_fd_add(
                fds, &count, s->attach_manager.listener.directory_fd) != 0)
            return -1;
        for (i = 0U; i < ATTACH_LOCAL_MAX_CONNECTIONS; i++)
            if (channel_close_fd_add(
                    fds, &count,
                    s->attach_manager.listener.connections[i].fd) != 0)
                return -1;
    }
    *count_out = count;
    return 0;
}

static ssize_t channel_exec_preface_write(void *context,
                                          const uint8_t *buffer,
                                          size_t length)
{
    session_channel_application_t *app = context;
    session_t *s;
    size_t consumed = 0U;

    if (!app || !app->session || !buffer || length == 0U ||
        !app->active || app->kind != CHANNEL_KIND_EXEC ||
        app->exec_spawned) {
        errno = EINVAL;
        return -1;
    }
    s = app->session;
    while (consumed < length) {
        size_t expected = 0U;
        int boundary;

        if (app->exec_preface_used >= sizeof(app->exec_preface)) {
            errno = EPROTO;
            return -1;
        }
        app->exec_preface[app->exec_preface_used++] = buffer[consumed++];
        boundary = attach_local_exec_prefix_boundary(
            app->exec_preface, app->exec_preface_used, &expected);
        if (boundary < 0) {
            errno = EPROTO;
            return -1;
        }
        if (boundary > 0) {
            attach_local_exec_argv_t decoded;
            int close_fds[CHANNEL_PROCESS_MAX_EXTRA_CLOSE_FDS];
            size_t close_fd_count = 0U;
            uint8_t slot = (uint8_t)(app->handle & 0x0fU);
            int input_fd;
            int output_fd;

            if (expected != app->exec_preface_used ||
                attach_local_exec_decode(app->exec_preface, expected,
                                         &decoded) != ATTACH_LOCAL_OK) {
                fprintf(stderr,
                        "session: channel-session EXEC preface rejected "
                        "(slot=%u bytes=%zu expected=%zu)\n",
                        (unsigned int)slot, app->exec_preface_used,
                        expected);
                crypto_memzero(&decoded, sizeof(decoded));
                errno = EPROTO;
                return -1;
            }
            if (channel_collect_child_close_fds(
                    s, close_fds, &close_fd_count) != 0) {
                fprintf(stderr,
                        "session: channel-session EXEC descriptor snapshot failed "
                        "(slot=%u): %s\n",
                        (unsigned int)slot, strerror(errno));
                crypto_memzero(&decoded, sizeof(decoded));
                return -1;
            }
            if (channel_process_spawn_exec(
                    &s->channel_processes, (size_t)(slot - 1U), app->handle,
                    app->exec_preface, expected, close_fds,
                    close_fd_count) != 0) {
                fprintf(stderr,
                        "session: channel-session EXEC spawn failed "
                        "(slot=%u): %s\n",
                        (unsigned int)slot, strerror(errno));
                crypto_memzero(&decoded, sizeof(decoded));
                return -1;
            }
            crypto_memzero(&decoded, sizeof(decoded));
            input_fd = channel_process_input_fd(
                &s->channel_processes, (size_t)(slot - 1U), app->handle);
            output_fd = channel_process_output_fd(
                &s->channel_processes, (size_t)(slot - 1U), app->handle);
            if (input_fd < 0 || output_fd < 0 ||
                sync_instance_set_io(
                    s, slot, app->handle, output_fd, input_fd,
                    NULL, NULL, NULL, NULL) != 0) {
                (void)channel_process_cancel(
                    &s->channel_processes, (size_t)(slot - 1U), app->handle,
                    mono_ms(), CHANNEL_PROCESS_TERM_GRACE_MS);
                errno = EIO;
                return -1;
            }
            app->exec_preface_expected = expected;
            app->exec_spawned = 1U;
            if (app->signal_pending && !app->signal_admitted) {
                if (channel_process_signal(
                        &s->channel_processes, (size_t)(slot - 1U),
                        app->handle, (int)app->pending_signal) != 0 &&
                    errno != ESRCH) {
                    app->signal_pending = 0U;
                    app->pending_signal = 0U;
                    session_channel_stream_io_failed(
                        s, slot, CHANNEL_CODE_RESOURCE);
                    errno = EIO;
                    return -1;
                }
                app->signal_pending = 0U;
                app->pending_signal = 0U;
            }
            break;
        }
    }
    return (ssize_t)consumed;
}

static ssize_t channel_attach_output_write(void *context,
                                           const uint8_t *buffer,
                                           size_t length)
{
    session_channel_application_t *app = context;
    session_t *s;
    size_t offered;
    uint64_t cookie;
    int status;

    if (!app || !app->session || !buffer || length == 0U ||
        !app->active || !app->attach_bound) {
        errno = EINVAL;
        return -1;
    }
    s = app->session;
    if (!s->attach_socket_open) {
        errno = EPIPE;
        return -1;
    }
    if (app->output_waiting) {
        if (!app->output_delivered) {
            errno = EAGAIN;
            return -1;
        }
        offered = app->output_length;
        app->output_waiting = 0U;
        app->output_delivered = 0U;
        app->output_length = 0U;
        return (ssize_t)offered;
    }
    offered = length > ATTACH_LOCAL_MAX_PAYLOAD
        ? ATTACH_LOCAL_MAX_PAYLOAD : length;
    cookie = app->output_cookie + 1U;
    if (cookie == 0U)
        cookie = 1U;
    status = attach_manager_queue_data(
        &s->attach_manager, app->attach_owner, buffer, offered, cookie);
    if (status == ATTACH_LOCAL_OK) {
        app->output_cookie = cookie;
        app->output_length = offered;
        app->output_waiting = 1U;
        app->output_delivered = 0U;
        errno = EAGAIN;
        return -1;
    }
    errno = status == ATTACH_LOCAL_WOULD_BLOCK ? EAGAIN : EPIPE;
    return -1;
}

static int channel_application_start_local_open(
    session_t *s, const attach_manager_event_t *event, int64_t now_ms)
{
    channel_session_open_t descriptor;
    channel_session_open_t open;
    session_channel_application_t *app;
    uint8_t reserved_slot;
    uint8_t slot;
    uint16_t unavailable_mask = 0U;
    uint32_t refusal = CHANNEL_CODE_CAPACITY;

    if (!s || !event || event->type != ATTACH_MANAGER_EVENT_OPEN ||
        s->is_server || !s->attach_socket_open)
        return -1;
    memset(&descriptor, 0, sizeof(descriptor));
    descriptor.version = 1U;
    descriptor.kind = event->kind;
    if (!channel_kind_capability_selected(s, descriptor.kind)) {
        refusal = CHANNEL_CODE_KIND_UNSUPPORTED;
        goto refuse_without_handle;
    }
    if (descriptor.kind == CHANNEL_KIND_TERMINAL) {
        if (event->record.length != 4U) {
            refusal = CHANNEL_CODE_POLICY;
            goto refuse_without_handle;
        }
        descriptor.parameter0 = (uint32_t)load16le(event->record.payload) |
            ((uint32_t)load16le(event->record.payload + 2U) << 16);
    } else if (descriptor.kind == CHANNEL_KIND_EXEC) {
        attach_local_exec_argv_t decoded;

        if (attach_local_exec_decode(event->record.payload,
                                     event->record.length,
                                     &decoded) != ATTACH_LOCAL_OK) {
            refusal = CHANNEL_CODE_POLICY;
            goto refuse_without_handle;
        }
        crypto_memzero(&decoded, sizeof(decoded));
    } else {
        refusal = CHANNEL_CODE_KIND_UNSUPPORTED;
        goto refuse_without_handle;
    }
    if (s->channel_table.last_close_started) {
        refusal = CHANNEL_CODE_POLICY;
        goto refuse_without_handle;
    }
    for (slot = 1U; slot < CHANNEL_SESSION_SLOTS; slot++) {
        if (s->channel_application[slot].active ||
            sync_active_instance(s, slot))
            unavailable_mask |= (uint16_t)(1U << slot);
    }
    if (channel_session_live_count(&s->channel_table) >=
            CHANNEL_SESSION_DATA_SLOTS ||
        channel_session_client_candidate_slot_excluding(
            &s->channel_table, unavailable_mask, &reserved_slot) != 0)
        goto refuse_without_handle;
    app = &s->channel_application[reserved_slot];
    if (app->active || sync_active_instance(s, reserved_slot))
        goto refuse_without_handle;
    if (sync_reserve_instance(s, reserved_slot, descriptor.kind) != 0) {
        refusal = errno == ENOSPC ? CHANNEL_CODE_CAPACITY
                                  : CHANNEL_CODE_RESOURCE;
        goto refuse_without_handle;
    }
    if (channel_session_client_begin_open_at(
            &s->channel_table, &descriptor, reserved_slot, &open) != 0) {
        (void)sync_free_instance(s, reserved_slot);
        refusal = s->channel_table.last_close_started
            ? CHANNEL_CODE_POLICY : CHANNEL_CODE_CAPACITY;
        goto refuse_without_handle;
    }
    slot = reserved_slot;
    channel_application_reset(app);
    app->active = 1U;
    app->attach_bound = 1U;
    app->attach_owner = event->owner;
    app->handle = open.handle;
    app->kind = open.kind;
    if (open.kind == CHANNEL_KIND_EXEC) {
        memcpy(app->exec_preface, event->record.payload,
               event->record.length);
        app->exec_preface_used = event->record.length;
        app->exec_preface_expected = event->record.length;
    }
    if (sync_bind_reserved_instance(
            s, slot, open.handle, open.kind, -1, -1,
            NULL, NULL, channel_attach_output_write, app) != 0) {
        (void)channel_session_decide_open(
            &s->channel_table, open.handle, 0, CHANNEL_CODE_RESOURCE);
        (void)attach_manager_queue_result(
            &s->attach_manager, event->owner, open.handle,
            CHANNEL_CODE_RESOURCE);
        (void)sync_free_instance(s, slot);
        channel_application_reset(app);
        return 0;
    }
    channel_runtime_arm_open(&s->channel_runtime[slot], now_ms, 1);
    session_channel_tick(s, now_ms);
    return 0;

refuse_without_handle:
    (void)attach_manager_queue_result(
        &s->attach_manager, event->owner, 0U, refusal);
    return 0;
}

static int channel_application_begin_close(session_t *s, uint8_t slot,
                                           uint32_t code, int64_t now_ms)
{
    session_channel_application_t *app;
    channel_session_slot_t *entry;

    if (!s || slot == 0U || slot >= CHANNEL_SESSION_SLOTS)
        return -1;
    app = &s->channel_application[slot];
    entry = &s->channel_table.slots[slot];
    if (entry->state == CHANNEL_SLOT_CLOSING ||
        entry->state == CHANNEL_SLOT_RETIRED) {
        app->cleanup_pending = 1U;
        return 0;
    }
    if (channel_session_begin_close(&s->channel_table, entry->handle,
                                    code) != 0)
        return -1;
    channel_runtime_arm_close(&s->channel_runtime[slot], now_ms);
    app->cleanup_pending = 1U;
    session_event_emit_channel(
        s, EVENT_LOG_EVENT_CLOSE, channel_code_event_reason(code),
        entry->handle, entry->open.kind, code, now_ms);
    session_channel_tick(s, now_ms);
    return 0;
}

static void channel_application_cancel_process(session_t *s, uint8_t slot,
                                               int64_t now_ms)
{
    session_channel_application_t *app;

    if (!s || slot == 0U || slot >= CHANNEL_SESSION_SLOTS)
        return;
    app = &s->channel_application[slot];
    if (app->exec_spawned ||
        channel_process_get(&s->channel_processes,
                            (size_t)(slot - 1U)) != NULL)
        (void)channel_process_cancel(
            &s->channel_processes, (size_t)(slot - 1U), app->handle,
            now_ms, CHANNEL_PROCESS_TERM_GRACE_MS);
}

static int channel_application_attach_event(
    session_t *s, const attach_manager_event_t *event, int64_t now_ms)
{
    session_channel_application_t *app;
    size_t child_slot = 0U;
    uint8_t slot = 0U;

    if (!s || !event)
        return 0;
    if (event->type == ATTACH_MANAGER_EVENT_OPEN &&
        event->version == ATTACH_LOCAL_VERSION_V2) {
        if (session_child_transfer_start(s, event, now_ms) != 0)
            session_child_transfer_refuse(
                s, event->owner, CHANNEL_CODE_RESOURCE);
        return 0;
    }
    if (s->child_transfer_pending &&
        event->owner == s->child_transfer_pending_event.owner &&
        (event->type == ATTACH_MANAGER_EVENT_CLOSE ||
         event->type == ATTACH_MANAGER_EVENT_CANCEL)) {
        session_child_transfer_clear_pending(s, CHANNEL_CODE_POLICY);
        session_child_lease_maybe_close(s);
        return 0;
    }
    if (child_transfer_find_owner(
            &s->child_transfers, event->owner, &child_slot) == 0) {
        child_transfer_instance_t *instance =
            &s->child_transfers.slots[child_slot];

        if (event->type == ATTACH_MANAGER_EVENT_CLOSE ||
            event->type == ATTACH_MANAGER_EVENT_CANCEL) {
            (void)child_transfer_cancel(
                &s->child_transfers, child_slot, instance->handle, now_ms,
                CHANNEL_PROCESS_TERM_GRACE_MS);
        }
        return 0;
    }
    if (event->type == ATTACH_MANAGER_EVENT_OPEN) {
        if (channel_application_start_local_open(s, event, now_ms) != 0)
            (void)attach_manager_queue_result(
                &s->attach_manager, event->owner, 0U,
                CHANNEL_CODE_RESOURCE);
        return 0;
    }
    app = channel_application_by_owner(s, event->owner, &slot);
    if (!app)
        return 0;
    switch (event->type) {
    case ATTACH_MANAGER_EVENT_DATA:
        if (!app->pending_input && event->payload_length <=
                sync_tx_room_instance(s, slot)) {
            if (sync_tx_append_instance(
                    s, slot, event->record.payload,
                    event->payload_length) != 0)
                session_channel_stream_io_failed(
                    s, slot, CHANNEL_CODE_RESOURCE);
            else
                session_pacer_charge_read(s, event->payload_length);
        } else if (!app->pending_input &&
                   event->payload_length <= sizeof(app->pending_input_bytes)) {
            memcpy(app->pending_input_bytes, event->record.payload,
                   event->payload_length);
            app->pending_input_length = event->payload_length;
            app->pending_input = 1U;
        } else {
            session_channel_stream_io_failed(
                s, slot, CHANNEL_CODE_RESOURCE);
        }
        return 1;
    case ATTACH_MANAGER_EVENT_EOF:
        sync_tx_fin_instance(s, slot, 0, 0);
        break;
    case ATTACH_MANAGER_EVENT_RESIZE:
        if (attach_local_resize_decode(
                &event->record, &app->pending_rows,
                &app->pending_columns, &app->pending_xpixel,
                &app->pending_ypixel) == ATTACH_LOCAL_OK) {
            app->resize_pending = 1U;
            app->resize_admitted = 0U;
        } else {
            session_channel_stream_io_failed(
                s, slot, CHANNEL_CODE_PROTOCOL);
        }
        break;
    case ATTACH_MANAGER_EVENT_SIGNAL:
        if (app->signal_pending ||
            attach_local_signal_decode(
                &event->record, &app->pending_signal) != ATTACH_LOCAL_OK) {
            session_channel_stream_io_failed(
                s, slot, CHANNEL_CODE_PROTOCOL);
        } else {
            app->signal_pending = 1U;
            app->signal_admitted = 0U;
        }
        break;
    case ATTACH_MANAGER_EVENT_CLOSE:
    case ATTACH_MANAGER_EVENT_CANCEL:
        if (channel_application_begin_close(
                s, slot, event->code == 0U ? CHANNEL_CODE_PROTOCOL
                                           : event->code,
                now_ms) != 0)
            session_channel_stream_io_failed(
                s, slot, CHANNEL_CODE_PROTOCOL);
        (void)sync_instance_detach_io(s, slot, app->handle);
        break;
    case ATTACH_MANAGER_EVENT_DATA_DELIVERED:
        if (!app->output_waiting ||
            event->completion_cookie != app->output_cookie ||
            event->payload_length != app->output_length) {
            session_channel_stream_io_failed(
                s, slot, CHANNEL_CODE_PROTOCOL);
        } else {
            app->output_delivered = 1U;
            sync_rx_deliver_instance(s, slot);
        }
        break;
    case ATTACH_MANAGER_EVENT_NONE:
    case ATTACH_MANAGER_EVENT_OPEN:
        break;
    }
    return 0;
}

static int channel_application_aux_submit(session_t *s, uint8_t slot,
                                          uint8_t type,
                                          const uint8_t *body,
                                          size_t body_length,
                                          uint64_t generation,
                                          uint32_t coalesce_key)
{
    sync_instance_binding_t *binding;
    uint8_t wire[FRAME_MAX_LEN];

    if (!s || slot == 0U || slot >= CHANNEL_SESSION_SLOTS ||
        !body || generation == 0U ||
        body_length > sizeof(wire) - CHANNEL_SESSION_HANDLE_BYTES)
        return -1;
    binding = &s->sync_binding[slot];
    if (!binding->configured || binding->handle == 0U ||
        channel_session_resolve_data(
            &s->channel_table, binding->handle, binding->kind) !=
                CHANNEL_OBSERVE_NEW)
        return -1;
    store32le(wire, binding->handle);
    memcpy(wire + CHANNEL_SESSION_HANDLE_BYTES, body, body_length);
    return wire_submit_stream(
        s, SEND_LANE_INTERACTIVE,
        (uint8_t)((1U << 4) | CHAN_FF_BIT), type,
        wire, body_length + CHANNEL_SESSION_HANDLE_BYTES,
        SESSION_TX_DONE_NONE, 0U, 0U, coalesce_key,
        binding->handle, generation);
}

static void channel_application_drive_aux(session_t *s, uint8_t slot)
{
    session_channel_application_t *app;

    if (!s || slot == 0U || slot >= CHANNEL_SESSION_SLOTS)
        return;
    app = &s->channel_application[slot];
    if (!app->active)
        return;
    if (app->signal_admitted &&
        !session_stream_owner_active(s, app->handle)) {
        app->signal_pending = 0U;
        app->signal_admitted = 0U;
        app->pending_signal = 0U;
    }
    if (app->resize_admitted &&
        !session_stream_owner_active(s, app->handle)) {
        app->resize_pending = 0U;
        app->resize_admitted = 0U;
    }
    if (!s->is_server && app->signal_pending && !app->signal_admitted) {
        uint8_t body[4] = { app->pending_signal, 0U, 0U, 0U };

        if (channel_application_aux_submit(
                s, slot, PTY_SIGNAL, body, sizeof(body),
                ((uint64_t)app->output_cookie << 8) |
                    (uint64_t)app->pending_signal | UINT64_C(1),
                0U) == 0)
            app->signal_admitted = 1U;
    }
    if (!s->is_server && app->resize_pending && !app->resize_admitted) {
        uint8_t body[8];

        body[0] = (uint8_t)app->pending_rows;
        body[1] = (uint8_t)(app->pending_rows >> 8);
        body[2] = (uint8_t)app->pending_columns;
        body[3] = (uint8_t)(app->pending_columns >> 8);
        body[4] = (uint8_t)app->pending_xpixel;
        body[5] = (uint8_t)(app->pending_xpixel >> 8);
        body[6] = (uint8_t)app->pending_ypixel;
        body[7] = (uint8_t)(app->pending_ypixel >> 8);
        if (channel_application_aux_submit(
                s, slot, PTY_RESIZE, body, sizeof(body),
                ((uint64_t)app->pending_rows << 48) |
                    ((uint64_t)app->pending_columns << 32) |
                    ((uint64_t)app->pending_xpixel << 16) |
                    (uint64_t)app->pending_ypixel | UINT64_C(1),
                WIRE_COALESCE_PTY_RESIZE | (uint32_t)slot) == 0)
            app->resize_admitted = 1U;
    }
}

static void channel_application_try_cleanup(session_t *s, uint8_t slot)
{
    session_channel_application_t *app;
    channel_session_slot_t *entry;
    int sync_done;
    int process_done = 1;
    int attach_done = 1;

    if (!s || slot == 0U || slot >= CHANNEL_SESSION_SLOTS)
        return;
    app = &s->channel_application[slot];
    entry = &s->channel_table.slots[slot];
    if (!app->active || !app->cleanup_pending ||
        (entry->state != CHANNEL_SLOT_RETIRED &&
         !entry->peer_close_seen))
        return;
    (void)sync_instance_detach_io(s, slot, app->handle);
    sync_done = sync_free_instance(s, slot) == 0;
    if (slot == (uint8_t)(s->terminal_channel_handle & 0x0fU) &&
        app->handle == s->terminal_channel_handle) {
        (void)channel_pty_close_instance(s);
    } else {
        const channel_process_instance_t *process = channel_process_get(
            &s->channel_processes, (size_t)(slot - 1U));

        if (process) {
            uint32_t code;

            process_done = channel_process_result(
                &s->channel_processes, (size_t)(slot - 1U), app->handle,
                &code) == 1 &&
                channel_process_release(
                    &s->channel_processes, (size_t)(slot - 1U),
                    app->handle) == 0;
        }
    }
    if (app->attach_bound && s->attach_socket_open) {
        int status = attach_manager_release(
            &s->attach_manager, app->attach_owner);

        attach_done = status == ATTACH_LOCAL_OK ||
                      status == ATTACH_LOCAL_CLOSED;
    }
    if (sync_done && process_done && attach_done)
        channel_application_reset(app);
}

/*
 * A peer CHANNEL_CLOSE can overtake the final physical write to a local
 * attach socket.  The local grammar is DATA*, EXIT, CLOSE: latching CLOSE
 * after queue_exit() returned WOULD_BLOCK marks output ended and makes the
 * later EXIT retry fail as a protocol error.  Drive the three boundaries in
 * order and leave each retry with the event loop.
 */
static void channel_application_drive_attach_completion(session_t *s,
                                                        uint8_t slot)
{
    session_channel_application_t *app;
    channel_session_slot_t *entry;
    int status;

    if (!s || s->is_server || slot == 0U ||
        slot >= CHANNEL_SESSION_SLOTS)
        return;
    app = &s->channel_application[slot];
    entry = &s->channel_table.slots[slot];
    if (!app->active || !app->attach_bound || !s->attach_socket_open ||
        !app->receive_complete)
        return;

    if (!app->exit_queued) {
        status = attach_manager_queue_exit(
            &s->attach_manager, app->attach_owner,
            (int32_t)app->terminal_code);
        if (status == ATTACH_LOCAL_OK)
            app->exit_queued = 1U;
        else if (status != ATTACH_LOCAL_WOULD_BLOCK &&
                 status != ATTACH_LOCAL_CLOSED) {
            session_channel_stream_io_failed(
                s, slot, CHANNEL_CODE_RESOURCE);
            return;
        }
    }
    if (!app->exit_queued || !entry->peer_close_seen ||
        app->close_queued)
        return;

    status = attach_manager_queue_close(
        &s->attach_manager, app->attach_owner, entry->peer_close_code);
    if (status == ATTACH_LOCAL_OK)
        app->close_queued = 1U;
    else if (status != ATTACH_LOCAL_WOULD_BLOCK &&
             status != ATTACH_LOCAL_CLOSED)
        session_channel_stream_io_failed(s, slot, CHANNEL_CODE_RESOURCE);
}

static void channel_application_pump_process_source(session_t *s,
                                                    uint8_t slot)
{
    session_channel_application_t *app;
    uint8_t bytes[UNMOOR_TERMINAL_PLAINTEXT_MAX];
    size_t limit;
    ssize_t received;

    if (!s || slot == 0U || slot >= CHANNEL_SESSION_SLOTS)
        return;
    app = &s->channel_application[slot];
    if (!s->is_server || !app->active ||
        app->handle == s->terminal_channel_handle ||
        app->process_output_eof || app->cleanup_pending)
        return;
    limit = sync_tx_read_limit_instance(s, slot);
    if (limit == 0U)
        return;
    if (limit > sizeof(bytes))
        limit = sizeof(bytes);
    received = sync_instance_read_source(s, slot, bytes, limit);
    if (received > 0) {
        if (sync_tx_append_instance(
                s, slot, bytes, (size_t)received) != 0) {
            session_channel_stream_io_failed(
                s, slot, CHANNEL_CODE_RESOURCE);
        } else {
            session_pacer_charge_read(s, (size_t)received);
        }
        return;
    }
    if (received == 0 || errno == EIO) {
        if (channel_process_mark_output_eof(
                &s->channel_processes, (size_t)(slot - 1U),
                app->handle) != 0 && errno != EPIPE)
            session_channel_stream_io_failed(
                s, slot, CHANNEL_CODE_RESOURCE);
        app->process_output_eof = 1U;
        return;
    }
    if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
        session_channel_stream_io_failed(s, slot, CHANNEL_CODE_RESOURCE);
}

static void session_channel_application_tick(session_t *s, int64_t now_ms,
                                             int *poll_ms,
                                             unsigned int *source_budget)
{
    uint8_t slot;

    if (!s || !source_budget || !session_channelised_active(s))
        return;
    if (*source_budget != 0U && !session_pacer_source_blocked(s)) {
        unsigned int offset;

        for (offset = 0U; offset < CHANNEL_SESSION_DATA_SLOTS; offset++) {
            session_channel_application_t *app;

            slot = (uint8_t)(1U +
                ((unsigned int)s->channel_source_cursor + offset) %
                    CHANNEL_SESSION_DATA_SLOTS);
            app = &s->channel_application[slot];
            if (!app->active || !app->pending_input ||
                app->pending_input_length > sync_tx_room_instance(s, slot))
                continue;
            if (sync_tx_append_instance(
                    s, slot, app->pending_input_bytes,
                    app->pending_input_length) == 0) {
                session_pacer_charge_read(s, app->pending_input_length);
                crypto_memzero(app->pending_input_bytes,
                               app->pending_input_length);
                app->pending_input_length = 0U;
                app->pending_input = 0U;
            } else {
                session_channel_stream_io_failed(
                    s, slot, CHANNEL_CODE_RESOURCE);
            }
            *source_budget = 0U;
            s->channel_source_cursor =
                (uint8_t)(slot % CHANNEL_SESSION_DATA_SLOTS);
            break;
        }
    }
    if (s->attach_socket_open) {
        int64_t deadline;

        if (attach_manager_tick(&s->attach_manager, now_ms) < 0) {
            fprintf(stderr,
                    "session: local attach timeout manager failed: %s\n",
                    strerror(errno));
        }
        if (poll_ms &&
            attach_manager_next_deadline(
                &s->attach_manager, &deadline) == ATTACH_LOCAL_OK) {
            int64_t wait = deadline <= now_ms ? 0 : deadline - now_ms;

            if (wait < *poll_ms)
                *poll_ms = (int)wait;
        }
        for (;;) {
            attach_manager_event_t event;
            int allow_data = *source_budget != 0U &&
                             !session_pacer_source_blocked(s);
            int status = attach_manager_next_event_filtered(
                &s->attach_manager, &event, allow_data);

            if (status == ATTACH_LOCAL_WOULD_BLOCK)
                break;
            if (status != ATTACH_LOCAL_FRAME_READY) {
                fprintf(stderr,
                        "session: local attach event manager failed: %s\n",
                        strerror(errno));
                break;
            }
            if (channel_application_attach_event(s, &event, now_ms)) {
                uint8_t event_slot = 0U;

                (void)channel_application_by_owner(
                    s, event.owner, &event_slot);
                *source_budget = 0U;
                if (event_slot != 0U)
                    s->channel_source_cursor = (uint8_t)(
                        event_slot % CHANNEL_SESSION_DATA_SLOTS);
            }
        }
    }
    session_child_transfer_tick(s, now_ms);
    (void)channel_process_maintain(&s->channel_processes, now_ms);
    for (slot = 1U; slot < CHANNEL_SESSION_SLOTS; slot++) {
        session_channel_application_t *app = &s->channel_application[slot];
        const sync_rx_t *rx;

        if (!app->active)
            continue;
        rx = sync_rx_state_instance(s, slot);
        if (s->is_server && app->kind == CHANNEL_KIND_EXEC &&
            !app->exec_spawned && rx && rx->fin_delivered) {
            session_channel_stream_io_failed(
                s, slot, CHANNEL_CODE_PROTOCOL);
            continue;
        }
        if (s->is_server && app->kind == CHANNEL_KIND_EXEC &&
            app->exec_spawned && !app->process_input_closed && rx &&
            rx->fin_delivered) {
            if (channel_process_close_input(
                    &s->channel_processes, (size_t)(slot - 1U),
                    app->handle) != 0 && errno != EPIPE)
                session_channel_stream_io_failed(
                    s, slot, CHANNEL_CODE_RESOURCE);
            app->process_input_closed = 1U;
        }
        if (s->is_server && app->handle != s->terminal_channel_handle &&
            (app->exec_spawned || app->kind == CHANNEL_KIND_TERMINAL) &&
            !app->process_fin_sent) {
            uint32_t code;

            if (channel_process_result(
                    &s->channel_processes, (size_t)(slot - 1U),
                    app->handle, &code) == 1) {
                sync_tx_fin_instance(s, slot, 1, (int32_t)code);
                app->terminal_code = code;
                app->process_fin_sent = 1U;
            }
        }
        channel_application_drive_attach_completion(s, slot);
        channel_application_drive_aux(s, slot);
        if (sync_rx_pending_instance(s, slot))
            sync_rx_deliver_instance(s, slot);
        channel_application_try_cleanup(s, slot);
    }
    session_child_lease_start_pending(s, now_ms);
}

static void session_channel_application_cleanup_all(session_t *s)
{
    uint8_t slot;
    int child_result;
    int process_result;

    if (!s)
        return;
    for (slot = 1U; slot < CHANNEL_SESSION_SLOTS; slot++) {
        session_channel_application_t *app = &s->channel_application[slot];

        if (app->active && app->handle != 0U)
            (void)sync_instance_detach_io(s, slot, app->handle);
    }
    child_result = child_transfer_table_destroy(
        &s->child_transfers, CHANNEL_PROCESS_TERM_GRACE_MS,
        CHANNEL_PROCESS_REAP_HORIZON_MS);
    if (child_result != 0) {
        fprintf(stderr,
                "session: child-transfer cleanup exceeded its bound: %s\n",
                strerror(errno));
        s->run_failed = 1;
    }
    if (s->attach_socket_open) {
        if (attach_manager_close(&s->attach_manager) != ATTACH_LOCAL_OK) {
            fprintf(stderr,
                    "session: local attach socket cleanup failed: %s\n",
                    strerror(errno));
            s->run_failed = 1;
        }
        s->attach_socket_open = 0U;
    }
    process_result = channel_process_table_destroy(
        &s->channel_processes, CHANNEL_PROCESS_TERM_GRACE_MS,
        CHANNEL_PROCESS_REAP_HORIZON_MS);
    if (process_result != 0) {
        fprintf(stderr,
                "session: channel-session child cleanup exceeded its shared bound: %s\n",
                strerror(errno));
        s->run_failed = 1;
    }
    for (slot = 1U; slot < CHANNEL_SESSION_SLOTS; slot++)
        channel_application_reset(&s->channel_application[slot]);
    channel_process_table_init(&s->channel_processes);
    child_transfer_table_init(&s->child_transfers);
    s->child_transfer_manager_failed = 0U;
    s->child_transfer_pending = 0U;
    s->child_transfer_lease_slot = 0U;
    s->child_transfer_lease_handle = 0U;
    crypto_memzero(&s->child_transfer_pending_event,
                   sizeof(s->child_transfer_pending_event));
}

static int channel_server_decide_stage1(session_t *s, uint8_t slot)
{
    channel_session_slot_t *entry;
    session_channel_runtime_t *runtime;
    session_channel_application_t *app;
    uint32_t code = CHANNEL_CODE_KIND_UNSUPPORTED;
    uint32_t pid = 0U;
    int accepted = 0;

    if (!s || !s->is_server || slot == 0U ||
        slot >= CHANNEL_SESSION_SLOTS)
        return -1;
    entry = &s->channel_table.slots[slot];
    runtime = &s->channel_runtime[slot];
    app = &s->channel_application[slot];
    if (entry->state != CHANNEL_SLOT_OPENING)
        return -1;

    if (channel_kind_capability_selected(s, entry->open.kind)) {
        if (entry->open.kind == CHANNEL_KIND_TERMINAL &&
            entry->handle == s->terminal_channel_handle) {
            uint16_t rows = (uint16_t)entry->open.parameter0;
            uint16_t columns = (uint16_t)(entry->open.parameter0 >> 16);

            if (channel_pty_server_start(s, rows, columns, &pid) == 0) {
                /* The sync instance was admitted before application work,
                 * but the PTY did not yet exist.  Publish the process-owned
                 * descriptors before ACCEPT can become observable. */
                if (sync_instance_set_io(
                        s, slot, entry->handle,
                        s->pty_master_fd, s->pty_master_fd,
                        NULL, NULL, NULL, NULL) == 0) {
                    accepted = 1;
                    code = pid;
                    s->terminal_channel_handle = entry->handle;
                    channel_application_reset(app);
                    app->active = 1U;
                    app->handle = entry->handle;
                    app->kind = entry->open.kind;
                } else {
                    (void)channel_pty_close_instance(s);
                    code = CHANNEL_CODE_RESOURCE;
                }
            } else {
                code = CHANNEL_CODE_RESOURCE;
            }
        } else if (entry->open.kind == CHANNEL_KIND_TERMINAL ||
                   entry->open.kind == CHANNEL_KIND_EXEC) {
            int close_fds[CHANNEL_PROCESS_MAX_EXTRA_CLOSE_FDS];
            size_t close_fd_count = 0U;
            int initialized = 0;

            channel_application_reset(app);
            app->active = 1U;
            app->handle = entry->handle;
            app->kind = entry->open.kind;
            if (channel_collect_child_close_fds(
                    s, close_fds, &close_fd_count) != 0) {
                code = CHANNEL_CODE_RESOURCE;
            } else if (entry->open.kind == CHANNEL_KIND_EXEC) {
                if (sync_init_instance(
                        s, slot, entry->handle, entry->open.kind, -1, -1,
                        NULL, NULL, channel_exec_preface_write, app) == 0) {
                    initialized = 1;
                    accepted = 1;
                    code = CHANNEL_CODE_OK;
                } else {
                    code = errno == ENOSPC ? CHANNEL_CODE_CAPACITY
                                           : CHANNEL_CODE_RESOURCE;
                }
            } else {
                uint16_t rows = (uint16_t)entry->open.parameter0;
                uint16_t columns =
                    (uint16_t)(entry->open.parameter0 >> 16);

                if (sync_init_instance(
                        s, slot, entry->handle, entry->open.kind, -1, -1,
                        NULL, NULL, NULL, NULL) == 0) {
                    initialized = 1;
                    if (channel_process_spawn_terminal(
                            &s->channel_processes, (size_t)(slot - 1U),
                            entry->handle, NULL, rows, columns, close_fds,
                            close_fd_count) == 0) {
                        int input_fd = channel_process_input_fd(
                            &s->channel_processes, (size_t)(slot - 1U),
                            entry->handle);
                        int output_fd = channel_process_output_fd(
                            &s->channel_processes, (size_t)(slot - 1U),
                            entry->handle);

                        if (input_fd >= 0 && output_fd >= 0 &&
                            sync_instance_set_io(
                                s, slot, entry->handle, output_fd, input_fd,
                                NULL, NULL, NULL, NULL) == 0) {
                            const channel_process_instance_t *process =
                                channel_process_get(
                                    &s->channel_processes,
                                    (size_t)(slot - 1U));

                            accepted = 1;
                            pid = process ? (uint32_t)process->pid : 0U;
                            code = pid;
                        } else {
                            code = CHANNEL_CODE_RESOURCE;
                        }
                    } else {
                        code = CHANNEL_CODE_RESOURCE;
                    }
                } else {
                    code = errno == ENOSPC ? CHANNEL_CODE_CAPACITY
                                           : CHANNEL_CODE_RESOURCE;
                }
            }
            if (!accepted) {
                if (channel_process_get(
                        &s->channel_processes,
                        (size_t)(slot - 1U)) != NULL)
                    (void)channel_process_cancel(
                        &s->channel_processes, (size_t)(slot - 1U),
                        entry->handle, mono_ms(),
                        CHANNEL_PROCESS_TERM_GRACE_MS);
                if (initialized) {
                    (void)sync_instance_detach_io(s, slot, entry->handle);
                    (void)sync_free_instance(s, slot);
                }
                channel_application_reset(app);
            }
        } else {
            code = CHANNEL_CODE_KIND_UNSUPPORTED;
        }
    }
    if (channel_session_decide_open(&s->channel_table, entry->handle,
                                    accepted, code) != 0)
        return -1;
    runtime->decision_pending = 1U;
    runtime->response_next_ms = 0;
    /* ACCEPT ends this slot's OPEN timer. A secondary refusal does too: its
     * stale timer must never poison a later last-channel close. The refused
     * first embedded OPEN is different—while no channel has ever been
     * accepted, its absolute +31 s timer is the listener's channel-zero-only
     * fail-loud bound if REFUSE and the client's outer close are both lost. */
    if (accepted || !s->channel_first_open_valid ||
        entry->handle != s->channel_first_open.handle)
        runtime->open_armed = 0U;
    if (!accepted) {
        fprintf(stderr,
                "session: channel OPEN refused kind=%u code=%u\n",
                (unsigned int)entry->open.kind,
                (unsigned int)code);
        session_event_emit_channel(
            s, EVENT_LOG_EVENT_REFUSE, channel_code_event_reason(code),
            entry->handle, entry->open.kind, code, mono_ms());
    } else {
        session_event_emit_channel(
            s, EVENT_LOG_EVENT_OPEN, EVENT_LOG_REASON_SESSION_ACTIVE,
            entry->handle, entry->open.kind, code, mono_ms());
    }
    return 0;
}

static void channel_retire_application(session_t *s, uint8_t slot,
                                       uint32_t code, int64_t now_ms)
{
    session_channel_application_t *app;
    channel_session_slot_t *entry;

    if (!s || slot == 0U || slot >= CHANNEL_SESSION_SLOTS)
        return;
    app = &s->channel_application[slot];
    entry = &s->channel_table.slots[slot];
    if (!s->is_server && app->active && app->child_lease)
        session_child_lease_fail(s, slot, now_ms);
    if (entry->open.kind == CHANNEL_KIND_TERMINAL &&
        entry->handle == s->terminal_channel_handle) {
        if (!s->is_server && !s->pty_eof_seen && code <= INT_MAX) {
            s->client_exit_code = (int)code;
            s->pty_eof_seen = 1;
        }
    } else if (s->is_server) {
        channel_application_cancel_process(s, slot, now_ms);
    }
    if (app->active) {
        channel_application_drive_attach_completion(s, slot);
        (void)sync_instance_detach_io(s, slot, app->handle);
        app->cleanup_pending = 1U;
    }
    session_event_emit_channel(
        s, EVENT_LOG_EVENT_CLOSE, EVENT_LOG_REASON_PEER_CLOSE,
        entry->handle, entry->open.kind, code, now_ms);
    channel_application_try_cleanup(s, slot);
}

static void handle_channel_control(session_t *s, uint8_t type,
                                   const uint8_t *plaintext, size_t pt_len,
                                   int pending_frame, int64_t now_ms)
{
    channel_session_open_t open;
    channel_session_result_t result;
    channel_session_observe_t observed;
    channel_session_slot_t *entry;
    session_channel_runtime_t *runtime;
    uint8_t slot = 0U;
    uint32_t generation = 0U;
    if (!session_channelised_active(s) || pending_frame) {
        fprintf(stderr,
                "session: authenticated channel-session control outside its selected current epoch — ERR_CAPS\n");
        session_protocol_error_close(s, ERR_CAPS);
        return;
    }
    if (type == CTRL_CHANNEL_OPEN) {
        if (!s->is_server ||
            channel_session_open_decode(plaintext, pt_len, &open) != 0 ||
            channel_session_handle_decode(open.handle, &slot,
                                          &generation) != 0) {
            fprintf(stderr,
                    "session: malformed or wrong-role CHANNEL_OPEN — ERR_CAPS\n");
            session_protocol_error_close(s, ERR_CAPS);
            return;
        }
        entry = &s->channel_table.slots[slot];
        runtime = &s->channel_runtime[slot];
        if (generation > entry->last_generation) {
            unsigned int i;
            int response_outstanding = 0;
            int last_close_started = 0;

            for (i = 1U; i < CHANNEL_SESSION_SLOTS; i++) {
                if (s->channel_runtime[i].decision_pending)
                    response_outstanding = 1;
                if (s->channel_runtime[i].peer_close_hold)
                    last_close_started = 1;
            }
            if (s->channel_control_inflight &&
                (s->channel_control_type == CTRL_CHANNEL_ACCEPT ||
                 s->channel_control_type == CTRL_CHANNEL_REFUSE))
                response_outstanding = 1;
            /* A new OPEN is the peer's implicit proof that the previous
             * result was received.  It cannot overtake an uncompleted result
             * owner, a slot-local close obligation, or a last-close hold. */
            if (response_outstanding || last_close_started ||
                runtime->close_armed || runtime->close_ack_pending ||
                (runtime->peer_close_deadline_ms > now_ms)) {
                fprintf(stderr,
                        "session: overlapping CHANNEL_OPEN before prior lifecycle retirement — ERR_CAPS\n");
                session_protocol_error_close(s, ERR_CAPS);
                return;
            }
        }
        observed = channel_session_observe_open(&s->channel_table, &open);
        if (observed == CHANNEL_OBSERVE_STALE)
            return;
        if (observed == CHANNEL_OBSERVE_ERROR ||
            observed == CHANNEL_OBSERVE_CONFLICT) {
            fprintf(stderr,
                    "session: conflicting CHANNEL_OPEN — ERR_CAPS\n");
            session_protocol_error_close(s, ERR_CAPS);
            return;
        }
        if (observed == CHANNEL_OBSERVE_NEW) {
            memset(runtime, 0, sizeof(*runtime));
            if (!s->channel_first_open_valid) {
                s->channel_first_open = open;
                s->channel_first_open_valid = 1U;
                if (open.kind == CHANNEL_KIND_TERMINAL)
                    s->terminal_channel_handle = open.handle;
            }
            /* A standalone OPEN may overtake the READY that embeds the same
             * descriptor.  Stage it in the fixed table, but start neither
             * its deadline nor application work before mutual READY. */
            if (s->services_started) {
                channel_runtime_arm_open(runtime, now_ms, 0);
                if (channel_server_decide_stage1(s, slot) != 0) {
                    fprintf(stderr,
                            "session: CHANNEL_OPEN decision failed — ERR_CAPS\n");
                    session_protocol_error_close(s, ERR_CAPS);
                    return;
                }
            }
        } else if (s->channel_table.slots[slot].decision_type != 0U) {
            runtime->decision_pending = 1U;
            runtime->response_next_ms = now_ms;
        }
        session_channel_tick(s, now_ms);
        return;
    }

    if (channel_session_result_decode(type, plaintext, pt_len, &result) != 0 ||
        channel_session_handle_decode(result.handle, &slot,
                                      &generation) != 0) {
        fprintf(stderr,
                "session: malformed channel-session result record — ERR_CAPS\n");
        session_protocol_error_close(s, ERR_CAPS);
        return;
    }
    runtime = &s->channel_runtime[slot];
    if (type == CTRL_CHANNEL_ACCEPT || type == CTRL_CHANNEL_REFUSE) {
        if (s->is_server) {
            fprintf(stderr,
                    "session: wrong-role channel-session OPEN result — ERR_CAPS\n");
            session_protocol_error_close(s, ERR_CAPS);
            return;
        }
        /* READY is the application-service barrier, not an ordering promise
         * between UDP datagrams.  A result that overtakes the peer's READY
         * is classified against a copy of the lifecycle table, then a valid
         * current result is discarded without lifecycle or TTY side effects;
         * the client's absolute post-READY OPEN retry makes the peer reassert
         * its immutable decision. Future/conflicting authenticated results
         * remain fatal even before the service barrier. */
        if (!s->services_started) {
            channel_session_table_t shadow = s->channel_table;

            observed = channel_session_observe_result(
                &shadow, type, &result);
            crypto_memzero(&shadow, sizeof(shadow));
            if (observed == CHANNEL_OBSERVE_ERROR ||
                observed == CHANNEL_OBSERVE_CONFLICT) {
                fprintf(stderr,
                        "session: conflicting pre-service channel-session OPEN result — ERR_CAPS\n");
                session_protocol_error_close(s, ERR_CAPS);
            }
            return;
        }
        observed = channel_session_observe_result(
            &s->channel_table, type, &result);
        if (observed == CHANNEL_OBSERVE_STALE)
            return;
        if (observed == CHANNEL_OBSERVE_ERROR ||
            observed == CHANNEL_OBSERVE_CONFLICT) {
            fprintf(stderr,
                    "session: conflicting channel-session OPEN result — ERR_CAPS\n");
            session_protocol_error_close(s, ERR_CAPS);
            return;
        }
        if (observed == CHANNEL_OBSERVE_NEW) {
            runtime->open_armed = 0U;
            if (type == CTRL_CHANNEL_ACCEPT) {
                session_channel_application_t *app =
                    &s->channel_application[slot];

                if (result.handle == s->terminal_channel_handle) {
                    channel_pty_client_open_accepted(s);
                    session_event_emit_channel(
                        s, EVENT_LOG_EVENT_OPEN,
                        EVENT_LOG_REASON_SESSION_ACTIVE, result.handle,
                        result.kind, result.code, now_ms);
                } else if (app->active && app->child_lease &&
                           app->handle == result.handle &&
                           app->kind == result.kind) {
                    if (app->exec_preface_expected == 0U ||
                        sync_tx_append_instance(
                            s, slot, app->exec_preface,
                            app->exec_preface_expected) != 0) {
                        session_child_lease_fail(s, slot, now_ms);
                        session_channel_stream_io_failed(
                            s, slot, CHANNEL_CODE_RESOURCE);
                        return;
                    }
                    session_event_emit_channel(
                        s, EVENT_LOG_EVENT_OPEN,
                        EVENT_LOG_REASON_SESSION_ACTIVE, result.handle,
                        result.kind, result.code, now_ms);
                } else if (!app->active || !app->attach_bound ||
                           app->handle != result.handle ||
                           app->kind != result.kind) {
                    fprintf(stderr,
                            "session: accepted channel-session attach lacks its local binding — ERR_CAPS\n");
                    session_protocol_error_close(s, ERR_CAPS);
                    return;
                } else {
                    if (app->kind == CHANNEL_KIND_EXEC &&
                        (app->exec_preface_expected == 0U ||
                         sync_tx_append_instance(
                             s, slot, app->exec_preface,
                             app->exec_preface_expected) != 0)) {
                        session_channel_stream_io_failed(
                            s, slot, CHANNEL_CODE_RESOURCE);
                        return;
                    }
                    if (attach_manager_queue_result(
                            &s->attach_manager, app->attach_owner,
                            result.handle, CHANNEL_CODE_OK) !=
                            ATTACH_LOCAL_OK) {
                        session_channel_stream_io_failed(
                            s, slot, CHANNEL_CODE_RESOURCE);
                        return;
                    }
                    session_event_emit_channel(
                        s, EVENT_LOG_EVENT_OPEN,
                        EVENT_LOG_REASON_SESSION_ACTIVE, result.handle,
                        result.kind, result.code, now_ms);
                }
            } else {
                session_channel_application_t *app =
                    &s->channel_application[slot];

                if (result.handle == s->terminal_channel_handle) {
                    channel_pty_client_open_refused(s, result.code);
                    s->run_failed = 1;
                    session_close(s);
                } else {
                    if (app->active && app->child_lease &&
                        app->handle == result.handle) {
                        session_child_transfer_clear_pending(
                            s, result.code);
                        (void)sync_instance_detach_io(
                            s, slot, app->handle);
                        (void)sync_free_instance(s, slot);
                        channel_application_reset(app);
                    } else if (app->active && app->attach_bound &&
                        app->handle == result.handle) {
                        (void)attach_manager_queue_result(
                            &s->attach_manager, app->attach_owner,
                            result.handle, result.code);
                        (void)sync_instance_detach_io(
                            s, slot, app->handle);
                        (void)sync_free_instance(s, slot);
                        channel_application_reset(app);
                    }
                    session_event_emit_channel(
                        s, EVENT_LOG_EVENT_REFUSE,
                        channel_code_event_reason(result.code),
                        result.handle, result.kind, result.code, now_ms);
                }
            }
        }
        return;
    }
    /* The remaining result records can likewise overtake READY after the
     * peer activates first. Classify them against a table copy so malformed,
     * future, or conflicting authenticated state still fails loudly, while
     * a valid current result has no authority to retire resources or finish
     * teardown before this endpoint crosses its service barrier. */
    if (!s->services_started) {
        channel_session_table_t shadow = s->channel_table;

        observed = type == CTRL_CHANNEL_CLOSE
            ? channel_session_observe_close(&shadow, &result)
            : channel_session_observe_close_ack(&shadow, &result);
        crypto_memzero(&shadow, sizeof(shadow));
        if (observed == CHANNEL_OBSERVE_ERROR ||
            observed == CHANNEL_OBSERVE_CONFLICT) {
            fprintf(stderr,
                    "session: conflicting pre-service channel-session close result — ERR_CAPS\n");
            session_protocol_error_close(s, ERR_CAPS);
        }
        return;
    }
    if (type == CTRL_CHANNEL_CLOSE) {
        uint16_t other_live = (uint16_t)(
            s->channel_table.live_mask &
            (uint16_t)~(uint16_t)(1U << slot));

        observed = channel_session_observe_close(
            &s->channel_table, &result);
        if (observed == CHANNEL_OBSERVE_STALE)
            return;
        if (observed == CHANNEL_OBSERVE_ERROR ||
            observed == CHANNEL_OBSERVE_CONFLICT) {
            fprintf(stderr,
                    "session: conflicting CHANNEL_CLOSE — ERR_CAPS\n");
            session_protocol_error_close(s, ERR_CAPS);
            return;
        }
        if (observed == CHANNEL_OBSERVE_NEW)
            channel_retire_application(s, slot, result.code, now_ms);
        if (observed == CHANNEL_OBSERVE_NEW) {
            /* CLOSE is the terminal result for this incarnation even when
             * UDP reorders it ahead of ACCEPT/REFUSE. It supersedes the
             * first-OPEN wait so the shared horizon is judged only by the
             * matching CLOSE_ACK handoff below. */
            runtime->open_armed = 0U;
            runtime->open_next_ms = 0;
            runtime->peer_close_ack_completed = 0U;
        }
        runtime->close_ack_pending = 1U;
        runtime->response_next_ms = now_ms;
        if (observed == CHANNEL_OBSERVE_NEW) {
            /* The peer retry horizon is absolute from the first accepted
             * CLOSE.  Exact duplicates reassert the ACK obligation but must
             * never slide the teardown deadline indefinitely. */
            runtime->peer_close_deadline_ms =
                now_ms + CHANNEL_SESSION_FIRST_OPEN_MS;
            /* A simultaneous close leaves this slot live until our own
             * CLOSE is acknowledged, but it still carries the peer's
             * independent ACK obligation.  If no other data slot is live,
             * retain the session through the peer's complete retry horizon
             * in both cases. */
            if (other_live == 0U)
                runtime->peer_close_hold = 1U;
        }
        session_channel_tick(s, now_ms);
        return;
    }
    if (type == CTRL_CHANNEL_CLOSE_ACK) {
        observed = channel_session_observe_close_ack(
            &s->channel_table, &result);
        if (observed == CHANNEL_OBSERVE_STALE)
            return;
        if (observed == CHANNEL_OBSERVE_ERROR ||
            observed == CHANNEL_OBSERVE_CONFLICT) {
            fprintf(stderr,
                    "session: conflicting CHANNEL_CLOSE_ACK — ERR_CAPS\n");
            session_protocol_error_close(s, ERR_CAPS);
            return;
        }
        if (observed == CHANNEL_OBSERVE_NEW) {
            runtime->close_armed = 0U;
            runtime->close_next_ms = 0;
            s->channel_application[slot].cleanup_pending = 1U;
            channel_application_try_cleanup(s, slot);
        }
        session_channel_tick(s, now_ms);
    }
}

/* channel-session inner routing is intentionally called only for a complete plaintext:
 * immediately for FF-only records, or after fragmentation returns REASM_DELIVER. */
static int channelised_data_body(session_t *s, uint8_t outer_class,
                                 const uint8_t *wire, size_t wire_length,
                                 const uint8_t **body_out,
                                 size_t *body_length_out,
                                 uint8_t *slot_out, uint8_t *kind_out)
{
    channel_session_slot_t *entry;
    channel_session_observe_t observed;
    uint32_t handle;
    uint32_t generation;
    uint8_t slot;
    int class_matches;

    if (!s || !wire || !body_out || !body_length_out || !slot_out ||
        !kind_out)
        return -1;
    if (!session_channelised_active(s)) {
        *body_out = wire;
        *body_length_out = wire_length;
        *slot_out = 0U;
        *kind_out = 0U;
        return 1;
    }
    if (outer_class == 0U || outer_class > 3U ||
        outer_class == 2U ||
        wire_length < CHANNEL_SESSION_HANDLE_BYTES)
        return -1;
    handle = load32le(wire);
    if (channel_session_handle_decode(handle, &slot, &generation) != 0)
        return -1;
    entry = &s->channel_table.slots[slot];
    if (generation < entry->last_generation)
        return 0;
    if (generation > entry->last_generation || entry->handle != handle)
        return -1;
    class_matches = outer_class == 1U
        ? (entry->open.kind == CHANNEL_KIND_TERMINAL ||
           entry->open.kind == CHANNEL_KIND_EXEC)
        : (entry->open.kind == CHANNEL_KIND_BULK_PUSH ||
           entry->open.kind == CHANNEL_KIND_BULK_PULL);
    if (!class_matches ||
        !channel_kind_capability_selected(s, entry->open.kind))
        return -1;
    observed = channel_session_resolve_data(
        &s->channel_table, handle, entry->open.kind);
    if (observed == CHANNEL_OBSERVE_STALE)
        return 0;
    if (observed == CHANNEL_OBSERVE_DUPLICATE) {
        /* The exact current but unopened/closing/retired incarnation is
         * rejected at the handle boundary and never reaches its kind codec.
         * Pre-service callers still reach this decision only after complete
         * fragmentation reassembly, so future/conflicting handles remain fail-loud. */
        return 0;
    }
    if (observed != CHANNEL_OBSERVE_NEW)
        return -1;
    *body_out = wire + CHANNEL_SESSION_HANDLE_BYTES;
    *body_length_out = wire_length - CHANNEL_SESSION_HANDLE_BYTES;
    *slot_out = slot;
    *kind_out = entry->open.kind;
    return 1;
}

static int session_channel_data_prevalidate(session_t *s, uint8_t slot,
                                            uint8_t kind, uint8_t type,
                                            const uint8_t *body,
                                            size_t body_length)
{
    const sync_instance_binding_t *binding;

    if (!s || slot == 0U || slot >= CHANNEL_SESSION_SLOTS ||
        !body || !sync_active_instance(s, slot))
        return CHAN_ERR;
    binding = &s->sync_binding[slot];
    if (!binding->configured || binding->kind != kind ||
        binding->handle != s->channel_table.slots[slot].handle)
        return CHAN_ERR;
    switch (type) {
    case PTY_SYNC_DATA:
        return sync_prevalidate_data_instance(s, slot, body, body_length) == 0
            ? CHAN_OK : CHAN_ERR;
    case PTY_SYNC_ACK:
        return sync_prevalidate_ack_instance(s, slot, body, body_length) == 0
            ? CHAN_OK : CHAN_ERR;
    case PTY_RESIZE:
        return s->is_server && kind == CHANNEL_KIND_TERMINAL &&
               body_length == 8U && load16le(body) != 0U &&
               load16le(body) <= 1000U && load16le(body + 2U) != 0U &&
               load16le(body + 2U) <= 1000U
            ? CHAN_OK : CHAN_ERR;
    case PTY_SIGNAL:
        return s->is_server && body_length == 4U && body[0] != 0U &&
               body[0] < 64U && body[1] == 0U && body[2] == 0U &&
               body[3] == 0U ? CHAN_OK : CHAN_ERR;
    default:
        return CHAN_ERR;
    }
}

static int session_channel_data_dispatch(session_t *s, uint8_t slot,
                                         uint8_t kind, uint8_t type,
                                         const uint8_t *body,
                                         size_t body_length)
{
    uint32_t handle;

    if (session_channel_data_prevalidate(
            s, slot, kind, type, body, body_length) != CHAN_OK)
        return CHAN_ERR;
    handle = s->channel_table.slots[slot].handle;
    switch (type) {
    case PTY_SYNC_DATA:
        sync_handle_data_instance(s, slot, body, body_length);
        /* A FIN can complete in the receive call itself.  Enforce the EXEC
         * preface boundary in that same production turn; the ordinary
         * application-maintenance sweep below remains a second guard for a
         * FIN whose last hole is repaired by a later DATA record. */
        if (s->is_server && kind == CHANNEL_KIND_EXEC &&
            !s->channel_application[slot].exec_spawned) {
            const sync_rx_t *rx = sync_rx_state_instance(s, slot);

            if (rx != NULL && rx->fin_delivered)
                session_channel_stream_io_failed(
                    s, slot, CHANNEL_CODE_PROTOCOL);
        }
        return CHAN_OK;
    case PTY_SYNC_ACK:
        sync_handle_ack_instance(s, slot, body, body_length);
        return CHAN_OK;
    case PTY_RESIZE:
        if (handle == s->terminal_channel_handle)
            return channel_dispatch(
                s, (uint8_t)((1U << 4) | CHAN_FF_BIT), type,
                body, body_length);
        if (kind == CHANNEL_KIND_EXEC)
            return CHAN_ERR;
        if (!s->channel_application[slot].exec_spawned &&
            channel_process_get(&s->channel_processes,
                                (size_t)(slot - 1U)) == NULL) {
            s->channel_application[slot].pending_rows = load16le(body);
            s->channel_application[slot].pending_columns =
                load16le(body + 2U);
            s->channel_application[slot].pending_xpixel =
                load16le(body + 4U);
            s->channel_application[slot].pending_ypixel =
                load16le(body + 6U);
            s->channel_application[slot].resize_pending = 1U;
            return CHAN_OK;
        }
        if (channel_process_resize(
                &s->channel_processes, (size_t)(slot - 1U), handle,
                load16le(body), load16le(body + 2U),
                load16le(body + 4U), load16le(body + 6U)) != 0 &&
            errno != ESRCH) {
            session_channel_stream_io_failed(s, slot,
                                             CHANNEL_CODE_RESOURCE);
        }
        return CHAN_OK;
    case PTY_SIGNAL:
        if (handle == s->terminal_channel_handle)
            return channel_dispatch(
                s, (uint8_t)((1U << 4) | CHAN_FF_BIT), type,
                body, body_length);
        if (channel_process_get(&s->channel_processes,
                                (size_t)(slot - 1U)) == NULL) {
            session_channel_application_t *app =
                &s->channel_application[slot];

            if (kind != CHANNEL_KIND_EXEC || app->signal_pending) {
                session_channel_stream_io_failed(
                    s, slot, CHANNEL_CODE_PROTOCOL);
                return CHAN_OK;
            }
            app->pending_signal = body[0];
            app->signal_pending = 1U;
            return CHAN_OK;
        }
        if (channel_process_signal(
                &s->channel_processes, (size_t)(slot - 1U), handle,
                (int)body[0]) != 0 && errno != ESRCH) {
            session_channel_stream_io_failed(s, slot,
                                             CHANNEL_CODE_RESOURCE);
        }
        return CHAN_OK;
    default:
        return CHAN_ERR;
    }
}

/* -------------------------------------------------------------------------
 * Dispatch decrypted control frame
 * ---------------------------------------------------------------------- */

static void dispatch_control(session_t *s, uint8_t type,
                             const uint8_t *plaintext, size_t pt_len,
                             uint32_t seq, int pending_frame,
                             int64_t now_ms)
{
    switch (type) {
    case CTRL_HELLO:
        handle_hello(s, seq, plaintext, pt_len);
        break;

    case CTRL_HELLO_ACK:
        handle_hello_ack(s, plaintext, pt_len);
        break;

    case CTRL_READY:
        handle_ready(s, plaintext, pt_len);
        break;

    case CTRL_CHANNEL_OPEN:
    case CTRL_CHANNEL_ACCEPT:
    case CTRL_CHANNEL_REFUSE:
    case CTRL_CHANNEL_CLOSE:
    case CTRL_CHANNEL_CLOSE_ACK:
        handle_channel_control(s, type, plaintext, pt_len, pending_frame,
                               now_ms);
        break;

    case CTRL_KEEPALIVE:
        if (s->state == SESSION_ESTABLISHED) {
            /* Reply with ACK */
            send_ctrl(s, CTRL_KEEPALIVE_ACK, NULL, 0, s->session_key);
        } else if (s->state == SESSION_REKEYING && !pending_frame) {
            send_ctrl(s, CTRL_KEEPALIVE_ACK, NULL, 0, s->session_key);
        } else if (s->state == SESSION_KEY_DERIVING) {
            /* Explicitly ignore */
        } else {
            send_ctrl_error(s, ERR_SESSION);
            track_err_session(s);
        }
        break;

    case CTRL_KEEPALIVE_ACK:
        /* RTT measurement — not implemented */
        break;

    case CTRL_STATUS_HEARTBEAT: {
        sync_status_record_t record;
        uint64_t tx_tip, rx_delivered, rx_highest;
        int sink_blocked;
        uint32_t expected_epoch;
        int64_t now_ms = mono_ms();

        if ((s->selected_caps & UNMOOR_CAP_STATUS_HEARTBEAT_V1) == 0) {
            fprintf(stderr,
                    "session: authenticated status without negotiated "
                    "capability — ERR_CAPS\n");
            session_protocol_error_close(s, ERR_CAPS);
            break;
        }
        if (delivery_status_combined(s)) {
            fprintf(stderr,
                    "session: authenticated sync-status fallback carrier in "
                    "combined mode — ERR_CAPS\n");
            session_protocol_error_close(s, ERR_CAPS);
            break;
        }
        if (s->state == SESSION_KEY_DERIVING) {
            /* An endpoint may finish READY first. The next absolute sample
             * heals this harmless early arrival after local establishment. */
            fprintf(stderr,
                    "session: early status deferred until READY\n");
            break;
        }
        if (pending_frame ||
            (s->state != SESSION_ESTABLISHED &&
             s->state != SESSION_REKEYING) ||
            sync_status_record_decode(plaintext, pt_len, &record) != 0) {
            fprintf(stderr,
                    "session: malformed or out-of-phase authenticated "
                    "status — closing\n");
            session_protocol_error_close(s, ERR_CAPS);
            break;
        }
        if (session_status_counters(s, &tx_tip, &rx_delivered, &rx_highest,
                                    &sink_blocked) != 0) {
            fprintf(stderr,
                    "session: sync-status cumulative counter overflow — closing\n");
            session_protocol_error_close(s, ERR_SESSION);
            break;
        }
        (void)sink_blocked;
        expected_epoch = s->epoch_rekey_enabled ? s->epoch : 0;
        if (record.epoch != expected_epoch ||
            record.rx_delivered > tx_tip) {
            fprintf(stderr,
                    "session: impossible authenticated status counters or "
                    "epoch — closing\n");
            session_protocol_error_close(s, ERR_CAPS);
            break;
        }

        /* Like new-epoch application data, a fully validated current-epoch
         * status proves that the client adopted and handed its final ACK to
         * the transport. The proof comes from pair/key, AEAD, replay, phase,
         * grammar, epoch, and bounds—not from telemetry fields gaining any
         * delivery authority. Never open the barrier before those checks. */
        if (s->state == SESSION_REKEYING && s->is_server &&
            s->rekey_phase == REKEY_S_WAIT_ACK) {
            finish_epoch_barrier(s);
            if (s->state != SESSION_ESTABLISHED)
                break;
        }
        if (!session_status_active(s) ||
            sync_status_observe_peer(&s->sync_status, &record, now_ms,
                                     tx_tip, rx_delivered,
                                     rx_highest) != 0) {
            fprintf(stderr,
                    "session: impossible authenticated status counters or "
                    "epoch — closing\n");
            session_protocol_error_close(s, ERR_CAPS);
            break;
        }
        session_status_present(s, now_ms);
        if ((record.flags & SYNC_STATUS_FLAG_POLL) != 0 &&
            s->state == SESSION_ESTABLISHED)
            (void)send_status_record(s, 0, SESSION_TX_DONE_NONE,
                                     WIRE_COALESCE_STATUS_REPLY, now_ms);
        break;
    }

    case CTRL_RD_DATA:
    case CTRL_RD_STATUS:
        (void)session_delivery_receive_reliable(s, type, plaintext, pt_len);
        break;

    case CTRL_CLOSE:
        fprintf(stderr, "session: received CTRL_CLOSE\n");
        if (s->state == SESSION_CLOSING) {
            /* A retained stream prefix/body and our bounded acknowledgement
             * still own their safe completion boundary. */
            s->close_peer_seen = 1;
        } else if (s->state == SESSION_ESTABLISHED &&
                   s->bulk_activated &&
                   bulk_engine_completion_linger_active(s->bulk)) {
            /* bulk-transfer makes DONE_CONFIRM best-effort: after physical DONE_ACK
             * completion, the receiver reaches success at the original
             * ten-second linger even if every confirmation is lost.  A
             * later-sequence outer CLOSE can overtake DONE_CONFIRM across
             * UDP paths, so remember the authenticated peer close without
             * allowing transport teardown to preempt that already-pinned
             * application deadline.  The bulk tick will resolve the result,
             * after which the ordinary session loop initiates close. */
            if (!s->close_peer_seen)
                fprintf(stderr,
                        "session: deferring peer close through bulk-transfer completion linger\n");
            s->close_peer_seen = 1;
        } else if (s->state == SESSION_KEY_DERIVING ||
                   s->state == SESSION_REKEYING ||
                   s->state == SESSION_ESTABLISHED) {
            if (s->state == SESSION_REKEYING) {
                fprintf(stderr,
                        "session: peer aborted before epoch confirmation\n");
                s->run_failed = 1;
            }
            s->close_peer_seen = 1;
            session_close(s);
        }
        if (!s->wire_in_run_loop && s->state == SESSION_CLOSING)
            (void)session_close_tick(s, mono_ms());
        /* CONNECTING branch deleted — pre-ESTABLISHED CTRL_CLOSE is
         * only reachable via the stash replay, which the above
         * KEY_DERIVING branch now handles after handle_hello_ack. */
        break;

    case CTRL_ERROR:
        if (pt_len >= 2) {
            uint16_t code = load16le(plaintext);
            fprintf(stderr, "session: received CTRL_ERROR code=0x%04X\n", code);
            if (s->state == SESSION_REKEYING ||
                code == ERR_AUTH_FAIL || code == ERR_VERSION ||
                code == ERR_CAPS) {
                session_event_emit(
                    s, EVENT_LOG_EVENT_REFUSE,
                    EVENT_LOG_SCOPE_SESSION,
                    code == ERR_CAPS
                        ? EVENT_LOG_REASON_CAPABILITY_MISMATCH
                        : EVENT_LOG_REASON_PROTOCOL_ERROR,
                    EVENT_LOG_NO_LEG, 0U, mono_ms());
                s->run_failed = 1;
                channel_close_all(s);
                enter_idle(s);
            }
        } else if (s->state == SESSION_REKEYING && pending_frame) {
            rekey_fail(s, "malformed pending-epoch error");
        }
        break;

    case CTRL_REKEY_REQUEST:
    case CTRL_REKEY_INIT:
    case CTRL_REKEY_REPLY:
    case CTRL_REKEY_CONFIRM:
    case CTRL_REKEY_COMMIT:
    case CTRL_REKEY_ACK:
        handle_rekey_control(s, type, plaintext, pt_len, pending_frame);
        break;

    case CTRL_REKEY_PQ_BITMAP:
        handle_pq_bitmap(s, plaintext, pt_len, pending_frame, now_ms);
        break;

    default:
        fprintf(stderr, "session: unknown control type 0x%02X — ERR_SESSION\n", type);
        send_ctrl_error(s, ERR_SESSION);
        track_err_session(s);
        break;
    }
}

void session_set_liveness_unbound(session_t *s, int unbound)
{
    if (!s)
        return;
    s->liveness_unbound = unbound ? 1 : 0;
    s->next_liveness_warn_ms = 0;
    s->liveness_hold_announced = 0U;
}

void session_set_shared_raw_display_tty(session_t *s, int shared)
{
    if (s)
        s->shared_raw_display_tty = shared ? 1U : 0U;
}

void session_set_bootstrap_timeout(session_t *s, int secs)
{
    s->bootstrap_deadline_ms = secs > 0 ? mono_ms() + (int64_t)secs * 1000
                                        : 0;
}

void session_set_bootstrap_deadline_ms(session_t *s, int64_t deadline_ms)
{
    if (!s)
        return;
    s->bootstrap_deadline_ms = deadline_ms > 0 ? deadline_ms : 0;
}

/* -------------------------------------------------------------------------
 * Process one incoming frame
 * ---------------------------------------------------------------------- */

static void process_frame(session_t *s, const uint8_t *frame,
                          size_t frame_len,
                          const multipath_token_t *ingress,
                          const preauth_source_t *source,
                          int source_required, int64_t preauth_now_ms);

static int preauth_source_from_ingress(const multipath_token_t *ingress,
                                       preauth_source_t *source)
{
    size_t address_length;

    if (!multipath_token_valid(ingress) || !source)
        return -1;
    address_length = ingress->family == 4U ? 4U : 16U;
    return preauth_source_init(source, ingress->family, ingress->address,
                               address_length, ingress->scope);
}

static int session_preauth_admit(session_t *s,
                                 const preauth_source_t *source,
                                 int source_required, int64_t now_ms,
                                 preauth_budget_handle_t *handle)
{
    memset(handle, 0, sizeof(*handle));
    handle->index = PREAUTH_NO_INDEX;
    if (!source) {
        if (source_required) {
            preauth_budget_note_malformed(&s->preauth_budget);
            return PREAUTH_ADMIT_DROP;
        }
        return PREAUTH_ADMIT_ALLOW;
    }
    if (!preauth_source_valid(source)) {
        preauth_budget_note_malformed(&s->preauth_budget);
        return PREAUTH_ADMIT_DROP;
    }
    return preauth_budget_admit(&s->preauth_budget, source, now_ms,
                                handle);
}

/* A CONNECTING stash can hold one authenticated channel-session data fragment before
 * READY. It may populate only the already-bounded reassembly table and run
 * pure route/codec validation; it never reaches an application or opens the
 * service barrier. This keeps future/conflicting handles fail-loud even when
 * UDP reorders data ahead of READY. */
static int session_prevalidate_stashed_d36(
    session_t *s, uint8_t chan_id, uint8_t type,
    int ff_flag, int mf_flag, const uint8_t fragment_wire[FRAGMENT_DESC_LEN],
    const uint8_t *plaintext, size_t pt_len, int64_t now_ms)
{
    const uint8_t *complete = plaintext;
    size_t complete_length = pt_len;
    const uint8_t *body = NULL;
    size_t body_length = 0U;
    uint8_t stream_slot = 0U;
    uint8_t stream_kind = 0U;

    if (!s || !plaintext || chan_id != 1U ||
        !session_channelised_active(s) ||
        !channel_is_negotiated(s, chan_id))
        return -1;
    if (!(ff_flag && !mf_flag)) {
        fragment_desc_t desc;
        const uint8_t *deliver_buf = NULL;
        size_t deliver_len = 0U;
        int rc;

        if ((s->selected_caps & UNMOOR_CAP_FRAGMENT_D21_V1) == 0U ||
            type == PTY_SYNC_DATA || type == PTY_SYNC_ACK ||
            (sync_active(s) && (type == PTY_DATA || type == PTY_EOF)) ||
            !fragment_wire || pt_len < FRAGMENT_HASH_LEN ||
            fragment_desc_decode(fragment_wire, &desc) != 0)
            return -1;
        rc = reasm_feed_fragment(
            &s->reasm, s->is_server ? 0x00 : 0x01, chan_id, type,
            ff_flag, mf_flag, &desc, plaintext,
            plaintext + FRAGMENT_HASH_LEN,
            pt_len - FRAGMENT_HASH_LEN, now_ms, REASM_TIMEOUT_MS,
            &deliver_buf, &deliver_len);
        if (rc == REASM_DROP)
            return 0;
        if (rc != REASM_DELIVER)
            return -1;
        complete = deliver_buf;
        complete_length = deliver_len;
    }
    {
        int route = channelised_data_body(
            s, chan_id, complete, complete_length, &body, &body_length,
            &stream_slot, &stream_kind);

        if (route < 0)
            return -1;
        if (route == 0)
            return 0;
    }
    return session_channel_data_prevalidate(
        s, stream_slot, stream_kind, type, body, body_length) == CHAN_OK
        ? 0 : -1;
}

/* Replay a frame that was stashed in CONNECTING, after session_key
 * becomes available. */
void session_replay_stashed_frame(session_t *s)
{
    session_replay_stashed_frame_at(s, mono_ms());
}

void session_replay_stashed_frame_at(session_t *s, int64_t preauth_now_ms)
{
    uint8_t plaintext[UNMOOR_TERMINAL_PLAINTEXT_MAX];
    size_t plaintext_capacity = sizeof(plaintext);
    uint8_t ad[10 + FRAGMENT_DESC_LEN];
    const uint8_t *dec_ct;
    size_t dec_ct_len;
    size_t ad_len = 10;
    size_t pt_len = 0;
    uint8_t chan_id;
    uint8_t dec_direction;
    int ff_flag;
    int mf_flag;
    int is_fragment_frame;
    int decrypt_rc;
    preauth_budget_handle_t preauth_handle;

    if (!s->stashed_valid)
        return;
    s->stashed_valid = 0;
    memset(plaintext, 0, sizeof(plaintext));
    memcpy(ad, s->stashed_ad, 10);
    chan_id = (uint8_t)((s->stashed_chan_byte >> 4) & 0x0fU);
    ff_flag = (s->stashed_chan_byte & CHAN_FF_BIT) != 0;
    mf_flag = (s->stashed_chan_byte & CHAN_MF_BIT) != 0;
    is_fragment_frame = chan_id != 0 && !(ff_flag && !mf_flag);
    dec_direction = s->is_server ? 0x00 : 0x01;
    dec_ct = s->stashed_ct;
    dec_ct_len = s->stashed_ct_len;

    if (s->stashed_ct_len < FRAME_TAG_LEN) {
        preauth_budget_note_malformed(&s->preauth_budget);
        goto out;
    }
    if (is_fragment_frame) {
        if (dec_ct_len < FRAGMENT_DESC_LEN + FRAME_TAG_LEN +
                         FRAGMENT_HASH_LEN) {
            preauth_budget_note_malformed(&s->preauth_budget);
            goto out;
        }
        memcpy(ad + 10, dec_ct, FRAGMENT_DESC_LEN);
        ad_len = sizeof(ad);
        dec_ct += FRAGMENT_DESC_LEN;
        dec_ct_len -= FRAGMENT_DESC_LEN;
    }
    if (dec_ct_len < FRAME_TAG_LEN ||
        dec_ct_len - FRAME_TAG_LEN > sizeof(plaintext)) {
        preauth_budget_note_malformed(&s->preauth_budget);
        goto out;
    }
    if (!s->have_session_key) {
        /* A stashed frame can only be replayed under a derived key. */
        preauth_budget_note_no_key(&s->preauth_budget);
        goto out;
    }
    if (session_preauth_admit(
            s, s->stashed_source_valid ? &s->stashed_source : NULL,
            s->stashed_source_required, preauth_now_ms,
            &preauth_handle) != PREAUTH_ADMIT_ALLOW)
        goto out;
    preauth_budget_note_aead_attempt(&s->preauth_budget);
    decrypt_rc = crypto_decrypt_ad(
        s->session_key, s->stashed_seq, dec_direction,
        ad, ad_len, dec_ct, dec_ct_len, plaintext, &pt_len);
    if (decrypt_rc != 0) {
        preauth_budget_failure(&s->preauth_budget, &preauth_handle,
                               preauth_now_ms);
        goto out;
    }
    preauth_budget_authenticated(&s->preauth_budget, &preauth_handle);

    /* multipath authority includes the immutable ingress token.  CONNECTING
     * stashing deliberately cannot preserve receive authority across the
     * HELLO_ACK boundary.  Still enforce the authenticated negotiated
     * protocol and canonical grammar here: withholding receive authority is
     * not a downgrade from fail-loud multipath parsing.  A valid selected control
     * is then dropped before replay, liveness, table, transport-peer, or
     * dispatch mutation; the peer reasserts it with a fresh SEQ after service
     * activation. */
    if (chan_id == 0 &&
        (s->stashed_type == CTRL_PATH_CHALLENGE ||
         s->stashed_type == CTRL_PATH_RESPONSE)) {
        uint64_t challenge_id = 0U;

        if (!session_multipath_contract_selected(s) ||
            memcmp(s->stashed_ad, s->pair_id, sizeof(s->pair_id)) != 0 ||
            (s->stashed_chan_byte & 0x0fU) != CHAN_FF_BIT ||
            path_control_decode(plaintext, pt_len, &challenge_id) != 0) {
            fprintf(stderr,
                    "session: malformed or unselected stashed multipath control — ERR_CAPS\n");
            session_protocol_error_close(s, ERR_CAPS);
            goto out;
        }
        fprintf(stderr,
                "session: authenticated stashed multipath control withheld until fresh ingress\n");
        goto out;
    }

    /* The stashed frame's receive-address candidate was overwritten by the
     * later HELLO_ACK receive.  It may authenticate/replay/dispatch here but
     * must never confirm that unrelated candidate as a roaming path. */
    if (!replay_accept(&s->replay, s->stashed_seq)) {
        fprintf(stderr, "session: stashed frame replay check failed\n");
        goto out;
    }
    s->last_authenticated_ms = preauth_now_ms;
    s->liveness_hold_announced = 0U;
    s->next_liveness_warn_ms = 0;
    sync_status_observe_authenticated(&s->sync_status,
                                      s->last_authenticated_ms);

    if ((s->stashed_chan_byte & 0x0cU) != 0) {
        fprintf(stderr,
                "session: authenticated stashed frame has reserved CHAN "
                "bits\n");
        if (chan_id == DELIVERY_CHANNEL_ID ||
            (session_channelised_active(s) && chan_id == 1U) ||
            (chan_id == 0 &&
             (s->stashed_type == CTRL_RD_DATA ||
              s->stashed_type == CTRL_RD_STATUS)))
            session_protocol_error_close(s, ERR_CAPS);
        goto out;
    }
    if (chan_id == 0) {
        if (!ff_flag || mf_flag) {
            fprintf(stderr,
                    "session: fragmented stashed control frame rejected\n");
            if (rekey_control_type(s->stashed_type))
                rekey_fail(s, "fragmented stashed epoch control");
            else if (s->stashed_type == CTRL_RD_DATA ||
                     s->stashed_type == CTRL_RD_STATUS)
                session_protocol_error_close(s, ERR_CAPS);
            goto out;
        }
        dispatch_control(s, s->stashed_type, plaintext, pt_len,
                         s->stashed_seq, 0, preauth_now_ms);
    } else if (session_channelised_active(s) && chan_id == 1U) {
        if (session_prevalidate_stashed_d36(
                s, chan_id, s->stashed_type, ff_flag, mf_flag,
                is_fragment_frame ? ad + 10 : NULL,
                plaintext, pt_len, preauth_now_ms) != 0) {
            fprintf(stderr,
                    "session: FATAL: invalid stashed channel-session data record\n");
            session_protocol_error_close(s, ERR_CAPS);
            goto out;
        }
        fprintf(stderr,
                "session: valid stashed channel-session data withheld until service phase\n");
    } else if (chan_id == DELIVERY_CHANNEL_ID) {
        uint16_t object_id = 0;
        int rc;

        if (is_fragment_frame || !channel_is_negotiated(s, chan_id)) {
            fprintf(stderr,
                    "session: FATAL: invalid stashed delivery-class route or "
                    "fragmentation\n");
            session_protocol_error_close(s, ERR_CAPS);
            goto out;
        }
        rc = session_delivery_prevalidate_latest(
            s, s->stashed_type, plaintext, pt_len, &object_id);
        if (rc != DELIVERY_RESULT_OK) {
            fprintf(stderr,
                    "session: FATAL: invalid stashed delivery-class record (%d)\n",
                    rc);
            session_protocol_error_close(s, ERR_CAPS);
            goto out;
        }
        fprintf(stderr,
                "session: valid stashed delivery-class record withheld until "
                "service phase\n");
    }

out:
    crypto_memzero(plaintext, plaintext_capacity);
    crypto_memzero(s->stashed_ct, sizeof(s->stashed_ct));
    crypto_memzero(s->stashed_ad, sizeof(s->stashed_ad));
    s->stashed_ct_len = 0;
    s->stashed_seq = 0;
    s->stashed_chan_byte = 0;
    s->stashed_type = 0;
    memset(&s->stashed_source, 0, sizeof(s->stashed_source));
    s->stashed_source_valid = 0;
    s->stashed_source_required = 0;
}

static void session_observe_path_change(session_t *s, int64_t now_ms,
                                        int reassert_sync_rx)
{
    send_scheduler_path_changed(&s->wire_scheduler, now_ms);
    sync_path_changed(s, now_ms, reassert_sync_rx);
    /* A legacy one-path roam needs an immediate authenticated reply on its
     * newly adopted route.  Under multipath, however, ordinary critical traffic
     * is intentionally copied onto both validated legs.  Whichever copy
     * arrives first may change the primary; making that change publish an
     * immediate critical sync-status object creates a self-exciting two-path loop
     * (copy -> primary change -> heartbeat -> copy).  The accepted frame
     * already proves liveness, targeted PATH_CHALLENGE owns validation, and
     * the normal five-second heartbeat remains scheduled, so do not pull it
     * forward for an active multipath primary change. */
    if (s->sync_status.active && !s->multipath_active)
        s->sync_status.next_heartbeat_ms = now_ms;
    if (!s->multipath_active)
        fprintf(stderr,
                "session: authenticated path generation %llu\n",
                (unsigned long long)s->wire_scheduler.path_generation);
}

static void process_frame_impl(session_t *s, const uint8_t *frame,
                          size_t frame_len,
                          const multipath_token_t *ingress,
                          const preauth_source_t *source,
                          int source_required, int64_t preauth_now_ms)
{
    uint8_t *bulk_receive = NULL;
    size_t bulk_receive_capacity = 0U;
    uint8_t pair_id[4], chan_byte, type;
    uint32_t seq;
    const uint8_t *ct;
    size_t ct_len;
    int selected_pending_epoch = 0;
    replay_window_t *selected_replay = &s->replay;

#if defined(UNMOOR_CHAOS) && UNMOOR_CHAOS
    if (chaos_drop("rx", frame, frame_len))
        return;
#endif
    if (s->multipath_active &&
        (!ingress || !multipath_token_valid(ingress))) {
        /* This is an internal structural boundary, not peer input: every
         * active multipath receive must arrive with immutable transport metadata.
         * Reject before decoding, AEAD, replay, liveness, or dispatch so the
         * legacy white-box seam cannot mutate any protocol authority. */
        fprintf(stderr,
                "session: FATAL: active multipath receive has no canonical immutable ingress token\n");
        s->run_failed = 1;
        s->wire_protocol_failure = 1;
        return;
    }

    /* Product UDP must provide immutable canonical source metadata in every
     * mode. White-box and stream seams may explicitly omit it. */
    if (source_required && !preauth_source_valid(source)) {
        preauth_budget_note_malformed(&s->preauth_budget);
        return;
    }

    /* source-prefilter public route: four raw bytes are sufficient to reject unrelated,
     * retired, and future traffic. Do this before complete decode or a bulk-transfer
     * receive-arena copy. */
    if (frame_len < sizeof(pair_id)) {
        preauth_budget_note_malformed(&s->preauth_budget);
        return;
    }
    if (memcmp(frame, s->pair_id, sizeof(pair_id)) == 0) {
        selected_pending_epoch = 0;
    } else if (s->pending_epoch_valid &&
               memcmp(frame, s->pending_pair_id, sizeof(pair_id)) == 0) {
        selected_pending_epoch = 1;
        selected_replay = &s->pending_replay;
    } else {
        preauth_budget_note_unknown_pair(&s->preauth_budget);
        return;
    }

    if (unmoor_frame_decode(frame, frame_len, pair_id, &seq,
                          &chan_byte, &type, &ct, &ct_len) != 0) {
        preauth_budget_note_malformed(&s->preauth_budget);
        return;
    }

    uint8_t chan_id = (chan_byte >> 4) & 0x0F;
    int bulk_frame = chan_id == BULK_CHANNEL_ID && s->bulk_enabled &&
                     (s->selected_caps &
                      UNMOOR_CAP_BULK_FILE_D33_V1) != 0U;

    if (bulk_frame)
        bulk_receive = session_bulk_receive_storage(
            s, &bulk_receive_capacity);

    /* UDP may receive the separately negotiated bulk-transfer ceiling, while every
     * legacy class remains capped at FRAME_MAX_LEN.  The clear header can
     * only select the arena/size candidate; AEAD, replay and channel grammar
     * still precede every bulk mutation. */
    if (frame_len != FRAME_HEADER_LEN + ct_len ||
        (!bulk_frame && frame_len > FRAME_MAX_LEN) ||
        (bulk_frame &&
         (!bulk_receive || frame_len > bulk_receive_capacity ||
          frame_len > s->bulk_config.wire_budget))) {
        preauth_budget_note_malformed(&s->preauth_budget);
        return;
    }
    if (bulk_frame && frame != bulk_receive) {
        memmove(bulk_receive, frame, frame_len);
        frame = bulk_receive;
        ct = frame + FRAME_HEADER_LEN;
    }
    uint8_t direction_incoming = s->is_server ? 0x00 : 0x01;
    /* direction_incoming: if we're server, incoming is from client (0x00) */

    /* An IDLE server cannot accept HELLO_ACK. Treat it as quiet malformed
     * pre-authentication traffic; it has no error or close authority. */
    if (s->is_server && s->state == SESSION_IDLE &&
        chan_id == 0 && type == CTRL_HELLO_ACK) {
        preauth_budget_note_malformed(&s->preauth_budget);
        return;
    }

    int ff_flag = (chan_byte & CHAN_FF_BIT) ? 1 : 0;
    int mf_flag = (chan_byte & CHAN_MF_BIT) ? 1 : 0;
    int is_fragment_frame = chan_id != 0 && !(ff_flag && !mf_flag);
    int pq_share_frame = chan_id == 0 && type == CTRL_REKEY_PQ_SHARE;

    /* Build the base AD. Multi-fragment frames append their clear descriptor
     * bytes below, before any descriptor field is interpreted. */
    uint8_t ad[10 + PQ_REKEY_SHARE_DESCRIPTOR_LEN];
    size_t ad_len = 10;
    memcpy(ad, pair_id, 4);
    ad[4] = (uint8_t)(seq        & 0xFF);
    ad[5] = (uint8_t)((seq >>  8) & 0xFF);
    ad[6] = (uint8_t)((seq >> 16) & 0xFF);
    ad[7] = (uint8_t)((seq >> 24) & 0xFF);
    ad[8] = chan_byte;
    ad[9] = type;

    /* Determine which key to use for decryption. The pair id decides the
     * epoch first: a pending-epoch frame proves possession of the pending
     * key and nothing else, so its control type never selects the
     * bootstrap key. Only the current epoch carries the two hello frames. */
    const uint8_t *decrypt_key = NULL;
    int is_hello_frame = 0;

    if (selected_pending_epoch) {
        decrypt_key = s->pending_key;
    } else if (chan_id == 0 && type == CTRL_HELLO && s->is_server) {
        /* Server receives CTRL_HELLO with hello_key */
        decrypt_key = s->hello_key;
        is_hello_frame = 1;
    } else if (chan_id == 0 && type == CTRL_HELLO_ACK && !s->is_server) {
        /* Client receives CTRL_HELLO_ACK with hello_key */
        decrypt_key = s->hello_key;
        is_hello_frame = 1;
    } else {
        decrypt_key = s->session_key;
    }

    /* Never verify under a buffer that holds no live key. A wiped or
     * not-yet-derived key is all zero, and an all-zero key authenticates
     * any forgery built with it. Session frames that arrive before the
     * session key exists are only kept by the CONNECTING stash below. */
    if (is_hello_frame ? !s->have_hello_key
                       : (!selected_pending_epoch && !s->have_session_key &&
                          s->state != SESSION_CONNECTING)) {
        preauth_budget_note_no_key(&s->preauth_budget);
        return;
    }

    /* For CTRL_HELLO/CTRL_HELLO_ACK: direction is fixed */
    uint8_t dec_direction = direction_incoming;
    if (is_hello_frame) {
        /* CTRL_HELLO: sent by client (direction 0x00), so nonce uses 0x00 */
        /* CTRL_HELLO_ACK: sent by server (direction 0x01) */
        if (type == CTRL_HELLO)     dec_direction = 0x00;
        if (type == CTRL_HELLO_ACK) dec_direction = 0x01;
    }

    /* AEAD decrypt.  Bulk-transfer decrypts exactly in place inside its distinct
     * negotiated receive arena; the encoded outbound arena is never touched.
     * Existing classes retain the original fixed 512-byte stack scratch. */
    uint8_t legacy_plaintext[UNMOOR_TERMINAL_PLAINTEXT_MAX];
    uint8_t *plaintext = legacy_plaintext;
    size_t plaintext_capacity = sizeof(legacy_plaintext);
    size_t pt_len = 0;

    /* for hello frames, the wire body carries a 24-byte
     * cleartext hello_nonce prefix used directly as the AEAD nonce. Peel it
     * off here so the decrypt path sees the bare ciphertext. Other frames
     * are unchanged. */
    const uint8_t *dec_ct = ct;
    size_t         dec_ct_len = ct_len;
    const uint8_t *fragment_desc_wire = NULL;
    const uint8_t *pq_share_descriptor_wire = NULL;
    uint8_t        hello_nonce[24];
    int            have_hello_nonce = 0;
    preauth_budget_handle_t preauth_handle;
    if (pq_share_frame) {
        if (ct_len < PQ_REKEY_SHARE_DESCRIPTOR_LEN + FRAME_TAG_LEN + 1U) {
            preauth_budget_note_malformed(&s->preauth_budget);
            return;
        }
        pq_share_descriptor_wire = ct;
        memcpy(ad + 10, pq_share_descriptor_wire,
               PQ_REKEY_SHARE_DESCRIPTOR_LEN);
        ad_len = 10U + PQ_REKEY_SHARE_DESCRIPTOR_LEN;
        dec_ct = ct + PQ_REKEY_SHARE_DESCRIPTOR_LEN;
        dec_ct_len = ct_len - PQ_REKEY_SHARE_DESCRIPTOR_LEN;
    } else if (is_fragment_frame) {
        if (ct_len < FRAGMENT_DESC_LEN + FRAME_TAG_LEN + FRAGMENT_HASH_LEN) {
            preauth_budget_note_malformed(&s->preauth_budget);
            return;
        }
        fragment_desc_wire = ct;
        memcpy(ad + 10, fragment_desc_wire, FRAGMENT_DESC_LEN);
        ad_len = 10U + FRAGMENT_DESC_LEN;
        dec_ct = ct + FRAGMENT_DESC_LEN;
        dec_ct_len = ct_len - FRAGMENT_DESC_LEN;
    } else if (is_hello_frame) {
        if (ct_len < 24 + 16) {
            preauth_budget_note_malformed(&s->preauth_budget);
            return;
        }
        memcpy(hello_nonce, ct, 24);
        dec_ct      = ct + 24;
        dec_ct_len  = ct_len - 24;
        have_hello_nonce = 1;
    }

    if (bulk_frame) {
        plaintext = (uint8_t *)(uintptr_t)dec_ct;
        plaintext_capacity = dec_ct_len >= FRAME_TAG_LEN
            ? dec_ct_len - FRAME_TAG_LEN : 0U;
    }

    /* Bound ciphertext length against the selected plaintext arena. */
    if (dec_ct_len < 16 || dec_ct_len - 16 > plaintext_capacity) {
        preauth_budget_note_malformed(&s->preauth_budget);
        if (have_hello_nonce) crypto_memzero(hello_nonce, 24);
        return;
    }

    /* If we are CONNECTING and a non-HELLO control frame arrived, we
     * don't yet have a session_key. Stash it so we can decrypt after
     * handle_hello_ack derives the key. */
    if (s->state == SESSION_CONNECTING && !is_hello_frame && !s->have_session_key) {
        if (ct_len <= sizeof(s->stashed_ct) && !s->stashed_valid) {
            s->stashed_valid    = 1;
            s->stashed_chan_byte = chan_byte;
            s->stashed_type      = type;
            s->stashed_seq       = seq;
            memcpy(s->stashed_ad, ad, 10);
            memcpy(s->stashed_ct, ct, ct_len);
            s->stashed_ct_len    = ct_len;
            if (source) {
                s->stashed_source = *source;
                s->stashed_source_valid = 1;
            } else {
                memset(&s->stashed_source, 0,
                       sizeof(s->stashed_source));
                s->stashed_source_valid = 0;
            }
            s->stashed_source_required = source_required;
        }
        return;
    }

    if (session_preauth_admit(s, source, source_required,
                              preauth_now_ms, &preauth_handle) !=
        PREAUTH_ADMIT_ALLOW) {
        if (have_hello_nonce)
            crypto_memzero(hello_nonce, sizeof(hello_nonce));
        return;
    }
    preauth_budget_note_aead_attempt(&s->preauth_budget);

    int decrypt_rc;
    if (is_hello_frame) {
        decrypt_rc = crypto_decrypt_with_nonce(decrypt_key, hello_nonce, ad,
                                               dec_ct, dec_ct_len,
                                               plaintext, &pt_len);
        crypto_memzero(hello_nonce, 24);
    } else {
        decrypt_rc = crypto_decrypt_ad(decrypt_key, seq, dec_direction,
                                       ad, ad_len, dec_ct, dec_ct_len,
                                       plaintext, &pt_len);
    }

    if (decrypt_rc != 0) {
        crypto_memzero(plaintext, plaintext_capacity);
        preauth_budget_failure(&s->preauth_budget, &preauth_handle,
                               preauth_now_ms);
        return;
    }
    preauth_budget_authenticated(&s->preauth_budget, &preauth_handle);

    /* Replay check runs AFTER successful AEAD verification, using the
     * SEQ that was authenticated. Only for session frames (not pre-session
     * hello). This prevents a forged frame from poisoning the replay window. */
    if (!is_hello_frame) {
        if (!replay_accept(selected_replay, seq)) {
            if (s->replay_drop_count != UINT64_MAX)
                s->replay_drop_count++;
            /* Replays are authenticated but peer-controlled. Multipath normally
             * creates one expected duplicate per critical plan, so logging
             * every drop would eventually let an unread stderr block the
             * event loop. Preserve a saturating counter and a hard sample. */
            if (session_replay_log_due(s->replay_drop_count) &&
                !session_async_terminal_text_suppressed(s))
                fprintf(stderr,
                        "session: replay detected (seq=%u chan=%u type=%u) — dropped [sample=%llu]\n",
                        seq, chan_id, type,
                        (unsigned long long)s->replay_drop_count);
            crypto_memzero(plaintext, plaintext_capacity);
            return;
        }
    }

    /* Successful decrypt updates liveness only after replay acceptance. */
    s->last_authenticated_ms = preauth_now_ms;
    s->liveness_hold_announced = 0U;
    s->next_liveness_warn_ms = 0;
    sync_status_observe_authenticated(&s->sync_status,
                                      s->last_authenticated_ms);

    /* multipath path controls are consumed at the authority boundary, not by the
     * generic control dispatcher.  Capability and exact grammar precede
     * even provisional adoption, while AEAD/replay/HWM remain above them. */
    if (!is_hello_frame && chan_id == 0 &&
        (type == CTRL_PATH_CHALLENGE || type == CTRL_PATH_RESPONSE)) {
        uint64_t challenge_id = 0;
        int hwm = selected_replay->hwm == seq;
        multipath_handle_t handle;
        multipath_snapshot_t before_response;
        multipath_snapshot_t after_response;
        int have_before_response = 0;
        int path_rc;
        int peer_changed;
        int primary_changed = 0;
        int64_t path_now = mono_ms();

        if (!session_multipath_contract_selected(s) ||
            !s->multipath_active) {
            fprintf(stderr,
                    "session: authenticated unselected multipath control — ERR_CAPS\n");
            session_protocol_error_close(s, ERR_CAPS);
            crypto_memzero(plaintext, plaintext_capacity);
            return;
        }
        if (selected_pending_epoch || !ingress ||
            (chan_byte & 0x0fU) != CHAN_FF_BIT ||
            path_control_decode(plaintext, pt_len, &challenge_id) != 0) {
            fprintf(stderr,
                    "session: malformed or non-current multipath control — ERR_CAPS\n");
            session_protocol_error_close(s, ERR_CAPS);
            crypto_memzero(plaintext, plaintext_capacity);
            return;
        }
        if (type == CTRL_PATH_RESPONSE &&
            multipath_get_snapshot(&s->multipath, &before_response) == 0)
            have_before_response = 1;
        path_rc = type == CTRL_PATH_CHALLENGE
            ? multipath_receive_challenge(
                  &s->multipath, ingress,
                  hwm ? MULTIPATH_RX_HWM : MULTIPATH_RX_STALE,
                  challenge_id, path_now, &handle, &primary_changed)
            : multipath_receive_response(
                  &s->multipath, ingress,
                  hwm ? MULTIPATH_RX_HWM : MULTIPATH_RX_STALE,
                  challenge_id, &handle, &primary_changed);
        if (!hwm) {
            if (path_rc == MULTIPATH_ERROR) {
                s->run_failed = 1;
                session_protocol_error_close(s, ERR_CAPS);
            }
            crypto_memzero(plaintext, plaintext_capacity);
            return;
        }
        if (path_rc == MULTIPATH_IGNORED) {
            if (s->multipath_mismatch_count != UINT64_MAX)
                s->multipath_mismatch_count++;
            if (session_multipath_mismatch_log_due(
                    s->multipath_mismatch_count) &&
                !session_async_terminal_text_suppressed(s))
                fprintf(stderr,
                        "session: multipath challenge binding mismatch — ignored without path authority [sample=%llu]\n",
                        (unsigned long long)s->multipath_mismatch_count);
            crypto_memzero(plaintext, plaintext_capacity);
            return;
        }
        if (path_rc != MULTIPATH_ACCEPTED) {
            fprintf(stderr,
                    "session: FATAL: multipath path-control engine failure\n");
            s->run_failed = 1;
            session_protocol_error_close(s, ERR_CAPS);
            crypto_memzero(plaintext, plaintext_capacity);
            return;
        }
        peer_changed = s->transport->ops->peer_confirm_from(
            s->transport, ingress);
        if (peer_changed < 0 ||
            (peer_changed != 0) != (primary_changed != 0)) {
            fprintf(stderr,
                    "session: FATAL: multipath path/transport authority diverged\n");
            s->run_failed = 1;
            s->wire_protocol_failure = 1;
            crypto_memzero(plaintext, plaintext_capacity);
            return;
        }
        if (peer_changed > 0) {
            session_observe_path_change(s, path_now, 1);
            session_event_emit_multipath_roam(s, &handle, path_now);
        }
        if (type == CTRL_PATH_RESPONSE) {
            int first_validation =
                have_before_response &&
                handle.index < before_response.path_limit &&
                before_response.entry[handle.index].generation ==
                    handle.generation &&
                before_response.entry[handle.index].state !=
                    MULTIPATH_PATH_VALIDATED &&
                multipath_get_snapshot(&s->multipath,
                                       &after_response) == 0 &&
                handle.index < after_response.path_limit &&
                after_response.entry[handle.index].generation ==
                    handle.generation &&
                after_response.entry[handle.index].state ==
                    MULTIPATH_PATH_VALIDATED;

            if (session_refresh_path_legs(s, path_now) == 0 &&
                handle.index < s->path_leg_count)
                (void)path_leg_challenge_response(
                    &s->path_leg[handle.index], handle.generation,
                    challenge_id, path_now);
            session_multipath_log_snapshot(s, "response", path_now);
            if (first_validation)
                session_event_emit(
                    s, EVENT_LOG_EVENT_VALIDATE, EVENT_LOG_SCOPE_LEG,
                    EVENT_LOG_REASON_CHALLENGE_CONFIRMED,
                    (int)handle.index, handle.generation, path_now);
        }
        /* A PATH_CHALLENGE may be reasserted indefinitely under loss.  Its
         * accepted state is already visible through counters and any actual
         * primary-change record; logging a full transition for every retry
         * would let N=32 turn stderr backpressure into network liveness.
         * A matching response is one-shot validation progress and is logged. */
        crypto_memzero(plaintext, plaintext_capacity);
        return;
    }

    /* Ordinary session-key frames retain roaming-freshest-path. Under multipath, the immutable
     * ingress token enters the configured bounded path pool only after
     * AEAD/replay/HWM; stale accepted traffic is an observable no-op. */
    if (!is_hello_frame) {
        int hwm = selected_replay->hwm == seq;
        if (s->multipath_active && ingress) {
            multipath_handle_t handle;
            int primary_changed = 0;
            int64_t path_now = mono_ms();

            if (!session_multipath_contract_selected(s)) {
                fprintf(stderr,
                        "session: authenticated frame violates the selected multipath count — ERR_CAPS\n");
                s->run_failed = 1;
                session_protocol_error_close(s, ERR_CAPS);
                crypto_memzero(plaintext, plaintext_capacity);
                return;
            }
            int path_rc = multipath_observe(
                &s->multipath, ingress,
                hwm ? MULTIPATH_RX_HWM : MULTIPATH_RX_STALE,
                path_now, &handle, &primary_changed);
            if (path_rc == MULTIPATH_ERROR ||
                path_rc == MULTIPATH_EXHAUSTED) {
                fprintf(stderr,
                        "session: FATAL: multipath receive authority failed\n");
                s->run_failed = 1;
                s->wire_protocol_failure = 1;
                crypto_memzero(plaintext, plaintext_capacity);
                return;
            }
            if (hwm) {
                int peer_changed =
                    s->transport->ops->peer_confirm_from(s->transport,
                                                         ingress);
                if (peer_changed < 0 ||
                    (peer_changed != 0) != (primary_changed != 0)) {
                    fprintf(stderr,
                            "session: FATAL: multipath path/transport authority diverged\n");
                    s->run_failed = 1;
                    s->wire_protocol_failure = 1;
                    crypto_memzero(plaintext, plaintext_capacity);
                    return;
                }
                if (peer_changed > 0) {
                    session_observe_path_change(
                        s, path_now,
                        !(chan_id == 1U && type == PTY_SYNC_ACK));
                    session_event_emit_multipath_roam(
                        s, &handle, path_now);
                }
                if (primary_changed) {
                    multipath_snapshot_t path_snapshot;

                    if (multipath_get_snapshot(
                            &s->multipath, &path_snapshot) == 0 &&
                        path_snapshot.validated_count ==
                            path_snapshot.path_limit)
                        session_multipath_log_snapshot(
                            s, "primary-change", path_now);
                }
            }
        } else if (!s->multipath_active && hwm &&
                   s->transport->ops->peer_confirm) {
            int peer_changed =
                s->transport->ops->peer_confirm(s->transport);
            if (peer_changed > 0) {
                session_observe_path_change(s, mono_ms(), 1);
                session_event_emit(
                    s, EVENT_LOG_EVENT_ROAM, EVENT_LOG_SCOPE_SESSION,
                    EVENT_LOG_REASON_AUTHENTICATED_HWM,
                    EVENT_LOG_NO_LEG, 0U, mono_ms());
            }
        }
    }

    /* Dispatch. CHAN low bits other than FF/MF are reserved and are checked
     * only now, after authentication and replay acceptance. */
    if (chan_id == BULK_CHANNEL_ID &&
        (s->selected_caps & UNMOOR_CAP_BULK_FILE_D33_V1) != 0U &&
        (selected_pending_epoch ||
         (chan_byte & 0x0fU) != CHAN_FF_BIT ||
         type < BULK_REQUEST || type > BULK_STATUS)) {
        fprintf(stderr,
                "session: FATAL: noncanonical or pending-epoch bulk-transfer frame\n");
        session_protocol_error_close(s, ERR_CAPS);
        crypto_memzero(plaintext, plaintext_capacity);
        return;
    }
    if ((chan_byte & 0x0cU) != 0) {
        fprintf(stderr, "session: reserved CHAN flag bits set\n");
        if (chan_id == DELIVERY_CHANNEL_ID ||
            (chan_id == 0 &&
             (type == CTRL_RD_DATA || type == CTRL_RD_STATUS)))
            session_protocol_error_close(s, ERR_CAPS);
        crypto_memzero(plaintext, plaintext_capacity);
        return;
    }
    if (chan_id == 0) {
        if (!ff_flag || mf_flag) {
            fprintf(stderr, "session: fragmented control frame rejected\n");
            if (rekey_control_type(type))
                rekey_fail(s, "fragmented epoch control");
            else if (type == CTRL_RD_DATA || type == CTRL_RD_STATUS ||
                     channel_control_type_valid(type))
                session_protocol_error_close(s, ERR_CAPS);
            crypto_memzero(plaintext, plaintext_capacity);
            return;
        }
        if (selected_pending_epoch &&
            type != CTRL_REKEY_CONFIRM && type != CTRL_REKEY_COMMIT &&
            type != CTRL_CLOSE && type != CTRL_ERROR) {
            rekey_fail(s, "invalid pending-epoch control type");
            crypto_memzero(plaintext, plaintext_capacity);
            return;
        }
        if (type == CTRL_REKEY_PQ_SHARE) {
            handle_pq_share(s, pq_share_descriptor_wire,
                            plaintext, pt_len, selected_pending_epoch,
                            preauth_now_ms);
        } else {
            dispatch_control(s, type, plaintext, pt_len, seq,
                             selected_pending_epoch, preauth_now_ms);
        }
    } else {
        int implicit_proof_candidate =
            s->state == SESSION_REKEYING && s->is_server &&
            s->rekey_phase == REKEY_S_WAIT_ACK &&
            !selected_pending_epoch;
        int latest_nonservice_candidate =
            s->state != SESSION_ESTABLISHED &&
            !selected_pending_epoch &&
            chan_id == DELIVERY_CHANNEL_ID &&
            delivery_latest_selected(s);
        int d36_pre_service_candidate =
            s->state != SESSION_ESTABLISHED &&
            !selected_pending_epoch &&
            session_channelised_active(s) && chan_id == 1U;
        int latest_prebarrier_candidate =
            implicit_proof_candidate && chan_id == DELIVERY_CHANNEL_ID &&
            delivery_latest_selected(s) && !is_fragment_frame;
        int combined_status_record_candidate = 0;
        int combined_status_proof_candidate = 0;
        uint8_t logical_chan =
            (uint8_t)((chan_id << 4) | CHAN_FF_BIT);

        /* Channel dispatch (PTY and others). An adopted-epoch application
         * frame can heal a lost final ACK, but only after channel capability
         * and family-specific canonical framing checks below. Combined sync-status
         * is narrower: a canonical, configured object-1 HEAD/BLOCK is the
         * only delivery-class record with implicit epoch-proof authority. */
        if (s->state != SESSION_ESTABLISHED &&
            !implicit_proof_candidate) {
            if (latest_nonservice_candidate) {
                uint16_t object_id = 0;
                int prevalidate_rc;

                if (!channel_is_negotiated(s, chan_id) ||
                    is_fragment_frame) {
                    fprintf(stderr,
                            "session: FATAL: invalid early delivery-class channel "
                            "route or fragmentation\n");
                    session_protocol_error_close(s, ERR_CAPS);
                    crypto_memzero(plaintext, plaintext_capacity);
                    return;
                }
                prevalidate_rc = session_delivery_prevalidate_latest(
                    s, type, plaintext, pt_len, &object_id);
                if (prevalidate_rc == DELIVERY_RESULT_NOT_READY ||
                    prevalidate_rc == DELIVERY_RESULT_STALE) {
                    fprintf(stderr,
                            "session: valid early delivery-class record has no target "
                            "proof — withheld\n");
                    crypto_memzero(plaintext, plaintext_capacity);
                    return;
                }
                if (prevalidate_rc != DELIVERY_RESULT_OK) {
                    fprintf(stderr,
                            "session: FATAL: invalid early delivery-class record "
                            "(%d)\n", prevalidate_rc);
                    session_protocol_error_close(s, ERR_CAPS);
                    crypto_memzero(plaintext, plaintext_capacity);
                    return;
                }
                fprintf(stderr,
                        "session: valid early delivery-class record withheld until "
                        "service phase\n");
            }
            /* Current canonical delivery and all pending application data
             * are authenticated/replay-accounted but never reach a channel
             * before the local barrier. Channel-session class-1 is the exception only
             * for validation: a complete encrypted handle must still reject
             * a future/conflicting incarnation before any application side
             * effect, then the record is withheld below. */
            if (!d36_pre_service_candidate) {
                crypto_memzero(plaintext, plaintext_capacity);
                return;
            }
        }

        /* A capability violation is rejected after AEAD/replay acceptance but
         * before a forbidden fragment can allocate or mutate reassembly
         * state. channel_dispatch emits ERR_CAPS and closes the session. */
        if (!channel_is_negotiated(s, chan_id)) {
            if (implicit_proof_candidate) {
                fprintf(stderr,
                        "session: FATAL: unnegotiated channel cannot prove "
                        "epoch adoption\n");
                session_protocol_error_close(s, ERR_CAPS);
                crypto_memzero(plaintext, plaintext_capacity);
                return;
            }
            (void)channel_dispatch(s, logical_chan, type,
                                   plaintext, pt_len);
            crypto_memzero(plaintext, plaintext_capacity);
            return;
        }
        if (chan_id == DELIVERY_CHANNEL_ID &&
            delivery_latest_selected(s) && is_fragment_frame) {
            fprintf(stderr,
                    "session: FATAL: fragmented delivery-class channel-2 record "
                    "rejected before reassembly\n");
            session_protocol_error_close(s, ERR_CAPS);
            crypto_memzero(plaintext, plaintext_capacity);
            return;
        }
        if (latest_prebarrier_candidate) {
            uint16_t proof_object_id = 0;
            int prevalidate_rc = session_delivery_prevalidate_latest(
                s, type, plaintext, pt_len, &proof_object_id);
            if (prevalidate_rc == DELIVERY_RESULT_NOT_READY ||
                prevalidate_rc == DELIVERY_RESULT_STALE) {
                fprintf(stderr,
                        "session: valid pre-barrier delivery-class record has no "
                        "target proof — withheld\n");
                crypto_memzero(plaintext, plaintext_capacity);
                return;
            }
            if (prevalidate_rc != DELIVERY_RESULT_OK) {
                fprintf(stderr,
                        "session: FATAL: invalid pre-barrier delivery-class record "
                        "(%d)\n", prevalidate_rc);
                session_protocol_error_close(s, ERR_CAPS);
                crypto_memzero(plaintext, plaintext_capacity);
                return;
            }
            combined_status_record_candidate =
                delivery_status_combined(s) &&
                proof_object_id == DELIVERY_LATEST_SYSTEM_OBJECT_ID &&
                (type == DELIVERY_LATEST_HEAD_TYPE ||
                 type == DELIVERY_LATEST_BLOCK_TYPE);
            combined_status_proof_candidate =
                combined_status_record_candidate &&
                type == DELIVERY_LATEST_BLOCK_TYPE;
            if (!combined_status_record_candidate) {
                /* A client may start ordinary delivery immediately after
                 * its final ACK completes while the server is still waiting
                 * for that ACK.  Valid application delivery-class traffic has no epoch-rekey
                 * authority and is stale-worthless here; malformed or
                 * unconfigured records were rejected above. */
                fprintf(stderr,
                        "session: valid pre-barrier delivery-class application record "
                        "withheld until epoch confirmation\n");
                crypto_memzero(plaintext, plaintext_capacity);
                return;
            }
            if (combined_status_proof_candidate) {
                /* HEAD authenticates geometry only. BLOCK additionally
                 * carries a pure-validated sync-status epoch/counter value and is
                 * therefore the first object-1 record allowed to prove the
                 * adopted epoch. */
                finish_epoch_barrier(s);
                if (s->state != SESSION_ESTABLISHED) {
                    crypto_memzero(plaintext, plaintext_capacity);
                    return;
                }
            }
        }
        if (!is_fragment_frame) {
            const uint8_t *dispatch_plaintext = plaintext;
            size_t dispatch_length = pt_len;
            uint8_t stream_slot = 0U;
            uint8_t stream_kind = 0U;
            int route = channelised_data_body(
                s, chan_id, plaintext, pt_len,
                &dispatch_plaintext, &dispatch_length,
                &stream_slot, &stream_kind);

            if (route < 0) {
                fprintf(stderr,
                        "session: FATAL: invalid channel-session data handle/class route\n");
                session_protocol_error_close(s, ERR_CAPS);
                crypto_memzero(plaintext, plaintext_capacity);
                return;
            }
            if (route == 0) {
                crypto_memzero(plaintext, plaintext_capacity);
                return;
            }
            if (d36_pre_service_candidate) {
                if (session_channel_data_prevalidate(
                        s, stream_slot, stream_kind, type,
                        dispatch_plaintext, dispatch_length) != CHAN_OK) {
                    fprintf(stderr,
                            "session: FATAL: invalid pre-service channel-session data record\n");
                    session_protocol_error_close(s, ERR_CAPS);
                }
                crypto_memzero(plaintext, plaintext_capacity);
                return;
            }
            /* Independent single messages never disturb partial assemblies. */
            if (implicit_proof_candidate &&
                !combined_status_record_candidate) {
                int prevalidate = session_channelised_active(s)
                    ? session_channel_data_prevalidate(
                          s, stream_slot, stream_kind, type,
                          dispatch_plaintext, dispatch_length)
                    : channel_prevalidate(s, logical_chan, type,
                                          dispatch_plaintext,
                                          dispatch_length);
                if (prevalidate != CHAN_OK) {
                    fprintf(stderr,
                            "session: FATAL: invalid application epoch proof\n");
                    session_protocol_error_close(s, ERR_CAPS);
                    crypto_memzero(plaintext, plaintext_capacity);
                    return;
                }
                finish_epoch_barrier(s);
                if (s->state != SESSION_ESTABLISHED) {
                    crypto_memzero(plaintext, plaintext_capacity);
                    return;
                }
            }
            if (session_channelised_active(s)) {
                if (session_channel_data_dispatch(
                        s, stream_slot, stream_kind, type,
                        dispatch_plaintext, dispatch_length) != CHAN_OK) {
                    fprintf(stderr,
                            "session: FATAL: invalid channel body\n");
                    session_protocol_error_close(s, ERR_CAPS);
                }
            } else {
                (void)channel_dispatch(s, logical_chan, type,
                                       dispatch_plaintext,
                                       dispatch_length);
            }
        } else {
            if ((s->selected_caps & UNMOOR_CAP_FRAGMENT_D21_V1) == 0) {
                fprintf(stderr,
                        "session: authenticated fragment without the negotiated "
                        "capability (selected_caps=0x%08X) — ERR_CAPS\n",
                        s->selected_caps);
                session_protocol_error_close(s, ERR_CAPS);
                crypto_memzero(plaintext, plaintext_capacity);
                return;
            }
            if (chan_id == 1 &&
                (type == PTY_SYNC_DATA || type == PTY_SYNC_ACK ||
                 (sync_active(s) && (type == PTY_DATA || type == PTY_EOF)))) {
                /* Preserve capability error precedence: lack of fragmentation is ERR_CAPS
                 * above. Once fragmentation is selected, terminal-sync family
                 * exclusivity are checked before a forbidden frame can
                 * allocate or mutate reassembly state. */
                fprintf(stderr,
                        "session: FATAL: fragmented PTY type 0x%02X is invalid "
                        "for the negotiated delivery path — closing session\n",
                        type);
                s->run_failed = 1;
                session_close(s);
                crypto_memzero(plaintext, plaintext_capacity);
                return;
            }
            fragment_desc_t desc;
            const uint8_t *deliver_buf = NULL;
            size_t deliver_len = 0;
            int rc = REASM_ERROR;
            if (pt_len >= FRAGMENT_HASH_LEN && fragment_desc_wire &&
                fragment_desc_decode(fragment_desc_wire, &desc) == 0) {
                rc = reasm_feed_fragment(&s->reasm,
                                         direction_incoming, chan_id, type,
                                         ff_flag, mf_flag, &desc,
                                         plaintext,
                                         plaintext + FRAGMENT_HASH_LEN,
                                         pt_len - FRAGMENT_HASH_LEN,
                                         preauth_now_ms, REASM_TIMEOUT_MS,
                                         &deliver_buf, &deliver_len);
            }
            if (rc == REASM_DELIVER) {
                const uint8_t *dispatch_plaintext = deliver_buf;
                size_t dispatch_length = deliver_len;
                uint8_t stream_slot = 0U;
                uint8_t stream_kind = 0U;
                int route = channelised_data_body(
                    s, chan_id, deliver_buf, deliver_len,
                    &dispatch_plaintext, &dispatch_length,
                    &stream_slot, &stream_kind);

                if (route < 0) {
                    fprintf(stderr,
                            "session: FATAL: invalid reassembled channel-session data handle/class route\n");
                    session_protocol_error_close(s, ERR_CAPS);
                    crypto_memzero(plaintext, plaintext_capacity);
                    return;
                }
                if (route == 0) {
                    crypto_memzero(plaintext, plaintext_capacity);
                    return;
                }
                if (d36_pre_service_candidate) {
                    if (session_channel_data_prevalidate(
                            s, stream_slot, stream_kind, type,
                            dispatch_plaintext,
                            dispatch_length) != CHAN_OK) {
                        fprintf(stderr,
                                "session: FATAL: invalid reassembled pre-service channel-session data record\n");
                        session_protocol_error_close(s, ERR_CAPS);
                    }
                    crypto_memzero(plaintext, plaintext_capacity);
                    return;
                }
                if (implicit_proof_candidate) {
                    int prevalidate = session_channelised_active(s)
                        ? session_channel_data_prevalidate(
                              s, stream_slot, stream_kind, type,
                              dispatch_plaintext, dispatch_length)
                        : channel_prevalidate(s, logical_chan, type,
                                              dispatch_plaintext,
                                              dispatch_length);
                    if (prevalidate != CHAN_OK) {
                        fprintf(stderr,
                                "session: FATAL: invalid reassembled PTY "
                                "epoch proof\n");
                        session_protocol_error_close(s, ERR_CAPS);
                        crypto_memzero(plaintext, plaintext_capacity);
                        return;
                    }
                    finish_epoch_barrier(s);
                    if (s->state != SESSION_ESTABLISHED) {
                        crypto_memzero(plaintext, plaintext_capacity);
                        return;
                    }
                }
                if (session_channelised_active(s)) {
                    if (session_channel_data_dispatch(
                            s, stream_slot, stream_kind, type,
                            dispatch_plaintext,
                            dispatch_length) != CHAN_OK) {
                        fprintf(stderr,
                                "session: FATAL: invalid reassembled channel body\n");
                        session_protocol_error_close(s, ERR_CAPS);
                    }
                } else {
                    (void)channel_dispatch(s, logical_chan, type,
                                           dispatch_plaintext,
                                           dispatch_length);
                }
            } else if (rc == REASM_ERROR) {
                fprintf(stderr,
                        "session: authenticated fragment rejected on ch%u type=0x%02X (ff=%d mf=%d len=%zu)\n",
                        chan_id, type, ff_flag, mf_flag, pt_len);
            }
            /* REASM_DROP: incomplete, duplicate, completed, or pool-full. */
        }
    }

    crypto_memzero(plaintext, plaintext_capacity);
}

static void process_frame(session_t *s, const uint8_t *frame,
                          size_t frame_len,
                          const multipath_token_t *ingress,
                          const preauth_source_t *source,
                          int source_required, int64_t preauth_now_ms)
{
    /* An authenticated bulk REQUEST can acknowledge a lost final rekey ACK.
     * Service activation must not wipe/free the buffer still borrowed by
     * channel dispatch or its final plaintext wipe. This wrapper covers all
     * early returns without changing authentication or barrier ordering. */
    s->frame_dispatch_depth++;
    process_frame_impl(s, frame, frame_len, ingress, source,
                       source_required, preauth_now_ms);
    s->frame_dispatch_depth--;
    session_bulk_retire_receive_arena(s);
}

void session_process_datagram(session_t *s, const uint8_t *frame,
                              size_t frame_len)
{
    session_process_datagram_at(s, frame, frame_len, mono_ms());
}

void session_process_datagram_at(session_t *s, const uint8_t *frame,
                                 size_t frame_len, int64_t now_ms)
{
    if (!s || !frame)
        return;
    process_frame(s, frame, frame_len, NULL, NULL,
                  s->transport && s->transport->ops &&
                      s->transport->ops->recv_source != NULL,
                  now_ms);
}

void session_process_datagram_from(session_t *s, const uint8_t *frame,
                                   size_t frame_len,
                                   const multipath_token_t *ingress)
{
    session_process_datagram_from_at(s, frame, frame_len, ingress,
                                     mono_ms());
}

void session_process_datagram_from_at(session_t *s, const uint8_t *frame,
                                      size_t frame_len,
                                      const multipath_token_t *ingress,
                                      int64_t preauth_now_ms)
{
    preauth_source_t source;

    if (!s || !frame)
        return;
    if (!ingress || !multipath_token_valid(ingress) ||
        preauth_source_from_ingress(ingress, &source) != 0) {
        process_frame(s, frame, frame_len, ingress, NULL, 1,
                      preauth_now_ms);
        return;
    }
    process_frame(s, frame, frame_len, ingress, &source, 1,
                  preauth_now_ms);
}

/* -------------------------------------------------------------------------
 * session_close — send CTRL_CLOSE, enter CLOSING
 * ---------------------------------------------------------------------- */

static uint8_t wire_queued_abort_mask(const session_t *s)
{
    uint8_t mask = 0;
    for (size_t i = 0; i < SESSION_TX_SLOT_COUNT; i++) {
        const session_tx_intent_t *intent = &s->wire_intents[i];
        if (intent->valid && intent->done == SESSION_TX_DONE_ABORT &&
            (intent->type == CTRL_ERROR || intent->type == CTRL_CLOSE))
            mask |= wire_abort_epoch_bit(
                (session_tx_epoch_t)intent->epoch_source);
    }
    return mask;
}

void session_close(session_t *s)
{
    uint8_t valid_mask = 0;
    uint8_t queued_mask;
    uint8_t outstanding_mask;
    unsigned int outstanding;
    session_state_t old_state;

    if (s->state == SESSION_IDLE || s->state == SESSION_CLOSING)
        return;
    fprintf(stderr, "session: initiating close\n");
    old_state = s->state;
    s->state = SESSION_CLOSING;
    sync_monitor_stop(s);

    wire_abandon_untouched_on_close(s, mono_ms());

    if (old_state != SESSION_CONNECTING && s->have_session_key)
        valid_mask |= wire_abort_epoch_bit(SESSION_TX_EPOCH_CURRENT);
    if (s->pending_epoch_valid)
        valid_mask |= wire_abort_epoch_bit(SESSION_TX_EPOCH_PENDING);

    /* A terminal error may already have completed synchronously or may be
     * queued under the pre-session hello key. It is the terminal attempt for
     * that epoch; never follow it with a redundant close record. */
    queued_mask = wire_queued_abort_mask(s);
    valid_mask |= (uint8_t)((queued_mask |
                             s->terminal_abort_attempted_mask) &
                            wire_abort_epoch_bit(
                                SESSION_TX_EPOCH_HELLO_KEY));
    s->close_epoch_mask = valid_mask;

    /* Quiesce every ordinary record that has not begun transport I/O. Keep
     * only terminal ERROR/CLOSE records for valid epochs, and make their
     * eligibility explicit in the abort mode. An EAGAIN-only active frame
     * was abandoned above; one retained partial stream frame may still reach
     * its safe framing boundary first. */
    for (size_t i = 0; i < SESSION_TX_SLOT_COUNT; i++) {
        session_tx_intent_t *intent = &s->wire_intents[i];
        uint8_t bit = wire_abort_epoch_bit(
            (session_tx_epoch_t)intent->epoch_source);
        if (intent->valid && !intent->inflight &&
            intent->done == SESSION_TX_DONE_ABORT &&
            (intent->type == CTRL_ERROR || intent->type == CTRL_CLOSE) &&
            (valid_mask & bit) != 0) {
            intent->mode_mask = SESSION_TX_MODE_ABORT;
        } else if (intent->valid && !intent->inflight) {
            crypto_memzero(&s->wire_intents[i],
                           sizeof(s->wire_intents[i]));
        }
    }
    if (s->wire_message.valid && !s->wire_message.inflight)
        crypto_memzero(&s->wire_message, sizeof(s->wire_message));

    queued_mask = wire_queued_abort_mask(s);
    s->close_attempts_target = (int)wire_mask_count(valid_mask);
    s->close_tx_count = (int)wire_mask_count(
        (uint8_t)(s->terminal_abort_attempted_mask & valid_mask));
    outstanding_mask = (uint8_t)(valid_mask &
        (uint8_t)~s->terminal_abort_attempted_mask);
    outstanding = wire_mask_count(outstanding_mask);
    send_scheduler_begin_abort(&s->wire_scheduler, outstanding);

    if ((valid_mask & wire_abort_epoch_bit(SESSION_TX_EPOCH_CURRENT)) != 0 &&
        ((queued_mask | s->terminal_abort_attempted_mask) &
         wire_abort_epoch_bit(SESSION_TX_EPOCH_CURRENT)) == 0) {
        (void)wire_submit(s, SEND_LANE_INTERACTIVE,
                          SESSION_TX_EPOCH_CURRENT,
                          SESSION_TX_SEQ_EPOCH_CONTROL,
                          SESSION_TX_MODE_ABORT, CHAN_FF_BIT,
                          CTRL_CLOSE, NULL, 0, SESSION_TX_DONE_ABORT,
                          SESSION_TX_EPOCH_CURRENT, 0,
                          WIRE_COALESCE_CLOSE_BASE |
                              ((uint32_t)SESSION_TX_EPOCH_CURRENT << 8) |
                              CTRL_CLOSE);
    }
    if ((valid_mask & wire_abort_epoch_bit(SESSION_TX_EPOCH_PENDING)) != 0 &&
        ((queued_mask | s->terminal_abort_attempted_mask) &
         wire_abort_epoch_bit(SESSION_TX_EPOCH_PENDING)) == 0)
        (void)wire_submit(
            s, SEND_LANE_INTERACTIVE, SESSION_TX_EPOCH_PENDING,
            SESSION_TX_SEQ_EPOCH_CONTROL,
            SESSION_TX_MODE_ABORT, CHAN_FF_BIT, CTRL_CLOSE,
            NULL, 0, SESSION_TX_DONE_ABORT,
            SESSION_TX_EPOCH_PENDING, 0,
            WIRE_COALESCE_CLOSE_BASE |
                ((uint32_t)SESSION_TX_EPOCH_PENDING << 8) |
                CTRL_CLOSE);
    /* No rekey retry is possible after entering CLOSING. In particular the
     * client may still hold its fresh scalar while waiting for REPLY. */
    crypto_memzero(s->rekey_private, sizeof(s->rekey_private));
    crypto_memzero(s->pq_mlkem_private,
                   sizeof(s->pq_mlkem_private));
    /* Existing close was bounded to roughly three seconds. Send-scheduler replaces
     * its repeated burst with one terminal attempt per valid epoch while
     * retaining the same finite resource boundary. */
    s->close_next_send_ms = mono_ms() + 3000;
}

void session_local_disconnect(session_t *s)
{
    const sync_rx_t *rx = NULL;
    uint8_t slot = 1U;
    uint32_t generation = 0U;
    int incomplete = 0;

    if (!s || s->is_server || !s->is_client_pty || !s->raw_mode_active ||
        s->state == SESSION_IDLE || s->state == SESSION_CLOSING)
        return;
    s->client_exit_code = 0;
    if (session_channelised_active(s) &&
        channel_session_handle_decode(s->terminal_channel_handle, &slot,
                                      &generation) != 0) {
        incomplete = 1;
        s->run_failed = 1;
    } else {
        rx = sync_rx_state_instance(s, slot);
        if (rx != NULL && rx->active && !rx->fin_delivered) {
            incomplete = 1;
            s->run_failed = 1;
        }
    }
    fprintf(stderr, incomplete
        ? "\r\nunmoor: local escape — disconnecting; "
          "output may be incomplete\r\n"
        : "\r\nunmoor: local escape — disconnecting\r\n");
    session_close(s);
}

int session_close_tick(session_t *s, int64_t now_ms)
{
    if (!s || s->state != SESSION_CLOSING)
        return 0;
    if (s->wire_transport_broken || now_ms >= s->close_next_send_ms) {
        if (s->wire_frame_len != 0) {
            fprintf(stderr,
                    "session: close boundary expired with retained frame — "
                    "transport will be discarded\n");
            session_transport_closed(s);
            if (s->wire_scheduler.in_flight) {
                fprintf(stderr,
                        "session: FATAL: close discard left a logical send in flight\n");
                s->run_failed = 1;
                s->wire_protocol_failure = 1;
            }
        }
        fprintf(stderr, "session: force close at bounded send-scheduler boundary\n");
        channel_close_all(s);
        enter_idle(s);
        return 1;
    }
    if (s->close_tx_count >= s->close_attempts_target &&
        s->wire_frame_len == 0) {
        channel_close_all(s);
        enter_idle(s);
        return 1;
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * session_send — send plaintext payload
 * ---------------------------------------------------------------------- */

/* session_send() gates on ESTABLISHED to prevent any data send
 * from leaking out during IDLE/CONNECTING/KEY_DERIVING/CLOSING. session_close()
 * intentionally bypasses this gate by calling send_ctrl() directly, because
 * CTRL_CLOSE must remain transmittable from any post-handshake state — including
 * during teardown initiated from inside session_run(), where the state has
 * already flipped to SESSION_CLOSING by the time we send the close frame.
 * */
static void pause_for_epoch_sequence_reserve(session_t *s, int64_t now_ms)
{
    if (s->epoch == UINT32_MAX) {
        fprintf(stderr,
                "session: epoch space exhausted at sequence reserve — closing\n");
        s->run_failed = 1;
        session_close(s);
        return;
    }
    if (s->rekey_phase == REKEY_NONE) {
        int request_rc = session_request_epoch_rekey_at(s, now_ms);
        if (request_rc != 0 && s->rekey_phase == REKEY_NONE &&
            s->state == SESSION_ESTABLISHED) {
            fprintf(stderr,
                    "session: could not enter epoch rekey reserve — closing\n");
            s->run_failed = 1;
            session_close(s);
            return;
        }
    }
    fprintf(stderr,
            "session: application paused at the epoch rekey sequence reserve\n");
}

static int application_sequence_available(session_t *s)
{
    if (!s->epoch_rekey_enabled || s->tx_seq < REKEY_SEQ_RESERVE_START)
        return 1;
    pause_for_epoch_sequence_reserve(s, mono_ms());
    return 0;
}

int session_send_lane(session_t *s, send_lane_t lane,
                      uint8_t chan_byte, uint8_t type,
                      const uint8_t *plaintext, size_t plaintext_len)
{
    return session_send_lane_tracked(s, lane, chan_byte, type,
                                     plaintext, plaintext_len,
                                     SESSION_TX_DONE_NONE, 0, 0);
}

int session_send_lane_tracked(session_t *s, send_lane_t lane,
                              uint8_t chan_byte, uint8_t type,
                              const uint8_t *plaintext,
                              size_t plaintext_len,
                              session_tx_done_t done,
                              uint64_t arg0, uint64_t arg1)
{
    uint32_t coalesce_key = 0;
    uint8_t channelised[FRAME_MAX_LEN];
    const uint8_t *wire_plaintext = plaintext;
    size_t wire_plaintext_len = plaintext_len;

    if (s->state != SESSION_ESTABLISHED) {
        fprintf(stderr, "session_send: not ESTABLISHED\n");
        return -1;
    }
    if (!application_sequence_available(s))
        return -1;
    if ((chan_byte & 0x0fU) != CHAN_FF_BIT) {
        fprintf(stderr, "session_send: raw fragment flags are not allowed\n");
        return -1;
    }
    uint8_t chan_id = (uint8_t)(chan_byte >> 4);
    if ((chan_id == DELIVERY_CHANNEL_ID &&
         delivery_latest_selected(s)) ||
        (chan_id == 0 && (type == CTRL_RD_DATA ||
                          type == CTRL_RD_STATUS))) {
        fprintf(stderr,
                "session_send: delivery-class records must use bounded delivery APIs\n");
        return -1;
    }
    if (!channel_is_negotiated(s, chan_id)) {
        fprintf(stderr,
                "session_send: channel %u capability not negotiated "
                "(selected_caps=0x%08X)\n",
                chan_id, s->selected_caps);
        return -1;
    }
    if (session_channelised_active(s) && chan_id != 0U) {
        channel_session_observe_t resolved;

        if (chan_id != 1U ||
            plaintext_len > sizeof(channelised) -
                                CHANNEL_SESSION_HANDLE_BYTES) {
            fprintf(stderr,
                    "session_send: unsupported channel-session data class or oversized body\n");
            return -1;
        }
        resolved = channel_session_resolve_data(
            &s->channel_table, s->terminal_channel_handle,
            CHANNEL_KIND_TERMINAL);
        if (resolved != CHANNEL_OBSERVE_NEW) {
            fprintf(stderr,
                    "session_send: channel-session terminal handle is not ACTIVE\n");
            return -1;
        }
        wire_plaintext_len = plaintext_len + CHANNEL_SESSION_HANDLE_BYTES;
        if (wire_plaintext_len >
            (size_t)(s->current_mtu ? s->current_mtu
                                    : UNMOOR_TERMINAL_PLAINTEXT_MAX)) {
            fprintf(stderr,
                    "session_send: channel-session body exceeds physical plaintext budget\n");
            return -1;
        }
        store32le(channelised, s->terminal_channel_handle);
        if (plaintext_len != 0U)
            memcpy(channelised + CHANNEL_SESSION_HANDLE_BYTES,
                   plaintext, plaintext_len);
        wire_plaintext = channelised;
    }
    if (lane < SEND_LANE_FEEDBACK || lane >= SEND_LANE_COUNT)
        return -1;
    switch (done) {
    case SESSION_TX_DONE_SYNC_ACK:
        coalesce_key = WIRE_COALESCE_SYNC_ACK;
        break;
    case SESSION_TX_DONE_PTY_OPEN:
        coalesce_key = WIRE_COALESCE_PTY_OPEN;
        break;
    case SESSION_TX_DONE_STATUS_PERIODIC:
        coalesce_key = WIRE_COALESCE_STATUS;
        break;
    default:
        if ((chan_byte >> 4) == 1U && type == PTY_RESIZE)
            coalesce_key = WIRE_COALESCE_PTY_RESIZE;
        break;
    }
    return wire_submit(s, lane, SESSION_TX_EPOCH_CURRENT,
                       SESSION_TX_SEQ_NORMAL,
                       SESSION_TX_MODE_ESTABLISHED,
                       chan_byte, type, wire_plaintext, wire_plaintext_len,
                       done, arg0, arg1, coalesce_key);
}

int session_send_lane_tracked_instance(session_t *s, uint8_t stream_slot,
                                       send_lane_t lane,
                                       uint8_t chan_byte, uint8_t type,
                                       const uint8_t *plaintext,
                                       size_t plaintext_len,
                                       session_tx_done_t done,
                                       uint64_t arg0, uint64_t arg1)
{
    uint8_t channelised[FRAME_MAX_LEN];
    const sync_instance_binding_t *binding;
    uint64_t operation_generation;
    uint32_t coalesce_key = 0U;
    size_t wire_length;

    if (!s || stream_slot == 0U ||
        stream_slot >= CHANNEL_SESSION_SLOTS)
        return -1;
    if (!session_channelised_active(s)) {
        if (stream_slot != 1U)
            return -1;
        return session_send_lane_tracked(s, lane, chan_byte, type,
                                         plaintext, plaintext_len, done,
                                         arg0, arg1);
    }
    if (s->state != SESSION_ESTABLISHED ||
        !application_sequence_available(s) ||
        (chan_byte & 0x0fU) != CHAN_FF_BIT ||
        (chan_byte >> 4) != 1U ||
        (type != PTY_SYNC_DATA && type != PTY_SYNC_ACK) ||
        lane < SEND_LANE_FEEDBACK || lane >= SEND_LANE_COUNT ||
        (!plaintext && plaintext_len != 0U))
        return -1;
    binding = &s->sync_binding[stream_slot];
    if (!binding->configured || binding->slot != stream_slot ||
        binding->handle == 0U ||
        channel_session_resolve_data(&s->channel_table, binding->handle,
                                     binding->kind) != CHANNEL_OBSERVE_NEW)
        return -1;
    if (plaintext_len > sizeof(channelised) - CHANNEL_SESSION_HANDLE_BYTES)
        return -1;
    wire_length = plaintext_len + CHANNEL_SESSION_HANDLE_BYTES;
    if (wire_length >
        (size_t)(s->current_mtu ? s->current_mtu
                                : UNMOOR_TERMINAL_PLAINTEXT_MAX))
        return -1;
    store32le(channelised, binding->handle);
    if (plaintext_len != 0U)
        memcpy(channelised + CHANNEL_SESSION_HANDLE_BYTES,
               plaintext, plaintext_len);

    switch (done) {
    case SESSION_TX_DONE_SYNC_ACK:
        coalesce_key = WIRE_COALESCE_SYNC_ACK;
        operation_generation = arg0;
        break;
    case SESSION_TX_DONE_SYNC_NEW:
    case SESSION_TX_DONE_SYNC_REPAIR:
    case SESSION_TX_DONE_SYNC_PROBE:
        operation_generation = arg0;
        break;
    case SESSION_TX_DONE_SYNC_FIN:
        operation_generation = arg0 >> 1;
        break;
    default:
        return -1;
    }
    if (operation_generation == 0U)
        return -1;
    return wire_submit_stream(s, lane, chan_byte, type,
                              channelised, wire_length, done,
                              arg0, arg1, coalesce_key, binding->handle,
                              operation_generation);
}

int session_send(session_t *s, uint8_t chan_byte, uint8_t type,
                 const uint8_t *plaintext, size_t plaintext_len)
{
    send_lane_t lane = SEND_LANE_NEW;
    uint8_t chan_id = (uint8_t)(chan_byte >> 4);

    if (chan_id == 0 ||
        (chan_id == 1 && type != PTY_DATA && type != PTY_SYNC_DATA &&
         type != PTY_EOF))
        lane = SEND_LANE_INTERACTIVE;
    if ((chan_id == 0 &&
         (type == CTRL_KEEPALIVE || type == CTRL_KEEPALIVE_ACK ||
          type == CTRL_STATUS_HEARTBEAT)) ||
        (chan_id == 1 && type == PTY_SYNC_ACK))
        lane = SEND_LANE_FEEDBACK;
    return session_send_lane(s, lane, chan_byte, type,
                             plaintext, plaintext_len);
}

int session_send_data(session_t *s, uint8_t chan_id, uint8_t type,
                      const uint8_t *plaintext, size_t plaintext_len)
{
    uint32_t channel_handle = 0U;
    size_t envelope = 0U;
    size_t logical_length;
    if (s->state != SESSION_ESTABLISHED) {
        fprintf(stderr, "session_send_data: not ESTABLISHED\n");
        return -1;
    }
    if (!application_sequence_available(s))
        return -1;
    if (chan_id == 0 || chan_id >= 16 ||
        (!plaintext && plaintext_len != 0) ||
        plaintext_len > REASM_MAX_BUFFER)
        return -1;
    if (!channel_is_negotiated(s, chan_id)) {
        fprintf(stderr,
                "session_send_data: channel %u capability not negotiated "
                "(selected_caps=0x%08X)\n",
                chan_id, s->selected_caps);
        return -1;
    }
    if (chan_id == DELIVERY_CHANNEL_ID && delivery_latest_selected(s)) {
        fprintf(stderr,
                "session_send_data: delivery-class channel must use bounded delivery APIs\n");
        return -1;
    }
    if (chan_id == 1 && (type == PTY_SYNC_DATA || type == PTY_SYNC_ACK)) {
        /* terminal state sync records have their own bounded single-frame encoder in
         * sync.c. Letting the generic API fragment one would erase the
         * receive-side evidence that the invariant was violated. */
        fprintf(stderr,
                "session_send_data: sync records must use the single-frame API\n");
        return -1;
    }
    if (session_channelised_active(s)) {
        if (chan_id != 1U ||
            channel_session_resolve_data(
                &s->channel_table, s->terminal_channel_handle,
                CHANNEL_KIND_TERMINAL) != CHANNEL_OBSERVE_NEW) {
            fprintf(stderr,
                    "session_send_data: channel-session route is not an ACTIVE terminal\n");
            return -1;
        }
        channel_handle = s->terminal_channel_handle;
        envelope = CHANNEL_SESSION_HANDLE_BYTES;
    }
    if (plaintext_len > REASM_MAX_BUFFER - envelope)
        return -1;
    logical_length = plaintext_len + envelope;

    size_t mtu = s->current_mtu ? s->current_mtu
                                : UNMOOR_TERMINAL_PLAINTEXT_MAX;
    size_t max_mtu = FRAME_MAX_LEN - FRAME_HEADER_LEN - FRAME_TAG_LEN;
    if (mtu > max_mtu) {
        fprintf(stderr, "session_send_data: invalid mtu=%zu\n", mtu);
        return -1;
    }

    /* Fast path: single fragment fits in one frame. */
    if (logical_length <= mtu) {
        uint8_t chan_byte = (uint8_t)((chan_id << 4) | CHAN_FF_BIT);
        uint8_t body[FRAME_MAX_LEN];

        if (envelope != 0U) {
            store32le(body, channel_handle);
            if (plaintext_len != 0U)
                memcpy(body + envelope, plaintext, plaintext_len);
            plaintext = body;
        }
        return send_frame(s, s->session_key, chan_byte, type,
                          plaintext, logical_length, SEND_LANE_NEW);
    }

    if ((s->selected_caps & UNMOOR_CAP_FRAGMENT_D21_V1) == 0) {
        fprintf(stderr,
                "session_send_data: fragment capability not negotiated "
                "(selected_caps=0x%08X)\n",
                s->selected_caps);
        return -1;
    }

    /* Multi-fragment bodies spend 16 clear authenticated bytes on identity
     * and geometry plus 32 encrypted bytes on a repeated whole-message hash.
     * The remaining stride preserves the same outer datagram ceiling. */
    if (mtu <= FRAGMENT_OVERHEAD) {
        fprintf(stderr, "session_send_data: mtu=%zu cannot carry fragments\n", mtu);
        return -1;
    }
    size_t stride = mtu - FRAGMENT_OVERHEAD;
    size_t nfrags = (logical_length + stride - 1) / stride;
    if (nfrags < 2 || nfrags > REASM_MAX_FRAGMENTS) {
        fprintf(stderr, "session_send_data: invalid fragment count=%zu\n", nfrags);
        return -1;
    }

    /* Do not begin a logical message that would cross the close-before-wrap
     * threshold. A failure here emits no data fragment. */
    const uint32_t seq_limit = s->epoch_rekey_enabled
        ? REKEY_SEQ_RESERVE_START : UINT32_MAX - 1000U;
    if ((uint64_t)s->tx_seq + nfrags > seq_limit) {
        fprintf(stderr,
                "session_send_data: insufficient sequence space for %zu fragments\n",
                nfrags);
        if (s->epoch_rekey_enabled)
            pause_for_epoch_sequence_reserve(s, mono_ms());
        else
            session_close(s);
        return -1;
    }

    if (s->wire_message.valid ||
        wire_lane_count(s, SEND_LANE_NEW) != 0) {
        fprintf(stderr,
                "session_send_data: send-scheduler fragmented-message slot busy\n");
        return -1;
    }
    session_tx_message_t *message = &s->wire_message;
    memset(message, 0, sizeof(*message));
    message->valid = 1;
    message->chan_id = chan_id;
    message->type = type;
    message->count = (uint16_t)nfrags;
    message->stride = (uint16_t)stride;
    message->total_length = (uint16_t)logical_length;
    message->ticket = ++s->wire_next_ticket;
    message->order = ++s->wire_next_order;
    if (envelope != 0U)
        store32le(message->bytes, channel_handle);
    if (plaintext_len != 0U)
        memcpy(message->bytes + envelope, plaintext, plaintext_len);
    fprintf(stderr,
            "session: admitted %zu-byte authenticated message as %zu fragments at stride=%zu chan=%u type=%u\n",
            logical_length, nfrags, stride, (unsigned)chan_id,
            (unsigned)type);

    /* Deterministic white-box callers do not own an event loop. Their fake
     * transport completes synchronously, so drive one scheduler turn per
     * fragment. Product calls return after bounded logical admission. */
    if (!s->wire_in_run_loop) {
        uint64_t ticket = message->ticket;
        for (size_t i = 0; i < nfrags && message->valid; i++) {
            session_send_scheduler_turn(s, mono_ms());
            if (s->wire_failed_ticket == ticket)
                return -1;
        }
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * session_run — main event loop
 * ---------------------------------------------------------------------- */

/* Add one logical poll owner.  Transport receive descriptors must be unique,
 * and local source/sink descriptors must never alias a transport or each
 * other.  Send readiness is merged into its already-present receive owner by
 * the caller; every other duplicate is a fail-loud ownership error. */
static int poll_append_unique(struct pollfd *pfds, int capacity, int *count,
                              int fd, short events, int *index_out)
{
    int i;

    if (!pfds || !count || !index_out || fd < 0 || *count < 0 ||
        *count >= capacity)
        return -1;
    for (i = 0; i < *count; i++)
        if (pfds[i].fd == fd)
            return -1;
    pfds[*count].fd = fd;
    pfds[*count].events = events;
    pfds[*count].revents = 0;
    *index_out = *count;
    (*count)++;
    return 0;
}

static void session_poll_owner_failure(session_t *s, const char *owner)
{
    if (s == NULL)
        return;
    fprintf(stderr,
            "session: FATAL: duplicate or invalid %s poll descriptor\n",
            owner ? owner : "unknown");
    s->run_failed = 1;
    session_transport_closed(s);
    channel_close_all(s);
    enter_idle(s);
}

static void session_monitor_backend_failure(session_t *s,
                                            const char *operation)
{
    int cause;

    if (s == NULL)
        return;
    cause = errno ? errno : EIO;
    fprintf(stderr,
            "session: FATAL: monitor backend %s failed: %s\n",
            operation ? operation : "operation", strerror(cause));
    s->run_failed = 1;
    session_transport_closed(s);
    channel_close_all(s);
    enter_idle(s);
    errno = cause;
}

int session_run(session_t *s)
{
    uint8_t buf[FRAME_MAX_LEN + 1];
    int result;

    if (!s)
        return -1;
    if (!s->physical_clock_now) {
        s->physical_clock_now = physical_mono_ms;
        s->physical_clock_context = NULL;
    }
    s->wire_in_run_loop = 1;

    /* Track whether we have ever left IDLE; this ensures the server's initial
     * IDLE state doesn't cause an immediate exit before the first CTRL_HELLO. */
    int ever_active = !s->is_server; /* client starts CONNECTING (non-IDLE) */

    for (;;) {
        /* Exit condition: reached IDLE after being active */
        if (s->state == SESSION_IDLE && ever_active) break;
        if (s->state != SESSION_IDLE) ever_active = 1;

        int64_t now = mono_ms();
        unsigned int channel_source_budget = 1U;
        send_scheduler_begin_turn(&s->wire_scheduler);
        /* 100ms default poll timeout. The SIGINT/SIGWINCH pump on
         * the client may see up to 100ms of tail latency under an idle
         * link, because handle_sigint only sets a sig_atomic_t flag and
         * the loop only checks it after poll() returns. EINTR from the
         * signal handler typically breaks poll sooner on Linux glibc and
         * macOS libSystem, but POSIX does not require it. Acceptable for
         * an interactive terminal; reduce if sub-100ms signal latency
         * becomes a requirement. */
        int poll_ms = 100; /* default poll timeout */

#if defined(UNMOOR_CHAOS) && UNMOOR_CHAOS
        /* Release delayed tx frames / rescue a stranded reorder hold. */
        chaos_pump(s, now, &poll_ms);
#endif

        /* ---- Pacer refill (UNMOOR_PACE_BPS; producer-overrun cap) ---- */
        session_pacer_refill(s, now);

        /* ---- Timer: bootstrap accept deadline (one-shot listener) ---- */
        if (s->bootstrap_deadline_ms) {
            if (s->services_started) {
                s->bootstrap_deadline_ms = 0;  /* full barrier done — disarm */
            } else if (now >= s->bootstrap_deadline_ms) {
                fprintf(stderr, "session: bootstrap: no client within the "
                                "accept window — exiting\n");
                s->run_failed = 1;
                break;
            } else {
                int64_t bwait = s->bootstrap_deadline_ms - now;
                if (bwait < poll_ms) poll_ms = (int)bwait;
            }
        }

        /* ---- epoch barrier/rekey retransmission ---- */
        session_epoch_rekey_tick(s, now);
        if ((s->state == SESSION_REKEYING || s->rekey_request_pending) &&
            s->rekey_next_send_ms > now) {
            int64_t rwait = s->rekey_next_send_ms - now;
            if (rwait < poll_ms) poll_ms = (int)rwait;
        }

        /* ---- Timer: CTRL_HELLO retransmit (client, CONNECTING) ----
         * Schedule: send 5 total (1 initial + 4 retries), backoffs 1s/2s/4s/8s.
         * After 5th send, backoff is 16s — peer has 16s to reply.
         * When that 16s expires (t≈31s), give up. Total ≈31s (bulk-transfer). */
        if (s->state == SESSION_CONNECTING) {
            if (now >= s->hello_next_send_ms) {
                if (s->hello_tx_count < 5) {
                    (void)send_hello(s);
                } else {
                    fprintf(stderr, "session: handshake timeout after 5 attempts (31s)\n");
                    s->run_failed = 1;
                    enter_idle(s);
                    break;
                }
            }
            int64_t wait = s->hello_next_send_ms - now;
            if (wait > 0 && wait < poll_ms) poll_ms = (int)wait;
        }

        /* ---- Timer: KEY_DERIVING timeout (10s) ---- */
        if (s->state == SESSION_KEY_DERIVING) {
            session_ready_tick(s, now);
            if (now >= s->key_deriving_deadline_ms) {
                fprintf(stderr, "session: KEY_DERIVING timeout\n");
                s->run_failed = 1;
                enter_idle(s);
                break;
            }
            int64_t wait = s->key_deriving_deadline_ms - now;
            if (wait > 0 && wait < poll_ms) poll_ms = (int)wait;
            if (s->ready_next_send_ms > 0) {
                int64_t rwait = s->ready_next_send_ms - now;
                if (rwait > 0 && rwait < poll_ms) poll_ms = (int)rwait;
            }
        }

        /* ---- Timer: authenticated keepalive / PTY open (ESTABLISHED) ---- */
        if (s->state == SESSION_ESTABLISHED) {
            if (!session_status_active(s)) {
                if (now >= s->next_keepalive_ms) {
                    send_ctrl(s, CTRL_KEEPALIVE, NULL, 0, s->session_key);
                    s->next_keepalive_ms = now + s->keepalive_period_ms;
                }
                int64_t wait = s->next_keepalive_ms - now;
                if (wait > 0 && wait < poll_ms) poll_ms = (int)wait;
            }

            /* ---- Timer: PTY_OPEN retransmit (client) ----
             * Under injected loss, bulk-transfer gave only HELLO/CLOSE
             * retransmits, so one lost PTY_OPEN or PTY_OPEN_ACK left the
             * session ESTABLISHED but shell-less forever. Re-send on the
             * CTRL_HELLO schedule (5 total, 1s/2s/4s/8s backoff, final
             * 16s wait ≈31s) then close. The server re-ACKs duplicate
             * PTY_OPENs idempotently, so a lost ACK heals the same way. */
            if (!s->is_server && s->is_client_pty &&
                !s->pty_open_ack_seen && !s->pty_open_err_seen &&
                s->pty_open_tx_count > 0) {
                if (now >= s->pty_open_next_send_ms) {
                    if (s->pty_open_tx_count < 5) {
                        fprintf(stderr, "session: PTY_OPEN retransmit %d/5\n",
                                s->pty_open_tx_count + 1);
                        channel_pty_client_send_open(s, s->pty_open_rows,
                                                     s->pty_open_cols);
                    } else {
                        fprintf(stderr, "session: no PTY_OPEN_ACK after 5 "
                                        "attempts (31s) — closing\n");
                        session_close(s);
                    }
                }
                if (s->state == SESSION_ESTABLISHED) {
                    int64_t pwait = s->pty_open_next_send_ms - now;
                    if (pwait > 0 && pwait < poll_ms) poll_ms = (int)pwait;
                }
            }

            /* sync-status owns observation when selected and deliberately never
             * closes. Keep the pre-sync-status watchdog byte-for-byte for peers
             * that did not select the new exact capability. */
            if (!s->bulk_enabled && !session_status_active(s)) {
                int64_t since_last = now - s->last_authenticated_ms;
                if (since_last > s->liveness_timeout_ms) {
                    if (s->liveness_unbound) {
                        /* UDP roaming: mosh-style hold — report staleness,
                         * keep the session; the next authenticated frame
                         * resumes it (keepalives are still being sent). */
                        if (!s->liveness_hold_announced &&
                            now >= s->next_liveness_warn_ms) {
                            char line[192];

                            session_event_emit(
                                s, EVENT_LOG_EVENT_STALLED,
                                EVENT_LOG_SCOPE_SESSION,
                                EVENT_LOG_REASON_NO_CONTACT,
                                EVENT_LOG_NO_LEG, 0U, now);
                            s->liveness_hold_announced = 1U;
                            s->next_liveness_warn_ms = INT64_MAX;
                            if (!session_async_terminal_text_suppressed(s) &&
                                sync_status_format_liveness_hold(
                                    since_last, isatty(STDERR_FILENO),
                                    line, sizeof(line)) == 0)
                                fputs(line, stderr);
                        }
                    } else {
                        session_event_latch_close_reason(
                            s, EVENT_LOG_REASON_NO_CONTACT);
                        session_event_emit(
                            s, EVENT_LOG_EVENT_STALLED,
                            EVENT_LOG_SCOPE_SESSION,
                            EVENT_LOG_REASON_NO_CONTACT,
                            EVENT_LOG_NO_LEG, 0U, now);
                        fprintf(stderr,
                                "session: liveness timeout (%lldms) — closing\n",
                                (long long)since_last);
                        session_close(s);
                        continue;
                    }
                } else {
                    int64_t watchdog_remaining =
                        s->liveness_timeout_ms - since_last;
                    if (watchdog_remaining < poll_ms)
                        poll_ms = (int)watchdog_remaining;
                }
            }
        }

        /* ---- send-scheduler bounded terminal abort (CLOSING) ---- */
        if (s->state == SESSION_CLOSING) {
            if (session_close_tick(s, now))
                continue;
            {
                int64_t wait = s->close_next_send_ms - now;
                if (wait > 0 && wait < poll_ms)
                    poll_ms = (int)wait;
            }
        }

        /* ---- reassembly timeouts ---- */
        if (s->state == SESSION_ESTABLISHED) {
            reasm_tick(&s->reasm, now);
        }

        /* ---- channel-session local attach/process ownership ----
         * Service retained local events and child lifecycle before sync
         * chooses one per-instance logical producer for this turn. */
        if (session_channelised_active(s) &&
            (s->state == SESSION_ESTABLISHED ||
             s->state == SESSION_REKEYING))
            session_channel_application_tick(
                s, now, &poll_ms, &channel_source_budget);

        /* ---- terminal state sync timers: ack cadence + 100ms hole
         * repeats, RTO probes (incl. the persist probe), FIN
         * retransmit, server linger. ESTABLISHED only — session_send is
         * gated on ESTABLISHED, so ticking during CLOSING could only spam
         * failed sends; the sink drain stays alive via the POLLOUT path
         * below and the final drain in enter_idle. */
        if (s->state == SESSION_ESTABLISHED &&
            (sync_active(s) || session_channelised_active(s))) {
            sync_tick(s, now);
            if (s->state == SESSION_ESTABLISHED) {
                int64_t swait = sync_next_deadline(s, now);
                if (swait >= 0 && swait < poll_ms) poll_ms = (int)swait;
            }
        }

        /* ---- sync-status absolute status heartbeat and UI ---- */
        if (s->state == SESSION_ESTABLISHED && session_status_active(s)) {
            session_status_tick(s, now);
            if (s->state == SESSION_ESTABLISHED) {
                int64_t hwait = session_status_next_deadline(s, now);
                if (hwait >= 0 && hwait < poll_ms)
                    poll_ms = (int)hwait;
            }
        }

        /* ---- channel-session bounded channel-zero state ----
         * OPEN/CLOSE state remains live through epoch rekey and contributes
         * only one fixed CONTROL-lane owner before the sole wire turn. */
        if (session_channelised_active(s) &&
            (s->state == SESSION_ESTABLISHED ||
             s->state == SESSION_REKEYING)) {
            session_channel_tick(s, now);
            if (s->state == SESSION_CLOSING)
                continue;
            {
                int64_t cwait = session_channel_next_deadline(s, now);
                if (cwait >= 0 && cwait < poll_ms)
                    poll_ms = (int)cwait;
            }
        }

        /* ---- delivery-class bounded delivery: application completion plus repeated
         * absolute HEAD/STATUS/retry deadlines.  This must run before the
         * sole send-scheduler wire turn so newly exposed work participates in the same
         * turn without a side-channel send. */
        if (s->delivery_initialized &&
            (s->state == SESSION_ESTABLISHED ||
             delivery_barrier_feedback_active(s))) {
            if (s->state == SESSION_ESTABLISHED)
                session_delivery_tick(s, now);
            if (s->state == SESSION_ESTABLISHED ||
                delivery_barrier_feedback_active(s)) {
                int64_t dwait = session_delivery_next_deadline(s, now);
                if (dwait >= 0 && dwait < poll_ms)
                    poll_ms = (int)dwait;
            }
        }

        /* ---- multipath exact-path validation.  It only exposes bounded
         * feedback intents; the sole send-scheduler turn below remains the only send
         * authority and therefore attempts at most one physical copy. */
        if (s->multipath_active && s->state == SESSION_ESTABLISHED) {
            session_multipath_tick(s, now);
            if (s->state == SESSION_ESTABLISHED) {
                int64_t mwait = session_multipath_next_deadline(s, now);
                if (mwait >= 0 && mwait < poll_ms)
                    poll_ms = (int)mwait;
            }
        }

        /* ---- bulk-transfer portable bulk engine.  One bounded scan/timer step runs
         * before the sole send-scheduler turn, exactly like the other logical
         * producers.  Terminal success/failure is authenticated application
         * state; CTRL_CLOSE only performs the existing bounded transport
         * teardown after that result exists. */
        if (s->bulk_activated &&
            (s->state == SESSION_ESTABLISHED ||
             s->state == SESSION_REKEYING)) {
            bulk_result_code_t bulk_code = BULK_CODE_NONE;
            bulk_engine_result_t bulk_result;
            int bulk_tick = bulk_engine_tick(s->bulk, now);

            if (bulk_tick < 0) {
                fprintf(stderr,
                        "session: bulk-transfer local engine failure (%d)\n",
                        bulk_tick);
                session_event_latch_close_reason(
                    s, EVENT_LOG_REASON_PROTOCOL_ERROR);
                s->run_failed = 1;
                session_close(s);
            } else {
                session_bulk_log_path_edges(s, now);
            }
            if (bulk_tick >= 0 && s->state == SESSION_ESTABLISHED &&
                       session_bulk_reroll_tick(s, now) != 0) {
                fprintf(stderr,
                        "session: bulk-transfer source-port reroll controller failed\n");
                session_event_latch_close_reason(
                    s, EVENT_LOG_REASON_PROTOCOL_ERROR);
                s->run_failed = 1;
                session_close(s);
            } else if (bulk_tick >= 0) {
                int64_t bwait = bulk_engine_next_deadline(s->bulk, now);
                if (bwait >= 0 && bwait < poll_ms)
                    poll_ms = (int)bwait;
            }
            bulk_result = bulk_engine_result(s->bulk, &bulk_code);
            if (bulk_result != BULK_ENGINE_RESULT_RUNNING &&
                (s->state == SESSION_ESTABLISHED ||
                 s->state == SESSION_REKEYING)) {
                if (bulk_result == BULK_ENGINE_RESULT_FAILED) {
                    event_log_reason_t reason =
                        session_event_bulk_failure_reason(bulk_code);

                    session_event_latch_close_reason(s, reason);
                    session_event_emit(
                        s, reason == EVENT_LOG_REASON_NO_PROGRESS
                               ? EVENT_LOG_EVENT_STALLED
                               : EVENT_LOG_EVENT_REFUSE,
                        EVENT_LOG_SCOPE_SESSION,
                        reason,
                        EVENT_LOG_NO_LEG, 0U, now);
                    fprintf(stderr,
                            "session: bulk transfer failed (code=%u)\n",
                            (unsigned int)bulk_code);
                    s->run_failed = 1;
                }
                session_close(s);
            }
        }

        /* bulk-only authenticated-contact fallback.  The application
         * engine above owns the tighter no-progress transition at `stall`;
         * this catches a broken lifecycle no later than stall+error linger.
         * It is not sync-status wire state and liveness_unbound cannot turn a finite
         * bulk operation into the terminal hold-forever policy. */
        if (s->bulk_enabled && s->bulk_activated &&
            (s->state == SESSION_ESTABLISHED ||
             s->state == SESSION_REKEYING)) {
            int64_t stall = s->bulk_config.stall_ms == 0 ?
                BULK_ENGINE_STALL_DEFAULT_MS : s->bulk_config.stall_ms;
            int64_t timeout = stall + BULK_ENGINE_LINGER_MS;
            int64_t since_last = now - s->last_authenticated_ms;

            if (since_last >= timeout) {
                session_event_latch_close_reason(
                    s, EVENT_LOG_REASON_NO_CONTACT);
                session_event_emit(
                    s, EVENT_LOG_EVENT_STALLED,
                    EVENT_LOG_SCOPE_SESSION,
                    EVENT_LOG_REASON_NO_CONTACT,
                    EVENT_LOG_NO_LEG, 0U, now);
                fprintf(stderr,
                        "session: bulk contact timeout (%lldms) — closing failed\n",
                        (long long)since_last);
                s->run_failed = 1;
                session_close(s);
                continue;
            }
            if (timeout - since_last < poll_ms)
                poll_ms = (int)(timeout - since_last);
        }

        /* ---- send-scheduler sole wire authority: exactly one transport step in this
         * event-loop turn, after every producer exposed its bounded state. */
        (void)wire_drive_turn(s, now);
        if (s->wire_transport_broken) {
            if (s->state != SESSION_IDLE && s->state != SESSION_CLOSING)
                session_close(s);
            if (s->state == SESSION_CLOSING)
                (void)session_close_tick(s, now);
            if (s->state == SESSION_IDLE)
                continue;
        }
        if (s->wire_protocol_failure &&
            s->state != SESSION_IDLE && s->state != SESSION_CLOSING) {
            s->wire_protocol_failure = 0;
            session_close(s);
        }
        if (s->state == SESSION_CLOSING && session_close_tick(s, now))
            continue;

        /* ---- Sync deadline, re-read after the wire turn ----
         * The deadline computed above ran before wire_drive_turn(), so every
         * producer that self-gates on its own in-flight frame reported "not
         * due" for a frame this same turn was about to make terminal. Sync
         * repair is the one producer with a multi-frame per-ack grant, so it
         * is the one that loses work: it would sleep until the next ack with
         * grant still in hand. Ask again now that the turn is terminal. The
         * answer is still the producer's own — nothing here weakens the
         * admission test, it is only asked at a moment when it can be true. */
        if (s->state == SESSION_ESTABLISHED &&
            (sync_active(s) || session_channelised_active(s))) {
            int64_t swait = sync_next_deadline(s, now);
            if (swait >= 0 && swait < poll_ms) poll_ms = (int)swait;
        }

        {
            int64_t wwait = send_scheduler_next_deadline(
                &s->wire_scheduler, wire_eligible_mask(s, now),
                wire_mode(s), now);
            int64_t retry_wait = wire_bulk_retry_wait(s, now);
            if (wwait >= 0 && wwait < poll_ms)
                poll_ms = (int)wwait;
            if (retry_wait >= 0 && retry_wait < poll_ms)
                poll_ms = (int)retry_wait;
            if (s->wire_frame_len != 0 &&
                retry_wait < 0 &&
                (!s->transport->ops->get_send_fd ||
                 s->transport->ops->get_send_fd(s->transport) < 0) &&
                poll_ms > 1)
                poll_ms = 1;
        }

        /* ---- Poll transport, PTY master (server), stdin (client) ---- */
        int tfd = s->transport->ops->get_fd ? s->transport->ops->get_fd(s->transport) : -1;
        int use_poll = (tfd >= 0);

        if (use_poll) {
            struct pollfd pfds[SESSION_POLL_CAPACITY];
            int nfds = 0;
            int recv_fds[MULTIPATH_PATHS_MAX];
            int idx_transport[MULTIPATH_PATHS_MAX];
            int recv_count = 1;
            int send_fds[MULTIPATH_PATHS_MAX];
            int send_count = 0;
            int send_fd = -1;
            int poll_set_invalid = 0;
            attach_manager_poll_entry_t
                attach_entries[ATTACH_MANAGER_POLL_CAPACITY];
            int idx_attach[ATTACH_MANAGER_POLL_CAPACITY];
            size_t attach_count = 0U;
            int idx_process_source[CHANNEL_SESSION_SLOTS];
            int idx_process_sink[CHANNEL_SESSION_SLOTS];
            int idx_monitor_worker = -1;
            int monitor_worker_immediate = 0;
            uint8_t selected_source_slot = 0U;
            uint8_t anchor_source_slot = (uint8_t)(
                s->terminal_channel_handle & UINT32_C(0x0f));
            int64_t retry_wait = wire_bulk_retry_wait(s, now);
            int wire_poll_writable = s->wire_frame_len != 0 &&
                                     retry_wait <= 0;
            int poll_hup_err_is_readable =
                s->transport->ops->poll_hup_err_is_readable != 0U;
            const int poll_capacity =
                (int)(sizeof(pfds) / sizeof(pfds[0]));

            for (unsigned int fi = 0U; fi < MULTIPATH_PATHS_MAX; fi++) {
                recv_fds[fi] = -1;
                idx_transport[fi] = -1;
                send_fds[fi] = -1;
            }
            for (unsigned int si = 0U; si < CHANNEL_SESSION_SLOTS; si++) {
                idx_process_source[si] = -1;
                idx_process_sink[si] = -1;
            }
            for (unsigned int ai = 0U;
                 ai < ATTACH_MANAGER_POLL_CAPACITY; ai++)
                idx_attach[ai] = -1;

            recv_fds[0] = tfd;
            /* Receive-fd ownership is a transport property, not multipath
             * authority. An implicit UDP listener owns native v4 and v6
             * sockets even for the ordinary single-path profile. Whether
             * ingress carries a canonical path token remains separately
             * gated below by multipath_requested. */
            if (s->transport->ops->get_recv_fds) {
                recv_count = s->transport->ops->get_recv_fds(
                    s->transport, recv_fds);
                if (recv_count < 1 ||
                    recv_count > (int)MULTIPATH_PATHS_MAX) {
                    fprintf(stderr,
                            "session: FATAL: invalid transport receive-fd set\n");
                    session_transport_closed(s);
                    channel_close_all(s);
                    enter_idle(s);
                    break;
                }
            }
            if (wire_poll_writable &&
                s->wire_path_plan_active &&
                s->transport->ops->get_path_send_fd) {
                for (unsigned int pi = 0;
                     pi < s->wire_path_plan.count; pi++) {
                    int fd;
                    int duplicate = 0;
                    if ((s->wire_path_terminal_mask &
                         (UINT32_C(1) << pi)) != 0U)
                        continue;
                    fd = s->transport->ops->get_path_send_fd(
                        s->transport,
                        &s->wire_path_plan.item[pi].token);
                    if (fd < 0)
                        continue;
                    for (int si = 0; si < send_count; si++)
                        if (send_fds[si] == fd)
                            duplicate = 1;
                    if (!duplicate && send_count <
                        (int)MULTIPATH_PATHS_MAX)
                        send_fds[send_count++] = fd;
                }
                if (s->wire_path_ordinal < s->wire_path_plan.count)
                    send_fd = s->transport->ops->get_path_send_fd(
                        s->transport,
                        &s->wire_path_plan.item[
                            s->wire_path_ordinal].token);
            } else if (s->transport->ops->get_send_fd) {
                send_fd = s->transport->ops->get_send_fd(s->transport);
                if (send_fd >= 0)
                    send_fds[send_count++] = send_fd;
            }
            for (int ri = 0; ri < recv_count; ri++) {
                int wants_write = 0;
                for (int si = 0; si < send_count; si++)
                    if (recv_fds[ri] == send_fds[si])
                        wants_write = 1;
                if (poll_append_unique(
                        pfds, poll_capacity, &nfds, recv_fds[ri],
                        (short)(POLLIN |
                            ((wire_poll_writable && wants_write)
                                ? POLLOUT : 0)),
                        &idx_transport[ri]) != 0) {
                    poll_set_invalid = 1;
                    break;
                }
            }
            if (poll_set_invalid) {
                session_poll_owner_failure(s, "transport receive");
                break;
            }
            int idx_send = -1;
            if (wire_poll_writable && send_count == 1 &&
                send_fd >= 0) {
                int send_is_recv = 0;
                for (int ri = 0; ri < recv_count; ri++)
                    if (send_fd == recv_fds[ri])
                        send_is_recv = 1;
                if (!send_is_recv) {
                    if (poll_append_unique(
                            pfds, poll_capacity, &nfds, send_fd, POLLOUT,
                            &idx_send) != 0) {
                        session_poll_owner_failure(s, "transport send");
                        break;
                    }
                }
            }

            /* Pacer gate: when the bucket is empty, stop POLLINing the
             * bulk sources — backpressure lands in the kernel PTY/tty
             * buffer and the writer (e.g. cat) blocks there. Transport
             * stays polled, so inbound control (Ctrl+C from the peer)
             * is never delayed. Clamp poll_ms to the refill instant. */
            int pace_blocked = session_pacer_source_blocked(s);
            if (pace_blocked) {
                int64_t need = 1 - s->pace_credit_milli;
                int64_t pwait = need / s->pace_bps
                              + ((need % s->pace_bps) != 0);
                if (pwait < 1) pwait = 1;
                if (pwait < poll_ms) poll_ms = (int)pwait;
            }

            /* terminal state sync read gate: when the sync backlog quota is exhausted,
             * stop POLLINing the bulk source exactly like the pacer gate —
             * backpressure lands in the kernel PTY/tty buffer and the
             * writer blocks there. Peer credit never gates local reads
             *; only the local quota does. */
            int sync_on = sync_active(s);
            int sync_read_blocked = sync_on && sync_tx_room(s) == 0;
            int exact_new_busy = !sync_on &&
                (s->wire_message.valid ||
                 wire_lane_count(s, SEND_LANE_NEW) != 0);
            int channel_source_allowed =
                !session_channelised_active(s) ||
                channel_source_budget != 0U;

            int idx_pty = -1;
            if (s->pty_master_fd >= 0) {
                short pev = 0;
                if (s->state == SESSION_ESTABLISHED &&
                    !pace_blocked && !sync_read_blocked && !exact_new_busy &&
                    channel_source_allowed)
                    pev |= POLLIN;
                /* Also poll for POLLOUT when we have a backlog.
                 * Under sync, the pending contiguous bytes play that role,
                 * and the drain stays armed during CLOSING so received
                 * input still reaches the shell. */
                if (sync_on ? (sync_rx_pending(s) != 0)
                            : (s->pty_master_backlog_len > 0))
                    pev |= POLLOUT;
                if (pev) {
                    if (poll_append_unique(
                            pfds, poll_capacity, &nfds, s->pty_master_fd,
                            pev, &idx_pty) != 0) {
                        session_poll_owner_failure(s, "PTY");
                        break;
                    }
                }
            }

            int idx_stdin = -1;
            if (s->state == SESSION_ESTABLISHED && s->is_client_pty &&
                s->pty_open_ack_seen && !s->is_server && !s->stdin_closed &&
                !pace_blocked && !sync_read_blocked && !exact_new_busy &&
                channel_source_allowed) {
                if (poll_append_unique(
                        pfds, poll_capacity, &nfds, STDIN_FILENO, POLLIN,
                        &idx_stdin) != 0) {
                    session_poll_owner_failure(s, "stdin");
                    break;
                }
            }

            /* terminal state sync client sink: flush pending display bytes to stdout
             * (nonblocking under sync). Keyed on sync_active, not state, so
             * the drain keeps running during CLOSING. */
            int idx_stdout = -1;
            if (!s->is_server && sync_on && sync_rx_pending(s)) {
                if (poll_append_unique(
                        pfds, poll_capacity, &nfds, STDOUT_FILENO, POLLOUT,
                        &idx_stdout) != 0) {
                    session_poll_owner_failure(s, "stdout");
                    break;
                }
            }

            /* channel-session local authority descriptors retain incarnation tokens
             * alongside readiness. A pending application DATA record
             * suppresses another local read until those exact bytes enter
             * the bounded stream backlog. */
            if (s->attach_socket_open) {
                int attach_status = attach_manager_poll_snapshot(
                    &s->attach_manager, attach_entries,
                    ATTACH_MANAGER_POLL_CAPACITY, &attach_count);

                if (attach_status != ATTACH_LOCAL_OK) {
                    session_poll_owner_failure(s, "attach manager");
                    break;
                }
                for (size_t ai = 0U; ai < attach_count; ai++) {
                    short events = attach_entries[ai].events;
                    session_channel_application_t *owner_app =
                        channel_application_by_owner(
                            s, attach_entries[ai].owner, NULL);
                    attach_manager_connection_info_t info;
                    int active_source = owner_app != NULL &&
                        attach_manager_connection_info(
                            &s->attach_manager, attach_entries[ai].owner,
                            &info) == ATTACH_LOCAL_OK &&
                        info.state == ATTACH_MANAGER_STATE_ACTIVE;

                    if (active_source &&
                        (owner_app->pending_input || pace_blocked ||
                         channel_source_budget == 0U ||
                         owner_app->cleanup_pending))
                        events &= (short)~POLLIN;
                    if (events == 0)
                        continue;
                    if (poll_append_unique(
                            pfds, poll_capacity, &nfds,
                            attach_entries[ai].fd, events,
                            &idx_attach[ai]) != 0) {
                        session_poll_owner_failure(s, "attach");
                        poll_set_invalid = 1;
                        break;
                    }
                }
                if (poll_set_invalid)
                    break;
            }

            /* Dynamic listener-side processes contribute at most one source
             * and one sink. A PTY intentionally aliases them, so merge that
             * exact owner; cross-owner aliases remain fail-loud. */
            if (s->is_server && session_channelised_active(s)) {
                for (uint8_t slot = 1U;
                     slot < CHANNEL_SESSION_SLOTS; slot++) {
                    session_channel_application_t *app =
                        &s->channel_application[slot];
                    int source_fd;
                    int sink_fd;

                    if (!app->active ||
                        app->handle == s->terminal_channel_handle ||
                        app->cleanup_pending)
                        continue;
                    source_fd = sync_instance_source_fd(s, slot);
                    sink_fd = sync_instance_sink_fd(s, slot);
                    if (source_fd >= 0 && !app->process_output_eof &&
                        s->state == SESSION_ESTABLISHED && !pace_blocked &&
                        channel_source_budget != 0U &&
                        sync_tx_room_instance(s, slot) != 0U) {
                        if (poll_append_unique(
                                pfds, poll_capacity, &nfds, source_fd,
                                POLLIN, &idx_process_source[slot]) != 0) {
                            session_poll_owner_failure(
                                s, "channel process source");
                            poll_set_invalid = 1;
                            break;
                        }
                    }
                    if (sink_fd >= 0 &&
                        sync_rx_pending_instance(s, slot)) {
                        if (sink_fd == source_fd &&
                            idx_process_source[slot] >= 0) {
                            idx_process_sink[slot] =
                                idx_process_source[slot];
                            pfds[idx_process_sink[slot]].events |= POLLOUT;
                        } else if (poll_append_unique(
                                       pfds, poll_capacity, &nfds, sink_fd,
                                       POLLOUT,
                                       &idx_process_sink[slot]) != 0) {
                            session_poll_owner_failure(
                                s, "channel process sink");
                            poll_set_invalid = 1;
                            break;
                        }
                    }
                }
                if (poll_set_invalid)
                    break;
            }

            /* listener-monitor: the fixed existing-engine backend contributes exactly
             * one distinct work-carriage owner, or one immediate local
             * step.  PREBOUND/STOPPED contributes neither.  The ordinary
             * NULL path performs no additional poll operation. */
            if (monitor_session_backend_is_bound(s)) {
                monitor_session_backend_wait_t wait = {-1, 0U, 0U, 0U};

                if (monitor_session_backend_interest(s, &wait) != 0) {
                    session_monitor_backend_failure(s, "interest");
                    break;
                }
                if (wait.reserved != 0U ||
                    (wait.immediate &&
                     (wait.fd != -1 || wait.events != 0U)) ||
                    (!wait.immediate && wait.fd < 0 && wait.events != 0U) ||
                    (wait.events & (uint16_t)~(POLLIN | POLLOUT)) != 0U) {
                    session_poll_owner_failure(s, "monitor backend");
                    break;
                }
                if (wait.immediate) {
                    monitor_worker_immediate = 1;
                    poll_ms = 0;
                } else if (wait.fd >= 0) {
                    if (wait.events == 0U || poll_append_unique(
                            pfds, poll_capacity, &nfds, wait.fd,
                            (short)wait.events,
                            &idx_monitor_worker) != 0) {
                        session_poll_owner_failure(
                            s, "monitor backend worker");
                        break;
                    }
                }
            }

            int idx_inject = -1;

            int pr = poll(pfds, (nfds_t)nfds, poll_ms);
            if (pr < 0) {
                if (errno == EINTR) {
                    errno = 0;
                    /* Service the tick before restarting the poll. `continue`
                     * jumps over the tick at the tail of this body, so a
                     * signal that interrupts poll used to wait for a *fresh*
                     * full poll_ms before it was answered -- being
                     * interrupted was worse than not being interrupted, since
                     * without EINTR the flag is seen at whatever is left of
                     * the current timeout and with it the clock restarts from
                     * zero. MN-B4-6 above anticipated up to 100 ms of tail
                     * latency here and attributed it to the post-poll check;
                     * the restart made it a near-constant 100 ms instead.
                     * Measured on an idle endpoint: 20 signals at 101.5-104.8
                     * ms, mean 102.7, before this line; 0.2-0.7 ms, mean 0.3,
                     * after it. The spread is the tell -- a wait that
                     * depended on the signal's arrival phase would be spread
                     * across the band, and a constant full timeout is what a
                     * restarted poll produces.
                     *
                     * This is a correctness fix for two measurements, not a
                     * latency preference. The drain-capture window is placed
                     * from these answers and is quiet at both edges by
                     * construction, so the placement bracket was wide exactly
                     * where the reconciliation needs it tight; and
                     * `carriage_covers_delivery` compares two endpoints'
                     * counters from one request, so a 100 ms skew between
                     * their replies let delivery be read after carriage while
                     * bytes were still moving. `tools/signal_latency_test.py`
                     * holds the bound. The tick is the same call the tail of
                     * the loop makes and it is reached with the body having
                     * done nothing, so it sees the state the previous
                     * iteration left -- which is the state that call already
                     * ran against. */
                    if (session_run_tick) session_run_tick(s);
                    continue;
                }
                fprintf(stderr, "session: poll: %s — closing\n", strerror(errno));
                session_transport_closed(s);
                channel_close_all(s);
                enter_idle(s);
                break;
            }

            /* Service at most one existing work-engine step before another
             * local source can publish bytes. HUP/ERR is real readiness for
             * the fixed adapter; POLLNVAL and any service failure are an
             * owned loud local failure, never an ordinary-path fallback. */
            if (monitor_worker_immediate ||
                (idx_monitor_worker >= 0 &&
                 (pfds[idx_monitor_worker].revents &
                  (POLLIN | POLLOUT | POLLHUP | POLLERR | POLLNVAL)) != 0)) {
                short revents = idx_monitor_worker >= 0
                    ? pfds[idx_monitor_worker].revents : 0;

                if (monitor_session_backend_service(s, revents) != 0) {
                    session_monitor_backend_failure(s, "service");
                    break;
                }
            }

            /* A stream transport emits its two-byte length prefix and body
             * in separate one-syscall scheduler turns.  If both peers write
             * a prefix in the same turn, POLLIN and POLLOUT are ready
             * together.  Entering recv() first makes both sides wait for a
             * body that each side has deliberately retained for its next
             * turn.  Advance the immutable continuation before consuming a
             * newly readable prefix.  This cannot starve inbound work: the
             * retained product frame is at most FRAME_MAX_LEN and each
             * writable turn makes transport progress; EAGAIN leaves POLLOUT
             * clear and therefore falls through to inbound dispatch. */
            if (s->wire_frame_len != 0) {
                int send_ready = idx_send >= 0 &&
                    (pfds[idx_send].revents & POLLOUT) != 0;
                int send_error = idx_send >= 0 &&
                    ((pfds[idx_send].revents & POLLNVAL) != 0 ||
                     (!poll_hup_err_is_readable &&
                      (pfds[idx_send].revents &
                       (POLLHUP | POLLERR)) != 0));
                for (int ri = 0; ri < recv_count; ri++) {
                    for (int si = 0; si < send_count; si++) {
                        if (recv_fds[ri] != send_fds[si])
                            continue;
                        if ((pfds[idx_transport[ri]].revents &
                             POLLOUT) != 0)
                            send_ready = 1;
                        if ((pfds[idx_transport[ri]].revents &
                             POLLNVAL) != 0 ||
                            (!poll_hup_err_is_readable &&
                             (pfds[idx_transport[ri]].revents &
                              (POLLHUP | POLLERR)) != 0))
                            send_error = 1;
                    }
                }
                if (send_ready && !send_error)
                    continue;
            }

            /* Select from actual readiness, not requested poll interest.
             * The anchor and every dynamic exact-stream source share one
             * session cursor and one DATA-admission budget. Sinks and local
             * attach completions remain independently serviceable. */
            if (session_channelised_active(s) &&
                channel_source_budget != 0U && !pace_blocked) {
                const short source_revents =
                    POLLIN | POLLHUP | POLLERR | POLLNVAL;
                unsigned int offset;

                for (offset = 0U;
                     offset < CHANNEL_SESSION_DATA_SLOTS; offset++) {
                    uint8_t candidate = (uint8_t)(1U +
                        ((unsigned int)s->channel_source_cursor + offset) %
                            CHANNEL_SESSION_DATA_SLOTS);
                    int ready = 0;

                    if (candidate == anchor_source_slot) {
                        int index = s->is_server ? idx_pty : idx_stdin;

                        ready = index >= 0 &&
                            (pfds[index].revents & source_revents) != 0;
                    } else if (s->is_server) {
                        int index = idx_process_source[candidate];

                        ready = index >= 0 &&
                            (pfds[index].revents & source_revents) != 0;
                    } else {
                        for (size_t ai = 0U; ai < attach_count; ai++) {
                            uint8_t owner_slot = 0U;
                            attach_manager_connection_info_t info;
                            session_channel_application_t *owner_app =
                                channel_application_by_owner(
                                    s, attach_entries[ai].owner,
                                    &owner_slot);

                            if (!owner_app || owner_slot != candidate ||
                                idx_attach[ai] < 0 ||
                                attach_manager_connection_info(
                                    &s->attach_manager,
                                    attach_entries[ai].owner, &info) !=
                                        ATTACH_LOCAL_OK ||
                                info.state != ATTACH_MANAGER_STATE_ACTIVE)
                                continue;
                            if ((pfds[idx_attach[ai]].revents &
                                 source_revents) != 0)
                                ready = 1;
                            break;
                        }
                    }
                    if (ready) {
                        selected_source_slot = candidate;
                        break;
                    }
                }
            }

            /* PTY master readable (server) */
            if (idx_pty >= 0 &&
                (pfds[idx_pty].revents & POLLNVAL) != 0 &&
                session_channelised_active(s)) {
                session_channel_stream_io_failed(
                    s, anchor_source_slot, CHANNEL_CODE_RESOURCE);
                channel_source_budget = 0U;
                s->channel_source_cursor = (uint8_t)(
                    anchor_source_slot % CHANNEL_SESSION_DATA_SLOTS);
            } else if (idx_pty >= 0 &&
                (pfds[idx_pty].revents & (POLLIN|POLLHUP|POLLERR)) &&
                (!session_channelised_active(s) ||
                 selected_source_slot == anchor_source_slot)) {
                channel_pty_pump_master(s);
                if (session_channelised_active(s)) {
                    channel_source_budget = 0U;
                    s->channel_source_cursor = (uint8_t)(
                        anchor_source_slot % CHANNEL_SESSION_DATA_SLOTS);
                }
            }
            /* PTY master writable: legacy backlog flush, or the
             * terminal state sync pending-ring drain into the shell. */
            if (idx_pty >= 0 && (pfds[idx_pty].revents & POLLOUT)) {
                if (sync_on) sync_rx_deliver(s);
                else         channel_pty_flush_master_backlog(s);
            }

            /* stdin readable (client) */
            if (idx_stdin >= 0 &&
                (pfds[idx_stdin].revents & POLLNVAL) != 0 &&
                session_channelised_active(s) &&
                selected_source_slot == anchor_source_slot) {
                (void)channel_pty_finish_stdin(s);
                channel_source_budget = 0U;
                s->channel_source_cursor = (uint8_t)(
                    anchor_source_slot % CHANNEL_SESSION_DATA_SLOTS);
            } else if (idx_stdin >= 0 &&
                (pfds[idx_stdin].revents & (POLLIN|POLLHUP|POLLERR)) &&
                (!session_channelised_active(s) ||
                 selected_source_slot == anchor_source_slot)) {
                if (channel_pty_pump_stdin(s) < 0) {
                    /* stdin EOF — session_close already called */
                }
                if (session_channelised_active(s)) {
                    channel_source_budget = 0U;
                    s->channel_source_cursor = (uint8_t)(
                        anchor_source_slot % CHANNEL_SESSION_DATA_SLOTS);
                }
            }

            /* client stdout writable — flush pending display bytes */
            if (idx_stdout >= 0 &&
                (pfds[idx_stdout].revents & (POLLOUT|POLLHUP|POLLERR))) {
                sync_rx_deliver(s);
            }

            if (s->attach_socket_open) {
                for (size_t ai = 0U; ai < attach_count; ai++) {
                    int attach_status;
                    short revents;
                    uint8_t owner_slot = 0U;
                    attach_manager_connection_info_t info;
                    session_channel_application_t *owner_app;
                    int active_source;

                    if (idx_attach[ai] < 0 ||
                        pfds[idx_attach[ai]].revents == 0)
                        continue;
                    revents = pfds[idx_attach[ai]].revents;
                    owner_app = channel_application_by_owner(
                        s, attach_entries[ai].owner, &owner_slot);
                    active_source = owner_app != NULL &&
                        attach_manager_connection_info(
                            &s->attach_manager, attach_entries[ai].owner,
                            &info) == ATTACH_LOCAL_OK &&
                        info.state == ATTACH_MANAGER_STATE_ACTIVE;
                    if (active_source && owner_slot != selected_source_slot)
                        revents &= (short)~(POLLIN | POLLHUP | POLLERR);
                    if (revents == 0)
                        continue;
                    attach_status = attach_manager_service(
                        &s->attach_manager, attach_entries[ai].owner,
                        revents, mono_ms());
                    if (attach_status < 0 &&
                        attach_entries[ai].owner ==
                            ATTACH_MANAGER_LISTENER_OWNER) {
                        fprintf(stderr,
                                "session: local attach listener failed: %s\n",
                                strerror(errno));
                        (void)attach_manager_close(&s->attach_manager);
                        s->attach_socket_open = 0U;
                        break;
                    } else if (attach_status < 0) {
                        fprintf(stderr,
                                "session: local channel-session attach connection "
                                "failed (owner=%llu status=%d): %s\n",
                                (unsigned long long)
                                    attach_entries[ai].owner,
                                attach_status, strerror(errno));
                    }
                }
                session_channel_application_tick(
                    s, mono_ms(), NULL, &channel_source_budget);
                if (selected_source_slot != 0U &&
                    selected_source_slot != anchor_source_slot)
                    s->channel_source_cursor = (uint8_t)(
                        selected_source_slot % CHANNEL_SESSION_DATA_SLOTS);
            }

            if (s->is_server && session_channelised_active(s)) {
                for (uint8_t slot = 1U;
                     slot < CHANNEL_SESSION_SLOTS; slot++) {
                    int index = idx_process_sink[slot];

                    if (index < 0)
                        continue;
                    if ((pfds[index].revents & POLLNVAL) != 0) {
                        session_channel_stream_io_failed(
                            s, slot, CHANNEL_CODE_RESOURCE);
                    } else if ((pfds[index].revents &
                                (POLLOUT | POLLHUP | POLLERR)) != 0) {
                        sync_rx_deliver_instance(s, slot);
                    }
                }
                /* Poll may report many readable children, but channel-session admits at
                 * most one local source record per event-loop turn. */
                if (selected_source_slot != 0U &&
                    selected_source_slot != anchor_source_slot) {
                    uint8_t slot = selected_source_slot;
                    int index = idx_process_source[slot];

                    if (index >= 0 &&
                        (pfds[index].revents & POLLNVAL) != 0)
                        session_channel_stream_io_failed(
                            s, slot, CHANNEL_CODE_RESOURCE);
                    else if (index >= 0 &&
                             (pfds[index].revents &
                              (POLLIN | POLLHUP | POLLERR)) != 0)
                        channel_application_pump_process_source(s, slot);
                    channel_source_budget = 0U;
                    s->channel_source_cursor = (uint8_t)(
                        slot % CHANNEL_SESSION_DATA_SLOTS);
                }
                session_channel_application_tick(
                    s, mono_ms(), NULL, &channel_source_budget);
            }

            (void)idx_inject;
            (void)idx_send; /* POLLOUT is consumed by the next loop turn. */

            /* Transport readable. Multipath polls both local legs but consumes
             * exactly one datagram per loop turn with immutable ingress
             * metadata. */
            int transport_bad = 0;
            int transport_readable = 0;
            for (int ri = 0; ri < recv_count; ri++) {
                short revents = pfds[idx_transport[ri]].revents;
                if ((revents & POLLNVAL) != 0 ||
                    (!poll_hup_err_is_readable &&
                     (revents & (POLLHUP|POLLERR)) != 0))
                    transport_bad = 1;
                if ((revents & POLLIN) != 0 ||
                    (poll_hup_err_is_readable &&
                     (revents & (POLLHUP|POLLERR)) != 0))
                    transport_readable = 1;
            }
            if (transport_bad) {
                fprintf(stderr, "session: transport poll hup/err — closing\n");
                session_transport_closed(s);
                channel_close_all(s);
                enter_idle(s);
                break;
            }
            if (transport_readable) {
                /* Pass a small positive timeout so transports that need to
                 * read a full frame (e.g. length prefix + body) don't
                * spuriously time out between reads. */
                multipath_token_t ingress;
                preauth_source_t source;
                int path_aware = s->multipath_requested &&
                                 s->transport->ops->recv_from;
                int source_aware = s->transport->ops->recv_source != NULL;
                uint8_t *receive_buf = buf;
                size_t receive_capacity = sizeof(buf);
                size_t bulk_capacity = 0U;
                uint8_t *bulk_buf = session_bulk_receive_storage(
                    s, &bulk_capacity);
                if (bulk_buf) {
                    receive_buf = bulk_buf;
                    receive_capacity = bulk_capacity;
                }
                int n = source_aware
                    ? s->transport->ops->recv_source(
                          s->transport, receive_buf, receive_capacity,
                          500, &ingress, &source)
                    : path_aware
                    ? s->transport->ops->recv_from(
                          s->transport, receive_buf, receive_capacity,
                          500, &ingress)
                    : s->transport->ops->recv(
                          s->transport, receive_buf, receive_capacity, 500);
                if (n > 0 || (n == 0 && source_aware)) {
                    preauth_source_t derived_source;
                    const preauth_source_t *source_ptr =
                        source_aware ? &source : NULL;
                    int source_required = source_aware || path_aware;

                    if (!source_aware && path_aware &&
                        preauth_source_from_ingress(
                            &ingress, &derived_source) == 0)
                        source_ptr = &derived_source;
                    process_frame(s, receive_buf, (size_t)n,
                                  path_aware ? &ingress : NULL,
                                  source_ptr, source_required, mono_ms());
                } else if (n < 0) {
                    if (errno == EBADF || errno == EPIPE || errno == EIO ||
                        errno == ECONNRESET || errno == ENOTCONN) {
                        fprintf(stderr, "session: transport recv error (%s) — closing\n",
                                strerror(errno));
                        session_transport_closed(s);
                        channel_close_all(s);
                        enter_idle(s);
                        break;
                    }
                    errno = 0;
                }
            }
        } else {
            /* No pollable fd (shouldn't happen with current transports) —
             * fall back to blocking recv with timeout. */
            uint8_t *receive_buf = buf;
            size_t receive_capacity = sizeof(buf);
            size_t bulk_capacity = 0U;
            uint8_t *bulk_buf = session_bulk_receive_storage(
                s, &bulk_capacity);
            if (bulk_buf) {
                receive_buf = bulk_buf;
                receive_capacity = bulk_capacity;
            }
            multipath_token_t ingress;
            preauth_source_t source;
            int path_aware = s->multipath_requested &&
                             s->transport->ops->recv_from;
            int source_aware = s->transport->ops->recv_source != NULL;
            int n = source_aware
                ? s->transport->ops->recv_source(
                      s->transport, receive_buf, receive_capacity, poll_ms,
                      &ingress, &source)
                : path_aware
                ? s->transport->ops->recv_from(
                      s->transport, receive_buf, receive_capacity, poll_ms,
                      &ingress)
                : s->transport->ops->recv(
                      s->transport, receive_buf, receive_capacity, poll_ms);
            if (n < 0) {
                if (errno == EBADF || errno == EPIPE || errno == EIO ||
                    errno == ECONNRESET || errno == ENOTCONN) {
                    fprintf(stderr, "session: transport recv error (%s) — closing\n",
                            strerror(errno));
                    session_transport_closed(s);
                    channel_close_all(s);
                    enter_idle(s);
                    break;
                }
                errno = 0;
                continue;
            }
            if (n > 0 || (n == 0 && source_aware)) {
                preauth_source_t derived_source;
                const preauth_source_t *source_ptr =
                    source_aware ? &source : NULL;
                int source_required = source_aware || path_aware;

                if (!source_aware && path_aware &&
                    preauth_source_from_ingress(
                        &ingress, &derived_source) == 0)
                    source_ptr = &derived_source;
                process_frame(s, receive_buf, (size_t)n,
                              path_aware ? &ingress : NULL,
                              source_ptr, source_required, mono_ms());
            }
        }

        /* Client should_exit flag from PTY_EOF */
        if (s->should_exit) {
            if (s->bulk_activated &&
                bulk_engine_result(s->bulk, NULL) ==
                    BULK_ENGINE_RESULT_RUNNING) {
                /* A process-owned signal marks the authenticated bulk state
                 * CANCELLED first. Give that bounded state one ordinary
                 * scheduler opportunity; signal cleanup never waits on it. */
                (void)session_bulk_cancel(s);
                (void)wire_drive_turn(s, mono_ms());
            }
            if (session_channelised_active(s)) {
                if (session_channel_terminal_complete(
                        s, (uint32_t)s->client_exit_code) != 0) {
                    fprintf(stderr,
                            "session: could not begin channel-session terminal teardown\n");
                    s->run_failed = 1;
                    session_close(s);
                }
            } else {
                session_close(s);
            }
            s->should_exit = 0;
        }

        /* Client tick hook — flush pending SIGINT/SIGWINCH */
        if (session_run_tick) session_run_tick(s);
    }

    result = s->run_failed ? -1 :
             ((s->state == SESSION_IDLE) ? 0 : -1);
    s->wire_in_run_loop = 0;
    return result;
}
