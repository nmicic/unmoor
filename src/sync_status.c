/*
 * sync_status.c — truthful terminal-sync telemetry and idle heartbeat
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */

#define _POSIX_C_SOURCE 200809L

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "sync_status.h"

static uint32_t load32le(const uint8_t *p)
{
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint64_t load64le(const uint8_t *p)
{
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; i++)
        value |= (uint64_t)p[i] << (8U * i);
    return value;
}

static void store32le(uint8_t *p, uint32_t value)
{
    for (unsigned i = 0; i < 4; i++)
        p[i] = (uint8_t)(value >> (8U * i));
}

static void store64le(uint8_t *p, uint64_t value)
{
    for (unsigned i = 0; i < 8; i++)
        p[i] = (uint8_t)(value >> (8U * i));
}

static int64_t nonnegative_age(int64_t now_ms, int64_t then_ms)
{
    if (then_ms < 0)
        return -1;
    if (now_ms <= then_ms)
        return 0;
    return now_ms - then_ms;
}

static uint64_t saturating_add_u64(uint64_t a, uint64_t b)
{
    if (UINT64_MAX - a < b)
        return UINT64_MAX;
    return a + b;
}

int sync_status_record_encode(const sync_status_record_t *record,
                              uint8_t out[SYNC_STATUS_WIRE_LEN])
{
    if (!record || !out ||
        (record->flags & (uint8_t)~SYNC_STATUS_FLAGS_KNOWN) != 0)
        return -1;
    memset(out, 0, SYNC_STATUS_WIRE_LEN);
    out[0] = SYNC_STATUS_VERSION;
    out[1] = record->flags;
    store32le(out + 4, record->epoch);
    store64le(out + 8, record->tx_tip);
    store64le(out + 16, record->rx_delivered);
    return 0;
}

int sync_status_record_decode(const uint8_t *wire, size_t wire_len,
                              sync_status_record_t *record_out)
{
    if (!wire || !record_out || wire_len != SYNC_STATUS_WIRE_LEN ||
        wire[0] != SYNC_STATUS_VERSION ||
        (wire[1] & (uint8_t)~SYNC_STATUS_FLAGS_KNOWN) != 0 ||
        wire[2] != 0 || wire[3] != 0)
        return -1;
    record_out->flags = wire[1];
    record_out->epoch = load32le(wire + 4);
    record_out->tx_tip = load64le(wire + 8);
    record_out->rx_delivered = load64le(wire + 16);
    return 0;
}

void sync_status_tracker_init(sync_status_tracker_t *tracker,
                              uint32_t epoch, int64_t now_ms)
{
    if (!tracker)
        return;
    memset(tracker, 0, sizeof(*tracker));
    tracker->active = 1;
    tracker->epoch = epoch;
    tracker->started_ms = now_ms;
    tracker->last_authenticated_ms = now_ms;
    tracker->next_heartbeat_ms = now_ms;
    tracker->last_sync_ms = -1;
    tracker->peer_snapshot_ms = -1;
    tracker->behind_since_ms = -1;
    tracker->last_delivery_progress_ms = now_ms;
    tracker->state = SYNC_STATUS_OUT_OF_SYNC;
    tracker->next_title_refresh_ms = now_ms;
}

void sync_status_tracker_reset(sync_status_tracker_t *tracker)
{
    if (tracker)
        memset(tracker, 0, sizeof(*tracker));
}

void sync_status_tracker_set_epoch(sync_status_tracker_t *tracker,
                                   uint32_t epoch, int64_t now_ms)
{
    if (!tracker || !tracker->active)
        return;
    tracker->epoch = epoch;
    tracker->peer_valid = 0;
    tracker->peer_flags = 0;
    tracker->peer_tx_tip = 0;
    tracker->peer_rx_delivered = 0;
    tracker->peer_snapshot_ms = -1;
    tracker->previous_behind_known = 0;
    tracker->previous_behind = 0;
    tracker->behind_since_ms = -1;
    tracker->last_delivery_progress_ms = now_ms;
    tracker->next_heartbeat_ms = now_ms;
    tracker->state = SYNC_STATUS_OUT_OF_SYNC;
    tracker->state_announced = 0;
    tracker->next_title_refresh_ms = now_ms;
}

void sync_status_observe_authenticated(sync_status_tracker_t *tracker,
                                       int64_t now_ms)
{
    if (!tracker || !tracker->active)
        return;
    if (now_ms >= tracker->last_authenticated_ms)
        tracker->last_authenticated_ms = now_ms;
}

static void compute_behind(const sync_status_tracker_t *tracker,
                           uint64_t local_tx_tip,
                           uint64_t local_rx_delivered,
                           uint64_t local_rx_highest,
                           int *known_out, uint64_t *outgoing_out,
                           uint64_t *incoming_out, uint64_t *total_out)
{
    uint64_t outgoing = 0;
    uint64_t incoming = local_rx_highest > local_rx_delivered
                            ? local_rx_highest - local_rx_delivered : 0;
    int known = tracker && tracker->peer_valid;

    if (known) {
        uint64_t peer_rx = tracker->peer_rx_delivered;
        uint64_t peer_tip = tracker->peer_tx_tip;
        if (peer_rx < local_tx_tip)
            outgoing = local_tx_tip - peer_rx;
        if (peer_tip > local_rx_delivered &&
            peer_tip - local_rx_delivered > incoming)
            incoming = peer_tip - local_rx_delivered;
    }
    *known_out = known;
    *outgoing_out = outgoing;
    *incoming_out = incoming;
    *total_out = saturating_add_u64(outgoing, incoming);
}

static void observe_local_progress(sync_status_tracker_t *tracker,
                                   int64_t now_ms,
                                   uint64_t local_rx_delivered,
                                   int behind_known, uint64_t behind)
{
    if (local_rx_delivered > tracker->observed_local_rx_delivered)
        tracker->last_delivery_progress_ms = now_ms;
    tracker->observed_local_rx_delivered = local_rx_delivered;

    if (behind_known && behind > 0 &&
        (!tracker->previous_behind_known || tracker->previous_behind == 0)) {
        tracker->behind_since_ms = now_ms;
        tracker->last_delivery_progress_ms = now_ms;
    } else if (behind_known && behind == 0) {
        tracker->behind_since_ms = -1;
    }
    tracker->previous_behind_known = behind_known;
    tracker->previous_behind = behind;
}

int sync_status_evaluate(sync_status_tracker_t *tracker, int64_t now_ms,
                         uint64_t local_tx_tip,
                         uint64_t local_rx_delivered,
                         uint64_t local_rx_highest)
{
    int known;
    uint64_t outgoing, incoming, behind;
    int64_t authenticated_age;
    int64_t peer_age;
    int64_t progress_anchor;
    sync_status_state_t next;

    if (!tracker || !tracker->active)
        return 0;
    compute_behind(tracker, local_tx_tip, local_rx_delivered,
                   local_rx_highest, &known, &outgoing, &incoming, &behind);
    (void)outgoing;
    (void)incoming;
    observe_local_progress(tracker, now_ms, local_rx_delivered, known, behind);

    authenticated_age = nonnegative_age(now_ms,
                                         tracker->last_authenticated_ms);
    peer_age = tracker->peer_valid
        ? nonnegative_age(now_ms, tracker->peer_snapshot_ms) : -1;
    progress_anchor = tracker->behind_since_ms;
    if (tracker->last_delivery_progress_ms > progress_anchor)
        progress_anchor = tracker->last_delivery_progress_ms;

    if (authenticated_age >= SYNC_STATUS_STALL_MS ||
        (known && behind > 0 && progress_anchor >= 0 &&
         nonnegative_age(now_ms, progress_anchor) >= SYNC_STATUS_STALL_MS)) {
        next = SYNC_STATUS_STALLED;
    } else if (known && peer_age >= 0 &&
               peer_age < SYNC_STATUS_STALL_MS && behind == 0) {
        next = SYNC_STATUS_SYNC;
    } else {
        next = SYNC_STATUS_OUT_OF_SYNC;
    }

    if (next == SYNC_STATUS_SYNC && tracker->state != SYNC_STATUS_SYNC)
        tracker->last_sync_ms = now_ms;
    if (next == tracker->state)
        return 0;
    tracker->state = next;
    tracker->next_title_refresh_ms = now_ms;
    return 1;
}

int sync_status_observe_peer(sync_status_tracker_t *tracker,
                             const sync_status_record_t *record,
                             int64_t now_ms, uint64_t local_tx_tip,
                             uint64_t local_rx_delivered,
                             uint64_t local_rx_highest)
{
    if (!tracker || !record || !tracker->active ||
        record->epoch != tracker->epoch ||
        record->rx_delivered > local_tx_tip)
        return -1;

    /* Periodic status can reorder inside the replay window. Both counters are
     * monotonic in one epoch, so merge maxima and make a stale component
     * correctly worthless rather than turning ordinary reordering fatal. */
    if (!tracker->peer_valid || record->tx_tip > tracker->peer_tx_tip)
        tracker->peer_tx_tip = record->tx_tip;
    if (local_rx_delivered > tracker->peer_tx_tip)
        tracker->peer_tx_tip = local_rx_delivered;
    if (!tracker->peer_valid ||
        record->rx_delivered > tracker->peer_rx_delivered) {
        if (record->rx_delivered > tracker->observed_peer_rx_delivered)
            tracker->last_delivery_progress_ms = now_ms;
        tracker->peer_rx_delivered = record->rx_delivered;
    }
    tracker->observed_peer_rx_delivered = tracker->peer_rx_delivered;
    tracker->peer_flags = record->flags;
    tracker->peer_valid = 1;
    tracker->peer_snapshot_ms = now_ms;
    (void)sync_status_evaluate(tracker, now_ms, local_tx_tip,
                               local_rx_delivered, local_rx_highest);

    if (tracker->peer_rx_delivered == local_tx_tip &&
        tracker->peer_tx_tip == local_rx_delivered)
        tracker->last_sync_ms = now_ms;
    return 0;
}

void sync_status_snapshot(sync_status_tracker_t *tracker, int64_t now_ms,
                          uint64_t local_tx_tip,
                          uint64_t local_rx_delivered,
                          uint64_t local_rx_highest,
                          sync_status_view_t *view_out)
{
    int known;
    uint64_t outgoing, incoming, behind;
    int64_t progress_anchor;
    int64_t progress_age;

    if (!tracker || !view_out)
        return;
    (void)sync_status_evaluate(tracker, now_ms, local_tx_tip,
                               local_rx_delivered, local_rx_highest);
    compute_behind(tracker, local_tx_tip, local_rx_delivered,
                   local_rx_highest, &known, &outgoing, &incoming, &behind);
    memset(view_out, 0, sizeof(*view_out));
    view_out->state = tracker->state;
    view_out->peer_valid = tracker->peer_valid;
    view_out->behind_known = known;
    view_out->peer_sink_blocked = tracker->peer_valid &&
        (tracker->peer_flags & SYNC_STATUS_FLAG_SINK_BLOCKED) != 0;
    view_out->outgoing_behind = outgoing;
    view_out->incoming_behind = incoming;
    view_out->total_behind = behind;
    view_out->authenticated_age_ms = nonnegative_age(
        now_ms, tracker->last_authenticated_ms);
    view_out->peer_snapshot_age_ms = tracker->peer_valid
        ? nonnegative_age(now_ms, tracker->peer_snapshot_ms) : -1;
    view_out->last_sync_age_ms = nonnegative_age(now_ms,
                                                 tracker->last_sync_ms);

    progress_anchor = tracker->behind_since_ms;
    if (tracker->last_delivery_progress_ms > progress_anchor)
        progress_anchor = tracker->last_delivery_progress_ms;
    progress_age = progress_anchor >= 0
        ? nonnegative_age(now_ms, progress_anchor) : 0;
    view_out->stalled_age_ms = view_out->authenticated_age_ms;
    if (known && behind > 0 && progress_age > view_out->stalled_age_ms)
        view_out->stalled_age_ms = progress_age;
}

int sync_status_heartbeat_due(const sync_status_tracker_t *tracker,
                              int64_t now_ms)
{
    return tracker && tracker->active && now_ms >= tracker->next_heartbeat_ms;
}

void sync_status_heartbeat_sent(sync_status_tracker_t *tracker,
                                int64_t now_ms)
{
    if (!tracker || !tracker->active)
        return;
    tracker->next_heartbeat_ms = now_ms + SYNC_STATUS_HEARTBEAT_MS;
}

static int64_t sync_status_deadline(const sync_status_tracker_t *tracker,
                                    int64_t now_ms, int include_heartbeat)
{
    int64_t deadline = INT64_MAX;

    if (!tracker || !tracker->active)
        return -1;
    if (include_heartbeat)
        deadline = tracker->next_heartbeat_ms;
    if (tracker->state != SYNC_STATUS_STALLED) {
        int64_t auth_deadline = tracker->last_authenticated_ms +
                                SYNC_STATUS_STALL_MS;
        if (auth_deadline < deadline)
            deadline = auth_deadline;
    }
    if (tracker->state == SYNC_STATUS_SYNC && tracker->peer_valid) {
        int64_t peer_deadline = tracker->peer_snapshot_ms +
                                SYNC_STATUS_STALL_MS;
        if (peer_deadline < deadline)
            deadline = peer_deadline;
    }
    if (tracker->state != SYNC_STATUS_STALLED &&
        tracker->previous_behind_known && tracker->previous_behind > 0) {
        int64_t progress_anchor = tracker->behind_since_ms;
        if (tracker->last_delivery_progress_ms > progress_anchor)
            progress_anchor = tracker->last_delivery_progress_ms;
        if (progress_anchor >= 0 &&
            progress_anchor + SYNC_STATUS_STALL_MS < deadline)
            deadline = progress_anchor + SYNC_STATUS_STALL_MS;
    }
    if (!include_heartbeat && tracker->state != SYNC_STATUS_SYNC &&
        tracker->next_title_refresh_ms < deadline)
        deadline = tracker->next_title_refresh_ms;
    if (deadline == INT64_MAX)
        return -1;
    return deadline <= now_ms ? 0 : deadline - now_ms;
}

int64_t sync_status_next_deadline(const sync_status_tracker_t *tracker,
                                  int64_t now_ms)
{
    return sync_status_deadline(tracker, now_ms, 1);
}

int64_t sync_status_next_state_deadline(
    const sync_status_tracker_t *tracker, int64_t now_ms)
{
    return sync_status_deadline(tracker, now_ms, 0);
}

const char *sync_status_state_name(sync_status_state_t state)
{
    switch (state) {
    case SYNC_STATUS_SYNC:        return "SYNC";
    case SYNC_STATUS_STALLED:     return "STALLED";
    case SYNC_STATUS_OUT_OF_SYNC: return "OUT-OF-SYNC";
    }
    return "OUT-OF-SYNC";
}

static void format_bytes(uint64_t bytes, char *out, size_t out_len)
{
    if (bytes < UINT64_C(1000)) {
        (void)snprintf(out, out_len, "%" PRIu64 "B", bytes);
    } else if (bytes < UINT64_C(1000000)) {
        uint64_t tenths = (bytes + UINT64_C(50)) / UINT64_C(100);
        (void)snprintf(out, out_len, "%" PRIu64 ".%" PRIu64 "KB",
                       tenths / 10U, tenths % 10U);
    } else if (bytes < UINT64_C(1000000000)) {
        uint64_t tenths = (bytes + UINT64_C(50000)) / UINT64_C(100000);
        (void)snprintf(out, out_len, "%" PRIu64 ".%" PRIu64 "MB",
                       tenths / 10U, tenths % 10U);
    } else {
        uint64_t tenths = (bytes + UINT64_C(50000000)) /
                          UINT64_C(100000000);
        (void)snprintf(out, out_len, "%" PRIu64 ".%" PRIu64 "GB",
                       tenths / 10U, tenths % 10U);
    }
}

int sync_status_format_title(const sync_status_view_t *view,
                             char *out, size_t out_len)
{
    char bytes[48];
    int result;

    if (!view || !out || out_len == 0)
        return -1;
    if (view->state == SYNC_STATUS_SYNC) {
        result = snprintf(out, out_len, "unmoor: SYNC");
    } else if (!view->behind_known) {
        if (view->state == SYNC_STATUS_STALLED) {
            result = snprintf(out, out_len,
                              "unmoor: STALLED %llds · backlog unknown",
                              (long long)(view->stalled_age_ms / 1000));
        } else {
            result = snprintf(out, out_len,
                              "unmoor: OUT-OF-SYNC · backlog unknown");
        }
    } else {
        format_bytes(view->total_behind, bytes, sizeof(bytes));
        if (view->state == SYNC_STATUS_STALLED) {
            result = snprintf(out, out_len,
                              "unmoor: STALLED %llds · %s behind",
                              (long long)(view->stalled_age_ms / 1000), bytes);
        } else {
            result = snprintf(out, out_len,
                              "unmoor: OUT-OF-SYNC · %s behind", bytes);
        }
    }
    return result < 0 || (size_t)result >= out_len ? -1 : 0;
}

static void format_age(int64_t age_ms, char *out, size_t out_len)
{
    if (age_ms < 0)
        (void)snprintf(out, out_len, "unknown");
    else
        (void)snprintf(out, out_len, "%llds",
                       (long long)(age_ms / 1000));
}

int sync_status_format_line(const sync_status_view_t *view,
                            char *out, size_t out_len)
{
    char out_bytes[48], in_bytes[48];
    char peer_age[32], sync_age[32];
    int result;

    if (!view || !out || out_len == 0)
        return -1;
    format_bytes(view->outgoing_behind, out_bytes, sizeof(out_bytes));
    format_bytes(view->incoming_behind, in_bytes, sizeof(in_bytes));
    format_age(view->peer_snapshot_age_ms, peer_age, sizeof(peer_age));
    format_age(view->last_sync_age_ms, sync_age, sizeof(sync_age));
    if (!view->behind_known) {
        result = snprintf(out, out_len,
            "unmoor: status %s; contact=%llds; out=unknown; in=unknown; "
            "peer-status=%s; last-sync=%s",
            sync_status_state_name(view->state),
            (long long)(view->authenticated_age_ms / 1000),
            peer_age, sync_age);
    } else {
        result = snprintf(out, out_len,
            "unmoor: status %s; contact=%llds; out=%s; in=%s; "
            "peer-status=%s; last-sync=%s%s",
            sync_status_state_name(view->state),
            (long long)(view->authenticated_age_ms / 1000),
            out_bytes, in_bytes, peer_age, sync_age,
            view->peer_sink_blocked ? "; peer-sink=blocked" : "");
    }
    return result < 0 || (size_t)result >= out_len ? -1 : 0;
}

int sync_status_format_liveness_hold(int64_t age_ms, int raw_terminal,
                                     char *out, size_t out_len)
{
    const char *prefix;
    const char *suffix;
    int result;

    if (!out || out_len == 0U || age_ms < 0)
        return -1;
    prefix = raw_terminal ? "\r\n" : "";
    suffix = raw_terminal ? "\r\n" : "\n";
    result = snprintf(
        out, out_len,
        "%ssession: no contact for %llds — holding (liveness unbound)%s",
        prefix, (long long)(age_ms / 1000), suffix);
    return result < 0 || (size_t)result >= out_len ? -1 : 0;
}

int sync_status_format_line_with_legs(
    const sync_status_view_t *view,
    const path_leg_metrics_t *legs, size_t leg_count,
    char *out, size_t out_len)
{
    size_t used;
    size_t leg;

    if ((leg_count != 0U && legs == NULL) ||
        leg_count > SYNC_STATUS_OPERATOR_LEGS_MAX ||
        sync_status_format_line(view, out, out_len) != 0)
        return -1;
    used = strlen(out);
    for (leg = 0U; leg < leg_count; leg++) {
        char metrics[192];
        int result;

        if (path_leg_format_metrics(&legs[leg], metrics,
                                    sizeof(metrics)) != 0)
            return -1;
        result = snprintf(out + used, out_len - used, "%sP%zu[%s]",
                          leg == 0U ? "; legs=" : " ", leg, metrics);
        if (result < 0 || (size_t)result >= out_len - used)
            return -1;
        used += (size_t)result;
    }
    return 0;
}
