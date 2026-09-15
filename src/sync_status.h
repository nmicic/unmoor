/*
 * sync_status.h — truthful terminal-sync telemetry and idle heartbeat
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * This module is deliberately observational. Its absolute counters never
 * acknowledge, credit, prune, deliver, or otherwise mutate the terminal-state-sync stream.
 */
#ifndef UNMOOR_SYNC_STATUS_H
#define UNMOOR_SYNC_STATUS_H

#define _POSIX_C_SOURCE 200809L

#include <stddef.h>
#include <stdint.h>

#include "path_leg.h"

#define SYNC_STATUS_VERSION               1U
#define SYNC_STATUS_WIRE_LEN              24U
#define SYNC_STATUS_FLAG_POLL             0x01U
#define SYNC_STATUS_FLAG_SINK_BLOCKED     0x02U
#define SYNC_STATUS_FLAGS_KNOWN           0x03U

#define SYNC_STATUS_HEARTBEAT_MS          INT64_C(5000)
#define SYNC_STATUS_STALL_MS              INT64_C(12000)
#define SYNC_STATUS_TITLE_REFRESH_MS      INT64_C(1000)
#define SYNC_STATUS_LINE_MAX              8192U
#define SYNC_STATUS_OPERATOR_LEGS_MAX     32U

typedef struct {
    uint8_t  flags;
    uint32_t epoch;
    uint64_t tx_tip;
    uint64_t rx_delivered;
} sync_status_record_t;

typedef enum {
    SYNC_STATUS_OUT_OF_SYNC = 0,
    SYNC_STATUS_SYNC        = 1,
    SYNC_STATUS_STALLED     = 2,
} sync_status_state_t;

typedef struct {
    int      active;
    uint32_t epoch;

    int      peer_valid;
    uint8_t  peer_flags;
    uint64_t peer_tx_tip;
    uint64_t peer_rx_delivered;
    int64_t  peer_snapshot_ms;

    int64_t  started_ms;
    int64_t  last_authenticated_ms;
    int64_t  next_heartbeat_ms;
    int64_t  last_sync_ms;

    uint64_t observed_local_rx_delivered;
    uint64_t observed_peer_rx_delivered;
    uint64_t previous_behind;
    int      previous_behind_known;
    int64_t  behind_since_ms;
    int64_t  last_delivery_progress_ms;

    sync_status_state_t state;
    int      state_announced;
    sync_status_state_t announced_state;
    int64_t  next_title_refresh_ms;
} sync_status_tracker_t;

typedef struct {
    sync_status_state_t state;
    int      peer_valid;
    int      behind_known;
    int      peer_sink_blocked;
    uint64_t outgoing_behind;
    uint64_t incoming_behind;
    uint64_t total_behind;
    int64_t  authenticated_age_ms;
    int64_t  peer_snapshot_age_ms; /* -1 until the first valid snapshot */
    int64_t  last_sync_age_ms;     /* -1 until bilateral sync was proven */
    int64_t  stalled_age_ms;
} sync_status_view_t;

int sync_status_record_encode(const sync_status_record_t *record,
                              uint8_t out[SYNC_STATUS_WIRE_LEN]);
int sync_status_record_decode(const uint8_t *wire, size_t wire_len,
                              sync_status_record_t *record_out);

void sync_status_tracker_init(sync_status_tracker_t *tracker,
                              uint32_t epoch, int64_t now_ms);
void sync_status_tracker_reset(sync_status_tracker_t *tracker);
void sync_status_tracker_set_epoch(sync_status_tracker_t *tracker,
                                   uint32_t epoch, int64_t now_ms);
void sync_status_observe_authenticated(sync_status_tracker_t *tracker,
                                       int64_t now_ms);

/* Merge one authenticated absolute snapshot. Older component values are
 * stale and correctly worthless; they never regress state and are not fatal.
 * Returns 0, or -1 when the record is impossible in the local stream. */
int sync_status_observe_peer(sync_status_tracker_t *tracker,
                             const sync_status_record_t *record,
                             int64_t now_ms, uint64_t local_tx_tip,
                             uint64_t local_rx_delivered,
                             uint64_t local_rx_highest);

/* Recompute health from current local stream counters. Returns one when the
 * externally visible state changed, zero otherwise. */
int sync_status_evaluate(sync_status_tracker_t *tracker, int64_t now_ms,
                         uint64_t local_tx_tip,
                         uint64_t local_rx_delivered,
                         uint64_t local_rx_highest);

void sync_status_snapshot(sync_status_tracker_t *tracker, int64_t now_ms,
                          uint64_t local_tx_tip,
                          uint64_t local_rx_delivered,
                          uint64_t local_rx_highest,
                          sync_status_view_t *view_out);

int sync_status_heartbeat_due(const sync_status_tracker_t *tracker,
                              int64_t now_ms);
void sync_status_heartbeat_sent(sync_status_tracker_t *tracker,
                                int64_t now_ms);
int64_t sync_status_next_deadline(const sync_status_tracker_t *tracker,
                                  int64_t now_ms);
/* State/UI deadline without the heartbeat candidate.  Used while an exact
 * heartbeat publication is already owned by another reliable carrier. */
int64_t sync_status_next_state_deadline(
    const sync_status_tracker_t *tracker, int64_t now_ms);

const char *sync_status_state_name(sync_status_state_t state);
int sync_status_format_title(const sync_status_view_t *view,
                             char *out, size_t out_len);
int sync_status_format_line(const sync_status_view_t *view,
                            char *out, size_t out_len);
/* Legacy pre-sync-status roaming hold diagnostic.  A raw controlling terminal needs
 * CRLF on both sides so the operator's prompt/output cursor cannot turn
 * repeated diagnostics into a staircase.  Redirected logs retain ordinary
 * LF framing. */
int sync_status_format_liveness_hold(int64_t age_ms, int raw_terminal,
                                     char *out, size_t out_len);
/* Operator-local extension of the same status line. The exact 24-byte sync-status
 * wire record above is deliberately unchanged. */
int sync_status_format_line_with_legs(
    const sync_status_view_t *view,
    const path_leg_metrics_t *legs, size_t leg_count,
    char *out, size_t out_len);

#endif /* UNMOOR_SYNC_STATUS_H */
