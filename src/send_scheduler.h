/*
 * send_scheduler.h — send-scheduler fixed-rate wire arbitration policy
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * This module owns no payload and performs no I/O.  Product producers retain
 * their bounded logical state; the session asks this policy for one lane per
 * event-loop turn and retains at most one encoded frame while the transport
 * completes nonblockingly.
 */
#ifndef UNMOOR_SEND_SCHEDULER_H
#define UNMOOR_SEND_SCHEDULER_H

#define _POSIX_C_SOURCE 200809L

#include <stdint.h>

typedef enum {
    SEND_LANE_CONTROL = 0,
    SEND_LANE_FEEDBACK = 1,
    SEND_LANE_INTERACTIVE = 2,
    SEND_LANE_RECOVERY = 3,
    SEND_LANE_NEW = 4,
    SEND_LANE_COUNT = 5
} send_lane_t;

#define SEND_LANE_BIT(lane) (1U << (unsigned)(lane))

typedef enum {
    SEND_MODE_ESTABLISHED = 0,
    SEND_MODE_REKEY = 1,
    SEND_MODE_PRE_SERVICE = 2,
    SEND_MODE_ABORT = 3
} send_mode_t;

/* A transport step may make no progress, make a partial stream write,
 * complete the frame, or fail the attempt.  Only WOULD_BLOCK retains an
 * entirely uncharged frame.  PROGRESS charges once and retains it; COMPLETE
 * charges if needed and releases it; FAILED is an accounted attempt. */
typedef enum {
    SEND_STEP_WOULD_BLOCK = 0,
    SEND_STEP_PROGRESS = 1,
    SEND_STEP_COMPLETE = 2,
    SEND_STEP_FAILED = 3
} send_step_result_t;

typedef struct {
    int64_t rate_bps;
    int64_t credit_milli;
    int64_t burst_milli;
    int64_t last_refill_ms;
    int64_t frame_cost_milli;

    uint64_t path_generation;
    uint64_t selected[SEND_LANE_COUNT];
    uint64_t completed[SEND_LANE_COUNT];
    uint64_t failed[SEND_LANE_COUNT];
    uint64_t would_block;
    uint64_t partial_progress;
    /* multipath keeps logical producer accounting above visible physical-copy
     * accounting. One immutable logical frame may have two UDP copies. */
    uint64_t physical_attempted;
    uint64_t physical_completed;
    uint64_t physical_failed;
    uint64_t physical_would_block;
    uint64_t physical_partial;
    uint64_t physical_skipped;

    uint8_t next_lane;
    uint8_t turn_used;
    uint8_t in_flight;
    uint8_t in_flight_lane;
    uint8_t in_flight_charged;       /* any copy/progress handed off */
    uint8_t current_copy_charged;    /* current physical copy only */
    uint8_t replica_ready;           /* prior physical copy terminal */
    uint8_t abort_remaining;
    uint8_t service_started;         /* REKEY is paced only after this */
} send_scheduler_t;

/* `rate_bps == 0` keeps arbitration but disables the byte/time claim.
 * `effective_mtu` is the packet-equivalent payload unit and must be nonzero. */
int send_scheduler_init(send_scheduler_t *sched, int64_t rate_bps,
                        uint16_t effective_mtu, int64_t now_ms);

/* Start exactly one event-loop turn.  A turn may attempt one existing frame
 * or select/attempt one new frame, never drain a producer synchronously. */
void send_scheduler_begin_turn(send_scheduler_t *sched);

void send_scheduler_refill(send_scheduler_t *sched, int64_t now_ms);

/* Select one eligible lane. Returns 1 with `lane_out`, 0 when no grant is
 * currently legal, and -1 for invalid state/arguments.  PRE_SERVICE is
 * rate-exempt, and so is REKEY until send_scheduler_service_started()
 * (the mandatory epoch-one barrier, send-scheduler); ABORT is rate-exempt but
 * limited by abort_remaining. */
int send_scheduler_grant(send_scheduler_t *sched, uint8_t eligible_mask,
                         send_mode_t mode, int64_t now_ms,
                         send_lane_t *lane_out);

/* Begin one retry step for the retained frame in a new event-loop turn. */
int send_scheduler_retry_begin(send_scheduler_t *sched);

/* Record the result of the one transport step in this turn. */
int send_scheduler_step_result(send_scheduler_t *sched,
                               send_step_result_t result,
                               int64_t now_ms);

/* Account one failed physical datagram attempt while retaining the same
 * logical frame for a timer-owned retry. Unlike SEND_STEP_FAILED through
 * step_result/copy_result, this does not complete the logical owner or make a
 * different replica eligible. The next turn uses retry_begin() and charges
 * the next physical attempt independently. */
int send_scheduler_retryable_failure(send_scheduler_t *sched,
                                     int64_t now_ms);

/* Retire a retained logical frame after an external application/transport
 * boundary has made another physical syscall impossible. No phantom physical
 * attempt is counted. */
int send_scheduler_fail_retained(send_scheduler_t *sched);

/* multipath physical-copy boundary. `send_scheduler_copy_result` accounts one
 * visible transport syscall. COMPLETE/FAILED may leave the logical frame in
 * flight when `logical_terminal` is false; the next event-loop turn starts
 * its next fixed-plan copy with `send_scheduler_replica_begin`. A replica
 * skipped before a syscall is visible but uncharged. Logical completion and
 * the producer callback occur exactly once at the terminal call. */
int send_scheduler_copy_result(send_scheduler_t *sched,
                               send_step_result_t result,
                               int logical_terminal,
                               int logical_completed,
                               int64_t now_ms);
int send_scheduler_replica_begin(send_scheduler_t *sched);
/* After an uncharged WOULD_BLOCK, move to another fixed-plan copy without
 * classifying the blocked copy as terminal or incrementing `physical_skipped`.
 * The blocked copy remains eligible until success freezes best-effort policy. */
int send_scheduler_replica_rotate(send_scheduler_t *sched);
int send_scheduler_replica_skip(send_scheduler_t *sched,
                                int logical_terminal,
                                int logical_completed);

/* Cancel a selected frame only when the transport has made zero progress.
 * Used by terminal close to discard an EAGAIN-only ordinary record before
 * entering exclusive abort mode. A partial stream frame is not abandonable. */
int send_scheduler_abandon_untouched(send_scheduler_t *sched);

/* Arm the exact terminal-abort allowance. `valid_epochs` is clamped to two. */
void send_scheduler_begin_abort(send_scheduler_t *sched,
                                unsigned int valid_epochs);

/* Called only after the session's existing AEAD + replay + HWM gate confirms
 * an actual peer-address change.  Retains debt and clamps positive saved
 * credit to one packet-equivalent grant. */
void send_scheduler_path_changed(send_scheduler_t *sched, int64_t now_ms);

/* Service start (session_activate_services).  From here on REKEY work is
 * the established epoch engine and is paced like ESTABLISHED.  Before it,
 * REKEY is the mandatory pre-service epoch-one barrier, which send-scheduler keeps
 * rate-exempt so a supported 1 B/s setting cannot make its absolute
 * bootstrap deadline impossible.  The first transition clamps negative
 * exemption debt to zero without granting a fresh burst; repeated calls do
 * not forgive established debt.  send_scheduler_init() clears the state. */
void send_scheduler_service_started(send_scheduler_t *sched);

/* Time until a paced established/rekey grant can become legal, or -1 when no
 * timer is needed.  An in-flight frame is transport-writability driven. */
int64_t send_scheduler_next_deadline(send_scheduler_t *sched,
                                     uint8_t eligible_mask,
                                     send_mode_t mode, int64_t now_ms);

#endif /* UNMOOR_SEND_SCHEDULER_H */
