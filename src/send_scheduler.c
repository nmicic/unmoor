/*
 * send_scheduler.c — send-scheduler fixed-rate wire arbitration policy
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#include "send_scheduler.h"

#include <limits.h>
#include <stddef.h>
#include <string.h>

static int mode_valid(send_mode_t mode)
{
    return mode == SEND_MODE_ESTABLISHED || mode == SEND_MODE_REKEY ||
           mode == SEND_MODE_PRE_SERVICE || mode == SEND_MODE_ABORT;
}

static void charge_current_copy_once(send_scheduler_t *sched)
{
    if (sched->current_copy_charged)
        return;
    if (sched->rate_bps > 0)
        sched->credit_milli -= sched->frame_cost_milli;
    sched->current_copy_charged = 1;
    sched->in_flight_charged = 1;
}

static void finish_logical(send_scheduler_t *sched, int completed)
{
    unsigned int lane = sched->in_flight_lane;

    if (completed)
        sched->completed[lane]++;
    else
        sched->failed[lane]++;
    sched->next_lane = (uint8_t)((lane + 1U) % SEND_LANE_COUNT);
    sched->in_flight = 0;
    sched->in_flight_charged = 0;
    sched->current_copy_charged = 0;
    sched->replica_ready = 0;
}

int send_scheduler_init(send_scheduler_t *sched, int64_t rate_bps,
                        uint16_t effective_mtu, int64_t now_ms)
{
    int64_t burst_bytes;
    int64_t max_burst;

    if (!sched || rate_bps < 0 || effective_mtu == 0 || now_ms < 0)
        return -1;
    memset(sched, 0, sizeof(*sched));
    sched->rate_bps = rate_bps;
    sched->last_refill_ms = now_ms;
    sched->frame_cost_milli = (int64_t)effective_mtu * 1000;
    sched->next_lane = SEND_LANE_CONTROL;

    if (rate_bps == 0)
        return 0;
    max_burst = (int64_t)effective_mtu * 16;
    burst_bytes = rate_bps / 4;
    if (burst_bytes < 1)
        burst_bytes = 1;
    if (burst_bytes > max_burst)
        burst_bytes = max_burst;
    sched->burst_milli = burst_bytes * 1000;
    sched->credit_milli = sched->burst_milli;
    return 0;
}

void send_scheduler_begin_turn(send_scheduler_t *sched)
{
    if (sched)
        sched->turn_used = 0;
}

void send_scheduler_refill(send_scheduler_t *sched, int64_t now_ms)
{
    int64_t elapsed;
    int64_t deficit;
    int64_t full_ms;
    int64_t needed_ms;

    if (!sched || sched->rate_bps <= 0 ||
        now_ms <= sched->last_refill_ms)
        return;
    elapsed = now_ms - sched->last_refill_ms;
    sched->last_refill_ms = now_ms;
    if (sched->credit_milli >= sched->burst_milli) {
        sched->credit_milli = sched->burst_milli;
        return;
    }
    deficit = sched->burst_milli - sched->credit_milli;
    full_ms = deficit / sched->rate_bps;
    needed_ms = full_ms + ((deficit % sched->rate_bps) != 0);
    if (elapsed >= needed_ms) {
        sched->credit_milli = sched->burst_milli;
        return;
    }
    /* elapsed < ceil(deficit/rate), so the product is < deficit and cannot
     * overflow even when rate_bps came from LLONG_MAX input. */
    sched->credit_milli += sched->rate_bps * elapsed;
}

/* Rate gating applies to established work only.  PRE_SERVICE (the
 * handshake) and REKEY before service start (the mandatory epoch-one
 * barrier) are rate-exempt per send-scheduler so a supported 1 B/s setting cannot
 * make their absolute bootstrap deadline impossible.  Both are still
 * charged for physical accounting; the one-time service transition discards
 * only negative exemption debt so startup cannot impose an unbounded wait. */
static int rate_gated(const send_scheduler_t *sched, send_mode_t mode)
{
    return mode == SEND_MODE_ESTABLISHED ||
           (mode == SEND_MODE_REKEY && sched->service_started);
}

int send_scheduler_grant(send_scheduler_t *sched, uint8_t eligible_mask,
                         send_mode_t mode, int64_t now_ms,
                         send_lane_t *lane_out)
{
    unsigned int offset;

    if (!sched || !lane_out || !mode_valid(mode) || now_ms < 0 ||
        sched->in_flight || sched->turn_used)
        return -1;
    eligible_mask &= (uint8_t)((1U << SEND_LANE_COUNT) - 1U);
    if (eligible_mask == 0)
        return 0;
    send_scheduler_refill(sched, now_ms);
    if (rate_gated(sched, mode) && sched->rate_bps > 0 &&
        sched->credit_milli <= 0)
        return 0;
    if (mode == SEND_MODE_ABORT && sched->abort_remaining == 0)
        return 0;

    for (offset = 0; offset < SEND_LANE_COUNT; offset++) {
        unsigned int lane = ((unsigned int)sched->next_lane + offset) %
                            SEND_LANE_COUNT;
        if ((eligible_mask & SEND_LANE_BIT(lane)) == 0)
            continue;
        sched->in_flight = 1;
        sched->in_flight_lane = (uint8_t)lane;
        sched->in_flight_charged = 0;
        sched->current_copy_charged = 0;
        sched->replica_ready = 0;
        sched->turn_used = 1;
        sched->selected[lane]++;
        if (mode == SEND_MODE_ABORT)
            sched->abort_remaining--;
        *lane_out = (send_lane_t)lane;
        return 1;
    }
    return 0;
}

int send_scheduler_retry_begin(send_scheduler_t *sched)
{
    if (!sched || !sched->in_flight || sched->turn_used ||
        sched->replica_ready)
        return -1;
    sched->turn_used = 1;
    return 1;
}

int send_scheduler_copy_result(send_scheduler_t *sched,
                               send_step_result_t result,
                               int logical_terminal,
                               int logical_completed,
                               int64_t now_ms)
{
    if (!sched || !sched->in_flight || !sched->turn_used || now_ms < 0 ||
        result < SEND_STEP_WOULD_BLOCK || result > SEND_STEP_FAILED ||
        (logical_terminal != 0 && logical_terminal != 1) ||
        (logical_completed != 0 && logical_completed != 1) ||
        (logical_completed && !logical_terminal))
        return -1;
    send_scheduler_refill(sched, now_ms);
    sched->physical_attempted++;
    if (result == SEND_STEP_WOULD_BLOCK) {
        sched->would_block++;
        sched->physical_would_block++;
        if (logical_terminal)
            return -1;
        return 0;
    }
    charge_current_copy_once(sched);
    if (result == SEND_STEP_PROGRESS) {
        if (logical_terminal)
            return -1;
        sched->partial_progress++;
        sched->physical_partial++;
        return 0;
    }

    if (result == SEND_STEP_COMPLETE)
        sched->physical_completed++;
    else
        sched->physical_failed++;
    if (logical_terminal) {
        finish_logical(sched, logical_completed);
    } else {
        sched->replica_ready = 1;
    }
    return 0;
}

int send_scheduler_step_result(send_scheduler_t *sched,
                               send_step_result_t result,
                               int64_t now_ms)
{
    int terminal = result == SEND_STEP_COMPLETE || result == SEND_STEP_FAILED;
    return send_scheduler_copy_result(sched, result, terminal,
                                      result == SEND_STEP_COMPLETE, now_ms);
}

int send_scheduler_retryable_failure(send_scheduler_t *sched,
                                     int64_t now_ms)
{
    if (!sched || !sched->in_flight || !sched->turn_used ||
        sched->replica_ready || now_ms < 0)
        return -1;
    send_scheduler_refill(sched, now_ms);
    sched->physical_attempted++;
    charge_current_copy_once(sched);
    sched->physical_failed++;
    /* The logical owner remains selected. A later retry is a new physical
     * syscall, so it receives its own accounting/pace charge. */
    sched->current_copy_charged = 0;
    return 0;
}

int send_scheduler_fail_retained(send_scheduler_t *sched)
{
    if (!sched || !sched->in_flight)
        return -1;
    finish_logical(sched, 0);
    return 0;
}

int send_scheduler_replica_begin(send_scheduler_t *sched)
{
    if (!sched || !sched->in_flight || sched->turn_used ||
        !sched->replica_ready)
        return -1;
    sched->turn_used = 1;
    sched->current_copy_charged = 0;
    sched->replica_ready = 0;
    return 1;
}

int send_scheduler_replica_rotate(send_scheduler_t *sched)
{
    if (!sched || !sched->in_flight || !sched->turn_used ||
        sched->current_copy_charged || sched->replica_ready)
        return -1;
    sched->replica_ready = 1;
    return 0;
}

int send_scheduler_replica_skip(send_scheduler_t *sched,
                                int logical_terminal,
                                int logical_completed)
{
    if (!sched || !sched->in_flight || !sched->turn_used ||
        sched->current_copy_charged ||
        (logical_terminal != 0 && logical_terminal != 1) ||
        (logical_completed != 0 && logical_completed != 1) ||
        (logical_completed && !logical_terminal))
        return -1;
    sched->physical_skipped++;
    if (logical_terminal)
        finish_logical(sched, logical_completed);
    else
        sched->replica_ready = 1;
    return 0;
}

int send_scheduler_abandon_untouched(send_scheduler_t *sched)
{
    if (!sched || !sched->in_flight || sched->in_flight_charged)
        return -1;
    sched->in_flight = 0;
    sched->in_flight_lane = 0;
    sched->current_copy_charged = 0;
    sched->replica_ready = 0;
    return 0;
}

void send_scheduler_begin_abort(send_scheduler_t *sched,
                                unsigned int valid_epochs)
{
    if (!sched)
        return;
    sched->abort_remaining =
        (uint8_t)(valid_epochs > 2U ? 2U : valid_epochs);
}

void send_scheduler_service_started(send_scheduler_t *sched)
{
    if (!sched || sched->service_started)
        return;
    sched->service_started = 1;
    if (sched->rate_bps > 0 && sched->credit_milli < 0)
        sched->credit_milli = 0;
}

void send_scheduler_path_changed(send_scheduler_t *sched, int64_t now_ms)
{
    if (!sched || now_ms < 0)
        return;
    send_scheduler_refill(sched, now_ms);
    sched->path_generation++;
    if (sched->rate_bps > 0 &&
        sched->credit_milli > sched->frame_cost_milli)
        sched->credit_milli = sched->frame_cost_milli;
}

int64_t send_scheduler_next_deadline(send_scheduler_t *sched,
                                     uint8_t eligible_mask,
                                     send_mode_t mode, int64_t now_ms)
{
    int64_t need;

    if (!sched || !mode_valid(mode) || now_ms < 0)
        return -1;
    eligible_mask &= (uint8_t)((1U << SEND_LANE_COUNT) - 1U);
    if (eligible_mask == 0 || sched->in_flight)
        return -1;
    if (mode == SEND_MODE_ABORT)
        return sched->abort_remaining > 0 ? 0 : -1;
    if (!rate_gated(sched, mode) || sched->rate_bps == 0)
        return 0;
    send_scheduler_refill(sched, now_ms);
    if (sched->credit_milli > 0)
        return 0;
    need = 1 - sched->credit_milli;
    return need / sched->rate_bps + ((need % sched->rate_bps) != 0);
}
