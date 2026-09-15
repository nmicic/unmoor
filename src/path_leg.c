/*
 * path_leg.c — operator-only endpoint-leg observations
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */

#include "path_leg.h"

#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

_Static_assert(sizeof(path_leg_remote_t) == PATH_LEG_REMOTE_BYTES,
               "path-leg remote layout drift");
_Static_assert(sizeof(path_leg_t) == PATH_LEG_BYTES,
               "path-leg value layout drift");

static uint64_t add_saturating(uint64_t a, uint64_t b)
{
    return UINT64_MAX - a < b ? UINT64_MAX : a + b;
}

static uint64_t shift_left_three_saturating(uint64_t value)
{
    return value > (UINT64_MAX >> 3) ? UINT64_MAX : value << 3;
}

static uint64_t rounded_x8(uint64_t value)
{
    uint64_t whole = value >> 3;

    if ((value & UINT64_C(7)) >= UINT64_C(4) && whole != UINT64_MAX)
        whole++;
    return whole;
}

int path_leg_challenge_attempt(path_leg_t *leg, uint64_t generation,
                               uint64_t challenge_id, int64_t now_ms,
                               int completed)
{
    path_leg_observation_t *observation;

    if (leg == NULL || generation == 0U || challenge_id == 0U ||
        now_ms < 0 || (completed != 0 && completed != 1))
        return -1;
    if (leg->fd_generation != generation || !completed)
        return 0;
    observation = &leg->observation;
    if (observation->challenge_pending &&
        observation->challenge_generation == generation &&
        observation->challenge_id == challenge_id) {
        /* A response can now correspond to either physical handoff. */
        observation->challenge_ambiguous = 1U;
        return 1;
    }
    observation->challenge_generation = generation;
    observation->challenge_id = challenge_id;
    observation->challenge_sent_ms = now_ms;
    observation->challenge_pending = 1U;
    observation->challenge_ambiguous = 0U;
    return 1;
}

int path_leg_challenge_response(path_leg_t *leg, uint64_t generation,
                                uint64_t challenge_id, int64_t now_ms)
{
    path_leg_observation_t *observation;
    uint64_t sample_ms;
    uint64_t sample_x8;
    int ambiguous;
    int64_t sent_ms;

    if (leg == NULL || generation == 0U || challenge_id == 0U ||
        now_ms < 0)
        return -1;
    observation = &leg->observation;
    if (leg->fd_generation != generation ||
        !observation->challenge_pending ||
        observation->challenge_generation != generation ||
        observation->challenge_id != challenge_id)
        return 0;

    ambiguous = observation->challenge_ambiguous != 0U;
    sent_ms = observation->challenge_sent_ms;
    observation->challenge_generation = 0U;
    observation->challenge_id = 0U;
    observation->challenge_sent_ms = 0;
    observation->challenge_pending = 0U;
    observation->challenge_ambiguous = 0U;
    if (ambiguous || now_ms < sent_ms)
        return 0;

    sample_ms = (uint64_t)(now_ms - sent_ms);
    sample_x8 = shift_left_three_saturating(sample_ms);
    if (observation->rtt_samples == 0U) {
        observation->rtt_min_ms = sample_ms;
        observation->rtt_smoothed_x8 = sample_x8;
        observation->rtt_mdev_x8 = 0U;
    } else {
        uint64_t old_smoothed = observation->rtt_smoothed_x8;
        uint64_t error = sample_x8 >= old_smoothed
            ? sample_x8 - old_smoothed : old_smoothed - sample_x8;

        if (sample_ms < observation->rtt_min_ms)
            observation->rtt_min_ms = sample_ms;
        if (sample_x8 >= old_smoothed)
            observation->rtt_smoothed_x8 = add_saturating(
                old_smoothed, (sample_x8 - old_smoothed) >> 3);
        else
            observation->rtt_smoothed_x8 =
                old_smoothed - ((old_smoothed - sample_x8) >> 3);
        if (error >= observation->rtt_mdev_x8)
            observation->rtt_mdev_x8 = add_saturating(
                observation->rtt_mdev_x8,
                (error - observation->rtt_mdev_x8) >> 2);
        else
            observation->rtt_mdev_x8 -=
                (observation->rtt_mdev_x8 - error) >> 2;
    }
    if (observation->rtt_samples != UINT64_MAX)
        observation->rtt_samples++;
    return 1;
}

int path_leg_keepalive_complete(path_leg_t *leg, uint64_t generation,
                                int64_t now_ms, int64_t interval_ms)
{
    if (leg == NULL || generation == 0U || now_ms < 0 || interval_ms <= 0 ||
        now_ms > INT64_MAX - interval_ms)
        return -1;
    if (leg->fd_generation != generation)
        return 0;
    if (leg->keepalive_tx != UINT32_MAX)
        leg->keepalive_tx++;
    leg->keepalive_at_ms = now_ms + interval_ms;
    return 1;
}

int path_leg_counters_observe(path_leg_t *leg,
                              const path_leg_counters_t *counters,
                              int64_t now_ms, int64_t interval_ms)
{
    path_leg_counters_t next;
    path_leg_observation_t *observation;
    uint64_t delivered;

    if (leg == NULL || counters == NULL || now_ms < 0 || interval_ms <= 0 ||
        (uint64_t)interval_ms > UINT32_MAX)
        return -1;
    next = *counters;
    observation = &leg->observation;
    /* This consumes an absolute counter snapshot, not a timer event. Service
     * activation or a nested observer may have sampled monotonic time after
     * its enclosing scheduler did. Normalize every earlier enclosing sample
     * to the observation's monotonic maximum before either an ordinary delta
     * or a counter/interval reset, exactly like bulk_engine_update_paths();
     * operator-only telemetry must never make path eligibility fail or move
     * an interval boundary backward. */
    if (observation->delivered_initialized &&
        now_ms < observation->delivered_interval_start_ms)
        now_ms = observation->delivered_interval_start_ms;
    delivered = next.acked_bytes;
    if (!observation->delivered_initialized ||
        observation->delivered_interval_ms != (uint64_t)interval_ms ||
        delivered < observation->delivered_total_observed) {
        observation->delivered_total_observed = delivered;
        observation->delivered_interval_bytes = 0U;
        observation->delivered_interval_start_ms = now_ms;
        observation->delivered_interval_ms = (uint32_t)interval_ms;
        observation->delivered_initialized = 1U;
        leg->counters = next;
        return 0;
    }
    if (now_ms - observation->delivered_interval_start_ms >= interval_ms) {
        int64_t elapsed = now_ms -
                          observation->delivered_interval_start_ms;
        int64_t periods = elapsed / interval_ms;

        observation->delivered_interval_start_ms += periods * interval_ms;
        observation->delivered_interval_bytes = 0U;
    }
    observation->delivered_interval_bytes = add_saturating(
        observation->delivered_interval_bytes,
        delivered - observation->delivered_total_observed);
    observation->delivered_total_observed = delivered;
    leg->counters = next;
    return 0;
}

void path_leg_metrics_snapshot(const path_leg_t *leg,
                               path_leg_metrics_t *metrics_out)
{
    if (metrics_out == NULL)
        return;
    memset(metrics_out, 0, sizeof(*metrics_out));
    if (leg == NULL)
        return;
    metrics_out->rtt_valid = leg->observation.rtt_samples != 0U;
    metrics_out->rtt_min_ms = leg->observation.rtt_min_ms;
    metrics_out->rtt_smoothed_ms = rounded_x8(
        leg->observation.rtt_smoothed_x8);
    metrics_out->rtt_mdev_ms = rounded_x8(
        leg->observation.rtt_mdev_x8);
    metrics_out->rtt_samples = leg->observation.rtt_samples;
    metrics_out->loss_timeouts = leg->counters.timeout_loss;
    metrics_out->loss_attempts = leg->counters.sent_chunks;
    metrics_out->delivered_interval_bytes =
        leg->observation.delivered_interval_bytes;
    metrics_out->delivered_interval_ms =
        leg->observation.delivered_interval_ms;
    metrics_out->keepalive_tx = leg->keepalive_tx;
}

int path_leg_format_metrics(const path_leg_metrics_t *metrics,
                            char *out, size_t out_len)
{
    int result;

    if (metrics == NULL || out == NULL || out_len == 0U)
        return -1;
    if (metrics->rtt_valid) {
        result = snprintf(
            out, out_len,
            "rtt-ms=%" PRIu64 "/%" PRIu64 "/%" PRIu64
            " loss=%" PRIu64 "/%" PRIu64
            " delivered=%" PRIu64 "/%" PRIu64 "ms"
            " keepalive-tx=%" PRIu32,
            metrics->rtt_min_ms, metrics->rtt_smoothed_ms,
            metrics->rtt_mdev_ms, metrics->loss_timeouts,
            metrics->loss_attempts, metrics->delivered_interval_bytes,
            metrics->delivered_interval_ms, metrics->keepalive_tx);
    } else {
        result = snprintf(
            out, out_len,
            "rtt-ms=unknown loss=%" PRIu64 "/%" PRIu64
            " delivered=%" PRIu64 "/%" PRIu64 "ms"
            " keepalive-tx=%" PRIu32,
            metrics->loss_timeouts, metrics->loss_attempts,
            metrics->delivered_interval_bytes,
            metrics->delivered_interval_ms, metrics->keepalive_tx);
    }
    return result < 0 || (size_t)result >= out_len ? -1 : 0;
}
