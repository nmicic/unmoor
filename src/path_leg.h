/*
 * path_leg.h — transport-neutral first-class endpoint-leg snapshot
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * A leg is a composed local observation, not a second authority table.
 * multipath owns remote identity, validation, and incarnation; the transport owns
 * the local socket/port; bulk-transfer owns transfer counters.  The session joins those
 * existing facts here so operator observations, later interface binding, NAT
 * candidates, relays, and per-leg keepalives have one seam without changing
 * today's wire or path-selection policy.
 */
#ifndef UNMOOR_PATH_LEG_H
#define UNMOOR_PATH_LEG_H

#include <stddef.h>
#include <stdint.h>

#define PATH_LEG_REMOTE_BYTES 32U
#define PATH_LEG_BYTES 256U

/* Transport-neutral canonical remote endpoint. `port` is host order.
 * `local_leg` is the local physical socket index on which this remote is
 * reached; it is transport state, never an application-delivery bitmap. */
typedef struct {
    uint8_t local_leg;
    uint8_t family;                 /* exactly 4 or 6 when populated */
    uint16_t port;
    uint32_t scope;
    uint8_t address[16];
    uint8_t reserved[8];
} path_leg_remote_t;

typedef enum {
    PATH_LEG_VALIDATION_EMPTY = 0,
    PATH_LEG_VALIDATION_CONFIGURED = 1,
    PATH_LEG_VALIDATION_PROVISIONAL = 2,
    PATH_LEG_VALIDATION_VALIDATED = 3
} path_leg_validation_t;

typedef enum {
    PATH_LEG_ENVELOPE_NONE = 0,
    PATH_LEG_ENVELOPE_DIRECT = 1
} path_leg_envelope_t;

/* This is the existing bulk-transfer per-sender-slot accounting, lifted unchanged so
 * path users do not grow parallel counter families. */
typedef struct {
    uint64_t sent_chunks;
    uint64_t acked_chunks;
    uint64_t timeout_loss;
    uint64_t sent_bytes;
    uint64_t acked_bytes;
    uint64_t retransmits;
    uint64_t share_reductions;
    uint64_t share_recoveries;
    uint64_t reroll_requests;
    uint64_t reroll_attempts;
    uint64_t rerolls;
    uint64_t reroll_exhaustions;
    uint64_t mtu_failures;
} path_leg_counters_t;

/* Operator-only observations. These fields never cross the wire and never
 * participate in validation, scheduling, replay, or delivery authority.
 * RTT uses x8 fixed point so alpha=1/8 and mean-deviation beta=1/4 are exact
 * shifts. A repeated successful handoff of one challenge makes the sample
 * ambiguous (Karn's rule) and therefore ineligible for the estimator. */
typedef struct {
    uint64_t rtt_min_ms;
    uint64_t rtt_smoothed_x8;
    uint64_t rtt_mdev_x8;
    uint64_t rtt_samples;
    uint64_t challenge_id;
    uint64_t challenge_generation;
    int64_t challenge_sent_ms;
    uint64_t delivered_total_observed;
    uint64_t delivered_interval_bytes;
    int64_t delivered_interval_start_ms;
    /* Status intervals are bounded product constants, not wire durations.
     * Keeping the observation at 88 bytes leaves the fixed 256-byte leg room
     * for the transport-owned local address family. */
    uint32_t delivered_interval_ms;
    uint8_t challenge_pending;
    uint8_t challenge_ambiguous;
    uint8_t delivered_initialized;
    uint8_t reserved;
} path_leg_observation_t;

typedef struct {
    uint64_t rtt_min_ms;
    uint64_t rtt_smoothed_ms;
    uint64_t rtt_mdev_ms;
    uint64_t rtt_samples;
    uint64_t loss_timeouts;
    uint64_t loss_attempts;
    uint64_t delivered_interval_bytes;
    uint64_t delivered_interval_ms;
    uint32_t keepalive_tx;
    uint8_t rtt_valid;
    uint8_t reserved[3];
} path_leg_metrics_t;

typedef struct {
    path_leg_remote_t remote;
    path_leg_counters_t counters;
    /* multipath's nonwrapping slot/incarnation generation. It changes whenever
     * an endpoint/socket binding is replaced and is the generation bulk-transfer
     * already pins into outstanding work. Zero means no active binding. */
    uint64_t fd_generation;
    /* Reserved for a future per-leg keepalive. Zero means none has been
     * scheduled or observed; nothing in this revision arms a leg timer. */
    int64_t keepalive_at_ms;
    /* Portable interface index; zero means no explicit interface binding. */
    uint32_t local_interface;
    uint16_t local_port;            /* host order; zero means not observed */
    uint8_t validation;             /* path_leg_validation_t */
    uint8_t envelope;               /* only DIRECT is implemented */
    path_leg_observation_t observation;
    /* Actual physical local socket family, independently observed from the
     * transport. Zero is unknown; otherwise exactly 4 or 6. This is not path
     * authority and need not equal a future relay envelope's remote family. */
    uint32_t keepalive_tx;          /* saturating periodic COMPLETE count */
    uint8_t local_family;
    uint8_t reserved[3];
} path_leg_t;

/* Pure injected-clock observation helpers. Accepted responses return one,
 * ignored/stale identities return zero, and malformed inputs return -1. */
int path_leg_challenge_attempt(path_leg_t *leg, uint64_t generation,
                               uint64_t challenge_id, int64_t now_ms,
                               int completed);
int path_leg_challenge_response(path_leg_t *leg, uint64_t generation,
                                uint64_t challenge_id, int64_t now_ms);
int path_leg_keepalive_complete(path_leg_t *leg, uint64_t generation,
                                int64_t now_ms, int64_t interval_ms);
int path_leg_counters_observe(path_leg_t *leg,
                              const path_leg_counters_t *counters,
                              int64_t now_ms, int64_t interval_ms);
void path_leg_metrics_snapshot(const path_leg_t *leg,
                               path_leg_metrics_t *metrics_out);
int path_leg_format_metrics(const path_leg_metrics_t *metrics,
                            char *out, size_t out_len);

#endif /* UNMOOR_PATH_LEG_H */
