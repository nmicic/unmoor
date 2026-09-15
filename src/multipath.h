/*
 * multipath.h — multipath fixed-resource endpoint-path policy
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * This module owns no sockets, ciphertext, replay window, or clock.  The
 * session supplies canonical receive authority only after its existing
 * pair -> AEAD -> replay -> HWM gate.  The table retains one negotiated
 * power-of-two set of transport-neutral UDP endpoint tokens and snapshots
 * immutable one- or two-copy send plans.
 */
#ifndef UNMOOR_MULTIPATH_H
#define UNMOOR_MULTIPATH_H

#include <stddef.h>
#include <stdint.h>

#include "path_leg.h"

#define MULTIPATH_PATHS_MIN 2U
#define MULTIPATH_PATHS_DEFAULT 8U
#define MULTIPATH_PATHS_MAX 32U
#define MULTIPATH_PLAN_COPIES_MAX 2U
#define MULTIPATH_NO_INDEX UINT8_MAX
#define MULTIPATH_CHALLENGE_RETRY_MS 500
#define MULTIPATH_RESPONSE_RETRY_MS 500
/* RFC 4787 REQ-5 requires ordinary NAT UDP mappings to live at least two
 * minutes and recommends five.  This shorter maintenance cadence targets
 * deployed 30--60 second mappings; it is a send-scheduler-subordinate eligibility
 * interval, not an unconditional transport-completion deadline. */
#define MULTIPATH_VALIDATED_KEEPALIVE_MS 25000

/* Stable public-state ceilings.  Increasing one requires a multipath resource
 * review; implementations remain allocation-free below these bounds. */
#define MULTIPATH_TOKEN_BYTES PATH_LEG_REMOTE_BYTES
#define MULTIPATH_HANDLE_BYTES 16U
#define MULTIPATH_PLAN_ITEM_BYTES 48U
#define MULTIPATH_PLAN_BYTES 104U
#define MULTIPATH_STATE_BYTES_MAX 3072U
#define MULTIPATH_SNAPSHOT_BYTES_MAX 3072U

/* Transport-neutral canonical endpoint identity.  `port` is host order.
 * IPv4 occupies address[0..3], requires address[4..15] and scope to be zero.
 * IPv6 occupies all 16 bytes.  IPv4-mapped IPv6 is rejected. */
typedef path_leg_remote_t multipath_token_t;

typedef enum {
    MULTIPATH_PATH_EMPTY = 0,
    MULTIPATH_PATH_CONFIGURED = 1,
    MULTIPATH_PATH_PROVISIONAL = 2,
    MULTIPATH_PATH_VALIDATED = 3
} multipath_path_state_t;

/* Explicit result of the session's receive-authority gate.  Only HWM may
 * mutate endpoint authority.  INVALID/REPLAY/STALE are observable no-ops. */
typedef enum {
    MULTIPATH_RX_INVALID = 0,
    MULTIPATH_RX_REPLAY = 1,
    MULTIPATH_RX_STALE = 2,
    MULTIPATH_RX_HWM = 3
} multipath_rx_authority_t;

enum {
    MULTIPATH_ERROR = -1,
    MULTIPATH_EXHAUSTED = -2,
    MULTIPATH_IGNORED = 0,
    MULTIPATH_ACCEPTED = 1
};

/* A handle names one entry generation.  It never retargets when the slot is
 * replaced.  Reserved bytes make malformed externally retained handles fail
 * closed. */
typedef struct {
    uint64_t generation;
    uint8_t index;
    uint8_t reserved[7];
} multipath_handle_t;

typedef struct {
    multipath_handle_t handle;
    multipath_token_t token;
} multipath_plan_item_t;

/* `slot_mask` is table-slot domain. `count` is 0..2 and item order is
 * primary, then one round-robin validated alternate for critical plans. */
typedef struct {
    uint32_t slot_mask;
    uint8_t count;
    uint8_t reserved[3];
    multipath_plan_item_t item[MULTIPATH_PLAN_COPIES_MAX];
} multipath_plan_t;

typedef struct {
    uint64_t hwm_accepted;
    uint64_t primary_changes;
    uint64_t configurations;
    uint64_t replacements;
    uint64_t validations;
    uint64_t challenges_created;
    uint64_t challenge_attempts;
    uint64_t challenge_retries;
    uint64_t responses_queued;
    uint64_t responses_completed;
    uint64_t ignored_invalid;
    uint64_t ignored_replay;
    uint64_t ignored_stale;
    uint64_t response_mismatches;
    uint64_t plan_generation_skips;
} multipath_counters_t;

typedef struct {
    multipath_token_t token;
    uint64_t generation;
    uint64_t challenge_id;
    int64_t challenge_due_ms;
    uint64_t response_id;
    int64_t response_due_ms;
    uint32_t challenge_attempts;
    uint8_t state;
    uint8_t challenge_pending;
    uint8_t response_pending;
    uint8_t challenge_sent;     /* exact id had physical COMPLETE */
    uint8_t challenge_maintenance; /* armed while already VALIDATED */
} multipath_entry_t;

typedef struct {
    multipath_entry_t entry[MULTIPATH_PATHS_MAX];
    multipath_counters_t counters;
    uint64_t generation_counter;
    uint64_t challenge_counter;
    uint8_t primary_index;
    uint8_t path_limit;
    uint8_t alternate_cursor;
    uint8_t reserved[5];
} multipath_t;

typedef struct {
    multipath_entry_t entry[MULTIPATH_PATHS_MAX];
    multipath_counters_t counters;
    uint64_t generation_counter;
    uint64_t challenge_counter;
    uint32_t occupied_mask;
    uint32_t configured_mask;
    uint32_t provisional_mask;
    uint32_t validated_mask;
    uint32_t primary_mask;
    uint8_t primary_index;
    uint8_t path_limit;
    uint8_t path_count;
    uint8_t validated_count;
    uint8_t alternate_cursor;
    uint8_t reserved[3];
} multipath_snapshot_t;

int multipath_path_count_valid(unsigned int path_count);
uint32_t multipath_low_mask(unsigned int path_count);

/* Construct and validate canonical tokens without including socket headers. */
int multipath_token_init(multipath_token_t *token, uint8_t local_leg,
                         uint8_t family, uint16_t host_port,
                         uint32_t ipv6_scope, const uint8_t *address,
                         size_t address_length);
int multipath_token_valid(const multipath_token_t *token);
int multipath_token_equal(const multipath_token_t *a,
                          const multipath_token_t *b);

/* Full authenticated-session lifetime.  Epoch-rekey traffic-epoch adoption calls
 * the const no-op hook; only reset erases path authority and counters. */
int multipath_init(multipath_t *paths, unsigned int path_count);
void multipath_reset(multipath_t *paths);
int multipath_traffic_epoch_adopt(const multipath_t *paths);

/* Install the one bootstrap return path after authenticated negotiation has
 * bound it outside this pure engine.  This is not an HWM observation and
 * therefore does not increment receive-authority counters. */
int multipath_bootstrap_primary(multipath_t *paths,
                                const multipath_token_t *token,
                                int64_t now_ms,
                                multipath_handle_t *handle_out);

/* Configure one local path. Empty slots are filled before the deterministic
 * unvalidated-first, then oldest-within-class nonprimary replacement rule.
 * The path is CONFIGURED and an
 * immediately due, nonzero local challenge is created. Existing identical
 * entries are idempotent and retain their authority. */
int multipath_configure_alternate(multipath_t *paths,
                                  const multipath_token_t *token,
                                  int64_t now_ms,
                                  multipath_handle_t *handle_out);

/* bulk-transfer local-socket incarnation replacement. Unlike ordinary endpoint-token
 * configuration, the same token intentionally receives a fresh exact slot
 * generation and challenge. The retained handle must still name a VALIDATED
 * non-primary slot; every other entry and primary stay byte-identical. */
int multipath_reconfigure_local_slot(multipath_t *paths,
                                     const multipath_handle_t *target,
                                     int64_t now_ms,
                                     multipath_handle_t *handle_out);

/* bulk-transfer block/cube local-socket incarnation replacement.  `expected` must be
 * the exact full, fully validated table snapshot retained before the shadow
 * sockets were bound.  Success replaces every occupied slot with the same
 * endpoint token under fresh generations/challenges.  The retained physical
 * primary stays PROVISIONAL so roaming-freshest-path multipath and transport authority remain
 * aligned; every other slot becomes CONFIGURED.  Bulk DATA eligibility is a
 * separate caller-owned freeze until the entire fresh cohort validates.
 * The operation is all-or-none; stale state and counter exhaustion leave the
 * table byte-identical. */
int multipath_reconfigure_local_set(
    multipath_t *paths, const multipath_snapshot_t *expected,
    int64_t now_ms, multipath_handle_t handles_out[MULTIPATH_PATHS_MAX]);

/* Ordinary receive observation. Only HWM adopts/promotes a PROVISIONAL
 * primary. A fresh source fills an empty slot or replaces an unvalidated
 * non-primary first, otherwise the oldest validated non-primary, retaining
 * the previous primary. */
int multipath_observe(multipath_t *paths,
                      const multipath_token_t *ingress,
                      multipath_rx_authority_t authority,
                      int64_t now_ms,
                      multipath_handle_t *handle_out,
                      int *primary_changed_out);

/* Canonical multipath control policy after body parsing.  A challenge is queued
 * for response on its exact ingress and also starts local validation there.
 * A response validates only an existing exact path with the matching local
 * challenge id.  Wrong id/path and non-HWM traffic cannot adopt a path. */
int multipath_receive_challenge(multipath_t *paths,
                                const multipath_token_t *ingress,
                                multipath_rx_authority_t authority,
                                uint64_t challenge_id, int64_t now_ms,
                                multipath_handle_t *handle_out,
                                int *primary_changed_out);
int multipath_receive_response(multipath_t *paths,
                               const multipath_token_t *ingress,
                               multipath_rx_authority_t authority,
                               uint64_t challenge_id,
                               multipath_handle_t *handle_out,
                               int *primary_changed_out);

/* Local validation owner.  A newly created challenge is due immediately.
 * A terminal transport attempt schedules the same id 500 ms later; a
 * WOULD_BLOCK attempt must not call `multipath_challenge_attempted`.
 * `completed` is exactly the logical target-path transport result. Only a
 * physical COMPLETE marks the id as sent and permits its response to
 * validate reachability; a hard failure advances cadence without authority. */
int multipath_challenge_due(const multipath_t *paths,
                            const multipath_handle_t *target,
                            int64_t now_ms, uint64_t *challenge_id_out);
int multipath_challenge_attempted(multipath_t *paths,
                                  const multipath_handle_t *target,
                                  uint64_t challenge_id, int64_t now_ms,
                                  int completed);

/* Arm one client-owned validated-leg maintenance challenge.  This consumes a
 * fresh id but changes no token, generation, validation or primary authority.
 * Existing/non-validated/stale owners are exact no-ops. */
int multipath_validated_keepalive_arm(multipath_t *paths,
                                      const multipath_handle_t *target,
                                      int64_t now_ms,
                                      uint64_t *challenge_id_out);

/* One exact peer response owner per entry.  A fresh authenticated challenge
 * makes it due immediately.  A terminal hard failure retains the same id at
 * an injected-clock 500 ms floor; WOULD_BLOCK retains the immutable frame and
 * calls neither result hook.  Only exact transport COMPLETE clears it. */
int multipath_response_pending(const multipath_t *paths,
                               const multipath_handle_t *target,
                               uint64_t *challenge_id_out);
int multipath_response_due(const multipath_t *paths,
                           const multipath_handle_t *target,
                           int64_t now_ms, uint64_t *challenge_id_out);
int multipath_response_attempted(multipath_t *paths,
                                 const multipath_handle_t *target,
                                 uint64_t challenge_id, int64_t now_ms,
                                 int completed);

/* Immutable physical-plan snapshots.  `resolve` returns 0 (skip) when a
 * retained slot generation was reset/replaced, never a replacement token. */
int multipath_plan_primary(const multipath_t *paths,
                           multipath_plan_t *plan_out);
int multipath_plan_critical(multipath_t *paths,
                            multipath_plan_t *plan_out);
int multipath_plan_target(const multipath_t *paths,
                          const multipath_token_t *target,
                          multipath_plan_t *plan_out);
int multipath_plan_resolve(multipath_t *paths,
                           const multipath_plan_t *plan, size_t ordinal,
                           multipath_token_t *token_out);

int multipath_get_snapshot(const multipath_t *paths,
                           multipath_snapshot_t *snapshot_out);

/* Export the multipath-owned fields of one slot into the common leg snapshot.
 * Local interface/port, keepalive, and bulk-transfer counters remain zero for their
 * owning layers to populate. Empty slots return MULTIPATH_IGNORED with a
 * fully zero output. */
int multipath_describe_leg(const multipath_t *paths, unsigned int index,
                           path_leg_t *leg_out);

#endif /* UNMOOR_MULTIPATH_H */
