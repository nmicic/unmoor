/*
 * bulk_engine.h — bulk-transfer portable transfer and path-share state engine
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * The engine owns bounded logical/file state only.  It does not allocate a
 * sequence number, encrypt a frame, choose a path, or perform a UDP send.
 * send-scheduler grants one lane, bulk_engine_materialize() freezes one canonical
 * plaintext, and bulk_engine_transport_result() advances timers/state only
 * after the transport reports a terminal result.
 */
#ifndef UNMOOR_BULK_ENGINE_H
#define UNMOOR_BULK_ENGINE_H

#define _POSIX_C_SOURCE 200809L

#include <stddef.h>
#include <stdint.h>

#include "bulk.h"
#include "path_leg.h"
#include "send_scheduler.h"

#define BULK_ENGINE_REPEAT_MS          INT64_C(500)
#define BULK_ENGINE_DATA_TIMEOUT_MS   INT64_C(2000)
#define BULK_ENGINE_STALL_DEFAULT_MS INT64_C(30000)
#define BULK_ENGINE_STALL_MIN_MS      INT64_C(1000)
#define BULK_ENGINE_STALL_MAX_MS    INT64_C(300000)
#define BULK_ENGINE_LINGER_MS         INT64_C(10000)
#define BULK_ENGINE_SEND_RETRY_MIN_MS    INT64_C(16)
#define BULK_ENGINE_SEND_RETRY_MAX_MS  INT64_C(1024)
#define BULK_ENGINE_SHARE_INTERVAL_MS   INT64_C(500)
#define BULK_ENGINE_SHARE_SHIFT_MAX                 3U
#define BULK_ENGINE_REROLL_WAIT_INTERVALS            4U
#define BULK_ENGINE_REROLL_ATTEMPTS_MAX               4U
#define BULK_ENGINE_REROLL_QUIET_MS \
    BULK_ENGINE_DATA_TIMEOUT_MS
#define BULK_ENGINE_REROLL_WITNESS_MS \
    (INT64_C(2) * BULK_ENGINE_REROLL_WAIT_INTERVALS * \
     BULK_ENGINE_SHARE_INTERVAL_MS)
/* A different path becoming live first is not yet proof that a still-due
 * original tuple is dead. Give that tuple one complete DATA timeout to return
 * its own ACK and cancel the stale request before a replacement may bind. */
#define BULK_ENGINE_REROLL_RECOVERY_GRACE_MS \
    BULK_ENGINE_DATA_TIMEOUT_MS
#define BULK_ENGINE_NO_LEG                         UINT8_MAX
#define BULK_ENGINE_SCAN_QUANTUM      (UINT64_C(1) << 20)
#define BULK_ENGINE_SCAN_REPORT_MS     INT64_C(5000)
#define BULK_ENGINE_TX_BUFFER_BYTES            16384U
#define BULK_ENGINE_OUTSTANDING_PER_LEG           256U
#define BULK_ENGINE_OUTSTANDING_ENTRIES \
    (BULK_LEGS_MAX * BULK_ENGINE_OUTSTANDING_PER_LEG)
#define BULK_ENGINE_ACTIVE_INDEX_ENTRIES \
    (BULK_ENGINE_OUTSTANDING_ENTRIES * 2U)
#define BULK_ENGINE_RECOVERY_SCAN_WORDS             64U
#define BULK_ENGINE_PATH_STATE_BYTES              2048U
#define BULK_ENGINE_STATS_STORAGE_BYTES           4096U
#define BULK_ENGINE_PORTABLE_FIXED_BYTES \
    (BULK_BITMAP_BYTES + (BULK_ACK_PAGES / 8U) + \
     (BULK_ENGINE_OUTSTANDING_ENTRIES * 64U) + \
     (BULK_ENGINE_ACTIVE_INDEX_ENTRIES * sizeof(uint16_t)) + \
     (BULK_LEGS_MAX * 4U * sizeof(uint64_t)) + BULK_CHUNK_MAX + \
     BULK_PATH_SCRATCH_BYTES + BULK_ENGINE_PATH_STATE_BYTES + \
     BULK_ENGINE_STATS_STORAGE_BYTES + \
     (2U * BULK_ENGINE_TX_BUFFER_BYTES))
#define BULK_ENGINE_PORTABLE_LIMIT_BYTES \
    ((11U * 1024U * 1024U) / 4U)

typedef enum {
    BULK_ENGINE_ENDPOINT_CLIENT = 1,
    BULK_ENGINE_ENDPOINT_SERVER = 2
} bulk_engine_endpoint_t;

/* Server-only one-shot policy boundary. The engine calls this after a valid
 * authenticated REQUEST is bound and before it opens either source or sink.
 * A nonzero result becomes the existing typed source/destination refusal. */
typedef int (*bulk_engine_path_policy_fn)(
    void *arg, bulk_operation_t operation,
    const uint8_t *path, size_t path_length);

typedef enum {
    BULK_ENGINE_RESULT_RUNNING = 0,
    BULK_ENGINE_RESULT_SUCCESS = 1,
    BULK_ENGINE_RESULT_FAILED = 2
} bulk_engine_result_t;

typedef enum {
    BULK_ENGINE_RX_OK = 0,
    BULK_ENGINE_RX_PROGRESS = 1,
    BULK_ENGINE_RX_DUPLICATE = 2,
    BULK_ENGINE_RX_STALE = 3,
    /* Authenticated PUT MANIFEST/PREPARING may beat its repeated REQUEST.
     * It is ignored without binding identity or mutating file state. */
    BULK_ENGINE_RX_NOT_READY = 4,
    BULK_ENGINE_RX_FATAL = -1
} bulk_engine_receive_result_t;

typedef struct {
    bulk_engine_endpoint_t endpoint;

    /* Client-only request identity.  Server activation leaves operation and
     * transfer_id zero until an authenticated REQUEST arrives. */
    bulk_operation_t operation;
    uint64_t transfer_id;
    uint16_t wire_budget;
    int64_t pace_bps;       /* zero is test-harness-safety characterization */
    int64_t stall_ms;       /* zero selects 30 seconds */
    uint8_t force;
    /* Exact sender-local bulk-transfer leg count.  Zero is the compatibility spelling
     * for one path; otherwise only 1/2/4/8/16/32 is accepted. */
    uint8_t path_count;

    /* Server only. Both fields are copied at activation; NULL preserves the
     * pre-server-confinement path behavior byte-for-byte. */
    bulk_engine_path_policy_fn path_policy;
    void *path_policy_arg;

    /* Client local source (PUT) or destination (GET).  The remote path is
     * copied into encrypted REQUEST and never enters an SSH command. */
    const uint8_t *local_path;
    size_t local_path_length;
    const uint8_t *remote_path;
    size_t remote_path_length;
} bulk_engine_config_t;

typedef path_leg_counters_t bulk_engine_leg_stats_t;

typedef struct {
    uint8_t type;
    send_lane_t lane;
    const uint8_t *plaintext;
    size_t plaintext_length;
} bulk_engine_tx_view_t;

typedef struct {
    uint8_t valid;
    uint8_t sender_leg;
    send_lane_t lane;
    uint32_t chunk_index;
    uint32_t attempt_id;
    uint16_t body_length;
} bulk_engine_attempt_view_t;

typedef struct {
    uint64_t request_attempts;
    uint64_t manifest_attempts;
    uint64_t ack_attempts;
    uint64_t status_attempts;
    uint64_t data_attempts;
    uint64_t data_bytes;
    uint64_t data_retransmits;
    uint64_t timeout_loss;
    uint64_t first_admission_chunks;
    uint64_t first_admission_bytes;
    uint64_t duplicate_chunks;
    uint64_t epoch_pauses;
    uint64_t epoch_resumes;
    uint64_t path_pauses;
    uint64_t path_resumes;
    bulk_engine_leg_stats_t leg[BULK_LEGS_MAX];
} bulk_engine_stats_t;

/* Sender-local scheduling state only.  None of these masks is semantic file
 * truth or replay authority; the global chunk bitmap remains authoritative. */
typedef struct {
    uint32_t eligible_mask;
    uint32_t d32_eligible_mask;
    uint32_t mtu_usable_mask;
    uint32_t reroll_due_mask;
    uint32_t reroll_exhausted_mask;
    uint32_t reroll_claimed_mask;
    uint64_t set_reroll_generation;
    int64_t set_reroll_quiet_ms;
    int64_t reroll_session_quiet_ms;
    uint64_t generation[BULK_LEGS_MAX];
    int64_t share_next_ms[BULK_LEGS_MAX];
    int64_t reroll_defer_ms[BULK_LEGS_MAX];
    int64_t reroll_quiet_ms[BULK_LEGS_MAX];
    int64_t reroll_witness_deadline_ms[BULK_LEGS_MAX];
    uint16_t outstanding[BULK_LEGS_MAX];
    uint8_t share_shift[BULK_LEGS_MAX];
    uint8_t reroll_attempts[BULK_LEGS_MAX];
    uint8_t set_reroll_attempts;
    uint8_t set_reroll_claimed;
    uint8_t set_reroll_trigger_leg;
    uint8_t set_reroll_exhausted;
    uint8_t path_count;
    uint8_t primary_leg;
    uint8_t path_paused;
} bulk_engine_path_snapshot_t;

typedef struct {
    uint64_t transfer_id;
    uint64_t file_size;
    uint64_t processed_bytes;
    uint64_t represented_bytes;
    uint32_t chunk_count;
    uint32_t frontier;
    uint32_t represented_chunks;
    uint8_t local_phase;
    uint8_t manifest_bound;
    uint8_t installed;
    uint8_t paused;
    uint8_t path_paused;
    bulk_engine_result_t result;
    bulk_result_code_t result_code;
} bulk_engine_observation_t;

typedef struct bulk_engine bulk_engine_t;

/* The small owner object is separate from activation.  All bulk-transfer bitmap,
 * window, scratch and frame storage is allocated once by activate(). */
int bulk_engine_create(bulk_engine_t **engine_out);
int bulk_engine_activate(bulk_engine_t *engine,
                         const bulk_engine_config_t *config,
                         int64_t now_ms);
void bulk_engine_destroy(bulk_engine_t *engine);

/* Drive one bounded unit of local scanning plus timer transitions. */
int bulk_engine_tick(bulk_engine_t *engine, int64_t now_ms);
int64_t bulk_engine_next_deadline(bulk_engine_t *engine,
                                  int64_t now_ms);

/* Refresh the sender-local multipath eligibility view.  The mask contains the
 * current primary plus validated alternates and is an absolute replacement.
 * An already materialized DATA attempt retains its immutable sender leg. */
int bulk_engine_update_paths(bulk_engine_t *engine,
                             uint32_t eligible_mask,
                             uint8_t primary_leg,
                             const uint64_t generation[BULK_LEGS_MAX],
                             int64_t now_ms);
/* Composed leg-snapshot entry point used by the product session. It derives the exact
 * multipath eligibility/generation arguments above from one common leg snapshot;
 * the older scalar entry point remains for narrow engine fixtures. */
int bulk_engine_update_legs(bulk_engine_t *engine,
                            const path_leg_t legs[BULK_LEGS_MAX],
                            uint8_t leg_count, uint8_t primary_leg,
                            int64_t now_ms);
/* Overlay the existing bulk-transfer counters without changing any identity/timer
 * field already populated by multipath or the transport. */
int bulk_engine_copy_leg_counters(const bulk_engine_t *engine,
                                  path_leg_t legs[BULK_LEGS_MAX],
                                  uint8_t leg_count);
int bulk_engine_path_snapshot(const bulk_engine_t *engine,
                              bulk_engine_path_snapshot_t *snapshot);

typedef enum {
    BULK_ENGINE_REROLL_ERROR = -1,
    BULK_ENGINE_REROLL_NOT_DUE = 0,
    BULK_ENGINE_REROLL_CLAIMED = 1,
    BULK_ENGINE_REROLL_EXHAUSTED = 2
} bulk_engine_reroll_result_t;

/* Random-layout transport choreography. sender_leg is the source multipath table
 * slot and physical_leg is token.local_leg. A physical attempt is claimed
 * before bind, remains charged on later abort, and is finished synchronously.
 * A claim additionally needs a different source slot's post-due ACK witness
 * and the common session quiet deadline. Deferral charges nothing; explicit
 * exhaustion is scoped to sender generation while the physical-leg attempt
 * quota and common quiet survive generations and epochs. */
bulk_engine_reroll_result_t bulk_engine_reroll_claim(
    bulk_engine_t *engine, uint8_t sender_leg, uint8_t physical_leg,
    uint64_t generation, int64_t now_ms);
int bulk_engine_reroll_finish(bulk_engine_t *engine, uint8_t sender_leg,
                              uint8_t physical_leg, uint64_t generation,
                              int succeeded, int64_t now_ms);
int bulk_engine_reroll_defer(bulk_engine_t *engine, uint8_t sender_leg,
                             uint64_t generation, int64_t now_ms);
int bulk_engine_reroll_exhaust(bulk_engine_t *engine,
                               uint8_t sender_leg,
                               uint64_t generation,
                               int64_t now_ms);

/* send-scheduler producer seam.  eligible_mask() returns SEND_LANE_BIT values.
 * materialize() is legal only for a lane already granted by send-scheduler and freezes
 * its logical identity until COMPLETE/FAILED. */
uint8_t bulk_engine_eligible_mask(bulk_engine_t *engine, int64_t now_ms);
int bulk_engine_materialize(bulk_engine_t *engine, send_lane_t lane,
                            int64_t now_ms, uint8_t *plaintext_out,
                            size_t plaintext_capacity,
                            bulk_engine_tx_view_t *view);
int bulk_engine_transport_result(bulk_engine_t *engine,
                                 send_step_result_t result,
                                 int64_t now_ms);
/* A hard datagram-send failure retains the current logical record. The
 * caller retains its encoded ciphertext/SEQ and retries only once
 * transport_retry_wait() reaches zero. Delays double from 16 through
 * 1024 ms and remain capped there; WOULD_BLOCK is not reported here. */
int bulk_engine_transport_retryable_failure(bulk_engine_t *engine,
                                            int64_t now_ms);
int64_t bulk_engine_transport_retry_wait(const bulk_engine_t *engine,
                                         int64_t now_ms);
/* Called immediately before FAILED when a retained bulk-transfer send returned
 * EMSGSIZE.  `sender_leg` is the source-local multipath table slot selected by
 * the immutable path plan.  It suppresses only that generation; multipath path
 * validation and authority remain untouched. */
int bulk_engine_transport_mtu_failure(bulk_engine_t *engine,
                                      uint8_t sender_leg,
                                      int64_t now_ms);

/* Input has already passed pair routing, AEAD, global replay and HWM. */
bulk_engine_receive_result_t bulk_engine_receive(
    bulk_engine_t *engine, uint8_t type,
    const uint8_t *plaintext, size_t plaintext_length, int64_t now_ms);

/* Mutation-free epoch-rekey WAIT_ACK gate for an already activated engine.  It
 * checks canonical decoding plus the current transfer's direction, identity
 * and state grammar, but performs no file I/O, allocation, merge, or phase
 * transition.  A server whose bulk engine is intentionally activated only
 * after epoch adoption must separately use the REQUEST codec at the session
 * boundary; there is no engine state to consult before activation. */
int bulk_engine_prevalidate(const bulk_engine_t *engine, uint8_t type,
                            const uint8_t *plaintext,
                            size_t plaintext_length);

/* Called only at epoch-rekey's zero-progress pause/adoption seam.  pause() cancels
 * one untouched materialized record.  resume() discards old-epoch DATA
 * attempt timers and makes their still-missing chunks freshly eligible while
 * retaining transfer/file/bitmap/scan/phase state.  Bulk-retry's application stall
 * clock remains absolute across the pause. */
int bulk_engine_epoch_pause(bulk_engine_t *engine, int64_t now_ms);
int bulk_engine_epoch_resume(bulk_engine_t *engine, int64_t now_ms);

/* Block/cube all-socket replacement suppresses every local bulk producer
 * while authenticated peer ACK/STATUS input and multipath validation continue.
 * It is distinct from an epoch pause: path_resume() preserves semantic state,
 * shifts path-local attempt timers, leaves protocol repeats due, and never
 * extends bulk-retry's application stall clock. */
int bulk_engine_path_pause(bulk_engine_t *engine, int64_t now_ms);
int bulk_engine_path_resume(bulk_engine_t *engine, int64_t now_ms);

/* Block/cube whole-set re-roll quota. One attempt covers every physical
 * socket and is charged before shadow bind. It needs the same causal witness
 * and common session quiet as a random claim. The four-attempt quota is global
 * to the set for the whole live session and survives both fresh multipath
 * generations and epoch adoption. The per-set 4T quiet is transient;
 * the common session quiet is absolute for the session lifetime. */
bulk_engine_reroll_result_t bulk_engine_set_reroll_claim(
    bulk_engine_t *engine, uint8_t trigger_leg, uint64_t generation,
    int64_t now_ms);
int bulk_engine_set_reroll_finish(bulk_engine_t *engine,
                                  uint8_t trigger_leg,
                                  uint64_t generation,
                                  int succeeded, int64_t now_ms);

/* Local signal/error boundary.  It publishes CANCELLED when a transfer id is
 * already bound and otherwise fails locally without fabricating wire state. */
int bulk_engine_cancel(bulk_engine_t *engine, int64_t now_ms);

bulk_engine_result_t bulk_engine_result(const bulk_engine_t *engine,
                                        bulk_result_code_t *code_out);
/* True only after the receiver physically completed its first DONE_ACK and
 * before DONE_CONFIRM or the pinned completion-linger deadline resolves the
 * transfer.  This is local lifecycle state, never wire or delivery authority. */
int bulk_engine_completion_linger_active(const bulk_engine_t *engine);
int bulk_engine_is_requester(const bulk_engine_t *engine);
int bulk_engine_is_source(const bulk_engine_t *engine);
int bulk_engine_observe(const bulk_engine_t *engine,
                        bulk_engine_observation_t *observation);
const bulk_engine_stats_t *bulk_engine_stats(const bulk_engine_t *engine);
/* Copy every word that can represent the bound manifest. This is a read-only
 * exact-state observation for deterministic invariant tests; counters or a
 * frontier alone cannot prove a sparse bitmap survived path replacement. */
int bulk_engine_bitmap_copy(const bulk_engine_t *engine,
                            uint64_t *words_out, size_t word_capacity,
                            size_t *word_count_out);

/* Session-owned I/O operations use these distinct fixed arenas.  A caller
 * may decrypt a complete frame into receive_buffer, then pass its plaintext
 * slice to receive().  For output, pass receive_buffer (or another caller-
 * owned scratch) to materialize(), synchronously frame/AEAD encode its view
 * into encoded_buffer, and only then resume inbound polling.  The plaintext
 * view is valid until that caller-owned storage changes; the encoded buffer,
 * not the plaintext, is retained across WOULD_BLOCK.  The engine separately
 * retains immutable logical identity for the terminal transport callback. */
uint8_t *bulk_engine_encoded_buffer(bulk_engine_t *engine,
                                    size_t *capacity_out);
uint8_t *bulk_engine_receive_buffer(bulk_engine_t *engine,
                                    size_t *capacity_out);
uint16_t bulk_engine_wire_budget(const bulk_engine_t *engine);
uint8_t bulk_engine_path_count(const bulk_engine_t *engine);
int bulk_engine_active_attempt(const bulk_engine_t *engine,
                               bulk_engine_attempt_view_t *attempt);

#ifdef UNMOOR_BULK_ENGINE_TEST
typedef struct {
    uint64_t recovery_word_tests;
    uint64_t active_index_probes;
    uint32_t last_recovery_word_tests;
    uint32_t max_active_index_probes;
    uint32_t recovery_candidate;
} bulk_engine_test_scan_metrics_t;

/* Test-only structural fixture. The special bulk-engine test build records
 * `handed_out` chunks without reading their payloads, retains `active_floor`
 * as one outstanding attempt, and leaves `candidate` as the next recoverable
 * hole. No hook or symbol is compiled into the product object. */
int bulk_engine_test_quiesce_for_deadline(bulk_engine_t *engine);
int bulk_engine_test_prepare_recovery_scan(bulk_engine_t *engine,
                                           uint32_t handed_out,
                                           uint32_t active_floor,
                                           uint32_t candidate);
int bulk_engine_test_scan_metrics(
    const bulk_engine_t *engine, bulk_engine_test_scan_metrics_t *metrics);
#endif

#endif /* UNMOOR_BULK_ENGINE_H */
