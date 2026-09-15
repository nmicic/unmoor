/*
 * delivery.h — delivery-class bounded non-terminal delivery engines
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef UNMOOR_DELIVERY_H
#define UNMOOR_DELIVERY_H

#define _POSIX_C_SOURCE 200809L

#include <stddef.h>
#include <stdint.h>

/* Exact immutable delivery-class v1 wire/resource constants. */
#define DELIVERY_VERSION                    1U
#define DELIVERY_HASH_BYTES                32U
#define DELIVERY_CONTEXT_BYTES             32U
#define DELIVERY_LATEST_OBJECTS              4U
#define DELIVERY_LATEST_SNAPSHOT_SLOTS       3U
#define DELIVERY_LATEST_BLOCKS_MAX          64U
#define DELIVERY_LATEST_BLOCK_BODY_MAX     160U
#define DELIVERY_LATEST_SNAPSHOT_BYTES_MAX \
    (DELIVERY_LATEST_BLOCKS_MAX * DELIVERY_LATEST_BLOCK_BODY_MAX)
#define DELIVERY_LATEST_AGGREGATE_BYTES (32U * 1024U)
#define DELIVERY_LATEST_HEAD_BYTES          144U
#define DELIVERY_LATEST_BLOCK_HEADER_BYTES   56U
#define DELIVERY_LATEST_BLOCK_WIRE_MAX \
    (DELIVERY_LATEST_BLOCK_HEADER_BYTES + DELIVERY_LATEST_BLOCK_BODY_MAX)
#define DELIVERY_LATEST_STATUS_BYTES        152U
#define DELIVERY_LATEST_SYSTEM_OBJECT_ID       1U
#define DELIVERY_RELIABLE_FLOWS               4U
#define DELIVERY_RELIABLE_BODY_MAX          160U
#define DELIVERY_RELIABLE_DATA_HEADER_BYTES  48U
#define DELIVERY_RELIABLE_DATA_WIRE_MAX \
    (DELIVERY_RELIABLE_DATA_HEADER_BYTES + DELIVERY_RELIABLE_BODY_MAX)
#define DELIVERY_RELIABLE_STATUS_BYTES      100U
#define DELIVERY_RELIABLE_STATUS_FLAG_REFUSED 0x01U
#define DELIVERY_LATEST_RETRY_MS             200
#define DELIVERY_RELIABLE_RETRY_MS           500

/* Accepted fixed-state ceilings; changes require an explicit resource review. */
#define DELIVERY_LATEST_SNAPSHOT_STATE_BYTES_MAX       10360U
#define DELIVERY_LATEST_SENDER_OBJECT_STATE_BYTES_MAX  31400U
#define DELIVERY_LATEST_SENDER_STATE_BYTES_MAX        125648U
#define DELIVERY_LATEST_RECEIVER_OBJECT_STATE_BYTES_MAX 10528U
#define DELIVERY_LATEST_RECEIVER_STATE_BYTES_MAX       42152U
#define DELIVERY_RELIABLE_SENDER_STATE_BYTES_MAX        2192U
#define DELIVERY_RELIABLE_RECEIVER_STATE_BYTES_MAX      1448U

/* Channel-local delivery-class record types. */
#define DELIVERY_LATEST_HEAD_TYPE   0x01U
#define DELIVERY_LATEST_BLOCK_TYPE  0x02U
#define DELIVERY_LATEST_STATUS_TYPE 0x03U
#define DELIVERY_CTRL_RD_DATA_TYPE  0x0fU
#define DELIVERY_CTRL_RD_STATUS_TYPE 0x10U

typedef enum {
    DELIVERY_RESULT_OK          = 0,
    DELIVERY_RESULT_STALE       = 1,
    DELIVERY_RESULT_DUPLICATE   = 2,
    DELIVERY_RESULT_COMPLETE    = 3,
    DELIVERY_RESULT_INSTALLED   = 4,
    DELIVERY_RESULT_DELIVERED   = 5,
    DELIVERY_RESULT_REFUSED     = 6,
    DELIVERY_RESULT_NOT_READY   = 7,
    DELIVERY_RESULT_BUSY        = -1,
    DELIVERY_RESULT_SOURCE_QUOTA = -2,
    DELIVERY_RESULT_MALFORMED   = -3,
    DELIVERY_RESULT_DIVERGED    = -4,
    DELIVERY_RESULT_EXHAUSTED   = -5,
    DELIVERY_RESULT_UNCONFIGURED = -6
} delivery_result_t;

typedef enum {
    DELIVERY_MODE_ACTIVE = 0,
    DELIVERY_MODE_PAUSED = 1,
    DELIVERY_MODE_QUOTA_REFUSED = 2,
    DELIVERY_MODE_RESET_REQUIRED = 3,
    DELIVERY_MODE_NOT_INTERESTED = 4
} delivery_mode_t;

typedef enum {
    DELIVERY_REASON_PAUSED = 1,
    DELIVERY_REASON_QUOTA_REFUSED = 2,
    DELIVERY_REASON_RESET_REQUIRED = 3,
    DELIVERY_REASON_NOT_INTERESTED = 4
} delivery_reason_t;

typedef enum {
    DELIVERY_ATTEMPT_COMPLETE = 1,
    DELIVERY_ATTEMPT_FAILED = 2
} delivery_attempt_result_t;

typedef enum {
    DELIVERY_PRIORITY_LOW = 0,
    DELIVERY_PRIORITY_HIGH = 1
} delivery_priority_t;

typedef struct {
    uint8_t paused;
    uint8_t quota_refused;
    uint8_t reset_required;
    uint8_t not_interested;
    delivery_mode_t mode;
    uint64_t revision;
} delivery_flow_state_t;

/* One exact owner: selection starts no timer; terminal COMPLETE/FAILED does. */
typedef struct {
    uint8_t pending;
    uint8_t inflight;
    uint64_t generation;
    uint32_t attempts;
    int64_t retry_ms;
    int64_t next_attempt_ms;
} delivery_retry_owner_t;

typedef struct {
    uint8_t high_streak;
    uint8_t high_cursor;
    uint8_t low_cursor;
} delivery_service_t;

/* Canonical decoded latest-state records. */
typedef struct {
    uint16_t object_id;
    uint64_t revision;
    uint32_t total_length;
    uint16_t block_size;
    uint16_t block_count;
    uint8_t content_root[DELIVERY_HASH_BYTES];
    uint8_t previous_chain[DELIVERY_HASH_BYTES];
    uint8_t version_chain[DELIVERY_HASH_BYTES];
    uint64_t drop_revision;
    uint64_t dropped_first;
    uint64_t dropped_last;
} delivery_latest_head_t;

typedef struct {
    uint16_t object_id;
    uint64_t revision;
    uint16_t block_index;
    uint16_t block_count;
    uint32_t total_length;
    uint16_t body_length;
    uint8_t content_root[DELIVERY_HASH_BYTES];
    uint8_t body[DELIVERY_LATEST_BLOCK_BODY_MAX];
} delivery_latest_block_t;

typedef struct {
    uint16_t object_id;
    delivery_mode_t mode;
    uint64_t flow_revision;
    uint64_t installed_revision;
    uint8_t installed_chain[DELIVERY_HASH_BYTES];
    uint64_t target_revision;
    uint8_t target_root[DELIVERY_HASH_BYTES];
    uint16_t target_block_count;
    uint16_t have_base; /* v1 canonical value is zero */
    uint64_t have_bitmap;
    uint16_t frontier;
    uint8_t frontier_hash[DELIVERY_HASH_BYTES];
    uint32_t accepted_limit;
    uint64_t accepted_drop_revision;
} delivery_latest_status_t;

typedef struct {
    uint16_t flow_id;
    uint64_t message_id;
    uint16_t body_length;
    uint8_t content_hash[DELIVERY_HASH_BYTES];
    uint8_t body[DELIVERY_RELIABLE_BODY_MAX];
} delivery_reliable_data_t;

typedef struct {
    uint16_t flow_id;
    delivery_mode_t mode;
    uint64_t flow_revision;
    uint64_t delivered_id;
    uint8_t delivered_hash[DELIVERY_HASH_BYTES];
    uint64_t target_id;
    uint8_t target_hash[DELIVERY_HASH_BYTES];
    uint32_t accepted_limit;
    uint8_t flags;
} delivery_reliable_status_t;

typedef int (*delivery_latest_install_fn)(void *arg, uint16_t object_id,
                                          uint64_t revision,
                                          const uint8_t *bytes, size_t length);
/* Return 0 once the application owns the message: the target is retired,
 * delivered_id advances, and the same message id is never presented
 * again (at-most-once).  A nonzero return keeps the target staged and the
 * callback is presented the same message id again on later receive and
 * service turns, so refusal must be idempotent; it is not a drop. */
typedef int (*delivery_reliable_deliver_fn)(void *arg, uint16_t flow_id,
                                            uint64_t message_id,
                                            const uint8_t *bytes,
                                            size_t length);

/* Fixed product state. Applications configure slots; peer traffic never does. */
typedef struct {
    uint8_t valid;
    uint64_t revision;
    uint32_t total_length;
    uint16_t block_count;
    uint8_t content_root[DELIVERY_HASH_BYTES];
    uint8_t previous_chain[DELIVERY_HASH_BYTES];
    uint8_t version_chain[DELIVERY_HASH_BYTES];
    uint8_t bytes[DELIVERY_LATEST_SNAPSHOT_BYTES_MAX];
} delivery_latest_snapshot_t;

typedef struct {
    uint8_t configured;
    uint8_t priority;
    uint16_t object_id;
    uint8_t snapshot_count;
    uint64_t next_revision;
    uint64_t published_revision;
    uint8_t published_chain[DELIVERY_HASH_BYTES];
    uint64_t drop_revision;
    uint64_t drop_watermark; /* highest cumulative eviction ordinal */
    uint64_t dropped_first;
    uint64_t dropped_last;
    uint8_t drop_pending;
    delivery_latest_snapshot_t snapshots[DELIVERY_LATEST_SNAPSHOT_SLOTS];
    uint64_t peer_flow_revision;
    delivery_mode_t peer_mode;
    uint64_t peer_target_revision;
    uint8_t peer_target_root[DELIVERY_HASH_BYTES];
    uint16_t peer_target_block_count;
    uint64_t peer_have_bitmap;
    uint16_t peer_frontier;
    uint8_t peer_frontier_hash[DELIVERY_HASH_BYTES];
    uint32_t peer_accepted_limit;
    uint64_t peer_installed_revision;
    uint8_t peer_installed_chain[DELIVERY_HASH_BYTES];
    uint64_t peer_accepted_drop_revision;
    uint64_t attempted_bitmap;
    uint64_t inflight_revision;
    uint16_t inflight_block;
    delivery_retry_owner_t retry;
} delivery_latest_sender_object_t;

typedef struct {
    uint8_t context[DELIVERY_CONTEXT_BYTES];
    uint8_t direction;
    uint16_t reserved_object_bytes;
    uint32_t retained_bytes;
    delivery_latest_sender_object_t objects[DELIVERY_LATEST_OBJECTS];
    delivery_service_t service;
} delivery_latest_sender_t;

typedef struct {
    uint8_t configured;
    uint8_t priority;
    uint16_t object_id;
    delivery_flow_state_t flow;
    uint8_t target_valid;
    uint8_t target_reserved;
    uint8_t quota_local;
    uint8_t quota_reservation;
    delivery_latest_head_t target;
    uint64_t have_bitmap;
    uint16_t frontier;
    uint8_t frontier_hash[DELIVERY_HASH_BYTES];
    uint8_t bytes[DELIVERY_LATEST_SNAPSHOT_BYTES_MAX];
    uint64_t installed_revision;
    uint8_t installed_chain[DELIVERY_HASH_BYTES];
    uint64_t accepted_drop_revision;
    delivery_latest_install_fn install;
    void *install_arg;
} delivery_latest_receiver_object_t;

typedef struct {
    uint8_t context[DELIVERY_CONTEXT_BYTES];
    uint8_t direction;
    uint8_t status_changed_mask;
    uint16_t reserved_object_bytes;
    uint32_t reserved_bytes;
    delivery_latest_receiver_object_t objects[DELIVERY_LATEST_OBJECTS];
} delivery_latest_receiver_t;

typedef struct {
    uint8_t configured;
    uint8_t priority;
    uint16_t flow_id;
    uint64_t next_message_id;
    uint8_t pending;
    delivery_reliable_data_t record;
    delivery_retry_owner_t retry;
    uint8_t transport_semantic_retired;
    uint64_t transport_id;
    uint8_t transport_hash[DELIVERY_HASH_BYTES];
    uint64_t peer_flow_revision;
    delivery_mode_t peer_mode;
    delivery_reliable_status_t peer_status;
    uint64_t known_delivered_id;
    uint8_t known_delivered_hash[DELIVERY_HASH_BYTES];
    uint64_t last_result_id;
    uint8_t last_result_hash[DELIVERY_HASH_BYTES];
    delivery_result_t last_result;
    /* Reuses the last-result identity until a successor is accepted. */
    uint8_t last_refused_valid;
} delivery_reliable_sender_flow_t;

typedef struct {
    uint8_t context[DELIVERY_CONTEXT_BYTES];
    uint8_t direction;
    delivery_reliable_sender_flow_t flows[DELIVERY_RELIABLE_FLOWS];
    delivery_service_t service;
} delivery_reliable_sender_t;

typedef struct {
    uint8_t configured;
    uint8_t priority;
    uint16_t flow_id;
    delivery_flow_state_t flow;
    uint8_t target_valid;
    uint8_t target_has_body;
    delivery_reliable_data_t target;
    uint64_t refused_id;
    uint8_t refused_hash[DELIVERY_HASH_BYTES];
    uint64_t refused_flow_revision;
    uint64_t delivered_id;
    uint8_t delivered_hash[DELIVERY_HASH_BYTES];
    delivery_reliable_deliver_fn deliver;
    void *deliver_arg;
} delivery_reliable_receiver_flow_t;

typedef struct {
    uint8_t context[DELIVERY_CONTEXT_BYTES];
    uint8_t direction;
    delivery_reliable_receiver_flow_t flows[DELIVERY_RELIABLE_FLOWS];
} delivery_reliable_receiver_t;

/* Context and domain-separated hash primitives. */
void delivery_context_derive(const uint8_t client_hello[32],
                             const uint8_t server_ack[32],
                             uint32_t selected_caps,
                             uint8_t out[DELIVERY_CONTEXT_BYTES]);
void delivery_latest_leaf_hash(const uint8_t context[DELIVERY_CONTEXT_BYTES],
                               uint8_t direction, uint16_t object_id,
                               uint64_t revision, uint32_t total_length,
                               uint16_t block_count, uint16_t block_index,
                               const uint8_t *body, size_t body_length,
                               uint8_t out[DELIVERY_HASH_BYTES]);
void delivery_latest_chain_hash(const uint8_t context[DELIVERY_CONTEXT_BYTES],
                                uint8_t direction, uint16_t object_id,
                                uint64_t revision, uint16_t block_index,
                                const uint8_t previous[DELIVERY_HASH_BYTES],
                                const uint8_t leaf[DELIVERY_HASH_BYTES],
                                uint8_t out[DELIVERY_HASH_BYTES]);
void delivery_latest_version_hash(const uint8_t context[DELIVERY_CONTEXT_BYTES],
                                  uint8_t direction, uint16_t object_id,
                                  uint64_t revision, uint32_t total_length,
                                  uint16_t block_count,
                                  const uint8_t previous[DELIVERY_HASH_BYTES],
                                  const uint8_t root[DELIVERY_HASH_BYTES],
                                  uint8_t out[DELIVERY_HASH_BYTES]);
void delivery_reliable_content_hash(
    const uint8_t context[DELIVERY_CONTEXT_BYTES], uint8_t direction,
    uint16_t flow_id, uint64_t message_id, const uint8_t *body,
    size_t body_length, uint8_t out[DELIVERY_HASH_BYTES]);

/* Exact little-endian codecs. */
int delivery_latest_head_encode(const delivery_latest_head_t *record,
                                uint8_t out[DELIVERY_LATEST_HEAD_BYTES]);
int delivery_latest_head_decode(const uint8_t *wire, size_t wire_length,
                                delivery_latest_head_t *record);
int delivery_latest_block_encode(const delivery_latest_block_t *record,
                                 uint8_t *out, size_t out_size,
                                 size_t *wire_length);
int delivery_latest_block_decode(const uint8_t *wire, size_t wire_length,
                                 delivery_latest_block_t *record);
int delivery_latest_status_encode(const delivery_latest_status_t *record,
                                  uint8_t out[DELIVERY_LATEST_STATUS_BYTES]);
int delivery_latest_status_decode(const uint8_t *wire, size_t wire_length,
                                  delivery_latest_status_t *record);
int delivery_reliable_data_encode(const delivery_reliable_data_t *record,
                                  uint8_t *out, size_t out_size,
                                  size_t *wire_length);
int delivery_reliable_data_decode(const uint8_t *wire, size_t wire_length,
                                  delivery_reliable_data_t *record);
int delivery_reliable_status_encode(
    const delivery_reliable_status_t *record,
    uint8_t out[DELIVERY_RELIABLE_STATUS_BYTES]);
int delivery_reliable_status_decode(const uint8_t *wire, size_t wire_length,
                                    delivery_reliable_status_t *record);

/* Orthogonal repeated state. */
void delivery_flow_init(delivery_flow_state_t *flow);
int delivery_flow_set_reason(delivery_flow_state_t *flow,
                             delivery_reason_t reason, int enabled);
int delivery_flow_target_changed(delivery_flow_state_t *flow);

/* Generic exact-owner/retry and bounded 3:1 service helpers. */
int delivery_retry_init(delivery_retry_owner_t *owner, int64_t retry_ms);
int delivery_retry_arm(delivery_retry_owner_t *owner, uint64_t generation,
                       int64_t now_ms);
int delivery_retry_due(const delivery_retry_owner_t *owner, int64_t now_ms);
int delivery_retry_selected(delivery_retry_owner_t *owner, uint64_t generation,
                            int64_t now_ms);
int delivery_retry_result(delivery_retry_owner_t *owner, uint64_t generation,
                          delivery_attempt_result_t result, int64_t now_ms);
int delivery_retry_ack(delivery_retry_owner_t *owner, uint64_t generation);
void delivery_service_init(delivery_service_t *service);
int delivery_service_select(delivery_service_t *service, uint8_t high_mask,
                            uint8_t low_mask, unsigned int *slot_out);

/* Latest sender. Slots are configured locally before use. */
void delivery_latest_sender_init(delivery_latest_sender_t *sender,
                                 const uint8_t context[DELIVERY_CONTEXT_BYTES],
                                 uint8_t direction);
/* Before configuring slots, carve bytes out of the aggregate for canonical
 * system object 1.  Other objects cannot consume that carve; object 1 still
 * obeys the unchanged total aggregate ceiling and may evict only its own
 * snapshots. */
int delivery_latest_sender_reserve_object(
    delivery_latest_sender_t *sender, uint16_t object_id, uint32_t bytes);
int delivery_latest_sender_configure(delivery_latest_sender_t *sender,
                                     unsigned int slot, uint16_t object_id,
                                     delivery_priority_t priority);
int delivery_latest_sender_publish(delivery_latest_sender_t *sender,
                                   uint16_t object_id, const uint8_t *bytes,
                                   size_t length);
int delivery_latest_sender_retire_all(delivery_latest_sender_t *sender,
                                      uint16_t object_id);
int delivery_latest_sender_head(const delivery_latest_sender_t *sender,
                                uint16_t object_id,
                                delivery_latest_head_t *head);
int delivery_latest_sender_observe_status(
    delivery_latest_sender_t *sender,
    const delivery_latest_status_t *status, int64_t now_ms);
int delivery_latest_sender_validate_status(
    const delivery_latest_sender_t *sender,
    const delivery_latest_status_t *status);
int delivery_latest_sender_next_block(const delivery_latest_sender_t *sender,
                                      uint16_t object_id, int64_t now_ms,
                                      delivery_latest_block_t *block,
                                      int *is_recovery);
int delivery_latest_sender_select_block(delivery_latest_sender_t *sender,
                                        int64_t now_ms,
                                        delivery_latest_block_t *block,
                                        int *is_recovery,
                                        unsigned int *slot_out);
int delivery_latest_sender_block_selected(delivery_latest_sender_t *sender,
                                          uint16_t object_id,
                                          uint16_t block_index,
                                          int64_t now_ms);
int delivery_latest_sender_block_result(delivery_latest_sender_t *sender,
                                        uint16_t object_id,
                                        uint16_t block_index,
                                        delivery_attempt_result_t result,
                                        int64_t now_ms);

/* Latest receiver. Installation is an explicit atomic application boundary. */
void delivery_latest_receiver_init(
    delivery_latest_receiver_t *receiver,
    const uint8_t context[DELIVERY_CONTEXT_BYTES], uint8_t direction);
int delivery_latest_receiver_reserve_object(
    delivery_latest_receiver_t *receiver, uint16_t object_id,
    uint32_t bytes);
int delivery_latest_receiver_configure(
    delivery_latest_receiver_t *receiver, unsigned int slot,
    uint16_t object_id, delivery_priority_t priority,
    delivery_latest_install_fn install, void *install_arg);
int delivery_latest_receiver_observe_head(
    delivery_latest_receiver_t *receiver,
    const delivery_latest_head_t *head);
int delivery_latest_receiver_validate_head(
    const delivery_latest_receiver_t *receiver,
    const delivery_latest_head_t *head);
int delivery_latest_receiver_observe_block(
    delivery_latest_receiver_t *receiver,
    const delivery_latest_block_t *block);
int delivery_latest_receiver_validate_block(
    const delivery_latest_receiver_t *receiver,
    const delivery_latest_block_t *block);
int delivery_latest_receiver_install(delivery_latest_receiver_t *receiver,
                                     uint16_t object_id);
int delivery_latest_receiver_cancel_target(
    delivery_latest_receiver_t *receiver, uint16_t object_id);
int delivery_latest_receiver_status(
    const delivery_latest_receiver_t *receiver, uint16_t object_id,
    delivery_latest_status_t *status);
int delivery_latest_receiver_set_reason(
    delivery_latest_receiver_t *receiver, uint16_t object_id,
    delivery_reason_t reason, int enabled);
int delivery_latest_receiver_refresh_reservations(
    delivery_latest_receiver_t *receiver);
uint8_t delivery_latest_receiver_take_status_changed(
    delivery_latest_receiver_t *receiver);

/* One-outstanding exact reliable datagrams. */
void delivery_reliable_sender_init(
    delivery_reliable_sender_t *sender,
    const uint8_t context[DELIVERY_CONTEXT_BYTES], uint8_t direction);
int delivery_reliable_sender_configure(delivery_reliable_sender_t *sender,
                                       unsigned int slot, uint16_t flow_id,
                                       delivery_priority_t priority);
int delivery_reliable_sender_admit(delivery_reliable_sender_t *sender,
                                   uint16_t flow_id, const uint8_t *bytes,
                                   size_t length, int64_t now_ms,
                                   uint64_t *message_id_out);
int delivery_reliable_sender_due(const delivery_reliable_sender_t *sender,
                                 uint16_t flow_id, int64_t now_ms);
int delivery_reliable_sender_select_due(
    delivery_reliable_sender_t *sender, int64_t now_ms,
    delivery_reliable_data_t *record, int *is_recovery,
    unsigned int *slot_out);
int delivery_reliable_sender_data(const delivery_reliable_sender_t *sender,
                                  uint16_t flow_id,
                                  delivery_reliable_data_t *record);
int delivery_reliable_sender_selected(delivery_reliable_sender_t *sender,
                                      uint16_t flow_id, int64_t now_ms);
int delivery_reliable_sender_result(delivery_reliable_sender_t *sender,
                                    uint16_t flow_id, uint64_t message_id,
                                    delivery_attempt_result_t result,
                                    int64_t now_ms);
int delivery_reliable_sender_observe_status(
    delivery_reliable_sender_t *sender,
    const delivery_reliable_status_t *status);
int delivery_reliable_sender_validate_status(
    const delivery_reliable_sender_t *sender,
    const delivery_reliable_status_t *status);

void delivery_reliable_receiver_init(
    delivery_reliable_receiver_t *receiver,
    const uint8_t context[DELIVERY_CONTEXT_BYTES], uint8_t direction);
int delivery_reliable_receiver_configure(
    delivery_reliable_receiver_t *receiver, unsigned int slot,
    uint16_t flow_id, delivery_priority_t priority,
    delivery_reliable_deliver_fn deliver, void *deliver_arg);
int delivery_reliable_receiver_observe_data(
    delivery_reliable_receiver_t *receiver,
    const delivery_reliable_data_t *record);
int delivery_reliable_receiver_validate_data(
    const delivery_reliable_receiver_t *receiver,
    const delivery_reliable_data_t *record);
int delivery_reliable_receiver_deliver(delivery_reliable_receiver_t *receiver,
                                       uint16_t flow_id);
int delivery_reliable_receiver_status(
    const delivery_reliable_receiver_t *receiver, uint16_t flow_id,
    delivery_reliable_status_t *status);
int delivery_reliable_receiver_set_reason(
    delivery_reliable_receiver_t *receiver, uint16_t flow_id,
    delivery_reason_t reason, int enabled);

#endif /* UNMOOR_DELIVERY_H */
