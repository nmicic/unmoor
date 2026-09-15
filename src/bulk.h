/*
 * bulk.h — bulk-transfer portable bulk-transfer core
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef UNMOOR_BULK_H
#define UNMOOR_BULK_H

#include <stddef.h>
#include <stdint.h>

#include "frame.h"

#define BULK_VERSION                 1U
#define BULK_CAPABILITY              UINT32_C(0x00001000)
#define BULK_CHANNEL_ID              3U

#define BULK_REQUEST                 0x01U
#define BULK_MANIFEST                0x02U
#define BULK_DATA                    0x03U
#define BULK_ACK                     0x04U
#define BULK_STATUS                  0x05U

#define BULK_WIRE_MIN                768U
#define BULK_WIRE_DEFAULT            1200U
#define BULK_WIRE_MAX                8952U
#define BULK_FRAME_OVERHEAD_BYTES    (FRAME_HEADER_LEN + FRAME_TAG_LEN)

#define BULK_CHUNK_LOG2_MIN          9U
#define BULK_CHUNK_LOG2_MAX          13U
#define BULK_CHUNK_MIN               (1U << BULK_CHUNK_LOG2_MIN)
#define BULK_CHUNK_MAX               (1U << BULK_CHUNK_LOG2_MAX)
#define BULK_CHUNKS_MAX              (1U << 24)

#define BULK_BITMAP_BYTES            (2U * 1024U * 1024U)
#define BULK_BITMAP_WORDS            (BULK_BITMAP_BYTES / sizeof(uint64_t))
#define BULK_ACK_WORDS               16U
#define BULK_ACK_PAGE_BITS           (BULK_ACK_WORDS * 64U)
#define BULK_ACK_PAGES               (BULK_BITMAP_WORDS / BULK_ACK_WORDS)
#define BULK_ACK_PAGE_MAX_BASE       (BULK_BITMAP_WORDS - BULK_ACK_WORDS)
#define BULK_LEGS_MAX                32U

#define BULK_ROOT_BYTES              32U
#define BULK_PATH_MAX                1024U
#define BULK_PATH_SCRATCH_BYTES      2048U
#define BULK_TEMP_NAME_BYTES         128U

#define BULK_REQUEST_PREFIX_BYTES    16U
#define BULK_REQUEST_PLAINTEXT_MAX   (BULK_REQUEST_PREFIX_BYTES + BULK_PATH_MAX)
#define BULK_REQUEST_WIRE_BASE       (BULK_REQUEST_PREFIX_BYTES + BULK_FRAME_OVERHEAD_BYTES)
#define BULK_MANIFEST_BYTES          56U
#define BULK_MANIFEST_WIRE_BYTES     (BULK_MANIFEST_BYTES + BULK_FRAME_OVERHEAD_BYTES)
#define BULK_DATA_PREFIX_BYTES       20U
#define BULK_DATA_PLAINTEXT_MAX      (BULK_DATA_PREFIX_BYTES + BULK_CHUNK_MAX)
#define BULK_DATA_WIRE_BASE          (BULK_DATA_PREFIX_BYTES + BULK_FRAME_OVERHEAD_BYTES)
#define BULK_ACK_BYTES               561U
#define BULK_ACK_WIRE_BYTES          (BULK_ACK_BYTES + BULK_FRAME_OVERHEAD_BYTES)
#define BULK_STATUS_BYTES            68U
#define BULK_STATUS_WIRE_BYTES       (BULK_STATUS_BYTES + BULK_FRAME_OVERHEAD_BYTES)

#define BULK_REQUEST_FORCE           0x01U

typedef enum {
    BULK_OPERATION_PUT = 1,
    BULK_OPERATION_GET = 2
} bulk_operation_t;

typedef enum {
    BULK_PHASE_PREPARING = 1,
    BULK_PHASE_VERIFYING = 2,
    BULK_PHASE_INSTALLED = 3,
    BULK_PHASE_DONE = 4,
    BULK_PHASE_DONE_ACK = 5,
    BULK_PHASE_REFUSED = 6,
    BULK_PHASE_FAILED = 7,
    BULK_PHASE_DONE_CONFIRM = 8
} bulk_phase_t;

typedef enum {
    BULK_CODE_NONE = 0,
    BULK_CODE_EXISTS = 1,
    BULK_CODE_SOURCE_OPEN = 2,
    BULK_CODE_DESTINATION = 3,
    BULK_CODE_QUOTA_SIZE = 4,
    BULK_CODE_UNSUPPORTED_MTU = 5,
    BULK_CODE_ROOT_MISMATCH = 6,
    BULK_CODE_STALLED = 7,
    BULK_CODE_CANCELLED = 8,
    BULK_CODE_PROTOCOL = 9,
    BULK_CODE_SOURCE_CHANGED = 10,
    BULK_CODE_IO = 11,
    BULK_CODE_BUSY = 12,
    BULK_CODE_PACE_TOO_LOW = 13
} bulk_result_code_t;

/* Local core result. Positive values are successful observations. */
typedef enum {
    BULK_RC_OK = 0,
    BULK_RC_DUPLICATE = 1,
    BULK_RC_STALE = 2,
    BULK_RC_PROGRESS = 3,
    BULK_RC_MORE = 4,
    BULK_RC_ARGUMENT = -1,
    BULK_RC_MALFORMED = -2,
    BULK_RC_STATE = -3,
    BULK_RC_IO = -4,
    BULK_RC_EXISTS = -5,
    BULK_RC_ROOT_MISMATCH = -6,
    BULK_RC_SOURCE_CHANGED = -7,
    BULK_RC_DIVERGED = -8,
    BULK_RC_RESOURCE = -9
} bulk_rc_t;

typedef struct {
    uint8_t operation;
    uint8_t flags;
    uint64_t transfer_id;
    uint16_t wire_budget;
    uint16_t path_length;
    /* One private terminator byte; path_length and wire remain capped at
     * BULK_PATH_MAX opaque bytes. */
    uint8_t path[BULK_PATH_MAX + 1U];
} bulk_request_t;

typedef struct {
    uint64_t transfer_id;
    uint64_t file_size;
    uint32_t chunk_count;
    uint16_t wire_budget;
    uint8_t chunk_log2;
    uint8_t root[BULK_ROOT_BYTES];
} bulk_manifest_t;

/* body aliases the caller-owned plaintext buffer after decode. */
typedef struct {
    uint8_t sender_leg;
    uint64_t transfer_id;
    uint32_t chunk_index;
    uint32_t attempt_id;
    uint16_t body_length;
    const uint8_t *body;
} bulk_data_view_t;

typedef struct {
    uint32_t chunks;
    uint64_t bytes;
} bulk_leg_counter_t;

typedef struct {
    uint64_t transfer_id;
    uint8_t root[BULK_ROOT_BYTES];
    uint32_t frontier;
    uint32_t page_word_base;
    uint64_t words[BULK_ACK_WORDS];
    bulk_leg_counter_t counters[BULK_LEGS_MAX];
} bulk_ack_t;

typedef struct {
    uint8_t phase;
    uint16_t code;
    uint64_t revision;
    uint64_t transfer_id;
    uint8_t root[BULK_ROOT_BYTES];
    uint64_t file_size;
    uint64_t processed_bytes;
} bulk_status_t;

/* Exact little-endian plaintext codecs. */
int bulk_request_encode(const bulk_request_t *record, uint8_t *out,
                        size_t out_size, size_t *plaintext_length);
int bulk_request_decode(const uint8_t *plaintext, size_t plaintext_length,
                        bulk_request_t *record);
int bulk_manifest_encode(const bulk_manifest_t *record,
                         uint8_t out[BULK_MANIFEST_BYTES]);
int bulk_manifest_decode(const uint8_t *plaintext, size_t plaintext_length,
                         bulk_manifest_t *record);
int bulk_data_encode(const bulk_data_view_t *record, uint8_t *out,
                     size_t out_size, size_t *plaintext_length);
int bulk_data_decode(const uint8_t *plaintext, size_t plaintext_length,
                     bulk_data_view_t *record);
int bulk_ack_encode(const bulk_ack_t *record,
                    uint8_t out[BULK_ACK_BYTES]);
int bulk_ack_decode(const uint8_t *plaintext, size_t plaintext_length,
                    bulk_ack_t *record);
int bulk_status_encode(const bulk_status_t *record,
                       uint8_t out[BULK_STATUS_BYTES]);
int bulk_status_decode(const uint8_t *plaintext, size_t plaintext_length,
                       bulk_status_t *record);

/* Canonical bulk-transfer geometry and state-dependent record validation. */
int bulk_wire_budget_valid(uint16_t wire_budget);
size_t bulk_request_path_limit(uint16_t wire_budget);
int bulk_remote_path_valid(const uint8_t *path, size_t length);
int bulk_geometry_from_budget(uint16_t wire_budget, uint8_t *chunk_log2,
                              uint16_t *chunk_size);
int bulk_chunk_count(uint64_t file_size, uint8_t chunk_log2,
                     uint32_t *chunk_count);
int bulk_manifest_validate(const bulk_manifest_t *manifest);
int bulk_manifest_validate_request(const bulk_manifest_t *manifest,
                                   const bulk_request_t *request);
int bulk_chunk_extent(const bulk_manifest_t *manifest, uint32_t chunk_index,
                      uint64_t *offset, uint16_t *body_length);
int bulk_data_validate(const bulk_data_view_t *data,
                       const bulk_manifest_t *manifest, uint8_t path_count);

/* One call absorbs exactly one real or pad leaf; callers can yield between
 * calls. The context contains exactly the fixed 32-entry hash stack. */
typedef struct {
    uint8_t stack[32][BULK_ROOT_BYTES];
    uint64_t transfer_id;
    uint64_t file_size;
    uint32_t chunk_count;
    uint32_t capacity;
    uint32_t next_index;
    uint32_t occupied_levels;
    uint8_t chunk_log2;
    uint8_t ready;
} bulk_merkle_t;

int bulk_merkle_init(bulk_merkle_t *merkle, uint64_t transfer_id,
                     uint64_t file_size, uint8_t chunk_log2,
                     uint32_t chunk_count);
int bulk_merkle_push_chunk(bulk_merkle_t *merkle, const uint8_t *body,
                           size_t body_length);
int bulk_merkle_push_pad(bulk_merkle_t *merkle);
int bulk_merkle_root(const bulk_merkle_t *merkle,
                     uint8_t root[BULK_ROOT_BYTES]);

/* Bitmap storage is caller-owned and must be runtime-page-aligned. */
typedef struct {
    uint64_t *words;
    size_t storage_bytes;
    uint32_t chunk_count;
    uint32_t frontier;
    uint32_t represented_chunks;
    uint64_t represented_bytes;
} bulk_bitmap_t;

typedef struct {
    bulk_bitmap_t bitmap;
    bulk_leg_counter_t counters[BULK_LEGS_MAX];
} bulk_ack_state_t;

int bulk_bitmap_storage_alloc(void **storage_out);
void bulk_bitmap_storage_free(void *storage);
int bulk_bitmap_init(bulk_bitmap_t *bitmap, void *storage,
                     size_t storage_bytes, const bulk_manifest_t *manifest);
int bulk_bitmap_test(const bulk_bitmap_t *bitmap, uint32_t chunk_index);
/* Intended for recovery/testing; product DATA admission should use
 * bulk_sink_admit_chunk(), which enforces write-before-HAVE. */
int bulk_bitmap_mark_present(bulk_bitmap_t *bitmap,
                             const bulk_manifest_t *manifest,
                             uint32_t chunk_index, int *changed);
int bulk_ack_state_init(bulk_ack_state_t *state, void *storage,
                        size_t storage_bytes,
                        const bulk_manifest_t *manifest);
int bulk_ack_snapshot(const bulk_bitmap_t *bitmap,
                      const bulk_leg_counter_t counters[BULK_LEGS_MAX],
                      const bulk_manifest_t *manifest, uint8_t path_count,
                      uint32_t page_word_base, bulk_ack_t *ack);
int bulk_ack_validate(const bulk_ack_t *ack,
                      const bulk_manifest_t *manifest, uint8_t path_count);
int bulk_ack_merge(bulk_ack_state_t *state, const bulk_ack_t *ack,
                   const bulk_manifest_t *manifest, uint8_t path_count);

typedef struct {
    uint64_t device;
    uint64_t inode;
    uint64_t size;
    int64_t mtime_seconds;
    int64_t mtime_nanoseconds;
} bulk_source_identity_t;

typedef struct {
    int fd;
    uint8_t chunk_log2;
    uint32_t chunk_count;
    bulk_source_identity_t identity;
} bulk_source_t;

void bulk_source_init(bulk_source_t *source);
int bulk_source_open(bulk_source_t *source, const char *path,
                     uint8_t chunk_log2);
int bulk_source_read_chunk(const bulk_source_t *source,
                           const bulk_manifest_t *manifest,
                           uint32_t chunk_index, uint8_t *body,
                           size_t body_size, size_t *body_length);
int bulk_source_check_unchanged(const bulk_source_t *source);
int bulk_source_close(bulk_source_t *source);

typedef struct {
    int dirfd;
    int temp_fd;
    uint64_t file_size;
    char destination[BULK_PATH_MAX + 1U];
    char temp_name[BULK_TEMP_NAME_BYTES];
    uint8_t temp_named;
    uint8_t installed;
} bulk_sink_t;

void bulk_sink_init(bulk_sink_t *sink);
int bulk_sink_prepare(bulk_sink_t *sink, const uint8_t *path,
                      size_t path_length, uint64_t file_size,
                      char scratch[BULK_PATH_SCRATCH_BYTES]);
int bulk_sink_admit_chunk(bulk_sink_t *sink, bulk_bitmap_t *bitmap,
                          const bulk_manifest_t *manifest,
                          uint32_t chunk_index, const uint8_t *body,
                          size_t body_length,
                          uint8_t duplicate_scratch[BULK_CHUNK_MAX],
                          int *newly_admitted);
int bulk_sink_read_chunk(const bulk_sink_t *sink,
                         const bulk_manifest_t *manifest,
                         uint32_t chunk_index, uint8_t *body,
                         size_t body_size, size_t *body_length);
int bulk_sink_install(bulk_sink_t *sink, const bulk_bitmap_t *bitmap,
                      const bulk_manifest_t *manifest, int force,
                      const uint8_t computed_root[BULK_ROOT_BYTES]);
int bulk_sink_cleanup(bulk_sink_t *sink);

#ifdef UNMOOR_BULK_TEST
typedef enum {
    BULK_TEST_INSTALL_NONE = 0,
    BULK_TEST_INSTALL_SYNC_TEMP = 1,
    BULK_TEST_INSTALL_NAMESPACE = 2,
    BULK_TEST_INSTALL_SYNC_DIR = 3
} bulk_test_install_operation_t;

typedef struct {
    uint8_t operation[3];
    size_t count;
} bulk_test_install_trace_t;

int bulk_test_install_trace_reset(bulk_test_install_operation_t fail_at);
int bulk_test_install_trace_read(bulk_test_install_trace_t *trace);
#endif

#endif /* UNMOOR_BULK_H */
