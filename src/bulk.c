/*
 * bulk.c — bulk-transfer portable bulk-transfer core
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */

#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#ifdef __linux__
#define _GNU_SOURCE 1
#endif
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "bulk.h"
#include "crypto.h"
#include "fd_stat.h"
#include "monocypher.h"

_Static_assert(BULK_FRAME_OVERHEAD_BYTES == 28U,
               "bulk-transfer frame overhead changed");
_Static_assert(BULK_ACK_WIRE_BYTES == 589U,
               "bulk-transfer ACK wire size changed");
_Static_assert(BULK_BITMAP_WORDS == 262144U,
               "bulk-transfer bitmap geometry changed");
_Static_assert(BULK_ACK_PAGES == 16384U,
               "bulk-transfer ACK page geometry changed");
_Static_assert(sizeof(((bulk_merkle_t *)0)->stack) == 1024U,
               "bulk-transfer Merkle stack changed");

#define BULK_TEMP_RANDOM_BYTES 16U
#define BULK_TEMP_ATTEMPTS     16U

#define SINK_INSTALL_SYNC_TEMP 1U
#define SINK_INSTALL_NAMESPACE 2U
#define SINK_INSTALL_SYNC_DIR  3U

#ifdef UNMOOR_BULK_TEST
static bulk_test_install_trace_t test_install_trace;
static bulk_test_install_operation_t test_install_fail_at;
static int test_install_trace_enabled;

int bulk_test_install_trace_reset(bulk_test_install_operation_t fail_at)
{
    if (fail_at < BULK_TEST_INSTALL_NONE ||
        fail_at > BULK_TEST_INSTALL_SYNC_DIR)
        return BULK_RC_ARGUMENT;
    memset(&test_install_trace, 0, sizeof(test_install_trace));
    test_install_fail_at = fail_at;
    test_install_trace_enabled = 1;
    return BULK_RC_OK;
}

int bulk_test_install_trace_read(bulk_test_install_trace_t *trace)
{
    if (trace == NULL)
        return BULK_RC_ARGUMENT;
    *trace = test_install_trace;
    test_install_trace_enabled = 0;
    test_install_fail_at = BULK_TEST_INSTALL_NONE;
    return BULK_RC_OK;
}
#endif

static int sink_install_step(uint8_t operation)
{
#ifdef UNMOOR_BULK_TEST
    if (!test_install_trace_enabled)
        return 0;
    if (test_install_trace.count >= sizeof(test_install_trace.operation)) {
        errno = EOVERFLOW;
        return -1;
    }
    test_install_trace.operation[test_install_trace.count++] = operation;
    if ((uint8_t)test_install_fail_at == operation) {
        errno = EIO;
        return -1;
    }
#else
    (void)operation;
#endif
    return 0;
}

static int sink_sync_temp_file(int fd)
{
    if (sink_install_step(SINK_INSTALL_SYNC_TEMP) != 0)
        return -1;
#if defined(__APPLE__) && defined(F_FULLFSYNC)
    return fcntl(fd, F_FULLFSYNC);
#else
    return fsync(fd);
#endif
}

static int sink_sync_directory(int fd)
{
    if (sink_install_step(SINK_INSTALL_SYNC_DIR) != 0)
        return -1;
    return fsync(fd);
}

static uint16_t load16_le(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t load32_le(const uint8_t *p)
{
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint64_t load64_le(const uint8_t *p)
{
    return (uint64_t)load32_le(p) | ((uint64_t)load32_le(p + 4) << 32);
}

static void store16_le(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
}

static void store32_le(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
    p[2] = (uint8_t)(value >> 16);
    p[3] = (uint8_t)(value >> 24);
}

static void store64_le(uint8_t *p, uint64_t value)
{
    store32_le(p, (uint32_t)value);
    store32_le(p + 4, (uint32_t)(value >> 32));
}

static int bytes_zero(const uint8_t *bytes, size_t length)
{
    uint8_t aggregate = 0;
    size_t i;

    if (bytes == NULL)
        return 0;
    for (i = 0; i < length; i++)
        aggregate |= bytes[i];
    return aggregate == 0;
}

static int path_count_valid(uint8_t path_count)
{
    return path_count == 1U || path_count == 2U || path_count == 4U ||
           path_count == 8U || path_count == 16U || path_count == 32U;
}

static int phase_valid(uint8_t phase)
{
    return phase >= BULK_PHASE_PREPARING &&
           phase <= BULK_PHASE_DONE_CONFIRM;
}

int bulk_remote_path_valid(const uint8_t *path, size_t length)
{
    size_t i;
    size_t basename = 0;
    size_t basename_length;

    if (path == NULL || length == 0 || length > BULK_PATH_MAX ||
        path[length - 1U] == (uint8_t)'/')
        return 0;
    for (i = 0; i < length; i++) {
        if (path[i] == 0)
            return 0;
        if (path[i] == (uint8_t)'/')
            basename = i + 1U;
    }
    basename_length = length - basename;
    if (basename_length == 1U && path[basename] == (uint8_t)'.')
        return 0;
    if (basename_length == 2U && path[basename] == (uint8_t)'.' &&
        path[basename + 1U] == (uint8_t)'.')
        return 0;
    return 1;
}

int bulk_wire_budget_valid(uint16_t wire_budget)
{
    return wire_budget >= BULK_WIRE_MIN && wire_budget <= BULK_WIRE_MAX;
}

size_t bulk_request_path_limit(uint16_t wire_budget)
{
    size_t limit;

    if (!bulk_wire_budget_valid(wire_budget) ||
        wire_budget < BULK_REQUEST_WIRE_BASE)
        return 0;
    limit = (size_t)wire_budget - BULK_REQUEST_WIRE_BASE;
    if (limit > BULK_PATH_MAX)
        limit = BULK_PATH_MAX;
    return limit;
}

int bulk_geometry_from_budget(uint16_t wire_budget, uint8_t *chunk_log2,
                              uint16_t *chunk_size)
{
    uint8_t log2;

    if (!bulk_wire_budget_valid(wire_budget) || chunk_log2 == NULL ||
        chunk_size == NULL)
        return BULK_RC_ARGUMENT;
    for (log2 = BULK_CHUNK_LOG2_MAX;; log2--) {
        uint16_t size = (uint16_t)(1U << log2);
        if ((uint32_t)size + BULK_DATA_WIRE_BASE <= wire_budget) {
            *chunk_log2 = log2;
            *chunk_size = size;
            return BULK_RC_OK;
        }
        if (log2 == BULK_CHUNK_LOG2_MIN)
            break;
    }
    return BULK_RC_MALFORMED;
}

int bulk_chunk_count(uint64_t file_size, uint8_t chunk_log2,
                     uint32_t *chunk_count)
{
    uint64_t chunks;
    uint64_t mask;

    if (chunk_count == NULL || chunk_log2 < BULK_CHUNK_LOG2_MIN ||
        chunk_log2 > BULK_CHUNK_LOG2_MAX)
        return BULK_RC_ARGUMENT;
    mask = (UINT64_C(1) << chunk_log2) - UINT64_C(1);
    chunks = file_size >> chunk_log2;
    if ((file_size & mask) != 0)
        chunks++;
    if (chunks > BULK_CHUNKS_MAX)
        return BULK_RC_RESOURCE;
    *chunk_count = (uint32_t)chunks;
    return BULK_RC_OK;
}

static int request_valid(const bulk_request_t *record)
{
    if (record == NULL ||
        (record->operation != BULK_OPERATION_PUT &&
         record->operation != BULK_OPERATION_GET) ||
        (record->flags & (uint8_t)~BULK_REQUEST_FORCE) != 0 ||
        record->transfer_id == 0 ||
        record->path_length > bulk_request_path_limit(record->wire_budget) ||
        !bulk_remote_path_valid(record->path, record->path_length))
        return 0;
    return 1;
}

int bulk_manifest_validate(const bulk_manifest_t *manifest)
{
    uint8_t expected_log2;
    uint16_t expected_size;
    uint32_t expected_count;

    if (manifest == NULL || manifest->transfer_id == 0 ||
        bytes_zero(manifest->root, BULK_ROOT_BYTES) ||
        bulk_geometry_from_budget(manifest->wire_budget, &expected_log2,
                                  &expected_size) != BULK_RC_OK ||
        manifest->chunk_log2 != expected_log2 ||
        bulk_chunk_count(manifest->file_size, manifest->chunk_log2,
                         &expected_count) != BULK_RC_OK ||
        manifest->chunk_count != expected_count)
        return BULK_RC_MALFORMED;
    (void)expected_size;
    return BULK_RC_OK;
}

int bulk_manifest_validate_request(const bulk_manifest_t *manifest,
                                   const bulk_request_t *request)
{
    if (!request_valid(request) ||
        bulk_manifest_validate(manifest) != BULK_RC_OK)
        return BULK_RC_MALFORMED;
    if (manifest->transfer_id != request->transfer_id ||
        manifest->wire_budget != request->wire_budget)
        return BULK_RC_STATE;
    return BULK_RC_OK;
}

int bulk_chunk_extent(const bulk_manifest_t *manifest, uint32_t chunk_index,
                      uint64_t *offset, uint16_t *body_length)
{
    uint64_t start;
    uint64_t remaining;
    uint64_t chunk_size;

    if (offset == NULL || body_length == NULL ||
        bulk_manifest_validate(manifest) != BULK_RC_OK ||
        chunk_index >= manifest->chunk_count)
        return BULK_RC_ARGUMENT;
    start = (uint64_t)chunk_index << manifest->chunk_log2;
    if (start >= manifest->file_size)
        return BULK_RC_MALFORMED;
    remaining = manifest->file_size - start;
    chunk_size = UINT64_C(1) << manifest->chunk_log2;
    if (remaining > chunk_size)
        remaining = chunk_size;
    *offset = start;
    *body_length = (uint16_t)remaining;
    return BULK_RC_OK;
}

static int data_basic_valid(const bulk_data_view_t *record)
{
    return record != NULL && record->sender_leg < BULK_LEGS_MAX &&
           record->transfer_id != 0 && record->attempt_id != 0 &&
           record->chunk_index < BULK_CHUNKS_MAX &&
           record->body_length != 0 &&
           record->body_length <= BULK_CHUNK_MAX && record->body != NULL;
}

int bulk_data_validate(const bulk_data_view_t *data,
                       const bulk_manifest_t *manifest, uint8_t path_count)
{
    uint64_t offset;
    uint16_t expected_length;

    if (!data_basic_valid(data) || !path_count_valid(path_count) ||
        bulk_manifest_validate(manifest) != BULK_RC_OK)
        return BULK_RC_MALFORMED;
    if (data->transfer_id != manifest->transfer_id ||
        data->sender_leg >= path_count ||
        bulk_chunk_extent(manifest, data->chunk_index, &offset,
                          &expected_length) != BULK_RC_OK ||
        data->body_length != expected_length)
        return BULK_RC_STATE;
    (void)offset;
    return BULK_RC_OK;
}

static int ack_basic_valid(const bulk_ack_t *record)
{
    return record != NULL && record->transfer_id != 0 &&
           !bytes_zero(record->root, BULK_ROOT_BYTES) &&
           record->frontier <= BULK_CHUNKS_MAX &&
           record->page_word_base <= BULK_ACK_PAGE_MAX_BASE &&
           (record->page_word_base & (BULK_ACK_WORDS - 1U)) == 0;
}

static int status_valid(const bulk_status_t *record)
{
    int root_is_zero;
    int scan_phase;
    int error_phase;

    if (record == NULL || !phase_valid(record->phase) ||
        record->revision == 0 || record->transfer_id == 0)
        return 0;
    root_is_zero = bytes_zero(record->root, BULK_ROOT_BYTES);
    scan_phase = record->phase == BULK_PHASE_PREPARING ||
                 record->phase == BULK_PHASE_VERIFYING;
    error_phase = record->phase == BULK_PHASE_REFUSED ||
                  record->phase == BULK_PHASE_FAILED;
    if (error_phase) {
        if (record->code == BULK_CODE_NONE ||
            record->code > BULK_CODE_PACE_TOO_LOW ||
            record->processed_bytes != 0)
            return 0;
        if (root_is_zero && record->file_size != 0)
            return 0;
        if (record->phase == BULK_PHASE_REFUSED && !root_is_zero)
            return 0;
    } else if (record->code != BULK_CODE_NONE) {
        return 0;
    }
    if (!scan_phase && !error_phase && record->processed_bytes != 0)
        return 0;
    if (scan_phase && record->processed_bytes > record->file_size)
        return 0;
    if (record->phase == BULK_PHASE_VERIFYING && record->file_size == 0)
        return 0;
    if (record->phase == BULK_PHASE_PREPARING && !root_is_zero)
        return 0;
    if (record->phase != BULK_PHASE_PREPARING && !error_phase && root_is_zero)
        return 0;
    return 1;
}

int bulk_request_encode(const bulk_request_t *record, uint8_t *out,
                        size_t out_size, size_t *plaintext_length)
{
    size_t needed;

    if (!request_valid(record) || out == NULL || plaintext_length == NULL)
        return BULK_RC_MALFORMED;
    needed = BULK_REQUEST_PREFIX_BYTES + record->path_length;
    if (out_size < needed)
        return BULK_RC_RESOURCE;
    memset(out, 0, needed);
    out[0] = BULK_VERSION;
    out[1] = record->operation;
    out[2] = record->flags;
    store64_le(out + 4, record->transfer_id);
    store16_le(out + 12, record->wire_budget);
    store16_le(out + 14, record->path_length);
    memcpy(out + BULK_REQUEST_PREFIX_BYTES, record->path,
           record->path_length);
    *plaintext_length = needed;
    return BULK_RC_OK;
}

int bulk_request_decode(const uint8_t *plaintext, size_t plaintext_length,
                        bulk_request_t *record)
{
    bulk_request_t decoded;

    if (plaintext == NULL || record == NULL ||
        plaintext_length < BULK_REQUEST_PREFIX_BYTES ||
        plaintext_length > BULK_REQUEST_PLAINTEXT_MAX ||
        plaintext[0] != BULK_VERSION || plaintext[3] != 0)
        return BULK_RC_MALFORMED;
    memset(&decoded, 0, sizeof(decoded));
    decoded.operation = plaintext[1];
    decoded.flags = plaintext[2];
    decoded.transfer_id = load64_le(plaintext + 4);
    decoded.wire_budget = load16_le(plaintext + 12);
    decoded.path_length = load16_le(plaintext + 14);
    if (plaintext_length !=
            BULK_REQUEST_PREFIX_BYTES + (size_t)decoded.path_length ||
        decoded.path_length > BULK_PATH_MAX)
        return BULK_RC_MALFORMED;
    memcpy(decoded.path, plaintext + BULK_REQUEST_PREFIX_BYTES,
           decoded.path_length);
    if (!request_valid(&decoded))
        return BULK_RC_MALFORMED;
    *record = decoded;
    return BULK_RC_OK;
}

int bulk_manifest_encode(const bulk_manifest_t *record,
                         uint8_t out[BULK_MANIFEST_BYTES])
{
    if (out == NULL || bulk_manifest_validate(record) != BULK_RC_OK)
        return BULK_RC_MALFORMED;
    memset(out, 0, BULK_MANIFEST_BYTES);
    out[0] = BULK_VERSION;
    store64_le(out + 1, record->transfer_id);
    store64_le(out + 9, record->file_size);
    out[17] = record->chunk_log2;
    store32_le(out + 18, record->chunk_count);
    store16_le(out + 22, record->wire_budget);
    memcpy(out + 24, record->root, BULK_ROOT_BYTES);
    return BULK_RC_OK;
}

int bulk_manifest_decode(const uint8_t *plaintext, size_t plaintext_length,
                         bulk_manifest_t *record)
{
    bulk_manifest_t decoded;

    if (plaintext == NULL || record == NULL ||
        plaintext_length != BULK_MANIFEST_BYTES ||
        plaintext[0] != BULK_VERSION)
        return BULK_RC_MALFORMED;
    memset(&decoded, 0, sizeof(decoded));
    decoded.transfer_id = load64_le(plaintext + 1);
    decoded.file_size = load64_le(plaintext + 9);
    decoded.chunk_log2 = plaintext[17];
    decoded.chunk_count = load32_le(plaintext + 18);
    decoded.wire_budget = load16_le(plaintext + 22);
    memcpy(decoded.root, plaintext + 24, BULK_ROOT_BYTES);
    if (bulk_manifest_validate(&decoded) != BULK_RC_OK)
        return BULK_RC_MALFORMED;
    *record = decoded;
    return BULK_RC_OK;
}

int bulk_data_encode(const bulk_data_view_t *record, uint8_t *out,
                     size_t out_size, size_t *plaintext_length)
{
    size_t needed;

    if (!data_basic_valid(record) || out == NULL || plaintext_length == NULL)
        return BULK_RC_MALFORMED;
    needed = BULK_DATA_PREFIX_BYTES + record->body_length;
    if (out_size < needed)
        return BULK_RC_RESOURCE;
    memset(out, 0, BULK_DATA_PREFIX_BYTES);
    out[0] = BULK_VERSION;
    out[1] = record->sender_leg;
    store64_le(out + 2, record->transfer_id);
    store32_le(out + 10, record->chunk_index);
    store32_le(out + 14, record->attempt_id);
    store16_le(out + 18, record->body_length);
    memmove(out + BULK_DATA_PREFIX_BYTES, record->body,
            record->body_length);
    *plaintext_length = needed;
    return BULK_RC_OK;
}

int bulk_data_decode(const uint8_t *plaintext, size_t plaintext_length,
                     bulk_data_view_t *record)
{
    bulk_data_view_t decoded;

    if (plaintext == NULL || record == NULL ||
        plaintext_length < BULK_DATA_PREFIX_BYTES ||
        plaintext_length > BULK_DATA_PLAINTEXT_MAX ||
        plaintext[0] != BULK_VERSION)
        return BULK_RC_MALFORMED;
    memset(&decoded, 0, sizeof(decoded));
    decoded.sender_leg = plaintext[1];
    decoded.transfer_id = load64_le(plaintext + 2);
    decoded.chunk_index = load32_le(plaintext + 10);
    decoded.attempt_id = load32_le(plaintext + 14);
    decoded.body_length = load16_le(plaintext + 18);
    decoded.body = plaintext + BULK_DATA_PREFIX_BYTES;
    if (plaintext_length != BULK_DATA_PREFIX_BYTES + decoded.body_length ||
        !data_basic_valid(&decoded))
        return BULK_RC_MALFORMED;
    *record = decoded;
    return BULK_RC_OK;
}

int bulk_ack_encode(const bulk_ack_t *record,
                    uint8_t out[BULK_ACK_BYTES])
{
    size_t i;

    if (!ack_basic_valid(record) || out == NULL)
        return BULK_RC_MALFORMED;
    memset(out, 0, BULK_ACK_BYTES);
    out[0] = BULK_VERSION;
    store64_le(out + 1, record->transfer_id);
    memcpy(out + 9, record->root, BULK_ROOT_BYTES);
    store32_le(out + 41, record->frontier);
    store32_le(out + 45, record->page_word_base);
    for (i = 0; i < BULK_ACK_WORDS; i++)
        store64_le(out + 49 + i * 8U, record->words[i]);
    for (i = 0; i < BULK_LEGS_MAX; i++) {
        size_t offset = 177U + i * 12U;
        store32_le(out + offset, record->counters[i].chunks);
        store64_le(out + offset + 4U, record->counters[i].bytes);
    }
    return BULK_RC_OK;
}

int bulk_ack_decode(const uint8_t *plaintext, size_t plaintext_length,
                    bulk_ack_t *record)
{
    bulk_ack_t decoded;
    size_t i;

    if (plaintext == NULL || record == NULL ||
        plaintext_length != BULK_ACK_BYTES || plaintext[0] != BULK_VERSION)
        return BULK_RC_MALFORMED;
    memset(&decoded, 0, sizeof(decoded));
    decoded.transfer_id = load64_le(plaintext + 1);
    memcpy(decoded.root, plaintext + 9, BULK_ROOT_BYTES);
    decoded.frontier = load32_le(plaintext + 41);
    decoded.page_word_base = load32_le(plaintext + 45);
    for (i = 0; i < BULK_ACK_WORDS; i++)
        decoded.words[i] = load64_le(plaintext + 49 + i * 8U);
    for (i = 0; i < BULK_LEGS_MAX; i++) {
        size_t offset = 177U + i * 12U;
        decoded.counters[i].chunks = load32_le(plaintext + offset);
        decoded.counters[i].bytes = load64_le(plaintext + offset + 4U);
    }
    if (!ack_basic_valid(&decoded))
        return BULK_RC_MALFORMED;
    *record = decoded;
    return BULK_RC_OK;
}

int bulk_status_encode(const bulk_status_t *record,
                       uint8_t out[BULK_STATUS_BYTES])
{
    if (!status_valid(record) || out == NULL)
        return BULK_RC_MALFORMED;
    memset(out, 0, BULK_STATUS_BYTES);
    out[0] = BULK_VERSION;
    out[1] = record->phase;
    store16_le(out + 2, record->code);
    store64_le(out + 4, record->revision);
    store64_le(out + 12, record->transfer_id);
    memcpy(out + 20, record->root, BULK_ROOT_BYTES);
    store64_le(out + 52, record->file_size);
    store64_le(out + 60, record->processed_bytes);
    return BULK_RC_OK;
}

int bulk_status_decode(const uint8_t *plaintext, size_t plaintext_length,
                       bulk_status_t *record)
{
    bulk_status_t decoded;

    if (plaintext == NULL || record == NULL ||
        plaintext_length != BULK_STATUS_BYTES ||
        plaintext[0] != BULK_VERSION)
        return BULK_RC_MALFORMED;
    memset(&decoded, 0, sizeof(decoded));
    decoded.phase = plaintext[1];
    decoded.code = load16_le(plaintext + 2);
    decoded.revision = load64_le(plaintext + 4);
    decoded.transfer_id = load64_le(plaintext + 12);
    memcpy(decoded.root, plaintext + 20, BULK_ROOT_BYTES);
    decoded.file_size = load64_le(plaintext + 52);
    decoded.processed_bytes = load64_le(plaintext + 60);
    if (!status_valid(&decoded))
        return BULK_RC_MALFORMED;
    *record = decoded;
    return BULK_RC_OK;
}

static void hash_begin(crypto_blake2b_ctx *ctx, const uint8_t *domain,
                       size_t domain_length)
{
    crypto_blake2b_init(ctx, BULK_ROOT_BYTES);
    crypto_blake2b_update(ctx, domain, domain_length);
}

static void hash_u8(crypto_blake2b_ctx *ctx, uint8_t value)
{
    crypto_blake2b_update(ctx, &value, sizeof(value));
}

static void hash_u16(crypto_blake2b_ctx *ctx, uint16_t value)
{
    uint8_t encoded[2];
    store16_le(encoded, value);
    crypto_blake2b_update(ctx, encoded, sizeof(encoded));
}

static void hash_u32(crypto_blake2b_ctx *ctx, uint32_t value)
{
    uint8_t encoded[4];
    store32_le(encoded, value);
    crypto_blake2b_update(ctx, encoded, sizeof(encoded));
}

static void hash_u64(crypto_blake2b_ctx *ctx, uint64_t value)
{
    uint8_t encoded[8];
    store64_le(encoded, value);
    crypto_blake2b_update(ctx, encoded, sizeof(encoded));
}

static void merkle_real_leaf(const bulk_merkle_t *merkle, uint32_t index,
                             const uint8_t *body, uint16_t body_length,
                             uint8_t out[BULK_ROOT_BYTES])
{
    static const uint8_t domain[] = "unmoor-d33-leaf-v1";
    crypto_blake2b_ctx ctx;

    hash_begin(&ctx, domain, sizeof(domain) - 1U);
    hash_u64(&ctx, merkle->transfer_id);
    hash_u8(&ctx, merkle->chunk_log2);
    hash_u64(&ctx, merkle->file_size);
    hash_u32(&ctx, index);
    hash_u16(&ctx, body_length);
    crypto_blake2b_update(&ctx, body, body_length);
    crypto_blake2b_final(&ctx, out);
    crypto_memzero(&ctx, sizeof(ctx));
}

static void merkle_pad_leaf(const bulk_merkle_t *merkle, uint32_t index,
                            uint8_t out[BULK_ROOT_BYTES])
{
    static const uint8_t domain[] = "unmoor-d33-pad-v1";
    crypto_blake2b_ctx ctx;

    hash_begin(&ctx, domain, sizeof(domain) - 1U);
    hash_u64(&ctx, merkle->transfer_id);
    hash_u8(&ctx, merkle->chunk_log2);
    hash_u64(&ctx, merkle->file_size);
    hash_u32(&ctx, index);
    crypto_blake2b_final(&ctx, out);
    crypto_memzero(&ctx, sizeof(ctx));
}

static void merkle_empty(const bulk_merkle_t *merkle,
                         uint8_t out[BULK_ROOT_BYTES])
{
    static const uint8_t domain[] = "unmoor-d33-empty-v1";
    crypto_blake2b_ctx ctx;

    hash_begin(&ctx, domain, sizeof(domain) - 1U);
    hash_u64(&ctx, merkle->transfer_id);
    hash_u8(&ctx, merkle->chunk_log2);
    hash_u64(&ctx, UINT64_C(0));
    crypto_blake2b_final(&ctx, out);
    crypto_memzero(&ctx, sizeof(ctx));
}

static void merkle_parent(const bulk_merkle_t *merkle, uint8_t level,
                          const uint8_t left[BULK_ROOT_BYTES],
                          const uint8_t right[BULK_ROOT_BYTES],
                          uint8_t out[BULK_ROOT_BYTES])
{
    static const uint8_t domain[] = "unmoor-d33-parent-v1";
    crypto_blake2b_ctx ctx;

    hash_begin(&ctx, domain, sizeof(domain) - 1U);
    hash_u64(&ctx, merkle->transfer_id);
    hash_u8(&ctx, merkle->chunk_log2);
    hash_u64(&ctx, merkle->file_size);
    hash_u8(&ctx, level);
    crypto_blake2b_update(&ctx, left, BULK_ROOT_BYTES);
    crypto_blake2b_update(&ctx, right, BULK_ROOT_BYTES);
    crypto_blake2b_final(&ctx, out);
    crypto_memzero(&ctx, sizeof(ctx));
}

static int merkle_push_digest(bulk_merkle_t *merkle,
                              uint8_t digest[BULK_ROOT_BYTES])
{
    unsigned int level = 0;

    if (merkle == NULL || merkle->ready ||
        merkle->next_index >= merkle->capacity)
        return BULK_RC_STATE;
    while ((merkle->occupied_levels & (UINT32_C(1) << level)) != 0) {
        uint8_t parent[BULK_ROOT_BYTES];
        if (level + 1U >= 32U)
            return BULK_RC_RESOURCE;
        merkle_parent(merkle, (uint8_t)(level + 1U), merkle->stack[level],
                      digest, parent);
        merkle->occupied_levels &= ~(UINT32_C(1) << level);
        memcpy(digest, parent, sizeof(parent));
        crypto_memzero(parent, sizeof(parent));
        level++;
    }
    memcpy(merkle->stack[level], digest, BULK_ROOT_BYTES);
    merkle->occupied_levels |= UINT32_C(1) << level;
    merkle->next_index++;
    if (merkle->next_index == merkle->capacity)
        merkle->ready = 1U;
    return merkle->ready ? BULK_RC_OK : BULK_RC_MORE;
}

int bulk_merkle_init(bulk_merkle_t *merkle, uint64_t transfer_id,
                     uint64_t file_size, uint8_t chunk_log2,
                     uint32_t chunk_count)
{
    uint32_t expected_count;
    uint32_t capacity = 1U;

    if (merkle == NULL || transfer_id == 0 ||
        bulk_chunk_count(file_size, chunk_log2, &expected_count) != BULK_RC_OK ||
        expected_count != chunk_count)
        return BULK_RC_ARGUMENT;
    while (capacity < chunk_count)
        capacity <<= 1;
    memset(merkle, 0, sizeof(*merkle));
    merkle->transfer_id = transfer_id;
    merkle->file_size = file_size;
    merkle->chunk_log2 = chunk_log2;
    merkle->chunk_count = chunk_count;
    merkle->capacity = capacity;
    if (chunk_count == 0) {
        merkle_empty(merkle, merkle->stack[0]);
        merkle->occupied_levels = UINT32_C(1);
        merkle->next_index = 1U;
        merkle->ready = 1U;
    }
    return BULK_RC_OK;
}

int bulk_merkle_push_chunk(bulk_merkle_t *merkle, const uint8_t *body,
                           size_t body_length)
{
    uint64_t offset;
    uint64_t remaining;
    uint64_t chunk_size;
    uint16_t expected_length;
    uint8_t digest[BULK_ROOT_BYTES];
    int result;

    if (merkle == NULL || body == NULL || merkle->ready ||
        merkle->next_index >= merkle->chunk_count)
        return BULK_RC_STATE;
    offset = (uint64_t)merkle->next_index << merkle->chunk_log2;
    remaining = merkle->file_size - offset;
    chunk_size = UINT64_C(1) << merkle->chunk_log2;
    if (remaining > chunk_size)
        remaining = chunk_size;
    expected_length = (uint16_t)remaining;
    if (body_length != expected_length)
        return BULK_RC_MALFORMED;
    merkle_real_leaf(merkle, merkle->next_index, body, expected_length,
                     digest);
    result = merkle_push_digest(merkle, digest);
    crypto_memzero(digest, sizeof(digest));
    return result;
}

int bulk_merkle_push_pad(bulk_merkle_t *merkle)
{
    uint8_t digest[BULK_ROOT_BYTES];
    int result;

    if (merkle == NULL || merkle->ready ||
        merkle->next_index < merkle->chunk_count ||
        merkle->next_index >= merkle->capacity)
        return BULK_RC_STATE;
    merkle_pad_leaf(merkle, merkle->next_index, digest);
    result = merkle_push_digest(merkle, digest);
    crypto_memzero(digest, sizeof(digest));
    return result;
}

int bulk_merkle_root(const bulk_merkle_t *merkle,
                     uint8_t root[BULK_ROOT_BYTES])
{
    uint32_t occupied;
    unsigned int level = 0;

    if (merkle == NULL || root == NULL || !merkle->ready ||
        merkle->next_index != merkle->capacity)
        return BULK_RC_STATE;
    occupied = merkle->occupied_levels;
    if (occupied == 0 || (occupied & (occupied - 1U)) != 0)
        return BULK_RC_STATE;
    while ((occupied & UINT32_C(1)) == 0) {
        occupied >>= 1;
        level++;
    }
    memcpy(root, merkle->stack[level], BULK_ROOT_BYTES);
    if (bytes_zero(root, BULK_ROOT_BYTES)) {
        memset(root, 0, BULK_ROOT_BYTES);
        return BULK_RC_ROOT_MISMATCH;
    }
    return BULK_RC_OK;
}

static long runtime_page_size(void)
{
    long page_size = sysconf(_SC_PAGESIZE);

    if (page_size <= 0 ||
        (((unsigned long)page_size & ((unsigned long)page_size - 1UL)) != 0) ||
        (unsigned long)page_size < sizeof(void *))
        return -1;
    return page_size;
}

int bulk_bitmap_storage_alloc(void **storage_out)
{
    void *storage = NULL;
    long page_size;
    int result;

    if (storage_out == NULL)
        return BULK_RC_ARGUMENT;
    *storage_out = NULL;
    page_size = runtime_page_size();
    if (page_size < 0)
        return BULK_RC_RESOURCE;
    result = posix_memalign(&storage, (size_t)page_size, BULK_BITMAP_BYTES);
    if (result != 0) {
        errno = result;
        return BULK_RC_RESOURCE;
    }
    memset(storage, 0, BULK_BITMAP_BYTES);
    *storage_out = storage;
    return BULK_RC_OK;
}

void bulk_bitmap_storage_free(void *storage)
{
    free(storage);
}

int bulk_bitmap_init(bulk_bitmap_t *bitmap, void *storage,
                     size_t storage_bytes, const bulk_manifest_t *manifest)
{
    long page_size;

    if (bitmap == NULL || storage == NULL ||
        storage_bytes < BULK_BITMAP_BYTES ||
        bulk_manifest_validate(manifest) != BULK_RC_OK)
        return BULK_RC_ARGUMENT;
    page_size = runtime_page_size();
    if (page_size < 0 ||
        (uintptr_t)storage % (uintptr_t)page_size != 0)
        return BULK_RC_ARGUMENT;
    memset(storage, 0, BULK_BITMAP_BYTES);
    memset(bitmap, 0, sizeof(*bitmap));
    bitmap->words = (uint64_t *)storage;
    bitmap->storage_bytes = storage_bytes;
    bitmap->chunk_count = manifest->chunk_count;
    return BULK_RC_OK;
}

int bulk_bitmap_test(const bulk_bitmap_t *bitmap, uint32_t chunk_index)
{
    if (bitmap == NULL || bitmap->words == NULL ||
        bitmap->storage_bytes < BULK_BITMAP_BYTES ||
        chunk_index >= bitmap->chunk_count)
        return BULK_RC_ARGUMENT;
    return (int)((bitmap->words[chunk_index >> 6] >>
                  (chunk_index & 63U)) & UINT64_C(1));
}

static uint16_t chunk_length_unchecked(const bulk_manifest_t *manifest,
                                       uint32_t chunk_index)
{
    uint64_t offset = (uint64_t)chunk_index << manifest->chunk_log2;
    uint64_t remaining = manifest->file_size - offset;
    uint64_t chunk_size = UINT64_C(1) << manifest->chunk_log2;

    if (remaining > chunk_size)
        remaining = chunk_size;
    return (uint16_t)remaining;
}

int bulk_bitmap_mark_present(bulk_bitmap_t *bitmap,
                             const bulk_manifest_t *manifest,
                             uint32_t chunk_index, int *changed)
{
    uint64_t mask;
    uint64_t *word;

    if (bitmap == NULL || bitmap->words == NULL || changed == NULL ||
        bitmap->storage_bytes < BULK_BITMAP_BYTES ||
        bulk_manifest_validate(manifest) != BULK_RC_OK ||
        bitmap->chunk_count != manifest->chunk_count ||
        chunk_index >= bitmap->chunk_count)
        return BULK_RC_ARGUMENT;
    word = &bitmap->words[chunk_index >> 6];
    mask = UINT64_C(1) << (chunk_index & 63U);
    if ((*word & mask) != 0) {
        *changed = 0;
        return BULK_RC_DUPLICATE;
    }
    *word |= mask;
    bitmap->represented_chunks++;
    bitmap->represented_bytes += chunk_length_unchecked(manifest, chunk_index);
    while (bitmap->frontier < bitmap->chunk_count) {
        uint32_t index = bitmap->frontier;
        if ((bitmap->words[index >> 6] &
             (UINT64_C(1) << (index & 63U))) == 0)
            break;
        bitmap->frontier++;
    }
    *changed = 1;
    return BULK_RC_OK;
}

int bulk_ack_state_init(bulk_ack_state_t *state, void *storage,
                        size_t storage_bytes,
                        const bulk_manifest_t *manifest)
{
    int result;

    if (state == NULL)
        return BULK_RC_ARGUMENT;
    memset(state, 0, sizeof(*state));
    result = bulk_bitmap_init(&state->bitmap, storage, storage_bytes, manifest);
    if (result != BULK_RC_OK)
        memset(state, 0, sizeof(*state));
    return result;
}

static unsigned int popcount64(uint64_t value)
{
    unsigned int count = 0;

    while (value != 0) {
        value &= value - UINT64_C(1);
        count++;
    }
    return count;
}

static int page_stats(const bulk_manifest_t *manifest, uint32_t page_word_base,
                      const uint64_t words[BULK_ACK_WORDS],
                      uint32_t *chunks_out, uint64_t *bytes_out)
{
    uint32_t chunks = 0;
    uint64_t bytes = 0;
    size_t word_index;

    if (manifest == NULL || words == NULL || chunks_out == NULL ||
        bytes_out == NULL)
        return BULK_RC_ARGUMENT;
    for (word_index = 0; word_index < BULK_ACK_WORDS; word_index++) {
        uint64_t word = words[word_index];
        unsigned int bit;

        chunks += popcount64(word);
        for (bit = 0; bit < 64U; bit++) {
            uint32_t chunk_index;
            if ((word & (UINT64_C(1) << bit)) == 0)
                continue;
            chunk_index = ((page_word_base + (uint32_t)word_index) << 6) + bit;
            if (chunk_index >= manifest->chunk_count)
                return BULK_RC_MALFORMED;
            bytes += chunk_length_unchecked(manifest, chunk_index);
        }
    }
    *chunks_out = chunks;
    *bytes_out = bytes;
    return BULK_RC_OK;
}

static uint64_t frontier_bytes(const bulk_manifest_t *manifest,
                               uint32_t frontier)
{
    uint64_t bytes = (uint64_t)frontier << manifest->chunk_log2;

    if (bytes > manifest->file_size)
        bytes = manifest->file_size;
    return bytes;
}

static int counter_sums(const bulk_leg_counter_t counters[BULK_LEGS_MAX],
                        const bulk_manifest_t *manifest, uint8_t path_count,
                        uint64_t *chunks_out, uint64_t *bytes_out)
{
    uint64_t chunks = 0;
    uint64_t bytes = 0;
    uint64_t chunk_size = UINT64_C(1) << manifest->chunk_log2;
    size_t i;

    for (i = 0; i < BULK_LEGS_MAX; i++) {
        uint32_t component_chunks = counters[i].chunks;
        uint64_t component_bytes = counters[i].bytes;

        if (i >= path_count) {
            if (component_chunks != 0 || component_bytes != 0)
                return BULK_RC_MALFORMED;
            continue;
        }
        if (component_chunks > manifest->chunk_count ||
            component_bytes > manifest->file_size ||
            (component_chunks == 0 && component_bytes != 0) ||
            (component_chunks != 0 &&
             (component_bytes < component_chunks ||
              component_bytes > (uint64_t)component_chunks * chunk_size)))
            return BULK_RC_MALFORMED;
        chunks += component_chunks;
        bytes += component_bytes;
        if (chunks > manifest->chunk_count || bytes > manifest->file_size)
            return BULK_RC_MALFORMED;
    }
    *chunks_out = chunks;
    *bytes_out = bytes;
    return BULK_RC_OK;
}

int bulk_ack_validate(const bulk_ack_t *ack,
                      const bulk_manifest_t *manifest, uint8_t path_count)
{
    uint32_t page_chunks;
    uint64_t page_bytes;
    uint64_t counter_chunks;
    uint64_t counter_bytes;
    size_t word_index;

    if (!ack_basic_valid(ack) || !path_count_valid(path_count) ||
        bulk_manifest_validate(manifest) != BULK_RC_OK)
        return BULK_RC_MALFORMED;
    if (ack->transfer_id != manifest->transfer_id ||
        crypto_verify32_exact(ack->root, manifest->root) != 0 ||
        ack->frontier > manifest->chunk_count)
        return BULK_RC_STATE;
    if (manifest->chunk_count == 0) {
        if (ack->page_word_base != 0 || ack->frontier != 0)
            return BULK_RC_MALFORMED;
    } else if (((uint64_t)ack->page_word_base << 6) >=
               manifest->chunk_count) {
        return BULK_RC_MALFORMED;
    }

    for (word_index = 0; word_index < BULK_ACK_WORDS; word_index++) {
        uint64_t word = ack->words[word_index];
        unsigned int bit;

        for (bit = 0; bit < 64U; bit++) {
            uint32_t chunk_index =
                ((ack->page_word_base + (uint32_t)word_index) << 6) + bit;
            int is_set = (word & (UINT64_C(1) << bit)) != 0;

            if (chunk_index >= manifest->chunk_count) {
                if (is_set)
                    return BULK_RC_MALFORMED;
                continue;
            }
            if (chunk_index < ack->frontier && !is_set)
                return BULK_RC_MALFORMED;
            if (chunk_index == ack->frontier &&
                ack->frontier < manifest->chunk_count && is_set)
                return BULK_RC_MALFORMED;
        }
    }
    if (page_stats(manifest, ack->page_word_base, ack->words,
                   &page_chunks, &page_bytes) != BULK_RC_OK ||
        counter_sums(ack->counters, manifest, path_count,
                     &counter_chunks, &counter_bytes) != BULK_RC_OK)
        return BULK_RC_MALFORMED;
    if (counter_chunks < ack->frontier || counter_chunks < page_chunks ||
        counter_bytes < frontier_bytes(manifest, ack->frontier) ||
        counter_bytes < page_bytes)
        return BULK_RC_MALFORMED;
    return BULK_RC_OK;
}

int bulk_ack_snapshot(const bulk_bitmap_t *bitmap,
                      const bulk_leg_counter_t counters[BULK_LEGS_MAX],
                      const bulk_manifest_t *manifest, uint8_t path_count,
                      uint32_t page_word_base, bulk_ack_t *ack)
{
    bulk_ack_t snapshot;
    uint64_t counter_chunks;
    uint64_t counter_bytes;
    size_t i;

    if (bitmap == NULL || manifest == NULL || bitmap->words == NULL ||
        counters == NULL || ack == NULL ||
        bitmap->storage_bytes < BULK_BITMAP_BYTES ||
        bitmap->chunk_count != manifest->chunk_count ||
        page_word_base > BULK_ACK_PAGE_MAX_BASE ||
        (page_word_base & (BULK_ACK_WORDS - 1U)) != 0 ||
        bulk_manifest_validate(manifest) != BULK_RC_OK ||
        !path_count_valid(path_count))
        return BULK_RC_ARGUMENT;
    if ((manifest->chunk_count == 0 && page_word_base != 0) ||
        (manifest->chunk_count != 0 &&
         ((uint64_t)page_word_base << 6) >= manifest->chunk_count))
        return BULK_RC_ARGUMENT;
    if (counter_sums(counters, manifest, path_count, &counter_chunks,
                     &counter_bytes) != BULK_RC_OK ||
        counter_chunks != bitmap->represented_chunks ||
        counter_bytes != bitmap->represented_bytes)
        return BULK_RC_STATE;

    memset(&snapshot, 0, sizeof(snapshot));
    snapshot.transfer_id = manifest->transfer_id;
    memcpy(snapshot.root, manifest->root, BULK_ROOT_BYTES);
    snapshot.frontier = bitmap->frontier;
    snapshot.page_word_base = page_word_base;
    for (i = 0; i < BULK_ACK_WORDS; i++)
        snapshot.words[i] = bitmap->words[page_word_base + i];
    memcpy(snapshot.counters, counters, sizeof(snapshot.counters));
    if (bulk_ack_validate(&snapshot, manifest, path_count) != BULK_RC_OK)
        return BULK_RC_STATE;
    *ack = snapshot;
    return BULK_RC_OK;
}

int bulk_ack_merge(bulk_ack_state_t *state, const bulk_ack_t *ack,
                   const bulk_manifest_t *manifest, uint8_t path_count)
{
    uint64_t merged_words[BULK_ACK_WORDS];
    bulk_leg_counter_t merged_counters[BULK_LEGS_MAX];
    uint32_t delta_chunks = 0;
    uint64_t delta_bytes = 0;
    uint64_t counter_chunks;
    uint64_t counter_bytes;
    uint32_t merged_frontier;
    int changed = 0;
    int stale = 0;
    size_t i;

    if (state == NULL || manifest == NULL || state->bitmap.words == NULL ||
        state->bitmap.storage_bytes < BULK_BITMAP_BYTES ||
        state->bitmap.chunk_count != manifest->chunk_count)
        return BULK_RC_ARGUMENT;
    if (bulk_ack_validate(ack, manifest, path_count) != BULK_RC_OK)
        return BULK_RC_MALFORMED;

    for (i = 0; i < BULK_ACK_WORDS; i++) {
        uint64_t old_word =
            state->bitmap.words[ack->page_word_base + (uint32_t)i];
        uint64_t new_bits = ack->words[i] & ~old_word;
        unsigned int bit;

        if ((old_word & ~ack->words[i]) != 0)
            stale = 1;
        merged_words[i] = old_word | ack->words[i];
        if (new_bits != 0)
            changed = 1;
        delta_chunks += popcount64(new_bits);
        for (bit = 0; bit < 64U; bit++) {
            uint32_t chunk_index;
            if ((new_bits & (UINT64_C(1) << bit)) == 0)
                continue;
            chunk_index = ((ack->page_word_base + (uint32_t)i) << 6) + bit;
            delta_bytes += chunk_length_unchecked(manifest, chunk_index);
        }
    }
    merged_frontier = state->bitmap.frontier;
    if (ack->frontier < merged_frontier)
        stale = 1;
    else if (ack->frontier > merged_frontier) {
        merged_frontier = ack->frontier;
        changed = 1;
    }
    for (i = 0; i < BULK_LEGS_MAX; i++) {
        merged_counters[i] = state->counters[i];
        if (ack->counters[i].chunks < state->counters[i].chunks ||
            ack->counters[i].bytes < state->counters[i].bytes)
            stale = 1;
        if (ack->counters[i].chunks > merged_counters[i].chunks) {
            merged_counters[i].chunks = ack->counters[i].chunks;
            changed = 1;
        }
        if (ack->counters[i].bytes > merged_counters[i].bytes) {
            merged_counters[i].bytes = ack->counters[i].bytes;
            changed = 1;
        }
    }
    if (counter_sums(merged_counters, manifest, path_count, &counter_chunks,
                     &counter_bytes) != BULK_RC_OK ||
        counter_chunks <
            (uint64_t)state->bitmap.represented_chunks + delta_chunks ||
        counter_bytes < state->bitmap.represented_bytes + delta_bytes)
        return BULK_RC_MALFORMED;

    for (i = 0; i < BULK_ACK_WORDS; i++)
        state->bitmap.words[ack->page_word_base + (uint32_t)i] =
            merged_words[i];
    state->bitmap.frontier = merged_frontier;
    state->bitmap.represented_chunks += delta_chunks;
    state->bitmap.represented_bytes += delta_bytes;
    memcpy(state->counters, merged_counters, sizeof(merged_counters));
    if (changed)
        return BULK_RC_PROGRESS;
    return stale ? BULK_RC_STALE : BULK_RC_DUPLICATE;
}

static int identity_from_stat(const struct stat *st,
                              bulk_source_identity_t *identity)
{
    if (st == NULL || identity == NULL || st->st_size < 0)
        return BULK_RC_MALFORMED;
    memset(identity, 0, sizeof(*identity));
    identity->device = (uint64_t)st->st_dev;
    identity->inode = (uint64_t)st->st_ino;
    identity->size = (uint64_t)st->st_size;
#ifdef __APPLE__
    identity->mtime_seconds = (int64_t)st->st_mtimespec.tv_sec;
    identity->mtime_nanoseconds = (int64_t)st->st_mtimespec.tv_nsec;
#else
    identity->mtime_seconds = (int64_t)st->st_mtim.tv_sec;
    identity->mtime_nanoseconds = (int64_t)st->st_mtim.tv_nsec;
#endif
    return BULK_RC_OK;
}

static int identity_equal(const bulk_source_identity_t *left,
                          const bulk_source_identity_t *right)
{
    return left->device == right->device && left->inode == right->inode &&
           left->size == right->size &&
           left->mtime_seconds == right->mtime_seconds &&
           left->mtime_nanoseconds == right->mtime_nanoseconds;
}

static int read_exact_at(int fd, uint8_t *out, size_t length, uint64_t offset,
                         int short_result)
{
    size_t done = 0;

    if (fd < 0 || out == NULL || offset > (uint64_t)INT64_MAX ||
        length > (size_t)INT64_MAX ||
        offset + length < offset ||
        offset + length > (uint64_t)INT64_MAX)
        return BULK_RC_ARGUMENT;
    while (done < length) {
        ssize_t n = pread(fd, out + done, length - done,
                          (off_t)(offset + done));
        if (n > 0) {
            done += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        if (n == 0)
            return short_result;
        return BULK_RC_IO;
    }
    return BULK_RC_OK;
}

static int write_exact_at(int fd, const uint8_t *data, size_t length,
                          uint64_t offset)
{
    size_t done = 0;

    if (fd < 0 || data == NULL || offset > (uint64_t)INT64_MAX ||
        length > (size_t)INT64_MAX ||
        offset + length < offset ||
        offset + length > (uint64_t)INT64_MAX)
        return BULK_RC_ARGUMENT;
    while (done < length) {
        ssize_t n = pwrite(fd, data + done, length - done,
                           (off_t)(offset + done));
        if (n > 0) {
            done += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        if (n == 0)
            errno = EIO;
        return BULK_RC_IO;
    }
    return BULK_RC_OK;
}

static int ranges_overlap(const void *left, size_t left_length,
                          const void *right, size_t right_length)
{
    uintptr_t left_start = (uintptr_t)left;
    uintptr_t right_start = (uintptr_t)right;
    uintptr_t left_end;
    uintptr_t right_end;

    if (left_length == 0 || right_length == 0)
        return 0;
    if (left_start > UINTPTR_MAX - left_length ||
        right_start > UINTPTR_MAX - right_length)
        return 1;
    left_end = left_start + left_length;
    right_end = right_start + right_length;
    return left_start < right_end && right_start < left_end;
}

static int bitmap_complete(const bulk_bitmap_t *bitmap)
{
    uint32_t full_words;
    uint32_t tail_bits;
    uint32_t i;

    if (bitmap == NULL || bitmap->words == NULL ||
        bitmap->storage_bytes < BULK_BITMAP_BYTES)
        return 0;
    full_words = bitmap->chunk_count >> 6;
    tail_bits = bitmap->chunk_count & 63U;
    for (i = 0; i < full_words; i++) {
        if (bitmap->words[i] != UINT64_MAX)
            return 0;
    }
    if (tail_bits != 0) {
        uint64_t mask = (UINT64_C(1) << tail_bits) - UINT64_C(1);
        if (bitmap->words[full_words] != mask)
            return 0;
    }
    return 1;
}

void bulk_source_init(bulk_source_t *source)
{
    if (source == NULL)
        return;
    memset(source, 0, sizeof(*source));
    source->fd = -1;
}

int bulk_source_open(bulk_source_t *source, const char *path,
                     uint8_t chunk_log2)
{
    struct stat st;
    bulk_source_identity_t identity;
    uint32_t chunk_count;
    int fd;
    int saved_errno;

    if (source == NULL || path == NULL || path[0] == '\0' || source->fd != -1 ||
        chunk_log2 < BULK_CHUNK_LOG2_MIN ||
        chunk_log2 > BULK_CHUNK_LOG2_MAX)
        return BULK_RC_ARGUMENT;
    /* O_NONBLOCK is inert for regular files and prevents a hostile FIFO path
     * from blocking the sole event loop before fstat can reject it. */
    fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0)
        return BULK_RC_IO;
    if (unmoor_fd_stat(fd, &st) != 0) {
        saved_errno = errno;
        (void)close(fd);
        errno = saved_errno;
        return BULK_RC_IO;
    }
    if (!S_ISREG(st.st_mode) ||
        identity_from_stat(&st, &identity) != BULK_RC_OK) {
        saved_errno = EINVAL;
        (void)close(fd);
        errno = saved_errno;
        return BULK_RC_MALFORMED;
    }
    if (bulk_chunk_count(identity.size, chunk_log2, &chunk_count) !=
        BULK_RC_OK) {
        saved_errno = EFBIG;
        (void)close(fd);
        errno = saved_errno;
        return BULK_RC_RESOURCE;
    }
    source->fd = fd;
    source->chunk_log2 = chunk_log2;
    source->chunk_count = chunk_count;
    source->identity = identity;
    return BULK_RC_OK;
}

int bulk_source_read_chunk(const bulk_source_t *source,
                           const bulk_manifest_t *manifest,
                           uint32_t chunk_index, uint8_t *body,
                           size_t body_size, size_t *body_length)
{
    uint64_t offset;
    uint16_t expected_length;
    int result;

    if (source == NULL || manifest == NULL || source->fd < 0 || body == NULL ||
        body_length == NULL ||
        bulk_manifest_validate(manifest) != BULK_RC_OK ||
        source->identity.size != manifest->file_size ||
        source->chunk_log2 != manifest->chunk_log2 ||
        source->chunk_count != manifest->chunk_count ||
        bulk_chunk_extent(manifest, chunk_index, &offset, &expected_length) !=
            BULK_RC_OK ||
        body_size < expected_length)
        return BULK_RC_ARGUMENT;
    result = read_exact_at(source->fd, body, expected_length, offset,
                           BULK_RC_SOURCE_CHANGED);
    if (result != BULK_RC_OK)
        return result;
    *body_length = expected_length;
    return BULK_RC_OK;
}

int bulk_source_check_unchanged(const bulk_source_t *source)
{
    struct stat st;
    bulk_source_identity_t current;

    if (source == NULL || source->fd < 0)
        return BULK_RC_ARGUMENT;
    if (unmoor_fd_stat(source->fd, &st) != 0)
        return BULK_RC_IO;
    if (!S_ISREG(st.st_mode) ||
        identity_from_stat(&st, &current) != BULK_RC_OK ||
        !identity_equal(&source->identity, &current))
        return BULK_RC_SOURCE_CHANGED;
    return BULK_RC_OK;
}

int bulk_source_close(bulk_source_t *source)
{
    int fd;

    if (source == NULL)
        return BULK_RC_ARGUMENT;
    if (source->fd < 0)
        return BULK_RC_OK;
    fd = source->fd;
    source->fd = -1;
    return close(fd) == 0 ? BULK_RC_OK : BULK_RC_IO;
}

void bulk_sink_init(bulk_sink_t *sink)
{
    if (sink == NULL)
        return;
    memset(sink, 0, sizeof(*sink));
    sink->dirfd = -1;
    sink->temp_fd = -1;
}

static int temp_name_generate(char out[BULK_TEMP_NAME_BYTES])
{
    static const char prefix[] = ".unmoor-bulk-";
    static const char hex[] = "0123456789abcdef";
    uint8_t random[BULK_TEMP_RANDOM_BYTES];
    size_t i;

    if (crypto_random_bytes(random, sizeof(random)) != 0)
        return BULK_RC_RESOURCE;
    memcpy(out, prefix, sizeof(prefix) - 1U);
    for (i = 0; i < sizeof(random); i++) {
        out[sizeof(prefix) - 1U + i * 2U] = hex[random[i] >> 4];
        out[sizeof(prefix) + i * 2U] = hex[random[i] & 0x0fU];
    }
    out[sizeof(prefix) - 1U + sizeof(random) * 2U] = '\0';
    crypto_memzero(random, sizeof(random));
    return BULK_RC_OK;
}

static int new_temp_valid(int fd)
{
    struct stat st;

    if (unmoor_fd_stat(fd, &st) != 0)
        return BULK_RC_IO;
    if (!S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
        (st.st_mode & (mode_t)07777) != (mode_t)0600 || st.st_nlink != 1) {
        errno = EPERM;
        return BULK_RC_IO;
    }
    return BULK_RC_OK;
}

/* O_EXCL makes this a new inode, so a private creation mask is sufficient to
 * establish the exact 0600 mode without a later fchmod().  This also lets the
 * late bulk-server seccomp role omit every unscoped permission-changing
 * syscall.  The engine is single-threaded; restore the caller's mask before
 * returning and preserve openat()'s errno. */
static int open_private_temp_at(int dirfd, const char *name)
{
    mode_t saved_mask;
    int saved_errno;
    int fd;

    saved_mask = umask((mode_t)0077);
    fd = openat(dirfd, name,
                O_CREAT | O_EXCL | O_RDWR | O_NOFOLLOW | O_CLOEXEC,
                (mode_t)0600);
    saved_errno = errno;
    (void)umask(saved_mask);
    errno = saved_errno;
    return fd;
}

int bulk_sink_prepare(bulk_sink_t *sink, const uint8_t *path,
                      size_t path_length, uint64_t file_size,
                      char scratch[BULK_PATH_SCRATCH_BYTES])
{
    const char *parent;
    const char *basename;
    size_t last_slash = SIZE_MAX;
    size_t i;
    struct stat dir_stat;
    int dirfd = -1;
    int temp_fd = -1;
    unsigned int attempt;
    int result = BULK_RC_IO;
    int saved_errno;

    if (sink == NULL || scratch == NULL ||
        !bulk_remote_path_valid(path, path_length) ||
        sink->dirfd != -1 || sink->temp_fd != -1 || sink->temp_named ||
        sink->installed)
        return BULK_RC_ARGUMENT;
    memcpy(scratch, path, path_length);
    scratch[path_length] = '\0';
    for (i = 0; i < path_length; i++) {
        if (path[i] == (uint8_t)'/')
            last_slash = i;
    }
    if (last_slash == SIZE_MAX) {
        parent = ".";
        basename = scratch;
    } else if (last_slash == 0) {
        parent = "/";
        basename = scratch + 1;
    } else {
        scratch[last_slash] = '\0';
        parent = scratch;
        basename = scratch + last_slash + 1U;
    }
    if (strlen(basename) > BULK_PATH_MAX)
        return BULK_RC_ARGUMENT;
    memcpy(sink->destination, basename, strlen(basename) + 1U);

    dirfd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd < 0)
        goto fail;
    if (unmoor_fd_stat(dirfd, &dir_stat) != 0 || !S_ISDIR(dir_stat.st_mode))
        goto fail;
    sink->dirfd = dirfd;
    dirfd = -1;
    sink->file_size = file_size;

    for (attempt = 0; attempt < BULK_TEMP_ATTEMPTS; attempt++) {
        result = temp_name_generate(sink->temp_name);
        if (result != BULK_RC_OK)
            goto fail;
        if (strcmp(sink->temp_name, sink->destination) == 0)
            continue;
        temp_fd = open_private_temp_at(sink->dirfd, sink->temp_name);
        if (temp_fd >= 0)
            break;
        if (errno != EEXIST)
            goto fail;
    }
    if (temp_fd < 0) {
        errno = EEXIST;
        result = BULK_RC_RESOURCE;
        goto fail;
    }
    sink->temp_fd = temp_fd;
    sink->temp_named = 1U;
    temp_fd = -1;
    if (new_temp_valid(sink->temp_fd) != BULK_RC_OK)
        goto fail;
    return BULK_RC_OK;

fail:
    saved_errno = errno;
    if (temp_fd >= 0)
        (void)close(temp_fd);
    if (dirfd >= 0)
        (void)close(dirfd);
    if (sink->dirfd >= 0 || sink->temp_fd >= 0)
        (void)bulk_sink_cleanup(sink);
    errno = saved_errno;
    return result;
}

int bulk_sink_admit_chunk(bulk_sink_t *sink, bulk_bitmap_t *bitmap,
                          const bulk_manifest_t *manifest,
                          uint32_t chunk_index, const uint8_t *body,
                          size_t body_length,
                          uint8_t duplicate_scratch[BULK_CHUNK_MAX],
                          int *newly_admitted)
{
    uint64_t offset;
    uint16_t expected_length;
    int present;
    int changed;
    int result;

    if (sink == NULL || bitmap == NULL || manifest == NULL || body == NULL ||
        duplicate_scratch == NULL || newly_admitted == NULL ||
        sink->temp_fd < 0 || sink->dirfd < 0 || sink->installed ||
        sink->file_size != manifest->file_size ||
        bitmap->chunk_count != manifest->chunk_count ||
        bulk_chunk_extent(manifest, chunk_index, &offset, &expected_length) !=
            BULK_RC_OK ||
        body_length != expected_length ||
        ranges_overlap(body, body_length, duplicate_scratch,
                       BULK_CHUNK_MAX))
        return BULK_RC_ARGUMENT;
    present = bulk_bitmap_test(bitmap, chunk_index);
    if (present < 0)
        return present;
    if (present != 0) {
        result = read_exact_at(sink->temp_fd, duplicate_scratch,
                               expected_length, offset, BULK_RC_DIVERGED);
        if (result != BULK_RC_OK)
            return result;
        if (memcmp(duplicate_scratch, body, expected_length) != 0)
            return BULK_RC_DIVERGED;
        *newly_admitted = 0;
        return BULK_RC_DUPLICATE;
    }

    result = write_exact_at(sink->temp_fd, body, expected_length, offset);
    if (result != BULK_RC_OK)
        return result;
    result = bulk_bitmap_mark_present(bitmap, manifest, chunk_index, &changed);
    if (result != BULK_RC_OK || !changed)
        return BULK_RC_STATE;
    *newly_admitted = 1;
    return BULK_RC_OK;
}

int bulk_sink_read_chunk(const bulk_sink_t *sink,
                         const bulk_manifest_t *manifest,
                         uint32_t chunk_index, uint8_t *body,
                         size_t body_size, size_t *body_length)
{
    uint64_t offset;
    uint16_t expected_length;
    int result;

    if (sink == NULL || manifest == NULL || sink->temp_fd < 0 || body == NULL ||
        body_length == NULL || sink->file_size != manifest->file_size ||
        bulk_chunk_extent(manifest, chunk_index, &offset, &expected_length) !=
            BULK_RC_OK ||
        body_size < expected_length)
        return BULK_RC_ARGUMENT;
    result = read_exact_at(sink->temp_fd, body, expected_length, offset,
                           BULK_RC_DIVERGED);
    if (result != BULK_RC_OK)
        return result;
    *body_length = expected_length;
    return BULK_RC_OK;
}

int bulk_sink_install(bulk_sink_t *sink, const bulk_bitmap_t *bitmap,
                      const bulk_manifest_t *manifest, int force,
                      const uint8_t computed_root[BULK_ROOT_BYTES])
{
    struct stat st;

    if (sink == NULL || bitmap == NULL || manifest == NULL ||
        computed_root == NULL || (force != 0 && force != 1) ||
        sink->dirfd < 0 || sink->temp_fd < 0 || !sink->temp_named ||
        sink->installed || bitmap->words == NULL ||
        bitmap->chunk_count != manifest->chunk_count ||
        sink->file_size != manifest->file_size ||
        bulk_manifest_validate(manifest) != BULK_RC_OK)
        return BULK_RC_ARGUMENT;
    if (!bitmap_complete(bitmap) ||
        bitmap->frontier != manifest->chunk_count ||
        bitmap->represented_chunks != manifest->chunk_count ||
        bitmap->represented_bytes != manifest->file_size)
        return BULK_RC_STATE;
    if (bytes_zero(computed_root, BULK_ROOT_BYTES) ||
        crypto_verify32_exact(computed_root, manifest->root) != 0)
        return BULK_RC_ROOT_MISMATCH;
    if (unmoor_fd_stat(sink->temp_fd, &st) != 0)
        return BULK_RC_IO;
    if (!S_ISREG(st.st_mode) || st.st_size < 0 ||
        (uint64_t)st.st_size != manifest->file_size) {
        errno = EIO;
        return BULK_RC_IO;
    }

    if (sink_sync_temp_file(sink->temp_fd) != 0)
        return BULK_RC_IO;
    if (sink_install_step(SINK_INSTALL_NAMESPACE) != 0)
        return BULK_RC_IO;

    if (force) {
        if (renameat(sink->dirfd, sink->temp_name, sink->dirfd,
                     sink->destination) != 0)
            return BULK_RC_IO;
        sink->installed = 1U;
        sink->temp_named = 0U;
    } else {
        if (linkat(sink->dirfd, sink->temp_name, sink->dirfd,
                   sink->destination, 0) != 0)
            return errno == EEXIST ? BULK_RC_EXISTS : BULK_RC_IO;
        sink->installed = 1U;
        if (unlinkat(sink->dirfd, sink->temp_name, 0) != 0)
            return BULK_RC_IO;
        sink->temp_named = 0U;
    }
    if (sink_sync_directory(sink->dirfd) != 0)
        return BULK_RC_IO;
    return BULK_RC_OK;
}

int bulk_sink_cleanup(bulk_sink_t *sink)
{
    int result = BULK_RC_OK;
    int saved_errno = 0;
    int fd;

    if (sink == NULL)
        return BULK_RC_ARGUMENT;
    if (sink->temp_named && sink->dirfd < 0) {
        result = BULK_RC_IO;
        saved_errno = EBADF;
    }
    if (sink->temp_named && sink->dirfd >= 0) {
        if (unlinkat(sink->dirfd, sink->temp_name, 0) == 0 ||
            errno == ENOENT) {
            sink->temp_named = 0U;
        } else {
            result = BULK_RC_IO;
            saved_errno = errno;
        }
    }
    if (sink->temp_fd >= 0) {
        fd = sink->temp_fd;
        sink->temp_fd = -1;
        if (close(fd) != 0 && result == BULK_RC_OK) {
            result = BULK_RC_IO;
            saved_errno = errno;
        }
    }
    if (sink->dirfd >= 0) {
        fd = sink->dirfd;
        sink->dirfd = -1;
        if (close(fd) != 0 && result == BULK_RC_OK) {
            result = BULK_RC_IO;
            saved_errno = errno;
        }
    }
    if (saved_errno != 0)
        errno = saved_errno;
    return result;
}
