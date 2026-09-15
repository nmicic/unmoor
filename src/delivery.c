/*
 * delivery.c — delivery-class bounded non-terminal delivery engines
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */

#define _POSIX_C_SOURCE 200809L

#include "delivery.h"

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "monocypher.h"

_Static_assert(DELIVERY_LATEST_SNAPSHOT_BYTES_MAX == 10240U,
               "delivery-class latest snapshot cap changed");
_Static_assert(DELIVERY_LATEST_BLOCK_WIRE_MAX == 216U,
               "delivery-class latest block wire bound changed");
_Static_assert(DELIVERY_RELIABLE_DATA_WIRE_MAX == 208U,
               "delivery-class reliable wire bound changed");
_Static_assert(DELIVERY_LATEST_OBJECTS * DELIVERY_LATEST_SNAPSHOT_SLOTS == 12U,
               "delivery-class sender record cap changed");
_Static_assert(DELIVERY_LATEST_AGGREGATE_BYTES >=
                   DELIVERY_LATEST_SNAPSHOT_BYTES_MAX,
               "one maximum latest snapshot must fit");
_Static_assert(sizeof(delivery_latest_snapshot_t) <=
                   DELIVERY_LATEST_SNAPSHOT_STATE_BYTES_MAX,
               "latest snapshot metadata ceiling exceeded");
_Static_assert(sizeof(delivery_latest_sender_object_t) <=
                   DELIVERY_LATEST_SENDER_OBJECT_STATE_BYTES_MAX,
               "latest sender-object state ceiling exceeded");
_Static_assert(sizeof(delivery_latest_sender_t) <=
                   DELIVERY_LATEST_SENDER_STATE_BYTES_MAX,
               "latest sender state ceiling exceeded");
_Static_assert(sizeof(delivery_latest_receiver_object_t) <=
                   DELIVERY_LATEST_RECEIVER_OBJECT_STATE_BYTES_MAX,
               "latest receiver-object state ceiling exceeded");
_Static_assert(sizeof(delivery_latest_receiver_t) <=
                   DELIVERY_LATEST_RECEIVER_STATE_BYTES_MAX,
               "latest receiver state ceiling exceeded");
_Static_assert(sizeof(delivery_reliable_sender_t) <=
                   DELIVERY_RELIABLE_SENDER_STATE_BYTES_MAX,
               "reliable sender state ceiling exceeded");
_Static_assert(sizeof(delivery_reliable_receiver_t) <=
                   DELIVERY_RELIABLE_RECEIVER_STATE_BYTES_MAX,
               "reliable receiver state ceiling exceeded");

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

    for (i = 0; i < length; i++)
        aggregate |= bytes[i];
    return aggregate == 0;
}

static int hash_equal(const uint8_t a[DELIVERY_HASH_BYTES],
                      const uint8_t b[DELIVERY_HASH_BYTES])
{
    return crypto_verify32(a, b) == 0;
}

static int mode_valid(delivery_mode_t mode)
{
    return mode >= DELIVERY_MODE_ACTIVE &&
           mode <= DELIVERY_MODE_NOT_INTERESTED;
}

static uint16_t latest_block_count(size_t length)
{
    if (length == 0)
        return 1;
    return (uint16_t)((length + DELIVERY_LATEST_BLOCK_BODY_MAX - 1U) /
                      DELIVERY_LATEST_BLOCK_BODY_MAX);
}

static uint16_t latest_expected_body(uint32_t total_length,
                                     uint16_t block_count,
                                     uint16_t block_index)
{
    size_t offset;
    size_t remaining;

    if (block_count == 0 || block_index >= block_count)
        return UINT16_MAX;
    offset = (size_t)block_index * DELIVERY_LATEST_BLOCK_BODY_MAX;
    if (offset > total_length)
        return UINT16_MAX;
    remaining = (size_t)total_length - offset;
    if (remaining > DELIVERY_LATEST_BLOCK_BODY_MAX)
        remaining = DELIVERY_LATEST_BLOCK_BODY_MAX;
    return (uint16_t)remaining;
}

static uint64_t block_mask(uint16_t block_count)
{
    if (block_count >= 64U)
        return UINT64_MAX;
    return (UINT64_C(1) << block_count) - UINT64_C(1);
}

static void hash_begin(crypto_blake2b_ctx *ctx, const char *domain)
{
    crypto_blake2b_init(ctx, DELIVERY_HASH_BYTES);
    crypto_blake2b_update(ctx, (const uint8_t *)domain, strlen(domain));
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

void delivery_context_derive(const uint8_t client_hello[32],
                             const uint8_t server_ack[32],
                             uint32_t selected_caps,
                             uint8_t out[DELIVERY_CONTEXT_BYTES])
{
    crypto_blake2b_ctx ctx;

    hash_begin(&ctx, "unmoor-delivery-context-v1");
    crypto_blake2b_update(&ctx, (const uint8_t *)"client", 6);
    crypto_blake2b_update(&ctx, client_hello, 32);
    crypto_blake2b_update(&ctx, (const uint8_t *)"server", 6);
    crypto_blake2b_update(&ctx, server_ack, 32);
    hash_u32(&ctx, selected_caps);
    crypto_blake2b_final(&ctx, out);
    crypto_wipe(&ctx, sizeof(ctx));
}

void delivery_latest_leaf_hash(const uint8_t context[DELIVERY_CONTEXT_BYTES],
                               uint8_t direction, uint16_t object_id,
                               uint64_t revision, uint32_t total_length,
                               uint16_t block_count, uint16_t block_index,
                               const uint8_t *body, size_t body_length,
                               uint8_t out[DELIVERY_HASH_BYTES])
{
    crypto_blake2b_ctx ctx;

    hash_begin(&ctx, "unmoor-latest-leaf-v1");
    crypto_blake2b_update(&ctx, context, DELIVERY_CONTEXT_BYTES);
    hash_u8(&ctx, direction);
    hash_u16(&ctx, object_id);
    hash_u64(&ctx, revision);
    hash_u32(&ctx, total_length);
    hash_u16(&ctx, DELIVERY_LATEST_BLOCK_BODY_MAX);
    hash_u16(&ctx, block_count);
    hash_u16(&ctx, block_index);
    hash_u16(&ctx, (uint16_t)body_length);
    if (body_length != 0)
        crypto_blake2b_update(&ctx, body, body_length);
    crypto_blake2b_final(&ctx, out);
    crypto_wipe(&ctx, sizeof(ctx));
}

void delivery_latest_chain_hash(const uint8_t context[DELIVERY_CONTEXT_BYTES],
                                uint8_t direction, uint16_t object_id,
                                uint64_t revision, uint16_t block_index,
                                const uint8_t previous[DELIVERY_HASH_BYTES],
                                const uint8_t leaf[DELIVERY_HASH_BYTES],
                                uint8_t out[DELIVERY_HASH_BYTES])
{
    crypto_blake2b_ctx ctx;

    hash_begin(&ctx, "unmoor-latest-frontier-v1");
    crypto_blake2b_update(&ctx, context, DELIVERY_CONTEXT_BYTES);
    hash_u8(&ctx, direction);
    hash_u16(&ctx, object_id);
    hash_u64(&ctx, revision);
    hash_u16(&ctx, block_index);
    crypto_blake2b_update(&ctx, previous, DELIVERY_HASH_BYTES);
    crypto_blake2b_update(&ctx, leaf, DELIVERY_HASH_BYTES);
    crypto_blake2b_final(&ctx, out);
    crypto_wipe(&ctx, sizeof(ctx));
}

void delivery_latest_version_hash(const uint8_t context[DELIVERY_CONTEXT_BYTES],
                                  uint8_t direction, uint16_t object_id,
                                  uint64_t revision, uint32_t total_length,
                                  uint16_t block_count,
                                  const uint8_t previous[DELIVERY_HASH_BYTES],
                                  const uint8_t root[DELIVERY_HASH_BYTES],
                                  uint8_t out[DELIVERY_HASH_BYTES])
{
    crypto_blake2b_ctx ctx;

    hash_begin(&ctx, "unmoor-latest-version-v1");
    crypto_blake2b_update(&ctx, context, DELIVERY_CONTEXT_BYTES);
    hash_u8(&ctx, direction);
    hash_u16(&ctx, object_id);
    hash_u64(&ctx, revision);
    hash_u32(&ctx, total_length);
    hash_u16(&ctx, DELIVERY_LATEST_BLOCK_BODY_MAX);
    hash_u16(&ctx, block_count);
    crypto_blake2b_update(&ctx, previous, DELIVERY_HASH_BYTES);
    crypto_blake2b_update(&ctx, root, DELIVERY_HASH_BYTES);
    crypto_blake2b_final(&ctx, out);
    crypto_wipe(&ctx, sizeof(ctx));
}

void delivery_reliable_content_hash(
    const uint8_t context[DELIVERY_CONTEXT_BYTES], uint8_t direction,
    uint16_t flow_id, uint64_t message_id, const uint8_t *body,
    size_t body_length, uint8_t out[DELIVERY_HASH_BYTES])
{
    crypto_blake2b_ctx ctx;

    hash_begin(&ctx, "unmoor-reliable-dgram-v1");
    crypto_blake2b_update(&ctx, context, DELIVERY_CONTEXT_BYTES);
    hash_u8(&ctx, direction);
    hash_u16(&ctx, flow_id);
    hash_u64(&ctx, message_id);
    hash_u16(&ctx, (uint16_t)body_length);
    if (body_length != 0)
        crypto_blake2b_update(&ctx, body, body_length);
    crypto_blake2b_final(&ctx, out);
    crypto_wipe(&ctx, sizeof(ctx));
}

static int head_valid(const delivery_latest_head_t *record)
{
    uint16_t expected;

    if (record == NULL || record->object_id == 0 || record->revision == 0 ||
        record->total_length > DELIVERY_LATEST_SNAPSHOT_BYTES_MAX ||
        record->block_size != DELIVERY_LATEST_BLOCK_BODY_MAX ||
        record->block_count == 0 ||
        record->block_count > DELIVERY_LATEST_BLOCKS_MAX ||
        bytes_zero(record->content_root, DELIVERY_HASH_BYTES) ||
        bytes_zero(record->version_chain, DELIVERY_HASH_BYTES))
        return 0;
    expected = latest_block_count(record->total_length);
    if (record->block_count != expected)
        return 0;
    if (record->drop_revision == 0)
        return record->dropped_first == 0 && record->dropped_last == 0;
    return record->dropped_first != 0 &&
           record->dropped_first <= record->dropped_last;
}

int delivery_latest_head_encode(const delivery_latest_head_t *record,
                                uint8_t out[DELIVERY_LATEST_HEAD_BYTES])
{
    if (!head_valid(record) || out == NULL)
        return DELIVERY_RESULT_MALFORMED;
    memset(out, 0, DELIVERY_LATEST_HEAD_BYTES);
    out[0] = DELIVERY_VERSION;
    store16_le(out + 2, record->object_id);
    store64_le(out + 4, record->revision);
    store32_le(out + 12, record->total_length);
    store16_le(out + 16, record->block_size);
    store16_le(out + 18, record->block_count);
    memcpy(out + 20, record->content_root, DELIVERY_HASH_BYTES);
    memcpy(out + 52, record->previous_chain, DELIVERY_HASH_BYTES);
    memcpy(out + 84, record->version_chain, DELIVERY_HASH_BYTES);
    store64_le(out + 116, record->drop_revision);
    store64_le(out + 124, record->dropped_first);
    store64_le(out + 132, record->dropped_last);
    return DELIVERY_RESULT_OK;
}

int delivery_latest_head_decode(const uint8_t *wire, size_t wire_length,
                                delivery_latest_head_t *record)
{
    delivery_latest_head_t decoded;

    if (wire == NULL || record == NULL ||
        wire_length != DELIVERY_LATEST_HEAD_BYTES ||
        wire[0] != DELIVERY_VERSION || wire[1] != 0 || load32_le(wire + 140) != 0)
        return DELIVERY_RESULT_MALFORMED;
    memset(&decoded, 0, sizeof(decoded));
    decoded.object_id = load16_le(wire + 2);
    decoded.revision = load64_le(wire + 4);
    decoded.total_length = load32_le(wire + 12);
    decoded.block_size = load16_le(wire + 16);
    decoded.block_count = load16_le(wire + 18);
    memcpy(decoded.content_root, wire + 20, DELIVERY_HASH_BYTES);
    memcpy(decoded.previous_chain, wire + 52, DELIVERY_HASH_BYTES);
    memcpy(decoded.version_chain, wire + 84, DELIVERY_HASH_BYTES);
    decoded.drop_revision = load64_le(wire + 116);
    decoded.dropped_first = load64_le(wire + 124);
    decoded.dropped_last = load64_le(wire + 132);
    if (!head_valid(&decoded))
        return DELIVERY_RESULT_MALFORMED;
    *record = decoded;
    return DELIVERY_RESULT_OK;
}

static int block_valid(const delivery_latest_block_t *record)
{
    uint16_t expected;

    if (record == NULL || record->object_id == 0 || record->revision == 0 ||
        record->total_length > DELIVERY_LATEST_SNAPSHOT_BYTES_MAX ||
        record->block_count == 0 ||
        record->block_count > DELIVERY_LATEST_BLOCKS_MAX ||
        record->block_count != latest_block_count(record->total_length) ||
        record->block_index >= record->block_count ||
        bytes_zero(record->content_root, DELIVERY_HASH_BYTES))
        return 0;
    expected = latest_expected_body(record->total_length,
                                    record->block_count,
                                    record->block_index);
    return expected != UINT16_MAX && record->body_length == expected;
}

int delivery_latest_block_encode(const delivery_latest_block_t *record,
                                 uint8_t *out, size_t out_size,
                                 size_t *wire_length)
{
    size_t needed;

    if (!block_valid(record) || out == NULL || wire_length == NULL)
        return DELIVERY_RESULT_MALFORMED;
    needed = DELIVERY_LATEST_BLOCK_HEADER_BYTES + record->body_length;
    if (out_size < needed)
        return DELIVERY_RESULT_SOURCE_QUOTA;
    memset(out, 0, needed);
    out[0] = DELIVERY_VERSION;
    store16_le(out + 2, record->object_id);
    store64_le(out + 4, record->revision);
    store16_le(out + 12, record->block_index);
    store16_le(out + 14, record->block_count);
    store32_le(out + 16, record->total_length);
    store16_le(out + 20, record->body_length);
    memcpy(out + 24, record->content_root, DELIVERY_HASH_BYTES);
    if (record->body_length != 0)
        memcpy(out + DELIVERY_LATEST_BLOCK_HEADER_BYTES, record->body,
               record->body_length);
    *wire_length = needed;
    return DELIVERY_RESULT_OK;
}

int delivery_latest_block_decode(const uint8_t *wire, size_t wire_length,
                                 delivery_latest_block_t *record)
{
    delivery_latest_block_t decoded;

    if (wire == NULL || record == NULL ||
        wire_length < DELIVERY_LATEST_BLOCK_HEADER_BYTES ||
        wire_length > DELIVERY_LATEST_BLOCK_WIRE_MAX ||
        wire[0] != DELIVERY_VERSION || wire[1] != 0 || load16_le(wire + 22) != 0)
        return DELIVERY_RESULT_MALFORMED;
    memset(&decoded, 0, sizeof(decoded));
    decoded.object_id = load16_le(wire + 2);
    decoded.revision = load64_le(wire + 4);
    decoded.block_index = load16_le(wire + 12);
    decoded.block_count = load16_le(wire + 14);
    decoded.total_length = load32_le(wire + 16);
    decoded.body_length = load16_le(wire + 20);
    memcpy(decoded.content_root, wire + 24, DELIVERY_HASH_BYTES);
    if (wire_length != DELIVERY_LATEST_BLOCK_HEADER_BYTES + decoded.body_length)
        return DELIVERY_RESULT_MALFORMED;
    if (decoded.body_length != 0)
        memcpy(decoded.body, wire + DELIVERY_LATEST_BLOCK_HEADER_BYTES,
               decoded.body_length);
    if (!block_valid(&decoded))
        return DELIVERY_RESULT_MALFORMED;
    *record = decoded;
    return DELIVERY_RESULT_OK;
}

static int status_valid(const delivery_latest_status_t *record)
{
    uint64_t valid_mask;
    uint64_t frontier_mask;

    if (record == NULL || record->object_id == 0 ||
        !mode_valid(record->mode) || record->flow_revision == 0 ||
        record->accepted_limit > DELIVERY_LATEST_SNAPSHOT_BYTES_MAX ||
        record->have_base != 0)
        return 0;
    if ((record->installed_revision == 0) !=
        bytes_zero(record->installed_chain, DELIVERY_HASH_BYTES))
        return 0;
    if (record->target_revision == 0) {
        return bytes_zero(record->target_root, DELIVERY_HASH_BYTES) &&
               record->target_block_count == 0 && record->have_bitmap == 0 &&
               record->frontier == 0 &&
               bytes_zero(record->frontier_hash, DELIVERY_HASH_BYTES) &&
               record->accepted_limit == 0;
    }
    if (bytes_zero(record->target_root, DELIVERY_HASH_BYTES) ||
        record->target_block_count == 0 ||
        record->target_block_count > DELIVERY_LATEST_BLOCKS_MAX ||
        record->frontier > record->target_block_count)
        return 0;
    valid_mask = block_mask(record->target_block_count);
    if ((record->have_bitmap & ~valid_mask) != 0)
        return 0;
    frontier_mask = block_mask(record->frontier);
    if ((record->have_bitmap & frontier_mask) != frontier_mask)
        return 0;
    if ((record->frontier == 0) !=
        bytes_zero(record->frontier_hash, DELIVERY_HASH_BYTES))
        return 0;
    return 1;
}

int delivery_latest_status_encode(const delivery_latest_status_t *record,
                                  uint8_t out[DELIVERY_LATEST_STATUS_BYTES])
{
    if (!status_valid(record) || out == NULL)
        return DELIVERY_RESULT_MALFORMED;
    memset(out, 0, DELIVERY_LATEST_STATUS_BYTES);
    out[0] = DELIVERY_VERSION;
    out[1] = (uint8_t)record->mode;
    store16_le(out + 2, record->object_id);
    store64_le(out + 4, record->flow_revision);
    store64_le(out + 12, record->installed_revision);
    memcpy(out + 20, record->installed_chain, DELIVERY_HASH_BYTES);
    store64_le(out + 52, record->target_revision);
    memcpy(out + 60, record->target_root, DELIVERY_HASH_BYTES);
    store16_le(out + 92, record->target_block_count);
    store16_le(out + 94, record->have_base);
    store64_le(out + 96, record->have_bitmap);
    store16_le(out + 104, record->frontier);
    memcpy(out + 108, record->frontier_hash, DELIVERY_HASH_BYTES);
    store32_le(out + 140, record->accepted_limit);
    store64_le(out + 144, record->accepted_drop_revision);
    return DELIVERY_RESULT_OK;
}

int delivery_latest_status_decode(const uint8_t *wire, size_t wire_length,
                                  delivery_latest_status_t *record)
{
    delivery_latest_status_t decoded;

    if (wire == NULL || record == NULL ||
        wire_length != DELIVERY_LATEST_STATUS_BYTES ||
        wire[0] != DELIVERY_VERSION || load16_le(wire + 106) != 0)
        return DELIVERY_RESULT_MALFORMED;
    memset(&decoded, 0, sizeof(decoded));
    decoded.mode = (delivery_mode_t)wire[1];
    decoded.object_id = load16_le(wire + 2);
    decoded.flow_revision = load64_le(wire + 4);
    decoded.installed_revision = load64_le(wire + 12);
    memcpy(decoded.installed_chain, wire + 20, DELIVERY_HASH_BYTES);
    decoded.target_revision = load64_le(wire + 52);
    memcpy(decoded.target_root, wire + 60, DELIVERY_HASH_BYTES);
    decoded.target_block_count = load16_le(wire + 92);
    decoded.have_base = load16_le(wire + 94);
    decoded.have_bitmap = load64_le(wire + 96);
    decoded.frontier = load16_le(wire + 104);
    memcpy(decoded.frontier_hash, wire + 108, DELIVERY_HASH_BYTES);
    decoded.accepted_limit = load32_le(wire + 140);
    decoded.accepted_drop_revision = load64_le(wire + 144);
    if (!status_valid(&decoded))
        return DELIVERY_RESULT_MALFORMED;
    *record = decoded;
    return DELIVERY_RESULT_OK;
}

static int reliable_data_valid(const delivery_reliable_data_t *record)
{
    return record != NULL && record->flow_id != 0 && record->message_id != 0 &&
           record->body_length <= DELIVERY_RELIABLE_BODY_MAX &&
           !bytes_zero(record->content_hash, DELIVERY_HASH_BYTES);
}

int delivery_reliable_data_encode(const delivery_reliable_data_t *record,
                                  uint8_t *out, size_t out_size,
                                  size_t *wire_length)
{
    size_t needed;

    if (!reliable_data_valid(record) || out == NULL || wire_length == NULL)
        return DELIVERY_RESULT_MALFORMED;
    needed = DELIVERY_RELIABLE_DATA_HEADER_BYTES + record->body_length;
    if (out_size < needed)
        return DELIVERY_RESULT_SOURCE_QUOTA;
    memset(out, 0, needed);
    out[0] = DELIVERY_VERSION;
    store16_le(out + 2, record->flow_id);
    store64_le(out + 4, record->message_id);
    store16_le(out + 12, record->body_length);
    memcpy(out + 16, record->content_hash, DELIVERY_HASH_BYTES);
    if (record->body_length != 0)
        memcpy(out + DELIVERY_RELIABLE_DATA_HEADER_BYTES, record->body,
               record->body_length);
    *wire_length = needed;
    return DELIVERY_RESULT_OK;
}

int delivery_reliable_data_decode(const uint8_t *wire, size_t wire_length,
                                  delivery_reliable_data_t *record)
{
    delivery_reliable_data_t decoded;

    if (wire == NULL || record == NULL ||
        wire_length < DELIVERY_RELIABLE_DATA_HEADER_BYTES ||
        wire_length > DELIVERY_RELIABLE_DATA_WIRE_MAX ||
        wire[0] != DELIVERY_VERSION || wire[1] != 0 || load16_le(wire + 14) != 0)
        return DELIVERY_RESULT_MALFORMED;
    memset(&decoded, 0, sizeof(decoded));
    decoded.flow_id = load16_le(wire + 2);
    decoded.message_id = load64_le(wire + 4);
    decoded.body_length = load16_le(wire + 12);
    memcpy(decoded.content_hash, wire + 16, DELIVERY_HASH_BYTES);
    if (wire_length != DELIVERY_RELIABLE_DATA_HEADER_BYTES + decoded.body_length)
        return DELIVERY_RESULT_MALFORMED;
    if (decoded.body_length != 0)
        memcpy(decoded.body, wire + DELIVERY_RELIABLE_DATA_HEADER_BYTES,
               decoded.body_length);
    if (!reliable_data_valid(&decoded))
        return DELIVERY_RESULT_MALFORMED;
    *record = decoded;
    return DELIVERY_RESULT_OK;
}

static int reliable_status_valid(const delivery_reliable_status_t *record)
{
    if (record == NULL || record->flow_id == 0 ||
        !mode_valid(record->mode) || record->flow_revision == 0 ||
        (record->flags &
         (uint8_t)~DELIVERY_RELIABLE_STATUS_FLAG_REFUSED) != 0 ||
        record->accepted_limit > DELIVERY_RELIABLE_BODY_MAX)
        return 0;
    if ((record->delivered_id == 0) !=
        bytes_zero(record->delivered_hash, DELIVERY_HASH_BYTES))
        return 0;
    if ((record->target_id == 0) !=
        bytes_zero(record->target_hash, DELIVERY_HASH_BYTES))
        return 0;
    if (record->target_id == 0 && record->accepted_limit != 0)
        return 0;
    if (record->target_id != 0 &&
        record->target_id == record->delivered_id)
        return 0;
    if ((record->flags & DELIVERY_RELIABLE_STATUS_FLAG_REFUSED) != 0 &&
        (record->target_id == 0 || record->accepted_limit != 0))
        return 0;
    if (record->mode == DELIVERY_MODE_NOT_INTERESTED &&
        record->target_id != 0 &&
        (record->flags & DELIVERY_RELIABLE_STATUS_FLAG_REFUSED) == 0)
        return 0;
    return 1;
}

int delivery_reliable_status_encode(
    const delivery_reliable_status_t *record,
    uint8_t out[DELIVERY_RELIABLE_STATUS_BYTES])
{
    if (!reliable_status_valid(record) || out == NULL)
        return DELIVERY_RESULT_MALFORMED;
    memset(out, 0, DELIVERY_RELIABLE_STATUS_BYTES);
    out[0] = DELIVERY_VERSION;
    out[1] = (uint8_t)record->mode;
    store16_le(out + 2, record->flow_id);
    store64_le(out + 4, record->flow_revision);
    store64_le(out + 12, record->delivered_id);
    memcpy(out + 20, record->delivered_hash, DELIVERY_HASH_BYTES);
    store64_le(out + 52, record->target_id);
    memcpy(out + 60, record->target_hash, DELIVERY_HASH_BYTES);
    store32_le(out + 92, record->accepted_limit);
    out[96] = record->flags;
    return DELIVERY_RESULT_OK;
}

int delivery_reliable_status_decode(const uint8_t *wire, size_t wire_length,
                                    delivery_reliable_status_t *record)
{
    delivery_reliable_status_t decoded;

    if (wire == NULL || record == NULL ||
        wire_length != DELIVERY_RELIABLE_STATUS_BYTES ||
        wire[0] != DELIVERY_VERSION || wire[97] != 0 || wire[98] != 0 ||
        wire[99] != 0)
        return DELIVERY_RESULT_MALFORMED;
    memset(&decoded, 0, sizeof(decoded));
    decoded.mode = (delivery_mode_t)wire[1];
    decoded.flags = wire[96];
    decoded.flow_id = load16_le(wire + 2);
    decoded.flow_revision = load64_le(wire + 4);
    decoded.delivered_id = load64_le(wire + 12);
    memcpy(decoded.delivered_hash, wire + 20, DELIVERY_HASH_BYTES);
    decoded.target_id = load64_le(wire + 52);
    memcpy(decoded.target_hash, wire + 60, DELIVERY_HASH_BYTES);
    decoded.accepted_limit = load32_le(wire + 92);
    if (!reliable_status_valid(&decoded))
        return DELIVERY_RESULT_MALFORMED;
    *record = decoded;
    return DELIVERY_RESULT_OK;
}

static delivery_mode_t flow_mode(const delivery_flow_state_t *flow)
{
    if (flow->not_interested)
        return DELIVERY_MODE_NOT_INTERESTED;
    if (flow->reset_required)
        return DELIVERY_MODE_RESET_REQUIRED;
    if (flow->quota_refused)
        return DELIVERY_MODE_QUOTA_REFUSED;
    if (flow->paused)
        return DELIVERY_MODE_PAUSED;
    return DELIVERY_MODE_ACTIVE;
}

static int advance_revision(uint64_t *revision)
{
    if (*revision == UINT64_MAX)
        return DELIVERY_RESULT_EXHAUSTED;
    (*revision)++;
    return DELIVERY_RESULT_OK;
}

void delivery_flow_init(delivery_flow_state_t *flow)
{
    memset(flow, 0, sizeof(*flow));
    flow->mode = DELIVERY_MODE_ACTIVE;
    flow->revision = 1;
}

int delivery_flow_set_reason(delivery_flow_state_t *flow,
                             delivery_reason_t reason, int enabled)
{
    delivery_flow_state_t next;
    delivery_mode_t next_mode;

    if (flow == NULL)
        return DELIVERY_RESULT_MALFORMED;
    next = *flow;
    switch (reason) {
    case DELIVERY_REASON_PAUSED:
        next.paused = enabled != 0;
        break;
    case DELIVERY_REASON_QUOTA_REFUSED:
        next.quota_refused = enabled != 0;
        break;
    case DELIVERY_REASON_RESET_REQUIRED:
        next.reset_required = enabled != 0;
        break;
    case DELIVERY_REASON_NOT_INTERESTED:
        next.not_interested = enabled != 0;
        break;
    default:
        return DELIVERY_RESULT_MALFORMED;
    }
    next_mode = flow_mode(&next);
    if (next_mode != flow->mode) {
        if (flow->revision == UINT64_MAX)
            return DELIVERY_RESULT_EXHAUSTED;
        next.revision = flow->revision + 1;
        next.mode = next_mode;
    }
    *flow = next;
    return DELIVERY_RESULT_OK;
}

int delivery_flow_target_changed(delivery_flow_state_t *flow)
{
    if (flow == NULL)
        return DELIVERY_RESULT_MALFORMED;
    return advance_revision(&flow->revision);
}

int delivery_retry_init(delivery_retry_owner_t *owner, int64_t retry_ms)
{
    if (owner == NULL || retry_ms <= 0)
        return DELIVERY_RESULT_MALFORMED;
    memset(owner, 0, sizeof(*owner));
    owner->retry_ms = retry_ms;
    return DELIVERY_RESULT_OK;
}

int delivery_retry_arm(delivery_retry_owner_t *owner, uint64_t generation,
                       int64_t now_ms)
{
    if (owner == NULL || generation == 0 || owner->retry_ms <= 0)
        return DELIVERY_RESULT_MALFORMED;
    if (owner->pending || owner->inflight)
        return DELIVERY_RESULT_BUSY;
    owner->pending = 1;
    owner->generation = generation;
    owner->attempts = 0;
    owner->next_attempt_ms = now_ms;
    return DELIVERY_RESULT_OK;
}

int delivery_retry_due(const delivery_retry_owner_t *owner, int64_t now_ms)
{
    if (owner == NULL || !owner->pending || owner->inflight)
        return 0;
    return now_ms >= owner->next_attempt_ms;
}

int delivery_retry_selected(delivery_retry_owner_t *owner, uint64_t generation,
                            int64_t now_ms)
{
    if (owner == NULL || !owner->pending || owner->inflight ||
        owner->generation != generation || now_ms < owner->next_attempt_ms)
        return DELIVERY_RESULT_NOT_READY;
    owner->inflight = 1;
    return DELIVERY_RESULT_OK;
}

int delivery_retry_result(delivery_retry_owner_t *owner, uint64_t generation,
                          delivery_attempt_result_t result, int64_t now_ms)
{
    if (owner == NULL || !owner->pending || !owner->inflight ||
        owner->generation != generation ||
        (result != DELIVERY_ATTEMPT_COMPLETE &&
         result != DELIVERY_ATTEMPT_FAILED))
        return DELIVERY_RESULT_MALFORMED;
    owner->inflight = 0;
    if (owner->attempts != UINT32_MAX)
        owner->attempts++;
    if (now_ms > INT64_MAX - owner->retry_ms)
        owner->next_attempt_ms = INT64_MAX;
    else
        owner->next_attempt_ms = now_ms + owner->retry_ms;
    return DELIVERY_RESULT_OK;
}

int delivery_retry_ack(delivery_retry_owner_t *owner, uint64_t generation)
{
    int64_t retry_ms;

    if (owner == NULL || !owner->pending || owner->generation != generation)
        return DELIVERY_RESULT_STALE;
    if (owner->inflight)
        return DELIVERY_RESULT_BUSY;
    retry_ms = owner->retry_ms;
    memset(owner, 0, sizeof(*owner));
    owner->retry_ms = retry_ms;
    return DELIVERY_RESULT_OK;
}

void delivery_service_init(delivery_service_t *service)
{
    memset(service, 0, sizeof(*service));
}

static int select_mask(uint8_t mask, uint8_t *cursor, unsigned int *slot_out)
{
    unsigned int n;

    for (n = 0; n < 4U; n++) {
        unsigned int slot = ((unsigned int)*cursor + n) % 4U;
        if ((mask & (uint8_t)(1U << slot)) != 0) {
            *slot_out = slot;
            *cursor = (uint8_t)((slot + 1U) % 4U);
            return 1;
        }
    }
    return 0;
}

int delivery_service_select(delivery_service_t *service, uint8_t high_mask,
                            uint8_t low_mask, unsigned int *slot_out)
{
    int selected;

    if (service == NULL || slot_out == NULL ||
        (high_mask & 0xf0U) != 0 || (low_mask & 0xf0U) != 0)
        return DELIVERY_RESULT_MALFORMED;
    if (high_mask != 0 && (service->high_streak < 3U || low_mask == 0)) {
        selected = select_mask(high_mask, &service->high_cursor, slot_out);
        if (selected) {
            if (service->high_streak < 3U)
                service->high_streak++;
            return DELIVERY_RESULT_OK;
        }
    }
    if (low_mask != 0) {
        selected = select_mask(low_mask, &service->low_cursor, slot_out);
        if (selected) {
            service->high_streak = 0;
            return DELIVERY_RESULT_OK;
        }
    }
    if (high_mask != 0) {
        selected = select_mask(high_mask, &service->high_cursor, slot_out);
        if (selected) {
            service->high_streak = 1;
            return DELIVERY_RESULT_OK;
        }
    }
    return DELIVERY_RESULT_NOT_READY;
}

static delivery_latest_sender_object_t *latest_sender_find(
    delivery_latest_sender_t *sender, uint16_t object_id)
{
    unsigned int i;

    for (i = 0; i < DELIVERY_LATEST_OBJECTS; i++) {
        if (sender->objects[i].configured &&
            sender->objects[i].object_id == object_id)
            return &sender->objects[i];
    }
    return NULL;
}

static const delivery_latest_sender_object_t *latest_sender_find_const(
    const delivery_latest_sender_t *sender, uint16_t object_id)
{
    unsigned int i;

    for (i = 0; i < DELIVERY_LATEST_OBJECTS; i++) {
        if (sender->objects[i].configured &&
            sender->objects[i].object_id == object_id)
            return &sender->objects[i];
    }
    return NULL;
}

static const delivery_latest_snapshot_t *snapshot_find_const(
    const delivery_latest_sender_object_t *object, uint64_t revision,
    const uint8_t root[DELIVERY_HASH_BYTES])
{
    unsigned int i;

    for (i = 0; i < object->snapshot_count; i++) {
        const delivery_latest_snapshot_t *snapshot = &object->snapshots[i];
        if (snapshot->valid && snapshot->revision == revision &&
            hash_equal(snapshot->content_root, root))
            return snapshot;
    }
    return NULL;
}

static void snapshot_root(const uint8_t context[DELIVERY_CONTEXT_BYTES],
                          uint8_t direction, uint16_t object_id,
                          uint64_t revision, const uint8_t *bytes,
                          uint32_t total_length, uint16_t count,
                          uint8_t out[DELIVERY_HASH_BYTES])
{
    uint8_t previous[DELIVERY_HASH_BYTES] = {0};
    uint8_t leaf[DELIVERY_HASH_BYTES];
    uint8_t next[DELIVERY_HASH_BYTES];
    uint16_t i;

    for (i = 0; i < count; i++) {
        uint16_t length = latest_expected_body(total_length, count, i);
        const uint8_t *body = bytes + (size_t)i * DELIVERY_LATEST_BLOCK_BODY_MAX;
        delivery_latest_leaf_hash(context, direction, object_id, revision,
                                  total_length, count, i, body, length, leaf);
        delivery_latest_chain_hash(context, direction, object_id, revision, i,
                                   previous, leaf, next);
        memcpy(previous, next, sizeof(previous));
    }
    memcpy(out, previous, DELIVERY_HASH_BYTES);
    crypto_wipe(leaf, sizeof(leaf));
    crypto_wipe(next, sizeof(next));
    crypto_wipe(previous, sizeof(previous));
}

void delivery_latest_sender_init(delivery_latest_sender_t *sender,
                                 const uint8_t context[DELIVERY_CONTEXT_BYTES],
                                 uint8_t direction)
{
    memset(sender, 0, sizeof(*sender));
    memcpy(sender->context, context, DELIVERY_CONTEXT_BYTES);
    sender->direction = direction;
    delivery_service_init(&sender->service);
}

int delivery_latest_sender_reserve_object(
    delivery_latest_sender_t *sender, uint16_t object_id, uint32_t bytes)
{
    unsigned int i;

    if (sender == NULL || object_id != DELIVERY_LATEST_SYSTEM_OBJECT_ID ||
        bytes == 0 ||
        bytes > DELIVERY_LATEST_AGGREGATE_BYTES)
        return DELIVERY_RESULT_MALFORMED;
    if (sender->retained_bytes != 0 || sender->reserved_object_bytes != 0)
        return DELIVERY_RESULT_BUSY;
    for (i = 0; i < DELIVERY_LATEST_OBJECTS; i++)
        if (sender->objects[i].configured)
            return DELIVERY_RESULT_BUSY;
    sender->reserved_object_bytes = (uint16_t)bytes;
    return DELIVERY_RESULT_OK;
}

int delivery_latest_sender_configure(delivery_latest_sender_t *sender,
                                     unsigned int slot, uint16_t object_id,
                                     delivery_priority_t priority)
{
    delivery_latest_sender_object_t *object;

    if (sender == NULL || slot >= DELIVERY_LATEST_OBJECTS || object_id == 0 ||
        (priority != DELIVERY_PRIORITY_LOW &&
         priority != DELIVERY_PRIORITY_HIGH) ||
        latest_sender_find(sender, object_id) != NULL)
        return DELIVERY_RESULT_MALFORMED;
    object = &sender->objects[slot];
    if (object->configured)
        return DELIVERY_RESULT_BUSY;
    memset(object, 0, sizeof(*object));
    object->configured = 1;
    object->priority = (uint8_t)priority;
    object->object_id = object_id;
    object->next_revision = 1;
    object->peer_mode = DELIVERY_MODE_ACTIVE;
    (void)delivery_retry_init(&object->retry, DELIVERY_LATEST_RETRY_MS);
    return DELIVERY_RESULT_OK;
}

static void drop_oldest_snapshot(delivery_latest_sender_t *sender,
                                 delivery_latest_sender_object_t *object)
{
    uint32_t length = object->snapshots[0].total_length;
    unsigned int i;

    sender->retained_bytes -= length;
    for (i = 1; i < object->snapshot_count; i++)
        object->snapshots[i - 1] = object->snapshots[i];
    object->snapshot_count--;
    memset(&object->snapshots[object->snapshot_count], 0,
           sizeof(object->snapshots[object->snapshot_count]));
}

int delivery_latest_sender_publish(delivery_latest_sender_t *sender,
                                   uint16_t object_id, const uint8_t *bytes,
                                   size_t length)
{
    delivery_latest_sender_object_t *object;
    delivery_latest_snapshot_t candidate;
    uint32_t retained_after;
    uint32_t nonreserved_after = 0;
    uint32_t nonreserved_limit = DELIVERY_LATEST_AGGREGATE_BYTES;
    unsigned int drops = 0;
    unsigned int i;
    uint64_t first_dropped_ordinal = 0;
    uint64_t last_dropped_ordinal = 0;

    if (sender == NULL || length > DELIVERY_LATEST_SNAPSHOT_BYTES_MAX ||
        (length != 0 && bytes == NULL))
        return DELIVERY_RESULT_MALFORMED;
    object = latest_sender_find(sender, object_id);
    if (object == NULL)
        return DELIVERY_RESULT_UNCONFIGURED;
    if (object->next_revision == 0)
        return DELIVERY_RESULT_EXHAUSTED;

    retained_after = sender->retained_bytes;
    if (sender->reserved_object_bytes != 0) {
        nonreserved_limit -= sender->reserved_object_bytes;
        for (i = 0; i < DELIVERY_LATEST_OBJECTS; i++) {
            const delivery_latest_sender_object_t *candidate_object =
                &sender->objects[i];
            unsigned int snapshot_index;

            if (!candidate_object->configured ||
                candidate_object->object_id ==
                    DELIVERY_LATEST_SYSTEM_OBJECT_ID)
                continue;
            for (snapshot_index = 0;
                 snapshot_index < candidate_object->snapshot_count;
                 snapshot_index++)
                nonreserved_after +=
                    candidate_object->snapshots[snapshot_index].total_length;
        }
    }
    while ((object->snapshot_count - drops >= DELIVERY_LATEST_SNAPSHOT_SLOTS) ||
           ((uint64_t)retained_after + length >
            DELIVERY_LATEST_AGGREGATE_BYTES) ||
           (sender->reserved_object_bytes != 0 &&
            object_id != DELIVERY_LATEST_SYSTEM_OBJECT_ID &&
            (uint64_t)nonreserved_after + length > nonreserved_limit)) {
        if (drops >= object->snapshot_count)
            return DELIVERY_RESULT_SOURCE_QUOTA;
        retained_after -= object->snapshots[drops].total_length;
        if (sender->reserved_object_bytes != 0 &&
            object_id != DELIVERY_LATEST_SYSTEM_OBJECT_ID)
            nonreserved_after -= object->snapshots[drops].total_length;
        drops++;
    }

    memset(&candidate, 0, sizeof(candidate));
    candidate.valid = 1;
    candidate.revision = object->next_revision;
    candidate.total_length = (uint32_t)length;
    candidate.block_count = latest_block_count(length);
    memcpy(candidate.previous_chain, object->published_chain,
           DELIVERY_HASH_BYTES);
    if (length != 0)
        memcpy(candidate.bytes, bytes, length);
    snapshot_root(sender->context, sender->direction, object_id,
                  candidate.revision, candidate.bytes,
                  candidate.total_length, candidate.block_count,
                  candidate.content_root);
    delivery_latest_version_hash(sender->context, sender->direction, object_id,
                                 candidate.revision, candidate.total_length,
                                 candidate.block_count,
                                 candidate.previous_chain,
                                 candidate.content_root,
                                 candidate.version_chain);

    if (drops != 0) {
        if (object->drop_revision == UINT64_MAX ||
            object->drop_watermark > UINT64_MAX - drops)
            return DELIVERY_RESULT_EXHAUSTED;
        first_dropped_ordinal = object->drop_watermark + 1U;
        last_dropped_ordinal = object->drop_watermark + drops;
    }
    for (i = 0; i < drops; i++)
        drop_oldest_snapshot(sender, object);
    if (drops != 0) {
        object->drop_revision++;
        object->drop_watermark = last_dropped_ordinal;
        if (!object->drop_pending) {
            object->dropped_first = first_dropped_ordinal;
            object->drop_pending = 1;
        }
        object->dropped_last = last_dropped_ordinal;
    }
    object->snapshots[object->snapshot_count] = candidate;
    object->snapshot_count++;
    sender->retained_bytes += (uint32_t)length;
    object->published_revision = candidate.revision;
    memcpy(object->published_chain, candidate.version_chain,
           DELIVERY_HASH_BYTES);
    if (object->next_revision == UINT64_MAX)
        object->next_revision = 0;
    else
        object->next_revision++;
    return DELIVERY_RESULT_OK;
}

int delivery_latest_sender_retire_all(delivery_latest_sender_t *sender,
                                      uint16_t object_id)
{
    delivery_latest_sender_object_t *object;
    unsigned int count;
    uint64_t first_ordinal;
    uint64_t last_ordinal;

    if (sender == NULL)
        return DELIVERY_RESULT_MALFORMED;
    object = latest_sender_find(sender, object_id);
    if (object == NULL)
        return DELIVERY_RESULT_UNCONFIGURED;
    if (object->retry.inflight)
        return DELIVERY_RESULT_BUSY;
    count = object->snapshot_count;
    if (count != 0 &&
        (object->drop_revision == UINT64_MAX ||
         object->drop_watermark > UINT64_MAX - count))
        return DELIVERY_RESULT_EXHAUSTED;
    first_ordinal = object->drop_watermark + (count != 0 ? 1U : 0U);
    last_ordinal = object->drop_watermark + count;
    while (object->snapshot_count != 0)
        drop_oldest_snapshot(sender, object);
    if (count != 0) {
        object->drop_revision++;
        object->drop_watermark = last_ordinal;
        if (!object->drop_pending) {
            object->dropped_first = first_ordinal;
            object->drop_pending = 1;
        }
        object->dropped_last = last_ordinal;
    }
    object->peer_target_revision = 0;
    memset(object->peer_target_root, 0, DELIVERY_HASH_BYTES);
    object->peer_target_block_count = 0;
    object->peer_have_bitmap = 0;
    object->peer_frontier = 0;
    memset(object->peer_frontier_hash, 0, DELIVERY_HASH_BYTES);
    object->peer_accepted_limit = 0;
    object->attempted_bitmap = 0;
    object->inflight_revision = 0;
    object->inflight_block = 0;
    (void)delivery_retry_init(&object->retry, DELIVERY_LATEST_RETRY_MS);
    return DELIVERY_RESULT_OK;
}

int delivery_latest_sender_head(const delivery_latest_sender_t *sender,
                                uint16_t object_id,
                                delivery_latest_head_t *head)
{
    const delivery_latest_sender_object_t *object;
    const delivery_latest_snapshot_t *snapshot;

    if (sender == NULL || head == NULL)
        return DELIVERY_RESULT_MALFORMED;
    object = latest_sender_find_const(sender, object_id);
    if (object == NULL)
        return DELIVERY_RESULT_UNCONFIGURED;
    if (object->snapshot_count == 0)
        return DELIVERY_RESULT_NOT_READY;
    snapshot = &object->snapshots[object->snapshot_count - 1U];
    memset(head, 0, sizeof(*head));
    head->object_id = object_id;
    head->revision = snapshot->revision;
    head->total_length = snapshot->total_length;
    head->block_size = DELIVERY_LATEST_BLOCK_BODY_MAX;
    head->block_count = snapshot->block_count;
    memcpy(head->content_root, snapshot->content_root, DELIVERY_HASH_BYTES);
    memcpy(head->previous_chain, snapshot->previous_chain,
           DELIVERY_HASH_BYTES);
    memcpy(head->version_chain, snapshot->version_chain, DELIVERY_HASH_BYTES);
    if (object->drop_pending) {
        head->drop_revision = object->drop_revision;
        head->dropped_first = object->dropped_first;
        head->dropped_last = object->dropped_last;
    }
    return DELIVERY_RESULT_OK;
}

static int latest_status_equal(const delivery_latest_status_t *a,
                               const delivery_latest_status_t *b)
{
    return a->object_id == b->object_id && a->mode == b->mode &&
           a->flow_revision == b->flow_revision &&
           a->installed_revision == b->installed_revision &&
           hash_equal(a->installed_chain, b->installed_chain) &&
           a->target_revision == b->target_revision &&
           hash_equal(a->target_root, b->target_root) &&
           a->target_block_count == b->target_block_count &&
           a->have_base == b->have_base &&
           a->have_bitmap == b->have_bitmap &&
           a->frontier == b->frontier &&
           hash_equal(a->frontier_hash, b->frontier_hash) &&
           a->accepted_limit == b->accepted_limit &&
           a->accepted_drop_revision == b->accepted_drop_revision;
}

static void sender_status_snapshot(
    const delivery_latest_sender_object_t *object,
    delivery_latest_status_t *status)
{
    memset(status, 0, sizeof(*status));
    status->object_id = object->object_id;
    status->mode = object->peer_mode;
    status->flow_revision = object->peer_flow_revision;
    status->installed_revision = object->peer_installed_revision;
    memcpy(status->installed_chain, object->peer_installed_chain,
           DELIVERY_HASH_BYTES);
    status->target_revision = object->peer_target_revision;
    memcpy(status->target_root, object->peer_target_root, DELIVERY_HASH_BYTES);
    status->target_block_count = object->peer_target_block_count;
    status->have_bitmap = object->peer_have_bitmap;
    status->frontier = object->peer_frontier;
    memcpy(status->frontier_hash, object->peer_frontier_hash,
           DELIVERY_HASH_BYTES);
    status->accepted_limit = object->peer_accepted_limit;
    status->accepted_drop_revision = object->peer_accepted_drop_revision;
}

static int snapshot_frontier_valid(
    const delivery_latest_sender_t *sender,
    const delivery_latest_sender_object_t *object,
    const delivery_latest_snapshot_t *snapshot,
    const delivery_latest_status_t *status)
{
    uint8_t chain[DELIVERY_HASH_BYTES] = {0};
    uint8_t leaf[DELIVERY_HASH_BYTES];
    uint8_t next[DELIVERY_HASH_BYTES];
    uint16_t i;

    if (status->target_block_count != snapshot->block_count)
        return 0;
    if (status->mode == DELIVERY_MODE_ACTIVE ||
        status->mode == DELIVERY_MODE_PAUSED) {
        if (status->accepted_limit != snapshot->total_length)
            return 0;
    } else if (status->mode == DELIVERY_MODE_QUOTA_REFUSED ||
               status->mode == DELIVERY_MODE_RESET_REQUIRED ||
               status->mode == DELIVERY_MODE_NOT_INTERESTED) {
        if (status->accepted_limit != 0 &&
            status->accepted_limit != snapshot->total_length)
            return 0;
    }
    for (i = 0; i < status->frontier; i++) {
        uint16_t length = latest_expected_body(snapshot->total_length,
                                               snapshot->block_count, i);
        const uint8_t *body = snapshot->bytes +
            (size_t)i * DELIVERY_LATEST_BLOCK_BODY_MAX;
        delivery_latest_leaf_hash(sender->context, sender->direction,
                                  object->object_id, snapshot->revision,
                                  snapshot->total_length,
                                  snapshot->block_count, i, body, length, leaf);
        delivery_latest_chain_hash(sender->context, sender->direction,
                                   object->object_id, snapshot->revision, i,
                                   chain, leaf, next);
        memcpy(chain, next, DELIVERY_HASH_BYTES);
    }
    if (status->frontier == 0)
        return bytes_zero(status->frontier_hash, DELIVERY_HASH_BYTES);
    return hash_equal(chain, status->frontier_hash);
}

static int snapshot_revision_conflicts(
    const delivery_latest_sender_object_t *object, uint64_t revision,
    const uint8_t chain[DELIVERY_HASH_BYTES])
{
    unsigned int i;

    for (i = 0; i < object->snapshot_count; i++) {
        if (object->snapshots[i].revision == revision)
            return !hash_equal(object->snapshots[i].version_chain, chain);
    }
    return 0;
}

static int prune_new_installed(delivery_latest_sender_t *sender,
                               delivery_latest_sender_object_t *object,
                               uint64_t revision,
                               const uint8_t chain[DELIVERY_HASH_BYTES])
{
    unsigned int i;
    unsigned int prune_count = 0;

    if (revision == 0 || revision <= object->peer_installed_revision)
        return DELIVERY_RESULT_MALFORMED;
    for (i = 0; i < object->snapshot_count; i++) {
        if (object->snapshots[i].revision == revision &&
            hash_equal(object->snapshots[i].version_chain, chain)) {
            prune_count = i + 1U;
            break;
        }
    }
    if (prune_count == 0) {
        if (revision > object->published_revision ||
            snapshot_revision_conflicts(object, revision, chain))
            return DELIVERY_RESULT_DIVERGED;
        return DELIVERY_RESULT_STALE;
    }
    for (i = 0; i < prune_count; i++)
        drop_oldest_snapshot(sender, object);
    return DELIVERY_RESULT_OK;
}

static int validate_new_installed(
    const delivery_latest_sender_object_t *object, uint64_t revision,
    const uint8_t chain[DELIVERY_HASH_BYTES])
{
    unsigned int i;

    if (revision == 0 || revision <= object->peer_installed_revision)
        return DELIVERY_RESULT_MALFORMED;
    for (i = 0; i < object->snapshot_count; i++)
        if (object->snapshots[i].revision == revision &&
            hash_equal(object->snapshots[i].version_chain, chain))
            return DELIVERY_RESULT_OK;
    if (revision > object->published_revision ||
        snapshot_revision_conflicts(object, revision, chain))
        return DELIVERY_RESULT_DIVERGED;
    return DELIVERY_RESULT_STALE;
}

/* Within one flow revision the receiver only ORs HAVE
 * bits and advances its frontier (target, reason and drop changes advance
 * the revision), so a STATUS carrying strictly less progress for the SAME
 * revision, target and installed state is an earlier snapshot that was
 * overtaken in flight (multipath, netem-style reorder).  It is STALE
 * and ignored, never a contradiction.  Equal progress with a different
 * chain hash, a retracted install, or a changed mode still DIVERGES. */
static int latest_status_earlier_snapshot(
    const delivery_latest_sender_object_t *object,
    const delivery_latest_status_t *status)
{
    return status->flow_revision == object->peer_flow_revision &&
           status->mode == object->peer_mode &&
           status->target_revision == object->peer_target_revision &&
           hash_equal(status->target_root, object->peer_target_root) &&
           status->target_block_count == object->peer_target_block_count &&
           status->installed_revision == object->peer_installed_revision &&
           hash_equal(status->installed_chain,
                      object->peer_installed_chain) &&
           status->accepted_drop_revision ==
               object->peer_accepted_drop_revision &&
           status->accepted_limit <= object->peer_accepted_limit &&
           (status->have_bitmap & ~object->peer_have_bitmap) == 0 &&
           status->frontier <= object->peer_frontier &&
           (status->frontier < object->peer_frontier ||
            hash_equal(status->frontier_hash, object->peer_frontier_hash));
}

int delivery_latest_sender_validate_status(
    const delivery_latest_sender_t *sender,
    const delivery_latest_status_t *status)
{
    const delivery_latest_sender_object_t *object;
    const delivery_latest_snapshot_t *target = NULL;
    delivery_latest_status_t prior;
    int target_changed;
    int same_target;
    int rc;

    if (sender == NULL || !status_valid(status))
        return DELIVERY_RESULT_MALFORMED;
    object = latest_sender_find_const(sender, status->object_id);
    if (object == NULL)
        return DELIVERY_RESULT_UNCONFIGURED;
    if (status->flow_revision < object->peer_flow_revision)
        return DELIVERY_RESULT_STALE;
    sender_status_snapshot(object, &prior);
    if (object->peer_flow_revision != 0 && latest_status_equal(&prior, status))
        return DELIVERY_RESULT_DUPLICATE;
    if (object->peer_flow_revision != 0 &&
        latest_status_earlier_snapshot(object, status))
        return DELIVERY_RESULT_STALE;

    target_changed = status->target_revision != object->peer_target_revision ||
        !hash_equal(status->target_root, object->peer_target_root);
    same_target = !target_changed;
    if (object->peer_flow_revision != 0) {
        if (status->installed_revision < object->peer_installed_revision ||
            (status->installed_revision == object->peer_installed_revision &&
             !hash_equal(status->installed_chain,
                         object->peer_installed_chain)) ||
            status->accepted_drop_revision <
                object->peer_accepted_drop_revision)
            return DELIVERY_RESULT_DIVERGED;
        if (same_target &&
            (status->target_block_count != object->peer_target_block_count ||
             (object->peer_have_bitmap & ~status->have_bitmap) != 0 ||
             status->frontier < object->peer_frontier ||
             (status->frontier == object->peer_frontier &&
              !hash_equal(status->frontier_hash,
                          object->peer_frontier_hash)) ||
             status->accepted_limit < object->peer_accepted_limit))
            return DELIVERY_RESULT_DIVERGED;
        if (status->flow_revision == object->peer_flow_revision &&
            (status->mode != object->peer_mode || target_changed ||
             status->installed_revision != object->peer_installed_revision))
            return DELIVERY_RESULT_DIVERGED;
        if (target_changed && object->peer_target_revision != 0 &&
            status->target_revision != 0 &&
            status->target_revision <= object->peer_target_revision)
            return DELIVERY_RESULT_DIVERGED;
    }
    if (status->target_revision != 0 &&
        status->target_revision <= status->installed_revision)
        return DELIVERY_RESULT_DIVERGED;
    if (status->target_revision != 0) {
        target = snapshot_find_const(object, status->target_revision,
                                     status->target_root);
        if (target == NULL) {
            if (status->target_revision > object->published_revision ||
                snapshot_revision_conflicts(object, status->target_revision,
                                            status->target_root))
                return DELIVERY_RESULT_DIVERGED;
            return DELIVERY_RESULT_STALE;
        }
        if (!snapshot_frontier_valid(sender, object, target, status))
            return DELIVERY_RESULT_DIVERGED;
    }
    if (status->accepted_drop_revision > object->drop_revision)
        return DELIVERY_RESULT_DIVERGED;
    if (status->installed_revision > object->peer_installed_revision) {
        rc = validate_new_installed(object, status->installed_revision,
                                    status->installed_chain);
        if (rc != DELIVERY_RESULT_OK)
            return rc;
    }
    return DELIVERY_RESULT_OK;
}

int delivery_latest_sender_observe_status(
    delivery_latest_sender_t *sender,
    const delivery_latest_status_t *status, int64_t now_ms)
{
    delivery_latest_sender_object_t *object;
    const delivery_latest_snapshot_t *target = NULL;
    delivery_latest_status_t prior;
    int target_changed;
    int same_target;
    int rc;

    if (sender == NULL || !status_valid(status))
        return DELIVERY_RESULT_MALFORMED;
    object = latest_sender_find(sender, status->object_id);
    if (object == NULL)
        return DELIVERY_RESULT_UNCONFIGURED;
    if (status->flow_revision < object->peer_flow_revision)
        return DELIVERY_RESULT_STALE;
    sender_status_snapshot(object, &prior);
    if (object->peer_flow_revision != 0 && latest_status_equal(&prior, status))
        return DELIVERY_RESULT_DUPLICATE;
    if (object->peer_flow_revision != 0 &&
        latest_status_earlier_snapshot(object, status))
        return DELIVERY_RESULT_STALE;

    target_changed = status->target_revision != object->peer_target_revision ||
        !hash_equal(status->target_root, object->peer_target_root);
    same_target = !target_changed;
    if (object->peer_flow_revision != 0) {
        if (status->installed_revision < object->peer_installed_revision ||
            (status->installed_revision == object->peer_installed_revision &&
             !hash_equal(status->installed_chain,
                         object->peer_installed_chain)) ||
            status->accepted_drop_revision <
                object->peer_accepted_drop_revision)
            return DELIVERY_RESULT_DIVERGED;
        if (same_target &&
            (status->target_block_count != object->peer_target_block_count ||
             (object->peer_have_bitmap & ~status->have_bitmap) != 0 ||
             status->frontier < object->peer_frontier ||
             (status->frontier == object->peer_frontier &&
              !hash_equal(status->frontier_hash,
                          object->peer_frontier_hash)) ||
             status->accepted_limit < object->peer_accepted_limit))
            return DELIVERY_RESULT_DIVERGED;
        if (status->flow_revision == object->peer_flow_revision &&
            (status->mode != object->peer_mode || target_changed ||
             status->installed_revision != object->peer_installed_revision))
            return DELIVERY_RESULT_DIVERGED;
        if (target_changed && object->peer_target_revision != 0 &&
            status->target_revision != 0 &&
            status->target_revision <= object->peer_target_revision)
            return DELIVERY_RESULT_DIVERGED;
    }
    if (status->target_revision != 0 &&
        status->target_revision <= status->installed_revision)
        return DELIVERY_RESULT_DIVERGED;
    if (status->target_revision != 0) {
        target = snapshot_find_const(object, status->target_revision,
                                     status->target_root);
        if (target == NULL) {
            if (status->target_revision > object->published_revision ||
                snapshot_revision_conflicts(object, status->target_revision,
                                            status->target_root))
                return DELIVERY_RESULT_DIVERGED;
            return DELIVERY_RESULT_STALE;
        }
        if (!snapshot_frontier_valid(sender, object, target, status))
            return DELIVERY_RESULT_DIVERGED;
    }
    if (status->accepted_drop_revision > object->drop_revision)
        return DELIVERY_RESULT_DIVERGED;
    if (status->installed_revision > object->peer_installed_revision) {
        rc = prune_new_installed(sender, object, status->installed_revision,
                                 status->installed_chain);
        if (rc != DELIVERY_RESULT_OK)
            return rc;
    }
    object->peer_flow_revision = status->flow_revision;
    object->peer_mode = status->mode;
    object->peer_target_revision = status->target_revision;
    memcpy(object->peer_target_root, status->target_root, DELIVERY_HASH_BYTES);
    object->peer_target_block_count = status->target_block_count;
    object->peer_have_bitmap = status->have_bitmap;
    object->peer_frontier = status->frontier;
    memcpy(object->peer_frontier_hash, status->frontier_hash,
           DELIVERY_HASH_BYTES);
    object->peer_accepted_limit = status->accepted_limit;
    object->peer_installed_revision = status->installed_revision;
    memcpy(object->peer_installed_chain, status->installed_chain,
           DELIVERY_HASH_BYTES);
    object->peer_accepted_drop_revision = status->accepted_drop_revision;
    if (object->drop_pending &&
        status->accepted_drop_revision >= object->drop_revision) {
        object->drop_pending = 0;
        object->dropped_first = 0;
        object->dropped_last = 0;
    }
    if (target_changed) {
        object->attempted_bitmap = 0;
        if (!object->retry.inflight) {
            object->inflight_revision = 0;
            object->inflight_block = 0;
            (void)delivery_retry_init(&object->retry,
                                      DELIVERY_LATEST_RETRY_MS);
            if (status->target_revision != 0)
                (void)delivery_retry_arm(&object->retry,
                                         status->target_revision, now_ms);
        }
    }
    if (status->target_revision == 0 && !object->retry.inflight)
        (void)delivery_retry_init(&object->retry, DELIVERY_LATEST_RETRY_MS);
    return DELIVERY_RESULT_OK;
}

static int build_sender_block(const delivery_latest_sender_object_t *object,
                              const delivery_latest_snapshot_t *snapshot,
                              uint16_t index,
                              delivery_latest_block_t *block)
{
    uint16_t length;

    if (index >= snapshot->block_count)
        return DELIVERY_RESULT_MALFORMED;
    length = latest_expected_body(snapshot->total_length,
                                  snapshot->block_count, index);
    memset(block, 0, sizeof(*block));
    block->object_id = object->object_id;
    block->revision = snapshot->revision;
    block->block_index = index;
    block->block_count = snapshot->block_count;
    block->total_length = snapshot->total_length;
    block->body_length = length;
    memcpy(block->content_root, snapshot->content_root, DELIVERY_HASH_BYTES);
    if (length != 0)
        memcpy(block->body,
               snapshot->bytes + (size_t)index * DELIVERY_LATEST_BLOCK_BODY_MAX,
               length);
    return DELIVERY_RESULT_OK;
}

int delivery_latest_sender_next_block(const delivery_latest_sender_t *sender,
                                      uint16_t object_id, int64_t now_ms,
                                      delivery_latest_block_t *block,
                                      int *is_recovery)
{
    const delivery_latest_sender_object_t *object;
    const delivery_latest_snapshot_t *snapshot;
    uint64_t missing;
    uint64_t fresh;
    uint16_t index;

    if (sender == NULL || block == NULL || is_recovery == NULL)
        return DELIVERY_RESULT_MALFORMED;
    object = latest_sender_find_const(sender, object_id);
    if (object == NULL)
        return DELIVERY_RESULT_UNCONFIGURED;
    if (object->retry.inflight || object->peer_mode != DELIVERY_MODE_ACTIVE ||
        object->peer_target_revision == 0)
        return DELIVERY_RESULT_NOT_READY;
    snapshot = snapshot_find_const(object, object->peer_target_revision,
                                   object->peer_target_root);
    if (snapshot == NULL ||
        object->peer_accepted_limit != snapshot->total_length)
        return DELIVERY_RESULT_NOT_READY;
    missing = block_mask(snapshot->block_count) & ~object->peer_have_bitmap;
    if (missing == 0)
        return DELIVERY_RESULT_NOT_READY;
    fresh = missing & ~object->attempted_bitmap;
    if (fresh != 0) {
        index = (uint16_t)__builtin_ctzll(fresh);
        *is_recovery = 0;
    } else {
        if (!delivery_retry_due(&object->retry, now_ms))
            return DELIVERY_RESULT_NOT_READY;
        index = (uint16_t)__builtin_ctzll(missing);
        *is_recovery = 1;
    }
    return build_sender_block(object, snapshot, index, block);
}

int delivery_latest_sender_select_block(delivery_latest_sender_t *sender,
                                        int64_t now_ms,
                                        delivery_latest_block_t *block,
                                        int *is_recovery,
                                        unsigned int *slot_out)
{
    uint8_t high_mask = 0;
    uint8_t low_mask = 0;
    unsigned int i;
    unsigned int selected;

    if (sender == NULL || block == NULL || is_recovery == NULL ||
        slot_out == NULL)
        return DELIVERY_RESULT_MALFORMED;
    for (i = 0; i < DELIVERY_LATEST_OBJECTS; i++) {
        delivery_latest_block_t ignored;
        int ignored_recovery;
        delivery_latest_sender_object_t *object = &sender->objects[i];
        if (!object->configured)
            continue;
        if (delivery_latest_sender_next_block(sender, object->object_id,
                                              now_ms, &ignored,
                                              &ignored_recovery) ==
            DELIVERY_RESULT_OK) {
            if (object->priority == DELIVERY_PRIORITY_HIGH)
                high_mask |= (uint8_t)(1U << i);
            else
                low_mask |= (uint8_t)(1U << i);
        }
    }
    if (delivery_service_select(&sender->service, high_mask, low_mask,
                                &selected) != DELIVERY_RESULT_OK)
        return DELIVERY_RESULT_NOT_READY;
    *slot_out = selected;
    return delivery_latest_sender_next_block(
        sender, sender->objects[selected].object_id, now_ms, block,
        is_recovery);
}

int delivery_latest_sender_block_selected(delivery_latest_sender_t *sender,
                                          uint16_t object_id,
                                          uint16_t block_index,
                                          int64_t now_ms)
{
    delivery_latest_sender_object_t *object;
    const delivery_latest_snapshot_t *snapshot;
    uint64_t bit;
    int fresh;
    int rc;

    if (sender == NULL || block_index >= DELIVERY_LATEST_BLOCKS_MAX)
        return DELIVERY_RESULT_MALFORMED;
    object = latest_sender_find(sender, object_id);
    if (object == NULL)
        return DELIVERY_RESULT_UNCONFIGURED;
    snapshot = snapshot_find_const(object, object->peer_target_revision,
                                   object->peer_target_root);
    if (snapshot == NULL || block_index >= snapshot->block_count ||
        object->peer_mode != DELIVERY_MODE_ACTIVE || object->retry.inflight)
        return DELIVERY_RESULT_NOT_READY;
    bit = UINT64_C(1) << block_index;
    if ((object->peer_have_bitmap & bit) != 0)
        return DELIVERY_RESULT_STALE;
    fresh = (object->attempted_bitmap & bit) == 0;
    if (fresh) {
        if (object->retry.pending) {
            rc = delivery_retry_ack(&object->retry,
                                    object->retry.generation);
            if (rc != DELIVERY_RESULT_OK)
                return rc;
        }
        rc = delivery_retry_arm(&object->retry, snapshot->revision, now_ms);
        if (rc != DELIVERY_RESULT_OK)
            return rc;
    } else if (!delivery_retry_due(&object->retry, now_ms)) {
        return DELIVERY_RESULT_NOT_READY;
    }
    rc = delivery_retry_selected(&object->retry, snapshot->revision, now_ms);
    if (rc != DELIVERY_RESULT_OK)
        return rc;
    object->attempted_bitmap |= bit;
    object->inflight_revision = snapshot->revision;
    object->inflight_block = block_index;
    return DELIVERY_RESULT_OK;
}

int delivery_latest_sender_block_result(delivery_latest_sender_t *sender,
                                        uint16_t object_id,
                                        uint16_t block_index,
                                        delivery_attempt_result_t result,
                                        int64_t now_ms)
{
    delivery_latest_sender_object_t *object;
    int rc;

    if (sender == NULL)
        return DELIVERY_RESULT_MALFORMED;
    object = latest_sender_find(sender, object_id);
    if (object == NULL)
        return DELIVERY_RESULT_UNCONFIGURED;
    if (!object->retry.inflight || object->inflight_block != block_index)
        return DELIVERY_RESULT_STALE;
    rc = delivery_retry_result(&object->retry, object->inflight_revision,
                               result, now_ms);
    if (rc == DELIVERY_RESULT_OK) {
        uint64_t completed_revision = object->inflight_revision;
        object->inflight_revision = 0;
        object->inflight_block = 0;
        if (completed_revision != object->peer_target_revision) {
            (void)delivery_retry_init(&object->retry,
                                      DELIVERY_LATEST_RETRY_MS);
            if (object->peer_target_revision != 0)
                (void)delivery_retry_arm(&object->retry,
                                         object->peer_target_revision,
                                         now_ms);
        }
    }
    return rc;
}

static delivery_latest_receiver_object_t *latest_receiver_find(
    delivery_latest_receiver_t *receiver, uint16_t object_id)
{
    unsigned int i;

    for (i = 0; i < DELIVERY_LATEST_OBJECTS; i++) {
        if (receiver->objects[i].configured &&
            receiver->objects[i].object_id == object_id)
            return &receiver->objects[i];
    }
    return NULL;
}

static const delivery_latest_receiver_object_t *latest_receiver_find_const(
    const delivery_latest_receiver_t *receiver, uint16_t object_id)
{
    unsigned int i;

    for (i = 0; i < DELIVERY_LATEST_OBJECTS; i++) {
        if (receiver->objects[i].configured &&
            receiver->objects[i].object_id == object_id)
            return &receiver->objects[i];
    }
    return NULL;
}

static void latest_receiver_mark_status_changed(
    delivery_latest_receiver_t *receiver,
    const delivery_latest_receiver_object_t *object)
{
    ptrdiff_t slot;

    if (receiver == NULL || object == NULL)
        return;
    slot = object - receiver->objects;
    if (slot >= 0 && (size_t)slot < DELIVERY_LATEST_OBJECTS)
        receiver->status_changed_mask |=
            (uint8_t)(UINT8_C(1) << (unsigned int)slot);
}

static int latest_head_snapshot_equal(const delivery_latest_head_t *a,
                                      const delivery_latest_head_t *b)
{
    return a->object_id == b->object_id && a->revision == b->revision &&
           a->total_length == b->total_length &&
           a->block_size == b->block_size &&
           a->block_count == b->block_count &&
           hash_equal(a->content_root, b->content_root) &&
           hash_equal(a->previous_chain, b->previous_chain) &&
           hash_equal(a->version_chain, b->version_chain);
}

/* The snapshot fields above are immutable identity.  The drop tuple is
 * cumulative advisory state: once a receiver has acknowledged a revision,
 * the sender deliberately stops repeating that interval without publishing
 * a new snapshot.  A HEAD materialized on either side of that acknowledgement
 * may therefore arrive later.  Treat already-absorbed drop tuples as stale
 * detail of the same target, while an unacknowledged conflicting tuple remains
 * a loud divergence. */
static int latest_head_repeat_compatible(
    const delivery_latest_receiver_object_t *object,
    const delivery_latest_head_t *head)
{
    const delivery_latest_head_t *target = &object->target;

    if (!latest_head_snapshot_equal(head, target))
        return 0;
    if (head->drop_revision == target->drop_revision &&
        head->dropped_first == target->dropped_first &&
        head->dropped_last == target->dropped_last)
        return 1;
    return head->drop_revision <= object->accepted_drop_revision &&
           target->drop_revision <= object->accepted_drop_revision;
}

static int latest_head_integrity(const delivery_latest_receiver_t *receiver,
                                 const delivery_latest_head_t *head)
{
    uint8_t calculated[DELIVERY_HASH_BYTES];
    int valid;

    if (!head_valid(head))
        return 0;
    delivery_latest_version_hash(receiver->context, receiver->direction,
                                 head->object_id, head->revision,
                                 head->total_length, head->block_count,
                                 head->previous_chain, head->content_root,
                                 calculated);
    valid = hash_equal(calculated, head->version_chain);
    crypto_wipe(calculated, sizeof(calculated));
    return valid;
}

static int receiver_set_reservation_quota(
    delivery_latest_receiver_object_t *object, int enabled)
{
    uint8_t prior = object->quota_reservation;
    int combined;
    int rc;

    object->quota_reservation = enabled != 0;
    combined = object->quota_local || object->quota_reservation;
    rc = delivery_flow_set_reason(&object->flow,
                                  DELIVERY_REASON_QUOTA_REFUSED, combined);
    if (rc != DELIVERY_RESULT_OK)
        object->quota_reservation = prior;
    return rc;
}

static void latest_receiver_release_target(
    delivery_latest_receiver_t *receiver,
    delivery_latest_receiver_object_t *object)
{
    if (object->target_reserved) {
        receiver->reserved_bytes -= object->target.total_length;
        object->target_reserved = 0;
    }
    object->target_valid = 0;
    object->have_bitmap = 0;
    object->frontier = 0;
    memset(object->frontier_hash, 0, DELIVERY_HASH_BYTES);
    memset(&object->target, 0, sizeof(object->target));
    crypto_wipe(object->bytes, sizeof(object->bytes));
}

/* Check both independent resource invariants without mutating state:
 * aggregate reservations never exceed 32 KiB, and non-reserved objects never
 * consume the carve promised to the reserved object.  exclude_current is
 * used while atomically superseding an already-reserved target. */
static int latest_receiver_reservation_fits(
    const delivery_latest_receiver_t *receiver,
    const delivery_latest_receiver_object_t *object,
    uint32_t length, int exclude_current)
{
    const delivery_latest_receiver_object_t *reserved_object = NULL;
    uint32_t total = receiver->reserved_bytes;
    uint32_t reserved_current = 0;
    uint32_t nonreserved;
    unsigned int i;

    if (exclude_current && object->target_valid && object->target_reserved)
        total -= object->target.total_length;
    if (receiver->reserved_object_bytes != 0) {
        for (i = 0; i < DELIVERY_LATEST_OBJECTS; i++)
            if (receiver->objects[i].configured &&
                receiver->objects[i].object_id ==
                    DELIVERY_LATEST_SYSTEM_OBJECT_ID) {
                reserved_object = &receiver->objects[i];
                break;
            }
        if (reserved_object != NULL && reserved_object->target_valid &&
            reserved_object->target_reserved &&
            !(exclude_current && reserved_object == object))
            reserved_current = reserved_object->target.total_length;
    }
    if (reserved_current > total)
        return 0;
    nonreserved = total - reserved_current;
    if ((uint64_t)total + length > DELIVERY_LATEST_AGGREGATE_BYTES)
        return 0;
    if (receiver->reserved_object_bytes != 0 &&
        object->object_id != DELIVERY_LATEST_SYSTEM_OBJECT_ID &&
        (uint64_t)nonreserved + length >
            DELIVERY_LATEST_AGGREGATE_BYTES -
                receiver->reserved_object_bytes)
        return 0;
    return 1;
}

static int latest_receiver_try_reserve(
    delivery_latest_receiver_t *receiver,
    delivery_latest_receiver_object_t *object)
{
    uint64_t prior_flow_revision;
    uint8_t prior_reserved;
    uint8_t prior_quota;
    int blocked;
    int rc;

    if (!object->target_valid || object->target_reserved)
        return DELIVERY_RESULT_OK;
    prior_flow_revision = object->flow.revision;
    prior_reserved = object->target_reserved;
    prior_quota = object->quota_reservation;
    blocked = object->flow.not_interested || object->flow.reset_required ||
              object->quota_local;
    if (blocked)
        return DELIVERY_RESULT_NOT_READY;
    if (!latest_receiver_reservation_fits(
            receiver, object, object->target.total_length, 0)) {
        rc = receiver_set_reservation_quota(object, 1);
        if (object->flow.revision != prior_flow_revision ||
            object->target_reserved != prior_reserved ||
            object->quota_reservation != prior_quota)
            latest_receiver_mark_status_changed(receiver, object);
        return rc == DELIVERY_RESULT_OK ? DELIVERY_RESULT_SOURCE_QUOTA : rc;
    }
    rc = receiver_set_reservation_quota(object, 0);
    if (rc != DELIVERY_RESULT_OK)
        return rc;
    object->target_reserved = 1;
    receiver->reserved_bytes += object->target.total_length;
    if (object->flow.revision != prior_flow_revision ||
        object->target_reserved != prior_reserved ||
        object->quota_reservation != prior_quota)
        latest_receiver_mark_status_changed(receiver, object);
    return DELIVERY_RESULT_OK;
}

void delivery_latest_receiver_init(
    delivery_latest_receiver_t *receiver,
    const uint8_t context[DELIVERY_CONTEXT_BYTES], uint8_t direction)
{
    memset(receiver, 0, sizeof(*receiver));
    memcpy(receiver->context, context, DELIVERY_CONTEXT_BYTES);
    receiver->direction = direction;
}

int delivery_latest_receiver_reserve_object(
    delivery_latest_receiver_t *receiver, uint16_t object_id,
    uint32_t bytes)
{
    unsigned int i;

    if (receiver == NULL ||
        object_id != DELIVERY_LATEST_SYSTEM_OBJECT_ID || bytes == 0 ||
        bytes > DELIVERY_LATEST_AGGREGATE_BYTES)
        return DELIVERY_RESULT_MALFORMED;
    if (receiver->reserved_bytes != 0 ||
        receiver->reserved_object_bytes != 0)
        return DELIVERY_RESULT_BUSY;
    for (i = 0; i < DELIVERY_LATEST_OBJECTS; i++)
        if (receiver->objects[i].configured)
            return DELIVERY_RESULT_BUSY;
    receiver->reserved_object_bytes = (uint16_t)bytes;
    return DELIVERY_RESULT_OK;
}

int delivery_latest_receiver_configure(
    delivery_latest_receiver_t *receiver, unsigned int slot,
    uint16_t object_id, delivery_priority_t priority,
    delivery_latest_install_fn install, void *install_arg)
{
    delivery_latest_receiver_object_t *object;

    if (receiver == NULL || slot >= DELIVERY_LATEST_OBJECTS || object_id == 0 ||
        install == NULL ||
        (priority != DELIVERY_PRIORITY_LOW &&
         priority != DELIVERY_PRIORITY_HIGH) ||
        latest_receiver_find(receiver, object_id) != NULL)
        return DELIVERY_RESULT_MALFORMED;
    object = &receiver->objects[slot];
    if (object->configured)
        return DELIVERY_RESULT_BUSY;
    memset(object, 0, sizeof(*object));
    object->configured = 1;
    object->priority = (uint8_t)priority;
    object->object_id = object_id;
    object->install = install;
    object->install_arg = install_arg;
    delivery_flow_init(&object->flow);
    return DELIVERY_RESULT_OK;
}

int delivery_latest_receiver_validate_head(
    const delivery_latest_receiver_t *receiver,
    const delivery_latest_head_t *head)
{
    const delivery_latest_receiver_object_t *object;
    delivery_flow_state_t next_flow;
    int reserve_target;
    int reservation_quota;
    int combined_quota;
    int rc;

    if (receiver == NULL || !latest_head_integrity(receiver, head))
        return DELIVERY_RESULT_MALFORMED;
    object = latest_receiver_find_const(receiver, head->object_id);
    if (object == NULL)
        return DELIVERY_RESULT_UNCONFIGURED;
    if (head->revision < object->installed_revision)
        return DELIVERY_RESULT_STALE;
    if (head->revision == object->installed_revision) {
        if (!hash_equal(head->version_chain, object->installed_chain))
            return DELIVERY_RESULT_DIVERGED;
        if (head->drop_revision > object->accepted_drop_revision) {
            if (object->flow.revision == UINT64_MAX)
                return DELIVERY_RESULT_EXHAUSTED;
            next_flow = object->flow;
            return delivery_flow_target_changed(&next_flow);
        }
        return DELIVERY_RESULT_DUPLICATE;
    }
    if (object->target_valid) {
        if (head->revision < object->target.revision)
            return DELIVERY_RESULT_STALE;
        if (head->revision == object->target.revision)
            return latest_head_repeat_compatible(object, head)
                 ? DELIVERY_RESULT_DUPLICATE : DELIVERY_RESULT_DIVERGED;
    }
    reserve_target = !object->flow.not_interested &&
                     !object->flow.reset_required && !object->quota_local &&
                     latest_receiver_reservation_fits(
                         receiver, object, head->total_length, 1);
    reservation_quota = !reserve_target && !object->flow.not_interested &&
                        !object->flow.reset_required && !object->quota_local;
    combined_quota = object->quota_local || reservation_quota;
    next_flow = object->flow;
    rc = delivery_flow_set_reason(&next_flow,
                                  DELIVERY_REASON_QUOTA_REFUSED,
                                  combined_quota);
    if (rc != DELIVERY_RESULT_OK)
        return rc;
    return delivery_flow_target_changed(&next_flow);
}

int delivery_latest_receiver_observe_head(
    delivery_latest_receiver_t *receiver,
    const delivery_latest_head_t *head)
{
    delivery_latest_receiver_object_t *object;
    delivery_flow_state_t next_flow;
    int reserve_target;
    int reservation_quota;
    int combined_quota;
    int rc;

    if (receiver == NULL || !latest_head_integrity(receiver, head))
        return DELIVERY_RESULT_MALFORMED;
    object = latest_receiver_find(receiver, head->object_id);
    if (object == NULL)
        return DELIVERY_RESULT_UNCONFIGURED;
    if (head->revision < object->installed_revision)
        return DELIVERY_RESULT_STALE;
    if (head->revision == object->installed_revision) {
        if (!hash_equal(head->version_chain, object->installed_chain))
            return DELIVERY_RESULT_DIVERGED;
        if (head->drop_revision > object->accepted_drop_revision) {
            if (object->flow.revision == UINT64_MAX)
                return DELIVERY_RESULT_EXHAUSTED;
            object->accepted_drop_revision = head->drop_revision;
            rc = delivery_flow_target_changed(&object->flow);
            if (rc == DELIVERY_RESULT_OK)
                latest_receiver_mark_status_changed(receiver, object);
            return rc;
        }
        return DELIVERY_RESULT_DUPLICATE;
    }
    if (object->target_valid) {
        if (head->revision < object->target.revision)
            return DELIVERY_RESULT_STALE;
        if (head->revision == object->target.revision) {
            if (!latest_head_repeat_compatible(object, head))
                return DELIVERY_RESULT_DIVERGED;
            return DELIVERY_RESULT_DUPLICATE;
        }
    }
    reserve_target = !object->flow.not_interested &&
                     !object->flow.reset_required && !object->quota_local &&
                     latest_receiver_reservation_fits(
                         receiver, object, head->total_length, 1);
    reservation_quota = !reserve_target && !object->flow.not_interested &&
                        !object->flow.reset_required && !object->quota_local;
    combined_quota = object->quota_local || reservation_quota;
    next_flow = object->flow;
    rc = delivery_flow_set_reason(&next_flow,
                                  DELIVERY_REASON_QUOTA_REFUSED,
                                  combined_quota);
    if (rc != DELIVERY_RESULT_OK)
        return rc;
    rc = delivery_flow_target_changed(&next_flow);
    if (rc != DELIVERY_RESULT_OK)
        return rc;
    if (object->target_valid)
        latest_receiver_release_target(receiver, object);
    object->target = *head;
    object->target_valid = 1;
    object->target_reserved = reserve_target != 0;
    object->quota_reservation = reservation_quota != 0;
    object->flow = next_flow;
    object->have_bitmap = 0;
    object->frontier = 0;
    memset(object->frontier_hash, 0, DELIVERY_HASH_BYTES);
    if (object->target_reserved)
        receiver->reserved_bytes += head->total_length;
    if (head->drop_revision > object->accepted_drop_revision)
        object->accepted_drop_revision = head->drop_revision;
    latest_receiver_mark_status_changed(receiver, object);
    return DELIVERY_RESULT_OK;
}

static int latest_receiver_observe_block_object(
    const uint8_t context[DELIVERY_CONTEXT_BYTES], uint8_t direction,
    delivery_latest_receiver_object_t *object,
    const delivery_latest_block_t *block)
{
    uint64_t bit;
    size_t offset;
    uint16_t length;

    if (!object->target_valid ||
        block->revision != object->target.revision ||
        !hash_equal(block->content_root, object->target.content_root) ||
        block->block_count != object->target.block_count ||
        block->total_length != object->target.total_length)
        return DELIVERY_RESULT_STALE;
    if (!object->target_reserved || object->flow.mode != DELIVERY_MODE_ACTIVE)
        return DELIVERY_RESULT_NOT_READY;
    bit = UINT64_C(1) << block->block_index;
    offset = (size_t)block->block_index * DELIVERY_LATEST_BLOCK_BODY_MAX;
    if ((object->have_bitmap & bit) != 0) {
        if (block->body_length !=
                latest_expected_body(object->target.total_length,
                                     object->target.block_count,
                                     block->block_index) ||
            (block->body_length != 0 &&
             memcmp(object->bytes + offset, block->body,
                    block->body_length) != 0))
            return DELIVERY_RESULT_DIVERGED;
        return DELIVERY_RESULT_DUPLICATE;
    }
    if (block->body_length != 0)
        memcpy(object->bytes + offset, block->body, block->body_length);
    object->have_bitmap |= bit;

    while (object->frontier < object->target.block_count &&
           (object->have_bitmap & (UINT64_C(1) << object->frontier)) != 0) {
        uint8_t leaf[DELIVERY_HASH_BYTES];
        uint8_t next[DELIVERY_HASH_BYTES];
        uint16_t index = object->frontier;
        const uint8_t *body = object->bytes +
            (size_t)index * DELIVERY_LATEST_BLOCK_BODY_MAX;
        length = latest_expected_body(object->target.total_length,
                                      object->target.block_count, index);
        delivery_latest_leaf_hash(context, direction,
                                  object->object_id, object->target.revision,
                                  object->target.total_length,
                                  object->target.block_count, index,
                                  body, length, leaf);
        delivery_latest_chain_hash(context, direction,
                                   object->object_id, object->target.revision,
                                   index, object->frontier_hash, leaf, next);
        memcpy(object->frontier_hash, next, DELIVERY_HASH_BYTES);
        object->frontier++;
        crypto_wipe(leaf, sizeof(leaf));
        crypto_wipe(next, sizeof(next));
    }
    if (object->frontier == object->target.block_count) {
        if (!hash_equal(object->frontier_hash, object->target.content_root)) {
            (void)delivery_flow_set_reason(&object->flow,
                                           DELIVERY_REASON_RESET_REQUIRED, 1);
            return DELIVERY_RESULT_DIVERGED;
        }
        return DELIVERY_RESULT_COMPLETE;
    }
    return DELIVERY_RESULT_OK;
}

int delivery_latest_receiver_validate_block(
    const delivery_latest_receiver_t *receiver,
    const delivery_latest_block_t *block)
{
    const delivery_latest_receiver_object_t *object;
    delivery_latest_receiver_object_t copy;
    int rc;

    if (receiver == NULL || !block_valid(block))
        return DELIVERY_RESULT_MALFORMED;
    object = latest_receiver_find_const(receiver, block->object_id);
    if (object == NULL)
        return DELIVERY_RESULT_UNCONFIGURED;
    copy = *object;
    rc = latest_receiver_observe_block_object(
        receiver->context, receiver->direction, &copy, block);
    crypto_wipe(&copy, sizeof(copy));
    return rc;
}

int delivery_latest_receiver_observe_block(
    delivery_latest_receiver_t *receiver,
    const delivery_latest_block_t *block)
{
    delivery_latest_receiver_object_t *object;
    int rc;

    if (receiver == NULL || !block_valid(block))
        return DELIVERY_RESULT_MALFORMED;
    object = latest_receiver_find(receiver, block->object_id);
    if (object == NULL)
        return DELIVERY_RESULT_UNCONFIGURED;
    rc = latest_receiver_observe_block_object(
        receiver->context, receiver->direction, object, block);
    if (rc == DELIVERY_RESULT_OK || rc == DELIVERY_RESULT_COMPLETE ||
        rc == DELIVERY_RESULT_DIVERGED)
        latest_receiver_mark_status_changed(receiver, object);
    return rc;
}

static int latest_receiver_refresh_reservations_mutating(
    delivery_latest_receiver_t *receiver);

static int latest_receiver_commit_install_state(
    delivery_latest_receiver_t *receiver,
    delivery_latest_receiver_object_t *object)
{
    uint64_t revision;
    uint64_t drop_revision;
    uint8_t chain[DELIVERY_HASH_BYTES];
    int rc;

    revision = object->target.revision;
    drop_revision = object->target.drop_revision;
    memcpy(chain, object->target.version_chain, DELIVERY_HASH_BYTES);
    latest_receiver_release_target(receiver, object);
    object->installed_revision = revision;
    memcpy(object->installed_chain, chain, DELIVERY_HASH_BYTES);
    if (drop_revision > object->accepted_drop_revision)
        object->accepted_drop_revision = drop_revision;
    rc = delivery_flow_target_changed(&object->flow);
    if (rc != DELIVERY_RESULT_OK) {
        crypto_wipe(chain, sizeof(chain));
        return rc;
    }
    latest_receiver_mark_status_changed(receiver, object);
    rc = latest_receiver_refresh_reservations_mutating(receiver);
    crypto_wipe(chain, sizeof(chain));
    return rc < 0 ? rc : DELIVERY_RESULT_INSTALLED;
}

int delivery_latest_receiver_install(delivery_latest_receiver_t *receiver,
                                     uint16_t object_id)
{
    delivery_latest_receiver_t copy;
    delivery_latest_receiver_object_t *object;
    delivery_latest_receiver_object_t *copy_object;
    int rc;

    if (receiver == NULL)
        return DELIVERY_RESULT_MALFORMED;
    object = latest_receiver_find(receiver, object_id);
    if (object == NULL)
        return DELIVERY_RESULT_UNCONFIGURED;
    if (!object->target_valid || !object->target_reserved ||
        object->flow.mode != DELIVERY_MODE_ACTIVE ||
        object->frontier != object->target.block_count ||
        !hash_equal(object->frontier_hash, object->target.content_root))
        return DELIVERY_RESULT_NOT_READY;
    if (object->flow.revision == UINT64_MAX)
        return DELIVERY_RESULT_EXHAUSTED;

    /* Preflight every flow-revision and aggregate-reservation mutation before
     * the application callback makes the install externally visible. */
    copy = *receiver;
    copy_object = latest_receiver_find(&copy, object_id);
    if (copy_object == NULL) {
        crypto_wipe(&copy, sizeof(copy));
        return DELIVERY_RESULT_DIVERGED;
    }
    rc = latest_receiver_commit_install_state(&copy, copy_object);
    crypto_wipe(&copy, sizeof(copy));
    if (rc < 0)
        return rc;

    if (object->install(object->install_arg, object_id,
                        object->target.revision, object->bytes,
                        object->target.total_length) != 0)
        return DELIVERY_RESULT_NOT_READY;
    return latest_receiver_commit_install_state(receiver, object);
}

int delivery_latest_receiver_cancel_target(
    delivery_latest_receiver_t *receiver, uint16_t object_id)
{
    delivery_latest_receiver_t copy;
    delivery_latest_receiver_object_t *object;
    delivery_flow_state_t next_flow;
    int combined_quota;
    int rc;

    if (receiver == NULL)
        return DELIVERY_RESULT_MALFORMED;
    copy = *receiver;
    object = latest_receiver_find(&copy, object_id);
    if (object == NULL) {
        crypto_wipe(&copy, sizeof(copy));
        return DELIVERY_RESULT_UNCONFIGURED;
    }
    if (!object->target_valid) {
        crypto_wipe(&copy, sizeof(copy));
        return DELIVERY_RESULT_STALE;
    }
    next_flow = object->flow;
    combined_quota = object->quota_local != 0;
    rc = delivery_flow_set_reason(&next_flow,
                                  DELIVERY_REASON_QUOTA_REFUSED,
                                  combined_quota);
    if (rc != DELIVERY_RESULT_OK) {
        crypto_wipe(&copy, sizeof(copy));
        return rc;
    }
    rc = delivery_flow_target_changed(&next_flow);
    if (rc != DELIVERY_RESULT_OK) {
        crypto_wipe(&copy, sizeof(copy));
        return rc;
    }
    latest_receiver_release_target(&copy, object);
    object->quota_reservation = 0;
    object->flow = next_flow;
    latest_receiver_mark_status_changed(&copy, object);
    rc = latest_receiver_refresh_reservations_mutating(&copy);
    if (rc < 0) {
        crypto_wipe(&copy, sizeof(copy));
        return rc;
    }
    *receiver = copy;
    crypto_wipe(&copy, sizeof(copy));
    return DELIVERY_RESULT_OK;
}

int delivery_latest_receiver_status(
    const delivery_latest_receiver_t *receiver, uint16_t object_id,
    delivery_latest_status_t *status)
{
    const delivery_latest_receiver_object_t *object;

    if (receiver == NULL || status == NULL)
        return DELIVERY_RESULT_MALFORMED;
    object = latest_receiver_find_const(receiver, object_id);
    if (object == NULL)
        return DELIVERY_RESULT_UNCONFIGURED;
    memset(status, 0, sizeof(*status));
    status->object_id = object_id;
    status->mode = object->flow.mode;
    status->flow_revision = object->flow.revision;
    status->installed_revision = object->installed_revision;
    memcpy(status->installed_chain, object->installed_chain,
           DELIVERY_HASH_BYTES);
    status->accepted_drop_revision = object->accepted_drop_revision;
    if (object->target_valid) {
        status->target_revision = object->target.revision;
        memcpy(status->target_root, object->target.content_root,
               DELIVERY_HASH_BYTES);
        status->target_block_count = object->target.block_count;
        status->have_bitmap = object->have_bitmap;
        status->frontier = object->frontier;
        memcpy(status->frontier_hash, object->frontier_hash,
               DELIVERY_HASH_BYTES);
        /* Absolute credit is a reservation fact, not a resume event.  Policy
         * mode suppresses payload selection; it never retracts bytes already
         * reserved for this exact target. */
        if (object->target_reserved)
            status->accepted_limit = object->target.total_length;
    }
    return status_valid(status) ? DELIVERY_RESULT_OK :
                                  DELIVERY_RESULT_DIVERGED;
}

int delivery_latest_receiver_set_reason(
    delivery_latest_receiver_t *receiver, uint16_t object_id,
    delivery_reason_t reason, int enabled)
{
    delivery_latest_receiver_t copy;
    delivery_latest_receiver_object_t *object;
    uint64_t prior_flow_revision;
    int rc;

    if (receiver == NULL)
        return DELIVERY_RESULT_MALFORMED;
    copy = *receiver;
    object = latest_receiver_find(&copy, object_id);
    if (object == NULL) {
        crypto_wipe(&copy, sizeof(copy));
        return DELIVERY_RESULT_UNCONFIGURED;
    }
    prior_flow_revision = object->flow.revision;
    if (reason == DELIVERY_REASON_QUOTA_REFUSED) {
        uint8_t prior = object->quota_local;
        object->quota_local = enabled != 0;
        rc = delivery_flow_set_reason(
            &object->flow, reason,
            object->quota_local || object->quota_reservation);
        if (rc != DELIVERY_RESULT_OK)
            object->quota_local = prior;
    } else {
        rc = delivery_flow_set_reason(&object->flow, reason, enabled);
    }
    if (rc != DELIVERY_RESULT_OK) {
        crypto_wipe(&copy, sizeof(copy));
        return rc;
    }
    if (object->flow.revision != prior_flow_revision)
        latest_receiver_mark_status_changed(&copy, object);
    if (!enabled && (reason == DELIVERY_REASON_QUOTA_REFUSED ||
                     reason == DELIVERY_REASON_RESET_REQUIRED ||
                     reason == DELIVERY_REASON_NOT_INTERESTED))
        rc = latest_receiver_refresh_reservations_mutating(&copy);
    if (rc < 0) {
        crypto_wipe(&copy, sizeof(copy));
        return rc;
    }
    *receiver = copy;
    crypto_wipe(&copy, sizeof(copy));
    return DELIVERY_RESULT_OK;
}

static int latest_receiver_refresh_reservations_mutating(
    delivery_latest_receiver_t *receiver)
{
    unsigned int i;
    int waiting = 0;

    if (receiver == NULL)
        return DELIVERY_RESULT_MALFORMED;
    for (i = 0; i < DELIVERY_LATEST_OBJECTS; i++) {
        delivery_latest_receiver_object_t *object = &receiver->objects[i];
        int rc;
        if (!object->configured || !object->target_valid ||
            object->target_reserved)
            continue;
        rc = latest_receiver_try_reserve(receiver, object);
        if (rc == DELIVERY_RESULT_SOURCE_QUOTA ||
            rc == DELIVERY_RESULT_NOT_READY)
            waiting = 1;
        else if (rc != DELIVERY_RESULT_OK)
            return rc;
    }
    return waiting ? DELIVERY_RESULT_NOT_READY : DELIVERY_RESULT_OK;
}

int delivery_latest_receiver_refresh_reservations(
    delivery_latest_receiver_t *receiver)
{
    delivery_latest_receiver_t copy;
    int rc;

    if (receiver == NULL)
        return DELIVERY_RESULT_MALFORMED;
    copy = *receiver;
    rc = latest_receiver_refresh_reservations_mutating(&copy);
    if (rc < 0) {
        crypto_wipe(&copy, sizeof(copy));
        return rc;
    }
    *receiver = copy;
    crypto_wipe(&copy, sizeof(copy));
    return rc;
}

uint8_t delivery_latest_receiver_take_status_changed(
    delivery_latest_receiver_t *receiver)
{
    uint8_t mask;

    if (receiver == NULL)
        return 0;
    mask = receiver->status_changed_mask;
    receiver->status_changed_mask = 0;
    return mask;
}

static delivery_reliable_sender_flow_t *reliable_sender_find(
    delivery_reliable_sender_t *sender, uint16_t flow_id)
{
    unsigned int i;

    for (i = 0; i < DELIVERY_RELIABLE_FLOWS; i++) {
        if (sender->flows[i].configured && sender->flows[i].flow_id == flow_id)
            return &sender->flows[i];
    }
    return NULL;
}

static const delivery_reliable_sender_flow_t *reliable_sender_find_const(
    const delivery_reliable_sender_t *sender, uint16_t flow_id)
{
    unsigned int i;

    for (i = 0; i < DELIVERY_RELIABLE_FLOWS; i++) {
        if (sender->flows[i].configured && sender->flows[i].flow_id == flow_id)
            return &sender->flows[i];
    }
    return NULL;
}

static int reliable_status_equal(const delivery_reliable_status_t *a,
                                 const delivery_reliable_status_t *b)
{
    return a->flow_id == b->flow_id && a->mode == b->mode &&
           a->flags == b->flags &&
           a->flow_revision == b->flow_revision &&
           a->delivered_id == b->delivered_id &&
           hash_equal(a->delivered_hash, b->delivered_hash) &&
           a->target_id == b->target_id &&
           hash_equal(a->target_hash, b->target_hash) &&
           a->accepted_limit == b->accepted_limit;
}

void delivery_reliable_sender_init(
    delivery_reliable_sender_t *sender,
    const uint8_t context[DELIVERY_CONTEXT_BYTES], uint8_t direction)
{
    memset(sender, 0, sizeof(*sender));
    memcpy(sender->context, context, DELIVERY_CONTEXT_BYTES);
    sender->direction = direction;
    delivery_service_init(&sender->service);
}

int delivery_reliable_sender_configure(delivery_reliable_sender_t *sender,
                                       unsigned int slot, uint16_t flow_id,
                                       delivery_priority_t priority)
{
    delivery_reliable_sender_flow_t *flow;

    if (sender == NULL || slot >= DELIVERY_RELIABLE_FLOWS || flow_id == 0 ||
        (priority != DELIVERY_PRIORITY_LOW &&
         priority != DELIVERY_PRIORITY_HIGH) ||
        reliable_sender_find(sender, flow_id) != NULL)
        return DELIVERY_RESULT_MALFORMED;
    flow = &sender->flows[slot];
    if (flow->configured)
        return DELIVERY_RESULT_BUSY;
    memset(flow, 0, sizeof(*flow));
    flow->configured = 1;
    flow->priority = (uint8_t)priority;
    flow->flow_id = flow_id;
    flow->next_message_id = 1;
    flow->peer_mode = DELIVERY_MODE_ACTIVE;
    flow->last_result = DELIVERY_RESULT_NOT_READY;
    (void)delivery_retry_init(&flow->retry, DELIVERY_RELIABLE_RETRY_MS);
    return DELIVERY_RESULT_OK;
}

int delivery_reliable_sender_admit(delivery_reliable_sender_t *sender,
                                   uint16_t flow_id, const uint8_t *bytes,
                                   size_t length, int64_t now_ms,
                                   uint64_t *message_id_out)
{
    delivery_reliable_sender_flow_t *flow;
    delivery_reliable_data_t candidate;
    uint64_t message_id;
    int defer_retry;
    int rc;

    if (sender == NULL || length > DELIVERY_RELIABLE_BODY_MAX ||
        (length != 0 && bytes == NULL))
        return DELIVERY_RESULT_MALFORMED;
    flow = reliable_sender_find(sender, flow_id);
    if (flow == NULL)
        return DELIVERY_RESULT_UNCONFIGURED;
    if (flow->pending)
        return DELIVERY_RESULT_BUSY;
    if (flow->next_message_id == 0)
        return DELIVERY_RESULT_EXHAUSTED;
    message_id = flow->next_message_id;
    defer_retry = flow->retry.pending;
    if (defer_retry &&
        (!flow->retry.inflight || !flow->transport_semantic_retired))
        return DELIVERY_RESULT_BUSY;
    memset(&candidate, 0, sizeof(candidate));
    candidate.flow_id = flow_id;
    candidate.message_id = message_id;
    candidate.body_length = (uint16_t)length;
    if (length != 0)
        memcpy(candidate.body, bytes, length);
    delivery_reliable_content_hash(sender->context, sender->direction,
                                   flow_id, message_id, candidate.body,
                                   length, candidate.content_hash);
    if (!defer_retry) {
        rc = delivery_retry_arm(&flow->retry, message_id, now_ms);
        if (rc != DELIVERY_RESULT_OK)
            return rc;
    }
    flow->record = candidate;
    flow->pending = 1;
    flow->last_result = DELIVERY_RESULT_NOT_READY;
    if (message_id == UINT64_MAX)
        flow->next_message_id = 0;
    else
        flow->next_message_id++;
    if (message_id_out != NULL)
        *message_id_out = message_id;
    return DELIVERY_RESULT_OK;
}

int delivery_reliable_sender_due(const delivery_reliable_sender_t *sender,
                                 uint16_t flow_id, int64_t now_ms)
{
    const delivery_reliable_sender_flow_t *flow;

    if (sender == NULL)
        return 0;
    flow = reliable_sender_find_const(sender, flow_id);
    return flow != NULL && flow->pending &&
           flow->peer_mode == DELIVERY_MODE_ACTIVE &&
           flow->retry.generation == flow->record.message_id &&
           delivery_retry_due(&flow->retry, now_ms);
}

int delivery_reliable_sender_select_due(
    delivery_reliable_sender_t *sender, int64_t now_ms,
    delivery_reliable_data_t *record, int *is_recovery,
    unsigned int *slot_out)
{
    uint8_t high_mask = 0;
    uint8_t low_mask = 0;
    unsigned int i;
    unsigned int slot;

    if (sender == NULL || record == NULL || is_recovery == NULL ||
        slot_out == NULL)
        return DELIVERY_RESULT_MALFORMED;
    for (i = 0; i < DELIVERY_RELIABLE_FLOWS; i++) {
        const delivery_reliable_sender_flow_t *flow = &sender->flows[i];
        if (!flow->configured ||
            !delivery_reliable_sender_due(sender, flow->flow_id, now_ms))
            continue;
        if (flow->priority == DELIVERY_PRIORITY_HIGH)
            high_mask |= (uint8_t)(1U << i);
        else
            low_mask |= (uint8_t)(1U << i);
    }
    if (delivery_service_select(&sender->service, high_mask, low_mask,
                                &slot) != DELIVERY_RESULT_OK)
        return DELIVERY_RESULT_NOT_READY;
    *record = sender->flows[slot].record;
    *is_recovery = sender->flows[slot].retry.attempts != 0;
    *slot_out = slot;
    return DELIVERY_RESULT_OK;
}

int delivery_reliable_sender_data(const delivery_reliable_sender_t *sender,
                                  uint16_t flow_id,
                                  delivery_reliable_data_t *record)
{
    const delivery_reliable_sender_flow_t *flow;

    if (sender == NULL || record == NULL)
        return DELIVERY_RESULT_MALFORMED;
    flow = reliable_sender_find_const(sender, flow_id);
    if (flow == NULL)
        return DELIVERY_RESULT_UNCONFIGURED;
    if (!flow->pending)
        return DELIVERY_RESULT_NOT_READY;
    *record = flow->record;
    return DELIVERY_RESULT_OK;
}

int delivery_reliable_sender_selected(delivery_reliable_sender_t *sender,
                                      uint16_t flow_id, int64_t now_ms)
{
    delivery_reliable_sender_flow_t *flow;

    if (sender == NULL)
        return DELIVERY_RESULT_MALFORMED;
    flow = reliable_sender_find(sender, flow_id);
    if (flow == NULL)
        return DELIVERY_RESULT_UNCONFIGURED;
    if (!flow->pending || flow->peer_mode != DELIVERY_MODE_ACTIVE)
        return DELIVERY_RESULT_NOT_READY;
    if (delivery_retry_selected(&flow->retry, flow->record.message_id,
                                now_ms) != DELIVERY_RESULT_OK)
        return DELIVERY_RESULT_NOT_READY;
    flow->transport_id = flow->record.message_id;
    memcpy(flow->transport_hash, flow->record.content_hash,
           DELIVERY_HASH_BYTES);
    flow->transport_semantic_retired = 0;
    return DELIVERY_RESULT_OK;
}

int delivery_reliable_sender_result(delivery_reliable_sender_t *sender,
                                    uint16_t flow_id, uint64_t message_id,
                                    delivery_attempt_result_t result,
                                    int64_t now_ms)
{
    delivery_reliable_sender_flow_t *flow;
    int semantic_retired;
    int rc;

    if (sender == NULL)
        return DELIVERY_RESULT_MALFORMED;
    flow = reliable_sender_find(sender, flow_id);
    if (flow == NULL)
        return DELIVERY_RESULT_UNCONFIGURED;
    if (!flow->retry.inflight || flow->retry.generation != message_id ||
        flow->transport_id != message_id)
        return DELIVERY_RESULT_STALE;
    semantic_retired = flow->transport_semantic_retired;
    rc = delivery_retry_result(&flow->retry, message_id, result, now_ms);
    if (rc != DELIVERY_RESULT_OK)
        return rc;
    flow->transport_id = 0;
    memset(flow->transport_hash, 0, DELIVERY_HASH_BYTES);
    flow->transport_semantic_retired = 0;
    if (semantic_retired) {
        rc = delivery_retry_ack(&flow->retry, message_id);
        if (rc != DELIVERY_RESULT_OK)
            return rc;
        if (flow->pending)
            return delivery_retry_arm(&flow->retry,
                                      flow->record.message_id, now_ms);
    }
    return DELIVERY_RESULT_OK;
}

int delivery_reliable_sender_observe_status(
    delivery_reliable_sender_t *sender,
    const delivery_reliable_status_t *status)
{
    delivery_reliable_sender_flow_t *flow;
    uint64_t highest_issued;
    int exact_delivered = 0;
    int exact_refused = 0;
    int refusal_tombstone = 0;

    if (sender == NULL || !reliable_status_valid(status))
        return DELIVERY_RESULT_MALFORMED;
    flow = reliable_sender_find(sender, status->flow_id);
    if (flow == NULL)
        return DELIVERY_RESULT_UNCONFIGURED;
    if (status->flow_revision < flow->peer_flow_revision)
        return DELIVERY_RESULT_STALE;
    if (status->flow_revision == flow->peer_flow_revision &&
        flow->peer_flow_revision != 0) {
        if (!reliable_status_equal(&flow->peer_status, status))
            return DELIVERY_RESULT_DIVERGED;
        return DELIVERY_RESULT_DUPLICATE;
    }
    highest_issued = flow->next_message_id == 0 ? UINT64_MAX :
                                                    flow->next_message_id - 1U;
    if (status->delivered_id > highest_issued ||
        status->target_id > highest_issued)
        return DELIVERY_RESULT_DIVERGED;
    if (status->target_id != 0) {
        if ((status->flags & DELIVERY_RELIABLE_STATUS_FLAG_REFUSED) != 0) {
            if (flow->pending &&
                status->target_id == flow->record.message_id &&
                hash_equal(status->target_hash,
                           flow->record.content_hash)) {
                exact_refused = 1;
            } else if (flow->last_refused_valid &&
                       status->target_id == flow->last_result_id &&
                       hash_equal(status->target_hash,
                                  flow->last_result_hash)) {
                refusal_tombstone = 1;
            } else {
                return DELIVERY_RESULT_DIVERGED;
            }
        } else {
            if (!flow->pending ||
                status->target_id != flow->record.message_id ||
                !hash_equal(status->target_hash,
                            flow->record.content_hash))
                return DELIVERY_RESULT_DIVERGED;
            if ((status->mode == DELIVERY_MODE_ACTIVE ||
                 status->mode == DELIVERY_MODE_PAUSED ||
                 status->mode == DELIVERY_MODE_QUOTA_REFUSED) &&
                status->accepted_limit != flow->record.body_length)
                return DELIVERY_RESULT_DIVERGED;
            if (status->mode != DELIVERY_MODE_ACTIVE &&
                status->mode != DELIVERY_MODE_PAUSED &&
                status->mode != DELIVERY_MODE_QUOTA_REFUSED &&
                status->accepted_limit != 0)
                return DELIVERY_RESULT_DIVERGED;
        }
    }
    if (status->delivered_id != 0) {
        if (flow->pending &&
            status->delivered_id == flow->record.message_id &&
            hash_equal(status->delivered_hash,
                       flow->record.content_hash)) {
            exact_delivered = 1;
        } else if (status->delivered_id != flow->known_delivered_id ||
                   !hash_equal(status->delivered_hash,
                               flow->known_delivered_hash)) {
            return DELIVERY_RESULT_DIVERGED;
        }
    }
    if (status->target_id != 0 &&
        status->target_id == status->delivered_id) {
        return DELIVERY_RESULT_DIVERGED;
    }
    if ((exact_delivered || exact_refused) &&
        (!flow->retry.pending ||
         flow->retry.generation != flow->record.message_id ||
         (!flow->retry.inflight && flow->retry.attempts == 0) ||
         (flow->retry.inflight &&
          (flow->transport_id != flow->record.message_id ||
           !hash_equal(flow->transport_hash,
                       flow->record.content_hash)))))
        return DELIVERY_RESULT_DIVERGED;
    flow->peer_flow_revision = status->flow_revision;
    flow->peer_mode = status->mode;
    flow->peer_status = *status;
    if ((status->flags & DELIVERY_RELIABLE_STATUS_FLAG_REFUSED) == 0 &&
        (status->target_id != 0 || exact_delivered))
        flow->last_refused_valid = 0;
    if (exact_delivered || exact_refused) {
        uint64_t id = flow->record.message_id;
        uint8_t result_hash[DELIVERY_HASH_BYTES];
        memcpy(result_hash, flow->record.content_hash, DELIVERY_HASH_BYTES);
        if (flow->retry.inflight)
            flow->transport_semantic_retired = 1;
        else if (delivery_retry_ack(&flow->retry, id) != DELIVERY_RESULT_OK)
            return DELIVERY_RESULT_DIVERGED;
        flow->pending = 0;
        crypto_wipe(&flow->record, sizeof(flow->record));
        flow->last_result_id = id;
        memcpy(flow->last_result_hash, result_hash, DELIVERY_HASH_BYTES);
        flow->last_result = exact_delivered ? DELIVERY_RESULT_DELIVERED :
                                             DELIVERY_RESULT_REFUSED;
        flow->last_refused_valid = exact_refused != 0;
        if (exact_delivered) {
            flow->known_delivered_id = id;
            memcpy(flow->known_delivered_hash, result_hash,
                   DELIVERY_HASH_BYTES);
        }
        crypto_wipe(result_hash, sizeof(result_hash));
        return flow->last_result;
    }
    if (refusal_tombstone)
        return DELIVERY_RESULT_OK;
    return DELIVERY_RESULT_OK;
}

int delivery_reliable_sender_validate_status(
    const delivery_reliable_sender_t *sender,
    const delivery_reliable_status_t *status)
{
    delivery_reliable_sender_t copy;
    int rc;

    if (sender == NULL)
        return DELIVERY_RESULT_MALFORMED;
    copy = *sender;
    rc = delivery_reliable_sender_observe_status(&copy, status);
    crypto_wipe(&copy, sizeof(copy));
    return rc;
}

static delivery_reliable_receiver_flow_t *reliable_receiver_find(
    delivery_reliable_receiver_t *receiver, uint16_t flow_id)
{
    unsigned int i;

    for (i = 0; i < DELIVERY_RELIABLE_FLOWS; i++) {
        if (receiver->flows[i].configured &&
            receiver->flows[i].flow_id == flow_id)
            return &receiver->flows[i];
    }
    return NULL;
}

static const delivery_reliable_receiver_flow_t *reliable_receiver_find_const(
    const delivery_reliable_receiver_t *receiver, uint16_t flow_id)
{
    unsigned int i;

    for (i = 0; i < DELIVERY_RELIABLE_FLOWS; i++) {
        if (receiver->flows[i].configured &&
            receiver->flows[i].flow_id == flow_id)
            return &receiver->flows[i];
    }
    return NULL;
}

static int reliable_data_equal(const delivery_reliable_data_t *a,
                               const delivery_reliable_data_t *b)
{
    return a->flow_id == b->flow_id && a->message_id == b->message_id &&
           a->body_length == b->body_length &&
           hash_equal(a->content_hash, b->content_hash) &&
           (a->body_length == 0 ||
            memcmp(a->body, b->body, a->body_length) == 0);
}

void delivery_reliable_receiver_init(
    delivery_reliable_receiver_t *receiver,
    const uint8_t context[DELIVERY_CONTEXT_BYTES], uint8_t direction)
{
    memset(receiver, 0, sizeof(*receiver));
    memcpy(receiver->context, context, DELIVERY_CONTEXT_BYTES);
    receiver->direction = direction;
}

int delivery_reliable_receiver_configure(
    delivery_reliable_receiver_t *receiver, unsigned int slot,
    uint16_t flow_id, delivery_priority_t priority,
    delivery_reliable_deliver_fn deliver, void *deliver_arg)
{
    delivery_reliable_receiver_flow_t *flow;

    if (receiver == NULL || slot >= DELIVERY_RELIABLE_FLOWS || flow_id == 0 ||
        (priority != DELIVERY_PRIORITY_LOW &&
         priority != DELIVERY_PRIORITY_HIGH) || deliver == NULL ||
        reliable_receiver_find(receiver, flow_id) != NULL)
        return DELIVERY_RESULT_MALFORMED;
    flow = &receiver->flows[slot];
    if (flow->configured)
        return DELIVERY_RESULT_BUSY;
    memset(flow, 0, sizeof(*flow));
    flow->configured = 1;
    flow->priority = (uint8_t)priority;
    flow->flow_id = flow_id;
    flow->deliver = deliver;
    flow->deliver_arg = deliver_arg;
    delivery_flow_init(&flow->flow);
    return DELIVERY_RESULT_OK;
}

int delivery_reliable_receiver_observe_data(
    delivery_reliable_receiver_t *receiver,
    const delivery_reliable_data_t *record)
{
    delivery_reliable_receiver_flow_t *flow;
    uint8_t calculated[DELIVERY_HASH_BYTES];
    int rc;

    if (receiver == NULL || !reliable_data_valid(record))
        return DELIVERY_RESULT_MALFORMED;
    flow = reliable_receiver_find(receiver, record->flow_id);
    if (flow == NULL)
        return DELIVERY_RESULT_UNCONFIGURED;
    delivery_reliable_content_hash(receiver->context, receiver->direction,
                                   record->flow_id, record->message_id,
                                   record->body, record->body_length,
                                   calculated);
    if (!hash_equal(calculated, record->content_hash)) {
        crypto_wipe(calculated, sizeof(calculated));
        return DELIVERY_RESULT_DIVERGED;
    }
    crypto_wipe(calculated, sizeof(calculated));
    if (record->message_id < flow->delivered_id)
        return DELIVERY_RESULT_STALE;
    if (record->message_id == flow->delivered_id && flow->delivered_id != 0) {
        if (!hash_equal(record->content_hash, flow->delivered_hash))
            return DELIVERY_RESULT_DIVERGED;
        return DELIVERY_RESULT_DUPLICATE;
    }
    if (flow->refused_id != 0) {
        if (record->message_id < flow->refused_id)
            return DELIVERY_RESULT_STALE;
        if (record->message_id == flow->refused_id) {
            if (!hash_equal(record->content_hash, flow->refused_hash))
                return DELIVERY_RESULT_DIVERGED;
            return DELIVERY_RESULT_REFUSED;
        }
        if (flow->refused_id == UINT64_MAX ||
            record->message_id != flow->refused_id + 1U)
            return DELIVERY_RESULT_DIVERGED;
        if (flow->flow.revision == UINT64_MAX)
            return DELIVERY_RESULT_EXHAUSTED;
        if (flow->flow.mode == DELIVERY_MODE_NOT_INTERESTED) {
            flow->refused_id = record->message_id;
            memcpy(flow->refused_hash, record->content_hash,
                   DELIVERY_HASH_BYTES);
            rc = delivery_flow_target_changed(&flow->flow);
            if (rc != DELIVERY_RESULT_OK)
                return rc;
            flow->refused_flow_revision = flow->flow.revision;
            return DELIVERY_RESULT_REFUSED;
        }
        flow->refused_id = 0;
        memset(flow->refused_hash, 0, DELIVERY_HASH_BYTES);
        flow->refused_flow_revision = 0;
    }
    if (flow->target_valid) {
        if (record->message_id == flow->target.message_id) {
            if (!reliable_data_equal(record, &flow->target))
                return DELIVERY_RESULT_DIVERGED;
            return DELIVERY_RESULT_DUPLICATE;
        }
        return record->message_id < flow->target.message_id ?
            DELIVERY_RESULT_STALE : DELIVERY_RESULT_BUSY;
    }
    if (flow->flow.revision == UINT64_MAX)
        return DELIVERY_RESULT_EXHAUSTED;
    if (flow->flow.mode == DELIVERY_MODE_NOT_INTERESTED) {
        flow->refused_id = record->message_id;
        memcpy(flow->refused_hash, record->content_hash,
               DELIVERY_HASH_BYTES);
        rc = delivery_flow_target_changed(&flow->flow);
        if (rc != DELIVERY_RESULT_OK) {
            flow->refused_id = 0;
            memset(flow->refused_hash, 0, DELIVERY_HASH_BYTES);
            return rc;
        }
        flow->refused_flow_revision = flow->flow.revision;
        return DELIVERY_RESULT_REFUSED;
    }
    flow->target = *record;
    flow->target_valid = 1;
    flow->target_has_body = 1;
    rc = delivery_flow_target_changed(&flow->flow);
    if (rc != DELIVERY_RESULT_OK) {
        flow->target_valid = 0;
        flow->target_has_body = 0;
        crypto_wipe(&flow->target, sizeof(flow->target));
        return rc;
    }
    return DELIVERY_RESULT_OK;
}

int delivery_reliable_receiver_validate_data(
    const delivery_reliable_receiver_t *receiver,
    const delivery_reliable_data_t *record)
{
    delivery_reliable_receiver_t copy;
    int rc;

    if (receiver == NULL)
        return DELIVERY_RESULT_MALFORMED;
    copy = *receiver;
    rc = delivery_reliable_receiver_observe_data(&copy, record);
    crypto_wipe(&copy, sizeof(copy));
    return rc;
}

int delivery_reliable_receiver_deliver(delivery_reliable_receiver_t *receiver,
                                       uint16_t flow_id)
{
    delivery_reliable_receiver_flow_t *flow;
    uint64_t message_id;
    uint8_t hash[DELIVERY_HASH_BYTES];
    int rc;

    if (receiver == NULL)
        return DELIVERY_RESULT_MALFORMED;
    flow = reliable_receiver_find(receiver, flow_id);
    if (flow == NULL)
        return DELIVERY_RESULT_UNCONFIGURED;
    if (!flow->target_valid || !flow->target_has_body ||
        flow->flow.mode != DELIVERY_MODE_ACTIVE)
        return DELIVERY_RESULT_NOT_READY;
    if (flow->flow.revision == UINT64_MAX)
        return DELIVERY_RESULT_EXHAUSTED;
    if (flow->deliver(flow->deliver_arg, flow_id, flow->target.message_id,
                      flow->target.body, flow->target.body_length) != 0)
        return DELIVERY_RESULT_NOT_READY;
    message_id = flow->target.message_id;
    memcpy(hash, flow->target.content_hash, DELIVERY_HASH_BYTES);
    flow->target_valid = 0;
    flow->target_has_body = 0;
    crypto_wipe(&flow->target, sizeof(flow->target));
    flow->delivered_id = message_id;
    memcpy(flow->delivered_hash, hash, DELIVERY_HASH_BYTES);
    rc = delivery_flow_target_changed(&flow->flow);
    crypto_wipe(hash, sizeof(hash));
    if (rc != DELIVERY_RESULT_OK)
        return rc;
    return DELIVERY_RESULT_DELIVERED;
}

int delivery_reliable_receiver_status(
    const delivery_reliable_receiver_t *receiver, uint16_t flow_id,
    delivery_reliable_status_t *status)
{
    const delivery_reliable_receiver_flow_t *flow;

    if (receiver == NULL || status == NULL)
        return DELIVERY_RESULT_MALFORMED;
    flow = reliable_receiver_find_const(receiver, flow_id);
    if (flow == NULL)
        return DELIVERY_RESULT_UNCONFIGURED;
    memset(status, 0, sizeof(*status));
    status->flow_id = flow_id;
    status->mode = flow->flow.mode;
    status->flow_revision = flow->flow.revision;
    status->delivered_id = flow->delivered_id;
    memcpy(status->delivered_hash, flow->delivered_hash, DELIVERY_HASH_BYTES);
    if (flow->refused_id != 0) {
        status->flags = DELIVERY_RELIABLE_STATUS_FLAG_REFUSED;
        status->target_id = flow->refused_id;
        memcpy(status->target_hash, flow->refused_hash,
               DELIVERY_HASH_BYTES);
    } else if (flow->target_valid) {
        status->target_id = flow->target.message_id;
        memcpy(status->target_hash, flow->target.content_hash,
               DELIVERY_HASH_BYTES);
        if (flow->flow.mode == DELIVERY_MODE_ACTIVE ||
            flow->flow.mode == DELIVERY_MODE_PAUSED ||
            flow->flow.mode == DELIVERY_MODE_QUOTA_REFUSED)
            status->accepted_limit = flow->target.body_length;
    }
    return reliable_status_valid(status) ? DELIVERY_RESULT_OK :
                                           DELIVERY_RESULT_DIVERGED;
}

int delivery_reliable_receiver_set_reason(
    delivery_reliable_receiver_t *receiver, uint16_t flow_id,
    delivery_reason_t reason, int enabled)
{
    delivery_reliable_receiver_flow_t *flow;
    delivery_flow_state_t next;
    int rc;

    if (receiver == NULL)
        return DELIVERY_RESULT_MALFORMED;
    flow = reliable_receiver_find(receiver, flow_id);
    if (flow == NULL)
        return DELIVERY_RESULT_UNCONFIGURED;
    next = flow->flow;
    rc = delivery_flow_set_reason(&next, reason, enabled);
    if (rc != DELIVERY_RESULT_OK)
        return rc;
    if (reason == DELIVERY_REASON_NOT_INTERESTED && enabled &&
        flow->target_valid) {
        flow->refused_id = flow->target.message_id;
        memcpy(flow->refused_hash, flow->target.content_hash,
               DELIVERY_HASH_BYTES);
        flow->refused_flow_revision = next.revision;
        flow->target_valid = 0;
        flow->target_has_body = 0;
        crypto_wipe(&flow->target, sizeof(flow->target));
    }
    flow->flow = next;
    return DELIVERY_RESULT_OK;
}
