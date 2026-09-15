/*
 * pq_rekey.c — fixed pq-hybrid channel-zero share and bitmap grammar
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */

#include "pq_rekey.h"

#include <limits.h>
#include <string.h>

#include "crypto.h"

static void store16le(uint8_t *out, uint16_t value)
{
    out[0] = (uint8_t)value;
    out[1] = (uint8_t)(value >> 8);
}

static void store32le(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)value;
    out[1] = (uint8_t)(value >> 8);
    out[2] = (uint8_t)(value >> 16);
    out[3] = (uint8_t)(value >> 24);
}

static uint16_t load16le(const uint8_t *in)
{
    return (uint16_t)((uint16_t)in[0] | ((uint16_t)in[1] << 8));
}

static uint32_t load32le(const uint8_t *in)
{
    return (uint32_t)in[0] |
           ((uint32_t)in[1] << 8) |
           ((uint32_t)in[2] << 16) |
           ((uint32_t)in[3] << 24);
}

static int valid_kind(uint8_t kind)
{
    return kind == PQ_REKEY_KIND_INIT || kind == PQ_REKEY_KIND_REPLY;
}

static int all_zero(const uint8_t *bytes, size_t length)
{
    uint8_t any = 0;
    for (size_t i = 0; i < length; i++)
        any |= bytes[i];
    return any == 0;
}

static int id_equal(const uint8_t a[PQ_REKEY_ID_LEN],
                    const uint8_t b[PQ_REKEY_ID_LEN])
{
    uint8_t different = 0;
    for (size_t i = 0; i < PQ_REKEY_ID_LEN; i++)
        different |= (uint8_t)(a[i] ^ b[i]);
    return different == 0;
}

static int64_t deadline_after(int64_t now_ms, int64_t interval_ms)
{
    if (now_ms > INT64_MAX - interval_ms)
        return INT64_MAX;
    return now_ms + interval_ms;
}

static void bump_generation(pq_rekey_rx_t *rx)
{
    if (rx->bitmap_generation != UINT64_MAX)
        rx->bitmap_generation++;
}

int pq_rekey_geometry(size_t current_mtu, uint16_t *stride_out,
                      uint8_t *count_out)
{
    size_t stride;
    size_t count;

    if (!stride_out || !count_out || current_mtu < PQ_REKEY_MTU_MIN ||
        current_mtu > PQ_REKEY_MTU_MAX)
        return -1;
    stride = current_mtu - PQ_REKEY_SHARE_DESCRIPTOR_LEN;
    count = (PQ_REKEY_SHARE_LEN + stride - 1U) / stride;
    if (stride > UINT16_MAX || count < PQ_REKEY_FRAGMENT_MIN ||
        count > PQ_REKEY_FRAGMENT_MAX)
        return -1;
    *stride_out = (uint16_t)stride;
    *count_out = (uint8_t)count;
    return 0;
}

uint32_t pq_rekey_full_bitmap(uint8_t count)
{
    if (count == 0 || count >= 32)
        return 0;
    return (UINT32_C(1) << count) - UINT32_C(1);
}

static int descriptor_valid(const pq_rekey_share_descriptor_t *descriptor,
                            size_t current_mtu)
{
    uint16_t stride;
    uint8_t count;
    size_t offset;
    size_t payload_length;

    if (!descriptor || !valid_kind(descriptor->kind) ||
        descriptor->from_epoch == UINT32_MAX ||
        all_zero(descriptor->rekey_id, sizeof(descriptor->rekey_id)) ||
        pq_rekey_geometry(current_mtu, &stride, &count) != 0 ||
        descriptor->count != count || descriptor->index >= count)
        return 0;
    offset = (size_t)descriptor->index * stride;
    payload_length = PQ_REKEY_SHARE_LEN - offset;
    if (payload_length > stride)
        payload_length = stride;
    return descriptor->offset == offset &&
           descriptor->payload_length == payload_length;
}

int pq_rekey_share_descriptor_make(
    pq_rekey_share_descriptor_t *out, uint8_t kind, uint32_t from_epoch,
    const uint8_t rekey_id[PQ_REKEY_ID_LEN], uint8_t index,
    size_t current_mtu)
{
    uint16_t stride;
    uint8_t count;
    size_t offset;
    size_t payload_length;

    if (!out || !rekey_id || !valid_kind(kind) ||
        from_epoch == UINT32_MAX ||
        all_zero(rekey_id, PQ_REKEY_ID_LEN) ||
        pq_rekey_geometry(current_mtu, &stride, &count) != 0 ||
        index >= count)
        return -1;
    offset = (size_t)index * stride;
    payload_length = PQ_REKEY_SHARE_LEN - offset;
    if (payload_length > stride)
        payload_length = stride;

    memset(out, 0, sizeof(*out));
    out->kind = kind;
    out->from_epoch = from_epoch;
    memcpy(out->rekey_id, rekey_id, PQ_REKEY_ID_LEN);
    out->index = index;
    out->count = count;
    out->offset = (uint16_t)offset;
    out->payload_length = (uint16_t)payload_length;
    return 0;
}

int pq_rekey_share_descriptor_encode(
    uint8_t wire[PQ_REKEY_SHARE_DESCRIPTOR_LEN],
    const pq_rekey_share_descriptor_t *descriptor, size_t current_mtu)
{
    if (!wire || !descriptor_valid(descriptor, current_mtu))
        return -1;
    memset(wire, 0, PQ_REKEY_SHARE_DESCRIPTOR_LEN);
    wire[0] = PQ_REKEY_VERSION;
    wire[1] = PQ_REKEY_SUITE;
    wire[2] = descriptor->kind;
    store32le(wire + 4, descriptor->from_epoch);
    memcpy(wire + 8, descriptor->rekey_id, PQ_REKEY_ID_LEN);
    wire[24] = descriptor->index;
    wire[25] = descriptor->count;
    store16le(wire + 26, descriptor->offset);
    store16le(wire + 28, descriptor->payload_length);
    store16le(wire + 30, PQ_REKEY_SHARE_LEN);
    return 0;
}

int pq_rekey_share_descriptor_decode(
    const uint8_t *wire, size_t wire_len, size_t current_mtu,
    pq_rekey_share_descriptor_t *out)
{
    pq_rekey_share_descriptor_t decoded;

    if (!wire || !out || wire_len != PQ_REKEY_SHARE_DESCRIPTOR_LEN ||
        wire[0] != PQ_REKEY_VERSION || wire[1] != PQ_REKEY_SUITE ||
        wire[3] != 0 || load16le(wire + 30) != PQ_REKEY_SHARE_LEN)
        return -1;
    memset(&decoded, 0, sizeof(decoded));
    decoded.kind = wire[2];
    decoded.from_epoch = load32le(wire + 4);
    memcpy(decoded.rekey_id, wire + 8, PQ_REKEY_ID_LEN);
    decoded.index = wire[24];
    decoded.count = wire[25];
    decoded.offset = load16le(wire + 26);
    decoded.payload_length = load16le(wire + 28);
    if (!descriptor_valid(&decoded, current_mtu)) {
        crypto_memzero(&decoded, sizeof(decoded));
        return -1;
    }
    *out = decoded;
    return 0;
}

static int bitmap_valid(const pq_rekey_bitmap_t *bitmap)
{
    uint32_t full;
    if (!bitmap || !valid_kind(bitmap->kind) ||
        bitmap->from_epoch == UINT32_MAX ||
        all_zero(bitmap->rekey_id, sizeof(bitmap->rekey_id)) ||
        bitmap->count < PQ_REKEY_FRAGMENT_MIN ||
        bitmap->count > PQ_REKEY_FRAGMENT_MAX)
        return 0;
    full = pq_rekey_full_bitmap(bitmap->count);
    return (bitmap->received_bitmap & ~full) == 0;
}

int pq_rekey_bitmap_encode(uint8_t wire[PQ_REKEY_BITMAP_LEN],
                           const pq_rekey_bitmap_t *bitmap)
{
    if (!wire || !bitmap_valid(bitmap))
        return -1;
    memset(wire, 0, PQ_REKEY_BITMAP_LEN);
    wire[0] = PQ_REKEY_VERSION;
    wire[1] = PQ_REKEY_SUITE;
    wire[2] = bitmap->kind;
    store32le(wire + 4, bitmap->from_epoch);
    memcpy(wire + 8, bitmap->rekey_id, PQ_REKEY_ID_LEN);
    wire[24] = bitmap->count;
    store32le(wire + 28, bitmap->received_bitmap);
    return 0;
}

int pq_rekey_bitmap_decode(const uint8_t *wire, size_t wire_len,
                           pq_rekey_bitmap_t *out)
{
    pq_rekey_bitmap_t decoded;
    if (!wire || !out || wire_len != PQ_REKEY_BITMAP_LEN ||
        wire[0] != PQ_REKEY_VERSION || wire[1] != PQ_REKEY_SUITE ||
        wire[3] != 0 || wire[25] != 0 || wire[26] != 0 || wire[27] != 0)
        return -1;
    memset(&decoded, 0, sizeof(decoded));
    decoded.kind = wire[2];
    decoded.from_epoch = load32le(wire + 4);
    memcpy(decoded.rekey_id, wire + 8, PQ_REKEY_ID_LEN);
    decoded.count = wire[24];
    decoded.received_bitmap = load32le(wire + 28);
    if (!bitmap_valid(&decoded)) {
        crypto_memzero(&decoded, sizeof(decoded));
        return -1;
    }
    *out = decoded;
    return 0;
}

void pq_rekey_rx_init(pq_rekey_rx_t *rx)
{
    if (rx)
        memset(rx, 0, sizeof(*rx));
}

static int rx_identity_matches(const pq_rekey_rx_t *rx,
                               const pq_rekey_share_descriptor_t *descriptor)
{
    return rx->kind == descriptor->kind &&
           rx->from_epoch == descriptor->from_epoch &&
           rx->count == descriptor->count &&
           id_equal(rx->rekey_id, descriptor->rekey_id);
}

int pq_rekey_rx_accept(pq_rekey_rx_t *rx,
                       const pq_rekey_share_descriptor_t *descriptor,
                       const uint8_t *payload, size_t payload_len,
                       size_t current_mtu, int64_t now_ms)
{
    uint16_t stride;
    uint8_t count;
    uint32_t bit;

    if (!rx || !descriptor || !payload || now_ms < 0 ||
        !descriptor_valid(descriptor, current_mtu) ||
        payload_len != descriptor->payload_length ||
        pq_rekey_geometry(current_mtu, &stride, &count) != 0)
        return PQ_REKEY_RX_INVALID;

    if (!rx->active) {
        rx->active = 1;
        rx->kind = descriptor->kind;
        rx->from_epoch = descriptor->from_epoch;
        memcpy(rx->rekey_id, descriptor->rekey_id, PQ_REKEY_ID_LEN);
        rx->count = count;
        rx->stride = stride;
    } else if (!id_equal(rx->rekey_id, descriptor->rekey_id)) {
        return PQ_REKEY_RX_BUSY;
    } else if (!rx_identity_matches(rx, descriptor) || rx->stride != stride) {
        return PQ_REKEY_RX_INVALID;
    }

    bit = UINT32_C(1) << descriptor->index;
    if ((rx->received_bitmap & bit) != 0) {
        if (memcmp(rx->bytes + descriptor->offset, payload, payload_len) != 0)
            return PQ_REKEY_RX_INVALID;
        bump_generation(rx);
        rx->bitmap_due_ms = now_ms;
        return PQ_REKEY_RX_DUPLICATE;
    }

    if (rx->deadline_ms == 0)
        rx->deadline_ms = deadline_after(now_ms, PQ_REKEY_ASSEMBLY_MS);
    memcpy(rx->bytes + descriptor->offset, payload, payload_len);
    rx->received_bitmap |= bit;
    rx->complete = rx->received_bitmap == pq_rekey_full_bitmap(rx->count);
    bump_generation(rx);
    rx->bitmap_due_ms = now_ms;
    return PQ_REKEY_RX_ACCEPTED;
}

int pq_rekey_rx_expire(pq_rekey_rx_t *rx, int64_t now_ms)
{
    if (!rx || now_ms < 0)
        return -1;
    if (!rx->active || rx->complete || rx->deadline_ms == 0 ||
        now_ms < rx->deadline_ms)
        return 0;
    crypto_memzero(rx->bytes, sizeof(rx->bytes));
    rx->received_bitmap = 0;
    rx->deadline_ms = 0;
    bump_generation(rx);
    rx->bitmap_due_ms = now_ms;
    return 1;
}

int pq_rekey_rx_copy(const pq_rekey_rx_t *rx,
                     uint8_t share_out[PQ_REKEY_SHARE_LEN])
{
    if (!rx || !share_out || !rx->active || !rx->complete)
        return -1;
    memcpy(share_out, rx->bytes, PQ_REKEY_SHARE_LEN);
    return 0;
}

int pq_rekey_rx_bitmap_claim(pq_rekey_rx_t *rx, int64_t now_ms,
                             pq_rekey_bitmap_t *out)
{
    if (!rx || !out || now_ms < 0 || !rx->active ||
        rx->bitmap_inflight || now_ms < rx->bitmap_due_ms)
        return 0;
    memset(out, 0, sizeof(*out));
    out->kind = rx->kind;
    out->from_epoch = rx->from_epoch;
    memcpy(out->rekey_id, rx->rekey_id, PQ_REKEY_ID_LEN);
    out->count = rx->count;
    out->received_bitmap = rx->received_bitmap;
    rx->bitmap_inflight = 1;
    rx->bitmap_inflight_generation = rx->bitmap_generation;
    return 1;
}

int pq_rekey_rx_bitmap_complete(pq_rekey_rx_t *rx, int64_t now_ms)
{
    if (!rx || now_ms < 0 || !rx->bitmap_inflight)
        return -1;
    rx->bitmap_inflight = 0;
    if (rx->bitmap_inflight_generation == rx->bitmap_generation)
        rx->bitmap_due_ms = deadline_after(now_ms, PQ_REKEY_RETRY_MS);
    else
        rx->bitmap_due_ms = now_ms;
    rx->bitmap_inflight_generation = 0;
    return 0;
}

void pq_rekey_rx_wipe(pq_rekey_rx_t *rx)
{
    if (rx)
        crypto_memzero(rx, sizeof(*rx));
}

int pq_rekey_next_missing(uint32_t received_bitmap, uint8_t count,
                          uint8_t *cursor, uint8_t *index_out)
{
    uint32_t full;
    if (!cursor || !index_out || count < PQ_REKEY_FRAGMENT_MIN ||
        count > PQ_REKEY_FRAGMENT_MAX || *cursor >= count)
        return -1;
    full = pq_rekey_full_bitmap(count);
    if ((received_bitmap & ~full) != 0)
        return -1;
    if (received_bitmap == full)
        return 0;
    for (uint8_t step = 0; step < count; step++) {
        uint8_t index = (uint8_t)((*cursor + step) % count);
        if ((received_bitmap & (UINT32_C(1) << index)) == 0) {
            *index_out = index;
            *cursor = (uint8_t)((index + 1U) % count);
            return 1;
        }
    }
    return 0;
}
