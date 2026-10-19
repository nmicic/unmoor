/*
 * reasm.c — authenticated whole-message fragment reassembly
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */

#define _POSIX_C_SOURCE 200809L

#include <limits.h>
#include <string.h>

#include "crypto.h"
#include "reasm.h"

static uint16_t load16(const uint8_t *p)
{
    return (uint16_t)((uint32_t)p[0] | ((uint32_t)p[1] << 8));
}

static uint32_t load32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void store16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)(value & 0xff);
    p[1] = (uint8_t)(value >> 8);
}

static void store32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)(value & 0xff);
    p[1] = (uint8_t)((value >> 8) & 0xff);
    p[2] = (uint8_t)((value >> 16) & 0xff);
    p[3] = (uint8_t)((value >> 24) & 0xff);
}

void fragment_desc_encode(const fragment_desc_t *d,
                          uint8_t out[FRAGMENT_DESC_LEN])
{
    out[0] = d->version;
    out[1] = d->reserved;
    store32(out + 2, d->message_id);
    store16(out + 6, d->index);
    store16(out + 8, d->count);
    store16(out + 10, d->total_length);
    store16(out + 12, d->stride);
    store16(out + 14, d->fragment_length);
}

int fragment_desc_decode(const uint8_t in[FRAGMENT_DESC_LEN],
                         fragment_desc_t *d)
{
    if (!in || !d) return -1;
    d->version = in[0];
    d->reserved = in[1];
    d->message_id = load32(in + 2);
    d->index = load16(in + 6);
    d->count = load16(in + 8);
    d->total_length = load16(in + 10);
    d->stride = load16(in + 12);
    d->fragment_length = load16(in + 14);
    return 0;
}

void reasm_reset(reasm_t *r)
{
    if (r) memset(r, 0, sizeof(*r));
}

void reasm_reset_chan(reasm_t *r, uint8_t channel)
{
    if (!r || channel >= 16) return;
    for (size_t i = 0; i < REASM_MAX_SLOTS; i++) {
        if (r->slots[i].open && r->slots[i].channel == channel)
            r->slots[i].open = 0;
    }
    for (size_t i = 0; i < REASM_COMPLETED_SLOTS; i++) {
        if (r->completed[i].valid && r->completed[i].channel == channel)
            r->completed[i].valid = 0;
    }
}

size_t reasm_active_count(const reasm_t *r)
{
    size_t count = 0;
    if (!r) return 0;
    for (size_t i = 0; i < REASM_MAX_SLOTS; i++)
        if (r->slots[i].open) count++;
    return count;
}

void reasm_tick(reasm_t *r, int64_t now_ms)
{
    if (!r) return;
    for (size_t i = 0; i < REASM_MAX_SLOTS; i++) {
        reasm_slot_t *slot = &r->slots[i];
        if (slot->open && now_ms >= slot->deadline_ms)
            slot->open = 0;
    }
}

static int same_identity(uint8_t direction, uint8_t channel,
                         uint32_t message_id,
                         uint8_t other_direction, uint8_t other_channel,
                         uint32_t other_message_id)
{
    return direction == other_direction && channel == other_channel &&
           message_id == other_message_id;
}

static reasm_slot_t *find_slot(reasm_t *r, uint8_t direction,
                               uint8_t channel, uint32_t message_id)
{
    for (size_t i = 0; i < REASM_MAX_SLOTS; i++) {
        reasm_slot_t *slot = &r->slots[i];
        if (slot->open &&
            same_identity(direction, channel, message_id,
                          slot->direction, slot->channel, slot->message_id))
            return slot;
    }
    return NULL;
}

static int was_completed(const reasm_t *r, uint8_t direction,
                         uint8_t channel, uint32_t message_id)
{
    for (size_t i = 0; i < REASM_COMPLETED_SLOTS; i++) {
        const reasm_completed_t *done = &r->completed[i];
        if (done->valid &&
            same_identity(direction, channel, message_id,
                          done->direction, done->channel, done->message_id))
            return 1;
    }
    return 0;
}

static void remember_completed(reasm_t *r, uint8_t direction,
                               uint8_t channel, uint32_t message_id)
{
    reasm_completed_t *done = &r->completed[r->completed_next];
    done->valid = 1;
    done->direction = direction;
    done->channel = channel;
    done->message_id = message_id;
    r->completed_next = (r->completed_next + 1) % REASM_COMPLETED_SLOTS;
}

static int reject_identity(reasm_t *r, reasm_slot_t *slot,
                           uint8_t direction, uint8_t channel,
                           uint32_t message_id)
{
    if (slot) slot->open = 0;
    remember_completed(r, direction, channel, message_id);
    return REASM_ERROR;
}

static int descriptor_valid(const fragment_desc_t *d, int ff, int mf,
                            size_t actual_len)
{
    if (!d || d->version != FRAGMENT_VERSION || d->reserved != 0)
        return 0;
    if (d->count < 2 || d->count > REASM_MAX_FRAGMENTS ||
        d->index >= d->count || d->total_length == 0 ||
        d->total_length > REASM_MAX_BUFFER || d->stride == 0 ||
        d->fragment_length != actual_len)
        return 0;

    uint32_t start = (uint32_t)d->index * d->stride;
    uint32_t final_start = (uint32_t)(d->count - 1) * d->stride;
    if (final_start >= d->total_length ||
        d->total_length > (uint32_t)d->count * d->stride ||
        start >= d->total_length)
        return 0;

    uint16_t expected = d->index + 1 == d->count
                      ? (uint16_t)(d->total_length - start)
                      : d->stride;
    if (d->fragment_length != expected)
        return 0;

    if (ff != (d->index == 0) || mf != (d->index + 1 < d->count))
        return 0;
    return 1;
}

static reasm_slot_t *allocate_slot(reasm_t *r)
{
    for (size_t i = 0; i < REASM_MAX_SLOTS; i++)
        if (!r->slots[i].open) return &r->slots[i];
    return NULL;
}

int reasm_feed_fragment(reasm_t *r,
                        uint8_t direction, uint8_t channel, uint8_t type,
                        int ff, int mf,
                        const fragment_desc_t *d,
                        const uint8_t hash[FRAGMENT_HASH_LEN],
                        const uint8_t *data, size_t len,
                        int64_t now_ms, int64_t timeout_ms,
                        const uint8_t **out_buf, size_t *out_len)
{
    if (!r || !d || !hash || (!data && len != 0) || !out_buf || !out_len ||
        direction > 1 || channel == 0 || channel >= 16 ||
        timeout_ms <= 0 || now_ms > INT64_MAX - timeout_ms)
        return REASM_ERROR;

    reasm_slot_t *slot = find_slot(r, direction, channel, d->message_id);
    if (was_completed(r, direction, channel, d->message_id))
        return REASM_DROP;

    if (!descriptor_valid(d, ff, mf, len))
        return reject_identity(r, slot, direction, channel, d->message_id);

    if (slot) {
        if (slot->type != type || slot->count != d->count ||
            slot->total_length != d->total_length || slot->stride != d->stride ||
            memcmp(slot->hash, hash, FRAGMENT_HASH_LEN) != 0)
            return reject_identity(r, slot, direction, channel, d->message_id);
    } else {
        slot = allocate_slot(r);
        if (!slot) return REASM_DROP;
        memset(slot, 0, sizeof(*slot));
        slot->open = 1;
        slot->direction = direction;
        slot->channel = channel;
        slot->type = type;
        slot->message_id = d->message_id;
        slot->count = d->count;
        slot->total_length = d->total_length;
        slot->stride = d->stride;
        slot->deadline_ms = now_ms + timeout_ms;
        memcpy(slot->hash, hash, FRAGMENT_HASH_LEN);
    }

    uint32_t bit = UINT32_C(1) << d->index;
    size_t offset = (size_t)d->index * d->stride;
    /* descriptor_valid refused an empty payload above, so len is never
     * zero here; the guards keep the C library's non-null contract for
     * memcmp and memcpy visible to a static analyzer. */
    if (slot->received & bit) {
        if (len != 0 && memcmp(slot->buf + offset, data, len) != 0)
            return reject_identity(r, slot, direction, channel, d->message_id);
        return REASM_DROP;
    }

    if (len != 0)
        memcpy(slot->buf + offset, data, len);
    slot->received |= bit;

    uint32_t wanted = d->count == 32 ? UINT32_MAX
                                     : (UINT32_C(1) << d->count) - 1;
    if (slot->received != wanted)
        return REASM_DROP;

    uint8_t computed[FRAGMENT_HASH_LEN];
    crypto_fragment_hash(computed, direction, channel, type,
                         d->message_id, d->count, d->total_length, d->stride,
                         slot->buf, slot->total_length);
    if (memcmp(computed, slot->hash, sizeof(computed)) != 0) {
        crypto_memzero(computed, sizeof(computed));
        return reject_identity(r, slot, direction, channel, d->message_id);
    }
    crypto_memzero(computed, sizeof(computed));

    remember_completed(r, direction, channel, d->message_id);
    slot->open = 0;
    *out_buf = slot->buf;
    *out_len = slot->total_length;
    return REASM_DELIVER;
}
