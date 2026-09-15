/*
 * channel_session.c — channel-session encrypted channel handles and lifecycle
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */

#include "channel_session.h"

#include <string.h>

#define CHANNEL_SESSION_VERSION 1U

static uint32_t load32le(const uint8_t *p)
{
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static void store32le(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
    p[2] = (uint8_t)(value >> 16);
    p[3] = (uint8_t)(value >> 24);
}

int channel_session_kind_valid(uint8_t kind)
{
    return kind >= CHANNEL_KIND_TERMINAL && kind <= CHANNEL_KIND_BULK_PULL;
}

int channel_session_handle_make(uint8_t slot, uint32_t generation,
                                uint32_t *handle_out)
{
    if (!handle_out || slot == 0U || slot >= CHANNEL_SESSION_SLOTS ||
        generation == 0U || generation > CHANNEL_SESSION_GENERATION_MAX)
        return -1;
    *handle_out = (generation << 4) | (uint32_t)slot;
    return 0;
}

int channel_session_handle_decode(uint32_t handle, uint8_t *slot_out,
                                  uint32_t *generation_out)
{
    uint8_t slot = (uint8_t)(handle & UINT32_C(0x0f));
    uint32_t generation = handle >> 4;

    if (!slot_out || !generation_out || slot == 0U ||
        slot >= CHANNEL_SESSION_SLOTS || generation == 0U)
        return -1;
    *slot_out = slot;
    *generation_out = generation;
    return 0;
}

static int label_valid(const channel_session_open_t *open)
{
    size_t i;

    if (open->label_length > CHANNEL_SESSION_LABEL_MAX)
        return 0;
    for (i = 0; i < open->label_length; i++)
        if (open->label[i] < 0x20U || open->label[i] > 0x7eU)
            return 0;
    for (; i < CHANNEL_SESSION_LABEL_MAX; i++)
        if (open->label[i] != 0U)
            return 0;
    return 1;
}

static int open_valid(const channel_session_open_t *open)
{
    uint8_t slot;
    uint32_t generation;

    if (!open || open->version != CHANNEL_SESSION_VERSION ||
        !channel_session_kind_valid(open->kind) || open->flags != 0U ||
        channel_session_handle_decode(open->handle, &slot, &generation) != 0 ||
        !label_valid(open))
        return 0;
    if (open->kind == CHANNEL_KIND_TERMINAL) {
        uint16_t rows = (uint16_t)open->parameter0;
        uint16_t columns = (uint16_t)(open->parameter0 >> 16);
        return rows != 0U && columns != 0U && open->parameter1 == 0U;
    }
    return open->parameter0 == 0U && open->parameter1 == 0U;
}

int channel_session_open_encode(
    const channel_session_open_t *open,
    uint8_t out[CHANNEL_SESSION_OPEN_BYTES])
{
    if (!out || !open_valid(open))
        return -1;
    memset(out, 0, CHANNEL_SESSION_OPEN_BYTES);
    out[0] = open->version;
    out[1] = open->kind;
    out[2] = open->flags;
    out[3] = open->label_length;
    store32le(out + 4, open->handle);
    store32le(out + 8, open->parameter0);
    store32le(out + 12, open->parameter1);
    memcpy(out + 16, open->label, CHANNEL_SESSION_LABEL_MAX);
    return 0;
}

int channel_session_open_decode(
    const uint8_t *wire, size_t wire_length,
    channel_session_open_t *open_out)
{
    channel_session_open_t decoded;

    if (!wire || !open_out || wire_length != CHANNEL_SESSION_OPEN_BYTES)
        return -1;
    memset(&decoded, 0, sizeof(decoded));
    decoded.version = wire[0];
    decoded.kind = wire[1];
    decoded.flags = wire[2];
    decoded.label_length = wire[3];
    decoded.handle = load32le(wire + 4);
    decoded.parameter0 = load32le(wire + 8);
    decoded.parameter1 = load32le(wire + 12);
    memcpy(decoded.label, wire + 16, CHANNEL_SESSION_LABEL_MAX);
    if (!open_valid(&decoded))
        return -1;
    *open_out = decoded;
    return 0;
}

static int result_type_valid(uint8_t type)
{
    return type >= CTRL_CHANNEL_ACCEPT && type <= CTRL_CHANNEL_CLOSE_ACK;
}

static int result_code_valid(uint8_t type, uint32_t code)
{
    /* ACCEPT and CLOSE carry kind-specific results; CLOSE_ACK echoes CLOSE.
     * REFUSE alone has a closed, wire-stable reason domain. */
    if (type == CTRL_CHANNEL_REFUSE)
        return code >= CHANNEL_CODE_POLICY &&
               code <= CHANNEL_CODE_RESOURCE;
    return 1;
}

int channel_session_result_encode(
    uint8_t type, const channel_session_result_t *result,
    uint8_t out[CHANNEL_SESSION_RESULT_BYTES])
{
    uint8_t slot;
    uint32_t generation;

    if (!out || !result || !result_type_valid(type) ||
        result->version != CHANNEL_SESSION_VERSION ||
        !channel_session_kind_valid(result->kind) ||
        channel_session_handle_decode(result->handle, &slot, &generation) != 0 ||
        !result_code_valid(type, result->code))
        return -1;
    memset(out, 0, CHANNEL_SESSION_RESULT_BYTES);
    out[0] = result->version;
    out[1] = result->kind;
    store32le(out + 4, result->handle);
    store32le(out + 8, result->code);
    return 0;
}

int channel_session_result_decode(
    uint8_t type, const uint8_t *wire, size_t wire_length,
    channel_session_result_t *result_out)
{
    channel_session_result_t decoded;

    if (!wire || !result_out || wire_length != CHANNEL_SESSION_RESULT_BYTES ||
        !result_type_valid(type) || wire[2] != 0U || wire[3] != 0U)
        return -1;
    memset(&decoded, 0, sizeof(decoded));
    decoded.version = wire[0];
    decoded.kind = wire[1];
    decoded.handle = load32le(wire + 4);
    decoded.code = load32le(wire + 8);
    if (channel_session_result_encode(type, &decoded,
                                      (uint8_t[CHANNEL_SESSION_RESULT_BYTES]){0}) != 0)
        return -1;
    *result_out = decoded;
    return 0;
}

int channel_session_ready_encode(
    const uint8_t ready_prefix[8], int is_client,
    const channel_session_open_t *first_open,
    uint8_t out[CHANNEL_SESSION_READY_BYTES])
{
    if (!ready_prefix || !out || (is_client != 0 && is_client != 1) ||
        (is_client && !first_open) || (!is_client && first_open))
        return -1;
    memcpy(out, ready_prefix, 8U);
    if (is_client)
        return channel_session_open_encode(first_open, out + 8U);
    memset(out + 8U, 0, CHANNEL_SESSION_OPEN_BYTES);
    return 0;
}

int channel_session_ready_decode(
    const uint8_t *wire, size_t wire_length, int from_client,
    uint8_t ready_prefix_out[8], channel_session_open_t *first_open_out)
{
    static const uint8_t zeros[CHANNEL_SESSION_OPEN_BYTES] = { 0 };

    if (!wire || !ready_prefix_out ||
        (from_client != 0 && from_client != 1) ||
        wire_length != CHANNEL_SESSION_READY_BYTES)
        return -1;
    memcpy(ready_prefix_out, wire, 8U);
    if (from_client) {
        if (!first_open_out ||
            channel_session_open_decode(wire + 8U,
                                        CHANNEL_SESSION_OPEN_BYTES,
                                        first_open_out) != 0)
            return -1;
    } else if (first_open_out ||
               memcmp(wire + 8U, zeros, sizeof(zeros)) != 0) {
        return -1;
    }
    return 0;
}

void channel_session_table_init(channel_session_table_t *table)
{
    if (!table)
        return;
    memset(table, 0, sizeof(*table));
    table->next_slot = 1U;
}

static int same_open(const channel_session_open_t *a,
                     const channel_session_open_t *b)
{
    return a && b && a->version == b->version && a->kind == b->kind &&
           a->flags == b->flags && a->label_length == b->label_length &&
           a->handle == b->handle && a->parameter0 == b->parameter0 &&
           a->parameter1 == b->parameter1 &&
           memcmp(a->label, b->label, CHANNEL_SESSION_LABEL_MAX) == 0;
}

int channel_session_client_candidate_slot_excluding(
    const channel_session_table_t *table, uint16_t unavailable_mask,
    uint8_t *slot_out)
{
    unsigned int offset;

    if (!table || !slot_out || table->opening_slot != 0U ||
        table->last_close_started)
        return -1;
    for (offset = 0; offset < CHANNEL_SESSION_DATA_SLOTS; offset++) {
        uint8_t slot = (uint8_t)(1U +
            ((unsigned int)table->next_slot - 1U + offset) %
                CHANNEL_SESSION_DATA_SLOTS);
        const channel_session_slot_t *entry = &table->slots[slot];

        if ((unavailable_mask & (uint16_t)(1U << slot)) != 0U)
            continue;
        if (entry->state != CHANNEL_SLOT_FREE &&
            entry->state != CHANNEL_SLOT_RETIRED)
            continue;
        if (entry->last_generation >= CHANNEL_SESSION_GENERATION_MAX)
            continue;
        *slot_out = slot;
        return 0;
    }
    return -1;
}

int channel_session_client_candidate_slot(
    const channel_session_table_t *table, uint8_t *slot_out)
{
    return channel_session_client_candidate_slot_excluding(
        table, 0U, slot_out);
}

int channel_session_client_begin_open_at(
    channel_session_table_t *table, const channel_session_open_t *descriptor,
    uint8_t slot, channel_session_open_t *open_out)
{
    channel_session_slot_t *entry;
    channel_session_open_t open;
    uint32_t generation;
    uint32_t handle;

    if (!table || !descriptor || !open_out ||
        descriptor->handle != 0U || descriptor->version != CHANNEL_SESSION_VERSION ||
        !channel_session_kind_valid(descriptor->kind) ||
        descriptor->flags != 0U || !label_valid(descriptor) ||
        slot == 0U || slot >= CHANNEL_SESSION_SLOTS ||
        table->opening_slot != 0U || table->last_close_started)
        return -1;
    entry = &table->slots[slot];
    if ((entry->state != CHANNEL_SLOT_FREE &&
         entry->state != CHANNEL_SLOT_RETIRED) ||
        entry->last_generation >= CHANNEL_SESSION_GENERATION_MAX)
        return -1;
    generation = entry->last_generation + 1U;
    if (channel_session_handle_make(slot, generation, &handle) != 0)
        return -1;
    open = *descriptor;
    open.handle = handle;
    if (!open_valid(&open))
        return -1;
    *open_out = open;
    entry->state = CHANNEL_SLOT_OPENING;
    entry->last_generation = generation;
    entry->handle = handle;
    entry->open = *open_out;
    entry->decision_type = 0U;
    entry->decision_code = 0U;
    entry->close_code = 0U;
    entry->peer_close_code = 0U;
    entry->local_close_started = 0U;
    entry->local_close_acked = 0U;
    entry->peer_close_seen = 0U;
    table->live_mask |= (uint16_t)(1U << slot);
    table->opening_slot = slot;
    table->next_slot = (uint8_t)(slot == CHANNEL_SESSION_DATA_SLOTS
                                     ? 1U : slot + 1U);
    return 0;
}

int channel_session_client_begin_open(
    channel_session_table_t *table, const channel_session_open_t *descriptor,
    channel_session_open_t *open_out)
{
    uint8_t slot;

    if (channel_session_client_candidate_slot(table, &slot) != 0)
        return -1;
    return channel_session_client_begin_open_at(
        table, descriptor, slot, open_out);
}

channel_session_observe_t channel_session_observe_open(
    channel_session_table_t *table, const channel_session_open_t *open)
{
    uint8_t slot;
    uint32_t generation;
    channel_session_slot_t *entry;

    if (!table || !open_valid(open) ||
        channel_session_handle_decode(open->handle, &slot, &generation) != 0)
        return CHANNEL_OBSERVE_ERROR;
    entry = &table->slots[slot];
    if (generation < entry->last_generation)
        return CHANNEL_OBSERVE_STALE;
    if (generation == entry->last_generation && entry->last_generation != 0U) {
        if (entry->handle != open->handle || !same_open(&entry->open, open))
            return CHANNEL_OBSERVE_CONFLICT;
        return CHANNEL_OBSERVE_DUPLICATE;
    }
    if (table->opening_slot != 0U || table->last_close_started)
        return CHANNEL_OBSERVE_CONFLICT;
    if (entry->state != CHANNEL_SLOT_FREE &&
        entry->state != CHANNEL_SLOT_RETIRED)
        return CHANNEL_OBSERVE_CONFLICT;
    if (generation != entry->last_generation + 1U)
        return CHANNEL_OBSERVE_CONFLICT;
    memset(entry, 0, sizeof(*entry));
    entry->state = CHANNEL_SLOT_OPENING;
    entry->last_generation = generation;
    entry->handle = open->handle;
    entry->open = *open;
    table->live_mask |= (uint16_t)(1U << slot);
    table->opening_slot = slot;
    return CHANNEL_OBSERVE_NEW;
}

int channel_session_decide_open(channel_session_table_t *table,
                                uint32_t handle, int accepted,
                                uint32_t code)
{
    uint8_t slot;
    uint32_t generation;
    channel_session_slot_t *entry;

    if (!table || (accepted != 0 && accepted != 1) ||
        (!accepted && !result_code_valid(CTRL_CHANNEL_REFUSE, code)) ||
        channel_session_handle_decode(handle, &slot, &generation) != 0)
        return -1;
    entry = &table->slots[slot];
    if (entry->state != CHANNEL_SLOT_OPENING || entry->handle != handle)
        return -1;
    entry->decision_type = accepted ? CTRL_CHANNEL_ACCEPT : CTRL_CHANNEL_REFUSE;
    entry->decision_code = code;
    if (accepted) {
        entry->state = CHANNEL_SLOT_ACTIVE;
        table->active_mask |= (uint16_t)(1U << slot);
    } else {
        entry->state = CHANNEL_SLOT_RETIRED;
        table->live_mask &= (uint16_t)~(1U << slot);
    }
    table->opening_slot = 0U;
    return 0;
}

channel_session_observe_t channel_session_observe_result(
    channel_session_table_t *table, uint8_t type,
    const channel_session_result_t *result)
{
    uint8_t slot;
    uint32_t generation;
    channel_session_slot_t *entry;

    if (!table || !result ||
        (type != CTRL_CHANNEL_ACCEPT && type != CTRL_CHANNEL_REFUSE) ||
        channel_session_handle_decode(result->handle, &slot, &generation) != 0)
        return CHANNEL_OBSERVE_ERROR;
    entry = &table->slots[slot];
    if (generation < entry->last_generation)
        return CHANNEL_OBSERVE_STALE;
    if (entry->handle != result->handle || entry->open.kind != result->kind)
        return CHANNEL_OBSERVE_CONFLICT;
    /* CLOSE is final for this incarnation. UDP may deliver an earlier
     * ACCEPT/REFUSE after that CLOSE; it is obsolete state, never authority
     * to reactivate the retired slot. */
    if (entry->peer_close_seen)
        return CHANNEL_OBSERVE_STALE;
    if (entry->decision_type != 0U) {
        if (entry->decision_type == type && entry->decision_code == result->code)
            return CHANNEL_OBSERVE_DUPLICATE;
        return CHANNEL_OBSERVE_CONFLICT;
    }
    if (entry->state != CHANNEL_SLOT_OPENING ||
        !result_code_valid(type, result->code))
        return CHANNEL_OBSERVE_CONFLICT;
    entry->decision_type = type;
    entry->decision_code = result->code;
    table->opening_slot = 0U;
    if (type == CTRL_CHANNEL_ACCEPT) {
        entry->state = CHANNEL_SLOT_ACTIVE;
        table->active_mask |= (uint16_t)(1U << slot);
    } else {
        entry->state = CHANNEL_SLOT_RETIRED;
        table->live_mask &= (uint16_t)~(1U << slot);
    }
    return CHANNEL_OBSERVE_NEW;
}

channel_session_observe_t channel_session_resolve_data(
    const channel_session_table_t *table, uint32_t handle, uint8_t kind)
{
    uint8_t slot;
    uint32_t generation;
    const channel_session_slot_t *entry;

    if (!table || !channel_session_kind_valid(kind) ||
        channel_session_handle_decode(handle, &slot, &generation) != 0)
        return CHANNEL_OBSERVE_ERROR;
    entry = &table->slots[slot];
    if (generation < entry->last_generation)
        return CHANNEL_OBSERVE_STALE;
    if (generation > entry->last_generation || entry->handle != handle ||
        entry->open.kind != kind)
        return CHANNEL_OBSERVE_CONFLICT;
    return entry->state == CHANNEL_SLOT_ACTIVE
        ? CHANNEL_OBSERVE_NEW : CHANNEL_OBSERVE_DUPLICATE;
}

int channel_session_begin_close(channel_session_table_t *table,
                                uint32_t handle, uint32_t code)
{
    uint8_t slot;
    uint32_t generation;
    channel_session_slot_t *entry;

    if (!table ||
        channel_session_handle_decode(handle, &slot, &generation) != 0)
        return -1;
    entry = &table->slots[slot];
    if (entry->handle != handle || entry->state != CHANNEL_SLOT_ACTIVE)
        return -1;
    if (table->live_mask == (uint16_t)(1U << slot))
        table->last_close_started = 1U;
    entry->state = CHANNEL_SLOT_CLOSING;
    entry->close_code = code;
    entry->local_close_started = 1U;
    entry->local_close_acked = 0U;
    table->active_mask &= (uint16_t)~(1U << slot);
    return 0;
}

channel_session_observe_t channel_session_observe_close(
    channel_session_table_t *table,
    const channel_session_result_t *close_record)
{
    uint8_t slot;
    uint32_t generation;
    channel_session_slot_t *entry;

    if (!table || !close_record ||
        channel_session_handle_decode(close_record->handle, &slot,
                                      &generation) != 0)
        return CHANNEL_OBSERVE_ERROR;
    entry = &table->slots[slot];
    if (generation < entry->last_generation)
        return CHANNEL_OBSERVE_STALE;
    if (entry->handle != close_record->handle ||
        entry->open.kind != close_record->kind)
        return CHANNEL_OBSERVE_CONFLICT;
    if (entry->state == CHANNEL_SLOT_RETIRED)
        return entry->peer_close_seen &&
               entry->peer_close_code == close_record->code
            ? CHANNEL_OBSERVE_DUPLICATE : CHANNEL_OBSERVE_CONFLICT;
    if (entry->state != CHANNEL_SLOT_ACTIVE &&
        entry->state != CHANNEL_SLOT_CLOSING &&
        entry->state != CHANNEL_SLOT_OPENING)
        return CHANNEL_OBSERVE_CONFLICT;
    if (entry->peer_close_seen) {
        return entry->peer_close_code == close_record->code
            ? CHANNEL_OBSERVE_DUPLICATE : CHANNEL_OBSERVE_CONFLICT;
    }
    if (table->live_mask == (uint16_t)(1U << slot))
        table->last_close_started = 1U;
    entry->peer_close_seen = 1U;
    entry->peer_close_code = close_record->code;
    table->active_mask &= (uint16_t)~(1U << slot);
    if (table->opening_slot == slot)
        table->opening_slot = 0U;
    if (!entry->local_close_started) {
        /* A peer-only CLOSE creates an ACK obligation, not a reflected CLOSE.
         * Retain the exact tombstone so a lost ACK can be reasserted. */
        entry->state = CHANNEL_SLOT_RETIRED;
        table->live_mask &= (uint16_t)~(1U << slot);
    }
    return CHANNEL_OBSERVE_NEW;
}

channel_session_observe_t channel_session_observe_close_ack(
    channel_session_table_t *table,
    const channel_session_result_t *ack_record)
{
    uint8_t slot;
    uint32_t generation;
    channel_session_slot_t *entry;

    if (!table || !ack_record ||
        channel_session_handle_decode(ack_record->handle, &slot,
                                      &generation) != 0)
        return CHANNEL_OBSERVE_ERROR;
    entry = &table->slots[slot];
    if (generation < entry->last_generation)
        return CHANNEL_OBSERVE_STALE;
    if (entry->handle != ack_record->handle ||
        entry->open.kind != ack_record->kind)
        return CHANNEL_OBSERVE_CONFLICT;
    if (!entry->local_close_started)
        return CHANNEL_OBSERVE_CONFLICT;
    if (entry->local_close_acked)
        return entry->close_code == ack_record->code
            ? CHANNEL_OBSERVE_DUPLICATE : CHANNEL_OBSERVE_CONFLICT;
    if (entry->state != CHANNEL_SLOT_CLOSING ||
        entry->close_code != ack_record->code)
        return CHANNEL_OBSERVE_CONFLICT;
    entry->state = CHANNEL_SLOT_RETIRED;
    entry->local_close_acked = 1U;
    table->active_mask &= (uint16_t)~(1U << slot);
    table->live_mask &= (uint16_t)~(1U << slot);
    return CHANNEL_OBSERVE_NEW;
}

unsigned int channel_session_live_count(const channel_session_table_t *table)
{
    uint16_t mask;
    unsigned int count = 0U;

    if (!table)
        return 0U;
    mask = table->live_mask;
    while (mask != 0U) {
        count += (unsigned int)(mask & 1U);
        mask >>= 1;
    }
    return count;
}
