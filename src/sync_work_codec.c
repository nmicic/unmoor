/*
 * sync_work_codec.c — fixed local STORE/PLAN record preparation
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#include "sync_work_codec.h"
#include <string.h>

_Static_assert(SYNC_PLAN_BITMAP_MAX == 170U, "local PLAN bitmap grammar");
_Static_assert(SYNC_WORK_PLAN_BYTES == SYNC_WORK_HEADER + 30U +
               SYNC_PLAN_BITMAP_MAX, "local PLAN body grammar");

static void put_le(uint8_t *output, uint64_t value, size_t width)
{
    for (size_t i = 0; i < width; ++i) {
        output[i] = (uint8_t)value;
        value >>= 8;
    }
}

static uint64_t get_le(const uint8_t *input, size_t width)
{
    uint64_t value = 0;
    for (size_t i = 0; i < width; ++i)
        value |= (uint64_t)input[i] << (i * 8U);
    return value;
}

size_t sync_work_frame_bytes(uint8_t type)
{
    switch (type) {
    case SYNC_WORK_STORE: return SYNC_WORK_STORE_BYTES;
    case SYNC_WORK_STORED: return SYNC_WORK_STORED_BYTES;
    case SYNC_WORK_PLAN: return SYNC_WORK_PLAN_BYTES;
    case SYNC_WORK_PLANNED: return SYNC_WORK_PLANNED_BYTES;
    default: return 0;
    }
}

static int header_valid(const sync_work_header_t *header)
{
    return header != NULL && header->incarnation != 0U &&
           header->operation != 0U && header->direction <= 1U &&
           sync_work_frame_bytes(header->type) != 0U;
}

/* Call only after every encoder argument/body has been checked, so no
 * encoder error can publish a partial header. */
static void header_write(uint8_t *output, const sync_work_header_t *header)
{
    output[0] = SYNC_WORK_VERSION;
    output[1] = header->type;
    output[2] = header->direction;
    memset(output + 3, 0, 5);
    put_le(output + 8, header->incarnation, 8);
    put_le(output + 16, header->operation, 8);
}

static int encode_valid(const uint8_t *output, size_t capacity,
                         const sync_work_header_t *header, uint8_t type)
{
    return output != NULL && header_valid(header) && header->type == type &&
           capacity >= sync_work_frame_bytes(type);
}

/* candidate is private workspace, not a supplied output. The typed
 * decoders publish it only after the body has also passed validation. */
static int decode_header(sync_work_header_t *candidate, uint8_t type,
                          const uint8_t *input, size_t length)
{
    return length == sync_work_frame_bytes(type) &&
           sync_work_header_decode(candidate, input, SYNC_WORK_HEADER) == 0 &&
           candidate->type == type ? 0 : -1;
}

static int store_offset_valid(uint64_t offset)
{
    return offset % SYNC_WORK_UNIT == 0U &&
           offset <= UINT64_MAX - SYNC_WORK_UNIT;
}

static int view_valid(const sync_repair_view_t *view)
{
    const sync_repair_result_t none = {0};
    return sync_repair_plan_check(view, &none) == 0;
}

static int planned_valid(const sync_repair_result_t *result)
{
    if (result == NULL)
        return 0;
    if (result->kind == SYNC_PLAN_NONE || result->kind == SYNC_PLAN_EXHAUSTED)
        return result->offset == 0U && result->length == 0U;
    return result->kind == SYNC_PLAN_RANGE && result->length != 0U &&
           result->length <= SYNC_PLAN_PAYLOAD_MAX &&
           result->offset <= UINT64_MAX - result->length;
}

/* view_valid must precede these bounded bitmap operations. */
static void bitmap_write(uint8_t *output, const sync_repair_view_t *view)
{
    size_t complete = view->bits / 8U;
    unsigned remainder = view->bits % 8U;
    memset(output, 0, SYNC_PLAN_BITMAP_MAX);
    memcpy(output, view->bitmap, complete);
    if (remainder != 0U)
        output[complete] = (uint8_t)(view->bitmap[complete] &
                                     ((1U << remainder) - 1U));
}

static int bitmap_canonical(const sync_repair_view_t *view)
{
    size_t complete = view->bits / 8U;
    unsigned remainder = view->bits % 8U;
    if (remainder != 0U) {
        uint8_t mask = (uint8_t)((1U << remainder) - 1U);
        if ((view->bitmap[complete] & (uint8_t)~mask) != 0U)
            return 0;
        ++complete;
    }
    for (size_t i = complete; i < SYNC_PLAN_BITMAP_MAX; ++i)
        if (view->bitmap[i] != 0U)
            return 0;
    return 1;
}

int sync_work_header_encode(uint8_t output[SYNC_WORK_HEADER],
                            const sync_work_header_t *header)
{
    if (output == NULL || !header_valid(header))
        return -1;
    header_write(output, header);
    return 0;
}

int sync_work_header_decode(sync_work_header_t *header,
                            const uint8_t *input, size_t length)
{
    if (header) memset(header, 0, sizeof(*header));
    if (header == NULL || input == NULL || length != SYNC_WORK_HEADER ||
        input[0] != SYNC_WORK_VERSION)
        return -1;
    for (size_t i = 3; i < 8; ++i)
        if (input[i] != 0U)
            return -1;
    sync_work_header_t candidate = {0};
    candidate.type = input[1];
    candidate.direction = input[2];
    candidate.incarnation = get_le(input + 8, 8);
    candidate.operation = get_le(input + 16, 8);
    if (!header_valid(&candidate))
        return -1;
    *header = candidate;
    return 0;
}

int sync_work_store_encode(uint8_t *output, size_t capacity,
                           const sync_work_header_t *header, uint64_t offset,
                           const uint8_t unit[SYNC_WORK_UNIT])
{
    if (!encode_valid(output, capacity, header, SYNC_WORK_STORE) ||
        unit == NULL || !store_offset_valid(offset))
        return -1;
    header_write(output, header);
    put_le(output + SYNC_WORK_HEADER, offset, 8);
    memcpy(output + SYNC_WORK_HEADER + 8U, unit, SYNC_WORK_UNIT);
    return 0;
}

int sync_work_store_decode(sync_work_header_t *header, uint64_t *offset,
                           const uint8_t **unit, const uint8_t *input,
                           size_t length)
{
    if (header) memset(header, 0, sizeof(*header));
    if (offset) *offset = 0;
    if (unit) *unit = NULL;
    sync_work_header_t candidate;
    if (header == NULL || offset == NULL || unit == NULL ||
        decode_header(&candidate, SYNC_WORK_STORE, input, length) != 0)
        return -1;
    uint64_t decoded_offset = get_le(input + SYNC_WORK_HEADER, 8);
    if (!store_offset_valid(decoded_offset))
        return -1;
    *header = candidate;
    *offset = decoded_offset;
    *unit = input + SYNC_WORK_HEADER + 8U;
    return 0;
}

int sync_work_stored_encode(uint8_t *output, size_t capacity,
                            const sync_work_header_t *header, uint8_t status)
{
    if (!encode_valid(output, capacity, header, SYNC_WORK_STORED) || status > 1U)
        return -1;
    header_write(output, header);
    output[SYNC_WORK_HEADER] = status;
    return 0;
}

int sync_work_stored_decode(sync_work_header_t *header, uint8_t *status,
                            const uint8_t *input, size_t length)
{
    if (header) memset(header, 0, sizeof(*header));
    if (status) *status = 0;
    sync_work_header_t candidate;
    if (header == NULL || status == NULL ||
        decode_header(&candidate, SYNC_WORK_STORED, input, length) != 0 ||
        input[SYNC_WORK_HEADER] > 1U)
        return -1;
    *header = candidate;
    *status = input[SYNC_WORK_HEADER];
    return 0;
}

int sync_work_plan_encode(uint8_t *output, size_t capacity,
                          const sync_work_header_t *header,
                          const sync_repair_view_t *view)
{
    if (!encode_valid(output, capacity, header, SYNC_WORK_PLAN) || !view_valid(view))
        return -1;
    header_write(output, header);
    uint8_t *body = output + SYNC_WORK_HEADER;
    put_le(body, view->frontier, 8);
    put_le(body + 8, view->cursor, 8);
    put_le(body + 16, view->limit, 8);
    put_le(body + 24, view->bits, 4);
    put_le(body + 28, view->payload_max, 2);
    bitmap_write(body + 30, view);
    return 0;
}

int sync_work_plan_decode(sync_work_header_t *header, sync_repair_view_t *view,
                          const uint8_t *input, size_t length)
{
    if (header) memset(header, 0, sizeof(*header));
    if (view) memset(view, 0, sizeof(*view));
    sync_work_header_t candidate_header;
    if (header == NULL || view == NULL ||
        decode_header(&candidate_header, SYNC_WORK_PLAN, input, length) != 0)
        return -1;
    sync_repair_view_t candidate = {0};
    const uint8_t *body = input + SYNC_WORK_HEADER;
    candidate.frontier = get_le(body, 8);
    candidate.cursor = get_le(body + 8, 8);
    candidate.limit = get_le(body + 16, 8);
    candidate.bits = (uint32_t)get_le(body + 24, 4);
    candidate.payload_max = (uint16_t)get_le(body + 28, 2);
    memcpy(candidate.bitmap, body + 30, SYNC_PLAN_BITMAP_MAX);
    if (!view_valid(&candidate) || !bitmap_canonical(&candidate))
        return -1;
    *header = candidate_header;
    *view = candidate;
    return 0;
}

int sync_work_planned_encode(uint8_t *output, size_t capacity,
                             const sync_work_header_t *header,
                             const sync_repair_result_t *result)
{
    if (!encode_valid(output, capacity, header, SYNC_WORK_PLANNED) ||
        !planned_valid(result))
        return -1;
    header_write(output, header);
    output[SYNC_WORK_HEADER] = result->kind;
    put_le(output + SYNC_WORK_HEADER + 1U, result->offset, 8);
    put_le(output + SYNC_WORK_HEADER + 9U, result->length, 2);
    return 0;
}

int sync_work_planned_decode(sync_work_header_t *header,
                             sync_repair_result_t *result,
                             const uint8_t *input, size_t length)
{
    if (header) memset(header, 0, sizeof(*header));
    if (result) memset(result, 0, sizeof(*result));
    sync_work_header_t candidate_header;
    if (header == NULL || result == NULL ||
        decode_header(&candidate_header, SYNC_WORK_PLANNED, input, length) != 0)
        return -1;
    sync_repair_result_t candidate = {0};
    candidate.kind = input[SYNC_WORK_HEADER];
    candidate.offset = get_le(input + SYNC_WORK_HEADER + 1U, 8);
    candidate.length = (uint16_t)get_le(input + SYNC_WORK_HEADER + 9U, 2);
    if (!planned_valid(&candidate))
        return -1;
    *header = candidate_header;
    *result = candidate;
    return 0;
}
