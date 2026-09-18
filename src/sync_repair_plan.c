/*
 * sync_repair_plan.c — pure search and independent bounded-result guard
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#include "sync_repair_plan.h"

#include <stddef.h>
#include <string.h>

int sync_repair_plan_extent(uint64_t frontier, uint32_t bits,
                            uint64_t *map_base, uint64_t *map_end)
{
    uint64_t base;

    if (map_base != NULL)
        *map_base = 0;
    if (map_end != NULL)
        *map_end = 0;
    if (map_base == NULL || map_end == NULL ||
        bits > SYNC_PLAN_BITS_MAX ||
        frontier > UINT64_MAX - (SYNC_PLAN_GRID - 1U))
        return -1;
    base = (frontier + (SYNC_PLAN_GRID - 1U)) &
           ~(uint64_t)(SYNC_PLAN_GRID - 1U);
    if ((uint64_t)bits > (UINT64_MAX - base) / SYNC_PLAN_GRID)
        return -1;
    *map_base = base;
    *map_end = base + (uint64_t)bits * SYNC_PLAN_GRID;
    return 0;
}

static int view_valid(const sync_repair_view_t *view,
                       uint64_t *map_base, uint64_t *map_end)
{
    if (view == NULL || view->cursor < view->frontier ||
        view->payload_max == 0U ||
        view->payload_max > SYNC_PLAN_PAYLOAD_MAX)
        return -1;
    return sync_repair_plan_extent(view->frontier, view->bits,
                                   map_base, map_end);
}

int sync_repair_plan_choose(const sync_repair_view_t *view,
                            sync_repair_result_t *result)
{
    uint64_t map_base, map_end, off, end;

    if (result == NULL)
        return -1;
    memset(result, 0, sizeof(*result));
    if (view_valid(view, &map_base, &map_end) != 0)
        return -1;
    if (view->cursor >= view->limit)
        return 0;
    if (view->cursor < map_base) {
        off = view->cursor;
        end = map_base < view->limit ? map_base : view->limit;
    } else {
        uint64_t block = (view->cursor - map_base) / SYNC_PLAN_GRID;
        uint64_t after;

        while (block < view->bits &&
               (((uint32_t)view->bitmap[block >> 3] >> (block & 7U)) & 1U) != 0U)
            ++block;
        if (block >= view->bits) {
            result->kind = SYNC_PLAN_EXHAUSTED;
            return 0;
        }
        off = map_base + block * SYNC_PLAN_GRID;
        if (off < view->cursor)
            off = view->cursor;
        if (off >= view->limit) {
            result->kind = SYNC_PLAN_EXHAUSTED;
            return 0;
        }
        /* Extend over consecutive missing blocks while the range still fits
         * the session's own DATA payload budget. Every term here is bounded
         * by the already-validated map extent, so the subtraction cannot
         * wrap; stopping one block late is trimmed by the clamp below. */
        after = block + 1U;
        while (after < view->bits &&
               map_base + after * SYNC_PLAN_GRID - off < view->payload_max &&
               (((uint32_t)view->bitmap[after >> 3] >> (after & 7U)) & 1U) == 0U)
            ++after;
        end = map_base + after * SYNC_PLAN_GRID;
        if (end > view->limit)
            end = view->limit;
    }
    /* Geometry and off<limit guarantee a positive nonwrapping difference.
     * Subtraction avoids a new overflow at off+payload_max near UINT64_MAX. */
    if (end - off > view->payload_max)
        end = off + view->payload_max;
    result->kind = SYNC_PLAN_RANGE;
    result->offset = off;
    result->length = (uint16_t)(end - off);
    return 0;
}

int sync_repair_plan_check(const sync_repair_view_t *view,
                           const sync_repair_result_t *result)
{
    uint64_t map_base, map_end, end;
    uint64_t first, last, start;

    if (result == NULL || view_valid(view, &map_base, &map_end) != 0)
        return -1;
    if (result->kind == SYNC_PLAN_NONE ||
        result->kind == SYNC_PLAN_EXHAUSTED)
        return result->offset == 0U && result->length == 0U ? 0 : -1;
    if (result->kind != SYNC_PLAN_RANGE || result->length == 0U ||
        result->length > view->payload_max ||
        result->offset < view->cursor || result->offset >= view->limit ||
        (uint64_t)result->length > view->limit - result->offset)
        return -1;
    /* The difference check above establishes nonwrapping addition. */
    end = result->offset + result->length;
    if (view->cursor < map_base)
        return result->offset == view->cursor && end <= map_base ? 0 : -1;
    if (result->offset < map_base || end > map_end)
        return -1;
    first = (result->offset - map_base) / SYNC_PLAN_GRID;
    last = (end - 1U - map_base) / SYNC_PLAN_GRID;
    /* No separate block count: the payload bound checked above already caps
     * the span, so the loop below runs at most payload_max/GRID + 1 times. */
    if (first >= view->bits || last >= view->bits)
        return -1;
    start = map_base + first * SYNC_PLAN_GRID;
    if (start < view->cursor)
        start = view->cursor;
    if (result->offset != start)
        return -1;
    for (uint64_t bit = first; bit <= last; ++bit)
        if ((((uint32_t)view->bitmap[bit >> 3] >> (bit & 7U)) & 1U) != 0U)
            return -1;
    return 0;
}
