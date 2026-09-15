/*
 * sync_repair_plan.h — bounded, non-authoritative terminal-state-sync repair selection
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef UNMOOR_SYNC_REPAIR_PLAN_H
#define UNMOOR_SYNC_REPAIR_PLAN_H

#include <stdint.h>

#define SYNC_PLAN_GRID         64U
#define SYNC_PLAN_BITMAP_MAX  170U
#define SYNC_PLAN_BITS_MAX   1360U
#define SYNC_PLAN_PAYLOAD_MAX 210U

/* Caller-owned immutable view, not an IPC encoding or authority grant.
 * Cursor is already normalized to >= frontier. Limit is the trusted
 * min(source tip, actually sent, peer credit). No eligibility/timer state. */
typedef struct {
    uint64_t frontier;
    uint64_t cursor;
    uint64_t limit;
    uint32_t bits;
    uint16_t payload_max;
    uint8_t bitmap[SYNC_PLAN_BITMAP_MAX];
} sync_repair_view_t;

#define SYNC_PLAN_NONE      0U
#define SYNC_PLAN_RANGE     1U
#define SYNC_PLAN_EXHAUSTED 2U

typedef struct {
    uint64_t offset;
    uint16_t length;
    uint8_t kind;
} sync_repair_result_t;

/* Checked alignment/extent; outputs are cleared on invalid input. */
int sync_repair_plan_extent(uint64_t frontier, uint32_t bits,
                            uint64_t *map_base, uint64_t *map_end);

/* Pure honest search. No allocation, I/O, clock, mutation of the view or
 * session effects. Returns -1 for invalid geometry; output is then zero. */
int sync_repair_plan_choose(const sync_repair_view_t *view,
                            sync_repair_result_t *result);

/* Small independent authority check, not a second lowest-missing search.
 * Canonical NONE/EXHAUSTED may withhold work; they prove no absence and
 * grant no completion, credit, source, attempt or timer authority. A RANGE
 * must be a bounded prefix or begin canonically within missing map blocks.
 * The trusted caller must separately own eligibility and view freshness. */
int sync_repair_plan_check(const sync_repair_view_t *view,
                           const sync_repair_result_t *result);

#endif
