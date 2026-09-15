/*
 * sync_source_map.h — one-shot shared retained-payload mapping adapter
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef UNMOOR_SYNC_SOURCE_MAP_H
#define UNMOOR_SYNC_SOURCE_MAP_H

#include <stddef.h>
#include <stdint.h>

#define SYNC_SOURCE_MAP_OK           0
#define SYNC_SOURCE_MAP_RANGE       -1
#define SYNC_SOURCE_MAP_UNAVAILABLE -2
#define SYNC_SOURCE_MAP_SYSTEM      -3
#define SYNC_SOURCE_MAP_INVENTORY   -4
#define SYNC_SOURCE_MAP_STATE       -5
#define SYNC_SOURCE_MAP_FAILED      -6

enum {
    SYNC_SOURCE_MAP_EMPTY = 0,
    SYNC_SOURCE_MAP_CREATED,
    SYNC_SOURCE_MAP_MONITOR_RO,
    SYNC_SOURCE_MAP_WORKER_RW,
    SYNC_SOURCE_MAP_WIPED_RW,
    SYNC_SOURCE_MAP_POISONED,
    SYNC_SOURCE_MAP_RELEASED
};

/* LP64: 40 bytes. Logical payload is N*U; mapped rounding is not capacity.
 * U=16384, G=262144, Q is G-rounded in [G, 4 GiB], N=(Q/G+1)*(G/U). */
typedef struct {
    size_t nrecords;
    size_t payload_bytes;
    size_t payload_length;
    size_t page_length;
    size_t total_bytes;
} sync_source_map_layout_t;

/* LP64: 48 bytes. Fields are trusted adapter-owned state, not an input API.
 * Start with fresh zero storage; never copy/reset/reuse a live or released
 * owner. Only pre-role CREATED fork inheritance permits independent owners.
 * No heap, backing fd, resize, remap, source identity or writer registry. */
typedef struct {
    uint8_t *payload;
    uint64_t *control;
    size_t payload_length;
    size_t page_length;
    size_t nrecords;
    uint32_t state;
    int32_t failure;
} sync_source_map_t;

/* Compiled availability only: qualified LP64 GCC/Clang, 8-bit bytes and
 * inline always-lock-free byte/uint64 builtins. Not a runtime/kernel claim.
 * No external atomic helper or fallback implementation is permitted. */
int sync_source_map_supported(void);
/* Pure, independent of compiled availability. Positive page size must meet
 * uint64 alignment; checked rounding/addition need not assume power-of-two.
 * A separate non-NULL output is cleared on error. */
int sync_source_map_geometry(uint64_t quota, size_t page,
                             sync_source_map_layout_t *out);
/* Actual sysconf page size, two non-fixed anonymous shared RW mappings.
 * Only the control serial is initialized; payload uses OS zero initialization.
 * RANGE/STATE are nonmutating. SYSTEM poisons, retaining all unreleased maps.
 * UNAVAILABLE creates nothing. Mapping success makes no residency promise. */
int sync_source_map_create(sync_source_map_t *empty, uint64_t quota);
/* CREATED only, once. Monitor requires both successful RO protections;
 * worker retains the original RW view. Failure permits release, not retry.
 * These role states do not ban direct syscalls or supply a sandbox. */
int sync_source_map_enter_monitor(sync_source_map_t *map);
int sync_source_map_enter_worker(sync_source_map_t *map);

/* U-byte owned disjoint buffers; trusted owner/context, no reentry. Validate
 * aligned offset and full nonwrapping offset+U before addressing (offset/U)%N.
 * Read is MONITOR_RO only: exactly one relaxed atomic-byte copy; no shared
 * pointer, snapshot, retry or hash. A separate output is cleared on error.
 * The guard, not this adapter, checks initialized identity/base/tip/digest. */
int sync_source_map_read_unit(const void *map, uint64_t offset,
                              uint8_t *owned_u);
/* WORKER_RW only: U relaxed atomic-byte stores, then release-store the supplied
 * nonzero 64-bit serial. No serial issuance, authenticity or acceptance. */
int sync_source_map_store_unit(sync_source_map_t *map, uint64_t offset,
                               const uint8_t *owned_u, uint64_t issued_serial);
/* MONITOR_RO only: one acquire, including zero/wrong/stale observations.
 * Caller compares the exact operation; a separate output clears on error. */
int sync_source_map_publication(const sync_source_map_t *map, uint64_t *out);

/* Caller has independently proved exact worker reap AND no remaining writer.
 * This API neither obtains nor verifies that proof. MONITOR_RO only; frozen,
 * nonreentrant, non-NULL trusted inventory/context, explicit count equal N.
 * Make both known mappings RW; callback must return 0/1 for each slot. Wipe
 * every authorized full U and the entire control page, retaining mappings.
 * No added bitmap/scratch. Protection/callback failure poisons; a partial wipe
 * is NOT completion. Guard/key/staging wipes remain external obligations. */
int sync_source_map_wipe_after_reap(sync_source_map_t *map,
                                    size_t inventory_nrecords,
                                    int (*slot_used)(const void *, size_t),
                                    const void *trusted_inventory);
/* Attempt BOTH retained mappings even if one unmap fails; clear references
 * only after real success. Later release may finish cleanup, never revive
 * operations. Successful release (also EMPTY) is terminal and idempotent.
 * Release without successful authorized wipe means kernel reclamation only.
 * Null arguments return RANGE, invalid healthy roles STATE, poisoned live
 * operations FAILED. A syscall/callback failure records SYSTEM/INVENTORY. */
int sync_source_map_release(sync_source_map_t *map);

#endif
