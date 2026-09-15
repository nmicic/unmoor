/*
 * sync_source_map.c — one-shot shared retained-payload mapping adapter
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * listener-monitor standalone preparation: no process, source-authentication or kernel
 * role authority. Plain-byte GCC/Clang atomics are the qualified compiler
 * contract, not a universal ISO-C claim about interprocess shared memory.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
#include "sync_source_map.h"
#include "sync_source.h"
#include <limits.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#if defined(MAP_ANONYMOUS)
#define SOURCE_MAP_ANON MAP_ANONYMOUS
#elif defined(MAP_ANON)
#define SOURCE_MAP_ANON MAP_ANON
#endif
#if (defined(__GNUC__) || defined(__clang__)) && \
    (defined(__linux__) || defined(__APPLE__)) && defined(SOURCE_MAP_ANON)
#define SOURCE_MAP_BUILTINS 1
/* Constant branches also surround each atomic site: an unavailable target
 * must not emit an external helper even in an unoptimized build. Native
 * instruction/import qualification remains a separate gate. */
#define SOURCE_MAP_INLINE (__atomic_always_lock_free(1, 0) && \
                           __atomic_always_lock_free(8, 0))
#else
#define SOURCE_MAP_BUILTINS 0
#endif

int sync_source_map_supported(void)
{
#if SOURCE_MAP_BUILTINS
    return CHAR_BIT == 8 && sizeof(void *) == 8 && sizeof(size_t) == 8 &&
           sizeof(long) == 8 && sizeof(uint64_t) == 8 && SOURCE_MAP_INLINE;
#else
    return 0;
#endif
}

int sync_source_map_geometry(uint64_t quota, size_t page,
                             sync_source_map_layout_t *out)
{
    size_t slots, records, guard_bytes, logical, padding, mapped;

    if (out != NULL) memset(out, 0, sizeof(*out));
    if (out == NULL || page < sizeof(uint64_t) ||
        page % _Alignof(uint64_t) != 0 ||
        sync_source_geometry(quota, &slots, &records, &guard_bytes) != 0 ||
        records == 0 || records > SIZE_MAX / SYNC_SOURCE_UNIT)
        return SYNC_SOURCE_MAP_RANGE;
    logical = records * SYNC_SOURCE_UNIT;
    padding = logical % page;
    if (padding != 0) padding = page - padding;
    if (logical > SIZE_MAX - padding) return SYNC_SOURCE_MAP_RANGE;
    mapped = logical + padding;
    if (mapped > SIZE_MAX - page) return SYNC_SOURCE_MAP_RANGE;
    out->nrecords = records;
    out->payload_bytes = logical;
    out->payload_length = mapped;
    out->page_length = page;
    out->total_bytes = mapped + page;
    return SYNC_SOURCE_MAP_OK;
}

static int source_map_fail(sync_source_map_t *map, int reason)
{
    map->state = SYNC_SOURCE_MAP_POISONED;
    map->failure = reason;
    return reason;
}

static int source_map_role(const sync_source_map_t *map, uint32_t role)
{
    if (map == NULL) return SYNC_SOURCE_MAP_RANGE;
    if (map->state == SYNC_SOURCE_MAP_POISONED) return SYNC_SOURCE_MAP_FAILED;
    if (map->state != role) return SYNC_SOURCE_MAP_STATE;
    if (map->payload == NULL || map->control == NULL || map->nrecords == 0 ||
        map->nrecords > SIZE_MAX / SYNC_SOURCE_UNIT ||
        map->page_length < sizeof(uint64_t) ||
        map->page_length % _Alignof(uint64_t) != 0 ||
        map->payload_length < map->nrecords * SYNC_SOURCE_UNIT ||
        map->payload_length % map->page_length != 0 ||
        (uintptr_t)map->payload % map->page_length != 0 ||
        (uintptr_t)map->control % map->page_length != 0)
        return SYNC_SOURCE_MAP_RANGE;
    return SYNC_SOURCE_MAP_OK;
}

/* Called only after role/geometry validation. No shared pointer is formed
 * until the complete physical span has been checked against logical bytes. */
static int source_map_unit(const sync_source_map_t *map, uint64_t offset,
                            size_t *physical)
{
    if (offset % SYNC_SOURCE_UNIT != 0 ||
        offset > UINT64_MAX - SYNC_SOURCE_UNIT)
        return SYNC_SOURCE_MAP_RANGE;
    size_t index = (size_t)((offset / SYNC_SOURCE_UNIT) % map->nrecords);
    size_t logical = map->nrecords * SYNC_SOURCE_UNIT;
    size_t position = index * SYNC_SOURCE_UNIT;
    if (position > logical - SYNC_SOURCE_UNIT ||
        position > map->payload_length - SYNC_SOURCE_UNIT)
        return SYNC_SOURCE_MAP_RANGE;
    *physical = position;
    return SYNC_SOURCE_MAP_OK;
}

int sync_source_map_create(sync_source_map_t *map, uint64_t quota)
{
    sync_source_map_layout_t layout;

    if (map == NULL) return SYNC_SOURCE_MAP_RANGE;
    if (map->state == SYNC_SOURCE_MAP_POISONED) return SYNC_SOURCE_MAP_FAILED;
    if (map->state != SYNC_SOURCE_MAP_EMPTY || map->payload != NULL ||
        map->control != NULL || map->payload_length != 0 ||
        map->page_length != 0 || map->nrecords != 0 || map->failure != 0)
        return SYNC_SOURCE_MAP_STATE;
    /* Validate quota without an OS effect, then obtain the real page size. */
    if (sync_source_map_geometry(quota, sizeof(uint64_t), &layout) != 0)
        return SYNC_SOURCE_MAP_RANGE;
    if (!sync_source_map_supported()) return SYNC_SOURCE_MAP_UNAVAILABLE;
#if SOURCE_MAP_BUILTINS
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0 || (long)(size_t)page != page ||
        sync_source_map_geometry(quota, (size_t)page, &layout) != 0)
        return source_map_fail(map, SYNC_SOURCE_MAP_SYSTEM);
    map->nrecords = layout.nrecords;
    void *payload = mmap(NULL, layout.payload_length, PROT_READ | PROT_WRITE,
                         MAP_SHARED | SOURCE_MAP_ANON, -1, 0);
    if (payload == MAP_FAILED)
        return source_map_fail(map, SYNC_SOURCE_MAP_SYSTEM);
    map->payload = payload;
    map->payload_length = layout.payload_length;
    /* Length records successful mapping custody even for an unusable zero
     * address, so release can still unmap it. No implicit cleanup/retry. */
    if (payload == NULL || (uintptr_t)payload % layout.page_length != 0)
        return source_map_fail(map, SYNC_SOURCE_MAP_SYSTEM);
    void *control = mmap(NULL, layout.page_length, PROT_READ | PROT_WRITE,
                         MAP_SHARED | SOURCE_MAP_ANON, -1, 0);
    if (control == MAP_FAILED)
        return source_map_fail(map, SYNC_SOURCE_MAP_SYSTEM);
    map->control = control;
    map->page_length = layout.page_length;
    if (control == NULL || (uintptr_t)control % layout.page_length != 0)
        return source_map_fail(map, SYNC_SOURCE_MAP_SYSTEM);
    if (SOURCE_MAP_INLINE) {
        /* No payload first touch and no worker-side atomic_init requirement. */
        __atomic_store_n(map->control, UINT64_C(0), __ATOMIC_RELAXED);
        map->state = SYNC_SOURCE_MAP_CREATED;
        return SYNC_SOURCE_MAP_OK;
    }
#endif
    return SYNC_SOURCE_MAP_UNAVAILABLE;
}

int sync_source_map_enter_monitor(sync_source_map_t *map)
{
    int rc = source_map_role(map, SYNC_SOURCE_MAP_CREATED);
    if (rc != 0) return rc;
    if (mprotect(map->payload, map->payload_length, PROT_READ) != 0 ||
        mprotect(map->control, map->page_length, PROT_READ) != 0)
        return source_map_fail(map, SYNC_SOURCE_MAP_SYSTEM);
    map->state = SYNC_SOURCE_MAP_MONITOR_RO;
    return SYNC_SOURCE_MAP_OK;
}

int sync_source_map_enter_worker(sync_source_map_t *map)
{
    int rc = source_map_role(map, SYNC_SOURCE_MAP_CREATED);
    if (rc != 0) return rc;
    map->state = SYNC_SOURCE_MAP_WORKER_RW;
    return SYNC_SOURCE_MAP_OK;
}

int sync_source_map_read_unit(const void *map, uint64_t offset, uint8_t *owned_u)
{
    const sync_source_map_t *owner = map;
    size_t position = 0;
    if (owned_u == NULL) return SYNC_SOURCE_MAP_RANGE;
    int rc = source_map_role(owner, SYNC_SOURCE_MAP_MONITOR_RO);
    if (rc == 0) rc = source_map_unit(owner, offset, &position);
    if (rc != 0) {
        memset(owned_u, 0, SYNC_SOURCE_UNIT);
        return rc;
    }
#if SOURCE_MAP_BUILTINS
    if (SOURCE_MAP_INLINE) {
        for (size_t i = 0; i < SYNC_SOURCE_UNIT; ++i)
            owned_u[i] = __atomic_load_n(owner->payload + position + i,
                                        __ATOMIC_RELAXED);
        return SYNC_SOURCE_MAP_OK;
    }
#endif
    memset(owned_u, 0, SYNC_SOURCE_UNIT);
    return SYNC_SOURCE_MAP_UNAVAILABLE;
}

int sync_source_map_store_unit(sync_source_map_t *map, uint64_t offset,
                               const uint8_t *owned_u, uint64_t issued_serial)
{
    size_t position = 0;
    if (owned_u == NULL || issued_serial == 0) return SYNC_SOURCE_MAP_RANGE;
    int rc = source_map_role(map, SYNC_SOURCE_MAP_WORKER_RW);
    if (rc == 0) rc = source_map_unit(map, offset, &position);
    if (rc != 0) return rc;
#if SOURCE_MAP_BUILTINS
    if (SOURCE_MAP_INLINE) {
        for (size_t i = 0; i < SYNC_SOURCE_UNIT; ++i)
            __atomic_store_n(map->payload + position + i, owned_u[i],
                              __ATOMIC_RELAXED);
        __atomic_store_n(map->control, issued_serial, __ATOMIC_RELEASE);
        return SYNC_SOURCE_MAP_OK;
    }
#endif
    return SYNC_SOURCE_MAP_UNAVAILABLE;
}

int sync_source_map_publication(const sync_source_map_t *map, uint64_t *out)
{
    if (out == NULL) return SYNC_SOURCE_MAP_RANGE;
    *out = 0;
    int rc = source_map_role(map, SYNC_SOURCE_MAP_MONITOR_RO);
    if (rc != 0) return rc;
#if SOURCE_MAP_BUILTINS
    if (SOURCE_MAP_INLINE) {
        *out = __atomic_load_n(map->control, __ATOMIC_ACQUIRE);
        return SYNC_SOURCE_MAP_OK;
    }
#endif
    return SYNC_SOURCE_MAP_UNAVAILABLE;
}

int sync_source_map_wipe_after_reap(sync_source_map_t *map,
                                    size_t inventory_nrecords,
                                    int (*slot_used)(const void *, size_t),
                                    const void *trusted_inventory)
{
    if (slot_used == NULL || trusted_inventory == NULL)
        return SYNC_SOURCE_MAP_RANGE;
    int rc = source_map_role(map, SYNC_SOURCE_MAP_MONITOR_RO);
    if (rc != 0) return rc;
    if (inventory_nrecords != map->nrecords) return SYNC_SOURCE_MAP_RANGE;
    /* Exact reap/no-other-writer is the external caller's prerequisite.
     * Ordinary secure wiping is valid only after that synchronization. */
    if (mprotect(map->payload, map->payload_length, PROT_READ | PROT_WRITE) != 0 ||
        mprotect(map->control, map->page_length, PROT_READ | PROT_WRITE) != 0)
        return source_map_fail(map, SYNC_SOURCE_MAP_SYSTEM);
    for (size_t i = 0; i < map->nrecords; ++i) {
        int used = slot_used(trusted_inventory, i);
        if (used != 0 && used != 1)
            return source_map_fail(map, SYNC_SOURCE_MAP_INVENTORY);
        if (used == 1)
            crypto_memzero(map->payload + i * SYNC_SOURCE_UNIT, SYNC_SOURCE_UNIT);
    }
    crypto_memzero(map->control, map->page_length);
    map->state = SYNC_SOURCE_MAP_WIPED_RW;
    return SYNC_SOURCE_MAP_OK;
}

int sync_source_map_release(sync_source_map_t *map)
{
    int error = 0;
    if (map == NULL) return SYNC_SOURCE_MAP_RANGE;
    if (map->state == SYNC_SOURCE_MAP_RELEASED) return SYNC_SOURCE_MAP_OK;
    /* Length is published only after each successful mmap. Keep any mapping
     * whose munmap failed, including its exact address/length for a retry. */
    if (map->payload_length != 0) {
        if (munmap(map->payload, map->payload_length) != 0) error = 1;
        else { map->payload = NULL; map->payload_length = 0; }
    } else if (map->payload != NULL) error = 1;
    if (map->page_length != 0) {
        if (munmap(map->control, map->page_length) != 0) error = 1;
        else { map->control = NULL; map->page_length = 0; }
    } else if (map->control != NULL) error = 1;
    if (error) return source_map_fail(map, SYNC_SOURCE_MAP_SYSTEM);
    map->nrecords = 0;
    map->state = SYNC_SOURCE_MAP_RELEASED;
    return SYNC_SOURCE_MAP_OK;
}
