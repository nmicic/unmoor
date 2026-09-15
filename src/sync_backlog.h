/*
 * sync_backlog.h — synchronous byte storage for the sync TX backlog
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef UNMOOR_SYNC_BACKLOG_H
#define UNMOOR_SYNC_BACKLOG_H

#include <stddef.h>
#include <stdint.h>

#define SYNC_BACKLOG_CHUNK_SIZE 262144U

/* Storage only: no stream/credit/quota, keys, chain, descriptors or timers.
 * A chunk tag does not prove that every byte in the chunk was initialized.
 * The caller owns logical range validity and non-collision of live bytes.
 * In particular, acknowledged bytes may still serve a base-1 persist probe.
 * This is an in-process ownership seam, not an untrusted-worker boundary. */
typedef struct {
    uint8_t **chunks;
    uint64_t *chunk_no;
    size_t nchunks;
} sync_backlog_t;

/* Initialize an empty/zeroed object. Payload chunks allocate lazily on write.
 * Failure leaves the object empty; free also accepts partial initialization. */
int sync_backlog_init(sync_backlog_t *backlog, size_t slots);
void sync_backlog_free(sync_backlog_t *backlog);

/* Read/store return -1 on an invalid argument, missing/stale read slot, or
 * failed allocation. They are not transactional: earlier spans may already
 * have changed. Reads never allocate or claim a slot. Zero length is a no-op.
 * Each [off, off+len) must have a representable, nonwrapping end offset.
 * These argument checks are local API validity, not ACK/range authority.
 * No pointer returned by this interface may survive a mutation or free. */
int sync_backlog_store(sync_backlog_t *backlog, uint64_t off,
                        const uint8_t *data, size_t len);
int sync_backlog_load(const sync_backlog_t *backlog, uint64_t off,
                       uint8_t *out, size_t len);

/* Borrow a read-only contiguous span for immediate synchronous consumption.
 * Length is min(limit, bytes to chunk edge). Outputs reset on failure or a
 * zero limit. This establishes storage identity, not source authenticity. */
int sync_backlog_span(const sync_backlog_t *backlog, uint64_t off,
                       size_t limit, const uint8_t **data, size_t *len);

#endif
