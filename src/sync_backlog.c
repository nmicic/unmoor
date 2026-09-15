/*
 * sync_backlog.c — synchronous byte storage for the sync TX backlog
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#include "sync_backlog.h"
#include "crypto.h"

#include <stdlib.h>
#include <string.h>

int sync_backlog_init(sync_backlog_t *b, size_t slots)
{
    if (b == NULL || slots == 0 || slots > SIZE_MAX / sizeof(*b->chunks) ||
        slots > SIZE_MAX / sizeof(*b->chunk_no) || b->chunks != NULL ||
        b->chunk_no != NULL || b->nchunks != 0)
        return -1;
    b->nchunks = slots;
    b->chunks = calloc(slots, sizeof(*b->chunks));
    b->chunk_no = calloc(slots, sizeof(*b->chunk_no));
    if (b->chunks == NULL || b->chunk_no == NULL) {
        sync_backlog_free(b);
        return -1;
    }
    return 0;
}

void sync_backlog_free(sync_backlog_t *b)
{
    if (b == NULL)
        return;
    if (b->chunks != NULL) {
        for (size_t i = 0; i < b->nchunks; i++) {
            if (b->chunks[i] != NULL) {
                crypto_memzero(b->chunks[i], SYNC_BACKLOG_CHUNK_SIZE);
                free(b->chunks[i]);
            }
        }
        free(b->chunks);
    }
    free(b->chunk_no);
    crypto_memzero(b, sizeof(*b));
}

static int backlog_range_valid(const sync_backlog_t *b, uint64_t off,
                                size_t len)
{
    return b != NULL && b->chunks != NULL && b->chunk_no != NULL &&
           b->nchunks != 0 && len <= UINT64_MAX - off;
}

int sync_backlog_store(sync_backlog_t *b, uint64_t off,
                        const uint8_t *data, size_t len)
{
    if (!backlog_range_valid(b, off, len) || (len != 0 && data == NULL))
        return -1;
    while (len > 0) {
        uint64_t cn = off / SYNC_BACKLOG_CHUNK_SIZE;
        size_t in = (size_t)(off % SYNC_BACKLOG_CHUNK_SIZE);
        size_t n = SYNC_BACKLOG_CHUNK_SIZE - in;
        size_t slot = (size_t)(cn % b->nchunks);
        if (n > len)
            n = len;
        if (b->chunks[slot] == NULL) {
            b->chunks[slot] = malloc(SYNC_BACKLOG_CHUNK_SIZE);
            if (b->chunks[slot] == NULL)
                return -1;
        }
        b->chunk_no[slot] = cn; /* Only writes may claim/reuse a slot. */
        memcpy(b->chunks[slot] + in, data, n);
        off += n;
        data += n;
        len -= n;
    }
    return 0;
}

int sync_backlog_span(const sync_backlog_t *b, uint64_t off, size_t limit,
                       const uint8_t **data, size_t *len)
{
    uint64_t cn;
    size_t in, slot, n;

    if (data != NULL)
        *data = NULL;
    if (len != NULL)
        *len = 0;
    if (data == NULL || len == NULL)
        return -1;
    if (!backlog_range_valid(b, off, limit))
        return -1;
    if (limit == 0)
        return 0;
    cn = off / SYNC_BACKLOG_CHUNK_SIZE;
    in = (size_t)(off % SYNC_BACKLOG_CHUNK_SIZE);
    slot = (size_t)(cn % b->nchunks);
    if (b->chunks[slot] == NULL || b->chunk_no[slot] != cn)
        return -1;
    n = SYNC_BACKLOG_CHUNK_SIZE - in;
    if (n > limit)
        n = limit;
    *data = b->chunks[slot] + in;
    *len = n;
    return 0;
}

int sync_backlog_load(const sync_backlog_t *b, uint64_t off,
                       uint8_t *out, size_t len)
{
    if (!backlog_range_valid(b, off, len) || (len != 0 && out == NULL))
        return -1;
    while (len > 0) {
        const uint8_t *data;
        size_t n;
        if (sync_backlog_span(b, off, len, &data, &n) != 0)
            return -1;
        memcpy(out, data, n);
        off += n;
        out += n;
        len -= n;
    }
    return 0;
}
