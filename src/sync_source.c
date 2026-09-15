/*
 * sync_source.c — trusted commitments over separately owned byte storage
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#include "sync_source.h"
#include "vendor/monocypher.h"

#include <stdlib.h>
#include <string.h>

_Static_assert(SYNC_BACKLOG_CHUNK_SIZE % SYNC_SOURCE_UNIT == 0,
               "source units must divide backing chunks");
_Static_assert(sizeof(sync_source_record_t) == 48,
               "source commitment budget changed");
_Static_assert(sizeof(sync_source_cache_tag_t) == 16,
               "source cache tag budget changed");
_Static_assert(sizeof(sync_source_pending_t) == 64 && sizeof(sync_source_t) == 128,
               "pending source owner budget changed");
_Static_assert(sizeof(sync_source_reader_t) == 24 && sizeof(sync_source_store_t) == 16,
               "source reader/view budget changed");

#define SOURCE_APPEND_UNIT (2U + SYNC_SOURCE_CACHES)
#define SOURCE_SEAL_UNIT (3U + SYNC_SOURCE_CACHES)
#define SOURCE_WORKSPACE_BYTES ((size_t)(4U + SYNC_SOURCE_CACHES) * SYNC_SOURCE_UNIT)

int sync_source_issue(sync_source_issuer_t *issuer, uint64_t *identity)
{
    /* Refuse the one structural alias without resetting the issuer. */
    if (issuer != NULL && identity == &issuer->last)
        return SYNC_SOURCE_RANGE;
    if (identity != NULL)
        *identity = 0;
    if (issuer == NULL || identity == NULL || issuer->last == UINT64_MAX)
        return SYNC_SOURCE_RANGE;
    *identity = ++issuer->last;
    return SYNC_SOURCE_OK;
}

int sync_source_geometry(uint64_t quota, size_t *slots, size_t *records,
                         size_t *allocated_bytes)
{
    uint64_t count, n;
    size_t fixed = SOURCE_WORKSPACE_BYTES +
                   SYNC_SOURCE_CACHES * sizeof(sync_source_cache_tag_t);

    if (slots != NULL)
        *slots = 0;
    if (records != NULL)
        *records = 0;
    if (allocated_bytes != NULL)
        *allocated_bytes = 0;
    if (slots == NULL || records == NULL || allocated_bytes == NULL ||
        quota < SYNC_BACKLOG_CHUNK_SIZE || quota > SYNC_SOURCE_QUOTA_MAX ||
        quota % SYNC_BACKLOG_CHUNK_SIZE != 0)
        return SYNC_SOURCE_RANGE;
    count = quota / SYNC_BACKLOG_CHUNK_SIZE + 1U;
    n = count * (SYNC_BACKLOG_CHUNK_SIZE / SYNC_SOURCE_UNIT);
    if (count > SIZE_MAX || n > (SIZE_MAX - fixed) / sizeof(sync_source_record_t))
        return SYNC_SOURCE_RANGE;
    *slots = (size_t)count;
    *records = (size_t)n;
    *allocated_bytes = (size_t)n * sizeof(sync_source_record_t) + fixed;
    return SYNC_SOURCE_OK;
}

static int source_empty(const sync_source_t *s)
{
    const uint8_t *pending = (const uint8_t *)&s->pending;
    for (size_t i = 0; i < sizeof(s->pending); ++i)
        if (pending[i] != 0)
            return 0;
    return s->records == NULL && s->workspace == NULL &&
           s->cache_tags == NULL && s->nrecords == 0 && s->quota == 0 &&
           s->tip == 0 && s->incarnation == 0 && s->direction == 0 &&
           s->replacement == 0 && !s->initialized && !s->failed;
}

int sync_source_init(sync_source_t *s, uint64_t quota,
                     uint64_t incarnation, uint8_t direction)
{
    size_t slots, records, bytes;

    if (s == NULL || !source_empty(s) || incarnation == 0 || direction > 1U ||
        sync_source_geometry(quota, &slots, &records, &bytes) != 0)
        return SYNC_SOURCE_RANGE;
    s->nrecords = records;
    s->records = calloc(records, sizeof(*s->records));
    s->workspace = calloc(SOURCE_WORKSPACE_BYTES, 1);
    s->cache_tags = calloc(SYNC_SOURCE_CACHES, sizeof(*s->cache_tags));
    if (s->records == NULL || s->workspace == NULL || s->cache_tags == NULL) {
        sync_source_free(s);
        return SYNC_SOURCE_BACKING;
    }
    s->quota = quota;
    s->incarnation = incarnation;
    s->direction = direction;
    s->initialized = 1;
    return SYNC_SOURCE_OK;
}

void sync_source_free(sync_source_t *s)
{
    if (s == NULL)
        return;
    if (s->records != NULL) {
        crypto_memzero(s->records, s->nrecords * sizeof(*s->records));
        free(s->records);
    }
    if (s->workspace != NULL) {
        crypto_memzero(s->workspace, SOURCE_WORKSPACE_BYTES);
        free(s->workspace);
    }
    if (s->cache_tags != NULL) {
        crypto_memzero(s->cache_tags,
                       SYNC_SOURCE_CACHES * sizeof(*s->cache_tags));
        free(s->cache_tags);
    }
    crypto_memzero(s, sizeof(*s));
}

uint64_t sync_source_tip(const sync_source_t *s)
{
    return s == NULL ? 0 : s->tip;
}

static int source_state(const sync_source_t *s)
{
    if (s == NULL || !s->initialized)
        return SYNC_SOURCE_RANGE;
    if (s->failed)
        return SYNC_SOURCE_FAILED;
    return SYNC_SOURCE_OK;
}

static int source_base(const sync_source_t *s, uint64_t base)
{
    int rc = source_state(s);
    if (rc != SYNC_SOURCE_OK)
        return rc;
    if (base > s->tip || s->tip - base > s->quota)
        return SYNC_SOURCE_RANGE;
    return SYNC_SOURCE_OK;
}

static int source_ready(const sync_source_t *s, const sync_backlog_t *b,
                         uint64_t base)
{
    int rc = source_base(s, base);
    if (rc != SYNC_SOURCE_OK)
        return rc;
    if (b == NULL ||
        b->chunks == NULL || b->chunk_no == NULL ||
        b->nchunks != s->quota / SYNC_BACKLOG_CHUNK_SIZE + 1U)
        return SYNC_SOURCE_RANGE;
    return SYNC_SOURCE_OK;
}

static int source_poison(sync_source_t *s, int cause)
{
    s->failed = 1;
    return cause;
}

static uint64_t source_floor(uint64_t base)
{
    return base == 0 ? 0 : base - 1U;
}

static void source_put64(uint8_t out[8], uint64_t value)
{
    for (size_t i = 0; i < 8U; ++i)
        out[i] = (uint8_t)(value >> (8U * i));
}

static void source_digest(const sync_source_t *s, uint64_t offset,
                           uint32_t length, const uint8_t *bytes,
                           uint8_t digest[32])
{
    static const uint8_t domain[] = "unmoor-retained-source-v1";
    uint8_t header[25];
    crypto_blake2b_ctx hash;

    source_put64(header, s->incarnation);
    header[8] = s->direction;
    source_put64(header + 9, offset);
    source_put64(header + 17, length);
    crypto_blake2b_init(&hash, 32);
    crypto_blake2b_update(&hash, domain, sizeof(domain) - 1U);
    crypto_blake2b_update(&hash, header, sizeof(header));
    crypto_blake2b_update(&hash, bytes, length);
    crypto_blake2b_final(&hash, digest);
    crypto_memzero(&hash, sizeof(hash));
    crypto_memzero(header, sizeof(header));
}

int sync_source_available(const sync_source_t *s, uint64_t base, uint64_t *room)
{
    int rc;
    if (room == NULL)
        return SYNC_SOURCE_RANGE;
    *room = 0;
    rc = source_base(s, base);
    if (rc != SYNC_SOURCE_OK)
        return rc;
    if (s->pending.append_length > s->quota - (s->tip - base))
        return SYNC_SOURCE_RANGE;
    if (!s->pending.seal.valid)
        *room = s->quota - (s->tip - base);
    return SYNC_SOURCE_OK;
}

int sync_source_prepare(sync_source_t *s, uint64_t base,
                        const uint8_t *data, size_t length)
{
    int rc = source_base(s, base);
    size_t tail_length, fill, slot;
    uint64_t unit_offset;
    sync_source_record_t *candidate;
    sync_source_record_t *old;
    uint8_t *append, *seal;

    if (rc != SYNC_SOURCE_OK)
        return rc;
    if (length > SYNC_SOURCE_UNIT || (length != 0 && data == NULL) ||
        length > s->quota - (s->tip - base) || length > UINT64_MAX - s->tip)
        return SYNC_SOURCE_RANGE;
    if (length == 0)
        return SYNC_SOURCE_OK;
    if (s->pending.seal.valid)
        return SYNC_SOURCE_BUSY;
    tail_length = (size_t)(s->tip % SYNC_SOURCE_UNIT);
    fill = SYNC_SOURCE_UNIT - tail_length;
    if (length < fill) {
        memcpy(s->workspace + tail_length, data, length);
        s->tip += length;
        return SYNC_SOURCE_OK;
    }
    unit_offset = s->tip - tail_length;
    slot = (size_t)((unit_offset / SYNC_SOURCE_UNIT) % s->nrecords);
    old = &s->records[slot];
    if (old->valid &&
        (old->length != SYNC_SOURCE_UNIT ||
         old->offset > UINT64_MAX - old->length ||
         old->offset + old->length > source_floor(base)))
        return source_poison(s, SYNC_SOURCE_AUTH);
    append = s->workspace + SOURCE_APPEND_UNIT * SYNC_SOURCE_UNIT;
    seal = s->workspace + SOURCE_SEAL_UNIT * SYNC_SOURCE_UNIT;
    memcpy(append, data, length);
    memcpy(seal, s->workspace, tail_length);
    memcpy(seal + tail_length, append, fill);
    candidate = &s->pending.seal;
    candidate->offset = unit_offset;
    candidate->length = SYNC_SOURCE_UNIT;
    source_digest(s, unit_offset, candidate->length, seal, candidate->digest);
    s->pending.append_length = length;
    /* Original bytes/digest and cleanup slot precede exposure. The old
     * published tip, tail and record do not change until actual acceptance. */
    candidate->valid = 1;
    return SYNC_SOURCE_PENDING;
}

int sync_source_pending_view(const sync_source_t *s, sync_source_store_t *out)
{
    int rc;
    if (out == NULL)
        return SYNC_SOURCE_RANGE;
    memset(out, 0, sizeof(*out));
    rc = source_state(s);
    if (rc != SYNC_SOURCE_OK)
        return rc;
    if (!s->pending.seal.valid || s->pending.operation != 0)
        return SYNC_SOURCE_BUSY;
    out->offset = s->pending.seal.offset;
    out->unit = s->workspace + SOURCE_SEAL_UNIT * SYNC_SOURCE_UNIT;
    return SYNC_SOURCE_OK;
}

int sync_source_bind_once(sync_source_t *s, uint64_t operation)
{
    int rc = source_state(s);
    if (rc != SYNC_SOURCE_OK)
        return rc;
    if (operation == 0)
        return SYNC_SOURCE_RANGE;
    if (!s->pending.seal.valid || s->pending.operation != 0)
        return SYNC_SOURCE_BUSY;
    s->pending.operation = operation;
    return SYNC_SOURCE_OK;
}

/* Only a prepared seal whose store was accepted reaches this helper. Direct
 * backing and asynchronous checked-result paths share original-byte commit. */
static int source_commit(sync_source_t *s)
{
    size_t slot = (size_t)((s->pending.seal.offset / SYNC_SOURCE_UNIT) % s->nrecords);
    size_t fill = SYNC_SOURCE_UNIT - (size_t)(s->tip % SYNC_SOURCE_UNIT);
    size_t length = s->pending.append_length;
    size_t residual = length - fill;
    const uint8_t *append = s->workspace + SOURCE_APPEND_UNIT * SYNC_SOURCE_UNIT;

    /* An old cached unit may outlive retirement but cannot be rebound to a
     * reused record slot. Absolute source offsets never wrap or repeat. */
    for (size_t i = 0; i < SYNC_SOURCE_CACHES; ++i) {
        sync_source_cache_tag_t *tag = &s->cache_tags[i];
        if (tag->valid &&
            (tag->offset / SYNC_SOURCE_UNIT) % s->nrecords == slot) {
            crypto_memzero(s->workspace + (2U + i) * SYNC_SOURCE_UNIT,
                           SYNC_SOURCE_UNIT);
            crypto_memzero(tag, sizeof(*tag));
        }
    }
    s->records[slot] = s->pending.seal;
    crypto_memzero(s->workspace, SYNC_SOURCE_UNIT);
    if (residual != 0)
        memcpy(s->workspace, append + fill, residual);
    s->tip += length;
    crypto_memzero(s->workspace + SOURCE_APPEND_UNIT * SYNC_SOURCE_UNIT,
                   2U * SYNC_SOURCE_UNIT);
    crypto_memzero(&s->pending, sizeof(s->pending));
    return SYNC_SOURCE_OK;
}

int sync_source_finish(sync_source_t *s, const sync_work_header_t *stored,
                        uint8_t status, uint64_t publication)
{
    int rc = source_state(s);
    if (rc != SYNC_SOURCE_OK)
        return rc;
    if (stored == NULL)
        return SYNC_SOURCE_RANGE;
    if (!s->pending.seal.valid || s->pending.operation == 0 ||
        stored->incarnation != s->incarnation || stored->direction != s->direction ||
        stored->type != SYNC_WORK_STORED || stored->operation != s->pending.operation ||
        status > 1U)
        return source_poison(s, SYNC_SOURCE_AUTH);
    if (status == 1U)
        return source_poison(s, SYNC_SOURCE_BACKING);
    if (publication != s->pending.operation)
        return source_poison(s, SYNC_SOURCE_AUTH);
    return source_commit(s);
}

int sync_source_append(sync_source_t *s, sync_backlog_t *b,
                       uint64_t base, const uint8_t *data, size_t length)
{
    int rc = source_ready(s, b, base);
    if (rc != SYNC_SOURCE_OK)
        return rc;
    rc = sync_source_prepare(s, base, data, length);
    if (rc != SYNC_SOURCE_PENDING)
        return rc;
    /* Direct synchronous use does not invent a carriage serial/result. */
    if (sync_backlog_store(b, s->pending.seal.offset,
                           s->workspace + SOURCE_SEAL_UNIT * SYNC_SOURCE_UNIT,
                           SYNC_SOURCE_UNIT) != 0)
        return source_poison(s, SYNC_SOURCE_BACKING);
    return source_commit(s);
}

int sync_source_abandon(sync_source_t *s)
{
    int rc = source_state(s);
    return rc == SYNC_SOURCE_OK ? source_poison(s, SYNC_SOURCE_BACKING) : rc;
}

int sync_source_slot_used(const sync_source_t *s, size_t slot)
{
    if (s == NULL || !s->initialized || slot >= s->nrecords)
        return SYNC_SOURCE_RANGE;
    return s->records[slot].valid ||
        (s->pending.seal.valid &&
         (s->pending.seal.offset / SYNC_SOURCE_UNIT) % s->nrecords == slot);
}

static int source_range(const sync_source_t *s, const sync_source_reader_t *reader,
                         uint64_t base, uint64_t offset, size_t length)
{
    int rc = source_base(s, base);
    if (rc != SYNC_SOURCE_OK)
        return rc;
    if (reader == NULL || reader->context == NULL || reader->read_unit == NULL ||
        reader->nrecords != s->nrecords)
        return SYNC_SOURCE_RANGE;
    if (offset < source_floor(base) || offset > s->tip ||
        length > s->tip - offset)
        return SYNC_SOURCE_RANGE;
    return SYNC_SOURCE_OK;
}

int sync_source_span_with_reader(sync_source_t *s, const sync_source_reader_t *reader,
                     uint64_t base, uint64_t offset, size_t limit,
                     const uint8_t **bytes, size_t *length)
{
    uint64_t unit_offset, tail_offset;
    size_t inside, n, slot;
    uint8_t digest[32];
    uint8_t *scratch, *cache;
    sync_source_record_t *record;
    int rc;

    if (bytes != NULL)
        *bytes = NULL;
    if (length != NULL)
        *length = 0;
    if (bytes == NULL || length == NULL)
        return SYNC_SOURCE_RANGE;
    rc = source_range(s, reader, base, offset, limit);
    if (rc != SYNC_SOURCE_OK || limit == 0)
        return rc;
    unit_offset = offset - offset % SYNC_SOURCE_UNIT;
    inside = (size_t)(offset - unit_offset);
    n = SYNC_SOURCE_UNIT - inside;
    if (n > limit)
        n = limit;
    tail_offset = s->tip - s->tip % SYNC_SOURCE_UNIT;
    if (unit_offset == tail_offset) {
        /* Whole range validation proves initialized tail coverage. */
        *bytes = s->workspace + inside;
        *length = n;
        return SYNC_SOURCE_OK;
    }
    record = &s->records[(unit_offset / SYNC_SOURCE_UNIT) % s->nrecords];
    if (!record->valid || record->offset != unit_offset ||
        record->length != SYNC_SOURCE_UNIT)
        return source_poison(s, SYNC_SOURCE_AUTH);
    for (size_t i = 0; i < SYNC_SOURCE_CACHES; ++i) {
        if (s->cache_tags[i].valid && s->cache_tags[i].offset == unit_offset) {
            *bytes = s->workspace + (2U + i) * SYNC_SOURCE_UNIT + inside;
            *length = n;
            return SYNC_SOURCE_OK;
        }
    }
    scratch = s->workspace + SYNC_SOURCE_UNIT;
    if (reader->read_unit(reader->context, unit_offset, scratch) != 0) {
        crypto_memzero(scratch, SYNC_SOURCE_UNIT);
        return source_poison(s, SYNC_SOURCE_BACKING);
    }
    source_digest(s, unit_offset, record->length, scratch, digest);
    rc = crypto_verify32(digest, record->digest);
    crypto_memzero(digest, sizeof(digest));
    if (rc != 0) {
        crypto_memzero(scratch, SYNC_SOURCE_UNIT);
        return source_poison(s, SYNC_SOURCE_AUTH);
    }
    slot = s->replacement;
    cache = s->workspace + (2U + slot) * SYNC_SOURCE_UNIT;
    memcpy(cache, scratch, SYNC_SOURCE_UNIT);
    crypto_memzero(scratch, SYNC_SOURCE_UNIT);
    s->cache_tags[slot].offset = unit_offset;
    s->cache_tags[slot].valid = 1;
    s->replacement = (uint8_t)((slot + 1U) % SYNC_SOURCE_CACHES);
    *bytes = cache + inside;
    *length = n;
    return SYNC_SOURCE_OK;
}

int sync_source_load_with_reader(sync_source_t *s, const sync_source_reader_t *reader,
                     uint64_t base, uint64_t offset, uint8_t *output,
                     size_t length)
{
    int rc = source_range(s, reader, base, offset, length);
    if (rc != SYNC_SOURCE_OK)
        return rc;
    if (length != 0 && output == NULL)
        return SYNC_SOURCE_RANGE;
    while (length != 0) {
        const uint8_t *bytes;
        size_t n;
        rc = sync_source_span_with_reader(s, reader, base, offset, length, &bytes, &n);
        if (rc != SYNC_SOURCE_OK)
            return rc;
        memcpy(output, bytes, n);
        offset += n;
        output += n;
        length -= n;
    }
    return SYNC_SOURCE_OK;
}

int sync_source_chain_absorb_with_reader(sync_source_t *s,
                             const sync_source_reader_t *reader,
                             uint64_t base, uint64_t offset, size_t length,
                             crypto_sync_chain_t *chain)
{
    crypto_sync_chain_t candidate;
    int rc = source_range(s, reader, base, offset, length);
    if (rc != SYNC_SOURCE_OK)
        return rc;
    if (chain == NULL)
        return SYNC_SOURCE_RANGE;
    candidate = *chain;
    while (length != 0) {
        const uint8_t *bytes;
        size_t n;
        rc = sync_source_span_with_reader(s, reader, base, offset, length, &bytes, &n);
        if (rc != SYNC_SOURCE_OK)
            break;
        crypto_sync_chain_absorb(&candidate, bytes, n);
        offset += n;
        length -= n;
    }
    if (rc == SYNC_SOURCE_OK)
        *chain = candidate;
    crypto_memzero(&candidate, sizeof(candidate));
    return rc;
}

static int source_backlog_read(const void *context, uint64_t offset, uint8_t *out)
{
    return sync_backlog_load(context, offset, out, SYNC_SOURCE_UNIT);
}

int sync_source_span(sync_source_t *s, const sync_backlog_t *b,
                     uint64_t base, uint64_t offset, size_t limit,
                     const uint8_t **bytes, size_t *length)
{
    sync_source_reader_t reader;
    int rc;
    if (bytes != NULL)
        *bytes = NULL;
    if (length != NULL)
        *length = 0;
    if (bytes == NULL || length == NULL)
        return SYNC_SOURCE_RANGE;
    rc = source_ready(s, b, base);
    if (rc != SYNC_SOURCE_OK)
        return rc;
    reader = (sync_source_reader_t){b, source_backlog_read, s->nrecords};
    return sync_source_span_with_reader(s, &reader, base, offset, limit, bytes, length);
}

int sync_source_load(sync_source_t *s, const sync_backlog_t *b,
                     uint64_t base, uint64_t offset, uint8_t *out, size_t length)
{
    sync_source_reader_t reader;
    int rc = source_ready(s, b, base);
    if (rc != SYNC_SOURCE_OK)
        return rc;
    reader = (sync_source_reader_t){b, source_backlog_read, s->nrecords};
    return sync_source_load_with_reader(s, &reader, base, offset, out, length);
}

int sync_source_chain_absorb(sync_source_t *s, const sync_backlog_t *b,
                             uint64_t base, uint64_t offset, size_t length,
                             crypto_sync_chain_t *chain)
{
    sync_source_reader_t reader;
    int rc = source_ready(s, b, base);
    if (rc != SYNC_SOURCE_OK)
        return rc;
    reader = (sync_source_reader_t){b, source_backlog_read, s->nrecords};
    return sync_source_chain_absorb_with_reader(s, &reader, base, offset, length, chain);
}
