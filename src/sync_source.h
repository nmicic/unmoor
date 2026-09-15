/*
 * sync_source.h — synchronous trusted source commitments and verified readback
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef UNMOOR_SYNC_SOURCE_H
#define UNMOOR_SYNC_SOURCE_H

#include "crypto.h"
#include "sync_backlog.h"
#include "sync_work_codec.h"
#include <stddef.h>
#include <stdint.h>

#define SYNC_SOURCE_UNIT 16384U
#define SYNC_SOURCE_CACHES 4U
#define SYNC_SOURCE_QUOTA_MAX (UINT64_C(4) * 1024U * 1024U * 1024U)

#define SYNC_SOURCE_OK       0
#define SYNC_SOURCE_PENDING  1
#define SYNC_SOURCE_RANGE   -1
#define SYNC_SOURCE_BACKING -2
#define SYNC_SOURCE_AUTH    -3
#define SYNC_SOURCE_FAILED  -4
#define SYNC_SOURCE_BUSY    -5

/* One issuer per trusted monitor lifetime, outside every resettable source.
 * Single-threaded. Never copy/reset/recycle it during that lifetime. Output
 * must be separate: an output alias of last is refused without changing last
 * (rather than clearing that output and accidentally resetting the issuer). */
typedef struct { uint64_t last; } sync_source_issuer_t;
int sync_source_issue(sync_source_issuer_t *issuer, uint64_t *identity);

typedef struct {
    uint64_t offset;
    uint8_t digest[32];
    uint32_t length;
    uint32_t valid;
} sync_source_record_t;

typedef struct {
    uint64_t offset;
    uint64_t valid;
} sync_source_cache_tag_t;

typedef struct {
    sync_source_record_t seal;
    uint64_t operation;
    size_t append_length;
} sync_source_pending_t;

/* Trusted synchronous full-unit copy; non-NULL immutable context, matching
 * geometry, no reentry or retained output. Zero initializes all U bytes;
 * other returns fail. No returned shared pointer, byte count or digest. */
typedef struct {
    const void *context;
    int (*read_unit)(const void *context, uint64_t unit_offset,
                     uint8_t owned_output[SYNC_SOURCE_UNIT]);
    size_t nrecords;
} sync_source_reader_t;

typedef struct {
    uint64_t offset;
    const uint8_t *unit;
} sync_source_store_t;

/* All fields/allocations are trusted. Backing has a separate owner. This
 * is a standalone preparation, not yet a process or session integration.
 * workspace = tail, read scratch, four verified caches, owned append, seal. */
typedef struct {
    sync_source_record_t *records;
    uint8_t *workspace;
    sync_source_cache_tag_t *cache_tags;
    size_t nrecords;
    uint64_t quota;
    uint64_t tip;
    uint64_t incarnation;
    uint8_t direction;
    uint8_t replacement;
    uint8_t initialized;
    uint8_t failed;
    sync_source_pending_t pending;
} sync_source_t;

/* Quota is chunk-rounded, 256 KiB..4 GiB. Dynamic guard bytes only:
 * 48*N + 8*UNIT + 64. Fixed owner/issuer, hash/chain work and independently
 * owned backing/input/output buffers are additional. Outputs clear on error. */
int sync_source_geometry(uint64_t quota, size_t *slots, size_t *records,
                         size_t *allocated_bytes);

/* Requires an empty/zeroed owner and a nonzero monitor-issued identity;
 * cannot establish identity uniqueness itself. Init failure leaves an empty
 * owner; live re-init refuses without mutation. Free wipes complete owned
 * allocations and the object, never the separate backing or issuer. */
int sync_source_init(sync_source_t *source, uint64_t quota,
                     uint64_t incarnation, uint8_t direction);
void sync_source_free(sync_source_t *source);
uint64_t sync_source_tip(const sync_source_t *source);

/* base is monotonic chain-verified caller authority, never a worker value.
 * The guard checks base<=tip and complete ranges, but stores no ACK ledger
 * and therefore cannot detect a caller's base regression. Each operation is
 * synchronous; immutable input/output/chain storage must not alias the guard,
 * its allocations or the backing. No returned span survives another call.
 *
 * Healthy null/range/quota validation errors leave state unchanged. Backing,
 * authentication and impossible live-slot failures poison the owner; then
 * even zero-length operations return FAILED until retirement. A healthy
 * valid zero length is a no-op (data/output may be NULL). Backing must be
 * initialized separately with the matching geometry for every operation.
 */
int sync_source_append(sync_source_t *source, sync_backlog_t *backing,
                       uint64_t base, const uint8_t *data, size_t length);

/* Prepare publishes a small no-seal tail immediately (OK), or retains the
 * entire append and original seal without changing old tip/tail (PENDING).
 * A positive second append is BUSY; healthy valid zero remains a no-op.
 * pending_view -> actual carriage begin/copy/issue -> bind_once -> first step.
 * The view expires at the next source call. Bind never issues/predicts an ID.
 * Finish takes the actual checked STORED header and independent publication;
 * neither local receipt nor that scalar authenticates stored bytes.
 */
int sync_source_prepare(sync_source_t *, uint64_t base, const uint8_t *, size_t);
int sync_source_pending_view(const sync_source_t *, sync_source_store_t *out);
int sync_source_bind_once(sync_source_t *, uint64_t issued_operation);
int sync_source_finish(sync_source_t *, const sync_work_header_t *stored,
                        uint8_t status, uint64_t acquired_publication);
int sync_source_available(const sync_source_t *, uint64_t base, uint64_t *room);
/* Abandon is terminal BACKING, even without pending work. It retains cleanup
 * inventory; it cannot discard exact bytes and resume. Already failed=FAILED. */
int sync_source_abandon(sync_source_t *);
/* Metadata-only 0/1 historical-valid OR pending physical slot, including on
 * failed owners. RANGE for invalid owner/index. No writer-reap authority. */
int sync_source_slot_used(const sync_source_t *, size_t physical_slot);

/* Retained range is [base ? base-1 : 0, tip). Span always needs both output
 * parameters and clears them on failure/zero length. It returns only owned,
 * completely verified bytes (or the immediate initialized trusted tail).
 * Load may copy an earlier span before failure; ALL output is then unusable.
 * Chain stages a copy, publishes only complete success, wipes staging on
 * every exit, and grants no ACK/delivery authority. */
int sync_source_span(sync_source_t *source, const sync_backlog_t *backing,
                     uint64_t base, uint64_t offset, size_t limit,
                     const uint8_t **bytes, size_t *length);
int sync_source_load(sync_source_t *source, const sync_backlog_t *backing,
                     uint64_t base, uint64_t offset, uint8_t *output,
                     size_t length);
int sync_source_chain_absorb(sync_source_t *source,
                             const sync_backlog_t *backing, uint64_t base,
                             uint64_t offset, size_t length,
                             crypto_sync_chain_t *chain);

/* Same owned-byte/range/failure semantics using the separately trusted reader.
 * Validate its context/callback/geometry even for tail/cache/zero operations.
 * Cold reads use only read scratch, never either pending staging unit. */
int sync_source_span_with_reader(sync_source_t *, const sync_source_reader_t *,
                                  uint64_t base, uint64_t offset, size_t limit,
                                  const uint8_t **bytes, size_t *length);
int sync_source_load_with_reader(sync_source_t *, const sync_source_reader_t *,
                                  uint64_t base, uint64_t offset, uint8_t *output,
                                  size_t length);
int sync_source_chain_absorb_with_reader(sync_source_t *,
                                         const sync_source_reader_t *,
                                         uint64_t base, uint64_t offset,
                                         size_t length, crypto_sync_chain_t *chain);

#endif
