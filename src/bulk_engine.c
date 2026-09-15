/*
 * bulk_engine.c — bulk-transfer portable transfer and path-share state engine
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bulk_engine.h"

#define ENGINE_DIRTY_BYTES       (BULK_ACK_PAGES / 8U)
#define ENGINE_OCCUPANCY_WORDS   (BULK_LEGS_MAX * 4U)
#define ENGINE_ALIGN             64U
#define ENGINE_PAGE_ALIGN        4096U
#define ENGINE_CLOCK_HEADROOM    INT64_C(400000)

_Static_assert((BULK_ENGINE_ACTIVE_INDEX_ENTRIES &
                (BULK_ENGINE_ACTIVE_INDEX_ENTRIES - 1U)) == 0U,
               "bulk-transfer active-chunk index must be power-of-two");
_Static_assert(BULK_ENGINE_OUTSTANDING_ENTRIES < UINT16_MAX,
               "bulk-transfer active-chunk index value must fit uint16_t");

typedef enum {
    ENGINE_SCAN_NONE = 0,
    ENGINE_SCAN_SOURCE = 1,
    ENGINE_SCAN_VERIFY = 2
} engine_scan_t;

typedef enum {
    ENGINE_TX_NONE = 0,
    ENGINE_TX_REQUEST = 1,
    ENGINE_TX_MANIFEST = 2,
    ENGINE_TX_ACK = 3,
    ENGINE_TX_STATUS = 4,
    ENGINE_TX_DATA = 5,
    ENGINE_TX_BUSY = 6
} engine_tx_kind_t;

typedef struct {
    int64_t completed_ms;
    uint64_t generation;
    uint32_t chunk_index;
    uint32_t attempt_id;
    uint8_t active;
    uint8_t sender_leg;
    uint8_t reserved[38];
} engine_outstanding_t;

_Static_assert(sizeof(engine_outstanding_t) == 64U,
               "bulk-transfer outstanding entry must remain 64 bytes");

typedef struct {
    uint8_t active;
    uint8_t kind;
    uint8_t data_is_new;
    uint8_t status_phase;
    send_lane_t lane;
    uint32_t chunk_index;
    uint32_t attempt_id;
    uint32_t ack_page_word_base;
    uint64_t status_revision;
    uint16_t body_length;
    uint8_t sender_leg;
} engine_tx_state_t;

typedef struct {
    uint64_t sampled_acked_chunks[BULK_LEGS_MAX];
    int64_t share_next_ms[BULK_LEGS_MAX];
    int64_t reroll_defer_ms[BULK_LEGS_MAX];
    /* Indexed by physical token.local_leg, unlike the slot-indexed arrays. */
    int64_t reroll_quiet_ms[BULK_LEGS_MAX];
    uint16_t outstanding[BULK_LEGS_MAX];
    uint8_t share_shift[BULK_LEGS_MAX];
    uint8_t progress_intervals[BULK_LEGS_MAX];
    uint8_t no_progress_at_min[BULK_LEGS_MAX];
    /* Physical socket-attempt budgets are cumulative for this session. */
    uint8_t reroll_attempts[BULK_LEGS_MAX];
    uint8_t reroll_claim_physical[BULK_LEGS_MAX];
    uint64_t generation[BULK_LEGS_MAX];
    uint64_t set_reroll_generation;
    int64_t set_reroll_quiet_ms;
    int64_t reroll_session_quiet_ms;
    int64_t reroll_witness_deadline_ms[BULK_LEGS_MAX];
    uint32_t eligible_mask;
    uint32_t d32_eligible_mask;
    uint32_t mtu_usable_mask;
    uint32_t reroll_due_mask;
    uint32_t reroll_exhausted_mask;
    uint32_t reroll_claimed_mask;
    /* Whole-set socket-attempt budget is cumulative for this session. */
    uint8_t set_reroll_attempts;
    uint8_t set_reroll_claimed;
    uint8_t set_reroll_trigger_leg;
    uint8_t set_reroll_exhausted;
    uint8_t path_count;
    uint8_t primary_leg;
} engine_path_state_t;

_Static_assert(sizeof(engine_path_state_t) <=
               BULK_ENGINE_PATH_STATE_BYTES,
               "bulk-transfer path state exceeds its fixed aligned arena");
_Static_assert(sizeof(bulk_engine_stats_t) <=
               BULK_ENGINE_STATS_STORAGE_BYTES,
               "bulk-transfer accounting exceeds its fixed aligned arena");
_Static_assert(sizeof(path_leg_t) == PATH_LEG_BYTES,
               "path leg layout changed");

struct bulk_engine {
    uint8_t active;
    uint8_t endpoint;
    uint8_t operation;
    uint8_t force;
    uint8_t is_source;
    uint8_t request_bound;
    uint8_t request_completed;
    uint8_t manifest_bound;
    uint8_t allocation_acked;
    uint8_t root_ready;
    uint8_t paused;
    uint8_t path_paused;
    uint8_t path_pause_progress_seen;
    uint8_t path_pause_epoch_overlap_active;
    uint8_t clock_started;
    uint8_t local_status_valid;
    uint8_t peer_status_valid;
    uint8_t status_due;
    uint8_t request_due;
    uint8_t manifest_due;
    uint8_t failure_pending;
    uint8_t error_linger_started;
    uint8_t completion_linger_started;
    uint8_t installed;
    uint8_t done_seen;
    uint8_t done_sent_complete;
    uint8_t done_ack_sent_complete;
    uint8_t done_confirm_sent_complete;
    uint8_t interactive_cursor;
    uint8_t scan_kind;
    uint8_t scan_status_enabled;
    uint8_t busy_status_valid;
    uint8_t recovery_scan_valid;
    uint8_t recovery_scan_more;
    uint8_t path_policy_called;

    uint16_t wire_budget;
    uint16_t chunk_size;
    int64_t pace_bps;
    int64_t stall_ms;
    int64_t now_ms;
    int64_t last_progress_ms;
    int64_t request_next_ms;
    int64_t manifest_next_ms;
    int64_t ack_next_ms;
    int64_t status_next_ms;
    int64_t scan_last_report_ms;
    int64_t error_linger_ms;
    int64_t completion_linger_ms;
    int64_t pause_started_ms;
    int64_t path_pause_started_ms;
    int64_t path_pause_epoch_overlap_ms;
    int64_t path_pause_epoch_overlap_started_ms;
    int64_t send_retry_deadline_ms;
    int64_t send_retry_delay_ms;

    uint64_t transfer_id;
    uint64_t scan_processed;
    uint64_t scan_next_report;
    uint32_t scan_index;
    uint32_t new_cursor;
    uint32_t recovery_word_cursor;
    uint32_t recovery_words_remaining;
    uint32_t recovery_floor_word;
    uint32_t recovery_limit_word;
    uint32_t next_attempt_id;
    uint32_t ack_page_cursor;

    bulk_engine_result_t result;
    bulk_result_code_t result_code;
    bulk_request_t request;
    bulk_manifest_t manifest;
    bulk_status_t local_status;
    bulk_status_t peer_status;
    bulk_status_t busy_status;
    bulk_source_t source;
    bulk_sink_t sink;
    bulk_merkle_t merkle;
    bulk_ack_state_t ack_state;
    engine_tx_state_t tx;
    engine_path_state_t *paths;
    bulk_engine_stats_t *stats;
    bulk_engine_path_policy_fn path_policy;
    void *path_policy_arg;

    uint8_t local_path[BULK_PATH_MAX + 1U];
    size_t local_path_length;
    uint8_t *dirty_pages;
    void *bitmap_storage;
    engine_outstanding_t *outstanding;
    uint16_t *active_index;
    uint64_t *occupancy;
    uint8_t *chunk_buffer;
    uint8_t *path_scratch;
    uint8_t *encoded_buffer;
    uint8_t *receive_buffer;
#ifdef UNMOOR_BULK_ENGINE_TEST
    bulk_engine_test_scan_metrics_t test_scan;
#endif
};

_Static_assert(BULK_ENGINE_PORTABLE_FIXED_BYTES +
               sizeof(struct bulk_engine) <
               BULK_ENGINE_PORTABLE_LIMIT_BYTES,
               "bulk-transfer portable engine must remain below 2.75 MiB");

static int source_begin(bulk_engine_t *engine, int64_t now_ms);
static int receiver_bind_manifest(bulk_engine_t *engine,
                                  const bulk_manifest_t *manifest,
                                  int64_t now_ms);
static void local_fail(bulk_engine_t *engine, bulk_result_code_t code,
                       int64_t now_ms, int publish);
static int set_local_status(bulk_engine_t *engine, uint8_t phase,
                            uint16_t code, uint64_t processed,
                            int64_t now_ms);

static int clock_value_valid(int64_t now_ms)
{
    return now_ms >= 0 && now_ms <= INT64_MAX - ENGINE_CLOCK_HEADROOM;
}

static int64_t reroll_witness_ready_ms(
    const engine_path_state_t *paths, uint8_t sender_leg)
{
    int64_t deadline;

    if (paths == NULL || sender_leg >= BULK_LEGS_MAX)
        return 0;
    deadline = paths->reroll_witness_deadline_ms[sender_leg];
    if (deadline < BULK_ENGINE_REROLL_WITNESS_MS)
        return 0;
    return deadline - BULK_ENGINE_REROLL_WITNESS_MS +
           BULK_ENGINE_REROLL_RECOVERY_GRACE_MS;
}

static int reroll_witness_ready(const engine_path_state_t *paths,
                                uint8_t sender_leg, int64_t now_ms)
{
    int64_t deadline;
    int64_t ready;

    if (paths == NULL || sender_leg >= BULK_LEGS_MAX)
        return 0;
    deadline = paths->reroll_witness_deadline_ms[sender_leg];
    ready = reroll_witness_ready_ms(paths, sender_leg);
    return ready != 0 && now_ms >= ready && now_ms <= deadline;
}

static void reroll_defer_until(engine_path_state_t *paths,
                               uint8_t sender_leg, int64_t deadline_ms)
{
    if (paths != NULL && sender_leg < BULK_LEGS_MAX &&
        paths->reroll_defer_ms[sender_leg] < deadline_ms)
        paths->reroll_defer_ms[sender_leg] = deadline_ms;
}

static int path_count_valid(unsigned int path_count)
{
    return path_count >= 1U && path_count <= BULK_LEGS_MAX &&
           (path_count & (path_count - 1U)) == 0U;
}

static uint32_t path_low_mask(unsigned int path_count)
{
    if (!path_count_valid(path_count))
        return 0U;
    return path_count == 32U ? UINT32_MAX :
           (UINT32_C(1) << path_count) - UINT32_C(1);
}

static int bytes_zero(const uint8_t *bytes, size_t length)
{
    uint8_t aggregate = 0;
    size_t i;

    if (bytes == NULL)
        return 0;
    for (i = 0; i < length; i++)
        aggregate |= bytes[i];
    return aggregate == 0;
}

static int root_equal(const uint8_t left[BULK_ROOT_BYTES],
                      const uint8_t right[BULK_ROOT_BYTES])
{
    return memcmp(left, right, BULK_ROOT_BYTES) == 0;
}

static int request_equal(const bulk_request_t *left,
                         const bulk_request_t *right)
{
    return left->operation == right->operation &&
           left->flags == right->flags &&
           left->transfer_id == right->transfer_id &&
           left->wire_budget == right->wire_budget &&
           left->path_length == right->path_length &&
           memcmp(left->path, right->path, left->path_length) == 0;
}

static int manifest_equal(const bulk_manifest_t *left,
                          const bulk_manifest_t *right)
{
    return left->transfer_id == right->transfer_id &&
           left->file_size == right->file_size &&
           left->chunk_count == right->chunk_count &&
           left->wire_budget == right->wire_budget &&
           left->chunk_log2 == right->chunk_log2 &&
           root_equal(left->root, right->root);
}

static int status_equal(const bulk_status_t *left,
                        const bulk_status_t *right)
{
    return left->phase == right->phase && left->code == right->code &&
           left->revision == right->revision &&
           left->transfer_id == right->transfer_id &&
           left->file_size == right->file_size &&
           left->processed_bytes == right->processed_bytes &&
           root_equal(left->root, right->root);
}

static int aligned_zero_alloc(void **out, size_t alignment, size_t bytes)
{
    void *storage = NULL;

    if (out == NULL || bytes == 0 ||
        posix_memalign(&storage, alignment, bytes) != 0)
        return BULK_RC_RESOURCE;
    memset(storage, 0, bytes);
    *out = storage;
    return BULK_RC_OK;
}

static int copy_path(uint8_t destination[BULK_PATH_MAX + 1U],
                     size_t *destination_length,
                     const uint8_t *source, size_t source_length)
{
    size_t i;

    if (destination == NULL || destination_length == NULL || source == NULL ||
        source_length == 0 || source_length > BULK_PATH_MAX)
        return BULK_RC_ARGUMENT;
    for (i = 0; i < source_length; i++) {
        if (source[i] == 0)
            return BULK_RC_ARGUMENT;
    }
    memcpy(destination, source, source_length);
    destination[source_length] = 0;
    *destination_length = source_length;
    return BULK_RC_OK;
}

static void start_clock(bulk_engine_t *engine, int64_t now_ms)
{
    if (!engine->clock_started) {
        engine->clock_started = 1;
        engine->last_progress_ms = now_ms;
    }
}

static void start_error_linger(bulk_engine_t *engine, int64_t now_ms)
{
    if (!engine->error_linger_started) {
        engine->error_linger_started = 1;
        engine->error_linger_ms = now_ms + BULK_ENGINE_LINGER_MS;
    }
}

static void note_progress(bulk_engine_t *engine, int64_t now_ms)
{
    start_clock(engine, now_ms);
    if (now_ms > engine->last_progress_ms)
        engine->last_progress_ms = now_ms;
    if (engine->path_paused)
        engine->path_pause_progress_seen = 1U;
}

static void dirty_mark(bulk_engine_t *engine, uint32_t page)
{
    if (engine->dirty_pages != NULL && page < BULK_ACK_PAGES)
        engine->dirty_pages[page >> 3] |=
            (uint8_t)(1U << (unsigned int)(page & 7U));
}

static void dirty_clear(bulk_engine_t *engine, uint32_t page)
{
    if (engine->dirty_pages != NULL && page < BULK_ACK_PAGES)
        engine->dirty_pages[page >> 3] &=
            (uint8_t)~(uint8_t)(1U << (unsigned int)(page & 7U));
}

static int dirty_test(const bulk_engine_t *engine, uint32_t page)
{
    if (engine->dirty_pages == NULL || page >= BULK_ACK_PAGES)
        return 0;
    return (engine->dirty_pages[page >> 3] &
            (uint8_t)(1U << (unsigned int)(page & 7U))) != 0;
}

static uint32_t manifest_page_count(const bulk_manifest_t *manifest)
{
    uint32_t pages;

    if (manifest == NULL || manifest->chunk_count == 0)
        return 1U;
    pages = (manifest->chunk_count + BULK_ACK_PAGE_BITS - 1U) /
            BULK_ACK_PAGE_BITS;
    return pages;
}

static int any_dirty_page(const bulk_engine_t *engine)
{
    size_t i;

    if (engine->dirty_pages == NULL)
        return 0;
    for (i = 0; i < ENGINE_DIRTY_BYTES; i++) {
        if (engine->dirty_pages[i] != 0)
            return 1;
    }
    return 0;
}

static uint32_t select_ack_page(bulk_engine_t *engine)
{
    uint32_t page_count = manifest_page_count(&engine->manifest);
    uint32_t start = engine->ack_page_cursor % page_count;
    uint32_t offset;

    for (offset = 0; offset < page_count; offset++) {
        uint32_t page = (start + offset) % page_count;
        if (dirty_test(engine, page)) {
            engine->ack_page_cursor = (page + 1U) % page_count;
            return page;
        }
    }
    engine->ack_page_cursor = (start + 1U) % page_count;
    return start;
}

static void recovery_scan_reset(bulk_engine_t *engine)
{
    engine->recovery_scan_valid = 0U;
    engine->recovery_scan_more = 0U;
    engine->recovery_word_cursor = 0U;
    engine->recovery_words_remaining = 0U;
    engine->recovery_floor_word = 0U;
    engine->recovery_limit_word = 0U;
}

static size_t active_index_bucket(uint32_t chunk_index)
{
    uint32_t value = chunk_index;

    value ^= value >> 16;
    value *= UINT32_C(0x7feb352d);
    value ^= value >> 15;
    value *= UINT32_C(0x846ca68b);
    value ^= value >> 16;
    return (size_t)(value &
                    (BULK_ENGINE_ACTIVE_INDEX_ENTRIES - 1U));
}

static void active_index_record_probes(bulk_engine_t *engine,
                                       uint32_t probes)
{
#ifdef UNMOOR_BULK_ENGINE_TEST
    engine->test_scan.active_index_probes += probes;
    if (probes > engine->test_scan.max_active_index_probes)
        engine->test_scan.max_active_index_probes = probes;
#else
    (void)engine;
    (void)probes;
#endif
}

static int active_index_lookup(bulk_engine_t *engine, uint32_t chunk_index,
                               size_t *bucket_out, size_t *slot_out)
{
    size_t bucket;
    uint32_t probes = 0U;

    if (engine == NULL || engine->active_index == NULL ||
        engine->outstanding == NULL)
        return -1;
    bucket = active_index_bucket(chunk_index);
    while (probes < BULK_ENGINE_ACTIVE_INDEX_ENTRIES) {
        uint16_t value = engine->active_index[bucket];
        size_t slot;

        probes++;
        if (value == 0U) {
            active_index_record_probes(engine, probes);
            return 0;
        }
        slot = (size_t)value - 1U;
        if (slot >= BULK_ENGINE_OUTSTANDING_ENTRIES ||
            !engine->outstanding[slot].active) {
            active_index_record_probes(engine, probes);
            return -1;
        }
        if (engine->outstanding[slot].chunk_index == chunk_index) {
            if (bucket_out != NULL)
                *bucket_out = bucket;
            if (slot_out != NULL)
                *slot_out = slot;
            active_index_record_probes(engine, probes);
            return 1;
        }
        bucket = (bucket + 1U) &
                 (BULK_ENGINE_ACTIVE_INDEX_ENTRIES - 1U);
    }
    active_index_record_probes(engine, probes);
    return -1;
}

static int active_index_insert_slot(bulk_engine_t *engine, size_t slot)
{
    size_t bucket;
    size_t probes;

    if (engine == NULL || engine->active_index == NULL ||
        engine->outstanding == NULL ||
        slot >= BULK_ENGINE_OUTSTANDING_ENTRIES ||
        !engine->outstanding[slot].active)
        return BULK_RC_STATE;
    bucket = active_index_bucket(engine->outstanding[slot].chunk_index);
    for (probes = 0U; probes < BULK_ENGINE_ACTIVE_INDEX_ENTRIES; probes++) {
        if (engine->active_index[bucket] == 0U) {
            engine->active_index[bucket] = (uint16_t)(slot + 1U);
            return BULK_RC_OK;
        }
        bucket = (bucket + 1U) &
                 (BULK_ENGINE_ACTIVE_INDEX_ENTRIES - 1U);
    }
    return BULK_RC_RESOURCE;
}

static int active_index_remove_slot(bulk_engine_t *engine, size_t slot)
{
    size_t bucket;
    size_t found_slot;
    size_t scan;
    int found;

    if (engine == NULL || engine->outstanding == NULL ||
        slot >= BULK_ENGINE_OUTSTANDING_ENTRIES ||
        !engine->outstanding[slot].active)
        return BULK_RC_STATE;
    found = active_index_lookup(engine,
                                engine->outstanding[slot].chunk_index,
                                &bucket, &found_slot);
    if (found != 1 || found_slot != slot)
        return BULK_RC_STATE;
    engine->active_index[bucket] = 0U;

    /* Closing a linear-probe hole early would make later colliding members
     * invisible. Reinsert the finite following cluster; with at most 8,192
     * owners in 16,384 slots this remains fixed and allocation-free. */
    scan = (bucket + 1U) & (BULK_ENGINE_ACTIVE_INDEX_ENTRIES - 1U);
    while (engine->active_index[scan] != 0U) {
        uint16_t value = engine->active_index[scan];
        size_t displaced = (size_t)value - 1U;

        engine->active_index[scan] = 0U;
        if (active_index_insert_slot(engine, displaced) != BULK_RC_OK)
            return BULK_RC_STATE;
        scan = (scan + 1U) &
               (BULK_ENGINE_ACTIVE_INDEX_ENTRIES - 1U);
    }
    return BULK_RC_OK;
}

static int release_acked_attempts(bulk_engine_t *engine)
{
    size_t i;

    if (!engine->manifest_bound && !engine->allocation_acked)
        return BULK_RC_OK;
    for (i = 0; i < (size_t)engine->paths->path_count *
                    BULK_ENGINE_OUTSTANDING_PER_LEG; i++) {
        engine_outstanding_t *entry = &engine->outstanding[i];
        if (entry->active &&
            bulk_bitmap_test(&engine->ack_state.bitmap,
                             entry->chunk_index) == 1) {
            uint8_t leg = entry->sender_leg;

            if (active_index_remove_slot(engine, i) != BULK_RC_OK)
                return BULK_RC_STATE;
            entry->active = 0;
            engine->occupancy[i >> 6] &=
                ~(UINT64_C(1) << (unsigned int)(i & 63U));
            if (leg < engine->paths->path_count &&
                entry->generation == engine->paths->generation[leg] &&
                engine->paths->outstanding[leg] != 0U)
                engine->paths->outstanding[leg]--;
        }
    }
    return BULK_RC_OK;
}

static int chunk_active(bulk_engine_t *engine, uint32_t chunk_index)
{
    return active_index_lookup(engine, chunk_index, NULL, NULL);
}

static int leg_has_room(const bulk_engine_t *engine, uint8_t sender_leg)
{
    size_t word;
    size_t first_word;

    if (sender_leg >= engine->paths->path_count)
        return 0;
    first_word = (size_t)sender_leg * 4U;
    for (word = 0; word < 4U; word++) {
        if (engine->occupancy[first_word + word] != UINT64_MAX)
            return 1;
    }
    return 0;
}

static int add_outstanding(bulk_engine_t *engine, uint32_t chunk_index,
                           uint32_t attempt_id, uint8_t sender_leg,
                           int64_t now_ms)
{
    int active;
    size_t slot;
    size_t base;

    if (sender_leg >= engine->paths->path_count)
        return BULK_RC_STATE;
    active = chunk_active(engine, chunk_index);
    if (active != 0)
        return BULK_RC_STATE;
    base = (size_t)sender_leg * BULK_ENGINE_OUTSTANDING_PER_LEG;
    for (slot = 0; slot < BULK_ENGINE_OUTSTANDING_PER_LEG; slot++) {
        size_t i = base + slot;

        if (!engine->outstanding[i].active) {
            engine->outstanding[i].active = 1;
            engine->outstanding[i].sender_leg = sender_leg;
            engine->outstanding[i].generation =
                engine->paths->generation[sender_leg];
            engine->outstanding[i].chunk_index = chunk_index;
            engine->outstanding[i].attempt_id = attempt_id;
            engine->outstanding[i].completed_ms = now_ms;
            if (active_index_insert_slot(engine, i) != BULK_RC_OK) {
                memset(&engine->outstanding[i], 0,
                       sizeof(engine->outstanding[i]));
                return BULK_RC_STATE;
            }
            engine->occupancy[i >> 6] |=
                UINT64_C(1) << (unsigned int)(i & 63U);
            engine->paths->outstanding[sender_leg]++;
            if (engine->paths->share_next_ms[sender_leg] == 0) {
                engine->paths->sampled_acked_chunks[sender_leg] =
                    engine->ack_state.counters[sender_leg].chunks;
                engine->paths->share_next_ms[sender_leg] =
                    now_ms + BULK_ENGINE_SHARE_INTERVAL_MS;
            }
            recovery_scan_reset(engine);
            return BULK_RC_OK;
        }
    }
    return BULK_RC_RESOURCE;
}

static int allocate_fixed_state(bulk_engine_t *engine)
{
    if (bulk_bitmap_storage_alloc(&engine->bitmap_storage) != BULK_RC_OK ||
        aligned_zero_alloc((void **)&engine->dirty_pages, ENGINE_ALIGN,
                           ENGINE_DIRTY_BYTES) != BULK_RC_OK ||
        aligned_zero_alloc((void **)&engine->outstanding, ENGINE_ALIGN,
                           sizeof(engine_outstanding_t) *
                           BULK_ENGINE_OUTSTANDING_ENTRIES) != BULK_RC_OK ||
        aligned_zero_alloc((void **)&engine->active_index, ENGINE_ALIGN,
                           sizeof(uint16_t) *
                           BULK_ENGINE_ACTIVE_INDEX_ENTRIES) != BULK_RC_OK ||
        aligned_zero_alloc((void **)&engine->occupancy, ENGINE_ALIGN,
                           sizeof(uint64_t) * ENGINE_OCCUPANCY_WORDS) !=
                           BULK_RC_OK ||
        aligned_zero_alloc((void **)&engine->paths, ENGINE_ALIGN,
                           BULK_ENGINE_PATH_STATE_BYTES) != BULK_RC_OK ||
        aligned_zero_alloc((void **)&engine->stats, ENGINE_ALIGN,
                           BULK_ENGINE_STATS_STORAGE_BYTES) != BULK_RC_OK ||
        aligned_zero_alloc((void **)&engine->chunk_buffer, ENGINE_PAGE_ALIGN,
                           BULK_CHUNK_MAX) != BULK_RC_OK ||
        aligned_zero_alloc((void **)&engine->path_scratch, ENGINE_ALIGN,
                           BULK_PATH_SCRATCH_BYTES) != BULK_RC_OK ||
        aligned_zero_alloc((void **)&engine->encoded_buffer,
                           ENGINE_PAGE_ALIGN,
                           BULK_ENGINE_TX_BUFFER_BYTES) != BULK_RC_OK ||
        aligned_zero_alloc((void **)&engine->receive_buffer,
                           ENGINE_PAGE_ALIGN,
                           BULK_ENGINE_TX_BUFFER_BYTES) != BULK_RC_OK)
        return BULK_RC_RESOURCE;
    return BULK_RC_OK;
}

static void release_fixed_state(bulk_engine_t *engine)
{
    if (engine == NULL)
        return;
    (void)bulk_source_close(&engine->source);
    (void)bulk_sink_cleanup(&engine->sink);
    bulk_bitmap_storage_free(engine->bitmap_storage);
    free(engine->dirty_pages);
    free(engine->outstanding);
    free(engine->active_index);
    free(engine->occupancy);
    free(engine->paths);
    free(engine->stats);
    free(engine->chunk_buffer);
    free(engine->path_scratch);
    free(engine->encoded_buffer);
    free(engine->receive_buffer);
    engine->bitmap_storage = NULL;
    engine->dirty_pages = NULL;
    engine->outstanding = NULL;
    engine->active_index = NULL;
    engine->occupancy = NULL;
    engine->paths = NULL;
    engine->stats = NULL;
    engine->chunk_buffer = NULL;
    engine->path_scratch = NULL;
    engine->encoded_buffer = NULL;
    engine->receive_buffer = NULL;
}

int bulk_engine_create(bulk_engine_t **engine_out)
{
    bulk_engine_t *engine;

    if (engine_out == NULL)
        return BULK_RC_ARGUMENT;
    engine = (bulk_engine_t *)calloc(1, sizeof(*engine));
    if (engine == NULL)
        return BULK_RC_RESOURCE;
    bulk_source_init(&engine->source);
    bulk_sink_init(&engine->sink);
    engine->result = BULK_ENGINE_RESULT_RUNNING;
    engine->result_code = BULK_CODE_NONE;
    *engine_out = engine;
    return BULK_RC_OK;
}

static int config_valid(const bulk_engine_config_t *config)
{
    int64_t minimum_rate;
    unsigned int path_count;

    if (config == NULL ||
        (config->endpoint != BULK_ENGINE_ENDPOINT_CLIENT &&
         config->endpoint != BULK_ENGINE_ENDPOINT_SERVER) ||
        !bulk_wire_budget_valid(config->wire_budget) ||
        config->pace_bps < 0)
        return 0;
    path_count = config->path_count == 0U ? 1U : config->path_count;
    if (!path_count_valid(path_count))
        return 0;
    minimum_rate = (int64_t)config->wire_budget * INT64_C(2);
    if (config->pace_bps > 0 && config->pace_bps < minimum_rate)
        return 0;
    if (config->stall_ms != 0 &&
        (config->stall_ms < BULK_ENGINE_STALL_MIN_MS ||
         config->stall_ms > BULK_ENGINE_STALL_MAX_MS))
        return 0;
    if (config->endpoint == BULK_ENGINE_ENDPOINT_CLIENT) {
        if ((config->operation != BULK_OPERATION_PUT &&
             config->operation != BULK_OPERATION_GET) ||
            config->transfer_id == 0 || config->local_path == NULL ||
            config->remote_path == NULL || config->local_path_length == 0 ||
            config->remote_path_length == 0 ||
            config->local_path_length > BULK_PATH_MAX ||
            config->remote_path_length >
                bulk_request_path_limit(config->wire_budget))
            return 0;
        if (config->path_policy != NULL || config->path_policy_arg != NULL)
            return 0;
    } else if (config->path_policy == NULL &&
               config->path_policy_arg != NULL) {
        return 0;
    }
    return 1;
}

int bulk_engine_activate(bulk_engine_t *engine,
                         const bulk_engine_config_t *config,
                         int64_t now_ms)
{
    uint8_t validation[BULK_REQUEST_PLAINTEXT_MAX];
    size_t validation_length = 0;
    int result;

    if (engine == NULL || engine->active || !config_valid(config) ||
        !clock_value_valid(now_ms))
        return BULK_RC_ARGUMENT;
    engine->endpoint = (uint8_t)config->endpoint;
    engine->operation = (uint8_t)config->operation;
    engine->wire_budget = config->wire_budget;
    engine->pace_bps = config->pace_bps;
    engine->stall_ms = config->stall_ms == 0 ?
                       BULK_ENGINE_STALL_DEFAULT_MS : config->stall_ms;
    engine->force = config->force ? 1U : 0U;
    engine->path_policy = config->path_policy;
    engine->path_policy_arg = config->path_policy_arg;
    engine->now_ms = now_ms;
    engine->next_attempt_id = 1U;
    engine->scan_next_report = BULK_ENGINE_SCAN_QUANTUM;
    result = bulk_geometry_from_budget(engine->wire_budget,
                                       &engine->manifest.chunk_log2,
                                       &engine->chunk_size);
    if (result != BULK_RC_OK)
        return result;
    if (allocate_fixed_state(engine) != BULK_RC_OK) {
        release_fixed_state(engine);
        return BULK_RC_RESOURCE;
    }
    engine->paths->path_count = config->path_count == 0U ?
                                1U : config->path_count;
    engine->paths->primary_leg = 0U;
    engine->paths->set_reroll_trigger_leg = BULK_ENGINE_NO_LEG;
    engine->paths->d32_eligible_mask = UINT32_C(1);
    engine->paths->mtu_usable_mask =
        path_low_mask(engine->paths->path_count);
    engine->paths->eligible_mask = UINT32_C(1);
    if (engine->paths->path_count == 1U)
        engine->paths->generation[0] = UINT64_C(1);
    engine->active = 1;
    /* bulk-retry: activation is the first bounded application state.  In
     * particular, a server whose requester dies before REQUEST must not
     * outlive the operator-selected bulk deadline. */
    start_clock(engine, now_ms);

    if (config->endpoint == BULK_ENGINE_ENDPOINT_SERVER)
        return BULK_RC_OK;

    if (copy_path(engine->local_path, &engine->local_path_length,
                  config->local_path, config->local_path_length) !=
        BULK_RC_OK) {
        release_fixed_state(engine);
        engine->active = 0;
        return BULK_RC_ARGUMENT;
    }
    memset(&engine->request, 0, sizeof(engine->request));
    engine->request.operation = (uint8_t)config->operation;
    engine->request.flags = engine->force ? BULK_REQUEST_FORCE : 0U;
    engine->request.transfer_id = config->transfer_id;
    engine->request.wire_budget = config->wire_budget;
    engine->request.path_length = (uint16_t)config->remote_path_length;
    memcpy(engine->request.path, config->remote_path,
           config->remote_path_length);
    if (bulk_request_encode(&engine->request, validation,
                            sizeof(validation), &validation_length) !=
        BULK_RC_OK) {
        release_fixed_state(engine);
        engine->active = 0;
        return BULK_RC_ARGUMENT;
    }
    (void)validation_length;
    engine->transfer_id = config->transfer_id;
    engine->request_bound = 1;
    engine->is_source = config->operation == BULK_OPERATION_PUT ? 1U : 0U;
    if (engine->is_source) {
        result = source_begin(engine, now_ms);
        if (result != BULK_RC_OK) {
            release_fixed_state(engine);
            engine->active = 0;
            return result;
        }
        /* bulk-retry binds the remote receiver before a potentially long source
         * hash.  PUT REQUEST contains no root and is safe to repeat; once its
         * local send completes, absolute PREPARING progress keeps the bound
         * receiver live.  A reordered PREPARING remains NOT_READY until a
         * REQUEST actually reaches that peer. */
        engine->request_due = 1;
        engine->request_next_ms = now_ms;
    } else {
        engine->request_due = 1;
        engine->request_next_ms = now_ms;
    }
    return BULK_RC_OK;
}

void bulk_engine_destroy(bulk_engine_t *engine)
{
    if (engine == NULL)
        return;
    release_fixed_state(engine);
    memset(engine, 0, sizeof(*engine));
    free(engine);
}

static int status_uses_manifest(uint8_t phase)
{
    return phase != BULK_PHASE_PREPARING &&
           phase != BULK_PHASE_REFUSED;
}

static int set_local_status(bulk_engine_t *engine, uint8_t phase,
                            uint16_t code, uint64_t processed,
                            int64_t now_ms)
{
    bulk_status_t status;
    uint64_t revision;

    if (engine == NULL || engine->transfer_id == 0)
        return BULK_RC_STATE;
    if (engine->local_status_valid &&
        engine->local_status.phase == phase &&
        engine->local_status.code == code &&
        engine->local_status.processed_bytes == processed)
        return BULK_RC_DUPLICATE;
    revision = engine->local_status_valid ?
               engine->local_status.revision + UINT64_C(1) : UINT64_C(1);
    if (revision == 0)
        return BULK_RC_RESOURCE;
    memset(&status, 0, sizeof(status));
    status.phase = phase;
    status.code = code;
    status.revision = revision;
    status.transfer_id = engine->transfer_id;
    if (phase == BULK_PHASE_PREPARING) {
        status.file_size = engine->manifest.file_size;
        status.processed_bytes = processed;
    } else if (phase == BULK_PHASE_REFUSED ||
               (phase == BULK_PHASE_FAILED && !engine->manifest_bound &&
                !engine->allocation_acked)) {
        status.file_size = 0;
        status.processed_bytes = 0;
    } else {
        if (!engine->root_ready && !engine->manifest_bound)
            return BULK_RC_STATE;
        memcpy(status.root, engine->manifest.root, BULK_ROOT_BYTES);
        status.file_size = engine->manifest.file_size;
        status.processed_bytes = processed;
    }
    if (!status_uses_manifest(phase) && phase != BULK_PHASE_PREPARING)
        memset(status.root, 0, BULK_ROOT_BYTES);
    if (bulk_status_encode(&status, engine->receive_buffer) != BULK_RC_OK)
        return BULK_RC_STATE;
    engine->local_status = status;
    engine->local_status_valid = 1;
    engine->status_due = 1;
    engine->status_next_ms = now_ms;
    return BULK_RC_OK;
}

static void local_fail(bulk_engine_t *engine, bulk_result_code_t code,
                       int64_t now_ms, int publish)
{
    uint8_t phase;

    if (engine == NULL || engine->result != BULK_ENGINE_RESULT_RUNNING ||
        engine->failure_pending)
        return;
    engine->result_code = code;
    engine->failure_pending = 1;
    engine->scan_kind = ENGINE_SCAN_NONE;
    if (!publish || engine->transfer_id == 0 ||
        (!engine->request_completed && engine->endpoint ==
         BULK_ENGINE_ENDPOINT_CLIENT)) {
        engine->result = BULK_ENGINE_RESULT_FAILED;
        return;
    }
    phase = (engine->manifest_bound || engine->allocation_acked) ?
            BULK_PHASE_FAILED : BULK_PHASE_REFUSED;
    if (set_local_status(engine, phase, (uint16_t)code, 0, now_ms) !=
        BULK_RC_OK) {
        engine->result = BULK_ENGINE_RESULT_FAILED;
    } else {
        /* Publishing terminal state exposes the first STATUS attempt to the
         * scheduler.  Start the finite linger here: an epoch/path barrier,
         * an already-retained frame, or a transport that never accepts the
         * record must not leave the engine without a deadline. */
        start_error_linger(engine, now_ms);
    }
}

static bulk_result_code_t map_source_error(int result)
{
    if (result == BULK_RC_SOURCE_CHANGED)
        return BULK_CODE_SOURCE_CHANGED;
    if (result == BULK_RC_RESOURCE)
        return BULK_CODE_QUOTA_SIZE;
    return BULK_CODE_SOURCE_OPEN;
}

static bulk_result_code_t map_sink_error(int result)
{
    if (result == BULK_RC_EXISTS)
        return BULK_CODE_EXISTS;
    if (result == BULK_RC_ROOT_MISMATCH)
        return BULK_CODE_ROOT_MISMATCH;
    if (result == BULK_RC_RESOURCE)
        return BULK_CODE_QUOTA_SIZE;
    return BULK_CODE_DESTINATION;
}

static int source_begin(bulk_engine_t *engine, int64_t now_ms)
{
    int result;

    if (engine == NULL || engine->source.fd >= 0 ||
        engine->transfer_id == 0)
        return BULK_RC_STATE;
    result = bulk_source_open(&engine->source,
                              (const char *)engine->local_path,
                              engine->manifest.chunk_log2);
    if (result != BULK_RC_OK)
        return result;
    memset(&engine->manifest, 0, sizeof(engine->manifest));
    engine->manifest.transfer_id = engine->transfer_id;
    engine->manifest.file_size = engine->source.identity.size;
    engine->manifest.chunk_log2 = engine->source.chunk_log2;
    engine->manifest.chunk_count = engine->source.chunk_count;
    engine->manifest.wire_budget = engine->wire_budget;
    /* A nonzero private sentinel permits the source read helper to validate
     * immutable geometry while the real root is still being computed.  It is
     * never encoded or exposed as MANIFEST state. */
    engine->manifest.root[0] = 1U;
    result = bulk_merkle_init(&engine->merkle, engine->transfer_id,
                              engine->manifest.file_size,
                              engine->manifest.chunk_log2,
                              engine->manifest.chunk_count);
    if (result != BULK_RC_OK)
        return result;
    engine->scan_kind = ENGINE_SCAN_SOURCE;
    engine->scan_index = 0;
    engine->scan_processed = 0;
    engine->scan_next_report = BULK_ENGINE_SCAN_QUANTUM;
    engine->scan_last_report_ms = now_ms;
    engine->scan_status_enabled =
        engine->endpoint == BULK_ENGINE_ENDPOINT_SERVER ? 1U : 0U;
    if (engine->scan_status_enabled &&
        set_local_status(engine, BULK_PHASE_PREPARING, BULK_CODE_NONE, 0,
                         now_ms) != BULK_RC_OK)
        return BULK_RC_STATE;
    return BULK_RC_OK;
}

static int source_scan_step(bulk_engine_t *engine, int64_t now_ms)
{
    size_t body_length = 0;
    int result;

    if (engine->merkle.ready) {
        uint8_t root[BULK_ROOT_BYTES];
        result = bulk_merkle_root(&engine->merkle, root);
        if (result != BULK_RC_OK)
            return result;
        memcpy(engine->manifest.root, root, BULK_ROOT_BYTES);
        engine->root_ready = 1;
        result = bulk_ack_state_init(&engine->ack_state,
                                     engine->bitmap_storage,
                                     BULK_BITMAP_BYTES, &engine->manifest);
        if (result != BULK_RC_OK)
            return result;
        engine->scan_kind = ENGINE_SCAN_NONE;
        engine->manifest_due = 1;
        engine->manifest_next_ms = now_ms;
        if (engine->endpoint == BULK_ENGINE_ENDPOINT_CLIENT &&
            engine->operation == BULK_OPERATION_PUT) {
            engine->request_due = 1;
            engine->request_next_ms = now_ms;
        }
        if (engine->scan_status_enabled)
            (void)set_local_status(engine, BULK_PHASE_PREPARING,
                                   BULK_CODE_NONE,
                                   engine->manifest.file_size, now_ms);
        /* MANIFEST is the absolute successor to source scanning.  Retain the
         * PREPARING revision for lineage validation, but do not keep emitting
         * a completed scan beside the immutable MANIFEST. */
        if (engine->scan_status_enabled)
            engine->status_due = 0;
        return BULK_RC_OK;
    }
    if (engine->merkle.next_index < engine->manifest.chunk_count) {
        result = bulk_source_read_chunk(&engine->source, &engine->manifest,
                                        engine->merkle.next_index,
                                        engine->chunk_buffer, BULK_CHUNK_MAX,
                                        &body_length);
        if (result != BULK_RC_OK)
            return result;
        result = bulk_merkle_push_chunk(&engine->merkle,
                                        engine->chunk_buffer, body_length);
        if (result != BULK_RC_OK && result != BULK_RC_MORE)
            return result;
        engine->scan_index = engine->merkle.next_index;
        engine->scan_processed += body_length;
        if (engine->clock_started)
            note_progress(engine, now_ms);
        if (engine->scan_status_enabled &&
            (engine->scan_processed >= engine->scan_next_report ||
             (now_ms - engine->scan_last_report_ms >=
                  BULK_ENGINE_SCAN_REPORT_MS &&
              engine->scan_processed >
                  engine->local_status.processed_bytes))) {
            (void)set_local_status(engine, BULK_PHASE_PREPARING,
                                   BULK_CODE_NONE,
                                   engine->scan_processed, now_ms);
            while (engine->scan_next_report <= engine->scan_processed)
                engine->scan_next_report += BULK_ENGINE_SCAN_QUANTUM;
            engine->scan_last_report_ms = now_ms;
        }
        return BULK_RC_MORE;
    }
    result = bulk_merkle_push_pad(&engine->merkle);
    if (result != BULK_RC_OK && result != BULK_RC_MORE)
        return result;
    return BULK_RC_MORE;
}

static int start_verification(bulk_engine_t *engine, int64_t now_ms)
{
    int result;

    if (engine->scan_kind == ENGINE_SCAN_VERIFY || engine->installed)
        return BULK_RC_DUPLICATE;
    result = bulk_merkle_init(&engine->merkle, engine->manifest.transfer_id,
                              engine->manifest.file_size,
                              engine->manifest.chunk_log2,
                              engine->manifest.chunk_count);
    if (result != BULK_RC_OK)
        return result;
    engine->scan_kind = ENGINE_SCAN_VERIFY;
    engine->scan_index = 0;
    engine->scan_processed = 0;
    engine->scan_next_report = BULK_ENGINE_SCAN_QUANTUM;
    engine->scan_last_report_ms = now_ms;
    if (engine->manifest.chunk_count != 0)
        return set_local_status(engine, BULK_PHASE_VERIFYING,
                                BULK_CODE_NONE, 0, now_ms);
    return BULK_RC_OK;
}

static int verify_scan_step(bulk_engine_t *engine, int64_t now_ms)
{
    size_t body_length = 0;
    int result;

    if (engine->merkle.ready) {
        uint8_t root[BULK_ROOT_BYTES];
        result = bulk_merkle_root(&engine->merkle, root);
        if (result != BULK_RC_OK)
            return result;
        result = bulk_sink_install(&engine->sink, &engine->ack_state.bitmap,
                                   &engine->manifest, engine->force, root);
        if (result != BULK_RC_OK)
            return result;
        engine->installed = 1;
        engine->scan_kind = ENGINE_SCAN_NONE;
        note_progress(engine, now_ms);
        return set_local_status(engine, BULK_PHASE_INSTALLED,
                                BULK_CODE_NONE, 0, now_ms);
    }
    if (engine->merkle.next_index < engine->manifest.chunk_count) {
        result = bulk_sink_read_chunk(&engine->sink, &engine->manifest,
                                      engine->merkle.next_index,
                                      engine->chunk_buffer, BULK_CHUNK_MAX,
                                      &body_length);
        if (result != BULK_RC_OK)
            return result;
        result = bulk_merkle_push_chunk(&engine->merkle,
                                        engine->chunk_buffer, body_length);
        if (result != BULK_RC_OK && result != BULK_RC_MORE)
            return result;
        engine->scan_index = engine->merkle.next_index;
        engine->scan_processed += body_length;
        note_progress(engine, now_ms);
        if (engine->scan_processed >= engine->scan_next_report ||
            (now_ms - engine->scan_last_report_ms >=
                 BULK_ENGINE_SCAN_REPORT_MS &&
             engine->scan_processed > engine->local_status.processed_bytes)) {
            (void)set_local_status(engine, BULK_PHASE_VERIFYING,
                                   BULK_CODE_NONE,
                                   engine->scan_processed, now_ms);
            while (engine->scan_next_report <= engine->scan_processed)
                engine->scan_next_report += BULK_ENGINE_SCAN_QUANTUM;
            engine->scan_last_report_ms = now_ms;
        }
        return BULK_RC_MORE;
    }
    result = bulk_merkle_push_pad(&engine->merkle);
    if (result != BULK_RC_OK && result != BULK_RC_MORE)
        return result;
    return BULK_RC_MORE;
}

static int receiver_bind_manifest(bulk_engine_t *engine,
                                  const bulk_manifest_t *manifest,
                                  int64_t now_ms)
{
    const uint8_t *destination;
    size_t destination_length;
    int result;

    if (bulk_manifest_validate_request(manifest, &engine->request) !=
        BULK_RC_OK)
        return BULK_RC_MALFORMED;
    if (engine->endpoint == BULK_ENGINE_ENDPOINT_CLIENT) {
        destination = engine->local_path;
        destination_length = engine->local_path_length;
    } else {
        destination = engine->request.path;
        destination_length = engine->request.path_length;
    }
    result = bulk_sink_prepare(&engine->sink, destination,
                               destination_length, manifest->file_size,
                               (char *)engine->path_scratch);
    if (result != BULK_RC_OK)
        return result;
    engine->manifest = *manifest;
    engine->root_ready = 1;
    result = bulk_ack_state_init(&engine->ack_state,
                                 engine->bitmap_storage,
                                 BULK_BITMAP_BYTES, &engine->manifest);
    if (result != BULK_RC_OK)
        return result;
    engine->manifest_bound = 1;
    dirty_mark(engine, 0);
    engine->ack_next_ms = now_ms;
    note_progress(engine, now_ms);
    if (engine->manifest.chunk_count == 0)
        return start_verification(engine, now_ms);
    return BULK_RC_OK;
}

static int phase_is_error(uint8_t phase)
{
    return phase == BULK_PHASE_REFUSED || phase == BULK_PHASE_FAILED;
}

static int status_is_repeatable(const bulk_engine_t *engine)
{
    if (!engine->local_status_valid)
        return 0;
    if (engine->local_status.phase == BULK_PHASE_PREPARING &&
        engine->root_ready)
        return 0;
    return 1;
}

static void finish_failed(bulk_engine_t *engine, bulk_result_code_t code)
{
    int cleanup_result;
    int close_result;

    if (engine == NULL || engine->result != BULK_ENGINE_RESULT_RUNNING)
        return;
    cleanup_result = bulk_sink_cleanup(&engine->sink);
    close_result = bulk_source_close(&engine->source);
    if (cleanup_result != BULK_RC_OK || close_result != BULK_RC_OK)
        code = BULK_CODE_IO;
    engine->result_code = code;
    engine->result = BULK_ENGINE_RESULT_FAILED;
    engine->scan_kind = ENGINE_SCAN_NONE;
    engine->tx.active = 0;
    engine->send_retry_deadline_ms = 0;
    engine->send_retry_delay_ms = 0;
}

static void finish_success(bulk_engine_t *engine)
{
    int cleanup_result;
    int close_result;

    if (engine == NULL || engine->result != BULK_ENGINE_RESULT_RUNNING)
        return;
    cleanup_result = bulk_sink_cleanup(&engine->sink);
    close_result = bulk_source_close(&engine->source);
    if (cleanup_result != BULK_RC_OK || close_result != BULK_RC_OK) {
        engine->result_code = BULK_CODE_IO;
        engine->result = BULK_ENGINE_RESULT_FAILED;
    } else {
        engine->result_code = BULK_CODE_NONE;
        engine->result = BULK_ENGINE_RESULT_SUCCESS;
    }
    engine->scan_kind = ENGINE_SCAN_NONE;
    engine->tx.active = 0;
    engine->send_retry_deadline_ms = 0;
    engine->send_retry_delay_ms = 0;
}

static bulk_engine_receive_result_t protocol_fail(bulk_engine_t *engine,
                                                  int64_t now_ms)
{
    local_fail(engine, BULK_CODE_PROTOCOL, now_ms, 1);
    return BULK_ENGINE_RX_FATAL;
}

static void reassert_local_status(bulk_engine_t *engine, int64_t now_ms)
{
    if (status_is_repeatable(engine)) {
        engine->status_due = 1;
        engine->status_next_ms = now_ms;
    }
}

static void reassert_after_request(bulk_engine_t *engine, int64_t now_ms)
{
    if (engine->failure_pending) {
        reassert_local_status(engine, now_ms);
        return;
    }
    if (engine->is_source) {
        if (engine->root_ready && !engine->allocation_acked) {
            engine->manifest_due = 1;
            engine->manifest_next_ms = now_ms;
        } else if (engine->scan_kind == ENGINE_SCAN_SOURCE) {
            reassert_local_status(engine, now_ms);
        } else {
            reassert_local_status(engine, now_ms);
        }
    } else if (engine->manifest_bound) {
        dirty_mark(engine, 0);
        engine->ack_next_ms = now_ms;
        reassert_local_status(engine, now_ms);
    }
}

static int apply_request_path_policy(bulk_engine_t *engine)
{
    int result;

    if (engine == NULL || !engine->request_bound ||
        engine->endpoint != BULK_ENGINE_ENDPOINT_SERVER)
        return BULK_RC_STATE;
    if (engine->path_policy == NULL)
        return BULK_RC_OK;
    if (engine->path_policy_called)
        return BULK_RC_STATE;
    engine->path_policy_called = 1U;
    result = engine->path_policy(engine->path_policy_arg,
                                 (bulk_operation_t)engine->operation,
                                 engine->request.path,
                                 engine->request.path_length);
    return result == BULK_RC_OK ? BULK_RC_OK : BULK_RC_IO;
}

static bulk_engine_receive_result_t receive_request(
    bulk_engine_t *engine, const uint8_t *plaintext, size_t plaintext_length,
    int64_t now_ms)
{
    bulk_request_t request;
    uint8_t geometry_log2;
    uint16_t geometry_size;
    int result;

    if (bulk_request_decode(plaintext, plaintext_length, &request) !=
        BULK_RC_OK)
        return protocol_fail(engine, now_ms);
    if (engine->endpoint != BULK_ENGINE_ENDPOINT_SERVER)
        return protocol_fail(engine, now_ms);

    if (engine->request_bound) {
        if (request.transfer_id != engine->transfer_id) {
            memset(&engine->busy_status, 0, sizeof(engine->busy_status));
            engine->busy_status.phase = BULK_PHASE_REFUSED;
            engine->busy_status.code = BULK_CODE_BUSY;
            engine->busy_status.revision = 1;
            engine->busy_status.transfer_id = request.transfer_id;
            engine->busy_status_valid = 1;
            return BULK_ENGINE_RX_OK;
        }
        if (!request_equal(&request, &engine->request))
            return protocol_fail(engine, now_ms);
        reassert_after_request(engine, now_ms);
        return BULK_ENGINE_RX_DUPLICATE;
    }

    engine->request = request;
    engine->request_bound = 1;
    engine->request_completed = 1;
    engine->transfer_id = request.transfer_id;
    engine->operation = request.operation;
    engine->force = (request.flags & BULK_REQUEST_FORCE) != 0 ? 1U : 0U;
    engine->is_source = request.operation == BULK_OPERATION_GET ? 1U : 0U;
    start_clock(engine, now_ms);

    if (request.wire_budget != engine->wire_budget ||
        bulk_geometry_from_budget(request.wire_budget, &geometry_log2,
                                  &geometry_size) != BULK_RC_OK) {
        local_fail(engine, BULK_CODE_UNSUPPORTED_MTU, now_ms, 1);
        return BULK_ENGINE_RX_PROGRESS;
    }
    (void)geometry_size;
    engine->manifest.chunk_log2 = geometry_log2;
    result = apply_request_path_policy(engine);
    if (result != BULK_RC_OK) {
        local_fail(engine,
                   engine->is_source ? BULK_CODE_SOURCE_OPEN
                                     : BULK_CODE_DESTINATION,
                   now_ms, 1);
        return BULK_ENGINE_RX_PROGRESS;
    }
    if (!engine->is_source)
        return BULK_ENGINE_RX_PROGRESS;

    result = copy_path(engine->local_path, &engine->local_path_length,
                       request.path, request.path_length);
    if (result == BULK_RC_OK)
        result = source_begin(engine, now_ms);
    if (result != BULK_RC_OK) {
        local_fail(engine, map_source_error(result), now_ms, 1);
        return BULK_ENGINE_RX_PROGRESS;
    }
    return BULK_ENGINE_RX_PROGRESS;
}

static bulk_engine_receive_result_t receive_manifest(
    bulk_engine_t *engine, const uint8_t *plaintext, size_t plaintext_length,
    int64_t now_ms)
{
    bulk_manifest_t manifest;
    int result;

    if (bulk_manifest_decode(plaintext, plaintext_length, &manifest) !=
        BULK_RC_OK)
        return protocol_fail(engine, now_ms);
    if (engine->endpoint == BULK_ENGINE_ENDPOINT_SERVER &&
        !engine->request_bound)
        return BULK_ENGINE_RX_NOT_READY;
    if (!engine->request_bound || engine->is_source ||
        manifest.transfer_id != engine->transfer_id)
        return protocol_fail(engine, now_ms);
    if (engine->manifest_bound) {
        if (!manifest_equal(&manifest, &engine->manifest))
            return protocol_fail(engine, now_ms);
        dirty_mark(engine, 0);
        engine->ack_next_ms = now_ms;
        reassert_local_status(engine, now_ms);
        return BULK_ENGINE_RX_DUPLICATE;
    }
    if (bulk_manifest_validate_request(&manifest, &engine->request) !=
        BULK_RC_OK)
        return protocol_fail(engine, now_ms);
    if (engine->peer_status_valid &&
        engine->peer_status.phase == BULK_PHASE_PREPARING &&
        engine->peer_status.file_size != manifest.file_size)
        return protocol_fail(engine, now_ms);

    result = receiver_bind_manifest(engine, &manifest, now_ms);
    if (result != BULK_RC_OK) {
        local_fail(engine, map_sink_error(result), now_ms, 1);
        return BULK_ENGINE_RX_PROGRESS;
    }
    if (engine->endpoint == BULK_ENGINE_ENDPOINT_CLIENT &&
        engine->operation == BULK_OPERATION_GET)
        engine->request_due = 0;
    return BULK_ENGINE_RX_PROGRESS;
}

static bulk_engine_receive_result_t receive_data(
    bulk_engine_t *engine, const uint8_t *plaintext, size_t plaintext_length,
    int64_t now_ms)
{
    bulk_data_view_t data;
    size_t retained_length = 0;
    int newly_admitted = 0;
    int result;

    if (bulk_data_decode(plaintext, plaintext_length, &data) != BULK_RC_OK)
        return protocol_fail(engine, now_ms);
    if (engine->is_source || !engine->manifest_bound ||
        bulk_data_validate(&data, &engine->manifest,
                           engine->paths->path_count) != BULK_RC_OK)
        return protocol_fail(engine, now_ms);

    if (engine->installed) {
        result = bulk_sink_read_chunk(&engine->sink, &engine->manifest,
                                      data.chunk_index,
                                      engine->chunk_buffer, BULK_CHUNK_MAX,
                                      &retained_length);
        if (result != BULK_RC_OK) {
            local_fail(engine, BULK_CODE_IO, now_ms, 1);
            return BULK_ENGINE_RX_PROGRESS;
        }
        if (retained_length != data.body_length ||
            memcmp(engine->chunk_buffer, data.body, retained_length) != 0)
            return protocol_fail(engine, now_ms);
        dirty_mark(engine, data.chunk_index / BULK_ACK_PAGE_BITS);
        engine->ack_next_ms = now_ms;
        engine->stats->duplicate_chunks++;
        return BULK_ENGINE_RX_DUPLICATE;
    }

    result = bulk_sink_admit_chunk(&engine->sink,
                                   &engine->ack_state.bitmap,
                                   &engine->manifest, data.chunk_index,
                                   data.body, data.body_length,
                                   engine->chunk_buffer, &newly_admitted);
    if (result == BULK_RC_DIVERGED)
        return protocol_fail(engine, now_ms);
    if (result != BULK_RC_OK && result != BULK_RC_DUPLICATE) {
        local_fail(engine, BULK_CODE_IO, now_ms, 1);
        return BULK_ENGINE_RX_PROGRESS;
    }
    dirty_mark(engine, data.chunk_index / BULK_ACK_PAGE_BITS);
    engine->ack_next_ms = now_ms;
    if (!newly_admitted) {
        engine->stats->duplicate_chunks++;
        return BULK_ENGINE_RX_DUPLICATE;
    }

    engine->ack_state.counters[data.sender_leg].chunks++;
    engine->ack_state.counters[data.sender_leg].bytes += data.body_length;
    engine->stats->leg[data.sender_leg].acked_chunks =
        engine->ack_state.counters[data.sender_leg].chunks;
    engine->stats->leg[data.sender_leg].acked_bytes =
        engine->ack_state.counters[data.sender_leg].bytes;
    engine->stats->first_admission_chunks++;
    engine->stats->first_admission_bytes += data.body_length;
    note_progress(engine, now_ms);
    if (engine->ack_state.bitmap.frontier == engine->manifest.chunk_count) {
        result = start_verification(engine, now_ms);
        if (result != BULK_RC_OK && result != BULK_RC_DUPLICATE) {
            local_fail(engine, map_sink_error(result), now_ms, 1);
            return BULK_ENGINE_RX_PROGRESS;
        }
    }
    return BULK_ENGINE_RX_PROGRESS;
}

static bulk_engine_receive_result_t receive_ack(
    bulk_engine_t *engine, const uint8_t *plaintext, size_t plaintext_length,
    int64_t now_ms)
{
    bulk_ack_t ack;
    uint64_t old_chunks[BULK_LEGS_MAX];
    uint32_t advancing_mask = 0U;
    int first_allocation;
    int result;
    unsigned int leg;

    if (bulk_ack_decode(plaintext, plaintext_length, &ack) != BULK_RC_OK)
        return protocol_fail(engine, now_ms);
    if (!engine->is_source || !engine->root_ready ||
        ack.transfer_id != engine->transfer_id ||
        bulk_ack_validate(&ack, &engine->manifest,
                          engine->paths->path_count) != BULK_RC_OK)
        return protocol_fail(engine, now_ms);
    for (leg = 0U; leg < engine->paths->path_count; leg++) {
        if ((uint64_t)ack.counters[leg].chunks >
                engine->stats->leg[leg].sent_chunks ||
            ack.counters[leg].bytes >
                engine->stats->leg[leg].sent_bytes)
            return protocol_fail(engine, now_ms);
        old_chunks[leg] = engine->ack_state.counters[leg].chunks;
    }
    result = bulk_ack_merge(&engine->ack_state, &ack, &engine->manifest,
                            engine->paths->path_count);
    if (result != BULK_RC_PROGRESS && result != BULK_RC_DUPLICATE &&
        result != BULK_RC_STALE)
        return protocol_fail(engine, now_ms);

    first_allocation = !engine->allocation_acked;
    engine->allocation_acked = 1;
    engine->manifest_due = 0;
    if (engine->endpoint == BULK_ENGINE_ENDPOINT_CLIENT &&
        engine->operation == BULK_OPERATION_PUT)
        engine->request_due = 0;
    for (leg = 0U; leg < engine->paths->path_count; leg++) {
        engine->stats->leg[leg].acked_chunks =
            engine->ack_state.counters[leg].chunks;
        engine->stats->leg[leg].acked_bytes =
            engine->ack_state.counters[leg].bytes;
        if (engine->ack_state.counters[leg].chunks > old_chunks[leg])
            advancing_mask |= UINT32_C(1) << leg;
    }
    recovery_scan_reset(engine);
    if (release_acked_attempts(engine) != BULK_RC_OK)
        return protocol_fail(engine, now_ms);
    /* Only a push-side client owns sockets that these source-slot due bits
     * can replace. Pull keeps its existing exhaust/no-rebind path unchanged.
     * Process the complete advancing mask in two phases: recovered slots clear
     * their own unclaimed due state first, then every remaining due slot may
     * be witnessed by a different source slot. This preserves call order even
     * when the ACK and due edge share the same millisecond. */
    if (engine->endpoint == BULK_ENGINE_ENDPOINT_CLIENT &&
        engine->operation == BULK_OPERATION_PUT && advancing_mask != 0U) {
        uint32_t recovered = advancing_mask &
                             engine->paths->reroll_due_mask &
                             ~engine->paths->reroll_claimed_mask;

        if (engine->paths->set_reroll_claimed &&
            engine->paths->set_reroll_trigger_leg <
                engine->paths->path_count)
            recovered &= ~(UINT32_C(1) <<
                           engine->paths->set_reroll_trigger_leg);
        for (leg = 0U; leg < engine->paths->path_count; leg++) {
            uint32_t bit = UINT32_C(1) << leg;

            if ((recovered & bit) == 0U)
                continue;
            engine->paths->reroll_due_mask &= ~bit;
            engine->paths->no_progress_at_min[leg] = 0U;
            engine->paths->reroll_defer_ms[leg] = 0;
            engine->paths->reroll_witness_deadline_ms[leg] = 0;
        }
        for (leg = 0U; leg < engine->paths->path_count; leg++) {
            uint32_t bit = UINT32_C(1) << leg;

            if ((engine->paths->reroll_due_mask & bit) != 0U &&
                (advancing_mask & ~bit) != 0U &&
                (engine->paths->reroll_witness_deadline_ms[leg] == 0 ||
                 now_ms >
                     engine->paths->reroll_witness_deadline_ms[leg]))
                engine->paths->reroll_witness_deadline_ms[leg] =
                    now_ms + BULK_ENGINE_REROLL_WITNESS_MS;
        }
    }
    if (first_allocation || result == BULK_RC_PROGRESS)
        note_progress(engine, now_ms);
    if (first_allocation || result == BULK_RC_PROGRESS)
        return BULK_ENGINE_RX_PROGRESS;
    return result == BULK_RC_STALE ? BULK_ENGINE_RX_STALE :
                                     BULK_ENGINE_RX_DUPLICATE;
}

static int status_rank(int peer_is_source, uint8_t phase)
{
    if (peer_is_source) {
        if (phase == BULK_PHASE_PREPARING)
            return 1;
        if (phase == BULK_PHASE_DONE)
            return 2;
        if (phase == BULK_PHASE_DONE_CONFIRM)
            return 3;
    } else {
        if (phase == BULK_PHASE_VERIFYING)
            return 1;
        if (phase == BULK_PHASE_INSTALLED)
            return 2;
        if (phase == BULK_PHASE_DONE_ACK)
            return 3;
    }
    return 0;
}

static int status_identity_valid(const bulk_engine_t *engine,
                                 const bulk_status_t *status)
{
    int manifest_known;

    if (!engine->request_bound || status->transfer_id != engine->transfer_id)
        return 0;
    manifest_known = engine->is_source ? engine->root_ready :
                                        engine->manifest_bound;
    if (status->phase == BULK_PHASE_PREPARING) {
        return !manifest_known && bytes_zero(status->root, BULK_ROOT_BYTES);
    }
    if (status->phase == BULK_PHASE_REFUSED) {
        return !engine->manifest_bound && !engine->allocation_acked &&
               status->file_size == 0 &&
               bytes_zero(status->root, BULK_ROOT_BYTES);
    }
    if (!manifest_known)
        return 0;
    return status->file_size == engine->manifest.file_size &&
           root_equal(status->root, engine->manifest.root);
}

static int status_historical_identity_valid(const bulk_engine_t *engine,
                                            const bulk_status_t *status)
{
    int peer_is_source;
    int manifest_known;

    if (!engine->request_bound || status->transfer_id != engine->transfer_id)
        return 0;
    peer_is_source = !engine->is_source;
    if (!phase_is_error(status->phase) &&
        status_rank(peer_is_source, status->phase) == 0)
        return 0;
    manifest_known = engine->is_source ? engine->root_ready :
                                        engine->manifest_bound;
    if (status->phase == BULK_PHASE_PREPARING) {
        if (!peer_is_source ||
            !bytes_zero(status->root, BULK_ROOT_BYTES))
            return 0;
        if (manifest_known &&
            status->file_size != engine->manifest.file_size)
            return 0;
        return 1;
    }
    if (status->phase == BULK_PHASE_REFUSED)
        return status->file_size == 0 &&
               bytes_zero(status->root, BULK_ROOT_BYTES);
    return manifest_known &&
           status->file_size == engine->manifest.file_size &&
           root_equal(status->root, engine->manifest.root);
}

static int peer_status_transition_valid(const bulk_engine_t *engine,
                                        const bulk_status_t *status)
{
    int peer_is_source = !engine->is_source;
    int next_rank;
    int old_rank;

    if (engine->peer_status_valid &&
        status->revision <= engine->peer_status.revision) {
        if (!status_historical_identity_valid(engine, status))
            return 0;
        if (status->revision < engine->peer_status.revision)
            return 1;
        return status_equal(status, &engine->peer_status);
    }
    if (!status_identity_valid(engine, status) ||
        (!phase_is_error(status->phase) &&
         status_rank(peer_is_source, status->phase) == 0))
        return 0;
    if (status->phase == BULK_PHASE_REFUSED &&
        (engine->manifest_bound || engine->allocation_acked))
        return 0;
    if (status->phase == BULK_PHASE_FAILED &&
        !engine->manifest_bound && !engine->allocation_acked)
        return 0;

    if (!engine->peer_status_valid) {
        next_rank = status_rank(peer_is_source, status->phase);
        if (phase_is_error(status->phase))
            return 1;
        return next_rank == 1 || next_rank == 2;
    }
    if (phase_is_error(engine->peer_status.phase))
        return 0;
    if (phase_is_error(status->phase))
        return 1;
    old_rank = status_rank(peer_is_source, engine->peer_status.phase);
    next_rank = status_rank(peer_is_source, status->phase);
    if (old_rank == 0 || next_rank == 0)
        return 0;
    if (old_rank == next_rank) {
        return (status->phase == BULK_PHASE_PREPARING ||
                status->phase == BULK_PHASE_VERIFYING) &&
               status->file_size == engine->peer_status.file_size &&
               status->processed_bytes >
                   engine->peer_status.processed_bytes;
    }
    return next_rank > old_rank;
}

static int status_local_state_valid(const bulk_engine_t *engine,
                                    const bulk_status_t *status)
{
    if (phase_is_error(status->phase))
        return 1;
    if (engine->is_source) {
        if (status->phase == BULK_PHASE_VERIFYING)
            return engine->root_ready;
        if (status->phase == BULK_PHASE_INSTALLED)
            return engine->root_ready;
        if (status->phase == BULK_PHASE_DONE_ACK)
            return engine->done_sent_complete;
        return 0;
    }
    if (status->phase == BULK_PHASE_PREPARING)
        return !engine->manifest_bound;
    if (status->phase == BULK_PHASE_DONE)
        return engine->installed;
    if (status->phase == BULK_PHASE_DONE_CONFIRM)
        return engine->done_ack_sent_complete;
    return 0;
}

static bulk_engine_receive_result_t receive_status(
    bulk_engine_t *engine, const uint8_t *plaintext, size_t plaintext_length,
    int64_t now_ms)
{
    bulk_status_t status;
    int stale;
    int duplicate;
    int phase_progress;
    int result;

    if (bulk_status_decode(plaintext, plaintext_length, &status) !=
        BULK_RC_OK)
        return protocol_fail(engine, now_ms);
    if (engine->endpoint == BULK_ENGINE_ENDPOINT_SERVER &&
        !engine->request_bound && status.phase == BULK_PHASE_PREPARING)
        return BULK_ENGINE_RX_NOT_READY;
    stale = engine->peer_status_valid &&
            status.revision < engine->peer_status.revision;
    duplicate = engine->peer_status_valid &&
                status.revision == engine->peer_status.revision;
    if (stale || duplicate) {
        if (!peer_status_transition_valid(engine, &status))
            return protocol_fail(engine, now_ms);
        if (stale)
            return BULK_ENGINE_RX_STALE;
        if ((status.phase == BULK_PHASE_INSTALLED && engine->is_source) ||
            (status.phase == BULK_PHASE_DONE && !engine->is_source) ||
            (status.phase == BULK_PHASE_DONE_ACK && engine->is_source))
            reassert_local_status(engine, now_ms);
        return BULK_ENGINE_RX_DUPLICATE;
    }
    /* A canonical source PREPARING (server GET or early client PUT) can be
     * overtaken by MANIFEST even when no earlier scan STATUS survived.  It is
     * historical state, not a root retraction and not authority to reopen
     * pre-manifest state. */
    if (!engine->peer_status_valid && engine->manifest_bound &&
        status.phase == BULK_PHASE_PREPARING) {
        if (!status_historical_identity_valid(engine, &status))
            return protocol_fail(engine, now_ms);
        return BULK_ENGINE_RX_STALE;
    }
    if (!peer_status_transition_valid(engine, &status) ||
        !status_local_state_valid(engine, &status))
        return protocol_fail(engine, now_ms);

    /* A receiver can only publish a root-bound VERIFYING or INSTALLED state
     * after it has accepted the manifest and allocated the destination.  The
     * absolute status therefore closes the allocation handshake when page-0
     * ACK was lost or reordered.  It does not acknowledge any DATA chunk. */
    if (engine->is_source && !engine->allocation_acked &&
        (status.phase == BULK_PHASE_VERIFYING ||
         status.phase == BULK_PHASE_INSTALLED)) {
        engine->allocation_acked = 1U;
        engine->manifest_due = 0U;
        if (engine->endpoint == BULK_ENGINE_ENDPOINT_CLIENT &&
            engine->operation == BULK_OPERATION_PUT)
            engine->request_due = 0U;
        recovery_scan_reset(engine);
    }

    phase_progress = !engine->peer_status_valid ||
                     status.phase != engine->peer_status.phase ||
                     status.processed_bytes >
                         engine->peer_status.processed_bytes;
    engine->peer_status = status;
    engine->peer_status_valid = 1;
    if (phase_progress)
        note_progress(engine, now_ms);

    if (phase_is_error(status.phase)) {
        finish_failed(engine, (bulk_result_code_t)status.code);
        return BULK_ENGINE_RX_PROGRESS;
    }
    if (status.phase == BULK_PHASE_INSTALLED) {
        result = bulk_source_check_unchanged(&engine->source);
        if (result != BULK_RC_OK) {
            local_fail(engine, result == BULK_RC_SOURCE_CHANGED ?
                       BULK_CODE_SOURCE_CHANGED : BULK_CODE_IO, now_ms, 1);
            return BULK_ENGINE_RX_PROGRESS;
        }
        if (set_local_status(engine, BULK_PHASE_DONE, BULK_CODE_NONE, 0,
                             now_ms) < BULK_RC_OK)
            return protocol_fail(engine, now_ms);
    } else if (status.phase == BULK_PHASE_DONE) {
        engine->done_seen = 1;
        if (set_local_status(engine, BULK_PHASE_DONE_ACK, BULK_CODE_NONE, 0,
                             now_ms) < BULK_RC_OK)
            return protocol_fail(engine, now_ms);
    } else if (status.phase == BULK_PHASE_DONE_ACK) {
        if (set_local_status(engine, BULK_PHASE_DONE_CONFIRM,
                             BULK_CODE_NONE, 0, now_ms) < BULK_RC_OK)
            return protocol_fail(engine, now_ms);
    } else if (status.phase == BULK_PHASE_DONE_CONFIRM) {
        finish_success(engine);
    }
    return BULK_ENGINE_RX_PROGRESS;
}

bulk_engine_receive_result_t bulk_engine_receive(
    bulk_engine_t *engine, uint8_t type,
    const uint8_t *plaintext, size_t plaintext_length, int64_t now_ms)
{
    if (engine == NULL || !engine->active || plaintext == NULL ||
        !clock_value_valid(now_ms) || now_ms < engine->now_ms ||
        engine->paused ||
        engine->result != BULK_ENGINE_RESULT_RUNNING)
        return BULK_ENGINE_RX_FATAL;
    engine->now_ms = now_ms;
    switch (type) {
    case BULK_REQUEST:
        return receive_request(engine, plaintext, plaintext_length, now_ms);
    case BULK_MANIFEST:
        return receive_manifest(engine, plaintext, plaintext_length, now_ms);
    case BULK_DATA:
        return receive_data(engine, plaintext, plaintext_length, now_ms);
    case BULK_ACK:
        return receive_ack(engine, plaintext, plaintext_length, now_ms);
    case BULK_STATUS:
        return receive_status(engine, plaintext, plaintext_length, now_ms);
    default:
        return protocol_fail(engine, now_ms);
    }
}

static unsigned int path_count_log2(uint8_t path_count)
{
    unsigned int bits = 0U;

    while ((UINT32_C(1) << bits) < path_count)
        bits++;
    return bits;
}

static unsigned int ctz32_nonzero(uint32_t value)
{
    unsigned int count = 0U;

    while ((value & UINT32_C(1)) == 0U) {
        value >>= 1;
        count++;
    }
    return count;
}

static int select_rotated_leg(uint32_t candidates, uint8_t path_count,
                              uint8_t start, uint8_t *sender_leg)
{
    uint32_t low;
    uint32_t rotated;
    unsigned int offset;

    if (sender_leg == NULL || !path_count_valid(path_count) ||
        start >= path_count)
        return 0;
    low = path_low_mask(path_count);
    candidates &= low;
    if (candidates == 0U)
        return 0;
    if (start == 0U)
        rotated = candidates;
    else
        rotated = ((candidates >> start) |
                   (candidates << (path_count - start))) & low;
    offset = ctz32_nonzero(rotated);
    *sender_leg = (uint8_t)((start + offset) & (path_count - 1U));
    return 1;
}

static uint32_t room_mask(const bulk_engine_t *engine)
{
    uint32_t mask = 0U;
    unsigned int leg;

    for (leg = 0U; leg < engine->paths->path_count; leg++) {
        uint32_t bit = UINT32_C(1) << leg;

        if ((engine->paths->eligible_mask & bit) != 0U &&
            leg_has_room(engine, (uint8_t)leg))
            mask |= bit;
    }
    return mask;
}

static int select_new_leg(const bulk_engine_t *engine,
                          uint32_t chunk_index, uint8_t *sender_leg)
{
    uint8_t path_count = engine->paths->path_count;
    uint8_t base = (uint8_t)(chunk_index & (path_count - 1U));
    uint8_t shift = engine->paths->share_shift[base];
    uint32_t candidates = room_mask(engine);
    uint32_t base_bit = UINT32_C(1) << base;
    unsigned int stripe_ordinal =
        chunk_index >> path_count_log2(path_count);
    int base_keeps_share = shift == 0U ||
        (stripe_ordinal & ((UINT32_C(1) << shift) - UINT32_C(1))) == 0U;
    uint32_t healthier = 0U;
    unsigned int leg;

    if ((candidates & base_bit) != 0U &&
        (base_keeps_share || candidates == base_bit)) {
        *sender_leg = base;
        return 1;
    }
    for (leg = 0U; leg < path_count; leg++) {
        uint32_t bit = UINT32_C(1) << leg;

        if ((candidates & bit) != 0U && leg != base &&
            engine->paths->share_shift[leg] < shift)
            healthier |= bit;
    }
    candidates &= ~base_bit;
    if (healthier != 0U)
        candidates = healthier;
    return select_rotated_leg(candidates, path_count,
                              (uint8_t)((base + 1U) & (path_count - 1U)),
                              sender_leg);
}

static int select_recovery_leg(const bulk_engine_t *engine,
                               uint32_t chunk_index, uint8_t *sender_leg)
{
    uint8_t initial;
    uint8_t path_count = engine->paths->path_count;
    uint32_t candidates = room_mask(engine);

    if (!select_new_leg(engine, chunk_index, &initial))
        return 0;
    if ((candidates & ~(UINT32_C(1) << initial)) != 0U &&
        select_rotated_leg(candidates & ~(UINT32_C(1) << initial),
                           path_count,
                           (uint8_t)((initial + 1U) & (path_count - 1U)),
                           sender_leg))
        return 1;
    *sender_leg = initial;
    return 1;
}

static int find_new_chunk(bulk_engine_t *engine,
                          uint32_t *chunk_index, uint8_t *sender_leg)
{
    uint32_t index;

    if (!engine->is_source || !engine->root_ready ||
        !engine->allocation_acked || engine->failure_pending ||
        room_mask(engine) == 0U)
        return 0;
    for (index = engine->new_cursor; index < engine->manifest.chunk_count;
         index++) {
        int present = bulk_bitmap_test(&engine->ack_state.bitmap, index);
        int active;

        if (present < 0)
            return -1;
        active = chunk_active(engine, index);
        if (active < 0)
            return -1;
        if (!present && !active &&
            select_new_leg(engine, index, sender_leg)) {
            *chunk_index = index;
            return 1;
        }
    }
    return 0;
}

static unsigned int ctz64_nonzero(uint64_t value)
{
#if defined(__GNUC__) || defined(__clang__)
    return (unsigned int)__builtin_ctzll((unsigned long long)value);
#else
    unsigned int count = 0U;

    while ((value & UINT64_C(1)) == 0U) {
        value >>= 1;
        count++;
    }
    return count;
#endif
}

static void recovery_word_tested(bulk_engine_t *engine)
{
#ifdef UNMOOR_BULK_ENGINE_TEST
    engine->test_scan.recovery_word_tests++;
    engine->test_scan.last_recovery_word_tests++;
#else
    (void)engine;
#endif
}

static int find_recovery_chunk(bulk_engine_t *engine,
                               uint32_t *chunk_index,
                               uint8_t *sender_leg)
{
    uint32_t floor;
    uint32_t floor_word;
    uint32_t limit;
    uint32_t limit_word;
    uint32_t tests;

#ifdef UNMOOR_BULK_ENGINE_TEST
    engine->test_scan.last_recovery_word_tests = 0U;
    engine->test_scan.recovery_candidate = UINT32_MAX;
#endif

    if (!engine->is_source || !engine->root_ready ||
        !engine->allocation_acked || engine->failure_pending ||
        room_mask(engine) == 0U)
        return 0;
    limit = engine->new_cursor;
    if (limit > engine->manifest.chunk_count)
        limit = engine->manifest.chunk_count;
    floor = engine->ack_state.bitmap.frontier;
    if (floor >= limit) {
        recovery_scan_reset(engine);
        return 0;
    }
    if (engine->ack_state.bitmap.words == NULL ||
        engine->ack_state.bitmap.storage_bytes < BULK_BITMAP_BYTES ||
        engine->ack_state.bitmap.chunk_count !=
            engine->manifest.chunk_count)
        return -1;
    floor_word = floor >> 6;
    limit_word = (limit + 63U) >> 6;
    if (!engine->recovery_scan_valid ||
        engine->recovery_floor_word != floor_word ||
        engine->recovery_limit_word != limit_word ||
        engine->recovery_word_cursor < floor_word ||
        engine->recovery_word_cursor >= limit_word) {
        engine->recovery_scan_valid = 1U;
        engine->recovery_word_cursor = floor_word;
        engine->recovery_words_remaining = limit_word - floor_word;
        engine->recovery_floor_word = floor_word;
        engine->recovery_limit_word = limit_word;
    }
    if (engine->recovery_words_remaining == 0U) {
        engine->recovery_scan_more = 0U;
        return 0;
    }

    tests = engine->recovery_words_remaining;
    if (tests > BULK_ENGINE_RECOVERY_SCAN_WORDS)
        tests = BULK_ENGINE_RECOVERY_SCAN_WORDS;
    while (tests-- != 0U) {
        uint32_t word_index = engine->recovery_word_cursor;
        uint64_t missing = ~engine->ack_state.bitmap.words[word_index];

        recovery_word_tested(engine);
        if (word_index == floor_word && (floor & 63U) != 0U)
            missing &= UINT64_MAX << (floor & 63U);
        if (word_index + 1U == limit_word && (limit & 63U) != 0U)
            missing &= (UINT64_C(1) << (limit & 63U)) - UINT64_C(1);
        while (missing != 0U) {
            unsigned int bit = ctz64_nonzero(missing);
            uint32_t index = (word_index << 6) + bit;
            int active = chunk_active(engine, index);

            if (active < 0)
                return -1;
            if (!active && select_recovery_leg(engine, index, sender_leg)) {
                *chunk_index = index;
#ifdef UNMOOR_BULK_ENGINE_TEST
                engine->test_scan.recovery_candidate = index;
#endif
                engine->recovery_scan_more = 0U;
                return 1;
            }
            missing &= missing - UINT64_C(1);
        }
        engine->recovery_word_cursor++;
        engine->recovery_words_remaining--;
        if (engine->recovery_word_cursor == limit_word)
            engine->recovery_word_cursor = floor_word;
    }
    engine->recovery_scan_more =
        engine->recovery_words_remaining != 0U ? 1U : 0U;
    return 0;
}

static int request_ready(const bulk_engine_t *engine, int64_t now_ms)
{
    return !engine->failure_pending && engine->request_due &&
           now_ms >= engine->request_next_ms;
}

static int manifest_ready(const bulk_engine_t *engine, int64_t now_ms)
{
    if (engine->failure_pending || !engine->manifest_due ||
        !engine->root_ready ||
        engine->allocation_acked || now_ms < engine->manifest_next_ms)
        return 0;
    if (engine->endpoint == BULK_ENGINE_ENDPOINT_CLIENT &&
        engine->operation == BULK_OPERATION_PUT &&
        !engine->request_completed)
        return 0;
    return 1;
}

static int status_ready(const bulk_engine_t *engine, int64_t now_ms)
{
    return status_is_repeatable(engine) &&
           (engine->status_due || now_ms >= engine->status_next_ms);
}

static int ack_ready(const bulk_engine_t *engine, int64_t now_ms)
{
    return !engine->failure_pending && !engine->is_source &&
           engine->manifest_bound &&
           (any_dirty_page(engine) || now_ms >= engine->ack_next_ms);
}

static int interactive_ready(const bulk_engine_t *engine, int64_t now_ms)
{
    return status_ready(engine, now_ms) ||
           (!engine->failure_pending && engine->busy_status_valid) ||
           request_ready(engine, now_ms) ||
           manifest_ready(engine, now_ms);
}

uint8_t bulk_engine_eligible_mask(bulk_engine_t *engine, int64_t now_ms)
{
    uint8_t mask = 0;
    uint32_t ignored;
    uint8_t ignored_leg;
    int found;

    if (engine == NULL || !engine->active || engine->paused ||
        engine->path_paused ||
        engine->tx.active || !clock_value_valid(now_ms) ||
        now_ms < engine->now_ms ||
        engine->result != BULK_ENGINE_RESULT_RUNNING)
        return 0;
    engine->now_ms = now_ms;
    if (ack_ready(engine, now_ms))
        mask |= SEND_LANE_BIT(SEND_LANE_FEEDBACK);
    if (interactive_ready(engine, now_ms))
        mask |= SEND_LANE_BIT(SEND_LANE_INTERACTIVE);
    found = find_recovery_chunk(engine, &ignored, &ignored_leg);
    if (found < 0) {
        local_fail(engine, BULK_CODE_PROTOCOL, now_ms, 1);
        if (interactive_ready(engine, now_ms))
            mask |= SEND_LANE_BIT(SEND_LANE_INTERACTIVE);
        return mask;
    }
    if (found > 0)
        mask |= SEND_LANE_BIT(SEND_LANE_RECOVERY);
    found = find_new_chunk(engine, &ignored, &ignored_leg);
    if (found < 0) {
        local_fail(engine, BULK_CODE_PROTOCOL, now_ms, 1);
        if (interactive_ready(engine, now_ms))
            mask |= SEND_LANE_BIT(SEND_LANE_INTERACTIVE);
        return mask;
    }
    if (found > 0)
        mask |= SEND_LANE_BIT(SEND_LANE_NEW);
    return mask;
}

static int materialize_ack(bulk_engine_t *engine, uint8_t *out,
                           size_t capacity, bulk_engine_tx_view_t *view)
{
    bulk_ack_t ack;
    uint32_t page;
    uint32_t page_word_base;
    int result;

    if (capacity < BULK_ACK_BYTES)
        return BULK_RC_RESOURCE;
    page = select_ack_page(engine);
    page_word_base = page * BULK_ACK_WORDS;
    result = bulk_ack_snapshot(&engine->ack_state.bitmap,
                               engine->ack_state.counters,
                               &engine->manifest,
                               engine->paths->path_count,
                               page_word_base, &ack);
    if (result != BULK_RC_OK)
        return result;
    result = bulk_ack_encode(&ack, out);
    if (result != BULK_RC_OK)
        return result;
    dirty_clear(engine, page);
    engine->tx.kind = ENGINE_TX_ACK;
    engine->tx.ack_page_word_base = page_word_base;
    view->type = BULK_ACK;
    view->plaintext_length = BULK_ACK_BYTES;
    return BULK_RC_OK;
}

static int materialize_status_record(bulk_engine_t *engine,
                                     const bulk_status_t *status,
                                     engine_tx_kind_t kind,
                                     uint8_t *out, size_t capacity,
                                     bulk_engine_tx_view_t *view)
{
    int result;

    if (capacity < BULK_STATUS_BYTES)
        return BULK_RC_RESOURCE;
    result = bulk_status_encode(status, out);
    if (result != BULK_RC_OK)
        return result;
    engine->tx.kind = (uint8_t)kind;
    engine->tx.status_revision = status->revision;
    engine->tx.status_phase = status->phase;
    view->type = BULK_STATUS;
    view->plaintext_length = BULK_STATUS_BYTES;
    return BULK_RC_OK;
}

static int materialize_interactive(bulk_engine_t *engine, int64_t now_ms,
                                   uint8_t *out, size_t capacity,
                                   bulk_engine_tx_view_t *view)
{
    size_t length = 0;
    int request_is_ready = request_ready(engine, now_ms);
    int manifest_is_ready = manifest_ready(engine, now_ms);
    int result;

    if (status_ready(engine, now_ms))
        return materialize_status_record(engine, &engine->local_status,
                                         ENGINE_TX_STATUS, out, capacity,
                                         view);
    if (engine->busy_status_valid)
        return materialize_status_record(engine, &engine->busy_status,
                                         ENGINE_TX_BUSY, out, capacity,
                                         view);

    if (request_is_ready && manifest_is_ready) {
        if (engine->interactive_cursor != 0)
            request_is_ready = 0;
        else
            manifest_is_ready = 0;
    }
    if (request_is_ready) {
        result = bulk_request_encode(&engine->request, out, capacity, &length);
        if (result != BULK_RC_OK)
            return result;
        engine->tx.kind = ENGINE_TX_REQUEST;
        view->type = BULK_REQUEST;
        view->plaintext_length = length;
        return BULK_RC_OK;
    }
    if (manifest_is_ready) {
        if (capacity < BULK_MANIFEST_BYTES)
            return BULK_RC_RESOURCE;
        result = bulk_manifest_encode(&engine->manifest, out);
        if (result != BULK_RC_OK)
            return result;
        engine->tx.kind = ENGINE_TX_MANIFEST;
        view->type = BULK_MANIFEST;
        view->plaintext_length = BULK_MANIFEST_BYTES;
        return BULK_RC_OK;
    }
    return BULK_RC_STATE;
}

static int materialize_data_record(bulk_engine_t *engine, send_lane_t lane,
                                   uint8_t *out, size_t capacity,
                                   bulk_engine_tx_view_t *view)
{
    bulk_data_view_t data;
    size_t body_length = 0;
    size_t plaintext_length = 0;
    uint32_t chunk_index;
    uint8_t sender_leg;
    int found;
    int result;

    found = lane == SEND_LANE_NEW ?
            find_new_chunk(engine, &chunk_index, &sender_leg) :
            find_recovery_chunk(engine, &chunk_index, &sender_leg);
    if (found <= 0)
        return found < 0 ? BULK_RC_STATE : BULK_RC_DUPLICATE;
    if (engine->next_attempt_id == 0)
        return BULK_RC_RESOURCE;
    result = bulk_source_read_chunk(&engine->source, &engine->manifest,
                                    chunk_index, engine->chunk_buffer,
                                    BULK_CHUNK_MAX, &body_length);
    if (result != BULK_RC_OK) {
        local_fail(engine, result == BULK_RC_SOURCE_CHANGED ?
                   BULK_CODE_SOURCE_CHANGED : BULK_CODE_IO,
                   engine->now_ms, 1);
        return result;
    }
    memset(&data, 0, sizeof(data));
    data.sender_leg = sender_leg;
    data.transfer_id = engine->transfer_id;
    data.chunk_index = chunk_index;
    data.attempt_id = engine->next_attempt_id;
    data.body_length = (uint16_t)body_length;
    data.body = engine->chunk_buffer;
    result = bulk_data_encode(&data, out, capacity, &plaintext_length);
    if (result != BULK_RC_OK)
        return result;

    engine->tx.kind = ENGINE_TX_DATA;
    engine->tx.data_is_new = lane == SEND_LANE_NEW ? 1U : 0U;
    engine->tx.chunk_index = chunk_index;
    engine->tx.attempt_id = engine->next_attempt_id;
    engine->tx.body_length = (uint16_t)body_length;
    engine->tx.sender_leg = sender_leg;
    if (engine->next_attempt_id == UINT32_MAX)
        engine->next_attempt_id = 0;
    else
        engine->next_attempt_id++;
    view->type = BULK_DATA;
    view->plaintext_length = plaintext_length;
    return BULK_RC_OK;
}

int bulk_engine_materialize(bulk_engine_t *engine, send_lane_t lane,
                            int64_t now_ms, uint8_t *plaintext_out,
                            size_t plaintext_capacity,
                            bulk_engine_tx_view_t *view)
{
    uint8_t eligible;
    int result;

    if (engine == NULL || plaintext_out == NULL || view == NULL ||
        lane < SEND_LANE_FEEDBACK || lane >= SEND_LANE_COUNT ||
        plaintext_capacity == 0 || engine->tx.active || engine->paused ||
        engine->path_paused ||
        !clock_value_valid(now_ms) || now_ms < engine->now_ms ||
        engine->result != BULK_ENGINE_RESULT_RUNNING)
        return BULK_RC_ARGUMENT;
    eligible = bulk_engine_eligible_mask(engine, now_ms);
    if ((eligible & SEND_LANE_BIT(lane)) == 0)
        return BULK_RC_STATE;
    memset(&engine->tx, 0, sizeof(engine->tx));
    memset(view, 0, sizeof(*view));
    view->lane = lane;
    view->plaintext = plaintext_out;
    if (lane == SEND_LANE_FEEDBACK)
        result = materialize_ack(engine, plaintext_out, plaintext_capacity,
                                 view);
    else if (lane == SEND_LANE_INTERACTIVE)
        result = materialize_interactive(engine, now_ms, plaintext_out,
                                         plaintext_capacity, view);
    else
        result = materialize_data_record(engine, lane, plaintext_out,
                                         plaintext_capacity, view);
    if (result != BULK_RC_OK) {
        memset(&engine->tx, 0, sizeof(engine->tx));
        return result;
    }
    /* bulk-retry requires the finite error linger no later than first terminal
     * STATUS materialization and before its transport result.  local_fail()
     * normally starts it when publishing the state; keep this idempotent
     * boundary so an unreachable peer can never postpone exit. */
    if (engine->tx.kind == ENGINE_TX_STATUS &&
        phase_is_error(engine->tx.status_phase))
        start_error_linger(engine, now_ms);
    engine->tx.active = 1;
    engine->tx.lane = lane;
    return BULK_RC_OK;
}

static void tx_failed(bulk_engine_t *engine, const engine_tx_state_t *tx)
{
    if (tx->kind == ENGINE_TX_ACK)
        dirty_mark(engine,
                   tx->ack_page_word_base / BULK_ACK_WORDS);
}

static void tx_completed(bulk_engine_t *engine,
                         const engine_tx_state_t *tx, int64_t now_ms)
{
    int present;
    int result;

    switch (tx->kind) {
    case ENGINE_TX_REQUEST:
        engine->stats->request_attempts++;
        if (!engine->request_completed) {
            engine->request_completed = 1;
            if (engine->endpoint == BULK_ENGINE_ENDPOINT_CLIENT &&
                engine->operation == BULK_OPERATION_PUT &&
                engine->scan_kind == ENGINE_SCAN_SOURCE) {
                engine->scan_status_enabled = 1U;
                (void)set_local_status(engine, BULK_PHASE_PREPARING,
                                       BULK_CODE_NONE,
                                       engine->scan_processed, now_ms);
            }
        }
        engine->request_next_ms = now_ms + BULK_ENGINE_REPEAT_MS;
        engine->interactive_cursor = 1;
        break;
    case ENGINE_TX_MANIFEST:
        engine->stats->manifest_attempts++;
        engine->manifest_next_ms = now_ms + BULK_ENGINE_REPEAT_MS;
        engine->interactive_cursor = 0;
        break;
    case ENGINE_TX_ACK:
        engine->stats->ack_attempts++;
        engine->ack_next_ms = now_ms + BULK_ENGINE_REPEAT_MS;
        break;
    case ENGINE_TX_STATUS:
        engine->stats->status_attempts++;
        if (engine->local_status_valid &&
            engine->local_status.revision == tx->status_revision) {
            engine->status_due = 0;
            engine->status_next_ms = now_ms + BULK_ENGINE_REPEAT_MS;
        }
        if (tx->status_phase == BULK_PHASE_DONE) {
            engine->done_sent_complete = 1;
        } else if (tx->status_phase == BULK_PHASE_DONE_ACK) {
            engine->done_ack_sent_complete = 1;
            if (!engine->completion_linger_started) {
                engine->completion_linger_started = 1;
                engine->completion_linger_ms =
                    now_ms + BULK_ENGINE_LINGER_MS;
            }
        } else if (tx->status_phase == BULK_PHASE_DONE_CONFIRM) {
            engine->done_confirm_sent_complete = 1;
            finish_success(engine);
        }
        break;
    case ENGINE_TX_BUSY:
        engine->stats->status_attempts++;
        engine->busy_status_valid = 0;
        break;
    case ENGINE_TX_DATA:
        engine->stats->data_attempts++;
        engine->stats->data_bytes += tx->body_length;
        engine->stats->leg[tx->sender_leg].sent_chunks++;
        engine->stats->leg[tx->sender_leg].sent_bytes += tx->body_length;
        if (!tx->data_is_new) {
            engine->stats->data_retransmits++;
            engine->stats->leg[tx->sender_leg].retransmits++;
        }
        if (tx->data_is_new && tx->chunk_index >= engine->new_cursor)
            engine->new_cursor = tx->chunk_index + 1U;
        present = bulk_bitmap_test(&engine->ack_state.bitmap,
                                   tx->chunk_index);
        if (present == 0) {
            result = add_outstanding(engine, tx->chunk_index,
                                     tx->attempt_id, tx->sender_leg,
                                     now_ms);
            if (result != BULK_RC_OK)
                local_fail(engine, BULK_CODE_IO, now_ms, 1);
        } else if (present < 0) {
            local_fail(engine, BULK_CODE_PROTOCOL, now_ms, 1);
        }
        break;
    default:
        local_fail(engine, BULK_CODE_PROTOCOL, now_ms, 1);
        break;
    }
}

int bulk_engine_transport_result(bulk_engine_t *engine,
                                 send_step_result_t result,
                                 int64_t now_ms)
{
    engine_tx_state_t tx;

    if (engine == NULL || !engine->active || !engine->tx.active ||
        !clock_value_valid(now_ms) || now_ms < engine->now_ms ||
        result < SEND_STEP_WOULD_BLOCK ||
        result > SEND_STEP_FAILED)
        return BULK_RC_ARGUMENT;
    engine->now_ms = now_ms;
    if (result == SEND_STEP_WOULD_BLOCK)
        return BULK_RC_OK;
    if (result == SEND_STEP_PROGRESS)
        return BULK_RC_STATE;
    tx = engine->tx;
    memset(&engine->tx, 0, sizeof(engine->tx));
    engine->send_retry_deadline_ms = 0;
    engine->send_retry_delay_ms = 0;
    if (result == SEND_STEP_FAILED)
        tx_failed(engine, &tx);
    else
        tx_completed(engine, &tx, now_ms);
    return BULK_RC_OK;
}

int bulk_engine_transport_retryable_failure(bulk_engine_t *engine,
                                            int64_t now_ms)
{
    int64_t delay;

    if (engine == NULL || !engine->active || !engine->tx.active ||
        engine->result != BULK_ENGINE_RESULT_RUNNING ||
        !clock_value_valid(now_ms) || now_ms < engine->now_ms ||
        (engine->send_retry_deadline_ms != 0 &&
         now_ms < engine->send_retry_deadline_ms))
        return BULK_RC_STATE;
    delay = engine->send_retry_delay_ms;
    if (delay < BULK_ENGINE_SEND_RETRY_MIN_MS) {
        delay = BULK_ENGINE_SEND_RETRY_MIN_MS;
    } else if (delay < BULK_ENGINE_SEND_RETRY_MAX_MS) {
        delay *= 2;
        if (delay > BULK_ENGINE_SEND_RETRY_MAX_MS)
            delay = BULK_ENGINE_SEND_RETRY_MAX_MS;
    }
    if (now_ms > INT64_MAX - delay)
        return BULK_RC_ARGUMENT;
    engine->now_ms = now_ms;
    engine->send_retry_delay_ms = delay;
    engine->send_retry_deadline_ms = now_ms + delay;
    return BULK_RC_OK;
}

int64_t bulk_engine_transport_retry_wait(const bulk_engine_t *engine,
                                         int64_t now_ms)
{
    if (engine == NULL || !engine->active || !engine->tx.active ||
        engine->result != BULK_ENGINE_RESULT_RUNNING ||
        !clock_value_valid(now_ms) || now_ms < engine->now_ms ||
        engine->send_retry_deadline_ms == 0)
        return -1;
    return engine->send_retry_deadline_ms <= now_ms ? 0 :
           engine->send_retry_deadline_ms - now_ms;
}

int bulk_engine_transport_mtu_failure(bulk_engine_t *engine,
                                      uint8_t sender_leg,
                                      int64_t now_ms)
{
    uint32_t bit;

    if (engine == NULL || !engine->active || engine->paths == NULL ||
        !engine->tx.active || sender_leg >= engine->paths->path_count ||
        !clock_value_valid(now_ms) || now_ms < engine->now_ms)
        return BULK_RC_ARGUMENT;
    if (engine->tx.kind == ENGINE_TX_DATA &&
        engine->tx.sender_leg != sender_leg)
        return BULK_RC_STATE;
    bit = UINT32_C(1) << sender_leg;
    if ((engine->paths->d32_eligible_mask & bit) == 0U)
        return BULK_RC_STATE;
    if ((engine->paths->mtu_usable_mask & bit) != 0U) {
        engine->paths->mtu_usable_mask &= ~bit;
        engine->paths->eligible_mask =
            engine->paths->d32_eligible_mask &
            engine->paths->mtu_usable_mask;
        engine->stats->leg[sender_leg].mtu_failures++;
    }
    engine->now_ms = now_ms;
    recovery_scan_reset(engine);
    if (engine->paths->eligible_mask == 0U)
        local_fail(engine, BULK_CODE_UNSUPPORTED_MTU, now_ms, 1);
    return BULK_RC_OK;
}

static int expire_attempts(bulk_engine_t *engine, int64_t now_ms)
{
    int changed = 0;
    size_t i;

    for (i = 0; i < (size_t)engine->paths->path_count *
                    BULK_ENGINE_OUTSTANDING_PER_LEG; i++) {
        engine_outstanding_t *entry = &engine->outstanding[i];
        if (entry->active &&
            now_ms - entry->completed_ms >=
                BULK_ENGINE_DATA_TIMEOUT_MS) {
            uint8_t leg = entry->sender_leg;

            if (active_index_remove_slot(engine, i) != BULK_RC_OK)
                return BULK_RC_STATE;
            entry->active = 0;
            engine->occupancy[i >> 6] &=
                ~(UINT64_C(1) << (unsigned int)(i & 63U));
            engine->stats->timeout_loss++;
            if (leg < engine->paths->path_count) {
                if (entry->generation ==
                        engine->paths->generation[leg] &&
                    engine->paths->outstanding[leg] != 0U)
                    engine->paths->outstanding[leg]--;
                engine->stats->leg[leg].timeout_loss++;
            }
            changed = 1;
        }
    }
    if (changed)
        recovery_scan_reset(engine);
    return BULK_RC_OK;
}

static void path_share_tick(bulk_engine_t *engine, int64_t now_ms)
{
    unsigned int leg;

    if (engine->paths->path_count == 1U ||
        (engine->paths->eligible_mask &
         (engine->paths->eligible_mask - UINT32_C(1))) == 0U)
        return;

    for (leg = 0U; leg < engine->paths->path_count; leg++) {
        uint64_t acked = engine->ack_state.counters[leg].chunks;
        unsigned int intervals = 0U;

        if (engine->paths->share_next_ms[leg] == 0) {
            engine->paths->sampled_acked_chunks[leg] = acked;
            if (engine->paths->outstanding[leg] == 0U)
                continue;
            engine->paths->share_next_ms[leg] =
                now_ms + BULK_ENGINE_SHARE_INTERVAL_MS;
        }
        while (now_ms >= engine->paths->share_next_ms[leg] &&
               intervals < BULK_ENGINE_SHARE_SHIFT_MAX +
                           BULK_ENGINE_REROLL_WAIT_INTERVALS + 1U) {
            uint32_t bit = UINT32_C(1) << leg;

            if (acked > engine->paths->sampled_acked_chunks[leg]) {
                engine->paths->sampled_acked_chunks[leg] = acked;
                engine->paths->no_progress_at_min[leg] = 0U;
                if (engine->paths->progress_intervals[leg] < 2U)
                    engine->paths->progress_intervals[leg]++;
                if (engine->paths->progress_intervals[leg] == 2U &&
                    engine->paths->share_shift[leg] != 0U) {
                    engine->paths->share_shift[leg]--;
                    engine->stats->leg[leg].share_recoveries++;
                    engine->paths->progress_intervals[leg] = 0U;
                }
            } else if (engine->paths->outstanding[leg] != 0U) {
                engine->paths->progress_intervals[leg] = 0U;
                if (engine->paths->share_shift[leg] <
                    BULK_ENGINE_SHARE_SHIFT_MAX) {
                    engine->paths->share_shift[leg]++;
                    engine->stats->leg[leg].share_reductions++;
                    engine->paths->no_progress_at_min[leg] = 0U;
                } else if ((engine->paths->reroll_due_mask & bit) == 0U &&
                           (engine->paths->reroll_exhausted_mask & bit) ==
                               0U &&
                           engine->paths->no_progress_at_min[leg] <
                               BULK_ENGINE_REROLL_WAIT_INTERVALS) {
                    engine->paths->no_progress_at_min[leg]++;
                    if (engine->paths->no_progress_at_min[leg] ==
                        BULK_ENGINE_REROLL_WAIT_INTERVALS) {
                        engine->paths->reroll_witness_deadline_ms[leg] = 0;
                        engine->paths->reroll_due_mask |= bit;
                        engine->stats->leg[leg].reroll_requests++;
                    }
                }
            } else {
                /* A promptly ACKed attempt may drain the leg before its
                 * sampling deadline.  That is a healthy interval, not idle
                 * state to erase and not a no-progress interval to punish. */
                engine->paths->sampled_acked_chunks[leg] = acked;
            }
            engine->paths->share_next_ms[leg] +=
                BULK_ENGINE_SHARE_INTERVAL_MS;
            intervals++;
            if (engine->paths->outstanding[leg] == 0U) {
                engine->paths->share_next_ms[leg] = 0;
                break;
            }
            if ((engine->paths->reroll_due_mask & bit) != 0U) {
                engine->paths->share_next_ms[leg] =
                    now_ms + BULK_ENGINE_SHARE_INTERVAL_MS;
                break;
            }
        }
    }
}

int bulk_engine_tick(bulk_engine_t *engine, int64_t now_ms)
{
    int result = BULK_RC_OK;

    if (engine == NULL || !engine->active || !clock_value_valid(now_ms) ||
        now_ms < engine->now_ms)
        return BULK_RC_ARGUMENT;
    engine->now_ms = now_ms;
    if (engine->result != BULK_ENGINE_RESULT_RUNNING)
        return BULK_RC_OK;

    if (!engine->paused && !engine->path_paused) {
        path_share_tick(engine, now_ms);
        if (expire_attempts(engine, now_ms) != BULK_RC_OK)
            local_fail(engine, BULK_CODE_PROTOCOL, now_ms, 1);
        if (!engine->failure_pending) {
            if (engine->scan_kind == ENGINE_SCAN_SOURCE) {
                result = source_scan_step(engine, now_ms);
                if (result != BULK_RC_OK && result != BULK_RC_MORE)
                    local_fail(engine, map_source_error(result), now_ms, 1);
            } else if (engine->scan_kind == ENGINE_SCAN_VERIFY) {
                result = verify_scan_step(engine, now_ms);
                if (result != BULK_RC_OK && result != BULK_RC_MORE) {
                    bulk_result_code_t code;
                    if (result == BULK_RC_ROOT_MISMATCH)
                        code = BULK_CODE_ROOT_MISMATCH;
                    else if (result == BULK_RC_EXISTS)
                        code = BULK_CODE_EXISTS;
                    else if (result == BULK_RC_RESOURCE)
                        code = BULK_CODE_QUOTA_SIZE;
                    else
                        code = BULK_CODE_IO;
                    local_fail(engine, code, now_ms, 1);
                }
            }
        }
    }

    if (!engine->failure_pending && !engine->completion_linger_started &&
        engine->clock_started &&
        now_ms - engine->last_progress_ms >= engine->stall_ms)
        local_fail(engine, BULK_CODE_STALLED, now_ms, 1);
    if (engine->failure_pending && engine->error_linger_started &&
        now_ms >= engine->error_linger_ms)
        finish_failed(engine, engine->result_code);
    else if (engine->completion_linger_started &&
             now_ms >= engine->completion_linger_ms)
        finish_success(engine);
    return BULK_RC_OK;
}

static void deadline_min(int64_t *deadline, int64_t candidate)
{
    if (candidate < *deadline)
        *deadline = candidate;
}

int64_t bulk_engine_next_deadline(bulk_engine_t *engine,
                                  int64_t now_ms)
{
    int64_t deadline = INT64_MAX;
    uint32_t ignored;
    uint8_t ignored_leg;
    int recovery;
    size_t i;

    if (engine == NULL || !engine->active ||
        !clock_value_valid(now_ms) || now_ms < engine->now_ms ||
        engine->result != BULK_ENGINE_RESULT_RUNNING)
        return -1;
    if (!engine->paused && !engine->path_paused) {
        /* A retained transport owner already supplies the next runnable
         * boundary (writability or bulk retry). Do not advertise background
         * scan work at `now`: that would turn a failed datagram's finite
         * backoff into a zero-time event-loop spin. */
        if (engine->scan_kind != ENGINE_SCAN_NONE &&
            !engine->failure_pending && !engine->tx.active)
            deadline_min(&deadline, now_ms);
        for (i = 0; i < (size_t)engine->paths->path_count *
                        BULK_ENGINE_OUTSTANDING_PER_LEG; i++) {
            const engine_outstanding_t *entry = &engine->outstanding[i];
            if (entry->active)
                deadline_min(&deadline,
                             entry->completed_ms +
                             BULK_ENGINE_DATA_TIMEOUT_MS);
        }
        for (i = 0; i < engine->paths->path_count; i++) {
            /* A prompt ACK may drain the final attempt before the already-
             * armed sampling boundary.  Keep that boundary visible so the
             * event loop performs the healthy sample. */
            if (engine->paths->share_next_ms[i] != 0)
                deadline_min(&deadline, engine->paths->share_next_ms[i]);
        }
        for (i = 0; i < engine->paths->path_count; i++) {
            uint32_t bit = UINT32_C(1) << (unsigned int)i;
            int64_t claim_ms;
            int64_t witness_deadline;

            if ((engine->paths->reroll_due_mask & bit) == 0U)
                continue;
            witness_deadline =
                engine->paths->reroll_witness_deadline_ms[i];
            claim_ms = reroll_witness_ready_ms(
                engine->paths, (uint8_t)i);
            if (claim_ms == 0 || witness_deadline < now_ms)
                continue;
            if (claim_ms < engine->paths->reroll_session_quiet_ms)
                claim_ms = engine->paths->reroll_session_quiet_ms;
            if (claim_ms < engine->paths->reroll_defer_ms[i])
                claim_ms = engine->paths->reroll_defer_ms[i];
            /* Whole-set ownership is known inside the engine.  Random
             * source-slot -> physical-leg ownership is session state; its
             * exact quiet edge is cached into reroll_defer_ms by the first
             * denied claim below. */
            if (claim_ms < engine->paths->set_reroll_quiet_ms)
                claim_ms = engine->paths->set_reroll_quiet_ms;
            if (claim_ms <= witness_deadline)
                deadline_min(&deadline,
                             claim_ms <= now_ms ? now_ms : claim_ms);
        }
        if (!engine->tx.active) {
            if (ack_ready(engine, now_ms))
                deadline_min(&deadline,
                             any_dirty_page(engine) ? now_ms :
                             engine->ack_next_ms);
            if (status_ready(engine, now_ms))
                deadline_min(&deadline,
                             engine->status_due ? now_ms :
                             engine->status_next_ms);
            if (engine->busy_status_valid)
                deadline_min(&deadline, now_ms);
            if (engine->request_due)
                deadline_min(&deadline, engine->request_next_ms);
            if (engine->manifest_due && engine->root_ready &&
                !engine->allocation_acked)
                deadline_min(&deadline, engine->manifest_next_ms);
            recovery = find_recovery_chunk(engine, &ignored, &ignored_leg);
            if (recovery < 0) {
                local_fail(engine, BULK_CODE_PROTOCOL, now_ms, 1);
                deadline_min(&deadline, now_ms);
            } else {
                int fresh = find_new_chunk(engine, &ignored, &ignored_leg);

                if (fresh < 0) {
                    local_fail(engine, BULK_CODE_PROTOCOL, now_ms, 1);
                    deadline_min(&deadline, now_ms);
                } else if (recovery > 0 || engine->recovery_scan_more ||
                           fresh > 0) {
                    deadline_min(&deadline, now_ms);
                }
            }
        }
        if (engine->tx.active && engine->send_retry_deadline_ms != 0)
            deadline_min(&deadline, engine->send_retry_deadline_ms);
    }
    if (engine->clock_started && !engine->failure_pending)
        deadline_min(&deadline,
                     engine->last_progress_ms + engine->stall_ms);
    if (engine->failure_pending && engine->error_linger_started)
        deadline_min(&deadline, engine->error_linger_ms);
    if (engine->completion_linger_started)
        deadline_min(&deadline, engine->completion_linger_ms);
    if (deadline == INT64_MAX)
        return -1;
    return deadline <= now_ms ? 0 : deadline - now_ms;
}

static void shift_deadline(int64_t *deadline, int64_t delta)
{
    if (*deadline != 0)
        *deadline += delta;
}

int bulk_engine_epoch_pause(bulk_engine_t *engine, int64_t now_ms)
{
    engine_tx_state_t tx;

    if (engine == NULL || !engine->active || engine->paused ||
        !clock_value_valid(now_ms) || now_ms < engine->now_ms ||
        engine->result != BULK_ENGINE_RESULT_RUNNING)
        return BULK_RC_STATE;
    engine->now_ms = now_ms;
    if (engine->tx.active) {
        tx = engine->tx;
        memset(&engine->tx, 0, sizeof(engine->tx));
        tx_failed(engine, &tx);
    }
    engine->send_retry_deadline_ms = 0;
    engine->send_retry_delay_ms = 0;
    memset(engine->encoded_buffer, 0, BULK_ENGINE_TX_BUFFER_BYTES);
    engine->paused = 1;
    engine->pause_started_ms = now_ms;
    if (engine->path_paused) {
        engine->path_pause_epoch_overlap_active = 1U;
        engine->path_pause_epoch_overlap_started_ms = now_ms;
    }
    engine->stats->epoch_pauses++;
    return BULK_RC_OK;
}

int bulk_engine_epoch_resume(bulk_engine_t *engine, int64_t now_ms)
{
    int64_t delta;
    size_t i;

    if (engine == NULL || !engine->active || !engine->paused ||
        !clock_value_valid(now_ms) || now_ms < engine->now_ms ||
        engine->result != BULK_ENGINE_RESULT_RUNNING)
        return BULK_RC_STATE;
    delta = now_ms - engine->pause_started_ms;
    engine->now_ms = now_ms;
    if (engine->path_pause_epoch_overlap_active) {
        engine->path_pause_epoch_overlap_ms +=
            now_ms - engine->path_pause_epoch_overlap_started_ms;
        engine->path_pause_epoch_overlap_active = 0U;
        engine->path_pause_epoch_overlap_started_ms = 0;
    }
    shift_deadline(&engine->request_next_ms, delta);
    shift_deadline(&engine->manifest_next_ms, delta);
    shift_deadline(&engine->ack_next_ms, delta);
    shift_deadline(&engine->status_next_ms, delta);
    shift_deadline(&engine->scan_last_report_ms, delta);
    for (i = 0; i < (size_t)engine->paths->path_count *
                    BULK_ENGINE_OUTSTANDING_PER_LEG; i++)
        memset(&engine->outstanding[i], 0,
               sizeof(engine->outstanding[i]));
    memset(engine->active_index, 0, sizeof(uint16_t) *
           BULK_ENGINE_ACTIVE_INDEX_ENTRIES);
    memset(engine->occupancy, 0, sizeof(uint64_t) *
           ENGINE_OCCUPANCY_WORDS);
    recovery_scan_reset(engine);
    memset(engine->paths->outstanding, 0,
           sizeof(engine->paths->outstanding));
    memset(engine->paths->share_next_ms, 0,
           sizeof(engine->paths->share_next_ms));
    memset(engine->paths->progress_intervals, 0,
           sizeof(engine->paths->progress_intervals));
    memset(engine->paths->no_progress_at_min, 0,
           sizeof(engine->paths->no_progress_at_min));
    memset(engine->paths->reroll_defer_ms, 0,
           sizeof(engine->paths->reroll_defer_ms));
    memset(engine->paths->reroll_quiet_ms, 0,
           sizeof(engine->paths->reroll_quiet_ms));
    memset(engine->paths->reroll_claim_physical, 0,
           sizeof(engine->paths->reroll_claim_physical));
    memset(engine->paths->reroll_witness_deadline_ms, 0,
           sizeof(engine->paths->reroll_witness_deadline_ms));
    engine->paths->reroll_due_mask = 0U;
    engine->paths->reroll_exhausted_mask = 0U;
    engine->paths->reroll_claimed_mask = 0U;
    engine->paths->set_reroll_generation = 0U;
    engine->paths->set_reroll_quiet_ms = 0;
    engine->paths->set_reroll_claimed = 0U;
    engine->paths->set_reroll_trigger_leg = BULK_ENGINE_NO_LEG;
    engine->paths->set_reroll_exhausted = 0U;
    engine->paused = 0;
    if (engine->endpoint == BULK_ENGINE_ENDPOINT_CLIENT &&
        ((engine->operation == BULK_OPERATION_GET &&
          !engine->manifest_bound) ||
         (engine->operation == BULK_OPERATION_PUT &&
          !engine->allocation_acked))) {
        engine->request_due = 1;
        engine->request_next_ms = now_ms;
    }
    if (engine->is_source && engine->root_ready &&
        !engine->allocation_acked) {
        engine->manifest_due = 1;
        engine->manifest_next_ms = now_ms;
    }
    if (!engine->is_source && engine->manifest_bound) {
        dirty_mark(engine, engine->ack_page_cursor %
                           manifest_page_count(&engine->manifest));
        engine->ack_next_ms = now_ms;
    }
    reassert_local_status(engine, now_ms);
    engine->stats->epoch_resumes++;
    return BULK_RC_OK;
}

int bulk_engine_path_pause(bulk_engine_t *engine, int64_t now_ms)
{
    engine_tx_state_t tx;

    if (engine == NULL || !engine->active || engine->paused ||
        engine->path_paused || !clock_value_valid(now_ms) ||
        now_ms < engine->now_ms ||
        engine->result != BULK_ENGINE_RESULT_RUNNING)
        return BULK_RC_STATE;
    engine->now_ms = now_ms;
    if (engine->tx.active) {
        tx = engine->tx;
        memset(&engine->tx, 0, sizeof(engine->tx));
        tx_failed(engine, &tx);
    }
    engine->send_retry_deadline_ms = 0;
    engine->send_retry_delay_ms = 0;
    memset(engine->encoded_buffer, 0, BULK_ENGINE_TX_BUFFER_BYTES);
    engine->path_paused = 1U;
    engine->path_pause_progress_seen = 0U;
    engine->path_pause_started_ms = now_ms;
    engine->path_pause_epoch_overlap_ms = 0;
    engine->path_pause_epoch_overlap_started_ms = 0;
    engine->path_pause_epoch_overlap_active = 0U;
    engine->stats->path_pauses++;
    return BULK_RC_OK;
}

int bulk_engine_path_resume(bulk_engine_t *engine, int64_t now_ms)
{
    int64_t total;
    int64_t overlap;
    int64_t delta;
    size_t i;

    if (engine == NULL || !engine->active || engine->paused ||
        !engine->path_paused ||
        !clock_value_valid(now_ms) || now_ms < engine->now_ms ||
        engine->result != BULK_ENGINE_RESULT_RUNNING)
        return BULK_RC_STATE;
    total = now_ms - engine->path_pause_started_ms;
    overlap = engine->path_pause_epoch_overlap_ms;
    if (engine->path_pause_epoch_overlap_active)
        overlap += now_ms - engine->path_pause_epoch_overlap_started_ms;
    if (overlap < 0 || overlap > total)
        return BULK_RC_STATE;
    delta = total - overlap;
    engine->now_ms = now_ms;
    /* bulk-retry keeps last_progress_ms absolute.  Authenticated progress observed
     * during revalidation already records its real time; silence consumes
     * the same configured budget rather than minting a fresh one. */
    shift_deadline(&engine->scan_last_report_ms, delta);
    for (i = 0; i < (size_t)engine->paths->path_count *
                    BULK_ENGINE_OUTSTANDING_PER_LEG; i++)
        if (engine->outstanding[i].active)
            engine->outstanding[i].completed_ms += delta;
    for (i = 0; i < engine->paths->path_count; i++) {
        shift_deadline(&engine->paths->share_next_ms[i], delta);
        shift_deadline(&engine->paths->reroll_defer_ms[i], delta);
        shift_deadline(&engine->paths->reroll_quiet_ms[i], delta);
    }
    shift_deadline(&engine->paths->set_reroll_quiet_ms, delta);
    engine->path_paused = 0U;
    engine->path_pause_progress_seen = 0U;
    engine->path_pause_started_ms = 0;
    engine->path_pause_epoch_overlap_ms = 0;
    engine->path_pause_epoch_overlap_started_ms = 0;
    engine->path_pause_epoch_overlap_active = 0U;
    engine->stats->path_resumes++;
    return BULK_RC_OK;
}

int bulk_engine_cancel(bulk_engine_t *engine, int64_t now_ms)
{
    if (engine == NULL || !engine->active || !clock_value_valid(now_ms) ||
        now_ms < engine->now_ms ||
        engine->result != BULK_ENGINE_RESULT_RUNNING)
        return BULK_RC_STATE;
    engine->now_ms = now_ms;
    local_fail(engine, BULK_CODE_CANCELLED, now_ms, 1);
    return BULK_RC_OK;
}

bulk_engine_result_t bulk_engine_result(const bulk_engine_t *engine,
                                        bulk_result_code_t *code_out)
{
    if (engine == NULL) {
        if (code_out != NULL)
            *code_out = BULK_CODE_PROTOCOL;
        return BULK_ENGINE_RESULT_FAILED;
    }
    if (code_out != NULL)
        *code_out = engine->result_code;
    return engine->result;
}

int bulk_engine_completion_linger_active(const bulk_engine_t *engine)
{
    return engine != NULL && engine->active &&
           engine->result == BULK_ENGINE_RESULT_RUNNING &&
           engine->completion_linger_started;
}

int bulk_engine_is_requester(const bulk_engine_t *engine)
{
    return engine != NULL &&
           engine->endpoint == BULK_ENGINE_ENDPOINT_CLIENT;
}

int bulk_engine_is_source(const bulk_engine_t *engine)
{
    return engine != NULL && engine->request_bound && engine->is_source;
}

int bulk_engine_observe(const bulk_engine_t *engine,
                        bulk_engine_observation_t *observation)
{
    if (engine == NULL || observation == NULL)
        return BULK_RC_ARGUMENT;
    memset(observation, 0, sizeof(*observation));
    observation->transfer_id = engine->transfer_id;
    observation->file_size = engine->manifest.file_size;
    observation->processed_bytes = engine->scan_processed;
    observation->chunk_count = engine->manifest.chunk_count;
    if (engine->ack_state.bitmap.words != NULL) {
        observation->frontier = engine->ack_state.bitmap.frontier;
        observation->represented_chunks =
            engine->ack_state.bitmap.represented_chunks;
        observation->represented_bytes =
            engine->ack_state.bitmap.represented_bytes;
    }
    observation->local_phase = engine->local_status_valid ?
                               engine->local_status.phase : 0;
    observation->manifest_bound = engine->manifest_bound ||
                                  engine->root_ready;
    observation->installed = engine->installed || engine->sink.installed;
    observation->paused = engine->paused;
    observation->path_paused = engine->path_paused;
    observation->result = engine->result;
    observation->result_code = engine->result_code;
    return BULK_RC_OK;
}

const bulk_engine_stats_t *bulk_engine_stats(const bulk_engine_t *engine)
{
    return engine == NULL ? NULL : engine->stats;
}

int bulk_engine_bitmap_copy(const bulk_engine_t *engine,
                            uint64_t *words_out, size_t word_capacity,
                            size_t *word_count_out)
{
    size_t word_count;

    if (word_count_out)
        *word_count_out = 0U;
    if (engine == NULL || word_count_out == NULL ||
        engine->ack_state.bitmap.words == NULL ||
        engine->ack_state.bitmap.chunk_count == 0U)
        return BULK_RC_ARGUMENT;
    word_count = ((size_t)engine->ack_state.bitmap.chunk_count + 63U) >> 6;
    if (words_out == NULL || word_capacity < word_count)
        return BULK_RC_RESOURCE;
    memcpy(words_out, engine->ack_state.bitmap.words,
           word_count * sizeof(words_out[0]));
    *word_count_out = word_count;
    return BULK_RC_OK;
}

uint8_t *bulk_engine_encoded_buffer(bulk_engine_t *engine,
                                    size_t *capacity_out)
{
    if (capacity_out != NULL)
        *capacity_out = engine != NULL && engine->encoded_buffer != NULL ?
                        BULK_ENGINE_TX_BUFFER_BYTES : 0;
    return engine == NULL ? NULL : engine->encoded_buffer;
}

uint8_t *bulk_engine_receive_buffer(bulk_engine_t *engine,
                                    size_t *capacity_out)
{
    if (capacity_out != NULL)
        *capacity_out = engine != NULL && engine->receive_buffer != NULL ?
                        BULK_ENGINE_TX_BUFFER_BYTES : 0;
    return engine == NULL ? NULL : engine->receive_buffer;
}

uint16_t bulk_engine_wire_budget(const bulk_engine_t *engine)
{
    return engine == NULL ? 0 : engine->wire_budget;
}

uint8_t bulk_engine_path_count(const bulk_engine_t *engine)
{
    return engine != NULL && engine->active && engine->paths != NULL ?
           engine->paths->path_count : 0U;
}

int bulk_engine_update_paths(bulk_engine_t *engine,
                             uint32_t eligible_mask,
                             uint8_t primary_leg,
                             const uint64_t generation[BULK_LEGS_MAX],
                             int64_t now_ms)
{
    uint32_t low;
    unsigned int leg;
    int empty_revalidation;

    if (engine == NULL || !engine->active || engine->paths == NULL ||
        !clock_value_valid(now_ms))
        return BULK_RC_ARGUMENT;
    /* Service activation may sample monotonic time while an enclosing
     * session turn still carries its immediately older sample.  An absolute
     * topology refresh is state, not a timer event: apply it at the engine's
     * current logical time rather than turning a sub-millisecond ordering
     * boundary into a fatal multipath/bulk-transfer divergence. */
    if (now_ms < engine->now_ms)
        now_ms = engine->now_ms;
    low = path_low_mask(engine->paths->path_count);
    empty_revalidation = eligible_mask == 0U && engine->path_paused &&
                         primary_leg == BULK_ENGINE_NO_LEG;
    if ((!empty_revalidation && eligible_mask == 0U) ||
        (eligible_mask & ~low) != 0U ||
        (!empty_revalidation &&
         (primary_leg >= engine->paths->path_count ||
          (eligible_mask & (UINT32_C(1) << primary_leg)) == 0U)) ||
        ((engine->paths->path_count != 1U || empty_revalidation) &&
         generation == NULL))
        return BULK_RC_ARGUMENT;
    /* Validate the absolute replacement before mutating any slot.  A caller
     * may obtain the multipath snapshot while one entry is being retired; a
     * noncanonical generation array must be rejected atomically rather than
     * resetting the earlier slots and then failing on a later zero. */
    for (leg = 0U; leg < engine->paths->path_count; leg++) {
        uint32_t bit = UINT32_C(1) << leg;
        uint64_t next_generation = generation != NULL ?
                                   generation[leg] : UINT64_C(1);

        if (((eligible_mask & bit) != 0U || empty_revalidation) &&
            next_generation == 0U)
            return BULK_RC_ARGUMENT;
    }
    for (leg = 0U; leg < engine->paths->path_count; leg++) {
        uint32_t bit = UINT32_C(1) << leg;
        uint64_t next_generation = generation != NULL ?
                                   generation[leg] : UINT64_C(1);

        if (engine->paths->generation[leg] == next_generation)
            continue;
        engine->paths->generation[leg] = next_generation;
        engine->paths->share_shift[leg] = 0U;
        engine->paths->progress_intervals[leg] = 0U;
        engine->paths->no_progress_at_min[leg] = 0U;
        engine->paths->share_next_ms[leg] = 0;
        engine->paths->reroll_defer_ms[leg] = 0;
        engine->paths->reroll_witness_deadline_ms[leg] = 0;
        engine->paths->sampled_acked_chunks[leg] =
            engine->ack_state.counters[leg].chunks;
        /* A multipath slot generation is an immutable transport incarnation.
         * Retire its attempts without calling them loss or retargeting their
         * ciphertext; globally missing chunks become fresh recovery work and
         * a delayed old packet remains an ordinary receiver-side duplicate. */
        engine->paths->outstanding[leg] = 0U;
        {
            size_t slot;
            size_t base = (size_t)leg *
                          BULK_ENGINE_OUTSTANDING_PER_LEG;

            for (slot = 0U; slot < BULK_ENGINE_OUTSTANDING_PER_LEG; slot++) {
                engine_outstanding_t *entry =
                    &engine->outstanding[base + slot];

                if (!entry->active)
                    continue;
                if (entry->generation == next_generation) {
                    engine->paths->outstanding[leg]++;
                    continue;
                }
                if (active_index_remove_slot(engine, base + slot) !=
                    BULK_RC_OK)
                    return BULK_RC_STATE;
                entry->active = 0U;
                engine->occupancy[(base + slot) >> 6] &=
                    ~(UINT64_C(1) <<
                      (unsigned int)((base + slot) & 63U));
            }
        }
        engine->paths->reroll_due_mask &= ~bit;
        engine->paths->reroll_exhausted_mask &= ~bit;
        engine->paths->reroll_claimed_mask &= ~bit;
        engine->paths->reroll_claim_physical[leg] = 0U;
        if (next_generation != 0U)
            engine->paths->mtu_usable_mask |= bit;
        else
            engine->paths->mtu_usable_mask &= ~bit;
    }
    engine->now_ms = now_ms;
    engine->paths->d32_eligible_mask = eligible_mask;
    engine->paths->eligible_mask =
        eligible_mask & engine->paths->mtu_usable_mask;
    engine->paths->primary_leg = primary_leg;
    recovery_scan_reset(engine);
    return BULK_RC_OK;
}

int bulk_engine_update_legs(bulk_engine_t *engine,
                            const path_leg_t legs[BULK_LEGS_MAX],
                            uint8_t leg_count, uint8_t primary_leg,
                            int64_t now_ms)
{
    uint64_t generation[BULK_LEGS_MAX];
    uint32_t eligible_mask = 0U;
    unsigned int leg;

    if (engine == NULL || legs == NULL || engine->paths == NULL ||
        leg_count == 0U || leg_count != engine->paths->path_count)
        return BULK_RC_ARGUMENT;
    memset(generation, 0, sizeof(generation));
    for (leg = 0U; leg < leg_count; leg++) {
        uint32_t bit = UINT32_C(1) << leg;

        if (legs[leg].validation > PATH_LEG_VALIDATION_VALIDATED ||
            legs[leg].envelope > PATH_LEG_ENVELOPE_DIRECT ||
            (legs[leg].validation == PATH_LEG_VALIDATION_EMPTY &&
             (legs[leg].fd_generation != 0U ||
              legs[leg].envelope != PATH_LEG_ENVELOPE_NONE)) ||
            (legs[leg].validation != PATH_LEG_VALIDATION_EMPTY &&
             (legs[leg].fd_generation == 0U ||
              legs[leg].envelope != PATH_LEG_ENVELOPE_DIRECT)))
            return BULK_RC_ARGUMENT;
        generation[leg] = legs[leg].fd_generation;
        if (primary_leg != BULK_ENGINE_NO_LEG &&
            legs[leg].validation == PATH_LEG_VALIDATION_VALIDATED)
            eligible_mask |= bit;
    }
    if (primary_leg != BULK_ENGINE_NO_LEG) {
        if (primary_leg >= leg_count ||
            legs[primary_leg].validation == PATH_LEG_VALIDATION_EMPTY)
            return BULK_RC_ARGUMENT;
        eligible_mask |= UINT32_C(1) << primary_leg;
    }
    return bulk_engine_update_paths(engine, eligible_mask, primary_leg,
                                    generation, now_ms);
}

int bulk_engine_copy_leg_counters(const bulk_engine_t *engine,
                                  path_leg_t legs[BULK_LEGS_MAX],
                                  uint8_t leg_count)
{
    unsigned int leg;

    if (engine == NULL || legs == NULL || engine->paths == NULL ||
        engine->stats == NULL || leg_count != engine->paths->path_count)
        return BULK_RC_ARGUMENT;
    for (leg = 0U; leg < leg_count; leg++)
        legs[leg].counters = engine->stats->leg[leg];
    return BULK_RC_OK;
}

int bulk_engine_path_snapshot(const bulk_engine_t *engine,
                              bulk_engine_path_snapshot_t *snapshot)
{
    if (engine == NULL || !engine->active || engine->paths == NULL ||
        snapshot == NULL)
        return BULK_RC_ARGUMENT;
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->eligible_mask = engine->paths->eligible_mask;
    snapshot->d32_eligible_mask = engine->paths->d32_eligible_mask;
    snapshot->mtu_usable_mask = engine->paths->mtu_usable_mask;
    snapshot->reroll_due_mask = engine->paths->reroll_due_mask;
    snapshot->reroll_exhausted_mask =
        engine->paths->reroll_exhausted_mask;
    snapshot->reroll_claimed_mask = engine->paths->reroll_claimed_mask;
    snapshot->set_reroll_generation =
        engine->paths->set_reroll_generation;
    snapshot->set_reroll_quiet_ms = engine->paths->set_reroll_quiet_ms;
    snapshot->reroll_session_quiet_ms =
        engine->paths->reroll_session_quiet_ms;
    memcpy(snapshot->generation, engine->paths->generation,
           sizeof(snapshot->generation));
    memcpy(snapshot->share_next_ms, engine->paths->share_next_ms,
           sizeof(snapshot->share_next_ms));
    memcpy(snapshot->reroll_defer_ms, engine->paths->reroll_defer_ms,
           sizeof(snapshot->reroll_defer_ms));
    memcpy(snapshot->reroll_quiet_ms, engine->paths->reroll_quiet_ms,
           sizeof(snapshot->reroll_quiet_ms));
    memcpy(snapshot->reroll_witness_deadline_ms,
           engine->paths->reroll_witness_deadline_ms,
           sizeof(snapshot->reroll_witness_deadline_ms));
    memcpy(snapshot->outstanding, engine->paths->outstanding,
           sizeof(snapshot->outstanding));
    memcpy(snapshot->share_shift, engine->paths->share_shift,
           sizeof(snapshot->share_shift));
    memcpy(snapshot->reroll_attempts, engine->paths->reroll_attempts,
           sizeof(snapshot->reroll_attempts));
    snapshot->set_reroll_attempts = engine->paths->set_reroll_attempts;
    snapshot->set_reroll_claimed = engine->paths->set_reroll_claimed;
    snapshot->set_reroll_trigger_leg =
        engine->paths->set_reroll_trigger_leg;
    snapshot->set_reroll_exhausted = engine->paths->set_reroll_exhausted;
    snapshot->path_count = engine->paths->path_count;
    snapshot->primary_leg = engine->paths->primary_leg;
    snapshot->path_paused = engine->path_paused;
    return BULK_RC_OK;
}

static void reroll_mark_exhausted(bulk_engine_t *engine, uint8_t sender_leg)
{
    uint32_t bit = UINT32_C(1) << sender_leg;

    if ((engine->paths->reroll_exhausted_mask & bit) == 0U) {
        engine->paths->reroll_exhausted_mask |= bit;
        engine->stats->leg[sender_leg].reroll_exhaustions++;
    }
    engine->paths->reroll_due_mask &= ~bit;
    engine->paths->reroll_defer_ms[sender_leg] = 0;
    engine->paths->reroll_witness_deadline_ms[sender_leg] = 0;
}

bulk_engine_reroll_result_t bulk_engine_reroll_claim(
    bulk_engine_t *engine, uint8_t sender_leg, uint8_t physical_leg,
    uint64_t generation, int64_t now_ms)
{
    uint32_t bit;

    if (engine == NULL || !engine->active || engine->paths == NULL ||
        !engine->is_source || engine->paused || engine->path_paused ||
        engine->result != BULK_ENGINE_RESULT_RUNNING ||
        sender_leg >= engine->paths->path_count ||
        physical_leg >= engine->paths->path_count || generation == 0U ||
        !clock_value_valid(now_ms) || now_ms < engine->now_ms)
        return BULK_ENGINE_REROLL_ERROR;
    bit = UINT32_C(1) << sender_leg;
    if (engine->paths->generation[sender_leg] != generation ||
        (engine->paths->reroll_due_mask & bit) == 0U ||
        (engine->paths->reroll_exhausted_mask & bit) != 0U ||
        engine->paths->reroll_claimed_mask != 0U ||
        engine->paths->set_reroll_claimed)
        return BULK_ENGINE_REROLL_NOT_DUE;
    engine->now_ms = now_ms;
    if (now_ms < engine->paths->reroll_defer_ms[sender_leg] ||
        now_ms < engine->paths->reroll_session_quiet_ms ||
        !reroll_witness_ready(engine->paths, sender_leg, now_ms))
        return BULK_ENGINE_REROLL_NOT_DUE;
    if (now_ms < engine->paths->reroll_quiet_ms[physical_leg]) {
        /* The portable engine indexes due state by source-table slot while
         * only the session can resolve that slot to token.local_leg. Cache
         * the resolved physical quiet boundary so next_deadline() cannot
         * advertise zero repeatedly after a path-pause shift. */
        reroll_defer_until(engine->paths, sender_leg,
                           engine->paths->reroll_quiet_ms[physical_leg]);
        return BULK_ENGINE_REROLL_NOT_DUE;
    }
    if (engine->paths->reroll_attempts[physical_leg] >=
        BULK_ENGINE_REROLL_ATTEMPTS_MAX) {
        reroll_mark_exhausted(engine, sender_leg);
        return BULK_ENGINE_REROLL_EXHAUSTED;
    }
    engine->paths->reroll_attempts[physical_leg]++;
    engine->paths->reroll_quiet_ms[physical_leg] =
        now_ms + BULK_ENGINE_REROLL_QUIET_MS;
    engine->paths->reroll_session_quiet_ms =
        now_ms + BULK_ENGINE_REROLL_QUIET_MS;
    engine->paths->reroll_claim_physical[sender_leg] = physical_leg;
    engine->paths->reroll_claimed_mask |= bit;
    engine->stats->leg[sender_leg].reroll_attempts++;
    return BULK_ENGINE_REROLL_CLAIMED;
}

int bulk_engine_reroll_finish(bulk_engine_t *engine, uint8_t sender_leg,
                              uint8_t physical_leg, uint64_t generation,
                              int succeeded, int64_t now_ms)
{
    uint32_t bit;

    if (engine == NULL || !engine->active || engine->paths == NULL ||
        sender_leg >= engine->paths->path_count ||
        physical_leg >= engine->paths->path_count || generation == 0U ||
        (succeeded != 0 && succeeded != 1) ||
        !clock_value_valid(now_ms) || now_ms < engine->now_ms)
        return BULK_RC_ARGUMENT;
    bit = UINT32_C(1) << sender_leg;
    if ((engine->paths->reroll_claimed_mask & bit) == 0U ||
        engine->paths->generation[sender_leg] != generation ||
        engine->paths->reroll_claim_physical[sender_leg] != physical_leg)
        return BULK_RC_STATE;
    engine->now_ms = now_ms;
    engine->paths->reroll_claimed_mask &= ~bit;
    engine->paths->reroll_claim_physical[sender_leg] = 0U;
    if (succeeded != 0) {
        engine->stats->leg[sender_leg].rerolls++;
    } else if (engine->paths->reroll_attempts[physical_leg] >=
               BULK_ENGINE_REROLL_ATTEMPTS_MAX) {
        reroll_mark_exhausted(engine, sender_leg);
    }
    return BULK_RC_OK;
}

int bulk_engine_reroll_defer(bulk_engine_t *engine, uint8_t sender_leg,
                             uint64_t generation, int64_t now_ms)
{
    uint32_t bit;

    if (engine == NULL || !engine->active || engine->paths == NULL ||
        sender_leg >= engine->paths->path_count || generation == 0U ||
        !clock_value_valid(now_ms) || now_ms < engine->now_ms)
        return BULK_RC_ARGUMENT;
    bit = UINT32_C(1) << sender_leg;
    if (engine->paths->generation[sender_leg] != generation ||
        (engine->paths->reroll_due_mask & bit) == 0U ||
        (engine->paths->reroll_exhausted_mask & bit) != 0U ||
        (engine->paths->reroll_claimed_mask & bit) != 0U ||
        engine->paths->set_reroll_claimed)
        return BULK_RC_STATE;
    engine->now_ms = now_ms;
    if (engine->paths->reroll_defer_ms[sender_leg] <
        now_ms + BULK_ENGINE_SHARE_INTERVAL_MS)
        engine->paths->reroll_defer_ms[sender_leg] =
            now_ms + BULK_ENGINE_SHARE_INTERVAL_MS;
    return BULK_RC_OK;
}

int bulk_engine_reroll_exhaust(bulk_engine_t *engine,
                               uint8_t sender_leg,
                               uint64_t generation,
                               int64_t now_ms)
{
    uint32_t bit;

    if (engine == NULL || !engine->active || engine->paths == NULL ||
        sender_leg >= engine->paths->path_count || generation == 0U ||
        !clock_value_valid(now_ms) || now_ms < engine->now_ms)
        return BULK_RC_ARGUMENT;
    bit = UINT32_C(1) << sender_leg;
    if (engine->paths->generation[sender_leg] != generation ||
        (engine->paths->reroll_due_mask & bit) == 0U ||
        (engine->paths->reroll_claimed_mask & bit) != 0U ||
        engine->paths->set_reroll_claimed)
        return BULK_RC_STATE;
    engine->now_ms = now_ms;
    reroll_mark_exhausted(engine, sender_leg);
    return BULK_RC_OK;
}

static void set_reroll_mark_exhausted(bulk_engine_t *engine,
                                      uint8_t trigger_leg)
{
    engine->paths->set_reroll_exhausted = 1U;
    reroll_mark_exhausted(engine, trigger_leg);
}

bulk_engine_reroll_result_t bulk_engine_set_reroll_claim(
    bulk_engine_t *engine, uint8_t trigger_leg, uint64_t generation,
    int64_t now_ms)
{
    uint32_t bit;

    if (engine == NULL || !engine->active || engine->paths == NULL ||
        !engine->is_source || engine->paused || engine->path_paused ||
        engine->result != BULK_ENGINE_RESULT_RUNNING ||
        trigger_leg >= engine->paths->path_count || generation == 0U ||
        !clock_value_valid(now_ms) || now_ms < engine->now_ms)
        return BULK_ENGINE_REROLL_ERROR;
    bit = UINT32_C(1) << trigger_leg;
    if (engine->paths->generation[trigger_leg] != generation ||
        (engine->paths->reroll_due_mask & bit) == 0U ||
        (engine->paths->reroll_exhausted_mask & bit) != 0U ||
        engine->paths->reroll_claimed_mask != 0U ||
        engine->paths->set_reroll_claimed)
        return BULK_ENGINE_REROLL_NOT_DUE;
    engine->now_ms = now_ms;
    if (now_ms < engine->paths->reroll_defer_ms[trigger_leg] ||
        now_ms < engine->paths->set_reroll_quiet_ms ||
        now_ms < engine->paths->reroll_session_quiet_ms ||
        !reroll_witness_ready(engine->paths, trigger_leg, now_ms))
        return BULK_ENGINE_REROLL_NOT_DUE;
    if (engine->paths->set_reroll_exhausted ||
        engine->paths->set_reroll_attempts >=
            BULK_ENGINE_REROLL_ATTEMPTS_MAX) {
        set_reroll_mark_exhausted(engine, trigger_leg);
        return BULK_ENGINE_REROLL_EXHAUSTED;
    }
    engine->paths->set_reroll_attempts++;
    engine->paths->set_reroll_quiet_ms =
        now_ms + BULK_ENGINE_REROLL_QUIET_MS;
    engine->paths->reroll_session_quiet_ms =
        now_ms + BULK_ENGINE_REROLL_QUIET_MS;
    engine->paths->set_reroll_generation = generation;
    engine->paths->set_reroll_trigger_leg = trigger_leg;
    engine->paths->set_reroll_claimed = 1U;
    engine->stats->leg[trigger_leg].reroll_attempts++;
    return BULK_ENGINE_REROLL_CLAIMED;
}

int bulk_engine_set_reroll_finish(bulk_engine_t *engine,
                                  uint8_t trigger_leg,
                                  uint64_t generation,
                                  int succeeded, int64_t now_ms)
{
    if (engine == NULL || !engine->active || engine->paths == NULL ||
        trigger_leg >= engine->paths->path_count || generation == 0U ||
        (succeeded != 0 && succeeded != 1) ||
        !clock_value_valid(now_ms) || now_ms < engine->now_ms)
        return BULK_RC_ARGUMENT;
    if (!engine->paths->set_reroll_claimed ||
        engine->paths->set_reroll_trigger_leg != trigger_leg ||
        engine->paths->set_reroll_generation != generation ||
        engine->paths->generation[trigger_leg] != generation)
        return BULK_RC_STATE;
    engine->now_ms = now_ms;
    engine->paths->set_reroll_claimed = 0U;
    engine->paths->set_reroll_generation = 0U;
    engine->paths->set_reroll_trigger_leg = BULK_ENGINE_NO_LEG;
    if (succeeded != 0) {
        engine->stats->leg[trigger_leg].rerolls++;
    } else if (engine->paths->set_reroll_attempts >=
               BULK_ENGINE_REROLL_ATTEMPTS_MAX) {
        set_reroll_mark_exhausted(engine, trigger_leg);
    }
    return BULK_RC_OK;
}

int bulk_engine_active_attempt(const bulk_engine_t *engine,
                               bulk_engine_attempt_view_t *attempt)
{
    if (engine == NULL || attempt == NULL)
        return BULK_RC_ARGUMENT;
    memset(attempt, 0, sizeof(*attempt));
    if (!engine->tx.active || engine->tx.kind != ENGINE_TX_DATA)
        return BULK_RC_OK;
    attempt->valid = 1;
    attempt->sender_leg = engine->tx.sender_leg;
    attempt->lane = engine->tx.lane;
    attempt->chunk_index = engine->tx.chunk_index;
    attempt->attempt_id = engine->tx.attempt_id;
    attempt->body_length = engine->tx.body_length;
    return BULK_RC_OK;
}

int bulk_engine_prevalidate(const bulk_engine_t *engine, uint8_t type,
                            const uint8_t *plaintext,
                            size_t plaintext_length)
{
    bulk_request_t request;
    bulk_manifest_t manifest;
    bulk_data_view_t data;
    bulk_ack_t ack;
    bulk_status_t status;

    if (engine == NULL || !engine->active || plaintext == NULL)
        return BULK_RC_ARGUMENT;
    switch (type) {
    case BULK_REQUEST:
        if (bulk_request_decode(plaintext, plaintext_length, &request) !=
                BULK_RC_OK ||
            engine->endpoint != BULK_ENGINE_ENDPOINT_SERVER)
            return BULK_RC_MALFORMED;
        if (!engine->request_bound ||
            request.transfer_id != engine->transfer_id)
            return BULK_RC_OK;
        return request_equal(&request, &engine->request) ? BULK_RC_OK :
                                                          BULK_RC_STATE;
    case BULK_MANIFEST:
        if (bulk_manifest_decode(plaintext, plaintext_length, &manifest) !=
            BULK_RC_OK)
            return BULK_RC_MALFORMED;
        if (engine->endpoint == BULK_ENGINE_ENDPOINT_SERVER &&
            !engine->request_bound)
            return BULK_RC_OK;
        if (!engine->request_bound || engine->is_source ||
            manifest.transfer_id != engine->transfer_id)
            return BULK_RC_STATE;
        if (engine->manifest_bound)
            return manifest_equal(&manifest, &engine->manifest) ?
                   BULK_RC_OK : BULK_RC_STATE;
        return bulk_manifest_validate_request(&manifest, &engine->request);
    case BULK_DATA:
        if (bulk_data_decode(plaintext, plaintext_length, &data) !=
                BULK_RC_OK || engine->is_source ||
            !engine->manifest_bound)
            return BULK_RC_STATE;
        return bulk_data_validate(&data, &engine->manifest,
                                  engine->paths->path_count);
    case BULK_ACK:
        if (bulk_ack_decode(plaintext, plaintext_length, &ack) !=
                BULK_RC_OK || !engine->is_source || !engine->root_ready ||
            ack.transfer_id != engine->transfer_id)
            return BULK_RC_STATE;
        return bulk_ack_validate(&ack, &engine->manifest,
                                 engine->paths->path_count);
    case BULK_STATUS:
        if (bulk_status_decode(plaintext, plaintext_length, &status) !=
            BULK_RC_OK)
            return BULK_RC_MALFORMED;
        if (engine->endpoint == BULK_ENGINE_ENDPOINT_SERVER &&
            !engine->request_bound &&
            status.phase == BULK_PHASE_PREPARING)
            return BULK_RC_OK;
        if (engine->peer_status_valid &&
            status.revision <= engine->peer_status.revision)
            return peer_status_transition_valid(engine, &status) ?
                   BULK_RC_OK : BULK_RC_STATE;
        if (!engine->peer_status_valid && engine->manifest_bound &&
            status.phase == BULK_PHASE_PREPARING)
            return status_historical_identity_valid(engine, &status) ?
                   BULK_RC_OK : BULK_RC_STATE;
        if (!peer_status_transition_valid(engine, &status) ||
            !status_local_state_valid(engine, &status))
            return BULK_RC_STATE;
        return BULK_RC_OK;
    default:
        return BULK_RC_MALFORMED;
    }
}

#ifdef UNMOOR_BULK_ENGINE_TEST
int bulk_engine_test_quiesce_for_deadline(bulk_engine_t *engine)
{
    unsigned int leg;

    if (engine == NULL || !engine->active || !engine->is_source ||
        engine->paths == NULL || engine->outstanding == NULL ||
        engine->active_index == NULL || engine->occupancy == NULL ||
        engine->ack_state.bitmap.words == NULL)
        return BULK_RC_ARGUMENT;

    /* Build a reachable post-timeout source shape with no DATA/control
     * producer competing with a retained due/witness edge. This makes the
     * public next_deadline() result an exact reroll oracle without adding a
     * product symbol or bypassing its scheduler code. */
    memset(engine->outstanding, 0, sizeof(engine_outstanding_t) *
           BULK_ENGINE_OUTSTANDING_ENTRIES);
    memset(engine->active_index, 0, sizeof(uint16_t) *
           BULK_ENGINE_ACTIVE_INDEX_ENTRIES);
    memset(engine->occupancy, 0, sizeof(uint64_t) *
           ENGINE_OCCUPANCY_WORDS);
    memset(engine->paths->outstanding, 0,
           sizeof(engine->paths->outstanding));
    memset(engine->paths->share_next_ms, 0,
           sizeof(engine->paths->share_next_ms));
    memset(engine->ack_state.bitmap.words, 0xff, BULK_BITMAP_BYTES);
    engine->ack_state.bitmap.frontier = engine->manifest.chunk_count;
    engine->ack_state.bitmap.represented_chunks =
        engine->manifest.chunk_count;
    engine->ack_state.bitmap.represented_bytes = engine->manifest.file_size;
    for (leg = 0U; leg < engine->paths->path_count; leg++) {
        engine->ack_state.counters[leg].chunks =
            (uint32_t)engine->stats->leg[leg].sent_chunks;
        engine->ack_state.counters[leg].bytes =
            engine->stats->leg[leg].sent_bytes;
    }
    engine->new_cursor = engine->manifest.chunk_count;
    recovery_scan_reset(engine);
    engine->scan_kind = ENGINE_SCAN_NONE;
    engine->request_due = 0U;
    engine->manifest_due = 0U;
    engine->status_due = 0U;
    engine->local_status_valid = 0U;
    engine->peer_status_valid = 0U;
    engine->busy_status_valid = 0U;
    engine->failure_pending = 0U;
    engine->error_linger_started = 0U;
    engine->completion_linger_started = 0U;
    engine->clock_started = 0U;
    engine->send_retry_deadline_ms = 0;
    memset(&engine->tx, 0, sizeof(engine->tx));
    return BULK_RC_OK;
}

int bulk_engine_test_prepare_recovery_scan(bulk_engine_t *engine,
                                           uint32_t handed_out,
                                           uint32_t active_floor,
                                           uint32_t candidate)
{
    uint64_t file_size;

    if (engine == NULL || !engine->active || !engine->is_source ||
        engine->paths == NULL || engine->outstanding == NULL ||
        engine->active_index == NULL || engine->occupancy == NULL ||
        engine->bitmap_storage == NULL || handed_out < 2U ||
        handed_out > BULK_CHUNKS_MAX || active_floor >= candidate ||
        candidate >= handed_out || engine->manifest.chunk_log2 >= 32U)
        return BULK_RC_ARGUMENT;
    file_size = (uint64_t)handed_out << engine->manifest.chunk_log2;
    memset(engine->outstanding, 0, sizeof(engine_outstanding_t) *
           BULK_ENGINE_OUTSTANDING_ENTRIES);
    memset(engine->active_index, 0, sizeof(uint16_t) *
           BULK_ENGINE_ACTIVE_INDEX_ENTRIES);
    memset(engine->occupancy, 0, sizeof(uint64_t) *
           ENGINE_OCCUPANCY_WORDS);
    memset(engine->paths->outstanding, 0,
           sizeof(engine->paths->outstanding));
    memset(&engine->ack_state, 0, sizeof(engine->ack_state));
    engine->ack_state.bitmap.words = (uint64_t *)engine->bitmap_storage;
    engine->ack_state.bitmap.storage_bytes = BULK_BITMAP_BYTES;
    memset(engine->ack_state.bitmap.words, 0xff, BULK_BITMAP_BYTES);
    engine->ack_state.bitmap.words[active_floor >> 6] &=
        ~(UINT64_C(1) << (active_floor & 63U));
    engine->ack_state.bitmap.words[candidate >> 6] &=
        ~(UINT64_C(1) << (candidate & 63U));
    engine->manifest.chunk_count = handed_out;
    engine->manifest.file_size = file_size;
    engine->ack_state.bitmap.chunk_count = handed_out;
    engine->ack_state.bitmap.frontier = active_floor;
    engine->ack_state.bitmap.represented_chunks = handed_out - 2U;
    engine->ack_state.bitmap.represented_bytes =
        file_size - (UINT64_C(2) << engine->manifest.chunk_log2);
    engine->new_cursor = handed_out;
    engine->root_ready = 1U;
    engine->allocation_acked = 1U;
    engine->failure_pending = 0U;
    engine->result = BULK_ENGINE_RESULT_RUNNING;
    engine->result_code = BULK_CODE_NONE;
    engine->scan_kind = ENGINE_SCAN_NONE;
    engine->request_due = 0U;
    engine->manifest_due = 0U;
    engine->status_due = 0U;
    engine->local_status_valid = 0U;
    engine->peer_status_valid = 0U;
    engine->busy_status_valid = 0U;
    memset(&engine->tx, 0, sizeof(engine->tx));
    engine->paths->path_count = 1U;
    engine->paths->primary_leg = 0U;
    engine->paths->d32_eligible_mask = UINT32_C(1);
    engine->paths->mtu_usable_mask = UINT32_C(1);
    engine->paths->eligible_mask = UINT32_C(1);
    if (engine->paths->generation[0] == 0U)
        engine->paths->generation[0] = UINT64_C(1);
    if (add_outstanding(engine, active_floor, UINT32_C(1), 0U,
                        engine->now_ms) != BULK_RC_OK)
        return BULK_RC_STATE;
    memset(&engine->test_scan, 0, sizeof(engine->test_scan));
    engine->test_scan.recovery_candidate = UINT32_MAX;
    return BULK_RC_OK;
}

int bulk_engine_test_scan_metrics(
    const bulk_engine_t *engine, bulk_engine_test_scan_metrics_t *metrics)
{
    if (engine == NULL || metrics == NULL)
        return BULK_RC_ARGUMENT;
    *metrics = engine->test_scan;
    return BULK_RC_OK;
}
#endif
