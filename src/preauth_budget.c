/*
 * preauth_budget.c — source-prefilter fixed pre-authentication work budget
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */

#include <limits.h>
#include <string.h>

#include "preauth_budget.h"

_Static_assert(PREAUTH_SOURCE_SLOTS != 0U &&
               (PREAUTH_SOURCE_SLOTS & (PREAUTH_SOURCE_SLOTS - 1U)) == 0U,
               "pre-authentication table size must be a power of two");
_Static_assert(PREAUTH_SOURCE_SLOTS < PREAUTH_NO_INDEX,
               "pre-authentication slot index must fit its handle");
_Static_assert(PREAUTH_FAILURE_BUDGET <= UINT8_MAX,
               "pre-authentication failure count must fit its entry");

static int address_is_v4_mapped(const uint8_t address[16])
{
    static const uint8_t mapped_prefix[12] = {
        0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0xffU, 0xffU
    };

    return address &&
           memcmp(address, mapped_prefix, sizeof(mapped_prefix)) == 0;
}

static void increment_saturating(uint64_t *value)
{
    if (*value != UINT64_MAX)
        (*value)++;
}

static int64_t normalize_now(preauth_budget_t *budget, int64_t now_ms)
{
    if (now_ms < 0)
        now_ms = 0;
    if (!budget->clock_initialized) {
        budget->clock_initialized = 1U;
        budget->last_now_ms = now_ms;
    } else if (now_ms < budget->last_now_ms) {
        now_ms = budget->last_now_ms;
    } else {
        budget->last_now_ms = now_ms;
    }
    return now_ms;
}

static int64_t deadline_after(int64_t now_ms, int64_t interval_ms)
{
    if (now_ms > INT64_MAX - interval_ms)
        return INT64_MAX;
    return now_ms + interval_ms;
}

static int deadline_active(int64_t deadline_ms, int64_t now_ms)
{
    if (deadline_ms == INT64_MAX)
        return 1;
    return deadline_ms > 0 && now_ms < deadline_ms;
}

static int entry_active(const preauth_source_entry_t *entry, int64_t now_ms)
{
    if (!entry->occupied)
        return 0;
    if (entry->provisional)
        return 1;
    if (deadline_active(entry->blocked_until_ms, now_ms))
        return 1;
    return entry->failures != 0U &&
           deadline_active(entry->window_deadline_ms, now_ms);
}

static uint64_t next_generation(preauth_budget_t *budget)
{
    if (budget->generation_counter != UINT64_MAX)
        budget->generation_counter++;
    if (budget->generation_counter == 0U)
        budget->generation_counter = 1U;
    return budget->generation_counter;
}

static void reserve_entry(preauth_budget_t *budget, size_t index,
                          const preauth_source_t *source,
                          preauth_budget_handle_t *handle_out)
{
    preauth_source_entry_t *entry = &budget->entry[index];

    memset(entry, 0, sizeof(*entry));
    entry->source = *source;
    entry->generation = next_generation(budget);
    entry->occupied = 1U;
    entry->provisional = 1U;
    handle_out->generation = entry->generation;
    handle_out->index = (uint8_t)index;
    handle_out->provisional = 1U;
}

static preauth_source_entry_t *entry_for_handle(
    preauth_budget_t *budget, const preauth_budget_handle_t *handle)
{
    preauth_source_entry_t *entry;

    if (!budget || !handle || handle->index >= PREAUTH_SOURCE_SLOTS)
        return NULL;
    entry = &budget->entry[handle->index];
    if (!entry->occupied || entry->generation != handle->generation)
        return NULL;
    return entry;
}

void preauth_budget_init(preauth_budget_t *budget)
{
    if (budget)
        memset(budget, 0, sizeof(*budget));
}

int preauth_source_init(preauth_source_t *source, uint8_t family,
                        const uint8_t *address, size_t address_length,
                        uint32_t scope)
{
    if (!source || !address)
        return -1;
    memset(source, 0, sizeof(*source));
    if (family == 4U && address_length == 4U) {
        source->family = 4U;
        memcpy(source->address, address, 4U);
        return 0;
    }
    if (family != 6U || address_length != 16U)
        return -1;
    if (address_is_v4_mapped(address)) {
        source->family = 4U;
        memcpy(source->address, address + 12U, 4U);
        return 0;
    }
    source->family = 6U;
    source->scope = scope;
    memcpy(source->address, address, 16U);
    return 0;
}

int preauth_source_valid(const preauth_source_t *source)
{
    static const uint8_t zero[12] = {0};

    if (!source)
        return 0;
    if (source->family == 4U)
        return source->scope == 0U &&
               memcmp(source->address + 4U, zero, sizeof(zero)) == 0;
    return source->family == 6U &&
           !address_is_v4_mapped(source->address);
}

int preauth_source_equal(const preauth_source_t *left,
                         const preauth_source_t *right)
{
    return preauth_source_valid(left) && preauth_source_valid(right) &&
           left->family == right->family && left->scope == right->scope &&
           memcmp(left->address, right->address,
                  sizeof(left->address)) == 0;
}

uint64_t preauth_source_hash(const preauth_source_t *source)
{
    uint64_t hash = UINT64_C(1469598103934665603);
    size_t index;

    if (!preauth_source_valid(source))
        return 0U;
    hash ^= source->family;
    hash *= UINT64_C(1099511628211);
    for (index = 0U; index < sizeof(source->address); index++) {
        hash ^= source->address[index];
        hash *= UINT64_C(1099511628211);
    }
    for (index = 0U; index < sizeof(source->scope); index++) {
        hash ^= (uint8_t)(source->scope >> (index * 8U));
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

int preauth_budget_admit(preauth_budget_t *budget,
                         const preauth_source_t *source, int64_t now_ms,
                         preauth_budget_handle_t *handle_out)
{
    size_t start;
    size_t offset;
    size_t reusable = PREAUTH_SOURCE_SLOTS;

    if (!budget || !handle_out || !preauth_source_valid(source))
        return PREAUTH_ADMIT_INVALID;
    memset(handle_out, 0, sizeof(*handle_out));
    handle_out->index = PREAUTH_NO_INDEX;
    now_ms = normalize_now(budget, now_ms);
    start = (size_t)(preauth_source_hash(source) &
                     (PREAUTH_SOURCE_SLOTS - 1U));
    for (offset = 0U; offset < PREAUTH_SOURCE_SLOTS; offset++) {
        size_t index = (start + offset) & (PREAUTH_SOURCE_SLOTS - 1U);
        preauth_source_entry_t *entry = &budget->entry[index];
        int active = entry_active(entry, now_ms);

        if (entry->occupied &&
            preauth_source_equal(&entry->source, source)) {
            if (!active) {
                reserve_entry(budget, index, source, handle_out);
                return PREAUTH_ADMIT_ALLOW;
            }
            if (deadline_active(entry->blocked_until_ms, now_ms)) {
                increment_saturating(&budget->counters.budget_drop);
                return PREAUTH_ADMIT_DROP;
            }
            handle_out->generation = entry->generation;
            handle_out->index = (uint8_t)index;
            handle_out->provisional = entry->provisional;
            return PREAUTH_ADMIT_ALLOW;
        }
        if (!active && reusable == PREAUTH_SOURCE_SLOTS)
            reusable = index;
    }
    if (reusable == PREAUTH_SOURCE_SLOTS) {
        increment_saturating(&budget->counters.table_full_drop);
        return PREAUTH_ADMIT_DROP;
    }
    reserve_entry(budget, reusable, source, handle_out);
    return PREAUTH_ADMIT_ALLOW;
}

void preauth_budget_note_aead_attempt(preauth_budget_t *budget)
{
    if (budget)
        increment_saturating(&budget->counters.aead_attempt);
}

void preauth_budget_failure(preauth_budget_t *budget,
                            const preauth_budget_handle_t *handle,
                            int64_t now_ms)
{
    preauth_source_entry_t *entry;

    if (!budget)
        return;
    increment_saturating(&budget->counters.aead_failure);
    if (!handle || handle->index == PREAUTH_NO_INDEX)
        return;
    now_ms = normalize_now(budget, now_ms);
    entry = entry_for_handle(budget, handle);
    if (!entry)
        return;
    if (entry->provisional ||
        !deadline_active(entry->window_deadline_ms, now_ms)) {
        entry->failures = 1U;
        entry->window_deadline_ms = deadline_after(
            now_ms, PREAUTH_FAILURE_WINDOW_MS);
        entry->blocked_until_ms = 0;
        entry->provisional = 0U;
        return;
    }
    if (entry->failures < PREAUTH_FAILURE_BUDGET)
        entry->failures++;
    if (entry->failures == PREAUTH_FAILURE_BUDGET &&
        entry->blocked_until_ms == 0)
        entry->blocked_until_ms = deadline_after(now_ms,
                                                  PREAUTH_PENALTY_MS);
}

void preauth_budget_authenticated(preauth_budget_t *budget,
                                  const preauth_budget_handle_t *handle)
{
    preauth_source_entry_t *entry = entry_for_handle(budget, handle);

    if (entry && handle->provisional && entry->provisional &&
        entry->failures == 0U)
        memset(entry, 0, sizeof(*entry));
}

void preauth_budget_note_unknown_pair(preauth_budget_t *budget)
{
    if (budget)
        increment_saturating(&budget->counters.unknown_pair_drop);
}

void preauth_budget_note_malformed(preauth_budget_t *budget)
{
    if (budget)
        increment_saturating(&budget->counters.malformed_preauth_drop);
}
