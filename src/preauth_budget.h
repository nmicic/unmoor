/*
 * preauth_budget.h — source-prefilter fixed pre-authentication work budget
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef UNMOOR_PREAUTH_BUDGET_H
#define UNMOOR_PREAUTH_BUDGET_H

#include <stddef.h>
#include <stdint.h>

#define PREAUTH_SOURCE_SLOTS       64U
#define PREAUTH_FAILURE_BUDGET     8U
#define PREAUTH_FAILURE_WINDOW_MS  2000
#define PREAUTH_PENALTY_MS         2000
#define PREAUTH_NO_INDEX           UINT8_MAX

typedef struct {
    uint8_t family;             /* 4 or 6 */
    uint8_t address[16];        /* v4 uses address[0..3], rest zero */
    uint32_t scope;             /* zero for v4 */
} preauth_source_t;

typedef struct {
    preauth_source_t source;
    int64_t window_deadline_ms;
    int64_t blocked_until_ms;
    uint64_t generation;
    uint8_t failures;
    uint8_t occupied;
    uint8_t provisional;
    uint8_t reserved;
} preauth_source_entry_t;

typedef struct {
    uint64_t unknown_pair_drop;
    uint64_t malformed_preauth_drop;
    uint64_t aead_attempt;
    uint64_t aead_failure;
    uint64_t budget_drop;
    uint64_t table_full_drop;
    uint64_t no_key_drop;
} preauth_counters_t;

typedef struct {
    preauth_source_entry_t entry[PREAUTH_SOURCE_SLOTS];
    preauth_counters_t counters;
    int64_t last_now_ms;
    uint64_t generation_counter;
    uint8_t clock_initialized;
    uint8_t reserved[7];
} preauth_budget_t;

typedef struct {
    uint64_t generation;
    uint8_t index;
    uint8_t provisional;
    uint8_t reserved[6];
} preauth_budget_handle_t;

enum {
    PREAUTH_ADMIT_INVALID = -1,
    PREAUTH_ADMIT_DROP = 0,
    PREAUTH_ADMIT_ALLOW = 1
};

void preauth_budget_init(preauth_budget_t *budget);

/* `family` is the protocol-neutral value 4 or 6. IPv4-mapped IPv6 is
 * normalized to native v4 and loses its v6 scope. */
int preauth_source_init(preauth_source_t *source, uint8_t family,
                        const uint8_t *address, size_t address_length,
                        uint32_t scope);
int preauth_source_valid(const preauth_source_t *source);
int preauth_source_equal(const preauth_source_t *left,
                         const preauth_source_t *right);
uint64_t preauth_source_hash(const preauth_source_t *source);

int preauth_budget_admit(preauth_budget_t *budget,
                         const preauth_source_t *source, int64_t now_ms,
                         preauth_budget_handle_t *handle_out);
void preauth_budget_note_aead_attempt(preauth_budget_t *budget);
void preauth_budget_failure(preauth_budget_t *budget,
                            const preauth_budget_handle_t *handle,
                            int64_t now_ms);
void preauth_budget_authenticated(preauth_budget_t *budget,
                                  const preauth_budget_handle_t *handle);
void preauth_budget_note_unknown_pair(preauth_budget_t *budget);
void preauth_budget_note_malformed(preauth_budget_t *budget);
/* A frame whose selected key is not live is dropped before admission. */
void preauth_budget_note_no_key(preauth_budget_t *budget);

#endif /* UNMOOR_PREAUTH_BUDGET_H */
