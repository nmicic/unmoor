/*
 * pq_hybrid.h — pq-hybrid root and epoch-chain combiner
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef UNMOOR_PQ_HYBRID_H
#define UNMOOR_PQ_HYBRID_H

#include <stddef.h>
#include <stdint.h>

#define PQ_HYBRID_SECRET_LEN 32U

/* transcript is an already-canonical pq-hybrid public encoding.  Empty
 * transcripts are rejected so no caller can accidentally omit binding. */
int pq_hybrid_bootstrap_root(
    const uint8_t x25519_shared[PQ_HYBRID_SECRET_LEN],
    const uint8_t mlkem_shared[PQ_HYBRID_SECRET_LEN],
    const uint8_t *transcript, size_t transcript_len,
    uint8_t root_out[PQ_HYBRID_SECRET_LEN]);

int pq_hybrid_rekey_combine(
    const uint8_t current_traffic_key[PQ_HYBRID_SECRET_LEN],
    const uint8_t x25519_shared[PQ_HYBRID_SECRET_LEN],
    const uint8_t mlkem_shared[PQ_HYBRID_SECRET_LEN],
    const uint8_t *transcript, size_t transcript_len,
    uint8_t combined_out[PQ_HYBRID_SECRET_LEN]);

#endif /* UNMOOR_PQ_HYBRID_H */
