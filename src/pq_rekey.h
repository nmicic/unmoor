/*
 * pq_rekey.h — fixed pq-hybrid channel-zero share and bitmap grammar
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef UNMOOR_PQ_REKEY_H
#define UNMOOR_PQ_REKEY_H

#include <stddef.h>
#include <stdint.h>

#define PQ_REKEY_VERSION 1U
#define PQ_REKEY_SUITE 1U
#define PQ_REKEY_KIND_INIT 1U
#define PQ_REKEY_KIND_REPLY 2U
#define PQ_REKEY_ID_LEN 16U
#define PQ_REKEY_SHARE_LEN 1568U
#define PQ_REKEY_SHARE_DESCRIPTOR_LEN 32U
#define PQ_REKEY_BITMAP_LEN 32U
#define PQ_REKEY_MTU_MIN 92U
#define PQ_REKEY_MTU_MAX 482U
#define PQ_REKEY_FRAGMENT_MIN 4U
#define PQ_REKEY_FRAGMENT_MAX 27U
#define PQ_REKEY_ASSEMBLY_MS 5000
#define PQ_REKEY_RETRY_MS 500

enum {
    PQ_REKEY_RX_ACCEPTED = 0,
    PQ_REKEY_RX_DUPLICATE = 1,
    PQ_REKEY_RX_INVALID = -1,
    PQ_REKEY_RX_BUSY = -2
};

typedef struct {
    uint8_t kind;
    uint32_t from_epoch;
    uint8_t rekey_id[PQ_REKEY_ID_LEN];
    uint8_t index;
    uint8_t count;
    uint16_t offset;
    uint16_t payload_length;
} pq_rekey_share_descriptor_t;

typedef struct {
    uint8_t kind;
    uint32_t from_epoch;
    uint8_t rekey_id[PQ_REKEY_ID_LEN];
    uint8_t count;
    uint32_t received_bitmap;
} pq_rekey_bitmap_t;

typedef struct {
    uint8_t active;
    uint8_t complete;
    uint8_t kind;
    uint8_t count;
    uint16_t stride;
    uint32_t from_epoch;
    uint8_t rekey_id[PQ_REKEY_ID_LEN];
    uint32_t received_bitmap;
    int64_t deadline_ms;
    int64_t bitmap_due_ms;
    uint64_t bitmap_generation;
    uint64_t bitmap_inflight_generation;
    uint8_t bitmap_inflight;
    uint8_t bytes[PQ_REKEY_SHARE_LEN];
} pq_rekey_rx_t;

int pq_rekey_geometry(size_t current_mtu, uint16_t *stride_out,
                      uint8_t *count_out);
uint32_t pq_rekey_full_bitmap(uint8_t count);

int pq_rekey_share_descriptor_make(
    pq_rekey_share_descriptor_t *out, uint8_t kind, uint32_t from_epoch,
    const uint8_t rekey_id[PQ_REKEY_ID_LEN], uint8_t index,
    size_t current_mtu);
int pq_rekey_share_descriptor_encode(
    uint8_t wire[PQ_REKEY_SHARE_DESCRIPTOR_LEN],
    const pq_rekey_share_descriptor_t *descriptor, size_t current_mtu);
int pq_rekey_share_descriptor_decode(
    const uint8_t *wire, size_t wire_len, size_t current_mtu,
    pq_rekey_share_descriptor_t *out);

int pq_rekey_bitmap_encode(uint8_t wire[PQ_REKEY_BITMAP_LEN],
                           const pq_rekey_bitmap_t *bitmap);
int pq_rekey_bitmap_decode(const uint8_t *wire, size_t wire_len,
                           pq_rekey_bitmap_t *out);

void pq_rekey_rx_init(pq_rekey_rx_t *rx);
int pq_rekey_rx_accept(pq_rekey_rx_t *rx,
                       const pq_rekey_share_descriptor_t *descriptor,
                       const uint8_t *payload, size_t payload_len,
                       size_t current_mtu, int64_t now_ms);
int pq_rekey_rx_expire(pq_rekey_rx_t *rx, int64_t now_ms);
int pq_rekey_rx_copy(const pq_rekey_rx_t *rx,
                     uint8_t share_out[PQ_REKEY_SHARE_LEN]);
int pq_rekey_rx_bitmap_claim(pq_rekey_rx_t *rx, int64_t now_ms,
                             pq_rekey_bitmap_t *out);
int pq_rekey_rx_bitmap_complete(pq_rekey_rx_t *rx, int64_t now_ms);
void pq_rekey_rx_wipe(pq_rekey_rx_t *rx);

/* Returns 1 and advances cursor when a missing bit exists, 0 when complete,
 * and -1 for invalid arguments. */
int pq_rekey_next_missing(uint32_t received_bitmap, uint8_t count,
                          uint8_t *cursor, uint8_t *index_out);

#endif /* UNMOOR_PQ_REKEY_H */
