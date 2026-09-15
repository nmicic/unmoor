/*
 * reasm.h — authenticated whole-message fragment reassembly
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef UNMOOR_REASM_H
#define UNMOOR_REASM_H

#include <stddef.h>
#include <stdint.h>

#define REASM_MAX_BUFFER       4096
#define REASM_MAX_SLOTS          16
#define REASM_MAX_FRAGMENTS      32
#define REASM_COMPLETED_SLOTS    32
#define REASM_TIMEOUT_MS       5000

#define FRAGMENT_VERSION          1
#define FRAGMENT_DESC_LEN        16
#define FRAGMENT_HASH_LEN        32
#define FRAGMENT_OVERHEAD        (FRAGMENT_DESC_LEN + FRAGMENT_HASH_LEN)

/* Clear descriptor carried between the base frame header and ciphertext.
 * Its encoded bytes are AEAD associated data; semantic validation happens
 * only after the ciphertext authenticates. */
typedef struct {
    uint8_t  version;
    uint8_t  reserved;
    uint32_t message_id;
    uint16_t index;
    uint16_t count;
    uint16_t total_length;
    uint16_t stride;
    uint16_t fragment_length;
} fragment_desc_t;

typedef struct {
    int      open;
    uint8_t  direction;
    uint8_t  channel;
    uint8_t  type;
    uint32_t message_id;
    uint16_t count;
    uint16_t total_length;
    uint16_t stride;
    uint32_t received;
    int64_t  deadline_ms;
    uint8_t  hash[FRAGMENT_HASH_LEN];
    uint8_t  buf[REASM_MAX_BUFFER];
} reasm_slot_t;

typedef struct {
    int      valid;
    uint8_t  direction;
    uint8_t  channel;
    uint32_t message_id;
} reasm_completed_t;

typedef struct {
    reasm_slot_t      slots[REASM_MAX_SLOTS];
    reasm_completed_t completed[REASM_COMPLETED_SLOTS];
    size_t            completed_next;
} reasm_t;

#define REASM_DROP     0
#define REASM_DELIVER  1
#define REASM_ERROR   -1

void fragment_desc_encode(const fragment_desc_t *desc,
                          uint8_t out[FRAGMENT_DESC_LEN]);
int fragment_desc_decode(const uint8_t in[FRAGMENT_DESC_LEN],
                         fragment_desc_t *desc);

/* Feed one already-authenticated multi-fragment body. `hash` is the encrypted
 * repeated whole-message commitment and `data` is this fragment's plaintext
 * slice. Any index may arrive first. */
int reasm_feed_fragment(reasm_t *r,
                        uint8_t direction, uint8_t channel, uint8_t type,
                        int ff, int mf,
                        const fragment_desc_t *desc,
                        const uint8_t hash[FRAGMENT_HASH_LEN],
                        const uint8_t *data, size_t len,
                        int64_t now_ms, int64_t timeout_ms,
                        const uint8_t **out_buf, size_t *out_len);

void reasm_tick(reasm_t *r, int64_t now_ms);
void reasm_reset(reasm_t *r);
void reasm_reset_chan(reasm_t *r, uint8_t channel);
size_t reasm_active_count(const reasm_t *r);

#endif /* UNMOOR_REASM_H */
