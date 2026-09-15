/*
 * rekey.h — epoch-rekey canonical epoch-rekey control grammar
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef UNMOOR_REKEY_H
#define UNMOOR_REKEY_H

#include <stddef.h>
#include <stdint.h>

#include "frame.h"

#define REKEY_VERSION          0x01U
#define REKEY_ID_LEN           16U
#define REKEY_DIGEST_LEN       32U
#define REKEY_MESSAGE_LEN      92U
#define REKEY_RETRY_MS         500
#define REKEY_SEQ_RESERVE_START UINT32_C(0xC0000000)

typedef enum {
    REKEY_NONE = 0,
    REKEY_C_WAIT_REPLY,
    REKEY_C_WAIT_COMMIT,
    REKEY_C_WAIT_ACK_SEND,
    REKEY_S_WAIT_INIT,
    REKEY_S_WAIT_CONFIRM,
    REKEY_S_WAIT_ACK,
} rekey_phase_t;

typedef struct {
    uint8_t  type;
    uint32_t from_epoch;
    uint32_t to_epoch;
    uint8_t  id[REKEY_ID_LEN];
    uint8_t  first[REKEY_DIGEST_LEN];
    uint8_t  second[REKEY_DIGEST_LEN];
} rekey_message_t;

int rekey_control_type(uint8_t type);

/* Encode/decode the exact fixed grammar. `expected_type` is the authenticated
 * outer TYPE and must equal the redundant inner byte. Decode also enforces
 * from+1 without wrap and kind-specific zero fields. */
int rekey_message_encode(uint8_t out[REKEY_MESSAGE_LEN],
                         const rekey_message_t *message);
int rekey_message_decode(const uint8_t *wire, size_t wire_len,
                         uint8_t expected_type, rekey_message_t *out);

/* Exact public/control transcript equality; no pointer alias assumptions. */
int rekey_message_equal(const rekey_message_t *a,
                        const rekey_message_t *b);

#endif /* UNMOOR_REKEY_H */
