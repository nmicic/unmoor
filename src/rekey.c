/*
 * rekey.c — epoch-rekey canonical epoch-rekey control grammar
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include "rekey.h"

#define OFF_VERSION 0U
#define OFF_TYPE    1U
#define OFF_FROM    4U
#define OFF_TO      8U
#define OFF_ID      12U
#define OFF_FIRST   28U
#define OFF_SECOND  60U

static void store32le(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
    p[2] = (uint8_t)(value >> 16);
    p[3] = (uint8_t)(value >> 24);
}

static uint32_t load32le(const uint8_t *p)
{
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static int all_zero(const uint8_t *p, size_t len)
{
    uint8_t aggregate = 0;
    for (size_t i = 0; i < len; i++)
        aggregate |= p[i];
    return aggregate == 0;
}

int rekey_control_type(uint8_t type)
{
    return type >= CTRL_REKEY_REQUEST && type <= CTRL_REKEY_ACK;
}

static int valid_message(const rekey_message_t *message)
{
    if (!message || !rekey_control_type(message->type) ||
        message->from_epoch == UINT32_MAX ||
        message->to_epoch != message->from_epoch + 1U)
        return 0;

    if (message->type == CTRL_REKEY_REQUEST) {
        return all_zero(message->id, sizeof(message->id)) &&
               all_zero(message->first, sizeof(message->first)) &&
               all_zero(message->second, sizeof(message->second));
    }

    if (all_zero(message->id, sizeof(message->id)))
        return 0;
    if (message->type == CTRL_REKEY_INIT ||
        message->type == CTRL_REKEY_REPLY) {
        return !all_zero(message->first, sizeof(message->first)) &&
               all_zero(message->second, sizeof(message->second));
    }
    return 1;
}

int rekey_message_encode(uint8_t out[REKEY_MESSAGE_LEN],
                         const rekey_message_t *message)
{
    if (!out || !valid_message(message))
        return -1;
    memset(out, 0, REKEY_MESSAGE_LEN);
    out[OFF_VERSION] = REKEY_VERSION;
    out[OFF_TYPE] = message->type;
    store32le(out + OFF_FROM, message->from_epoch);
    store32le(out + OFF_TO, message->to_epoch);
    memcpy(out + OFF_ID, message->id, REKEY_ID_LEN);
    memcpy(out + OFF_FIRST, message->first, REKEY_DIGEST_LEN);
    memcpy(out + OFF_SECOND, message->second, REKEY_DIGEST_LEN);
    return 0;
}

int rekey_message_decode(const uint8_t *wire, size_t wire_len,
                         uint8_t expected_type, rekey_message_t *out)
{
    rekey_message_t decoded;
    if (!wire || !out || wire_len != REKEY_MESSAGE_LEN ||
        !rekey_control_type(expected_type) ||
        wire[OFF_VERSION] != REKEY_VERSION ||
        wire[OFF_TYPE] != expected_type || wire[2] != 0 || wire[3] != 0)
        return -1;

    memset(&decoded, 0, sizeof(decoded));
    decoded.type = wire[OFF_TYPE];
    decoded.from_epoch = load32le(wire + OFF_FROM);
    decoded.to_epoch = load32le(wire + OFF_TO);
    memcpy(decoded.id, wire + OFF_ID, REKEY_ID_LEN);
    memcpy(decoded.first, wire + OFF_FIRST, REKEY_DIGEST_LEN);
    memcpy(decoded.second, wire + OFF_SECOND, REKEY_DIGEST_LEN);
    if (!valid_message(&decoded)) {
        memset(&decoded, 0, sizeof(decoded));
        return -1;
    }
    *out = decoded;
    return 0;
}

/* Each byte-array comparison scans its complete field (accumulate-OR, never
 * memcmp), so a mismatch position inside that field is not observable through
 * timing.  rekey_message_equal() may short-circuit between public grammar
 * fields and byte fields; it currently has no product call site. */
static int rekey_bytes_equal(const uint8_t *a, const uint8_t *b,
                             size_t len)
{
    uint8_t diff = 0;
    size_t i;

    for (i = 0; i < len; i++)
        diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

int rekey_message_equal(const rekey_message_t *a,
                        const rekey_message_t *b)
{
    return a && b && a->type == b->type &&
           a->from_epoch == b->from_epoch &&
           a->to_epoch == b->to_epoch &&
           rekey_bytes_equal(a->id, b->id, REKEY_ID_LEN) &&
           rekey_bytes_equal(a->first, b->first, REKEY_DIGEST_LEN) &&
           rekey_bytes_equal(a->second, b->second, REKEY_DIGEST_LEN);
}
