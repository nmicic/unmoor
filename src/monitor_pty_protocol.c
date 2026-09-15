/*
 * monitor_pty_protocol.c — listener-monitor lifecycle preparation
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#include "monitor_pty_protocol.h"
#include <string.h>

_Static_assert(sizeof(monitor_pty_record_t) == 32U, "decoded record budget");
_Static_assert(sizeof(monitor_pty_protocol_t) == 32U, "protocol owner budget");

static int zero_bytes(const void *input, size_t n)
{
    const uint8_t *bytes = input;
    for (size_t i = 0; i < n; ++i) if (bytes[i] != 0U) return 0;
    return 1;
}

static int record_valid(const monitor_pty_record_t *r)
{
    if (!r || r->incarnation == 0U || r->kind < MONITOR_PTY_LAUNCH ||
        r->kind > MONITOR_PTY_REAPED ||
        !zero_bytes(r->reserved, sizeof(r->reserved)) ||
        r->rights != (r->kind == MONITOR_PTY_OFFER ? 2U : 0U) ||
        r->status != (r->kind == MONITOR_PTY_REFUSED ? 1U : 0U) ||
        (r->kind == MONITOR_PTY_LAUNCH ? r->serial != 0U : r->serial == 0U))
        return 0;
    switch (r->kind) {
    case MONITOR_PTY_LAUNCH:
    case MONITOR_PTY_ACQUIRED:
    case MONITOR_PTY_COMMIT:
        return r->arg0 == 0U && r->arg1 == 0U;
    case MONITOR_PTY_OPEN:
        return (r->arg0 & UINT32_C(0xffff)) >= 1U &&
               (r->arg0 & UINT32_C(0xffff)) <= 1000U &&
               (r->arg0 >> 16) >= 1U && (r->arg0 >> 16) <= 1000U &&
               r->arg1 == 0U;
    case MONITOR_PTY_OFFER:
    case MONITOR_PTY_REFUSED:
        return r->arg0 >= 1U && r->arg0 <= INT32_MAX && r->arg1 == 0U;
    case MONITOR_PTY_RETIRE:
        return r->arg0 != 0U || r->arg1 != 0U;
    case MONITOR_PTY_REAPED:
        return r->arg0 <= 255U && r->arg1 == 0U;
    default:
        return 0;
    }
}

static void put_le(uint8_t *out, uint64_t value, size_t n)
{
    for (size_t i = 0; i < n; ++i) { out[i] = (uint8_t)value; value >>= 8; }
}
static uint64_t get_le(const uint8_t *in, size_t n)
{
    uint64_t value = 0;
    for (size_t i = 0; i < n; ++i) value |= (uint64_t)in[i] << (8U * i);
    return value;
}

int monitor_pty_encode(uint8_t *output, size_t capacity,
                       const monitor_pty_record_t *record)
{
    if (!output || capacity < MONITOR_PTY_RECORD_BYTES || !record_valid(record))
        return -1;
    output[0] = MONITOR_PTY_RECORD_VERSION;
    output[1] = record->kind; output[2] = record->rights; output[3] = record->status;
    memset(output + 4, 0, 4);
    put_le(output + 8, record->incarnation, 8);
    put_le(output + 16, record->serial, 8);
    put_le(output + 24, record->arg0, 4);
    put_le(output + 28, record->arg1, 4);
    return 0;
}
int monitor_pty_decode(monitor_pty_record_t *record,
                       const uint8_t *input, size_t length)
{
    if (!record) return -1;
    memset(record, 0, sizeof(*record));
    if (!input || length != MONITOR_PTY_RECORD_BYTES ||
        input[0] != MONITOR_PTY_RECORD_VERSION || !zero_bytes(input + 4, 4))
        return -1;
    record->incarnation = get_le(input + 8, 8);
    record->serial = get_le(input + 16, 8);
    record->arg0 = (uint32_t)get_le(input + 24, 4);
    record->arg1 = (uint32_t)get_le(input + 28, 4);
    record->kind = input[1]; record->rights = input[2]; record->status = input[3];
    if (!record_valid(record)) { memset(record, 0, sizeof(*record)); return -1; }
    return 0;
}
int monitor_pty_protocol_init(monitor_pty_protocol_t *owner, uint64_t incarnation)
{
    if (!owner || incarnation == 0U || !zero_bytes(owner, sizeof(*owner)))
        return -1;
    owner->incarnation = incarnation;
    return 0;
}
int monitor_pty_protocol_observe(monitor_pty_protocol_t *owner, uint8_t sender,
                                const monitor_pty_record_t *record)
{
    if (!owner || !record || (sender != MONITOR_PTY_C && sender != MONITOR_PTY_M))
        return -1;
    if (owner->phase == MONITOR_PTY_FAILED) return -1;
    if (owner->incarnation == 0U || !zero_bytes(owner->reserved, sizeof(owner->reserved)) ||
        !record_valid(record) || record->incarnation != owner->incarnation ||
        sender != ((record->kind == MONITOR_PTY_OPEN ||
                    record->kind == MONITOR_PTY_ACQUIRED ||
                    record->kind == MONITOR_PTY_RETIRE) ? MONITOR_PTY_M : MONITOR_PTY_C))
        goto failed;
    switch (owner->phase) {
    case MONITOR_PTY_WAIT_LAUNCH:
        if (record->kind != MONITOR_PTY_LAUNCH) goto failed;
        owner->phase = MONITOR_PTY_IDLE;
        return 0;
    case MONITOR_PTY_IDLE:
        if (record->kind != MONITOR_PTY_OPEN || owner->last_serial == UINT64_MAX ||
            record->serial != owner->last_serial + 1U) goto failed;
        owner->last_serial = record->serial;
        owner->phase = MONITOR_PTY_WAIT_OFFER;
        return 0;
    case MONITOR_PTY_WAIT_OFFER:
        if (record->serial != owner->last_serial) goto failed;
        if (record->kind == MONITOR_PTY_REFUSED) {
            owner->phase = MONITOR_PTY_IDLE;
            return 0;
        }
        if (record->kind != MONITOR_PTY_OFFER) goto failed;
        owner->public_pid = record->arg0;
        owner->phase = MONITOR_PTY_WAIT_ACQUIRED;
        return 0;
    case MONITOR_PTY_WAIT_ACQUIRED:
        if (record->kind != MONITOR_PTY_ACQUIRED || record->serial != owner->last_serial)
            goto failed;
        owner->phase = MONITOR_PTY_WAIT_COMMIT;
        return 0;
    case MONITOR_PTY_WAIT_COMMIT:
        if (record->kind != MONITOR_PTY_COMMIT || record->serial != owner->last_serial)
            goto failed;
        owner->shell_token = record->serial;
        owner->phase = MONITOR_PTY_LIVE;
        return 0;
    case MONITOR_PTY_LIVE:
        if (record->kind != MONITOR_PTY_RETIRE || owner->last_serial == UINT64_MAX ||
            record->serial != owner->last_serial + 1U ||
            (((uint64_t)record->arg1 << 32) | record->arg0) != owner->shell_token)
            goto failed;
        owner->last_serial = record->serial;
        owner->phase = MONITOR_PTY_WAIT_REAPED;
        return 0;
    case MONITOR_PTY_WAIT_REAPED:
        if (record->kind != MONITOR_PTY_REAPED || record->serial != owner->last_serial)
            goto failed;
        owner->public_pid = 0;
        owner->shell_token = 0;
        owner->phase = MONITOR_PTY_IDLE;
        return 0;
    default:
        break;
    }
failed:
    owner->phase = MONITOR_PTY_FAILED;
    return -1;
}
