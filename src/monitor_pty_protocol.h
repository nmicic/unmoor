/*
 * monitor_pty_protocol.h — pure listener-monitor lifecycle records and ordered observations
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef UNMOOR_MONITOR_PTY_PROTOCOL_H
#define UNMOOR_MONITOR_PTY_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#define MONITOR_PTY_RECORD_BYTES 32U
#define MONITOR_PTY_RECORD_VERSION 1U
#define MONITOR_PTY_C 1U
#define MONITOR_PTY_M 2U

enum {
    MONITOR_PTY_LAUNCH = 1,
    MONITOR_PTY_OPEN,
    MONITOR_PTY_OFFER,
    MONITOR_PTY_ACQUIRED,
    MONITOR_PTY_COMMIT,
    MONITOR_PTY_REFUSED,
    MONITOR_PTY_RETIRE,
    MONITOR_PTY_REAPED
};
enum {
    MONITOR_PTY_WAIT_LAUNCH = 0,
    MONITOR_PTY_IDLE,
    MONITOR_PTY_WAIT_OFFER,
    MONITOR_PTY_WAIT_ACQUIRED,
    MONITOR_PTY_WAIT_COMMIT,
    MONITOR_PTY_LIVE,
    MONITOR_PTY_WAIT_REAPED,
    MONITOR_PTY_FAILED
};

/* Host values, never serialized by copying this struct. Reserved bytes zero.
 * The public PID in OFFER is report data, never an OS target. */
typedef struct {
    uint64_t incarnation, serial;
    uint32_t arg0, arg1;
    uint8_t kind, rights, status, reserved[5];
} monitor_pty_record_t;

/* Fresh zero storage, one init, no copy/reset of a live runtime owner.
 * Tests may copy pure observations; no descriptors or resources live here.
 * Fields remain available for diagnosis after the phase becomes FAILED. */
typedef struct {
    uint64_t incarnation, last_serial, shell_token;
    uint32_t public_pid;
    uint8_t phase, reserved[3];
} monitor_pty_protocol_t;

/* All inputs/outputs/owners are disjoint caller storage. No heap, I/O, errno,
 * time, child, fd or authority operation. Return0 success/-1 invalid.
 * Encode validates before writing exactly32 bytes, leaving output untouched
 * on error. Decode requires exact length and clears any supplied output on
 * error. Kinds9..11 are NOT enabled; their outer cleanup contract is owed. */
int monitor_pty_encode(uint8_t *output, size_t capacity,
                       const monitor_pty_record_t *record);
int monitor_pty_decode(monitor_pty_record_t *record,
                       const uint8_t *input, size_t length);

int monitor_pty_protocol_init(monitor_pty_protocol_t *, uint64_t incarnation);
/* Sender is the trusted observation's role, not a field authenticated by this
 * function. Healthy null/bad-sender arguments are nonmutating. Wrong canonical
 * record, identity or phase poisons only phase; no later reset or progress.
 * Future carriage must observe real complete sends/receives, not admission.
 * ACQUIRED/COMMIT/REAPED do not themselves prove receipt/close/reap.
 * End-of-life admission is external, as are actual custody and cleanup. */
int monitor_pty_protocol_observe(monitor_pty_protocol_t *, uint8_t sender,
                                const monitor_pty_record_t *);

#endif
