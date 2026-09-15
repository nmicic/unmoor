/*
 * monitor_worker.h — fixed listener-monitor STORE/PLAN worker entry
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef UNMOOR_MONITOR_WORKER_H
#define UNMOOR_MONITOR_WORKER_H

#include "sync_source_map.h"
#include <stdint.h>

#define MONITOR_WORKER_FD 3
#define MONITOR_WORKER_OTHER_FD 4
#define MONITOR_WORKER_READY 0x57U
#define MONITOR_WORKER_EXIT_SETUP 70
#define MONITOR_WORKER_EXIT_WAIT 71
#define MONITOR_WORKER_EXIT_WORK 72

/* Native inherited public data, never a wire record. LP64:24 bytes. The
 * trusted never-secret single-threaded constructor owns birth ordering;
 * this manifest is not proof of that history. No pointers/keys/epochs/fds
 * or caller-selected commands/operations cross the manifest. */
typedef struct {
    uint64_t incarnation;
    uint64_t quota;
    int32_t expected_c_pid;
    uint8_t direction;
    uint8_t reserved[3];
} monitor_worker_birth_t;

/* Compiled availability only, not native filter installation evidence.
 * Little-endian Linux LP64 x86_64/aarch64 normal GCC/Clang only. Supported
 * project instrumentation refuses; arbitrary compiler instrumentation
 * detection is not promised. Ordinary product paths do not call this role. */
int monitor_worker_supported(void);

/* Trusted C immediately around W fork, including restoring after a failed
 * fork. Block saves8 bytes and checks all catchable kernel signals blocked.
 * C restores its exact saved mask; W normalizes instead, never restores.
 * 0 or -1/errno; EINVAL for null save or an unmaskable saved bit, ENOTSUP
 * before mutation on unsupported targets. Partial failures may have changed
 * signal state: do not continue startup or assume rollback. */
int monitor_worker_block_for_fork(uint64_t *saved);
int monitor_worker_restore_after_fork(uint64_t saved);

/* No return, no fallback. Fresh never-secret W only; stdin/out/err harmless,
 * exact freshly created work pair3/4 and inherited CREATED map are the only
 * resources. Parent guard, opposite-fd retirement, map/source checks, signals,
 * core policy and final role all precede prefix0x57 and any work read.
 * Birth/map must be separate valid inherited owners, not IPC addresses.
 * This API cannot prove caller custody/no-extra-fd/no-prior-private-memory.
 * Readiness is ordering, not attestation, continued life or public ACCEPT.
 * Ordinary terminal exits are internal failure70/71/72, not FIN/completion.
 * Unsupported/instrumented targets exit SETUP without a readiness prefix.
 * Exact reap/shared wipe and C/M lifecycle/runtime admission remain external.
 */
_Noreturn void monitor_worker_enter(sync_source_map_t *map,
                                    const monitor_worker_birth_t *birth);

#endif
