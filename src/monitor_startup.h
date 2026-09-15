/*
 * monitor_startup.h — standalone fixed listener-monitor P-C public handoff
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * Contract: the listener-monitor, fixed before this API.  Linux LP64
 * x86_64/aarch64 only; no production constructor or runtime option calls
 * this yet.
 * Callers are trusted, single-threaded and retain exact child/parent identity.
 * No endpoint may be shared, inherited by W/M, transferred or re-executed.
 */
#ifndef UNMOOR_MONITOR_STARTUP_H
#define UNMOOR_MONITOR_STARTUP_H

#include <stdint.h>
#include <sys/types.h>

#define MONITOR_STARTUP_RECORD_BYTES 20U
#define MONITOR_STARTUP_ID_BYTES 16U
#define MONITOR_STARTUP_RETRY_MS INT64_C(20)
#define MONITOR_STARTUP_BUNDLE_EMPTY { -1, -1, -1, -1, -1 }

typedef struct monitor_startup_bundle {
    int parent_fd;
    int attempt_fd;
    int status_write_fd;
    int control_read_fd;
    int stderr_fd;
} monitor_startup_bundle_t;

/* Fixed caller-owned storage, private fields after init. Do not copy/reset.
 * P bundle numbers are borrowed, C bundle aliases owned until take/cleanup.
 * failure_errno is first operational failure; cleanup_errno is permanent
 * close uncertainty, never authority to retry a now-ambiguous numeric fd. */
typedef struct monitor_startup {
    int64_t deadline_ms, next_connect_ms, last_now_ms;
    pid_t expected_pid;
    uid_t expected_uid;
    uint8_t id[MONITOR_STARTUP_ID_BYTES];
    int listener_fd, stream_fd;
    monitor_startup_bundle_t bundle;
    int failure_errno, cleanup_errno;
    uint8_t rx[MONITOR_STARTUP_RECORD_BYTES];
    uint8_t tx[MONITOR_STARTUP_RECORD_BYTES];
    uint8_t role, phase, rx_n, tx_n, expected_n, received_n, flags, owned_mask;
} monitor_startup_t;

typedef struct monitor_startup_wait {
    int64_t wake_ms;
    int fd;                  /* borrowed; -1 when no socket readiness needed */
    uint16_t events;          /* POLLIN/POLLOUT only */
    uint8_t immediate, reserved;
} monitor_startup_wait_t;

typedef enum monitor_startup_result {
    MONITOR_STARTUP_ERROR = -1,
    MONITOR_STARTUP_WAIT = 0,
    MONITOR_STARTUP_PROGRESS = 1,
    MONITOR_STARTUP_P_BUNDLE = 2,
    MONITOR_STARTUP_C_VALIDATE = 3,
    MONITOR_STARTUP_P_ACQUIRED = 4,
    MONITOR_STARTUP_DONE = 5
} monitor_startup_result_t;

/* Fresh zeroed storage. P init only after P/C fork; C init/connect only
 * after complete birth closure, W birth and trusted seal. No API proves
 * those preconditions. stderr_expected is exactly 0/1. One original epoch-rekey
 * deadline, never refreshed; negative time is EINVAL, expired init ETIMEDOUT.
 * Invalid/unsupported init does not change the owner or open a descriptor.
 * Valid setup failure is terminal and eagerly retires acquired resources. */
int monitor_startup_parent_init(monitor_startup_t *, const uint8_t id[16],
    pid_t child, uid_t uid, int stderr_expected, int64_t deadline_ms, int64_t now_ms);
int monitor_startup_child_init(monitor_startup_t *, const uint8_t id[16],
    pid_t parent, uid_t uid, int stderr_expected, int64_t deadline_ms, int64_t now_ms);
int monitor_startup_interest(const monitor_startup_t *, monitor_startup_wait_t *);
monitor_startup_result_t monitor_startup_step(monitor_startup_t *, int64_t now_ms);

/* P_BUNDLE action: no dup/close/ownership transfer of P's bundle. All
 * required numbers distinct/nonnegative and disjoint from startup sockets;
 * absent stderr=-1. Caller keeps them stable until actual P_ACQUIRED. */
int monitor_startup_parent_offer(monitor_startup_t *,
    const monitor_startup_bundle_t *, int64_t now_ms);
/* C_VALIDATE action: fixed directory/pipe/CLOEXEC/identity checks happen
 * inside this call before ACQUIRED. Predicate refusal EPERM, query errno
 * retained; no shared-OFD mutation or pre-validation bundle view. */
int monitor_startup_child_approve(monitor_startup_t *, int64_t now_ms);
/* P_ACQUIRED action: caller MUST already have closed both its C-side pipe
 * aliases once with success (remove numeric cleanup entries before close).
 * Uncertain external close means abort, never this call. This API cannot
 * prove caller action; it never touches those stale numbers after ACQUIRED. */
int monitor_startup_parent_commit(monitor_startup_t *, int64_t now_ms);
/* C_DONE only, after COMMIT + nonzero EOF probe + successful stream close.
 * Output is separate/nonoverlapping and initially EMPTY. Failure leaves it
 * unchanged. Transfers every alias once; repeat EALREADY. No public ACCEPT,
 * attempt cleanup, child reaping, map wipe or worker seal is implied. */
int monitor_startup_child_take(monitor_startup_t *, monitor_startup_bundle_t *);

/* Abort returns -1 with first cause, closes only owned sockets/C aliases.
 * Dispose cancels an incomplete exchange or untaken C_DONE, permanently
 * preventing take. After a clean take it closes no transferred descriptor.
 * Cleanup may succeed after an operational failure but never clears it.
 * Any uncertain close makes all later dispose calls fail without retry. */
int monitor_startup_abort(monitor_startup_t *, int cause_errno);
int monitor_startup_dispose(monitor_startup_t *);

#endif
