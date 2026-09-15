/*
 * monitor_pty_custody.h — standalone native listener-monitor C-M PTY owner
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * Contract: the listener-monitor, fixed before this API.  This helper is
 * not linked into the product and supplies no constructor, process role or
 * monitored-session option.
 */
#ifndef UNMOOR_MONITOR_PTY_CUSTODY_H
#define UNMOOR_MONITOR_PTY_CUSTODY_H

#include "monitor_pty_protocol.h"
#include "sync_source_map.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define MONITOR_PTY_CUSTODY_PAIR_EMPTY { -1, -1 }
#define MONITOR_PTY_CUSTODY_RESULT_EMPTY { 0, -1, -1, 0, 0, 0, {0} }

enum {
    MONITOR_PTY_CUSTODY_RESULT_OPENED = 1,
    MONITOR_PTY_CUSTODY_RESULT_REFUSED,
    MONITOR_PTY_CUSTODY_RESULT_REAPED
};

typedef struct monitor_pty_custody_result {
    uint64_t token;
    int master_fd;                 /* borrowed for OPENED; never transferred */
    int pidfd;                     /* borrowed for OPENED; never transferred */
    uint32_t public_pid;           /* report data, never an OS target */
    int value;                     /* errno for REFUSED, status for REAPED */
    uint8_t kind;
    uint8_t reserved[7];
} monitor_pty_custody_result_t;

typedef struct monitor_pty_custody_wait {
    int fd;                        /* borrowed owner endpoint */
    uint16_t events;               /* POLLIN plus conditional POLLOUT */
    uint8_t immediate;             /* fixed C action, no socket syscall */
    uint8_t reserved;
} monitor_pty_custody_wait_t;

/* Fixed caller storage.  Start zero, initialize once, never copy/reset/reuse.
 * C retains the exact child; pair[] is C's pre-COMMIT alias pair or M's
 * received pair.  released_map is a bound trusted C prerequisite, not a proof
 * of constructor provenance.  failure_errno and cleanup_errno never clear. */
typedef struct monitor_pty_custody {
    monitor_pty_protocol_t protocol;
    const sync_source_map_t *released_map;
    monitor_pty_custody_result_t result;
    uint8_t tx[MONITOR_PTY_RECORD_BYTES];
    uint8_t rx[MONITOR_PTY_RECORD_BYTES];
    int channel_fd;
    int pair[2];
    int failure_errno;
    int cleanup_errno;
    int child_status;
    pid_t child_pid;
    uint16_t rows, columns;
    uint8_t role, action, tx_n, rx_n, received_n, flags, reserved[2];
} monitor_pty_custody_t;

typedef enum monitor_pty_custody_step_result {
    MONITOR_PTY_CUSTODY_ERROR = -1,
    MONITOR_PTY_CUSTODY_WAIT = 0,
    MONITOR_PTY_CUSTODY_PROGRESS = 1,
    MONITOR_PTY_CUSTODY_ACTION = 2,
    MONITOR_PTY_CUSTODY_RESULT = 3
} monitor_pty_custody_step_result_t;

/* Linux LP64 x86_64/aarch64 only. */
int monitor_pty_custody_supported(void);

/* pair[] must be {-1,-1}.  Success creates exactly one nonblocking/CLOEXEC
 * AF_UNIX SOCK_STREAM pair.  Failure leaves pair unchanged. */
int monitor_pty_custody_pair_create(int pair[2]);

/* Fresh zero owner.  Success consumes *endpoint and sets it to -1.  Invalid,
 * unsupported or prerequisite failure changes neither owner nor endpoint.
 * C requires one terminal RELEASED shared-map owner and queues LAUNCH only
 * after accepting it; M receives LAUNCH before it may request OPEN. */
int monitor_pty_custody_c_init(monitor_pty_custody_t *, int *endpoint,
                               uint64_t incarnation,
                               const sync_source_map_t *released_map);
int monitor_pty_custody_m_init(monitor_pty_custody_t *, int *endpoint,
                               uint64_t incarnation);

int monitor_pty_custody_interest(const monitor_pty_custody_t *,
                                 monitor_pty_custody_wait_t *);
/* revents uses poll(2) bits.  One call performs at most one sendmsg/recvmsg.
 * HUP/ERR lead to a real receive, never a fabricated EOF. */
monitor_pty_custody_step_result_t
monitor_pty_custody_step(monitor_pty_custody_t *, short revents);

/* M requests one new pre-end OPEN only while IDLE and with no untaken result.
 * End eligibility remains outside this component.  C perform_action has
 * no action payload: validated state selects spawn, alias release or reap. */
int monitor_pty_custody_request_open(monitor_pty_custody_t *,
                                     uint16_t rows, uint16_t columns);
int monitor_pty_custody_perform_action(monitor_pty_custody_t *);

/* C's final role may be installed only after ACQUIRED caused certain release
 * of both offered aliases and while COMMIT is still locally queued.  Returns
 * one only at that boundary, zero at every other valid C state, and -1 for an
 * invalid/non-C owner. */
int monitor_pty_custody_c_role_ready(const monitor_pty_custody_t *);

/* OPENED returns borrowed live fds only after COMMIT.  REFUSED and REAPED
 * carry one value.  Output must be separate and EMPTY; taking consumes only
 * the notification. */
int monitor_pty_custody_take_result(monitor_pty_custody_t *,
                                    monitor_pty_custody_result_t *);

/* M invalidates/closes its live aliases before queuing exact-token RETIRE. */
int monitor_pty_custody_request_retire(monitor_pty_custody_t *);

/* Fixed M-only live PTY operations.  They add no buffering and ordinary I/O
 * errors do not poison lifecycle state. */
ssize_t monitor_pty_custody_read(monitor_pty_custody_t *, void *, size_t);
ssize_t monitor_pty_custody_write(monitor_pty_custody_t *, const void *, size_t);
int monitor_pty_custody_resize(monitor_pty_custody_t *,
                               uint16_t rows, uint16_t columns);
int monitor_pty_custody_signal(monitor_pty_custody_t *, int signum);

/* Abort records one positive operational cause and closes owned aliases.
 * Dispose closes the channel/aliases once and lets C retire only its retained
 * exact child.  Cleanup can never clear the first cause or retry an uncertain
 * numeric descriptor/PID. */
int monitor_pty_custody_abort(monitor_pty_custody_t *, int cause_errno);
int monitor_pty_custody_dispose(monitor_pty_custody_t *);

#endif
