/*
 * monitor_shutdown.h — fixed listener-monitor M-C worker retirement proof
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * Contract: the listener-monitor runtime bridge, fixed before this API.
 */
#ifndef UNMOOR_MONITOR_SHUTDOWN_H
#define UNMOOR_MONITOR_SHUTDOWN_H

#include <stdint.h>

#define MONITOR_SHUTDOWN_RECORD_BYTES 4U
#define MONITOR_SHUTDOWN_WORKER_EXIT 72
#define MONITOR_SHUTDOWN_PAIR_EMPTY { -1, -1 }

typedef struct monitor_shutdown_wait {
    int fd;                         /* borrowed owner endpoint */
    uint16_t events;                /* POLLIN plus conditional POLLOUT */
    uint8_t immediate;              /* fixed C action or M result */
    uint8_t reserved;
} monitor_shutdown_wait_t;

/* Fresh zero storage, initialized once and never copied/reset/reused. The
 * endpoint is owned after successful init. failure_errno is the first local
 * failure; cleanup_errno records uncertain close and never authorizes retry. */
typedef struct monitor_shutdown {
    int fd;
    int failure_errno;
    int cleanup_errno;
    uint8_t tx[MONITOR_SHUTDOWN_RECORD_BYTES];
    uint8_t rx[MONITOR_SHUTDOWN_RECORD_BYTES + 1U];
    uint8_t role;
    uint8_t phase;
    uint8_t tx_n;
    uint8_t rx_n;
    uint8_t flags;
    uint8_t reserved[2];
} monitor_shutdown_t;

typedef enum monitor_shutdown_step_result {
    MONITOR_SHUTDOWN_ERROR = -1,
    MONITOR_SHUTDOWN_WAIT = 0,
    MONITOR_SHUTDOWN_PROGRESS = 1,
    MONITOR_SHUTDOWN_ACTION = 2,
    MONITOR_SHUTDOWN_RESULT = 3,
    MONITOR_SHUTDOWN_DONE = 4
} monitor_shutdown_step_result_t;

/* Native Linux LP64 little-endian x86_64/aarch64 only. */
int monitor_shutdown_supported(void);
/* pair[] must be {-1,-1}. Success creates one nonblocking/CLOEXEC AF_UNIX
 * stream pair. Failure does not transfer either descriptor. */
int monitor_shutdown_pair_create(int pair[2]);
/* Fresh owner. Success consumes *endpoint and writes -1 there. Invalid or
 * unsupported setup leaves both owner and endpoint unchanged. */
int monitor_shutdown_c_init(monitor_shutdown_t *, int *endpoint);
int monitor_shutdown_m_init(monitor_shutdown_t *, int *endpoint);

int monitor_shutdown_interest(const monitor_shutdown_t *,
                              monitor_shutdown_wait_t *);
/* One call performs at most one read/write. HUP/ERR require an actual read;
 * POLLNVAL is failure. Partial I/O is retained. */
monitor_shutdown_step_result_t
monitor_shutdown_step(monitor_shutdown_t *, short revents);

/* M closes its sole W-carriage alias before requesting STOP. The component
 * cannot prove that external close. C receives ACTION, exact-waits its owned
 * W, then passes the unmodified waitpid status. Only exit72 queues REAPED. */
int monitor_shutdown_m_request_stop(monitor_shutdown_t *);
int monitor_shutdown_c_report_reaped(monitor_shutdown_t *, int wait_status);
/* M receives RESULT, then consumes the only success proof. Output must start
 * at zero. Success writes72 and makes the owner terminal. */
int monitor_shutdown_m_take_reaped(monitor_shutdown_t *, int *worker_exit);

/* Abort is sticky and closes the owned endpoint once. Dispose is idempotent
 * after clean completion. Neither clears an operational/cleanup failure. */
int monitor_shutdown_abort(monitor_shutdown_t *, int cause_errno);
int monitor_shutdown_dispose(monitor_shutdown_t *);

#endif
