/*
 * monitor_session_backend.h — fixed listener-monitor existing-engine adapter
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 * Contract: the listener-monitor, fixed before this API.
 */
#ifndef UNMOOR_MONITOR_SESSION_BACKEND_H
#define UNMOOR_MONITOR_SESSION_BACKEND_H

#include "monitor_pty_custody.h"
#include "sync_monitor.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

struct session;

typedef struct monitor_session_backend_wait {
    int fd;
    uint16_t events;
    uint8_t immediate;
    uint8_t reserved;
} monitor_session_backend_wait_t;

/* Fixed trusted constructor object; pointers are borrowed for its lifetime.
 * No IPC record or peer input selects them. The PTY pair remains owned by
 * custody; master_fd/pidfd are diagnostic borrowed aliases only. */
typedef struct monitor_session_backend {
    struct session *session;
    sync_monitor_binding_t *binding;
    monitor_pty_custody_t *custody;
    int worker_fd;
    int master_fd;
    int pidfd;
    int failure_errno;
    uint32_t public_pid;
    uint8_t live;
    uint8_t bound;
    uint8_t disposed;
    uint8_t prepared;
} monitor_session_backend_t;

/* Before M's final role, prepare validates and borrows only the ready M
 * custody owner and verified nonblocking/CLOEXEC worker stream. Attach after
 * session creation performs no descriptor syscall and binds the already
 * PREBOUND server/classic sync monitor. Existing bind is the exact one-call
 * composition. Every path is one-shot; a failed attach never permits an
 * ordinary fallback. */
int monitor_session_backend_prepare(monitor_session_backend_t *,
                                    monitor_pty_custody_t *, int worker_fd);
int monitor_session_backend_attach(struct session *,
                                   monitor_session_backend_t *,
                                   sync_monitor_binding_t *);
int monitor_session_backend_bind(struct session *, monitor_session_backend_t *,
                                 sync_monitor_binding_t *,
                                 monitor_pty_custody_t *, int worker_fd);
int monitor_session_backend_is_bound(const struct session *);

/* Exactly one worker poll owner. PREBOUND/STOPPED sync has no interest. A
 * newly sealed source unit is immediate until service issues its STORE;
 * otherwise the worker stream cannot become readable. Service performs at
 * most one existing sync_monitor_service step. */
int monitor_session_backend_interest(const struct session *,
                                     monitor_session_backend_wait_t *);
int monitor_session_backend_service(struct session *, short revents);

/* Server classic PTY operations. OPEN/retire synchronously drive the already
 * adopted A1 custody owner; returned fds stay borrowed. */
int monitor_session_backend_open(struct session *, uint16_t rows,
                                 uint16_t columns, uint32_t *public_pid);
ssize_t monitor_session_backend_read(struct session *, void *, size_t);
ssize_t monitor_session_backend_write(struct session *, const void *, size_t);
int monitor_session_backend_resize(struct session *, uint16_t, uint16_t);
int monitor_session_backend_signal(struct session *, int signum);
int monitor_session_backend_retire(struct session *, int *exit_code);

/* Called only after channel close has retired/cleared the borrowed PTY view.
 * Detach clears the session pointer but never disposes custody or worker fd. */
int monitor_session_backend_detach(struct session *);
int monitor_session_backend_dispose(monitor_session_backend_t *);

#endif
