/*
 * monitor_endpoint.h — fixed listener-monitor M-side session binding owner
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * Contract: the listener-monitor runtime bridge.  This object binds the
 * existing source/sync/session engine; it is not a process constructor or
 * IPC service.
 */
#ifndef UNMOOR_MONITOR_ENDPOINT_H
#define UNMOOR_MONITOR_ENDPOINT_H

#include "monitor_session_backend.h"
#include "sync_source_map.h"

#include <stdint.h>

struct session;

typedef struct d28_monitor_endpoint {
    sync_source_t source;
    sync_work_carriage_t work;
    sync_monitor_binding_t binding;
    sync_source_reader_t reader;
    monitor_session_backend_t backend;
    sync_source_map_t *map;
    monitor_pty_custody_t *custody;
    uint64_t incarnation;
    uint64_t quota;
    int worker_fd;
    int failure_errno;
    uint8_t prepared;
    uint8_t source_ready;
    uint8_t work_ready;
    uint8_t bound;
    uint8_t disposed;
    uint8_t reserved[3];
} d28_monitor_endpoint_t;

/* Fresh M-owned storage after the map is monitor-RO and custody has consumed
 * LAUNCH. Validates the worker stream now, before M installs its final role.
 * All referenced owners and the descriptor remain externally owned/borrowed. */
int d28_monitor_endpoint_prepare(d28_monitor_endpoint_t *,
                                 sync_source_map_t *,
                                 monitor_pty_custody_t *,
                                 int worker_fd,
                                 uint64_t incarnation,
                                 uint64_t quota);

/* Newly created server/classic session only. Initializes the existing source
 * and monitor carriage, binds sync, then performs the syscall-free backend
 * attach. Failure is sticky and requires ordinary session destruction. */
int d28_monitor_endpoint_bind_session(d28_monitor_endpoint_t *,
                                      struct session *);

/* Only after session destruction detached the backend and cleared the sync
 * reference. Retires owned source/work metadata but never closes the borrowed
 * worker/custody/map resources; exact worker shutdown/wipe remains outer. */
int d28_monitor_endpoint_dispose(d28_monitor_endpoint_t *);

#endif /* UNMOOR_MONITOR_ENDPOINT_H */
