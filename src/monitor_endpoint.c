/*
 * monitor_endpoint.c — fixed listener-monitor M-side session binding owner
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#include "monitor_endpoint.h"
#include "session.h"

#include <errno.h>
#include <string.h>

static int error_with(int cause)
{
    errno = cause > 0 ? cause : EIO;
    return -1;
}

static int zero_owner(const d28_monitor_endpoint_t *owner)
{
    static const d28_monitor_endpoint_t empty;
    return owner != NULL && memcmp(owner, &empty, sizeof(empty)) == 0;
}

static int map_matches(const sync_source_map_t *map, uint64_t quota)
{
    size_t slots = 0, records = 0, bytes = 0;
    return map != NULL && map->state == SYNC_SOURCE_MAP_MONITOR_RO &&
           map->failure == 0 && map->payload != NULL &&
           map->control != NULL && map->nrecords != 0U &&
           sync_source_geometry(quota, &slots, &records, &bytes) == 0 &&
           slots != 0U && records == map->nrecords && bytes != 0U;
}

static int map_publication(const void *context, uint64_t *publication)
{
    return sync_source_map_publication(context, publication);
}

int d28_monitor_endpoint_prepare(d28_monitor_endpoint_t *owner,
                                 sync_source_map_t *map,
                                 monitor_pty_custody_t *custody,
                                 int worker_fd,
                                 uint64_t incarnation,
                                 uint64_t quota)
{
    d28_monitor_endpoint_t initialized;
    if (!zero_owner(owner) || incarnation == 0U ||
        !map_matches(map, quota))
        return error_with(EINVAL);
    memset(&initialized, 0, sizeof(initialized));
    initialized.map = map;
    initialized.custody = custody;
    initialized.incarnation = incarnation;
    initialized.quota = quota;
    initialized.worker_fd = worker_fd;
    if (monitor_session_backend_prepare(&initialized.backend, custody,
                                        worker_fd) != 0)
        return -1;
    initialized.prepared = 1U;
    *owner = initialized;
    return 0;
}

int d28_monitor_endpoint_bind_session(d28_monitor_endpoint_t *owner,
                                      struct session *session)
{
    if (owner == NULL || session == NULL || owner->prepared != 1U ||
        owner->disposed != 0U || owner->bound != 0U ||
        owner->failure_errno != 0 || !map_matches(owner->map, owner->quota) ||
        !session->is_server || session->services_started ||
        session->channelised_requested || session->bulk_enabled ||
        session->sync_monitor != NULL || session->monitor_backend != NULL)
        return error_with(EINVAL);

    if (sync_source_init(&owner->source, owner->quota,
                         owner->incarnation, 1U) != SYNC_SOURCE_OK) {
        owner->failure_errno = ENOMEM;
        return error_with(owner->failure_errno);
    }
    owner->source_ready = 1U;
    if (sync_work_carriage_init(&owner->work, SYNC_WORK_MONITOR,
                                owner->incarnation, 1U) != SYNC_WORK_OK) {
        owner->failure_errno = EIO;
        return error_with(owner->failure_errno);
    }
    owner->work_ready = 1U;
    owner->reader.context = owner->map;
    owner->reader.read_unit = sync_source_map_read_unit;
    owner->reader.nrecords = owner->map->nrecords;
    if (sync_monitor_bind(session, &owner->binding, &owner->source,
                          &owner->work, &owner->reader,
                          map_publication,
                          owner->map) != 0 ||
        monitor_session_backend_attach(session, &owner->backend,
                                       &owner->binding) != 0) {
        owner->failure_errno = errno ? errno : EIO;
        return error_with(owner->failure_errno);
    }
    owner->bound = 1U;
    return 0;
}

int d28_monitor_endpoint_dispose(d28_monitor_endpoint_t *owner)
{
    int cause;
    if (owner == NULL)
        return error_with(EINVAL);
    if (owner->disposed != 0U) {
        cause = owner->failure_errno;
        return cause ? error_with(cause) : 0;
    }
    if (owner->backend.bound != 0U || owner->backend.session != NULL ||
        owner->binding.session != NULL)
        return error_with(EBUSY);
    if (owner->backend.prepared != 0U &&
        monitor_session_backend_dispose(&owner->backend) != 0 &&
        owner->failure_errno == 0)
        owner->failure_errno = errno ? errno : EIO;
    if (owner->work_ready != 0U) {
        if (sync_work_retire(&owner->work) != SYNC_WORK_OK &&
            owner->failure_errno == 0)
            owner->failure_errno = EIO;
        owner->work_ready = 0U;
    }
    if (owner->source_ready != 0U) {
        sync_source_free(&owner->source);
        owner->source_ready = 0U;
    }
    memset(&owner->binding, 0, sizeof(owner->binding));
    memset(&owner->reader, 0, sizeof(owner->reader));
    owner->bound = 0U;
    owner->disposed = 1U;
    cause = owner->failure_errno;
    return cause ? error_with(cause) : 0;
}
