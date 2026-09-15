/*
 * attach_manager.c — channel-session fixed-storage local attach connection manager
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#define _POSIX_C_SOURCE 200809L

#include "attach_manager.h"

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <string.h>

#define ATTACH_MANAGER_SLOT_BITS 4U
#define ATTACH_MANAGER_SLOT_MASK UINT64_C(0x0f)

static int manager_ready(const attach_manager_t *manager)
{
    return manager != NULL && manager->initialized && manager->opened;
}

#ifdef UNMOOR_ATTACH_MANAGER_TEST
static attach_manager_t *attach_manager_test_stage_manager;
static attach_manager_owner_t attach_manager_test_stage_owner;
static unsigned int attach_manager_test_stage_failure_count;

int attach_manager_test_fail_next_result_stage(
    attach_manager_t *manager, attach_manager_owner_t owner)
{
    if (!manager_ready(manager) || owner == ATTACH_MANAGER_LISTENER_OWNER ||
        manager->opening_owner != owner ||
        attach_manager_test_stage_manager != NULL) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    attach_manager_test_stage_manager = manager;
    attach_manager_test_stage_owner = owner;
    return ATTACH_LOCAL_OK;
}

unsigned int attach_manager_test_result_stage_failures(void)
{
    return attach_manager_test_stage_failure_count;
}
#endif

static int output_pending(const attach_local_connection_t *connection)
{
    return connection->write_offset != connection->write_length;
}

static int owner_index(const attach_manager_t *manager,
                       attach_manager_owner_t owner, size_t *index_out)
{
    uint64_t low;
    size_t index;

    if (manager == NULL || index_out == NULL || owner == 0U)
        return 0;
    low = owner & ATTACH_MANAGER_SLOT_MASK;
    if (low == 0U || low > ATTACH_LOCAL_MAX_CONNECTIONS)
        return 0;
    index = (size_t)(low - 1U);
    if (manager->slots[index].state == ATTACH_MANAGER_STATE_FREE ||
        manager->slots[index].owner != owner)
        return 0;
    *index_out = index;
    return 1;
}

static void reset_slot(attach_manager_t *manager, size_t index)
{
    uint64_t incarnation = manager->slots[index].incarnation;

    if (manager->opening_owner == manager->slots[index].owner)
        manager->opening_owner = 0U;
    attach_local_connection_close(&manager->listener.connections[index]);
    memset(&manager->slots[index], 0, sizeof(manager->slots[index]));
    manager->slots[index].incarnation = incarnation;
    manager->slots[index].state = ATTACH_MANAGER_STATE_FREE;
}

/* Discard a record that can no longer reach its local peer. */
static void discard_outbound(attach_manager_t *manager, size_t index)
{
    attach_local_connection_t *connection =
        &manager->listener.connections[index];
    attach_manager_slot_t *slot = &manager->slots[index];

    connection->write_length = 0U;
    connection->write_offset = 0U;
    slot->outbound_type = 0U;
    slot->outbound_cookie = 0U;
    slot->outbound_payload_length = 0U;
    slot->close_pending = 0;
    slot->close_code = 0U;
}

static void quiesce_connection(attach_manager_t *manager, size_t index)
{
    attach_manager_slot_t *slot = &manager->slots[index];

    discard_outbound(manager, index);
    slot->input_quiesced = 1;
    slot->io_quiesced = 1;
}

/*
 * Cancellation is a separate retained fact, not an occupant of the one exact
 * input-record slot.  A complete causal record may therefore be delivered
 * first; next_event then synthesizes exactly one CANCEL.
 */
static void latch_cancel_event(attach_manager_t *manager, size_t index)
{
    attach_manager_slot_t *slot = &manager->slots[index];

    slot->cancel_pending = 1;
    slot->cancel_event_pending = 1;
    slot->state = ATTACH_MANAGER_STATE_CLOSING;
    slot->output_ended = 1;
    quiesce_connection(manager, index);
}

static int connection_failed(attach_manager_t *manager, size_t index,
                             int status)
{
    attach_manager_slot_t *slot = &manager->slots[index];

    if (slot->state == ATTACH_MANAGER_STATE_AWAIT_OPEN ||
        slot->state == ATTACH_MANAGER_STATE_OPEN_QUEUED) {
        reset_slot(manager, index);
        return status;
    }
    if (slot->state == ATTACH_MANAGER_STATE_OPENING) {
        slot->cancel_pending = 1;
        slot->input_quiesced = 1;
        quiesce_connection(manager, index);
        return status;
    }
    if (slot->state == ATTACH_MANAGER_STATE_RESULT_PENDING &&
        slot->result_code != 0U) {
        reset_slot(manager, index);
        return status;
    }
    if (slot->state == ATTACH_MANAGER_STATE_RESULT_PENDING ||
        slot->state == ATTACH_MANAGER_STATE_ACTIVE) {
        latch_cancel_event(manager, index);
        return status;
    }
    if (slot->state == ATTACH_MANAGER_STATE_CLOSING) {
        quiesce_connection(manager, index);
        return status;
    }
    return status;
}

static int protocol_failure(attach_manager_t *manager, size_t index)
{
    errno = EPROTO;
    return connection_failed(manager, index, ATTACH_LOCAL_ERR_PROTOCOL);
}

static int retain_input(attach_manager_slot_t *slot,
                        attach_manager_event_type_t type,
                        const attach_local_record_t *record, uint32_t code)
{
    if (slot->inbound_ready) {
        errno = EAGAIN;
        return ATTACH_LOCAL_WOULD_BLOCK;
    }
    slot->inbound_ready = 1;
    slot->inbound_type = type;
    slot->inbound_code = code;
    slot->inbound_record = *record;
    return ATTACH_LOCAL_OK;
}

static int retain_latest_resize(attach_manager_slot_t *slot,
                                const attach_local_record_t *record)
{
    slot->resize_record = *record;
    slot->resize_ready = 1;
    return ATTACH_LOCAL_OK;
}

static int classify_record(attach_manager_t *manager, size_t index,
                           const attach_local_record_t *record)
{
    attach_manager_slot_t *slot = &manager->slots[index];

    if (slot->state == ATTACH_MANAGER_STATE_AWAIT_OPEN) {
        if (record->type != (uint8_t)ATTACH_LOCAL_RECORD_OPEN)
            return protocol_failure(manager, index);
        slot->version = record->version;
        slot->kind = record->kind;
        slot->state = ATTACH_MANAGER_STATE_OPEN_QUEUED;
        return retain_input(slot, ATTACH_MANAGER_EVENT_OPEN, record, 0U);
    }

    if (record->version != slot->version)
        return protocol_failure(manager, index);

    /* No attach-to-session record is legal before accepted RESULT. */
    if (slot->state == ATTACH_MANAGER_STATE_OPEN_QUEUED ||
        slot->state == ATTACH_MANAGER_STATE_OPENING ||
        slot->state == ATTACH_MANAGER_STATE_RESULT_PENDING)
        return protocol_failure(manager, index);

    if (slot->state != ATTACH_MANAGER_STATE_ACTIVE)
        return protocol_failure(manager, index);

    if (slot->version == ATTACH_LOCAL_VERSION_V2) {
        uint32_t code = 0U;

        if (record->type != (uint8_t)ATTACH_LOCAL_RECORD_CLOSE ||
            attach_local_code_decode(record, ATTACH_LOCAL_RECORD_CLOSE,
                                     &code) != ATTACH_LOCAL_OK ||
            code < 5U || code > 7U)
            return protocol_failure(manager, index);
        slot->state = ATTACH_MANAGER_STATE_CLOSING;
        slot->input_quiesced = 1;
        return retain_input(slot, ATTACH_MANAGER_EVENT_CLOSE, record, code);
    }

    switch (record->type) {
    case ATTACH_LOCAL_RECORD_DATA:
        if (slot->input_eof)
            return protocol_failure(manager, index);
        return retain_input(slot, ATTACH_MANAGER_EVENT_DATA, record, 0U);
    case ATTACH_LOCAL_RECORD_EOF:
        if (slot->input_eof)
            return protocol_failure(manager, index);
        slot->input_eof = 1;
        return retain_input(slot, ATTACH_MANAGER_EVENT_EOF, record, 0U);
    case ATTACH_LOCAL_RECORD_RESIZE:
        if (slot->kind != 1U)
            return protocol_failure(manager, index);
        return retain_latest_resize(slot, record);
    case ATTACH_LOCAL_RECORD_SIGNAL:
        if (slot->kind != 1U && slot->kind != 2U)
            return protocol_failure(manager, index);
        return retain_input(slot, ATTACH_MANAGER_EVENT_SIGNAL, record, 0U);
    case ATTACH_LOCAL_RECORD_CLOSE:
        {
            uint32_t code = 0U;

            if (attach_local_code_decode(record,
                                         ATTACH_LOCAL_RECORD_CLOSE,
                                         &code) != ATTACH_LOCAL_OK ||
                code < 5U || code > 7U)
                return protocol_failure(manager, index);
            slot->state = ATTACH_MANAGER_STATE_CLOSING;
            slot->input_quiesced = 1;
            return retain_input(slot, ATTACH_MANAGER_EVENT_CLOSE, record,
                                code);
        }
    default:
        return protocol_failure(manager, index);
    }
}

/*
 * Arm the already-latched graceful CLOSE once every preceding local record
 * and, for DATA, its physical-delivery event have been consumed.
 */
static int queue_latched_close(attach_manager_t *manager, size_t index)
{
    attach_manager_slot_t *slot = &manager->slots[index];
    attach_local_connection_t *connection =
        &manager->listener.connections[index];
    attach_local_record_t record;
    int status;

    if (!slot->close_pending)
        return ATTACH_LOCAL_OK;
    if (connection->fd < 0 || slot->io_quiesced)
        return ATTACH_LOCAL_CLOSED;
    if (output_pending(connection) || slot->outbound_type != 0U ||
        slot->completion_ready) {
        errno = EAGAIN;
        return ATTACH_LOCAL_WOULD_BLOCK;
    }
    status = attach_local_close_version(slot->version, slot->close_code,
                                        &record);
    if (status != ATTACH_LOCAL_OK)
        return status;
    status = attach_local_connection_queue(connection, &record);
    if (status != ATTACH_LOCAL_OK)
        return status;
    slot->outbound_type = ATTACH_LOCAL_RECORD_CLOSE;
    return ATTACH_LOCAL_OK;
}

static int finish_outbound(attach_manager_t *manager, size_t index)
{
    attach_manager_slot_t *slot = &manager->slots[index];
    uint8_t type = slot->outbound_type;

    slot->outbound_type = 0U;
    if (type == (uint8_t)ATTACH_LOCAL_RECORD_RESULT) {
        if (slot->result_code == 0U) {
            if (slot->cancel_pending) {
                latch_cancel_event(manager, index);
                return ATTACH_LOCAL_OK;
            }
            slot->state = ATTACH_MANAGER_STATE_ACTIVE;
            return ATTACH_LOCAL_OK;
        }
        reset_slot(manager, index);
        return ATTACH_LOCAL_OK;
    }
    if (type == (uint8_t)ATTACH_LOCAL_RECORD_DATA) {
        slot->completion_ready = 1;
        slot->completion_cookie = slot->outbound_cookie;
        slot->completion_payload_length = slot->outbound_payload_length;
        slot->outbound_cookie = 0U;
        slot->outbound_payload_length = 0U;
        return ATTACH_LOCAL_OK;
    }
    if (type == (uint8_t)ATTACH_LOCAL_RECORD_EXIT)
        return queue_latched_close(manager, index);
    if (type == (uint8_t)ATTACH_LOCAL_RECORD_CLOSE) {
        slot->close_pending = 0;
        slot->close_code = 0U;
        slot->state = ATTACH_MANAGER_STATE_CLOSE_FLUSHED;
        slot->input_quiesced = 1;
        slot->io_quiesced = 1;
        return ATTACH_LOCAL_OK;
    }
    errno = EPROTO;
    return ATTACH_LOCAL_ERR_PROTOCOL;
}

static int service_connection(attach_manager_t *manager, size_t index,
                              short revents, int64_t now_ms)
{
    attach_local_connection_t *connection =
        &manager->listener.connections[index];
    attach_manager_slot_t *slot = &manager->slots[index];

    if ((revents & POLLNVAL) != 0)
        return connection_failed(manager, index, ATTACH_LOCAL_ERR_IO);

    /* Read first: a peer close cannot acknowledge an unfinished local DATA. */
    if (!slot->input_quiesced &&
        (!slot->inbound_ready ||
         slot->state == ATTACH_MANAGER_STATE_OPEN_QUEUED) &&
        connection->fd >= 0 &&
        (revents & (POLLIN | POLLHUP | POLLERR)) != 0) {
        attach_local_record_t record;
        int status = attach_local_connection_read(connection, now_ms, &record);

        if (status == ATTACH_LOCAL_FRAME_READY) {
            status = classify_record(manager, index, &record);
            if (status < 0)
                return status;
        } else if (status == ATTACH_LOCAL_CLOSED) {
            return connection_failed(manager, index, ATTACH_LOCAL_CLOSED);
        } else if (status < 0) {
            return connection_failed(manager, index, status);
        }
    }

    if (slot->state == ATTACH_MANAGER_STATE_FREE || connection->fd < 0 ||
        slot->io_quiesced)
        return ATTACH_LOCAL_OK;
    if ((revents & POLLOUT) != 0 && output_pending(connection)) {
        int status = attach_local_connection_flush(connection);

        if (status == ATTACH_LOCAL_OK)
            return finish_outbound(manager, index);
        if (status == ATTACH_LOCAL_WOULD_BLOCK &&
            (revents & (POLLHUP | POLLERR)) == 0)
            return status;
        if (status == ATTACH_LOCAL_WOULD_BLOCK)
            return connection_failed(
                manager, index,
                (revents & POLLHUP) != 0 ? ATTACH_LOCAL_CLOSED
                                         : ATTACH_LOCAL_ERR_IO);
        return connection_failed(manager, index, status);
    }
    /*
     * Darwin may report only POLLHUP after a local client has flushed CLOSE
     * and exited.  A CLOSING slot can still own a queued supervisor CLOSE,
     * so ignoring that bare hangup leaves the fixed slot and its child result
     * retained forever.  Read and a genuinely successful write above keep
     * their causal priority; otherwise peer loss physically quiesces every
     * non-free state without synthesizing delivery.
     */
    if ((revents & (POLLHUP | POLLERR)) != 0)
        return connection_failed(
            manager, index,
            (revents & POLLHUP) != 0 ? ATTACH_LOCAL_CLOSED
                                     : ATTACH_LOCAL_ERR_IO);
    return ATTACH_LOCAL_OK;
}

void attach_manager_init(attach_manager_t *manager)
{
    size_t i;

    if (manager == NULL)
        return;
    memset(manager, 0, sizeof(*manager));
    manager->listener.listen_fd = -1;
    manager->listener.base_fd = -1;
    manager->listener.directory_fd = -1;
    for (i = 0U; i < ATTACH_LOCAL_MAX_CONNECTIONS; i++)
        manager->listener.connections[i].fd = -1;
    manager->initialized = 1;
}

int attach_manager_open(attach_manager_t *manager,
                        const attach_local_listener_config_t *config)
{
    int status;

    if (manager == NULL || !manager->initialized || manager->opened) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    status = attach_local_listener_open(&manager->listener, config);
    if (status == ATTACH_LOCAL_OK)
        manager->opened = 1;
    return status;
}

int attach_manager_open_path(attach_manager_t *manager,
                             const char *absolute_path, uid_t uid)
{
    int status;

    if (manager == NULL || !manager->initialized || manager->opened) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    status = attach_local_listener_open_path(&manager->listener,
                                             absolute_path, uid);
    if (status == ATTACH_LOCAL_OK)
        manager->opened = 1;
    return status;
}

int attach_manager_prepare_path(attach_manager_t *manager,
                                const char *absolute_path, uid_t uid)
{
    if (manager == NULL || !manager->initialized || manager->opened) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    return attach_local_listener_prepare_path(&manager->listener,
                                              absolute_path, uid);
}

int attach_manager_bind_prepared(attach_manager_t *manager)
{
    int status;

    if (manager == NULL || !manager->initialized || manager->opened) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    status = attach_local_listener_bind_prepared(&manager->listener);
    if (status == ATTACH_LOCAL_OK)
        manager->opened = 1;
    return status;
}

int attach_manager_close(attach_manager_t *manager)
{
    int status = ATTACH_LOCAL_OK;
    size_t i;

    if (manager == NULL || !manager->initialized) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    /* client-confinement: a prepared-but-unbound listener still holds the runtime
     * directory and saved cwd descriptors, so close covers it too. */
    if (manager->opened || manager->listener.prepared)
        status = attach_local_listener_close(&manager->listener);
    for (i = 0U; i < ATTACH_LOCAL_MAX_CONNECTIONS; i++) {
        uint64_t incarnation = manager->slots[i].incarnation;

        memset(&manager->slots[i], 0, sizeof(manager->slots[i]));
        manager->slots[i].incarnation = incarnation;
    }
    manager->opening_owner = 0U;
    manager->event_cursor = 0U;
    manager->opened = 0;
#ifdef UNMOOR_ATTACH_MANAGER_TEST
    if (attach_manager_test_stage_manager == manager) {
        attach_manager_test_stage_manager = NULL;
        attach_manager_test_stage_owner = ATTACH_MANAGER_LISTENER_OWNER;
    }
#endif
    return status;
}

static short slot_poll_events(const attach_manager_t *manager, size_t index)
{
    const attach_manager_slot_t *slot = &manager->slots[index];
    const attach_local_connection_t *connection =
        &manager->listener.connections[index];
    short events = 0;

    if (slot->state == ATTACH_MANAGER_STATE_FREE || connection->fd < 0 ||
        slot->io_quiesced)
        return 0;
    if (!slot->input_quiesced &&
        (!slot->inbound_ready ||
         slot->state == ATTACH_MANAGER_STATE_OPEN_QUEUED) &&
        slot->state != ATTACH_MANAGER_STATE_CLOSING)
        events |= POLLIN;
    if (output_pending(connection))
        events |= POLLOUT;
    return events;
}

int attach_manager_poll_snapshot(const attach_manager_t *manager,
                                 attach_manager_poll_entry_t *entries,
                                 size_t capacity, size_t *count_out)
{
    size_t needed = 1U;
    size_t count = 0U;
    size_t i;

    if (!manager_ready(manager) || entries == NULL || count_out == NULL) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    for (i = 0U; i < ATTACH_LOCAL_MAX_CONNECTIONS; i++) {
        if (slot_poll_events(manager, i) != 0)
            needed++;
    }
    if (capacity < needed) {
        errno = ENOSPC;
        return ATTACH_LOCAL_ERR_CAPACITY;
    }
    entries[count].fd = manager->listener.listen_fd;
    entries[count].events = POLLIN;
    entries[count].owner = ATTACH_MANAGER_LISTENER_OWNER;
    count++;
    for (i = 0U; i < ATTACH_LOCAL_MAX_CONNECTIONS; i++) {
        short events = slot_poll_events(manager, i);

        if (events == 0)
            continue;
        entries[count].fd = manager->listener.connections[i].fd;
        entries[count].events = events;
        entries[count].owner = manager->slots[i].owner;
        count++;
    }
    *count_out = count;
    return ATTACH_LOCAL_OK;
}

static int accept_one(attach_manager_t *manager, int64_t now_ms)
{
    size_t index = SIZE_MAX;
    attach_manager_slot_t *slot;
    int status;

    status = attach_local_listener_accept(&manager->listener, now_ms, &index);
    if (status != ATTACH_LOCAL_OK)
        return status;
    if (index >= ATTACH_LOCAL_MAX_CONNECTIONS ||
        manager->slots[index].state != ATTACH_MANAGER_STATE_FREE) {
        if (index < ATTACH_LOCAL_MAX_CONNECTIONS)
            attach_local_connection_close(
                &manager->listener.connections[index]);
        errno = EPROTO;
        return ATTACH_LOCAL_ERR_PROTOCOL;
    }
    slot = &manager->slots[index];
    if (slot->incarnation >= (UINT64_MAX >> ATTACH_MANAGER_SLOT_BITS)) {
        attach_local_connection_close(&manager->listener.connections[index]);
        errno = EOVERFLOW;
        return ATTACH_LOCAL_ERR_CAPACITY;
    }
    slot->incarnation++;
    slot->owner =
        (slot->incarnation << ATTACH_MANAGER_SLOT_BITS) | (index + 1U);
    slot->state = ATTACH_MANAGER_STATE_AWAIT_OPEN;
    return ATTACH_LOCAL_OK;
}

int attach_manager_service(attach_manager_t *manager,
                           attach_manager_owner_t owner, short revents,
                           int64_t now_ms)
{
    size_t index;

    if (!manager_ready(manager)) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    if (owner == ATTACH_MANAGER_LISTENER_OWNER) {
        if ((revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            errno = EIO;
            return ATTACH_LOCAL_ERR_IO;
        }
        if ((revents & POLLIN) == 0)
            return ATTACH_LOCAL_OK;
        return accept_one(manager, now_ms);
    }
    if (!owner_index(manager, owner, &index))
        return ATTACH_LOCAL_CLOSED;
    return service_connection(manager, index, revents, now_ms);
}

int attach_manager_tick(attach_manager_t *manager, int64_t now_ms)
{
    size_t i;

    if (!manager_ready(manager)) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    for (i = 0U; i < ATTACH_LOCAL_MAX_CONNECTIONS; i++) {
        attach_manager_slot_t *slot = &manager->slots[i];

        if (slot->state == ATTACH_MANAGER_STATE_AWAIT_OPEN &&
            manager->listener.connections[i].fd >= 0) {
            int status = attach_local_parser_check_deadline(
                &manager->listener.connections[i].parser, now_ms);

            if (status == ATTACH_LOCAL_ERR_TIMEOUT)
                reset_slot(manager, i);
            else if (status < 0)
                return status;
        }
    }
    return ATTACH_LOCAL_OK;
}

int attach_manager_next_deadline(const attach_manager_t *manager,
                                 int64_t *deadline_ms_out)
{
    int found = 0;
    int64_t earliest = INT64_MAX;
    size_t i;

    if (!manager_ready(manager) || deadline_ms_out == NULL) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    for (i = 0U; i < ATTACH_LOCAL_MAX_CONNECTIONS; i++) {
        if (manager->slots[i].state == ATTACH_MANAGER_STATE_AWAIT_OPEN &&
            manager->listener.connections[i].fd >= 0) {
            int64_t deadline = manager->listener.connections[i]
                                   .parser.first_record_deadline_ms;

            if (!found || deadline < earliest)
                earliest = deadline;
            found = 1;
        }
    }
    if (!found)
        return ATTACH_LOCAL_WOULD_BLOCK;
    *deadline_ms_out = earliest;
    return ATTACH_LOCAL_OK;
}

static void fill_event(const attach_manager_slot_t *slot,
                       attach_manager_event_t *event,
                       attach_manager_event_type_t type)
{
    memset(event, 0, sizeof(*event));
    event->type = type;
    event->owner = slot->owner;
    event->handle = slot->handle;
    event->transfer_id = slot->transfer_id;
    event->version = slot->version;
    event->kind = slot->kind;
}

int attach_manager_next_event_filtered(attach_manager_t *manager,
                                       attach_manager_event_t *event_out,
                                       int allow_data)
{
    size_t offset;

    if (!manager_ready(manager) || event_out == NULL ||
        (allow_data != 0 && allow_data != 1)) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    for (offset = 0U; offset < ATTACH_LOCAL_MAX_CONNECTIONS; offset++) {
        size_t index = (manager->event_cursor + offset) %
                       ATTACH_LOCAL_MAX_CONNECTIONS;
        attach_manager_slot_t *slot = &manager->slots[index];

        if (slot->completion_ready) {
            fill_event(slot, event_out,
                       ATTACH_MANAGER_EVENT_DATA_DELIVERED);
            event_out->completion_cookie = slot->completion_cookie;
            event_out->payload_length = slot->completion_payload_length;
            slot->completion_ready = 0;
            slot->completion_cookie = 0U;
            slot->completion_payload_length = 0U;
            (void)queue_latched_close(manager, index);
            manager->event_cursor = (index + 1U) %
                                    ATTACH_LOCAL_MAX_CONNECTIONS;
            return ATTACH_LOCAL_FRAME_READY;
        }
        if (slot->resize_ready) {
            fill_event(slot, event_out, ATTACH_MANAGER_EVENT_RESIZE);
            event_out->record = slot->resize_record;
            event_out->payload_length = slot->resize_record.length;
            slot->resize_ready = 0;
            memset(&slot->resize_record, 0, sizeof(slot->resize_record));
            manager->event_cursor = (index + 1U) %
                                    ATTACH_LOCAL_MAX_CONNECTIONS;
            return ATTACH_LOCAL_FRAME_READY;
        }
        if (!slot->inbound_ready)
            goto maybe_cancel;
        if (!allow_data &&
            slot->inbound_type == ATTACH_MANAGER_EVENT_DATA)
            continue;
        if (slot->inbound_type == ATTACH_MANAGER_EVENT_OPEN &&
            manager->opening_owner != 0U)
            continue;
        fill_event(slot, event_out, slot->inbound_type);
        event_out->code = slot->inbound_code;
        event_out->record = slot->inbound_record;
        event_out->payload_length = slot->inbound_record.length;
        slot->inbound_ready = 0;
        slot->inbound_type = ATTACH_MANAGER_EVENT_NONE;
        slot->inbound_code = 0U;
        memset(&slot->inbound_record, 0, sizeof(slot->inbound_record));
        if (event_out->type == ATTACH_MANAGER_EVENT_OPEN) {
            slot->state = ATTACH_MANAGER_STATE_OPENING;
            manager->opening_owner = slot->owner;
        }
        manager->event_cursor = (index + 1U) %
                                ATTACH_LOCAL_MAX_CONNECTIONS;
        return ATTACH_LOCAL_FRAME_READY;

maybe_cancel:
        if (slot->cancel_event_pending) {
            fill_event(slot, event_out, ATTACH_MANAGER_EVENT_CANCEL);
            event_out->code = ATTACH_MANAGER_CLOSE_PROTOCOL;
            slot->cancel_event_pending = 0;
            manager->event_cursor = (index + 1U) %
                                    ATTACH_LOCAL_MAX_CONNECTIONS;
            return ATTACH_LOCAL_FRAME_READY;
        }
    }
    return ATTACH_LOCAL_WOULD_BLOCK;
}

int attach_manager_next_event(attach_manager_t *manager,
                              attach_manager_event_t *event_out)
{
    return attach_manager_next_event_filtered(manager, event_out, 1);
}

static int stage_result(attach_manager_t *manager, size_t index,
                        attach_manager_owner_t owner,
                        const attach_local_record_t *record)
{
    (void)owner;
#ifdef UNMOOR_ATTACH_MANAGER_TEST
    if (attach_manager_test_stage_manager == manager &&
        attach_manager_test_stage_owner == owner) {
        attach_manager_test_stage_manager = NULL;
        attach_manager_test_stage_owner = ATTACH_MANAGER_LISTENER_OWNER;
        attach_manager_test_stage_failure_count++;
        errno = EIO;
        return ATTACH_LOCAL_ERR_IO;
    }
#endif
    return attach_local_connection_queue(
        &manager->listener.connections[index], record);
}

static int queue_result(attach_manager_t *manager,
                        attach_manager_owner_t owner,
                        uint8_t version, uint32_t handle, uint32_t code,
                        uint64_t transfer_id)
{
    attach_local_record_t record;
    attach_manager_slot_t *slot;
    size_t index;
    int status;

    if (!manager_ready(manager)) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    if (!owner_index(manager, owner, &index))
        return ATTACH_LOCAL_CLOSED;
    slot = &manager->slots[index];
    if (slot->state != ATTACH_MANAGER_STATE_OPENING ||
        manager->opening_owner != owner || slot->version != version) {
        errno = EPROTO;
        return ATTACH_LOCAL_ERR_PROTOCOL;
    }
    status = version == ATTACH_LOCAL_VERSION_V1
        ? attach_local_result(handle, code, &record)
        : attach_local_bulk_result(handle, code, transfer_id, &record);
    if (status != ATTACH_LOCAL_OK) {
        errno = EPROTO;
        return ATTACH_LOCAL_ERR_PROTOCOL;
    }

    if (slot->cancel_pending ||
        manager->listener.connections[index].fd < 0) {
        manager->opening_owner = 0U;
        if (code == 0U) {
            slot->handle = handle;
            slot->result_code = 0U;
            slot->transfer_id = transfer_id;
            latch_cancel_event(manager, index);
            return ATTACH_LOCAL_OK;
        }
        reset_slot(manager, index);
        return ATTACH_LOCAL_OK;
    }
    status = stage_result(manager, index, owner, &record);
    if (status != ATTACH_LOCAL_OK) {
        int saved_errno = errno;

        /* A claimed OPEN has no retryable local RESULT staging state. Close
         * and recycle its exact attach incarnation before releasing the
         * global OPEN barrier; the session caller separately retires any
         * application or child resource allocated for this owner. */
        reset_slot(manager, index);
        errno = saved_errno;
        return status;
    }
    slot->handle = code == 0U ? handle : 0U;
    slot->result_code = code;
    slot->transfer_id = code == 0U ? transfer_id : 0U;
    slot->outbound_type = ATTACH_LOCAL_RECORD_RESULT;
    slot->state = ATTACH_MANAGER_STATE_RESULT_PENDING;
    manager->opening_owner = 0U;
    return ATTACH_LOCAL_OK;
}

int attach_manager_queue_result(attach_manager_t *manager,
                                attach_manager_owner_t owner,
                                uint32_t handle, uint32_t code)
{
    return queue_result(manager, owner, ATTACH_LOCAL_VERSION_V1,
                        handle, code, 0U);
}

int attach_manager_queue_bulk_result(attach_manager_t *manager,
                                     attach_manager_owner_t owner,
                                     uint32_t handle, uint32_t code,
                                     uint64_t transfer_id)
{
    return queue_result(manager, owner, ATTACH_LOCAL_VERSION_V2,
                        handle, code, transfer_id);
}

static int can_queue_output(const attach_manager_t *manager, size_t index)
{
    const attach_manager_slot_t *slot = &manager->slots[index];
    const attach_local_connection_t *connection =
        &manager->listener.connections[index];

    return connection->fd >= 0 && !slot->io_quiesced &&
           !output_pending(connection) &&
           !slot->completion_ready;
}

int attach_manager_queue_data(attach_manager_t *manager,
                              attach_manager_owner_t owner,
                              const uint8_t *data, size_t length,
                              uint64_t completion_cookie)
{
    attach_local_record_t record;
    attach_manager_slot_t *slot;
    size_t index;
    int status;

    if (!manager_ready(manager)) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    if (!owner_index(manager, owner, &index))
        return ATTACH_LOCAL_CLOSED;
    slot = &manager->slots[index];
    if (slot->state != ATTACH_MANAGER_STATE_ACTIVE || slot->output_ended ||
        slot->version != ATTACH_LOCAL_VERSION_V1) {
        errno = EPROTO;
        return ATTACH_LOCAL_ERR_PROTOCOL;
    }
    if (!can_queue_output(manager, index)) {
        errno = EAGAIN;
        return ATTACH_LOCAL_WOULD_BLOCK;
    }
    status = attach_local_data(data, length, &record);
    if (status != ATTACH_LOCAL_OK)
        return status;
    status = attach_local_connection_queue(
        &manager->listener.connections[index], &record);
    if (status != ATTACH_LOCAL_OK)
        return status;
    slot->outbound_type = ATTACH_LOCAL_RECORD_DATA;
    slot->outbound_cookie = completion_cookie;
    slot->outbound_payload_length = length;
    return ATTACH_LOCAL_OK;
}

int attach_manager_queue_exit(attach_manager_t *manager,
                              attach_manager_owner_t owner, int32_t code)
{
    attach_local_record_t record;
    attach_manager_slot_t *slot;
    size_t index;
    int status;

    if (!manager_ready(manager)) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    if (!owner_index(manager, owner, &index))
        return ATTACH_LOCAL_CLOSED;
    slot = &manager->slots[index];
    if (slot->state != ATTACH_MANAGER_STATE_ACTIVE || slot->output_ended ||
        slot->version != ATTACH_LOCAL_VERSION_V1) {
        errno = EPROTO;
        return ATTACH_LOCAL_ERR_PROTOCOL;
    }
    if (!can_queue_output(manager, index)) {
        errno = EAGAIN;
        return ATTACH_LOCAL_WOULD_BLOCK;
    }
    status = attach_local_exit((uint32_t)code, &record);
    if (status != ATTACH_LOCAL_OK)
        return status;
    status = attach_local_connection_queue(
        &manager->listener.connections[index], &record);
    if (status != ATTACH_LOCAL_OK)
        return status;
    slot->outbound_type = ATTACH_LOCAL_RECORD_EXIT;
    slot->output_ended = 1;
    return ATTACH_LOCAL_OK;
}

int attach_manager_queue_close(attach_manager_t *manager,
                               attach_manager_owner_t owner, uint32_t code)
{
    attach_manager_slot_t *slot;
    size_t index;

    if (!manager_ready(manager)) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    if (!owner_index(manager, owner, &index))
        return ATTACH_LOCAL_CLOSED;
    slot = &manager->slots[index];
    if (slot->state != ATTACH_MANAGER_STATE_ACTIVE &&
        slot->state != ATTACH_MANAGER_STATE_CLOSING) {
        errno = EPROTO;
        return ATTACH_LOCAL_ERR_PROTOCOL;
    }
    if (slot->io_quiesced ||
        manager->listener.connections[index].fd < 0)
        return ATTACH_LOCAL_CLOSED;
    if (slot->close_pending) {
        if (slot->close_code == code)
            return ATTACH_LOCAL_OK;
        errno = EPROTO;
        return ATTACH_LOCAL_ERR_PROTOCOL;
    }
    slot->close_pending = 1;
    slot->close_code = code;
    slot->output_ended = 1;
    slot->input_quiesced = 1;
    slot->state = ATTACH_MANAGER_STATE_CLOSING;
    if (output_pending(&manager->listener.connections[index]) ||
        slot->outbound_type != 0U || slot->completion_ready)
        return ATTACH_LOCAL_OK;
    return queue_latched_close(manager, index);
}

int attach_manager_release(attach_manager_t *manager,
                           attach_manager_owner_t owner)
{
    size_t index;

    if (!manager_ready(manager) ||
        !owner_index(manager, owner, &index))
        return ATTACH_LOCAL_CLOSED;
    if (manager->slots[index].state !=
            ATTACH_MANAGER_STATE_CLOSE_FLUSHED &&
        !(manager->slots[index].state == ATTACH_MANAGER_STATE_CLOSING &&
          manager->slots[index].io_quiesced)) {
        errno = EBUSY;
        return ATTACH_LOCAL_WOULD_BLOCK;
    }
    if (manager->slots[index].cancel_event_pending) {
        errno = EBUSY;
        return ATTACH_LOCAL_WOULD_BLOCK;
    }
    reset_slot(manager, index);
    return ATTACH_LOCAL_OK;
}

int attach_manager_connection_info(
    const attach_manager_t *manager, attach_manager_owner_t owner,
    attach_manager_connection_info_t *info_out)
{
    const attach_manager_slot_t *slot;
    size_t index;

    if (!manager_ready(manager) || info_out == NULL) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    if (!owner_index(manager, owner, &index))
        return ATTACH_LOCAL_CLOSED;
    slot = &manager->slots[index];
    memset(info_out, 0, sizeof(*info_out));
    info_out->state = slot->state;
    info_out->owner = slot->owner;
    info_out->handle = slot->handle;
    info_out->transfer_id = slot->transfer_id;
    info_out->version = slot->version;
    info_out->kind = slot->kind;
    info_out->input_eof = slot->input_eof;
    info_out->cancel_pending = slot->cancel_pending;
    info_out->input_quiesced = slot->input_quiesced;
    info_out->close_pending = slot->close_pending;
    info_out->outbound_pending =
        output_pending(&manager->listener.connections[index]) ||
        slot->completion_ready || slot->close_pending;
    return ATTACH_LOCAL_OK;
}

size_t attach_manager_connection_count(const attach_manager_t *manager)
{
    size_t count = 0U;
    size_t i;

    if (manager == NULL || !manager->initialized)
        return 0U;
    for (i = 0U; i < ATTACH_LOCAL_MAX_CONNECTIONS; i++) {
        if (manager->slots[i].state != ATTACH_MANAGER_STATE_FREE)
            count++;
    }
    return count;
}
