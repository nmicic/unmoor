/*
 * sync_work_carriage.c — local fixed-credit work stream
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#include "sync_work_carriage.h"
#include "crypto.h"
#include <string.h>

_Static_assert(sizeof(sync_work_cell_t) == 24, "cell budget");
_Static_assert(sizeof(sync_work_control_t) == 80, "control budget");
_Static_assert(sizeof(sync_work_workspace_t) == 248, "workspace budget");
_Static_assert(sizeof(sync_work_carriage_t) <= SYNC_WORK_ROLE_BYTES_MAX,
               "carriage owner budget");

enum { CELL_FREE, CELL_REQUEST, CELL_WAIT, CELL_RESPONSE, CELL_READY };
enum { STORE_CELL, PLAN_CELL, NO_CELL };

static int live(const sync_work_carriage_t *c)
{
    return c != NULL && c->control.initialized == 1U &&
           (c->control.role == SYNC_WORK_MONITOR ||
            c->control.role == SYNC_WORK_WORKER);
}

static int mutable(const sync_work_carriage_t *c, uint8_t role)
{
    if (!live(c) || c->control.in_step || (role && c->control.role != role))
        return SYNC_WORK_INVALID;
    return c->control.failure ? SYNC_WORK_FAILED : SYNC_WORK_OK;
}

static int fail(sync_work_carriage_t *c, uint32_t reason)
{
    if (c->control.failure == SYNC_WORK_FAIL_NONE)
        c->control.failure = reason;
    return SYNC_WORK_FAILED;
}

static size_t request_size(unsigned cell)
{
    return cell == STORE_CELL ? SYNC_WORK_STORE_BYTES : SYNC_WORK_PLAN_BYTES;
}

static size_t response_size(unsigned cell)
{
    return cell == STORE_CELL ? SYNC_WORK_STORED_BYTES : SYNC_WORK_PLANNED_BYTES;
}

static uint8_t *request(sync_work_carriage_t *c, unsigned cell)
{
    return cell == STORE_CELL ? c->store_request : c->plan_request;
}

static uint8_t *response(sync_work_carriage_t *c, unsigned cell)
{
    return cell == STORE_CELL ? c->stored_response : c->planned_response;
}

static void release_cell(sync_work_carriage_t *c, unsigned cell)
{
    crypto_memzero(request(c, cell), request_size(cell));
    crypto_memzero(response(c, cell), response_size(cell));
    crypto_memzero(&c->control.cell[cell], sizeof(c->control.cell[cell]));
    if (c->control.tx_cell == cell)
        c->control.tx_cell = NO_CELL;
    if (c->control.rx_cell == cell)
        c->control.rx_cell = NO_CELL;
}

static unsigned oldest(const sync_work_carriage_t *c, uint8_t state)
{
    unsigned selected = NO_CELL;
    for (unsigned i = 0; i < NO_CELL; ++i)
        if (c->control.cell[i].state == state &&
            (selected == NO_CELL ||
             c->control.cell[i].operation < c->control.cell[selected].operation))
            selected = i;
    return selected;
}

int sync_work_carriage_init(sync_work_carriage_t *c, uint8_t role,
                            uint64_t incarnation, uint8_t direction)
{
    if (c == NULL || incarnation == 0U || direction > 1U ||
        (role != SYNC_WORK_MONITOR && role != SYNC_WORK_WORKER))
        return SYNC_WORK_INVALID;
    const uint8_t *bytes = (const uint8_t *)c;
    for (size_t i = 0; i < sizeof(*c); ++i)
        if (bytes[i] != 0U)
            return SYNC_WORK_INVALID;
    c->control.role = role;
    c->control.incarnation = incarnation;
    c->control.direction = direction;
    c->control.tx_cell = NO_CELL;
    c->control.rx_cell = NO_CELL;
    c->control.initialized = 1;
    return SYNC_WORK_OK;
}

static int begin_check(sync_work_carriage_t *c, unsigned cell, uint64_t *operation)
{
    if (operation != NULL)
        *operation = 0;
    int rc = mutable(c, SYNC_WORK_MONITOR);
    if (rc != SYNC_WORK_OK)
        return rc;
    if (operation == NULL)
        return SYNC_WORK_INVALID;
    if (c->control.cell[cell].state != CELL_FREE)
        return SYNC_WORK_BUSY;
    return c->control.serial == UINT64_MAX ? SYNC_WORK_EXHAUSTED : SYNC_WORK_OK;
}

static sync_work_header_t new_header(const sync_work_carriage_t *c, uint8_t type,
                                      uint64_t operation)
{
    sync_work_header_t h = {0};
    h.incarnation = c->control.incarnation;
    h.operation = operation;
    h.type = type;
    h.direction = c->control.direction;
    return h;
}

static int begin_publish(sync_work_carriage_t *c, unsigned cell, uint64_t *operation)
{
    sync_work_cell_t *slot = &c->control.cell[cell];
    slot->operation = ++c->control.serial;
    slot->state = CELL_REQUEST;
    *operation = slot->operation;
    return SYNC_WORK_OK;
}

int sync_work_begin_store(sync_work_carriage_t *c, uint64_t offset,
                          const uint8_t unit[SYNC_WORK_UNIT], uint64_t *operation)
{
    int rc = begin_check(c, STORE_CELL, operation);
    if (rc != SYNC_WORK_OK)
        return rc;
    sync_work_header_t h = new_header(c, SYNC_WORK_STORE, c->control.serial + 1U);
    if (sync_work_store_encode(c->store_request, sizeof(c->store_request),
                               &h, offset, unit) != 0)
        return SYNC_WORK_INVALID;
    return begin_publish(c, STORE_CELL, operation);
}

int sync_work_begin_plan(sync_work_carriage_t *c, const sync_repair_view_t *view,
                         uint64_t *operation)
{
    int rc = begin_check(c, PLAN_CELL, operation);
    if (rc != SYNC_WORK_OK)
        return rc;
    sync_work_header_t h = new_header(c, SYNC_WORK_PLAN, c->control.serial + 1U);
    if (sync_work_plan_encode(c->plan_request, sizeof(c->plan_request), &h, view) != 0)
        return SYNC_WORK_INVALID;
    return begin_publish(c, PLAN_CELL, operation);
}

static int take_check(sync_work_carriage_t *c, unsigned cell, uint64_t operation)
{
    int rc = mutable(c, SYNC_WORK_MONITOR);
    if (rc != SYNC_WORK_OK)
        return rc;
    const sync_work_cell_t *slot = &c->control.cell[cell];
    if (operation == 0U || slot->state == CELL_FREE || slot->operation != operation)
        return SYNC_WORK_INVALID;
    return slot->state == CELL_READY ? SYNC_WORK_OK : SYNC_WORK_NOT_READY;
}

static int decode_plan_result(sync_work_carriage_t *c)
{
    sync_work_workspace_t *w = &c->workspace;
    if (sync_work_planned_decode(&w->header, &w->result, c->planned_response,
                                  sizeof(c->planned_response)) != 0 ||
        sync_work_plan_decode(&w->header, &w->input.view, c->plan_request,
                               sizeof(c->plan_request)) != 0)
        return fail(c, SYNC_WORK_FAIL_FRAME);
    if (sync_repair_plan_check(&w->input.view, &w->result) != 0)
        return fail(c, SYNC_WORK_FAIL_RESULT);
    return SYNC_WORK_OK;
}

int sync_work_take_stored(sync_work_carriage_t *c, uint64_t operation,
                          sync_work_header_t *header, uint8_t *status)
{
    if (header != NULL)
        memset(header, 0, sizeof(*header));
    if (status != NULL)
        *status = 0;
    int rc = take_check(c, STORE_CELL, operation);
    if (rc != SYNC_WORK_OK)
        return rc;
    if (header == NULL || status == NULL)
        return SYNC_WORK_INVALID;
    if (sync_work_stored_decode(&c->workspace.header, &c->workspace.stored_status,
                                 c->stored_response, sizeof(c->stored_response)) != 0)
        rc = fail(c, SYNC_WORK_FAIL_FRAME);
    else {
        *header = c->workspace.header;
        *status = c->workspace.stored_status;
        release_cell(c, STORE_CELL);
    }
    crypto_memzero(&c->workspace, sizeof(c->workspace));
    return rc;
}

int sync_work_take_planned(sync_work_carriage_t *c, uint64_t operation,
                           sync_repair_view_t *view, sync_repair_result_t *result)
{
    if (view != NULL)
        memset(view, 0, sizeof(*view));
    if (result != NULL)
        memset(result, 0, sizeof(*result));
    int rc = take_check(c, PLAN_CELL, operation);
    if (rc != SYNC_WORK_OK)
        return rc;
    if (view == NULL || result == NULL)
        return SYNC_WORK_INVALID;
    rc = decode_plan_result(c);
    if (rc == SYNC_WORK_OK) {
        *view = c->workspace.input.view;
        *result = c->workspace.result;
        release_cell(c, PLAN_CELL);
    }
    crypto_memzero(&c->workspace, sizeof(c->workspace));
    return rc;
}

int sync_work_cancel_plan(sync_work_carriage_t *c, uint64_t operation)
{
    int rc = mutable(c, SYNC_WORK_MONITOR);
    if (rc != SYNC_WORK_OK)
        return rc;
    sync_work_cell_t *slot = &c->control.cell[PLAN_CELL];
    if (operation == 0U || slot->state == CELL_FREE || slot->operation != operation)
        return SYNC_WORK_INVALID;
    if ((slot->state == CELL_REQUEST && slot->request_at == 0U) ||
        slot->state == CELL_READY)
        release_cell(c, PLAN_CELL);
    else
        slot->canceled = 1;
    return SYNC_WORK_OK;
}

unsigned sync_work_interests(const sync_work_carriage_t *c)
{
    if (!live(c) || c->control.failure)
        return 0;
    unsigned interest = SYNC_WORK_READ;
    uint8_t state = c->control.role == SYNC_WORK_MONITOR ? CELL_REQUEST : CELL_RESPONSE;
    if (oldest(c, state) != NO_CELL)
        interest |= SYNC_WORK_WRITE;
    if (c->control.role == SYNC_WORK_WORKER) {
        if (oldest(c, CELL_READY) != NO_CELL)
            interest |= SYNC_WORK_LOCAL;
    } else {
        if (c->control.cell[STORE_CELL].state == CELL_READY)
            interest |= SYNC_WORK_STORED_READY;
        if (c->control.cell[PLAN_CELL].state == CELL_READY)
            interest |= SYNC_WORK_PLANNED_READY;
    }
    return interest;
}

/* The header is complete and held in owned probe storage. Do not reserve a
 * body or copy any body bytes until role/source/credit checks have passed. */
static int receive_header(sync_work_carriage_t *c)
{
    sync_work_header_t *h = &c->workspace.header;
    if (sync_work_header_decode(h, c->probe, sizeof(c->probe)) != 0)
        return fail(c, SYNC_WORK_FAIL_FRAME);
    int monitor = c->control.role == SYNC_WORK_MONITOR;
    unsigned cell;
    if (h->type == (monitor ? SYNC_WORK_STORED : SYNC_WORK_STORE))
        cell = STORE_CELL;
    else if (h->type == (monitor ? SYNC_WORK_PLANNED : SYNC_WORK_PLAN))
        cell = PLAN_CELL;
    else
        return fail(c, SYNC_WORK_FAIL_IDENTITY);
    sync_work_cell_t *slot = &c->control.cell[cell];
    if (h->incarnation != c->control.incarnation || h->direction != c->control.direction ||
        (monitor ? slot->state != CELL_WAIT || slot->operation != h->operation :
                   slot->state != CELL_FREE || h->operation <= c->control.serial))
        return fail(c, SYNC_WORK_FAIL_IDENTITY);
    if (monitor) {
        memcpy(response(c, cell), c->probe, sizeof(c->probe));
        slot->response_at = SYNC_WORK_HEADER;
        slot->state = CELL_RESPONSE;
    } else {
        memcpy(request(c, cell), c->probe, sizeof(c->probe));
        slot->request_at = SYNC_WORK_HEADER;
        slot->operation = h->operation;
        slot->state = CELL_REQUEST;
    }
    c->control.rx_cell = (uint8_t)cell;
    c->control.probe_used = 0;
    crypto_memzero(c->probe, sizeof(c->probe));
    return SYNC_WORK_OK;
}

static int receive_complete(sync_work_carriage_t *c, unsigned cell)
{
    sync_work_workspace_t *w = &c->workspace;
    sync_work_cell_t *slot = &c->control.cell[cell];
    int monitor = c->control.role == SYNC_WORK_MONITOR;
    int rc;
    if (monitor) {
        rc = cell == STORE_CELL ?
            sync_work_stored_decode(&w->header, &w->stored_status,
                                     c->stored_response, sizeof(c->stored_response)) :
            decode_plan_result(c);
    } else {
        rc = cell == STORE_CELL ?
            sync_work_store_decode(&w->header, &w->input.store.offset,
                                    &w->input.store.unit, c->store_request,
                                    sizeof(c->store_request)) :
            sync_work_plan_decode(&w->header, &w->input.view, c->plan_request,
                                   sizeof(c->plan_request));
    }
    if (rc != 0)
        return fail(c, SYNC_WORK_FAIL_FRAME); /* preserves a prior RESULT reason */
    if (!monitor)
        c->control.serial = slot->operation;
    slot->state = CELL_READY;
    c->control.rx_cell = NO_CELL;
    if (monitor && slot->canceled)
        release_cell(c, cell);
    crypto_memzero(w, sizeof(*w));
    return SYNC_WORK_OK;
}

static int io_count(sync_work_carriage_t *c, ptrdiff_t count, size_t offered,
                     int writing)
{
    if (count == SYNC_WORK_IO_AGAIN || count == SYNC_WORK_IO_INTR)
        return SYNC_WORK_OK;
    if (count == SYNC_WORK_IO_ERROR)
        return fail(c, SYNC_WORK_FAIL_IO);
    if (count < 0 || (size_t)count > offered)
        return fail(c, SYNC_WORK_FAIL_CALLBACK);
    if (count == 0)
        return fail(c, writing ? SYNC_WORK_FAIL_IO : SYNC_WORK_FAIL_EOF);
    return SYNC_WORK_OK;
}

static int read_stage(sync_work_carriage_t *c, const sync_work_io_t *io)
{
    size_t budget = SYNC_WORK_STEP_BYTES;
    for (unsigned call = 0; call < SYNC_WORK_STEP_CALLS && budget != 0U; ++call) {
        unsigned cell = c->control.rx_cell;
        uint32_t *at;
        uint8_t *buffer;
        size_t length;
        if (cell == NO_CELL) {
            at = &c->control.probe_used;
            buffer = c->probe;
            length = sizeof(c->probe);
        } else if (c->control.role == SYNC_WORK_MONITOR) {
            at = &c->control.cell[cell].response_at;
            buffer = response(c, cell);
            length = response_size(cell);
        } else {
            at = &c->control.cell[cell].request_at;
            buffer = request(c, cell);
            length = request_size(cell);
        }
        if (*at >= length)
            return fail(c, SYNC_WORK_FAIL_FRAME);
        size_t offered = length - *at;
        if (offered > budget)
            offered = budget;
        ptrdiff_t count = io->read(io->context, buffer + *at, offered);
        if (io_count(c, count, offered, 0) != SYNC_WORK_OK)
            return SYNC_WORK_FAILED;
        if (count == SYNC_WORK_IO_AGAIN)
            break;
        if (count == SYNC_WORK_IO_INTR)
            continue;
        *at += (uint32_t)count;
        budget -= (size_t)count;
        if (*at == length) {
            int rc = cell == NO_CELL ? receive_header(c) : receive_complete(c, cell);
            if (rc != SYNC_WORK_OK)
                return rc;
        }
    }
    return SYNC_WORK_OK;
}

static int write_stage(sync_work_carriage_t *c, const sync_work_io_t *io)
{
    size_t budget = SYNC_WORK_STEP_BYTES;
    int monitor = c->control.role == SYNC_WORK_MONITOR;
    for (unsigned call = 0; call < SYNC_WORK_STEP_CALLS && budget != 0U; ++call) {
        unsigned cell = c->control.tx_cell;
        if (cell == NO_CELL) {
            cell = oldest(c, monitor ? CELL_REQUEST : CELL_RESPONSE);
            if (cell == NO_CELL)
                break;
            c->control.tx_cell = (uint8_t)cell;
        }
        sync_work_cell_t *slot = &c->control.cell[cell];
        uint32_t *at = monitor ? &slot->request_at : &slot->response_at;
        const uint8_t *buffer = monitor ? request(c, cell) : response(c, cell);
        size_t length = monitor ? request_size(cell) : response_size(cell);
        if (*at >= length)
            return fail(c, SYNC_WORK_FAIL_FRAME);
        size_t offered = length - *at;
        if (offered > budget)
            offered = budget;
        ptrdiff_t count = io->write(io->context, buffer + *at, offered);
        if (io_count(c, count, offered, 1) != SYNC_WORK_OK)
            return SYNC_WORK_FAILED;
        if (count == SYNC_WORK_IO_AGAIN)
            break;
        if (count == SYNC_WORK_IO_INTR)
            continue;
        *at += (uint32_t)count;
        budget -= (size_t)count;
        if (*at == length) {
            c->control.tx_cell = NO_CELL;
            if (monitor)
                slot->state = CELL_WAIT;
            else
                release_cell(c, cell);
        }
    }
    return SYNC_WORK_OK;
}

static int dispatch(sync_work_carriage_t *c, const sync_work_callbacks_t *callbacks)
{
    unsigned cell = oldest(c, CELL_READY);
    if (cell == NO_CELL)
        return SYNC_WORK_OK;
    sync_work_workspace_t *w = &c->workspace;
    sync_work_header_t h = new_header(c, cell == STORE_CELL ? SYNC_WORK_STORED :
                                     SYNC_WORK_PLANNED, c->control.cell[cell].operation);
    int rc;
    if (cell == STORE_CELL) {
        rc = sync_work_store_decode(&w->header, &w->input.store.offset,
                                     &w->input.store.unit, c->store_request,
                                     sizeof(c->store_request));
        if (rc != 0)
            return fail(c, SYNC_WORK_FAIL_FRAME);
        int status = callbacks->store(callbacks->context, &w->header,
                                      w->input.store.offset, w->input.store.unit);
        if (status < 0 || status > 1)
            return fail(c, SYNC_WORK_FAIL_CALLBACK);
        rc = sync_work_stored_encode(c->stored_response, sizeof(c->stored_response),
                                      &h, (uint8_t)status);
    } else {
        rc = sync_work_plan_decode(&w->header, &w->input.view, c->plan_request,
                                    sizeof(c->plan_request));
        if (rc != 0)
            return fail(c, SYNC_WORK_FAIL_FRAME);
        memset(&w->result, 0, sizeof(w->result));
        if (callbacks->plan(callbacks->context, &w->input.view, &w->result) != 0)
            return fail(c, SYNC_WORK_FAIL_CALLBACK);
        rc = sync_work_planned_encode(c->planned_response, sizeof(c->planned_response),
                                       &h, &w->result);
    }
    if (rc != 0)
        return fail(c, SYNC_WORK_FAIL_CALLBACK);
    c->control.cell[cell].state = CELL_RESPONSE;
    crypto_memzero(w, sizeof(*w));
    return SYNC_WORK_OK;
}

int sync_work_step(sync_work_carriage_t *c, const sync_work_io_t *io,
                    const sync_work_callbacks_t *callbacks)
{
    int rc = mutable(c, 0);
    if (rc != SYNC_WORK_OK)
        return rc;
    if (io == NULL || io->read == NULL || io->write == NULL ||
        (c->control.role == SYNC_WORK_MONITOR ? callbacks != NULL :
         callbacks == NULL || callbacks->store == NULL || callbacks->plan == NULL))
        return SYNC_WORK_INVALID;
    c->control.in_step = 1;
    int write_first = c->control.first_io;
    c->control.first_io ^= 1U;
    rc = write_first ? write_stage(c, io) : read_stage(c, io);
    if (rc == SYNC_WORK_OK)
        rc = write_first ? read_stage(c, io) : write_stage(c, io);
    if (rc == SYNC_WORK_OK && c->control.role == SYNC_WORK_WORKER)
        rc = dispatch(c, callbacks);
    crypto_memzero(&c->workspace, sizeof(c->workspace));
    c->control.in_step = 0;
    return rc;
}

uint32_t sync_work_failure(const sync_work_carriage_t *c)
{
    return live(c) ? c->control.failure : SYNC_WORK_FAIL_NONE;
}

int sync_work_abort(sync_work_carriage_t *c)
{
    int rc = mutable(c, 0);
    if (rc != SYNC_WORK_OK)
        return rc;
    (void)fail(c, SYNC_WORK_FAIL_ABORT);
    return SYNC_WORK_OK;
}

int sync_work_retire(sync_work_carriage_t *c)
{
    if (!live(c) || c->control.in_step)
        return SYNC_WORK_INVALID;
    crypto_memzero(c, sizeof(*c));
    c->control.initialized = 2;
    return SYNC_WORK_OK;
}
