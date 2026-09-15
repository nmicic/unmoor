/*
 * sync_work_carriage.h — bounded local STORE/PLAN stream ownership
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef UNMOOR_SYNC_WORK_CARRIAGE_H
#define UNMOOR_SYNC_WORK_CARRIAGE_H

#include "sync_work_codec.h"

#define SYNC_WORK_MONITOR 1U
#define SYNC_WORK_WORKER  2U
#define SYNC_WORK_ROLE_BYTES_MAX 17112U
#define SYNC_WORK_STEP_BYTES 4096U
#define SYNC_WORK_STEP_CALLS 4U

#define SYNC_WORK_OK         0
#define SYNC_WORK_BUSY       1
#define SYNC_WORK_NOT_READY  2
#define SYNC_WORK_INVALID   -1
#define SYNC_WORK_EXHAUSTED -2
#define SYNC_WORK_FAILED    -3

#define SYNC_WORK_READ          1U
#define SYNC_WORK_WRITE         2U
#define SYNC_WORK_LOCAL         4U
#define SYNC_WORK_STORED_READY  8U
#define SYNC_WORK_PLANNED_READY 16U

#define SYNC_WORK_FAIL_NONE       0U
#define SYNC_WORK_FAIL_EOF        1U
#define SYNC_WORK_FAIL_IO         2U
#define SYNC_WORK_FAIL_FRAME      3U
#define SYNC_WORK_FAIL_IDENTITY   4U
#define SYNC_WORK_FAIL_RESULT     5U
#define SYNC_WORK_FAIL_CALLBACK   6U
#define SYNC_WORK_FAIL_ABORT      7U

#define SYNC_WORK_IO_AGAIN ((ptrdiff_t)-1)
#define SYNC_WORK_IO_INTR  ((ptrdiff_t)-2)
#define SYNC_WORK_IO_ERROR ((ptrdiff_t)-3)

/* Native owner data, never serialized. Caller owns the complete object;
 * fields are visible for size accounting, not a mutation API. */
typedef struct {
    uint64_t operation;
    uint32_t request_at, response_at;
    uint8_t state, canceled, reserved[6];
} sync_work_cell_t;

typedef struct {
    sync_work_cell_t cell[2];
    uint64_t incarnation, serial;
    uint32_t probe_used, failure;
    uint8_t role, direction, first_io, tx_cell, rx_cell;
    uint8_t in_step, initialized, reserved;
} sync_work_control_t;

typedef struct {
    sync_work_header_t header;
    union {
        sync_repair_view_t view;
        struct { uint64_t offset; const uint8_t *unit; } store;
    } input;
    sync_repair_result_t result;
    uint8_t stored_status;
} sync_work_workspace_t;

typedef struct {
    sync_work_control_t control;
    sync_work_workspace_t workspace;
    uint8_t store_request[SYNC_WORK_STORE_BYTES];
    uint8_t stored_response[SYNC_WORK_STORED_BYTES];
    uint8_t plan_request[SYNC_WORK_PLAN_BYTES];
    uint8_t planned_response[SYNC_WORK_PLANNED_BYTES];
    uint8_t probe[SYNC_WORK_HEADER];
} sync_work_carriage_t;

/* Synchronous byte adapters only; never retained. read copies owned bytes
 * into output; write consumes input without retaining access. Counts must
 * be <= offered; zero means EOF/nonempty zero-write and is fatal. */
typedef struct {
    void *context;
    ptrdiff_t (*read)(void *context, uint8_t *output, size_t offered);
    ptrdiff_t (*write)(void *context, const uint8_t *input, size_t offered);
} sync_work_io_t;

/* Nonblocking, synchronous worker functions, called at most once per step.
 * No callback may retain a span or mutate/reenter this carriage. STORE
 * returns exactly 0/1; PLAN returns zero plus a canonical result or fails.
 * Callback context/backing/publication and call stacks are separate budgets.
 */
typedef struct {
    void *context;
    int (*store)(void *context, const sync_work_header_t *header,
                 uint64_t offset, const uint8_t unit[SYNC_WORK_UNIT]);
    int (*plan)(void *context, const sync_repair_view_t *view,
                sync_repair_result_t *result);
} sync_work_callbacks_t;

/* Fresh zeroed owner only. Fixed role/source for its complete lifetime;
 * no descriptor, allocation, thread, process or clock is created. All input,
 * output, callback context and owner objects are disjoint/non-aliasing.
 * Mutation during step returns INVALID without running another operation.
 */
int sync_work_carriage_init(sync_work_carriage_t *c, uint8_t role,
                            uint64_t incarnation, uint8_t direction);
int sync_work_begin_store(sync_work_carriage_t *c, uint64_t offset,
                          const uint8_t unit[SYNC_WORK_UNIT], uint64_t *operation);
int sync_work_begin_plan(sync_work_carriage_t *c,
                         const sync_repair_view_t *view, uint64_t *operation);
/* Return the actual checked record identity, not a reconstructed source
 * tuple. Both separate outputs are required and clear on refusal. */
int sync_work_take_stored(sync_work_carriage_t *c, uint64_t operation,
                          sync_work_header_t *header, uint8_t *status);
int sync_work_take_planned(sync_work_carriage_t *c, uint64_t operation,
                           sync_repair_view_t *issued_view,
                           sync_repair_result_t *result);
int sync_work_cancel_plan(sync_work_carriage_t *c, uint64_t operation);

/* READ/WRITE interests describe readiness to attempt bounded local I/O.
 * LOCAL means W has one or more dispatchable requests; result-ready bits
 * belong to M. They grant neither real UDP nor PTY completion. Each step
 * alternates first direction, allows <=4 calls and <=4096 bytes per
 * direction (INTR uses a call), then <=1 W dispatch. M passes callbacks=NULL.
 * Returns OK for a healthy step even when no progress was possible.
 */
unsigned sync_work_interests(const sync_work_carriage_t *c);
int sync_work_step(sync_work_carriage_t *c, const sync_work_io_t *io,
                    const sync_work_callbacks_t *callbacks);
uint32_t sync_work_failure(const sync_work_carriage_t *c);
int sync_work_abort(sync_work_carriage_t *c);
/* Wipes the whole local object, leaving initialized=2 as a retired marker.
 * No later re-init; this is not proof of writer exit/backing erasure. */
int sync_work_retire(sync_work_carriage_t *c);

#endif
