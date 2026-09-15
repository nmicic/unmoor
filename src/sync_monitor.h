/*
 * sync_monitor.h — externally owned listener-monitor sync/source continuation binding
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef UNMOOR_SYNC_MONITOR_H
#define UNMOOR_SYNC_MONITOR_H

#include "sync_source.h"
#include "sync_work_carriage.h"

struct session;
#define SYNC_MONITOR_EMPTY    0U
#define SYNC_MONITOR_PREBOUND 1U
#define SYNC_MONITOR_LIVE     2U
#define SYNC_MONITOR_STOPPED  3U

typedef int (*sync_monitor_publication_fn)(const void *, uint64_t *);

/* Trusted permanent contexts, never worker-provided. LP64: 80 bytes.
 * One-shot external ownership survives sync_free; only session_destroy may
 * clear its session reference. No payload/bitmap queue or IO pointer here.
 * Fields expose accounting, not a mutation API. */
typedef struct sync_monitor_binding {
    struct session *session;
    sync_source_t *source;
    sync_work_carriage_t *work;
    sync_source_reader_t reader;
    const void *publication_context;
    sync_monitor_publication_fn publication;
    uint64_t plan_operation;
    int32_t fin_code;
    uint8_t life, fin_deferred, fin_have_code, in_service;
} sync_monitor_binding_t;

/* Resolve the existing classic source quota once before guard/map creation;
 * normal unbound init uses the same parser. Not a new option/default. */
uint64_t sync_classic_backlog_quota(void);
/* Fresh zero binding, empty healthy source/M carriage, same identity and
 * direction1, inactive listener TX/RX and no previous services/binding.
 * Reader descriptor is copied; all referenced owners/contexts stay alive
 * through session destruction and external exact-worker retirement.
 * 0 success/-1 nonmutating refusal. Actual epoch-rekey/UDP/runtime admission and
 * pre-key custody are the separately reviewed constructor's responsibility.
 * sync_init rechecks selected classic PTY+SYNC and never silently falls back. */
int sync_monitor_bind(struct session *s, sync_monitor_binding_t *binding,
                      sync_source_t *source, sync_work_carriage_t *work,
                      const sync_source_reader_t *reader,
                      sync_monitor_publication_fn publication,
                      const void *publication_context);
/* Borrow IO only for this non-reentrant call. At most one STORE begin/bind,
 * one bounded M step and one matching STORED finish. Service continues over
 * rekey barriers, not after stop. No descriptor/process/time authority.
 * Returns0 for healthy progress/no progress, -1 on loud local failure. */
int sync_monitor_service(struct session *s, const sync_work_io_t *io);
/* Cancel one exact PLAN, retaining exposed drainage in its existing cell.
 * Epoch/path barriers never abandon STORE or reset source/serial lifetime. */
int sync_monitor_plan_barrier(struct session *s);
/* Idempotent, mark STOPPED first; discard FIN intent, cancel PLAN and
 * terminally abandon source but preserve cleanup inventory. No free/reap. */
void sync_monitor_stop(struct session *s);

#endif
