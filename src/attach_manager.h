/*
 * attach_manager.h — channel-session fixed-storage local attach connection manager
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef UNMOOR_ATTACH_MANAGER_H
#define UNMOOR_ATTACH_MANAGER_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "attach_local.h"

#define ATTACH_MANAGER_POLL_CAPACITY \
    (ATTACH_LOCAL_MAX_CONNECTIONS + 1U)
#define ATTACH_MANAGER_LISTENER_OWNER UINT64_C(0)
#define ATTACH_MANAGER_CLOSE_PROTOCOL UINT32_C(7)

/*
 * A token names one local connection incarnation, not a channel session
 * generation.  Zero is reserved for the listener.  Callers must preserve the
 * token beside poll readiness so a reused fd cannot redirect an old event.
 */
typedef uint64_t attach_manager_owner_t;

typedef enum {
    ATTACH_MANAGER_STATE_FREE = 0,
    ATTACH_MANAGER_STATE_AWAIT_OPEN,
    ATTACH_MANAGER_STATE_OPEN_QUEUED,
    ATTACH_MANAGER_STATE_OPENING,
    ATTACH_MANAGER_STATE_RESULT_PENDING,
    ATTACH_MANAGER_STATE_ACTIVE,
    ATTACH_MANAGER_STATE_CLOSING,
    /* Local CLOSE is physically complete; fd ownership awaits detach. */
    ATTACH_MANAGER_STATE_CLOSE_FLUSHED
} attach_manager_state_t;

typedef enum {
    ATTACH_MANAGER_EVENT_NONE = 0,
    ATTACH_MANAGER_EVENT_OPEN,
    ATTACH_MANAGER_EVENT_DATA,
    ATTACH_MANAGER_EVENT_EOF,
    ATTACH_MANAGER_EVENT_RESIZE,
    ATTACH_MANAGER_EVENT_SIGNAL,
    ATTACH_MANAGER_EVENT_CLOSE,
    ATTACH_MANAGER_EVENT_CANCEL,
    /* The complete local DATA header and payload reached the Unix socket. */
    ATTACH_MANAGER_EVENT_DATA_DELIVERED
} attach_manager_event_type_t;

typedef struct {
    int fd;
    short events;
    attach_manager_owner_t owner;
} attach_manager_poll_entry_t;

typedef struct {
    attach_manager_event_type_t type;
    attach_manager_owner_t owner;
    uint32_t handle;
    uint32_t code;
    uint64_t transfer_id;
    uint64_t completion_cookie;
    size_t payload_length;
    uint8_t version;
    uint8_t kind;
    attach_local_record_t record;
} attach_manager_event_t;

typedef struct {
    attach_manager_state_t state;
    attach_manager_owner_t owner;
    uint32_t handle;
    uint64_t transfer_id;
    uint8_t version;
    uint8_t kind;
    int input_eof;
    int cancel_pending;
    int input_quiesced;
    int close_pending;
    int outbound_pending;
} attach_manager_connection_info_t;

/* Public: fixed storage permits direct embedding in the session object. */
typedef struct {
    attach_manager_state_t state;
    attach_manager_owner_t owner;
    uint64_t incarnation;
    uint32_t handle;
    uint32_t result_code;
    uint64_t transfer_id;
    uint8_t version;
    uint8_t kind;
    uint8_t outbound_type;
    int input_eof;
    int cancel_pending;
    int cancel_event_pending;
    int input_quiesced;
    int io_quiesced;
    int output_ended;
    int close_pending;
    int inbound_ready;
    int resize_ready;
    int completion_ready;
    attach_manager_event_type_t inbound_type;
    attach_local_record_t inbound_record;
    attach_local_record_t resize_record;
    uint32_t inbound_code;
    uint64_t outbound_cookie;
    size_t outbound_payload_length;
    uint64_t completion_cookie;
    size_t completion_payload_length;
    uint32_t close_code;
} attach_manager_slot_t;

typedef struct {
    attach_local_listener_t listener;
    attach_manager_slot_t slots[ATTACH_LOCAL_MAX_CONNECTIONS];
    attach_manager_owner_t opening_owner;
    size_t event_cursor;
    int initialized;
    int opened;
} attach_manager_t;

#ifdef UNMOOR_ATTACH_MANAGER_TEST
/* Test-only exact-owner RESULT staging seam; absent from product builds. */
int attach_manager_test_fail_next_result_stage(
    attach_manager_t *manager, attach_manager_owner_t owner);
unsigned int attach_manager_test_result_stage_failures(void);
#endif

void attach_manager_init(attach_manager_t *manager);
int attach_manager_open(attach_manager_t *manager,
                        const attach_local_listener_config_t *config);
int attach_manager_open_path(attach_manager_t *manager,
                             const char *absolute_path, uid_t uid);
/* client-confinement: run the path work before the client confines itself, then bind at
 * the unchanged point in the session. */
int attach_manager_prepare_path(attach_manager_t *manager,
                                const char *absolute_path, uid_t uid);
int attach_manager_bind_prepared(attach_manager_t *manager);
int attach_manager_close(attach_manager_t *manager);

/*
 * Return one listener entry and one entry per live fd.  Connection entries
 * carry incarnation-safe owner tokens.  POLLIN is suppressed while one exact
 * decoded input event is retained; a pending RESIZE remains replaceable as
 * latest state, and a queued OPEN remains readable only so premature input
 * can fail before network selection.  POLLOUT appears while one output record
 * is retained.  No dynamic allocation is performed.
 */
int attach_manager_poll_snapshot(const attach_manager_t *manager,
                                 attach_manager_poll_entry_t *entries,
                                 size_t capacity, size_t *count_out);

/*
 * Consume one readiness result.  Listener owner zero accepts at most one
 * same-uid client.  A connection service consumes at most one parser read and
 * retains at most one complete input record.  Stale owner tokens return
 * ATTACH_LOCAL_CLOSED without mutating a current connection.
 */
int attach_manager_service(attach_manager_t *manager,
                           attach_manager_owner_t owner, short revents,
                           int64_t now_ms);

/* Close first-record timeouts at equality even when no fd is ready. */
int attach_manager_tick(attach_manager_t *manager, int64_t now_ms);
int attach_manager_next_deadline(const attach_manager_t *manager,
                                 int64_t *deadline_ms_out);

/*
 * Pop one retained event.  Popping OPEN atomically claims the sole network
 * OPEN handshake; later complete OPENs remain in their fixed parser slots.
 * The manager never allocates a channel handle or generation.
 */
int attach_manager_next_event(attach_manager_t *manager,
                              attach_manager_event_t *event_out);
/* As above, but retain DATA in place while a session-wide source budget is
 * exhausted. Completion and control events remain selectable. */
int attach_manager_next_event_filtered(attach_manager_t *manager,
                                       attach_manager_event_t *event_out,
                                       int allow_data);

/*
 * Resolve the currently claimed OPEN with a caller-allocated channel-session handle.
 * For code 0, the session must publish the handle's sink/source binding before
 * calling this function: queue_result is the first operation that can make an
 * accepted RESULT observable to the attach client. If local RESULT staging
 * fails, the exact attach incarnation is closed and reset before the error is
 * returned; no unobservable OPENING state or global barrier remains.
 */
int attach_manager_queue_result(attach_manager_t *manager,
                                attach_manager_owner_t owner,
                                uint32_t handle, uint32_t code);
/* Version-2 BULK result. Identity follows channel-session's exact all-zero/all-selected
 * refusal rule and is retained through partial output and abrupt cancellation. */
int attach_manager_queue_bulk_result(attach_manager_t *manager,
                                     attach_manager_owner_t owner,
                                     uint32_t handle, uint32_t code,
                                     uint64_t transfer_id);

/*
 * Queue one session-to-attach record.  DATA's opaque cookie is returned only
 * after the complete local frame has physically reached the socket; callers
 * use that event to advance terminal-state-sync rx.delivered.  CLOSE is different: the first
 * call latches its immutable code, immediately quiesces attach input, and
 * returns OK even when prior DATA is retained.  The manager emits that DATA's
 * physical completion first, then serializes CLOSE without a caller retry.
 */
int attach_manager_queue_data(attach_manager_t *manager,
                              attach_manager_owner_t owner,
                              const uint8_t *data, size_t length,
                              uint64_t completion_cookie);
int attach_manager_queue_exit(attach_manager_t *manager,
                              attach_manager_owner_t owner, int32_t code);
int attach_manager_queue_close(attach_manager_t *manager,
                               attach_manager_owner_t owner, uint32_t code);

/*
 * Release parser/fd ownership after the associated channel is retired.
 * Abrupt-EOF and protocol cancellation quiesce the fd but deliberately retain
 * it until this call, allowing the session to detach the generation-bound
 * stream binding before the descriptor is closed.  Graceful CLOSE likewise
 * remains in CLOSE_FLUSHED until explicit release.  Release rejects a live or
 * still-flushing connection.
 */
int attach_manager_release(attach_manager_t *manager,
                           attach_manager_owner_t owner);
int attach_manager_connection_info(
    const attach_manager_t *manager, attach_manager_owner_t owner,
    attach_manager_connection_info_t *info_out);
size_t attach_manager_connection_count(const attach_manager_t *manager);

#endif /* UNMOOR_ATTACH_MANAGER_H */
