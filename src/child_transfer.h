/*
 * child_transfer.h — child-transfer fixed two-child transfer supervisor
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef UNMOOR_CHILD_TRANSFER_H
#define UNMOOR_CHILD_TRANSFER_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "traffic_profile.h"
#include "transport.h"

#define CHILD_TRANSFER_SLOT_COUNT 2U
#define CHILD_TRANSFER_PUSH_SLOT 0U
#define CHILD_TRANSFER_PULL_SLOT 1U
#define CHILD_TRANSFER_KIND_PUSH UINT8_C(3)
#define CHILD_TRANSFER_KIND_PULL UINT8_C(4)
#define CHILD_TRANSFER_RESULT_FD 3
#define CHILD_TRANSFER_RESULT_BYTES 24U
#define CHILD_TRANSFER_MAX_ARGS 64U
#define CHILD_TRANSFER_MAX_EXTRA_CLOSE_FDS 96U
#define CHILD_TRANSFER_PATH_MAX 1024U
/* Private child-to-parent result sentinel.  The parent maps it to the local
 * attach protocol explicitly; it is neither a bulk-transfer nor a channel-session code. */
#define CHILD_TRANSFER_RESULT_CONFINED UINT32_C(0xffffffff)

typedef struct {
    const char *program_path;
    const char *attach_socket_path;
    const char *udp_host;
    const char *remote_command;
    const char *remote_bind_host; /* optional */
    traffic_profile_t traffic_profile;
    traffic_multipath_option_t multipath_option;
    uint16_t port_mask;
    int timeout_seconds;
    uint8_t exact_paths;
    uint8_t configured_paths;
    uint8_t log_json;
    uint8_t port_layout; /* transport_udp_port_layout_t */
    uint8_t port_mask_explicit;
    /* Exact crypto inheritance from the authenticated control session:
     * zero emits --pq off; one emits --pq require plus the pq-hybrid carrier. */
    uint8_t pq_carrier_required;
    /* Client confinement level word passed to the child as "--confine <level>".
     * NULL leaves the child's own default in place, which is what a zeroed
     * policy (unit fixtures) gets, so argv is unchanged for those. The string
     * is a static literal owned by confine.c; the policy does not copy it. */
    const char *confine_level;
    /* server-confinement: optional server-side level handed to the child as public
     * "--server-confine <level>" policy. NULL preserves legacy argv. */
    const char *server_confine_level;
} child_transfer_launch_policy_t;

typedef struct {
    const uint8_t *local_path;
    const uint8_t *remote_path;
    size_t local_path_length;
    size_t remote_path_length;
    uint64_t transfer_id;
    uint16_t wire_budget;
    uint16_t stall_seconds;
    uint8_t kind;
    uint8_t options;
} child_transfer_command_t;

/* Fixed argv ownership. String pointers in argv refer either to these buffers,
 * immutable literals, or the launch policy's session-owned text. */
typedef struct {
    const char *argv[CHILD_TRANSFER_MAX_ARGS + 1U];
    char timeout[16];
    char wire_budget[16];
    char stall_seconds[16];
    char multipath[24];
    char port_mask[16];
    char transfer_id[32];
    char local_path[CHILD_TRANSFER_PATH_MAX + 1U];
    char remote_path[CHILD_TRANSFER_PATH_MAX + 1U];
    size_t argc;
} child_transfer_argv_t;

typedef enum {
    CHILD_TRANSFER_EMPTY = 0,
    CHILD_TRANSFER_RUNNING,
    CHILD_TRANSFER_TERMINATING,
    CHILD_TRANSFER_EXITED
} child_transfer_state_t;

typedef struct {
    uint64_t owner;
    uint64_t transfer_id;
    uint32_t handle;
    uint32_t result_code;
    uint32_t process_exit_code;
    pid_t pid;
    int result_fd;
    int64_t termination_deadline_ms;
    size_t result_used;
    uint8_t result_bytes[CHILD_TRANSFER_RESULT_BYTES];
    uint8_t kind;
    uint8_t state;
    uint8_t active;
    uint8_t reaped;
    uint8_t result_eof;
    uint8_t result_valid;
    uint8_t result_invalid;
    uint8_t cancel_requested;
    uint8_t term_sent;
    uint8_t kill_sent;
    uint8_t close_queued;
} child_transfer_instance_t;

typedef struct {
    child_transfer_instance_t slots[CHILD_TRANSFER_SLOT_COUNT];
    uint32_t last_generation[CHILD_TRANSFER_SLOT_COUNT];
} child_transfer_table_t;

void child_transfer_table_init(child_transfer_table_t *table);
size_t child_transfer_active_count(const child_transfer_table_t *table);
int child_transfer_direction_active(const child_transfer_table_t *table,
                                    uint8_t kind);
const child_transfer_instance_t *child_transfer_get(
    const child_transfer_table_t *table, size_t slot);
/* Read-only admission candidate. A failed spawn does not spend a generation. */
int child_transfer_next_handle(const child_transfer_table_t *table,
                               uint8_t kind, size_t *slot_out,
                               uint32_t *handle_out);
int child_transfer_find_owner(const child_transfer_table_t *table,
                              uint64_t owner, size_t *slot_out);
int child_transfer_argv_build(const child_transfer_launch_policy_t *policy,
                              const child_transfer_command_t *command,
                              child_transfer_argv_t *arguments);

/*
 * Start one exact self-exec child.  All parent-side fallible descriptor work
 * completes before fork.  The child receives a fixed inherited result pipe
 * as descriptor 3; stdin/stdout/stderr are /dev/null so a background transfer
 * cannot paint over the authenticated terminal stream.  `argv` must already
 * contain the matching internal descriptor argument.
 */
int child_transfer_spawn(
    child_transfer_table_t *table, size_t slot, uint8_t kind,
    uint64_t owner, uint32_t handle, uint64_t transfer_id,
    const char *const argv[],
    const int extra_close_fds[], size_t extra_close_fd_count);

/* Nonblocking exact-owned-PID lifecycle. A descriptor close diagnostic after
 * result EOF is local to the completed slot; it cannot invalidate a decoded
 * result or turn maintenance into a sibling-cancelling table failure. */
int child_transfer_cancel(child_transfer_table_t *table, size_t slot,
                          uint32_t handle, int64_t now_ms,
                          int64_t term_grace_ms);
int child_transfer_cancel_all(child_transfer_table_t *table,
                              int64_t now_ms, int64_t term_grace_ms);
int child_transfer_maintain(child_transfer_table_t *table, int64_t now_ms);

/*
 * Return 0 while running, 1 after both waitpid and result-pipe EOF, or -1 for
 * a stale/invalid owner.  A completed child can legitimately have no valid
 * status record (exec failure, signal, malformed output); callers map that to
 * a loud protocol/cancellation result without affecting the control session.
 */
int child_transfer_result(const child_transfer_table_t *table, size_t slot,
                          uint32_t handle, int *record_valid_out,
                          uint32_t *result_code_out,
                          uint32_t *process_exit_code_out);
uint32_t child_transfer_normalize_result(
    const child_transfer_instance_t *instance, int record_valid,
    uint32_t record_code, uint32_t process_exit_code);
int child_transfer_release(child_transfer_table_t *table, size_t slot,
                           uint32_t handle);
int child_transfer_table_destroy(child_transfer_table_t *table,
                                 int64_t term_grace_ms,
                                 int64_t reap_horizon_ms);

/* Child-side fixed local result record.  The record is public metadata only. */
int child_transfer_result_fd_arm(int fd);
/* Map the production confinement result to child-transfer's private local sentinel.
 * Standalone children (no owned result fd) retain the ordinary exit path. */
uint32_t child_transfer_confinement_result(int apply_result,
                                           int child_result_fd);
int child_transfer_result_write(int fd, uint8_t kind,
                                uint64_t transfer_id,
                                uint32_t result_code);

#ifdef UNMOOR_CHILD_TRANSFER_TEST
/* Test-only post-EOF close seam; absent from production builds. */
int child_transfer_test_fail_next_result_close(int fd);
unsigned int child_transfer_test_result_close_failures(void);
#endif

#endif /* UNMOOR_CHILD_TRANSFER_H */
