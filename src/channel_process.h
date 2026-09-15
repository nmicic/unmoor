/*
 * channel_process.h — channel-session bounded per-channel child/process ownership
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef UNMOOR_CHANNEL_PROCESS_H
#define UNMOOR_CHANNEL_PROCESS_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define CHANNEL_PROCESS_MAX_INSTANCES 15U
#define CHANNEL_PROCESS_MAX_EXTRA_CLOSE_FDS 96U

typedef enum {
    CHANNEL_PROCESS_KIND_NONE = 0,
    CHANNEL_PROCESS_KIND_TERMINAL = 1,
    CHANNEL_PROCESS_KIND_EXEC = 2
} channel_process_kind_t;

typedef enum {
    CHANNEL_PROCESS_EMPTY = 0,
    CHANNEL_PROCESS_RUNNING,
    CHANNEL_PROCESS_TERMINATING,
    CHANNEL_PROCESS_EXITED
} channel_process_state_t;

typedef struct {
    uint32_t handle;
    pid_t pid;
    int input_fd;
    int output_fd;
    int64_t termination_deadline_ms;
    uint32_t exit_code;
    uint8_t kind;
    uint8_t state;
    uint8_t active;
    uint8_t input_closed;
    uint8_t output_eof;
    uint8_t reaped;
    uint8_t term_sent;
    uint8_t kill_sent;
} channel_process_instance_t;

typedef struct {
    channel_process_instance_t instances[CHANNEL_PROCESS_MAX_INSTANCES];
} channel_process_table_t;

void channel_process_table_init(channel_process_table_t *table);

/*
 * Spawn into one exact table slot.  handle is retained as immutable ownership
 * and must match every later operation.  extra_close_fds names other
 * session/listener/attach descriptors to close in the child before exec;
 * at most 96 fixed entries are accepted.  The table's own process fds are
 * always closed in the child.  All retained parent fds are nonblocking and
 * close-on-exec.  All fallible parent-side descriptor preparation completes
 * before fork, so a spawn error never enters a blocking child-cleanup path.
 */
int channel_process_spawn_terminal(
    channel_process_table_t *table, size_t index, uint32_t handle,
    const char *shell, uint16_t rows, uint16_t columns,
    const int extra_close_fds[], size_t extra_close_fd_count);
int channel_process_spawn_exec(
    channel_process_table_t *table, size_t index, uint32_t handle,
    const uint8_t *argv_preface, size_t argv_preface_length,
    const int extra_close_fds[], size_t extra_close_fd_count);

size_t channel_process_active_count(const channel_process_table_t *table);
const channel_process_instance_t *channel_process_get(
    const channel_process_table_t *table, size_t index);
int channel_process_input_fd(const channel_process_table_t *table,
                             size_t index, uint32_t handle);
int channel_process_output_fd(const channel_process_table_t *table,
                              size_t index, uint32_t handle);

/* EXEC has a separate stdin pipe and supports an orderly input half-close.
 * A PTY has one bidirectional master, so this operation is unsupported for
 * TERMINAL; terminal lifecycle remains driven by data/signal/cancellation. */
int channel_process_close_input(channel_process_table_t *table,
                                size_t index, uint32_t handle);

/* Called only after read(2) returns EOF (or PTY EIO after the slave closes). */
int channel_process_mark_output_eof(channel_process_table_t *table,
                                    size_t index, uint32_t handle);

int channel_process_resize(channel_process_table_t *table, size_t index,
                           uint32_t handle, uint16_t rows, uint16_t columns,
                           uint16_t xpixel, uint16_t ypixel);
int channel_process_signal(channel_process_table_t *table, size_t index,
                           uint32_t handle, int signum);

/*
 * Nonblocking lifecycle.  cancel closes owned descriptors immediately,
 * sends TERM once and fixes one absolute deadline.  maintain performs one
 * shared WNOHANG reap sweep, sends KILL once for every due child, and sweeps
 * again; no per-channel operation sleeps or waits.
 */
int channel_process_cancel(channel_process_table_t *table, size_t index,
                           uint32_t handle, int64_t now_ms,
                           int64_t term_grace_ms);
int channel_process_cancel_all(channel_process_table_t *table,
                               int64_t now_ms, int64_t term_grace_ms);
int channel_process_reap_sweep(channel_process_table_t *table);
int channel_process_maintain(channel_process_table_t *table, int64_t now_ms);

/* Ready only after the child is reaped and its output reached EOF/drained. */
int channel_process_result(const channel_process_table_t *table,
                           size_t index, uint32_t handle,
                           uint32_t *exit_code_out);
int channel_process_release(channel_process_table_t *table, size_t index,
                            uint32_t handle);

/*
 * Synchronous session-destruction helper.  TERM is sent to every child before
 * any wait; all children share one monotonic horizon.  term_grace_ms must not
 * exceed reap_horizon_ms.  On timeout it returns -1/ETIMEDOUT with ownership
 * retained so a caller can continue shared maintain sweeps.
 */
int channel_process_table_destroy(channel_process_table_t *table,
                                  int64_t term_grace_ms,
                                  int64_t reap_horizon_ms);

#endif /* UNMOOR_CHANNEL_PROCESS_H */
