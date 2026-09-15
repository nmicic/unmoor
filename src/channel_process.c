/*
 * channel_process.c — channel-session bounded per-channel child/process ownership
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */

#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE 1
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif

#include "channel_process.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include "attach_local.h"
#include "process_hygiene.h"

/* -Isrc makes the project's own pty.h shadow the platform header. */
extern int openpty(int *amaster, int *aslave, char *name,
                   const struct termios *termp, const struct winsize *winp);
extern int login_tty(int fd);

#define CHANNEL_PROCESS_SHELL_BYTES 1024U

static int handle_matches_index(uint32_t handle, size_t index)
{
    return handle != 0U && (handle >> 4) != 0U &&
           (handle & UINT32_C(0x0f)) == (uint32_t)(index + 1U);
}

static int validate_spawn(const channel_process_table_t *table, size_t index,
                          uint32_t handle, const int extra_close_fds[],
                          size_t extra_close_fd_count)
{
    size_t i;

    if (table == NULL || index >= CHANNEL_PROCESS_MAX_INSTANCES ||
        !handle_matches_index(handle, index) ||
        table->instances[index].active ||
        extra_close_fd_count > CHANNEL_PROCESS_MAX_EXTRA_CLOSE_FDS ||
        (extra_close_fd_count != 0U && extra_close_fds == NULL)) {
        errno = EINVAL;
        return -1;
    }
    for (i = 0U; i < extra_close_fd_count; i++) {
        if (extra_close_fds[i] <= STDERR_FILENO) {
            errno = EINVAL;
            return -1;
        }
    }
    return 0;
}

static int set_cloexec(int fd)
{
    int flags = fcntl(fd, F_GETFD);

    if (flags < 0)
        return -1;
    if ((flags & FD_CLOEXEC) != 0)
        return 0;
    return fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

static int set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL);

    if (flags < 0)
        return -1;
    if ((flags & O_NONBLOCK) != 0)
        return 0;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int move_above_standard(int fd)
{
    int moved;

    if (fd > STDERR_FILENO)
        return fd;
#ifdef F_DUPFD_CLOEXEC
    moved = fcntl(fd, F_DUPFD_CLOEXEC, STDERR_FILENO + 1);
#else
    moved = fcntl(fd, F_DUPFD, STDERR_FILENO + 1);
    if (moved >= 0 && set_cloexec(moved) != 0) {
        int saved_errno = errno;

        (void)close(moved);
        errno = saved_errno;
        moved = -1;
    }
#endif
    if (moved < 0) {
        int saved_errno = errno;

        (void)close(fd);
        errno = saved_errno;
        return -1;
    }
    (void)close(fd);
    return moved;
}

static void close_fd_value(int fd)
{
    if (fd > STDERR_FILENO)
        (void)close(fd);
}

static void close_child_fds(const channel_process_table_t *table,
                            const int extra_close_fds[],
                            size_t extra_close_fd_count,
                            const int local_fds[], size_t local_fd_count)
{
    size_t i;

    for (i = 0U; i < CHANNEL_PROCESS_MAX_INSTANCES; i++) {
        close_fd_value(table->instances[i].input_fd);
        if (table->instances[i].output_fd != table->instances[i].input_fd)
            close_fd_value(table->instances[i].output_fd);
    }
    for (i = 0U; i < extra_close_fd_count; i++)
        close_fd_value(extra_close_fds[i]);
    for (i = 0U; i < local_fd_count; i++)
        close_fd_value(local_fds[i]);
}

static void close_fd_pair(int first_fd, int second_fd)
{
    if (first_fd >= 0)
        (void)close(first_fd);
    if (second_fd >= 0 && second_fd != first_fd)
        (void)close(second_fd);
}

static void instance_start(channel_process_instance_t *instance,
                           uint32_t handle, uint8_t kind, pid_t pid,
                           int input_fd, int output_fd)
{
    memset(instance, 0, sizeof(*instance));
    instance->handle = handle;
    instance->kind = kind;
    instance->pid = pid;
    instance->input_fd = input_fd;
    instance->output_fd = output_fd;
    instance->state = CHANNEL_PROCESS_RUNNING;
    instance->active = 1U;
}

void channel_process_table_init(channel_process_table_t *table)
{
    size_t i;

    if (table == NULL)
        return;
    memset(table, 0, sizeof(*table));
    for (i = 0U; i < CHANNEL_PROCESS_MAX_INSTANCES; i++) {
        table->instances[i].input_fd = -1;
        table->instances[i].output_fd = -1;
    }
}

static int copy_selected_shell(const char *shell,
                               char selected[CHANNEL_PROCESS_SHELL_BYTES])
{
    const char *candidate = shell;
    size_t length;

    if (candidate == NULL || candidate[0] == '\0')
        candidate = getenv("SHELL");
    if (candidate == NULL || candidate[0] == '\0') {
        if (access("/bin/zsh", X_OK) == 0)
            candidate = "/bin/zsh";
        else if (access("/bin/bash", X_OK) == 0)
            candidate = "/bin/bash";
        else
            candidate = "/bin/sh";
    }
    length = strnlen(candidate, CHANNEL_PROCESS_SHELL_BYTES);
    if (length == 0U || length == CHANNEL_PROCESS_SHELL_BYTES) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(selected, candidate, length + 1U);
    return 0;
}

int channel_process_spawn_terminal(
    channel_process_table_t *table, size_t index, uint32_t handle,
    const char *shell, uint16_t rows, uint16_t columns,
    const int extra_close_fds[], size_t extra_close_fd_count)
{
    struct winsize window;
    char selected_shell[CHANNEL_PROCESS_SHELL_BYTES];
    int master_fd = -1;
    int slave_fd = -1;
    pid_t pid;

    if (validate_spawn(table, index, handle, extra_close_fds,
                       extra_close_fd_count) != 0 ||
        rows == 0U || rows > 1000U || columns == 0U || columns > 1000U) {
        errno = EINVAL;
        return -1;
    }
    if (copy_selected_shell(shell, selected_shell) != 0)
        return -1;
    memset(&window, 0, sizeof(window));
    window.ws_row = rows;
    window.ws_col = columns;
    if (openpty(&master_fd, &slave_fd, NULL, NULL, &window) != 0)
        return -1;
    master_fd = move_above_standard(master_fd);
    if (master_fd < 0) {
        int saved_errno = errno;

        (void)close(slave_fd);
        errno = saved_errno;
        return -1;
    }
    slave_fd = move_above_standard(slave_fd);
    if (slave_fd < 0) {
        int saved_errno = errno;

        (void)close(master_fd);
        errno = saved_errno;
        return -1;
    }
    /* Every fallible parent-side descriptor operation precedes fork. */
    if (set_cloexec(master_fd) != 0 || set_nonblocking(master_fd) != 0 ||
        set_cloexec(slave_fd) != 0) {
        int saved_errno = errno;

        close_fd_pair(master_fd, slave_fd);
        errno = saved_errno;
        return -1;
    }
    pid = fork();
    if (pid < 0) {
        int saved_errno = errno;

        close_fd_pair(master_fd, slave_fd);
        errno = saved_errno;
        return -1;
    }
    if (pid == 0) {
        process_reset_child_signals();
        (void)close(master_fd);
        close_child_fds(table, extra_close_fds, extra_close_fd_count,
                        NULL, 0U);
        if (login_tty(slave_fd) != 0)
            _exit(127);
        if (process_close_from(STDERR_FILENO + 1, NULL, 0U) != 0)
            _exit(127);
        (void)setenv("TERM", "xterm-256color", 1);
        (void)setenv("UNMOOR_SESSION", "1", 1);
        execl(selected_shell, selected_shell, (char *)NULL);
        _exit(127);
    }
    (void)close(slave_fd);
    instance_start(&table->instances[index], handle,
                   CHANNEL_PROCESS_KIND_TERMINAL, pid,
                   master_fd, master_fd);
    return 0;
}

static int prepare_pipe(int pipe_fds[2], int nonblocking_end)
{
    int first;
    int second;

    if (pipe(pipe_fds) != 0)
        return -1;
    first = move_above_standard(pipe_fds[0]);
    if (first < 0) {
        int saved_errno = errno;

        (void)close(pipe_fds[1]);
        errno = saved_errno;
        return -1;
    }
    pipe_fds[0] = first;
    second = move_above_standard(pipe_fds[1]);
    if (second < 0) {
        int saved_errno = errno;

        (void)close(pipe_fds[0]);
        errno = saved_errno;
        return -1;
    }
    pipe_fds[1] = second;
    if (set_cloexec(pipe_fds[0]) != 0 || set_cloexec(pipe_fds[1]) != 0 ||
        set_nonblocking(pipe_fds[nonblocking_end]) != 0) {
        int saved_errno = errno;

        (void)close(pipe_fds[0]);
        (void)close(pipe_fds[1]);
        errno = saved_errno;
        return -1;
    }
    return 0;
}

int channel_process_spawn_exec(
    channel_process_table_t *table, size_t index, uint32_t handle,
    const uint8_t *argv_preface, size_t argv_preface_length,
    const int extra_close_fds[], size_t extra_close_fd_count)
{
    attach_local_exec_argv_t decoded;
    char *arguments[ATTACH_LOCAL_MAX_EXEC_ARGS + 1U];
    int input_pipe[2] = { -1, -1 };
    int output_pipe[2] = { -1, -1 };
    int local_fds[4];
    size_t i;
    pid_t pid;

    if (validate_spawn(table, index, handle, extra_close_fds,
                       extra_close_fd_count) != 0 ||
        argv_preface == NULL || argv_preface_length < 5U ||
        argv_preface_length > ATTACH_LOCAL_MAX_PAYLOAD ||
        attach_local_exec_decode(argv_preface, argv_preface_length,
                                 &decoded) != ATTACH_LOCAL_OK)
        return -1;
    /* Keep the process boundary self-contained even if the decoder contract
     * changes later: execvp must always receive a nonempty argv[0]. */
    if (decoded.count == 0U || decoded.count > ATTACH_LOCAL_MAX_EXEC_ARGS ||
        decoded.offsets[0] >= ATTACH_LOCAL_EXEC_STORAGE ||
        decoded.storage[decoded.offsets[0]] == '\0') {
        errno = EPROTO;
        return -1;
    }
    arguments[0] = decoded.storage + decoded.offsets[0];
    for (i = 1U; i < decoded.count; i++)
        arguments[i] = decoded.storage + decoded.offsets[i];
    arguments[decoded.count] = NULL;

    /* Parent writes child stdin, so its write end is nonblocking. */
    if (prepare_pipe(input_pipe, 1) != 0)
        return -1;
    /* Parent reads merged child stdout/stderr, so its read end is nonblocking. */
    if (prepare_pipe(output_pipe, 0) != 0) {
        int saved_errno = errno;

        (void)close(input_pipe[0]);
        (void)close(input_pipe[1]);
        errno = saved_errno;
        return -1;
    }
    pid = fork();
    if (pid < 0) {
        int saved_errno = errno;

        close_fd_pair(input_pipe[0], input_pipe[1]);
        close_fd_pair(output_pipe[0], output_pipe[1]);
        errno = saved_errno;
        return -1;
    }
    if (pid == 0) {
        local_fds[0] = input_pipe[0];
        local_fds[1] = input_pipe[1];
        local_fds[2] = output_pipe[0];
        local_fds[3] = output_pipe[1];
        process_reset_child_signals();
        if (dup2(input_pipe[0], STDIN_FILENO) < 0 ||
            dup2(output_pipe[1], STDOUT_FILENO) < 0 ||
            dup2(output_pipe[1], STDERR_FILENO) < 0)
            _exit(127);
        close_child_fds(table, extra_close_fds, extra_close_fd_count,
                        local_fds, 4U);
        if (process_close_from(STDERR_FILENO + 1, NULL, 0U) != 0)
            _exit(127);
        execvp(arguments[0], arguments);
        _exit(127);
    }
    (void)close(input_pipe[0]);
    input_pipe[0] = -1;
    (void)close(output_pipe[1]);
    output_pipe[1] = -1;
    instance_start(&table->instances[index], handle,
                   CHANNEL_PROCESS_KIND_EXEC, pid,
                   input_pipe[1], output_pipe[0]);
    return 0;
}

size_t channel_process_active_count(const channel_process_table_t *table)
{
    size_t count = 0U;
    size_t i;

    if (table == NULL)
        return 0U;
    for (i = 0U; i < CHANNEL_PROCESS_MAX_INSTANCES; i++) {
        if (table->instances[i].active)
            count++;
    }
    return count;
}

const channel_process_instance_t *channel_process_get(
    const channel_process_table_t *table, size_t index)
{
    if (table == NULL || index >= CHANNEL_PROCESS_MAX_INSTANCES ||
        !table->instances[index].active)
        return NULL;
    return &table->instances[index];
}

static channel_process_instance_t *owned_instance(
    channel_process_table_t *table, size_t index, uint32_t handle)
{
    if (table == NULL || index >= CHANNEL_PROCESS_MAX_INSTANCES ||
        !table->instances[index].active ||
        table->instances[index].handle != handle) {
        errno = EINVAL;
        return NULL;
    }
    return &table->instances[index];
}

static const channel_process_instance_t *owned_const_instance(
    const channel_process_table_t *table, size_t index, uint32_t handle)
{
    if (table == NULL || index >= CHANNEL_PROCESS_MAX_INSTANCES ||
        !table->instances[index].active ||
        table->instances[index].handle != handle) {
        errno = EINVAL;
        return NULL;
    }
    return &table->instances[index];
}

int channel_process_input_fd(const channel_process_table_t *table,
                             size_t index, uint32_t handle)
{
    const channel_process_instance_t *instance =
        owned_const_instance(table, index, handle);

    if (instance == NULL)
        return -1;
    if (instance->input_closed || instance->reaped) {
        errno = EPIPE;
        return -1;
    }
    return instance->input_fd;
}

int channel_process_output_fd(const channel_process_table_t *table,
                              size_t index, uint32_t handle)
{
    const channel_process_instance_t *instance =
        owned_const_instance(table, index, handle);

    if (instance == NULL)
        return -1;
    if (instance->output_eof) {
        errno = EPIPE;
        return -1;
    }
    return instance->output_fd;
}

static int close_instance_input(channel_process_instance_t *instance)
{
    int result = 0;

    if (instance->input_closed)
        return 0;
    instance->input_closed = 1U;
    if (instance->input_fd >= 0 &&
        instance->input_fd != instance->output_fd) {
        if (close(instance->input_fd) != 0)
            result = -1;
        instance->input_fd = -1;
    }
    return result;
}

int channel_process_close_input(channel_process_table_t *table,
                                size_t index, uint32_t handle)
{
    channel_process_instance_t *instance =
        owned_instance(table, index, handle);

    if (instance == NULL)
        return -1;
    if (instance->kind != CHANNEL_PROCESS_KIND_EXEC) {
        errno = EOPNOTSUPP;
        return -1;
    }
    return close_instance_input(instance);
}

int channel_process_mark_output_eof(channel_process_table_t *table,
                                    size_t index, uint32_t handle)
{
    channel_process_instance_t *instance =
        owned_instance(table, index, handle);
    int result = 0;

    if (instance == NULL)
        return -1;
    if (instance->output_eof)
        return 0;
    instance->output_eof = 1U;
    if (instance->output_fd >= 0) {
        if (close(instance->output_fd) != 0)
            result = -1;
        if (instance->input_fd == instance->output_fd) {
            instance->input_fd = -1;
            instance->input_closed = 1U;
        }
        instance->output_fd = -1;
    }
    return result;
}

int channel_process_resize(channel_process_table_t *table, size_t index,
                           uint32_t handle, uint16_t rows, uint16_t columns,
                           uint16_t xpixel, uint16_t ypixel)
{
    channel_process_instance_t *instance =
        owned_instance(table, index, handle);
    struct winsize window;

    if (instance == NULL)
        return -1;
    if (instance->kind != CHANNEL_PROCESS_KIND_TERMINAL || instance->reaped ||
        instance->output_eof || rows == 0U || rows > 1000U ||
        columns == 0U || columns > 1000U) {
        errno = EINVAL;
        return -1;
    }
    memset(&window, 0, sizeof(window));
    window.ws_row = rows;
    window.ws_col = columns;
    window.ws_xpixel = xpixel;
    window.ws_ypixel = ypixel;
    return ioctl(instance->output_fd, TIOCSWINSZ, &window);
}

int channel_process_signal(channel_process_table_t *table, size_t index,
                           uint32_t handle, int signum)
{
    channel_process_instance_t *instance =
        owned_instance(table, index, handle);

    if (instance == NULL)
        return -1;
    if (instance->reaped || signum <= 0 || signum > 63) {
        errno = EINVAL;
        return -1;
    }
    return kill(instance->pid, signum);
}

static int64_t deadline_after(int64_t now_ms, int64_t delay_ms)
{
    if (delay_ms > INT64_MAX - now_ms)
        return INT64_MAX;
    return now_ms + delay_ms;
}

static int close_instance_fds(channel_process_instance_t *instance)
{
    int input_fd = instance->input_fd;
    int output_fd = instance->output_fd;
    int result = 0;

    instance->input_fd = -1;
    instance->output_fd = -1;
    instance->input_closed = 1U;
    instance->output_eof = 1U;
    if (input_fd >= 0 && close(input_fd) != 0)
        result = -1;
    if (output_fd >= 0 && output_fd != input_fd && close(output_fd) != 0)
        result = -1;
    return result;
}

int channel_process_cancel(channel_process_table_t *table, size_t index,
                           uint32_t handle, int64_t now_ms,
                           int64_t term_grace_ms)
{
    channel_process_instance_t *instance =
        owned_instance(table, index, handle);
    int result = 0;
    int saved_errno = 0;

    if (instance == NULL)
        return -1;
    if (now_ms < 0 || term_grace_ms < 0) {
        errno = EINVAL;
        return -1;
    }
    if (close_instance_fds(instance) != 0) {
        result = -1;
        saved_errno = errno;
    }
    if (instance->reaped)
        return result;
    if (!instance->term_sent) {
        instance->term_sent = 1U;
        instance->state = CHANNEL_PROCESS_TERMINATING;
        instance->termination_deadline_ms =
            deadline_after(now_ms, term_grace_ms);
        if (kill(instance->pid, SIGTERM) != 0 && errno != ESRCH) {
            if (result == 0)
                saved_errno = errno;
            result = -1;
        }
    }
    if (result != 0)
        errno = saved_errno;
    return result;
}

int channel_process_cancel_all(channel_process_table_t *table,
                               int64_t now_ms, int64_t term_grace_ms)
{
    int result = 0;
    int saved_errno = 0;
    size_t i;

    if (table == NULL || now_ms < 0 || term_grace_ms < 0) {
        errno = EINVAL;
        return -1;
    }
    for (i = 0U; i < CHANNEL_PROCESS_MAX_INSTANCES; i++) {
        channel_process_instance_t *instance = &table->instances[i];

        if (!instance->active)
            continue;
        if (channel_process_cancel(table, i, instance->handle, now_ms,
                                   term_grace_ms) != 0) {
            if (result == 0)
                saved_errno = errno;
            result = -1;
        }
    }
    if (result != 0)
        errno = saved_errno;
    return result;
}

static uint32_t normalized_wait_status(int status)
{
    if (WIFEXITED(status))
        return (uint32_t)WEXITSTATUS(status);
    if (WIFSIGNALED(status))
        return (uint32_t)(128 + WTERMSIG(status));
    return UINT32_C(127);
}

int channel_process_reap_sweep(channel_process_table_t *table)
{
    int reaped_count = 0;
    int result = 0;
    int saved_errno = 0;
    size_t i;

    if (table == NULL) {
        errno = EINVAL;
        return -1;
    }
    for (i = 0U; i < CHANNEL_PROCESS_MAX_INSTANCES; i++) {
        channel_process_instance_t *instance = &table->instances[i];
        int status;
        pid_t waited;

        if (!instance->active || instance->reaped || instance->pid <= 0)
            continue;
        do {
            waited = waitpid(instance->pid, &status, WNOHANG);
        } while (waited < 0 && errno == EINTR);
        if (waited == 0)
            continue;
        if (waited < 0) {
            if (result == 0)
                saved_errno = errno;
            result = -1;
            continue;
        }
        instance->exit_code = normalized_wait_status(status);
        instance->reaped = 1U;
        instance->state = CHANNEL_PROCESS_EXITED;
        if (close_instance_input(instance) != 0 && result == 0) {
            saved_errno = errno;
            result = -1;
        }
        reaped_count++;
    }
    if (result != 0) {
        errno = saved_errno;
        return -1;
    }
    return reaped_count;
}

static int unreaped_count(const channel_process_table_t *table)
{
    int count = 0;
    size_t i;

    for (i = 0U; i < CHANNEL_PROCESS_MAX_INSTANCES; i++) {
        if (table->instances[i].active && !table->instances[i].reaped)
            count++;
    }
    return count;
}

int channel_process_maintain(channel_process_table_t *table, int64_t now_ms)
{
    int result = 0;
    int saved_errno = 0;
    size_t i;

    if (table == NULL || now_ms < 0) {
        errno = EINVAL;
        return -1;
    }
    if (channel_process_reap_sweep(table) < 0) {
        result = -1;
        saved_errno = errno;
    }
    for (i = 0U; i < CHANNEL_PROCESS_MAX_INSTANCES; i++) {
        channel_process_instance_t *instance = &table->instances[i];

        if (!instance->active || instance->reaped || !instance->term_sent ||
            instance->kill_sent ||
            now_ms < instance->termination_deadline_ms)
            continue;
        instance->kill_sent = 1U;
        if (kill(instance->pid, SIGKILL) != 0 && errno != ESRCH) {
            if (result == 0)
                saved_errno = errno;
            result = -1;
        }
    }
    if (channel_process_reap_sweep(table) < 0 && result == 0) {
        result = -1;
        saved_errno = errno;
    }
    if (result != 0) {
        errno = saved_errno;
        return -1;
    }
    return unreaped_count(table);
}

int channel_process_result(const channel_process_table_t *table,
                           size_t index, uint32_t handle,
                           uint32_t *exit_code_out)
{
    const channel_process_instance_t *instance =
        owned_const_instance(table, index, handle);

    if (instance == NULL || exit_code_out == NULL) {
        if (instance != NULL)
            errno = EINVAL;
        return -1;
    }
    if (!instance->reaped || !instance->output_eof)
        return 0;
    *exit_code_out = instance->exit_code;
    return 1;
}

int channel_process_release(channel_process_table_t *table, size_t index,
                            uint32_t handle)
{
    channel_process_instance_t *instance =
        owned_instance(table, index, handle);
    int result;

    if (instance == NULL)
        return -1;
    if (!instance->reaped || !instance->output_eof) {
        errno = EBUSY;
        return -1;
    }
    result = close_instance_fds(instance);
    memset(instance, 0, sizeof(*instance));
    instance->input_fd = -1;
    instance->output_fd = -1;
    return result;
}

static int monotonic_ms(int64_t *now_out)
{
    struct timespec value;

    if (now_out == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0)
        return -1;
    if (value.tv_sec > INT64_MAX / INT64_C(1000)) {
        *now_out = INT64_MAX;
        return 0;
    }
    *now_out = (int64_t)value.tv_sec * INT64_C(1000) +
               (int64_t)(value.tv_nsec / 1000000L);
    return 0;
}

int channel_process_table_destroy(channel_process_table_t *table,
                                  int64_t term_grace_ms,
                                  int64_t reap_horizon_ms)
{
    struct timespec pause_time;
    int64_t now_ms;
    int64_t horizon;
    size_t i;

    if (table == NULL || term_grace_ms < 0 || reap_horizon_ms < 0 ||
        term_grace_ms > reap_horizon_ms) {
        errno = EINVAL;
        return -1;
    }
    if (monotonic_ms(&now_ms) != 0)
        return -1;
    horizon = deadline_after(now_ms, reap_horizon_ms);
    if (channel_process_cancel_all(table, now_ms, term_grace_ms) != 0)
        return -1;
    pause_time.tv_sec = 0;
    pause_time.tv_nsec = 1000000L;
    for (;;) {
        int remaining = channel_process_maintain(table, now_ms);

        if (remaining < 0)
            return -1;
        if (remaining == 0)
            break;
        if (now_ms >= horizon) {
            errno = ETIMEDOUT;
            return -1;
        }
        (void)nanosleep(&pause_time, NULL);
        if (monotonic_ms(&now_ms) != 0)
            return -1;
    }
    for (i = 0U; i < CHANNEL_PROCESS_MAX_INSTANCES; i++) {
        if (table->instances[i].active &&
            channel_process_release(table, i,
                                    table->instances[i].handle) != 0)
            return -1;
    }
    return 0;
}
