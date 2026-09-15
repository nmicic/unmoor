/*
 * child_transfer.c — child-transfer fixed two-child transfer supervisor
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

#include "child_transfer.h"

#include "attach_local.h"
#include "bulk.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "process_hygiene.h"

#define CHILD_TRANSFER_MAGIC_0 ((uint8_t)'U')
#define CHILD_TRANSFER_MAGIC_1 ((uint8_t)'C')
#define CHILD_TRANSFER_MAGIC_2 ((uint8_t)'T')
#define CHILD_TRANSFER_MAGIC_3 ((uint8_t)'1')
#define CHILD_TRANSFER_RESULT_VERSION UINT8_C(1)

#ifdef UNMOOR_CHILD_TRANSFER_TEST
static int child_transfer_test_close_fd = -1;
static unsigned int child_transfer_test_close_failure_count;

int child_transfer_test_fail_next_result_close(int fd)
{
    if (fd < 0 || child_transfer_test_close_fd >= 0) {
        errno = EINVAL;
        return -1;
    }
    child_transfer_test_close_fd = fd;
    return 0;
}

unsigned int child_transfer_test_result_close_failures(void)
{
    return child_transfer_test_close_failure_count;
}
#endif

static int result_fd_close(int fd)
{
#ifdef UNMOOR_CHILD_TRANSFER_TEST
    if (fd == child_transfer_test_close_fd) {
        child_transfer_test_close_fd = -1;
        child_transfer_test_close_failure_count++;
        (void)close(fd);
        errno = EIO;
        return -1;
    }
#endif
    return close(fd);
}

static void store32le(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)value;
    out[1] = (uint8_t)(value >> 8);
    out[2] = (uint8_t)(value >> 16);
    out[3] = (uint8_t)(value >> 24);
}

static uint32_t load32le(const uint8_t *in)
{
    return (uint32_t)in[0] |
           ((uint32_t)in[1] << 8) |
           ((uint32_t)in[2] << 16) |
           ((uint32_t)in[3] << 24);
}

static void store64le(uint8_t *out, uint64_t value)
{
    store32le(out, (uint32_t)value);
    store32le(out + 4U, (uint32_t)(value >> 32));
}

static uint64_t load64le(const uint8_t *in)
{
    return (uint64_t)load32le(in) |
           ((uint64_t)load32le(in + 4U) << 32);
}

static int kind_slot(uint8_t kind, size_t *slot_out)
{
    if (slot_out == NULL)
        return -1;
    if (kind == CHILD_TRANSFER_KIND_PUSH)
        *slot_out = CHILD_TRANSFER_PUSH_SLOT;
    else if (kind == CHILD_TRANSFER_KIND_PULL)
        *slot_out = CHILD_TRANSFER_PULL_SLOT;
    else
        return -1;
    return 0;
}

static int set_cloexec(int fd, int enabled)
{
    int flags = fcntl(fd, F_GETFD);

    if (flags < 0)
        return -1;
    if (enabled)
        flags |= FD_CLOEXEC;
    else
        flags &= ~FD_CLOEXEC;
    return fcntl(fd, F_SETFD, flags);
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
    if (moved >= 0 && set_cloexec(moved, 1) != 0) {
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

static int prepare_pipe(int fds[2])
{
    int first;
    int second;

    if (pipe(fds) != 0)
        return -1;
    first = move_above_standard(fds[0]);
    if (first < 0) {
        int saved_errno = errno;

        (void)close(fds[1]);
        errno = saved_errno;
        return -1;
    }
    fds[0] = first;
    second = move_above_standard(fds[1]);
    if (second < 0) {
        int saved_errno = errno;

        (void)close(fds[0]);
        errno = saved_errno;
        return -1;
    }
    fds[1] = second;
    if (set_cloexec(fds[0], 1) != 0 ||
        set_cloexec(fds[1], 1) != 0 ||
        set_nonblocking(fds[0]) != 0) {
        int saved_errno = errno;

        (void)close(fds[0]);
        (void)close(fds[1]);
        errno = saved_errno;
        return -1;
    }
    return 0;
}

static void close_unless_result(int fd)
{
    if (fd > STDERR_FILENO && fd != CHILD_TRANSFER_RESULT_FD)
        (void)close(fd);
}

static void child_close_owned_fds(
    const child_transfer_table_t *table,
    const int extra_close_fds[], size_t extra_close_fd_count,
    int result_read_fd, int result_write_fd, int null_fd)
{
    size_t i;

    for (i = 0U; i < CHILD_TRANSFER_SLOT_COUNT; i++)
        close_unless_result(table->slots[i].result_fd);
    for (i = 0U; i < extra_close_fd_count; i++)
        close_unless_result(extra_close_fds[i]);
    close_unless_result(result_read_fd);
    close_unless_result(result_write_fd);
    close_unless_result(null_fd);
}

static void instance_reset(child_transfer_instance_t *instance)
{
    memset(instance, 0, sizeof(*instance));
    instance->result_fd = -1;
}

void child_transfer_table_init(child_transfer_table_t *table)
{
    size_t i;

    if (table == NULL)
        return;
    memset(table, 0, sizeof(*table));
    for (i = 0U; i < CHILD_TRANSFER_SLOT_COUNT; i++)
        table->slots[i].result_fd = -1;
}

size_t child_transfer_active_count(const child_transfer_table_t *table)
{
    size_t count = 0U;
    size_t i;

    if (table == NULL)
        return 0U;
    for (i = 0U; i < CHILD_TRANSFER_SLOT_COUNT; i++)
        if (table->slots[i].active)
            count++;
    return count;
}

int child_transfer_direction_active(const child_transfer_table_t *table,
                                    uint8_t kind)
{
    size_t slot;

    if (table == NULL || kind_slot(kind, &slot) != 0)
        return 0;
    return table->slots[slot].active != 0U;
}

const child_transfer_instance_t *child_transfer_get(
    const child_transfer_table_t *table, size_t slot)
{
    if (table == NULL || slot >= CHILD_TRANSFER_SLOT_COUNT ||
        !table->slots[slot].active)
        return NULL;
    return &table->slots[slot];
}

int child_transfer_next_handle(const child_transfer_table_t *table,
                               uint8_t kind, size_t *slot_out,
                               uint32_t *handle_out)
{
    size_t slot;
    uint32_t generation;

    if (table == NULL || slot_out == NULL || handle_out == NULL ||
        kind_slot(kind, &slot) != 0 || table->slots[slot].active ||
        table->last_generation[slot] >= UINT32_C(0x0fffffff)) {
        errno = EBUSY;
        return -1;
    }
    generation = table->last_generation[slot] + 1U;
    *slot_out = slot;
    *handle_out = (generation << 4) | (uint32_t)(slot + 1U);
    return 0;
}

int child_transfer_find_owner(const child_transfer_table_t *table,
                              uint64_t owner, size_t *slot_out)
{
    size_t slot;

    if (table == NULL || owner == 0U || slot_out == NULL) {
        errno = EINVAL;
        return -1;
    }
    for (slot = 0U; slot < CHILD_TRANSFER_SLOT_COUNT; slot++) {
        if (table->slots[slot].active &&
            table->slots[slot].owner == owner) {
            *slot_out = slot;
            return 0;
        }
    }
    errno = ENOENT;
    return -1;
}

static int child_transfer_path_count_valid(uint8_t count)
{
    return count == 2U || count == 4U || count == 8U || count == 16U ||
           count == 32U;
}

static unsigned int child_transfer_popcount16(uint16_t value)
{
    unsigned int count = 0U;

    while (value != 0U) {
        count += (unsigned int)(value & UINT16_C(1));
        value >>= 1;
    }
    return count;
}

static unsigned int child_transfer_log2(uint8_t value)
{
    unsigned int result = 0U;

    while (value > 1U) {
        value >>= 1;
        result++;
    }
    return result;
}

static int child_transfer_text_valid(const char *text)
{
    return text != NULL && text[0] != '\0';
}

static int child_transfer_confine_level_valid(const char *level)
{
    return level == NULL || strcmp(level, "off") == 0 ||
        strcmp(level, "best-effort") == 0 || strcmp(level, "require") == 0;
}

static int child_transfer_argv_append(child_transfer_argv_t *arguments,
                                      const char *value)
{
    if (arguments == NULL || value == NULL ||
        arguments->argc >= CHILD_TRANSFER_MAX_ARGS) {
        errno = E2BIG;
        return -1;
    }
    arguments->argv[arguments->argc++] = value;
    arguments->argv[arguments->argc] = NULL;
    return 0;
}

int child_transfer_argv_build(const child_transfer_launch_policy_t *policy,
                              const child_transfer_command_t *command,
                              child_transfer_argv_t *arguments)
{
    traffic_profile_result_t resolved;
    const char *profile;
    const char *operation;
    const char *layout = NULL;
    int timeout_count;
    int wire_count;
    int stall_count;
    int transfer_count;

    if (policy == NULL || command == NULL || arguments == NULL ||
        !child_transfer_text_valid(policy->program_path) ||
        !child_transfer_text_valid(policy->attach_socket_path) ||
        policy->attach_socket_path[0] != '/' ||
        !child_transfer_text_valid(policy->udp_host) ||
        !child_transfer_text_valid(policy->remote_command) ||
        (policy->remote_bind_host != NULL &&
         !child_transfer_text_valid(policy->remote_bind_host)) ||
        policy->timeout_seconds < 1 || policy->timeout_seconds > 3600 ||
        policy->log_json > 1U ||
        policy->port_layout > TRANSPORT_UDP_PORT_LAYOUT_RANDOM ||
        policy->port_mask_explicit > 1U ||
        policy->pq_carrier_required > 1U ||
        !child_transfer_confine_level_valid(policy->server_confine_level) ||
        command->transfer_id == 0U ||
        command->wire_budget < 768U || command->wire_budget > 8952U ||
        command->stall_seconds < 1U || command->stall_seconds > 300U ||
        (command->options & (uint8_t)~UINT8_C(0x01)) != 0U ||
        command->local_path == NULL || command->remote_path == NULL ||
        command->local_path_length == 0U ||
        command->local_path_length > CHILD_TRANSFER_PATH_MAX ||
        command->remote_path_length == 0U ||
        command->remote_path_length > CHILD_TRANSFER_PATH_MAX ||
        memchr(command->local_path, 0, command->local_path_length) != NULL ||
        memchr(command->remote_path, 0, command->remote_path_length) != NULL) {
        errno = EINVAL;
        return -1;
    }
    if (command->kind == CHILD_TRANSFER_KIND_PUSH)
        operation = "push";
    else if (command->kind == CHILD_TRANSFER_KIND_PULL)
        operation = "pull";
    else {
        errno = EINVAL;
        return -1;
    }
    if (policy->traffic_profile == TRAFFIC_PROFILE_ENTERPRISE)
        profile = "enterprise";
    else if (policy->traffic_profile == TRAFFIC_PROFILE_LAB)
        profile = "lab";
    else {
        errno = EINVAL;
        return -1;
    }
    if (traffic_profile_resolve(
            policy->traffic_profile, TRAFFIC_APPLICATION_BULK, 1,
            policy->multipath_option, policy->exact_paths, &resolved) != 0 ||
        policy->configured_paths != resolved.configured_paths) {
        errno = EINVAL;
        return -1;
    }
    if (policy->multipath_option == TRAFFIC_MULTIPATH_OPTION_NONE) {
        if (policy->exact_paths != 0U) {
            errno = EINVAL;
            return -1;
        }
    } else {
        if (!child_transfer_path_count_valid(policy->configured_paths) ||
            (policy->multipath_option == TRAFFIC_MULTIPATH_OPTION_EXACT &&
             policy->exact_paths != policy->configured_paths) ||
            (policy->multipath_option == TRAFFIC_MULTIPATH_OPTION_BARE &&
             policy->exact_paths != 0U) ||
            (policy->multipath_option != TRAFFIC_MULTIPATH_OPTION_BARE &&
             policy->multipath_option != TRAFFIC_MULTIPATH_OPTION_EXACT)) {
            errno = EINVAL;
            return -1;
        }
    }
    if (policy->configured_paths == 1U) {
        if (policy->port_layout != TRANSPORT_UDP_PORT_LAYOUT_BLOCK ||
            policy->port_mask_explicit != 0U || policy->port_mask != 0U) {
            errno = EINVAL;
            return -1;
        }
    } else {
        if (policy->port_layout == TRANSPORT_UDP_PORT_LAYOUT_CUBE) {
            if (policy->port_mask_explicit &&
                (policy->port_mask == 0U ||
                 (policy->port_mask & UINT16_C(0xc000)) != 0U ||
                 child_transfer_popcount16(policy->port_mask) !=
                     child_transfer_log2(policy->configured_paths))) {
                errno = EINVAL;
                return -1;
            }
            if (!policy->port_mask_explicit && policy->port_mask != 0U) {
                errno = EINVAL;
                return -1;
            }
            layout = "cube";
        } else if (policy->port_layout ==
                   TRANSPORT_UDP_PORT_LAYOUT_RANDOM) {
            if (policy->port_mask_explicit || policy->port_mask != 0U) {
                errno = EINVAL;
                return -1;
            }
            layout = "random";
        } else if (policy->port_layout !=
                       TRANSPORT_UDP_PORT_LAYOUT_BLOCK ||
                   policy->port_mask_explicit || policy->port_mask != 0U) {
            errno = EINVAL;
            return -1;
        }
    }

    memset(arguments, 0, sizeof(*arguments));
    memcpy(arguments->local_path, command->local_path,
           command->local_path_length);
    memcpy(arguments->remote_path, command->remote_path,
           command->remote_path_length);
    timeout_count = snprintf(arguments->timeout, sizeof(arguments->timeout),
                             "%d", policy->timeout_seconds);
    wire_count = snprintf(arguments->wire_budget,
                          sizeof(arguments->wire_budget), "%u",
                          (unsigned int)command->wire_budget);
    stall_count = snprintf(arguments->stall_seconds,
                           sizeof(arguments->stall_seconds), "%u",
                           (unsigned int)command->stall_seconds);
    transfer_count = snprintf(arguments->transfer_id,
                              sizeof(arguments->transfer_id), "%llu",
                              (unsigned long long)command->transfer_id);
    if (timeout_count <= 0 ||
        (size_t)timeout_count >= sizeof(arguments->timeout) ||
        wire_count <= 0 ||
        (size_t)wire_count >= sizeof(arguments->wire_budget) ||
        stall_count <= 0 ||
        (size_t)stall_count >= sizeof(arguments->stall_seconds) ||
        transfer_count <= 0 ||
        (size_t)transfer_count >= sizeof(arguments->transfer_id)) {
        errno = EOVERFLOW;
        return -1;
    }
    if (policy->multipath_option == TRAFFIC_MULTIPATH_OPTION_EXACT) {
        int count = snprintf(arguments->multipath,
                             sizeof(arguments->multipath), "--multipath=%u",
                             (unsigned int)policy->exact_paths);

        if (count <= 0 || (size_t)count >= sizeof(arguments->multipath)) {
            errno = EOVERFLOW;
            return -1;
        }
    }
    if (policy->port_mask_explicit) {
        int count = snprintf(arguments->port_mask,
                             sizeof(arguments->port_mask), "0x%04x",
                             (unsigned int)policy->port_mask);

        if (count <= 0 || (size_t)count >= sizeof(arguments->port_mask)) {
            errno = EOVERFLOW;
            return -1;
        }
    }

#define APPEND(value) do { \
        if (child_transfer_argv_append(arguments, (value)) != 0) \
            return -1; \
    } while (0)
    APPEND(policy->program_path);
    APPEND(operation);
    APPEND("--profile");
    APPEND(profile);
    if (policy->log_json) {
        APPEND("--log-format");
        APPEND("json");
    }
    if (policy->multipath_option == TRAFFIC_MULTIPATH_OPTION_BARE)
        APPEND("--multipath");
    else if (policy->multipath_option == TRAFFIC_MULTIPATH_OPTION_EXACT)
        APPEND(arguments->multipath);
    if (layout != NULL) {
        APPEND("--port-layout");
        APPEND(layout);
    }
    if (policy->port_mask_explicit) {
        APPEND("--port-mask");
        APPEND(arguments->port_mask);
    }
    if (policy->confine_level != NULL) {
        APPEND("--confine");
        APPEND(policy->confine_level);
    }
    if (policy->server_confine_level != NULL) {
        APPEND("--server-confine");
        APPEND(policy->server_confine_level);
    }
    /* secure-default-policy: a child inherits the authenticated control association's
     * resolved crypto profile.  It must never reinterpret a later product
     * default.  A non-pq-hybrid control is exact legacy/off; selected pq-hybrid is
     * exact require plus its private carrier marker. */
    APPEND("--pq");
    APPEND(policy->pq_carrier_required != 0U ? "require" : "off");
    if (policy->pq_carrier_required != 0U)
        APPEND("--pq-carrier=require");
    APPEND("--bootstrap-exec-socket");
    APPEND(policy->attach_socket_path);
    APPEND("--udp-host");
    APPEND(policy->udp_host);
    APPEND("--remote");
    APPEND(policy->remote_command);
    if (policy->remote_bind_host != NULL) {
        APPEND("--remote-bind-host");
        APPEND(policy->remote_bind_host);
    }
    APPEND("--timeout");
    APPEND(arguments->timeout);
    APPEND("--bulk-mtu");
    APPEND(arguments->wire_budget);
    APPEND("--bulk-stall-secs");
    APPEND(arguments->stall_seconds);
    if ((command->options & UINT8_C(0x01)) != 0U)
        APPEND("--force");
    APPEND("--child-result-fd");
    APPEND("3");
    APPEND("--child-transfer-id");
    APPEND(arguments->transfer_id);
    APPEND("--");
    if (command->kind == CHILD_TRANSFER_KIND_PUSH) {
        APPEND(arguments->local_path);
        APPEND(arguments->remote_path);
    } else {
        APPEND(arguments->remote_path);
        APPEND(arguments->local_path);
    }
#undef APPEND
    return 0;
}

static size_t argv_count(const char *const argv[])
{
    size_t count;

    if (argv == NULL)
        return 0U;
    for (count = 0U; count <= CHILD_TRANSFER_MAX_ARGS; count++) {
        if (argv[count] == NULL)
            return count;
        if (argv[count][0] == '\0')
            return 0U;
    }
    return 0U;
}

int child_transfer_spawn(
    child_transfer_table_t *table, size_t slot, uint8_t kind,
    uint64_t owner, uint32_t handle, uint64_t transfer_id,
    const char *const argv[],
    const int extra_close_fds[], size_t extra_close_fd_count)
{
    int result_pipe[2] = { -1, -1 };
    int null_fd = -1;
    size_t expected_slot;
    uint32_t expected_handle;
    size_t count;
    pid_t pid;

    count = argv_count(argv);
    if (table == NULL ||
        child_transfer_next_handle(table, kind, &expected_slot,
                                   &expected_handle) != 0 ||
        slot != expected_slot || handle != expected_handle ||
        slot >= CHILD_TRANSFER_SLOT_COUNT ||
        table->slots[slot].active || owner == 0U || transfer_id == 0U ||
        count == 0U ||
        count > CHILD_TRANSFER_MAX_ARGS ||
        extra_close_fd_count > CHILD_TRANSFER_MAX_EXTRA_CLOSE_FDS ||
        (extra_close_fd_count != 0U && extra_close_fds == NULL)) {
        errno = EINVAL;
        return -1;
    }
    for (size_t i = 0U; i < extra_close_fd_count; i++) {
        if (extra_close_fds[i] <= STDERR_FILENO) {
            errno = EINVAL;
            return -1;
        }
    }
    if (prepare_pipe(result_pipe) != 0)
        return -1;
    null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (null_fd < 0) {
        int saved_errno = errno;

        (void)close(result_pipe[0]);
        (void)close(result_pipe[1]);
        errno = saved_errno;
        return -1;
    }
    null_fd = move_above_standard(null_fd);
    if (null_fd < 0) {
        int saved_errno = errno;

        (void)close(result_pipe[0]);
        (void)close(result_pipe[1]);
        errno = saved_errno;
        return -1;
    }
    if (set_cloexec(null_fd, 1) != 0) {
        int saved_errno = errno;

        (void)close(result_pipe[0]);
        (void)close(result_pipe[1]);
        (void)close(null_fd);
        errno = saved_errno;
        return -1;
    }
    pid = fork();
    if (pid < 0) {
        int saved_errno = errno;

        (void)close(result_pipe[0]);
        (void)close(result_pipe[1]);
        (void)close(null_fd);
        errno = saved_errno;
        return -1;
    }
    if (pid == 0) {
        static const int keep_fds[] = { CHILD_TRANSFER_RESULT_FD };

        process_reset_child_signals();
        if (dup2(null_fd, STDIN_FILENO) < 0 ||
            dup2(null_fd, STDOUT_FILENO) < 0 ||
            dup2(null_fd, STDERR_FILENO) < 0 ||
            dup2(result_pipe[1], CHILD_TRANSFER_RESULT_FD) < 0 ||
            set_cloexec(CHILD_TRANSFER_RESULT_FD, 0) != 0)
            _exit(127);
        child_close_owned_fds(table, extra_close_fds,
                              extra_close_fd_count, result_pipe[0],
                              result_pipe[1], null_fd);
        if (process_close_from(STDERR_FILENO + 1, keep_fds,
                               sizeof(keep_fds) / sizeof(keep_fds[0])) != 0)
            _exit(127);
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }
    (void)close(result_pipe[1]);
    (void)close(null_fd);
    instance_reset(&table->slots[slot]);
    table->slots[slot].owner = owner;
    table->slots[slot].handle = handle;
    table->slots[slot].transfer_id = transfer_id;
    table->slots[slot].pid = pid;
    table->slots[slot].result_fd = result_pipe[0];
    table->slots[slot].kind = kind;
    table->slots[slot].state = CHILD_TRANSFER_RUNNING;
    table->slots[slot].active = 1U;
    table->last_generation[slot] = handle >> 4;
    return 0;
}

static child_transfer_instance_t *owned_instance(
    child_transfer_table_t *table, size_t slot, uint32_t handle)
{
    if (table == NULL || slot >= CHILD_TRANSFER_SLOT_COUNT ||
        !table->slots[slot].active ||
        table->slots[slot].handle != handle) {
        errno = EINVAL;
        return NULL;
    }
    return &table->slots[slot];
}

static const child_transfer_instance_t *owned_const_instance(
    const child_transfer_table_t *table, size_t slot, uint32_t handle)
{
    if (table == NULL || slot >= CHILD_TRANSFER_SLOT_COUNT ||
        !table->slots[slot].active ||
        table->slots[slot].handle != handle) {
        errno = EINVAL;
        return NULL;
    }
    return &table->slots[slot];
}

static int64_t deadline_after(int64_t now_ms, int64_t delay_ms)
{
    if (delay_ms > INT64_MAX - now_ms)
        return INT64_MAX;
    return now_ms + delay_ms;
}

int child_transfer_cancel(child_transfer_table_t *table, size_t slot,
                          uint32_t handle, int64_t now_ms,
                          int64_t term_grace_ms)
{
    child_transfer_instance_t *instance =
        owned_instance(table, slot, handle);

    if (instance == NULL)
        return -1;
    if (now_ms < 0 || term_grace_ms < 0) {
        errno = EINVAL;
        return -1;
    }
    instance->cancel_requested = 1U;
    if (instance->reaped || instance->term_sent)
        return 0;
    instance->term_sent = 1U;
    instance->state = CHILD_TRANSFER_TERMINATING;
    instance->termination_deadline_ms =
        deadline_after(now_ms, term_grace_ms);
    if (kill(instance->pid, SIGTERM) != 0 && errno != ESRCH)
        return -1;
    return 0;
}

int child_transfer_cancel_all(child_transfer_table_t *table,
                              int64_t now_ms, int64_t term_grace_ms)
{
    int result = 0;
    int saved_errno = 0;
    size_t i;

    if (table == NULL || now_ms < 0 || term_grace_ms < 0) {
        errno = EINVAL;
        return -1;
    }
    for (i = 0U; i < CHILD_TRANSFER_SLOT_COUNT; i++) {
        child_transfer_instance_t *instance = &table->slots[i];

        if (!instance->active)
            continue;
        if (child_transfer_cancel(table, i, instance->handle, now_ms,
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

static int decode_result(child_transfer_instance_t *instance)
{
    const uint8_t *record = instance->result_bytes;

    if (instance->result_used != CHILD_TRANSFER_RESULT_BYTES ||
        record[0] != CHILD_TRANSFER_MAGIC_0 ||
        record[1] != CHILD_TRANSFER_MAGIC_1 ||
        record[2] != CHILD_TRANSFER_MAGIC_2 ||
        record[3] != CHILD_TRANSFER_MAGIC_3 ||
        record[4] != CHILD_TRANSFER_RESULT_VERSION ||
        record[5] != instance->kind || record[6] != 0U || record[7] != 0U ||
        load64le(record + 8U) != instance->transfer_id ||
        load32le(record + 20U) != 0U) {
        instance->result_invalid = 1U;
        return -1;
    }
    instance->result_code = load32le(record + 16U);
    instance->result_valid = 1U;
    return 0;
}

static int drain_result(child_transfer_instance_t *instance)
{
    uint8_t extra;

    if (instance->result_eof || instance->result_fd < 0)
        return 0;
    for (;;) {
        ssize_t received;

        if (instance->result_used < CHILD_TRANSFER_RESULT_BYTES) {
            received = read(
                instance->result_fd,
                instance->result_bytes + instance->result_used,
                CHILD_TRANSFER_RESULT_BYTES - instance->result_used);
            if (received > 0) {
                instance->result_used += (size_t)received;
                continue;
            }
        } else {
            received = read(instance->result_fd, &extra, 1U);
            if (received > 0) {
                instance->result_invalid = 1U;
                continue;
            }
        }
        if (received == 0) {
            int saved_errno = 0;

            instance->result_eof = 1U;
            if (result_fd_close(instance->result_fd) != 0)
                saved_errno = errno;
            instance->result_fd = -1;
            if (!instance->result_invalid)
                (void)decode_result(instance);
            if (saved_errno != 0) {
                /* POSIX leaves descriptor state after an interrupted close
                 * unspecified, so never retry it. EOF and the complete
                 * decoded record are already authoritative; keep this
                 * descriptor-cleanup failure local to the finished slot
                 * rather than cancelling its sibling transfer. */
                fprintf(stderr,
                        "child_transfer: result pipe close after EOF "
                        "failed for transfer=%llu: %s "
                        "(completion retained)\n",
                        (unsigned long long)instance->transfer_id,
                        strerror(saved_errno));
            }
            return 0;
        }
        if (errno == EINTR)
            continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;
        return -1;
    }
}

static int reap_one(child_transfer_instance_t *instance)
{
    int status;
    pid_t waited;

    if (!instance->active || instance->reaped || instance->pid <= 0)
        return 0;
    do {
        waited = waitpid(instance->pid, &status, WNOHANG);
    } while (waited < 0 && errno == EINTR);
    if (waited == 0)
        return 0;
    if (waited < 0)
        return -1;
    instance->process_exit_code = normalized_wait_status(status);
    instance->reaped = 1U;
    instance->state = CHILD_TRANSFER_EXITED;
    return 1;
}

static int active_unready_count(const child_transfer_table_t *table)
{
    int count = 0;
    size_t i;

    for (i = 0U; i < CHILD_TRANSFER_SLOT_COUNT; i++) {
        const child_transfer_instance_t *instance = &table->slots[i];

        if (instance->active && (!instance->reaped || !instance->result_eof))
            count++;
    }
    return count;
}

int child_transfer_maintain(child_transfer_table_t *table, int64_t now_ms)
{
    int result = 0;
    int saved_errno = 0;
    size_t i;

    if (table == NULL || now_ms < 0) {
        errno = EINVAL;
        return -1;
    }
    for (i = 0U; i < CHILD_TRANSFER_SLOT_COUNT; i++) {
        child_transfer_instance_t *instance = &table->slots[i];

        if (!instance->active)
            continue;
        if (drain_result(instance) != 0 && result == 0) {
            saved_errno = errno;
            result = -1;
        }
        if (reap_one(instance) < 0 && result == 0) {
            saved_errno = errno;
            result = -1;
        }
        if (!instance->reaped && instance->term_sent &&
            !instance->kill_sent &&
            now_ms >= instance->termination_deadline_ms) {
            instance->kill_sent = 1U;
            if (kill(instance->pid, SIGKILL) != 0 && errno != ESRCH &&
                result == 0) {
                saved_errno = errno;
                result = -1;
            }
        }
        if (reap_one(instance) < 0 && result == 0) {
            saved_errno = errno;
            result = -1;
        }
        if (drain_result(instance) != 0 && result == 0) {
            saved_errno = errno;
            result = -1;
        }
    }
    if (result != 0) {
        errno = saved_errno;
        return -1;
    }
    return active_unready_count(table);
}

int child_transfer_result(const child_transfer_table_t *table, size_t slot,
                          uint32_t handle, int *record_valid_out,
                          uint32_t *result_code_out,
                          uint32_t *process_exit_code_out)
{
    const child_transfer_instance_t *instance =
        owned_const_instance(table, slot, handle);

    if (instance == NULL || record_valid_out == NULL ||
        result_code_out == NULL || process_exit_code_out == NULL) {
        if (instance != NULL)
            errno = EINVAL;
        return -1;
    }
    if (!instance->reaped || !instance->result_eof)
        return 0;
    *record_valid_out = instance->result_valid != 0U;
    *result_code_out = instance->result_code;
    *process_exit_code_out = instance->process_exit_code;
    return 1;
}

uint32_t child_transfer_normalize_result(
    const child_transfer_instance_t *instance, int record_valid,
    uint32_t record_code, uint32_t process_exit_code)
{
    if (instance == NULL)
        return (uint32_t)BULK_CODE_PROTOCOL;
    if (instance->cancel_requested)
        return (uint32_t)BULK_CODE_CANCELLED;
    if (record_valid && record_code == CHILD_TRANSFER_RESULT_CONFINED &&
        process_exit_code != 0U)
        return ATTACH_LOCAL_BULK_CLOSE_CONFINED;
    if (!record_valid || record_code > (uint32_t)BULK_CODE_PACE_TOO_LOW ||
        ((record_code == (uint32_t)BULK_CODE_NONE) !=
         (process_exit_code == 0U)))
        return (uint32_t)BULK_CODE_PROTOCOL;
    return record_code;
}

int child_transfer_release(child_transfer_table_t *table, size_t slot,
                           uint32_t handle)
{
    child_transfer_instance_t *instance =
        owned_instance(table, slot, handle);

    if (instance == NULL)
        return -1;
    if (!instance->reaped || !instance->result_eof) {
        errno = EBUSY;
        return -1;
    }
    if (instance->result_fd >= 0 && close(instance->result_fd) != 0)
        return -1;
    instance_reset(instance);
    return 0;
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

int child_transfer_table_destroy(child_transfer_table_t *table,
                                 int64_t term_grace_ms,
                                 int64_t reap_horizon_ms)
{
    struct timespec pause_time;
    int64_t now_ms;
    int64_t horizon;
    int result = 0;
    int saved_errno = 0;
    size_t i;

    if (table == NULL || term_grace_ms < 0 || reap_horizon_ms < 0 ||
        term_grace_ms > reap_horizon_ms) {
        errno = EINVAL;
        return -1;
    }
    if (monotonic_ms(&now_ms) != 0) {
        saved_errno = errno;
        result = -1;
        now_ms = 0;
    }
    horizon = deadline_after(now_ms, reap_horizon_ms);
    if (child_transfer_cancel_all(table, now_ms, term_grace_ms) != 0) {
        if (result == 0)
            saved_errno = errno;
        result = -1;
    }
    pause_time.tv_sec = 0;
    pause_time.tv_nsec = 1000000L;
    for (;;) {
        int remaining = child_transfer_maintain(table, now_ms);

        if (remaining < 0) {
            if (result == 0)
                saved_errno = errno;
            result = -1;
            remaining = active_unready_count(table);
        }
        if (remaining == 0)
            break;
        if (now_ms >= horizon)
            break;
        (void)nanosleep(&pause_time, NULL);
        if (monotonic_ms(&now_ms) != 0) {
            if (result == 0)
                saved_errno = errno;
            result = -1;
            now_ms = horizon;
        }
    }

    /*
     * Never return ownership of an unreaped direct child to a caller that is
     * about to discard the table.  The ordinary loop above keeps the bounded
     * TERM/KILL policy.  At its horizon, force the exact owned PID and perform
     * the authoritative reap; no process-name lookup or unrelated wait is
     * permitted.  waitpid can only complete after this direct child exits.
     */
    for (i = 0U; i < CHILD_TRANSFER_SLOT_COUNT; i++) {
        child_transfer_instance_t *instance = &table->slots[i];

        if (!instance->active || instance->reaped)
            continue;
        instance->kill_sent = 1U;
        if (kill(instance->pid, SIGKILL) != 0 && errno != ESRCH) {
            if (result == 0)
                saved_errno = errno;
            result = -1;
        }
    }
    for (i = 0U; i < CHILD_TRANSFER_SLOT_COUNT; i++) {
        child_transfer_instance_t *instance = &table->slots[i];

        if (instance->active && !instance->reaped) {
            int status = 0;
            pid_t waited;

            do {
                waited = waitpid(instance->pid, &status, 0);
            } while (waited < 0 && errno == EINTR);
            if (waited == instance->pid) {
                instance->process_exit_code = normalized_wait_status(status);
                instance->reaped = 1U;
                instance->state = CHILD_TRANSFER_EXITED;
            } else if (waited < 0 && errno == ECHILD) {
                /* A SIGCHLD disposition may have auto-reaped it.  ECHILD is
                 * still authoritative evidence that this PID is no longer
                 * an owned waitable child. */
                instance->process_exit_code = UINT32_C(127);
                instance->reaped = 1U;
                instance->state = CHILD_TRANSFER_EXITED;
                if (result == 0)
                    saved_errno = ECHILD;
                result = -1;
            } else {
                if (result == 0)
                    saved_errno = errno;
                result = -1;
            }
        }
        if (!instance->active || !instance->reaped)
            continue;
        if (instance->result_fd >= 0 && close(instance->result_fd) != 0) {
            if (result == 0)
                saved_errno = errno;
            result = -1;
        }
        instance_reset(instance);
    }
    if (result != 0)
        errno = saved_errno != 0 ? saved_errno : EIO;
    return result;
}

int child_transfer_result_fd_arm(int fd)
{
    if (fd != CHILD_TRANSFER_RESULT_FD) {
        errno = EINVAL;
        return -1;
    }
    return set_cloexec(fd, 1);
}

uint32_t child_transfer_confinement_result(int apply_result,
                                           int child_result_fd)
{
    if (apply_result != 0 && child_result_fd == CHILD_TRANSFER_RESULT_FD)
        return CHILD_TRANSFER_RESULT_CONFINED;
    return 0U;
}

int child_transfer_result_write(int fd, uint8_t kind,
                                uint64_t transfer_id,
                                uint32_t result_code)
{
    uint8_t record[CHILD_TRANSFER_RESULT_BYTES];
    size_t offset = 0U;
    size_t slot;

    if (fd != CHILD_TRANSFER_RESULT_FD ||
        kind_slot(kind, &slot) != 0 || transfer_id == 0U) {
        errno = EINVAL;
        return -1;
    }
    memset(record, 0, sizeof(record));
    record[0] = CHILD_TRANSFER_MAGIC_0;
    record[1] = CHILD_TRANSFER_MAGIC_1;
    record[2] = CHILD_TRANSFER_MAGIC_2;
    record[3] = CHILD_TRANSFER_MAGIC_3;
    record[4] = CHILD_TRANSFER_RESULT_VERSION;
    record[5] = kind;
    store64le(record + 8U, transfer_id);
    store32le(record + 16U, result_code);
    while (offset < sizeof(record)) {
        ssize_t written = write(fd, record + offset,
                                sizeof(record) - offset);

        if (written > 0) {
            offset += (size_t)written;
            continue;
        }
        if (written < 0 && errno == EINTR)
            continue;
        if (written == 0)
            errno = EIO;
        return -1;
    }
    return 0;
}
