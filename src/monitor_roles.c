/*
 * monitor_roles.c — listener-monitor native C/M seccomp roles, unlinked preparation
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE
#include "monitor_roles.h"

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#ifndef __has_feature
#define __has_feature(x) 0
#endif

#if defined(__linux__) && defined(__LP64__) && \
    (defined(__x86_64__) || defined(__aarch64__)) && \
    defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ && \
    !defined(UNMOOR_SANITIZER) && !defined(__SANITIZE_ADDRESS__) && \
    !defined(__SANITIZE_THREAD__) && !__has_feature(address_sanitizer) && \
    !__has_feature(undefined_behavior_sanitizer) && \
    !__has_feature(thread_sanitizer) && !__has_feature(memory_sanitizer)
#define MONITOR_ROLE_NATIVE 1
#else
#define MONITOR_ROLE_NATIVE 0
#endif

#if MONITOR_ROLE_NATIVE
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#if defined(__x86_64__)
#define MONITOR_ROLE_AUDIT_ARCH AUDIT_ARCH_X86_64
#else
#define MONITOR_ROLE_AUDIT_ARCH AUDIT_ARCH_AARCH64
#endif

enum { MONITOR_ROLE_FILTER_MAX = 256 };

typedef struct role_builder {
    struct sock_filter instructions[MONITOR_ROLE_FILTER_MAX];
    size_t count;
} role_builder_t;

_Static_assert(sizeof(monitor_custodian_role_config_t) == 32U,
               "fixed C role configuration changed");

static int fail_with(int cause)
{
    errno = cause;
    return -1;
}

static int emit_stmt(role_builder_t *builder, unsigned short code,
                     uint32_t value)
{
    if (builder->count >= MONITOR_ROLE_FILTER_MAX)
        return fail_with(E2BIG);
    builder->instructions[builder->count++] =
        (struct sock_filter)BPF_STMT(code, value);
    return 0;
}

static int emit_jump(role_builder_t *builder, unsigned short code,
                     uint32_t value, uint8_t yes, uint8_t no)
{
    if (builder->count >= MONITOR_ROLE_FILTER_MAX)
        return fail_with(E2BIG);
    builder->instructions[builder->count++] =
        (struct sock_filter)BPF_JUMP(code, value, yes, no);
    return 0;
}

static int emit_kill(role_builder_t *builder)
{
    return emit_stmt(builder, BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
}

static int emit_allow(role_builder_t *builder)
{
    return emit_stmt(builder, BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
}

static int begin_syscall(role_builder_t *builder, int number, size_t *start)
{
    *start = builder->count;
    return emit_jump(builder, BPF_JMP | BPF_JEQ | BPF_K,
                     (uint32_t)number, 0, 0);
}

static int finish_syscall(role_builder_t *builder, size_t start)
{
    size_t distance;
    if (start >= builder->count)
        return fail_with(EPROTO);
    distance = builder->count - start - 1U;
    if (distance > UINT8_MAX)
        return fail_with(E2BIG);
    builder->instructions[start].jf = (uint8_t)distance;
    return 0;
}

static uint32_t arg_low(unsigned arg)
{
    return (uint32_t)offsetof(struct seccomp_data, args) + arg * 8U;
}

static uint32_t arg_high(unsigned arg)
{
    return arg_low(arg) + 4U;
}

static int require_high_zero(role_builder_t *builder, unsigned arg)
{
    return emit_stmt(builder, BPF_LD | BPF_W | BPF_ABS, arg_high(arg)) != 0 ||
           emit_jump(builder, BPF_JMP | BPF_JEQ | BPF_K, 0U, 1, 0) != 0 ||
           emit_kill(builder) != 0 ? -1 : 0;
}

static int require_one_of(role_builder_t *builder, unsigned arg,
                          const uint32_t *values, size_t count)
{
    size_t index;
    if (values == NULL || count == 0U || count > UINT8_MAX)
        return fail_with(EINVAL);
    if (require_high_zero(builder, arg) != 0 ||
        emit_stmt(builder, BPF_LD | BPF_W | BPF_ABS, arg_low(arg)) != 0)
        return -1;
    for (index = 0U; index < count; ++index) {
        size_t distance = count - index;
        if (distance > UINT8_MAX ||
            emit_jump(builder, BPF_JMP | BPF_JEQ | BPF_K, values[index],
                      (uint8_t)distance, 0) != 0)
            return -1;
    }
    return emit_kill(builder);
}

static int require_exact(role_builder_t *builder, unsigned arg,
                         uint32_t value)
{
    return require_one_of(builder, arg, &value, 1U);
}

static int require_signal(role_builder_t *builder, unsigned arg)
{
    if (require_high_zero(builder, arg) != 0 ||
        emit_stmt(builder, BPF_LD | BPF_W | BPF_ABS, arg_low(arg)) != 0 ||
        emit_jump(builder, BPF_JMP | BPF_JGE | BPF_K, 1U, 1, 0) != 0 ||
        emit_kill(builder) != 0 ||
        emit_jump(builder, BPF_JMP | BPF_JGT | BPF_K, 63U, 0, 1) != 0)
        return -1;
    return emit_kill(builder);
}

static int simple(role_builder_t *builder, int number)
{
    return emit_jump(builder, BPF_JMP | BPF_JEQ | BPF_K,
                     (uint32_t)number, 0, 1) != 0 ||
           emit_allow(builder) != 0 ? -1 : 0;
}

#define ROLE_SIMPLE(builder, name)                 \
    do {                                            \
        if (simple((builder), SYS_##name) != 0)     \
            return -1;                              \
    } while (0)

static int preamble(role_builder_t *builder)
{
    memset(builder, 0, sizeof(*builder));
    if (emit_stmt(builder, BPF_LD | BPF_W | BPF_ABS,
                  (uint32_t)offsetof(struct seccomp_data, arch)) != 0 ||
        emit_jump(builder, BPF_JMP | BPF_JEQ | BPF_K,
                  MONITOR_ROLE_AUDIT_ARCH, 1, 0) != 0 ||
        emit_kill(builder) != 0 ||
        emit_stmt(builder, BPF_LD | BPF_W | BPF_ABS,
                  (uint32_t)offsetof(struct seccomp_data, nr)) != 0)
        return -1;
#if defined(__x86_64__)
    if (emit_jump(builder, BPF_JMP | BPF_JSET | BPF_K,
                  UINT32_C(0x40000000), 0, 1) != 0 || emit_kill(builder) != 0)
        return -1;
#endif
    return 0;
}

static int common_memory_time(role_builder_t *builder)
{
    ROLE_SIMPLE(builder, read);
    ROLE_SIMPLE(builder, write);
#ifdef SYS_readv
    ROLE_SIMPLE(builder, readv);
#endif
#ifdef SYS_writev
    ROLE_SIMPLE(builder, writev);
#endif
    ROLE_SIMPLE(builder, close);
#ifdef SYS_fstat
    ROLE_SIMPLE(builder, fstat);
#endif
    ROLE_SIMPLE(builder, poll);
#ifdef SYS_ppoll
    ROLE_SIMPLE(builder, ppoll);
#endif
    ROLE_SIMPLE(builder, rt_sigreturn);
    ROLE_SIMPLE(builder, rt_sigaction);
    ROLE_SIMPLE(builder, rt_sigprocmask);
#ifdef SYS_restart_syscall
    ROLE_SIMPLE(builder, restart_syscall);
#endif
    ROLE_SIMPLE(builder, exit);
    ROLE_SIMPLE(builder, exit_group);
    ROLE_SIMPLE(builder, brk);
    ROLE_SIMPLE(builder, mmap);
    ROLE_SIMPLE(builder, munmap);
#ifdef SYS_mremap
    ROLE_SIMPLE(builder, mremap);
#endif
    ROLE_SIMPLE(builder, mprotect);
#ifdef SYS_madvise
    ROLE_SIMPLE(builder, madvise);
#endif
    ROLE_SIMPLE(builder, clock_gettime);
#ifdef SYS_clock_nanosleep
    ROLE_SIMPLE(builder, clock_nanosleep);
#endif
    ROLE_SIMPLE(builder, nanosleep);
    return 0;
}

static int emit_fcntl(role_builder_t *builder)
{
    static const uint32_t commands[] = {
        F_GETFD, F_SETFD, F_GETFL, F_SETFL
    };
    size_t start;
    if (begin_syscall(builder, SYS_fcntl, &start) != 0 ||
        require_one_of(builder, 1U, commands,
                       sizeof(commands) / sizeof(commands[0])) != 0 ||
        emit_allow(builder) != 0)
        return -1;
    return finish_syscall(builder, start);
}

static int emit_local_message(role_builder_t *builder, int number,
                              int channel_fd, uint32_t flags)
{
    size_t start;
    if (begin_syscall(builder, number, &start) != 0 ||
        require_exact(builder, 0U, (uint32_t)channel_fd) != 0 ||
        require_exact(builder, 2U, flags) != 0 || emit_allow(builder) != 0)
        return -1;
    return finish_syscall(builder, start);
}

static int emit_udp_socket_options(role_builder_t *builder)
{
    size_t start, ipv6_level, distance;
    /* The only socket option the UDP legs set is IPV6_V6ONLY; the listener
     * binds exclusively, so no SOL_SOCKET option is admitted. */
    if (begin_syscall(builder, SYS_setsockopt, &start) != 0 ||
        require_high_zero(builder, 1U) != 0 ||
        emit_stmt(builder, BPF_LD | BPF_W | BPF_ABS, arg_low(1U)) != 0)
        return -1;

    ipv6_level = builder->count;
    if (emit_jump(builder, BPF_JMP | BPF_JEQ | BPF_K,
                  (uint32_t)IPPROTO_IPV6, 0, 0) != 0 ||
        require_exact(builder, 2U, (uint32_t)IPV6_V6ONLY) != 0 ||
        emit_allow(builder) != 0)
        return -1;
    distance = builder->count - ipv6_level - 1U;
    if (distance > UINT8_MAX) return fail_with(E2BIG);
    builder->instructions[ipv6_level].jf = (uint8_t)distance;
    if (emit_kill(builder) != 0) return -1;
    return finish_syscall(builder, start);
}

static int build_m(role_builder_t *builder, int c_channel_fd)
{
    static const uint32_t socket_domains[] = { AF_INET, AF_INET6 };
    size_t start;
    if (preamble(builder) != 0 || common_memory_time(builder) != 0 ||
        emit_fcntl(builder) != 0)
        return -1;
    /* Existing session and PQ key lifetimes lock only their exact buffers.
     * Keep this M-only: C owns no secrets, and process-wide locking remains
     * outside the recorded role. */
    ROLE_SIMPLE(builder, mlock);
    ROLE_SIMPLE(builder, munlock);
#ifdef SYS_getpid
    ROLE_SIMPLE(builder, getpid);
#endif
#ifdef SYS_getppid
    ROLE_SIMPLE(builder, getppid);
#endif
#ifdef SYS_getuid
    ROLE_SIMPLE(builder, getuid);
#endif
#ifdef SYS_geteuid
    ROLE_SIMPLE(builder, geteuid);
#endif
#ifdef SYS_getgid
    ROLE_SIMPLE(builder, getgid);
#endif
#ifdef SYS_getegid
    ROLE_SIMPLE(builder, getegid);
#endif
    ROLE_SIMPLE(builder, getrandom);

    if (begin_syscall(builder, SYS_socket, &start) != 0 ||
        require_one_of(builder, 0U, socket_domains,
                       sizeof(socket_domains) / sizeof(socket_domains[0])) != 0 ||
        require_exact(builder, 1U, SOCK_DGRAM) != 0 ||
        require_exact(builder, 2U, 0U) != 0 || emit_allow(builder) != 0 ||
        finish_syscall(builder, start) != 0)
        return -1;
    if (emit_udp_socket_options(builder) != 0) return -1;
    ROLE_SIMPLE(builder, bind);
    ROLE_SIMPLE(builder, getsockname);
    ROLE_SIMPLE(builder, recvfrom);
    ROLE_SIMPLE(builder, sendto);
    if (emit_local_message(builder, SYS_recvmsg, c_channel_fd,
                           MSG_CMSG_CLOEXEC) != 0 ||
        emit_local_message(builder, SYS_sendmsg, c_channel_fd,
                           MSG_NOSIGNAL) != 0)
        return -1;

    if (begin_syscall(builder, SYS_ioctl, &start) != 0 ||
        require_exact(builder, 1U, (uint32_t)TIOCSWINSZ) != 0 ||
        emit_allow(builder) != 0 || finish_syscall(builder, start) != 0)
        return -1;
#ifdef SYS_pidfd_send_signal
    if (begin_syscall(builder, SYS_pidfd_send_signal, &start) != 0 ||
        require_signal(builder, 1U) != 0 ||
        require_exact(builder, 2U, 0U) != 0 ||
        require_exact(builder, 3U, 0U) != 0 || emit_allow(builder) != 0 ||
        finish_syscall(builder, start) != 0)
        return -1;
#else
    return fail_with(ENOTSUP);
#endif
    return emit_kill(builder);
}

static int config_valid(const monitor_custodian_role_config_t *config)
{
    size_t i, j;
    if (config == NULL || config->channel_fd < 3 ||
        config->child_count == 0U ||
        config->child_count > MONITOR_ROLE_C_CHILDREN ||
        config->attempt_count != MONITOR_ROLE_C_ATTEMPT_FDS)
        return fail_with(EINVAL);
    for (i = 0U; i < sizeof(config->reserved); ++i)
        if (config->reserved[i] != 0U) return fail_with(EINVAL);
    for (i = 0U; i < config->child_count; ++i) {
        if (config->children[i] <= 0) return fail_with(EINVAL);
        for (j = 0U; j < i; ++j)
            if (config->children[i] == config->children[j])
                return fail_with(EINVAL);
    }
    for (i = config->child_count; i < MONITOR_ROLE_C_CHILDREN; ++i)
        if (config->children[i] != -1) return fail_with(EINVAL);
    for (i = 0U; i < MONITOR_ROLE_C_ATTEMPT_FDS; ++i) {
        if (config->attempt_fds[i] < 3 ||
            config->attempt_fds[i] == config->channel_fd)
            return fail_with(EINVAL);
        for (j = 0U; j < i; ++j)
            if (config->attempt_fds[i] == config->attempt_fds[j])
                return fail_with(EINVAL);
    }
    return 0;
}

static int emit_c_wait(role_builder_t *builder,
                       const monitor_custodian_role_config_t *config)
{
    uint32_t pids[MONITOR_ROLE_C_CHILDREN];
    static const uint32_t options[] = { 0U, WNOHANG };
    size_t start, i;
    for (i = 0U; i < config->child_count; ++i)
        pids[i] = (uint32_t)config->children[i];
    if (begin_syscall(builder, SYS_wait4, &start) != 0 ||
        require_one_of(builder, 0U, pids, config->child_count) != 0 ||
        require_one_of(builder, 2U, options,
                       sizeof(options) / sizeof(options[0])) != 0 ||
        emit_allow(builder) != 0)
        return -1;
    return finish_syscall(builder, start);
}

static int emit_c_kill(role_builder_t *builder,
                       const monitor_custodian_role_config_t *config)
{
    uint32_t pids[MONITOR_ROLE_C_CHILDREN];
    static const uint32_t signals[] = { SIGTERM, SIGKILL, SIGUSR1 };
    size_t start, i;
    for (i = 0U; i < config->child_count; ++i)
        pids[i] = (uint32_t)config->children[i];
    if (begin_syscall(builder, SYS_kill, &start) != 0 ||
        require_one_of(builder, 0U, pids, config->child_count) != 0 ||
        require_one_of(builder, 1U, signals,
                       sizeof(signals) / sizeof(signals[0])) != 0 ||
        emit_allow(builder) != 0)
        return -1;
    return finish_syscall(builder, start);
}

static int build_c(role_builder_t *builder,
                   const monitor_custodian_role_config_t *config)
{
    uint32_t fds[MONITOR_ROLE_C_ATTEMPT_FDS];
    static const uint32_t unlink_flags[] = { 0U, AT_REMOVEDIR };
    size_t start, i;
    for (i = 0U; i < MONITOR_ROLE_C_ATTEMPT_FDS; ++i)
        fds[i] = (uint32_t)config->attempt_fds[i];
    if (preamble(builder) != 0 || common_memory_time(builder) != 0 ||
        emit_local_message(builder, SYS_recvmsg, config->channel_fd,
                           MSG_CMSG_CLOEXEC) != 0 ||
        emit_local_message(builder, SYS_sendmsg, config->channel_fd,
                           MSG_NOSIGNAL) != 0 ||
        emit_c_wait(builder, config) != 0 || emit_c_kill(builder, config) != 0)
        return -1;

    /* The canonical preopened-directory cleanup revalidates ownership before
     * removing the exact public records and attempt.  This observes only C's
     * immutable effective identity; it grants no credential mutation. */
#ifdef SYS_geteuid
    ROLE_SIMPLE(builder, geteuid);
#endif

    if (begin_syscall(builder, SYS_unlinkat, &start) != 0 ||
        require_one_of(builder, 0U, fds,
                       MONITOR_ROLE_C_ATTEMPT_FDS) != 0 ||
        require_one_of(builder, 2U, unlink_flags,
                       sizeof(unlink_flags) / sizeof(unlink_flags[0])) != 0 ||
        emit_allow(builder) != 0 || finish_syscall(builder, start) != 0)
        return -1;
    if (begin_syscall(builder, SYS_fsync, &start) != 0 ||
        require_one_of(builder, 0U, fds,
                       MONITOR_ROLE_C_ATTEMPT_FDS) != 0 ||
        emit_allow(builder) != 0 || finish_syscall(builder, start) != 0)
        return -1;
    return emit_kill(builder);
}

static int install(role_builder_t *builder)
{
    struct sock_fprog program;
    if (builder->count == 0U || builder->count > UINT16_MAX)
        return fail_with(E2BIG);
    program.len = (unsigned short)builder->count;
    program.filter = builder->instructions;
    if (prctl(PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L) != 0)
        return -1;
    if (prctl(PR_SET_SECCOMP, (long)SECCOMP_MODE_FILTER, &program,
              0L, 0L) != 0)
        return -1;
    return 0;
}
#endif

int monitor_role_supported(void)
{
    return MONITOR_ROLE_NATIVE;
}

int monitor_role_install_m(int c_channel_fd)
{
#if MONITOR_ROLE_NATIVE
    role_builder_t builder;
    if (c_channel_fd < 3) return fail_with(EINVAL);
    if (build_m(&builder, c_channel_fd) != 0) return -1;
    return install(&builder);
#else
    (void)c_channel_fd;
    errno = ENOTSUP;
    return -1;
#endif
}

int monitor_role_install_c(const monitor_custodian_role_config_t *config)
{
#if MONITOR_ROLE_NATIVE
    role_builder_t builder;
    if (config_valid(config) != 0) return -1;
    if (build_c(&builder, config) != 0) return -1;
    return install(&builder);
#else
    (void)config;
    errno = ENOTSUP;
    return -1;
#endif
}
