/*
 * monitor_child_pidfd.c — standalone exact-child reference, not a custodian
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE
#include "monitor_child_pidfd.h"
#include <errno.h>
#include <signal.h>
#include <string.h>
#if defined(__linux__)
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#if defined(__linux__) && defined(__LP64__) && \
    (defined(__x86_64__) || defined(__aarch64__)) && \
    defined(SYS_pidfd_open) && defined(SYS_pidfd_send_signal)
#define CHILD_PIDFD_NATIVE 1
#else
#define CHILD_PIDFD_NATIVE 0
#endif

static int fail_with(int error)
{
    errno = error;
    return -1;
}

#if CHILD_PIDFD_NATIVE
static int native_failure(void)
{
    if (errno == ENOSYS) errno = ENOTSUP;
    return -1;
}
#endif

int monitor_child_pidfd_open(pid_t owned_child)
{
    if (owned_child <= 0) return fail_with(EINVAL);
#if CHILD_PIDFD_NATIVE
    struct sigaction action;
    siginfo_t information;
    long result;

    memset(&action, 0, sizeof(action));
    if (sigaction(SIGCHLD, NULL, &action) != 0) return native_failure();
    if (action.sa_handler != SIG_DFL || (action.sa_flags & SA_NOCLDWAIT) != 0)
        return fail_with(EPERM);

    memset(&information, 0, sizeof(information));
    if (waitid(P_PID, (id_t)owned_child, &information,
               WEXITED | WNOHANG | WNOWAIT) != 0) return native_failure();
    if (information.si_pid != 0 &&
        (information.si_pid != owned_child || information.si_signo != SIGCHLD ||
         (information.si_code != CLD_EXITED && information.si_code != CLD_KILLED &&
          information.si_code != CLD_DUMPED))) return fail_with(EPROTO);

    /* The caller's unreaped-child reservation spans all these calls.
     * Kernel success supplies a CLOEXEC int fd. No fallible step follows
     * acquisition: ownership cannot be hidden by an uncertain cleanup. */
    result = syscall(SYS_pidfd_open, owned_child, 0U);
    return result < 0 ? native_failure() : (int)result;
#else
    return fail_with(ENOTSUP);
#endif
}

int monitor_child_pidfd_signal(int borrowed_pidfd, int signum)
{
    if (borrowed_pidfd < 0 || signum < 1 || signum > 63)
        return fail_with(EINVAL);
#if CHILD_PIDFD_NATIVE
    if (syscall(SYS_pidfd_send_signal, borrowed_pidfd, signum, NULL, 0U) != 0)
        return native_failure();
    return 0;
#else
    return fail_with(ENOTSUP);
#endif
}
