/*
 * process_hygiene.c — process-boundary hygiene shared by every exec site
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif

#include "process_hygiene.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/prctl.h>
#include <sys/syscall.h>
#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#include <sys/ptrace.h>
#endif

#define PROCESS_SELF_PATH_CAP 4096U

int process_ignore_sigpipe(void)
{
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_IGN;
    if (sigemptyset(&action.sa_mask) != 0)
        return -1;
    return sigaction(SIGPIPE, &action, NULL);
}

void process_reset_child_signals(void)
{
    static const int signals[] = {
        SIGPIPE, SIGINT, SIGQUIT, SIGTERM, SIGHUP, SIGWINCH, SIGTSTP,
        SIGCHLD, SIGUSR1
    };
    struct sigaction action;
    sigset_t empty;
    size_t index;

    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_DFL;
    (void)sigemptyset(&action.sa_mask);
    for (index = 0U; index < sizeof(signals) / sizeof(signals[0]); index++)
        (void)sigaction(signals[index], &action, NULL);
    (void)sigemptyset(&empty);
    (void)sigprocmask(SIG_SETMASK, &empty, NULL);
}

static int descriptor_is_kept(int descriptor, const int keep[],
                              size_t keep_count)
{
    size_t index;

    for (index = 0U; index < keep_count; index++)
        if (keep[index] == descriptor)
            return 1;
    return 0;
}

#if defined(__linux__) && defined(SYS_close_range)
static int close_range_except(unsigned int first, const int keep[],
                              size_t keep_count)
{
    unsigned int cursor = first;

    for (;;) {
        unsigned int next = UINT_MAX;
        size_t index;

        for (index = 0U; index < keep_count; index++) {
            unsigned int candidate;

            if (keep[index] < 0)
                continue;
            candidate = (unsigned int)keep[index];
            if (candidate >= cursor && candidate < next)
                next = candidate;
        }
        if (next == UINT_MAX)
            return (int)syscall(SYS_close_range, cursor, UINT_MAX, 0U);
        if (next > cursor &&
            syscall(SYS_close_range, cursor, next - 1U, 0U) != 0)
            return -1;
        cursor = next + 1U;
    }
}
#endif

#if defined(__APPLE__)
static int close_dev_fd_except(int lowfd, const int keep[], size_t keep_count)
{
    DIR *directory = opendir("/dev/fd");
    struct dirent *entry;
    int directory_fd;
    int scan_errno = 0;

    if (directory == NULL)
        return -1;
    directory_fd = dirfd(directory);
    for (;;) {
        const unsigned char *cursor;
        unsigned long value = 0UL;
        int descriptor;

        errno = 0;
        entry = readdir(directory);
        if (entry == NULL) {
            scan_errno = errno;
            break;
        }
        cursor = (const unsigned char *)entry->d_name;

        if (*cursor < (unsigned char)'0' || *cursor > (unsigned char)'9')
            continue;
        do {
            unsigned long digit = (unsigned long)(*cursor -
                                                   (unsigned char)'0');

            if (value > ((unsigned long)INT_MAX - digit) / 10UL) {
                value = (unsigned long)INT_MAX + 1UL;
                break;
            }
            value = value * 10UL + digit;
            cursor++;
        } while (*cursor >= (unsigned char)'0' &&
                 *cursor <= (unsigned char)'9');
        if (*cursor != '\0' || value > (unsigned long)INT_MAX)
            continue;
        descriptor = (int)value;
        if (descriptor >= lowfd && descriptor != directory_fd &&
            !descriptor_is_kept(descriptor, keep, keep_count))
            (void)close(descriptor);
    }
    if (scan_errno != 0) {
        (void)closedir(directory);
        errno = scan_errno;
        return -1;
    }
    return closedir(directory);
}
#endif

int process_close_from(int lowfd, const int keep[], size_t keep_count)
{
    struct rlimit limit;
    rlim_t upper;
    int saved_errno = errno;
    rlim_t descriptor;

    if (lowfd < 0 || (keep_count > 0U && keep == NULL)) {
        errno = EINVAL;
        return -1;
    }
#if defined(__linux__) && defined(SYS_close_range)
    if (close_range_except((unsigned int)lowfd, keep, keep_count) == 0) {
        errno = saved_errno;
        return 0;
    }
    if (errno != ENOSYS && errno != EINVAL && errno != EPERM)
        return -1;
#endif
#if defined(__APPLE__)
    if (close_dev_fd_except(lowfd, keep, keep_count) == 0) {
        errno = saved_errno;
        return 0;
    }
#endif
    if (getrlimit(RLIMIT_NOFILE, &limit) != 0)
        return -1;
    if (limit.rlim_cur == RLIM_INFINITY) {
        long open_max = sysconf(_SC_OPEN_MAX);

        if (open_max < 0)
            return -1;
        upper = (rlim_t)open_max;
    } else {
        upper = limit.rlim_cur;
    }
    /* File descriptors are ints.  A larger numeric resource limit cannot
     * name a descriptor beyond INT_MAX, and clamping here avoids integer
     * wrap while still covering every representable descriptor. */
    if (upper > (rlim_t)INT_MAX)
        upper = (rlim_t)INT_MAX;
    for (descriptor = (rlim_t)lowfd; descriptor < upper; descriptor++) {
        int fd = (int)descriptor;

        if (!descriptor_is_kept(fd, keep, keep_count))
            (void)close(fd);
    }
    errno = saved_errno;
    return 0;
}

int process_resolve_self_path(const char *argv0, char *path,
                              size_t path_size, int *bare_fallback)
{
    size_t length;

    if (argv0 == NULL || argv0[0] == '\0' || path == NULL ||
        path_size == 0U || bare_fallback == NULL) {
        errno = EINVAL;
        return -1;
    }
#if defined(__linux__)
    if (path_size > 1U) {
        ssize_t count = readlink("/proc/self/exe", path, path_size - 1U);

        if (count > 0 && (size_t)count < path_size - 1U) {
            path[count] = '\0';
            *bare_fallback = 0;
            return 0;
        }
    }
#elif defined(__APPLE__)
    {
        char candidate[PROCESS_SELF_PATH_CAP];
        char canonical[PROCESS_SELF_PATH_CAP];
        uint32_t candidate_size = (uint32_t)sizeof(candidate);

        if (_NSGetExecutablePath(candidate, &candidate_size) == 0 &&
            realpath(candidate, canonical) != NULL) {
            length = strlen(canonical);
            if (length < path_size) {
                memcpy(path, canonical, length + 1U);
                *bare_fallback = 0;
                return 0;
            }
        }
    }
#endif
    length = strlen(argv0);
    if (length >= path_size) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(path, argv0, length + 1U);
    *bare_fallback = strchr(argv0, '/') == NULL ? 1 : 0;
    return 0;
}

int process_harden(int debuggable)
{
    struct rlimit core_limit;

    if (debuggable)
        return 0;
    if (getrlimit(RLIMIT_CORE, &core_limit) != 0)
        return -1;
    core_limit.rlim_cur = 0;
    if (setrlimit(RLIMIT_CORE, &core_limit) != 0)
        return -1;

    /* LeakSanitizer suspends and inspects the process.  Keep the core limit
     * but leave the platform attach mechanism available in sanitizer builds. */
#if !defined(UNMOOR_SANITIZER)
#if defined(__linux__)
    if (prctl(PR_SET_DUMPABLE, 0L, 0L, 0L, 0L) != 0)
        return -1;
#elif defined(__APPLE__)
    if (ptrace(PT_DENY_ATTACH, 0, (caddr_t)0, 0) != 0)
        return -1;
#endif
#endif
    return 0;
}

int process_harden_command(const char *command, int debuggable)
{
    int saved_errno;

    if (debuggable)
        fprintf(stderr,
                "unmoor: process hardening disabled (--debuggable)\n");
    if (process_harden(debuggable) == 0)
        return 0;
    saved_errno = errno;
    fprintf(stderr, "%s: process hardening failed: %s\n",
            command ? command : "unmoor", strerror(saved_errno));
    errno = saved_errno;
    return -1;
}
