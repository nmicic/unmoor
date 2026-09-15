/*
 * monitor_platform.c — listener-monitor native startup prerequisite preparation
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE
#define _DARWIN_C_SOURCE
#include "monitor_platform.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <dirent.h>
#endif
#if defined(__linux__)
#include <sys/prctl.h>
#include <sys/syscall.h>
#endif

static int fail_with(int error)
{
    errno = error;
    return -1;
}

static int native_failure(void)
{
    if (errno == ENOSYS || errno == ENOPROTOOPT || errno == EOPNOTSUPP)
        errno = ENOTSUP;
    return -1;
}

#if defined(__APPLE__)
static int fd_number(const char *name, int *fd)
{
    unsigned int value = 0;
    const unsigned char *p = (const unsigned char *)name;

    if (name[0] == '\0' || (name[0] == '0' && name[1] != '\0'))
        return fail_with(EPROTO);
    while (*p) {
        unsigned int digit;
        if (*p < '0' || *p > '9')
            return fail_with(EPROTO);
        digit = (unsigned int)(*p - '0');
        if (value > ((unsigned int)INT_MAX - digit) / 10U)
            return fail_with(EPROTO);
        value = value * 10U + digit;
        ++p;
    }
    *fd = (int)value;
    return 0;
}

static int is_closed(int fd)
{
    int rc;
    errno = 0;
    rc = fcntl(fd, F_GETFD);
    if (rc == -1 && errno == EBADF)
        return 0;
    return fail_with(rc >= 0 ? EIO : errno);
}

/* /dev/fd walks the actual descriptor table, including entries above a
 * lowered limit. This is a strict native prerequisite, never a fallback. */
static int inventory_pass(int close_unknown)
{
    DIR *directory = opendir("/dev/fd");
    struct dirent *entry;
    int directory_fd, error = 0;
    unsigned int witnesses = 0;

    if (!directory)
        return -1;
    directory_fd = dirfd(directory);
    if (directory_fd < 3) {
        error = directory_fd < 0 ? (errno ? errno : EBADF) : EPROTO;
        goto finish;
    }
    for (;;) {
        int fd;
        errno = 0;
        entry = readdir(directory);
        if (!entry) {
            error = errno ? errno : (witnesses == 15U ? 0 : EPROTO);
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;
        if (fd_number(entry->d_name, &fd) != 0) {
            error = errno;
            break;
        }
        if (fd < 3 || fd == directory_fd) {
            unsigned int bit = fd < 3 ? 1U << (unsigned int)fd : 8U;
            if ((witnesses & bit) != 0) {
                error = EPROTO;
                break;
            }
            witnesses |= bit;
            continue;
        }
        if (!close_unknown) {
            error = EPROTO;
            break;
        }
        /* A failed close is not retried: its descriptor state may already
         * have changed. Any uncertainty refuses the later worker birth. */
        if (close(fd) != 0 || is_closed(fd) != 0) {
            error = errno;
            break;
        }
    }
finish:
    if (closedir(directory) != 0) {
        if (!error)
            error = errno;
    } else if (directory_fd >= 0 && is_closed(directory_fd) != 0 && !error) {
        error = errno;
    }
    return error ? fail_with(error) : 0;
}
#endif

int monitor_birth_fds(void)
{
#if defined(__linux__) || defined(__APPLE__)
    int null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    int fd;

    if (null_fd < 0)
        return -1;
    for (fd = 0; fd < 3; ++fd) {
        if (dup2(null_fd, fd) < 0 || fcntl(fd, F_SETFD, 0) != 0) {
            int error = errno;
            if (null_fd >= 3)
                (void)close(null_fd);
            return fail_with(error);
        }
    }
#if defined(__linux__) && defined(SYS_close_range)
    if (syscall(SYS_close_range, 3U, UINT_MAX, 0U) != 0)
        return native_failure();
    return 0;
#elif defined(__APPLE__)
    if (inventory_pass(1) != 0)
        return -1;
    return inventory_pass(0);
#else
    return fail_with(ENOTSUP);
#endif
#else
    return fail_with(ENOTSUP);
#endif
}

int monitor_peer_matches(int fd, pid_t expected_pid, uid_t expected_uid)
{
    struct sockaddr_storage address;
    socklen_t length;
    int type = 0;
    pid_t pid;
    uid_t uid;

    if (fd < 0 || expected_pid <= 0 || expected_uid == (uid_t)-1)
        return fail_with(EINVAL);
    length = sizeof(type);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &length) != 0)
        return native_failure();
    if (length != sizeof(type))
        return fail_with(EPROTO);
    if (type != SOCK_STREAM)
        return fail_with(EINVAL);
    memset(&address, 0, sizeof(address));
    length = sizeof(address);
    if (getsockname(fd, (struct sockaddr *)&address, &length) != 0)
        return -1;
    if (length < offsetof(struct sockaddr, sa_data) || length > sizeof(address))
        return fail_with(EPROTO);
    if (address.ss_family != AF_UNIX)
        return fail_with(EINVAL);
    memset(&address, 0, sizeof(address));
    length = sizeof(address);
    if (getpeername(fd, (struct sockaddr *)&address, &length) != 0)
        return -1;
    if (length < offsetof(struct sockaddr, sa_data) || length > sizeof(address))
        return fail_with(EPROTO);
    if (address.ss_family != AF_UNIX)
        return fail_with(EINVAL);
#if defined(__linux__) && defined(SO_PEERCRED)
    {
        struct ucred peer;
        memset(&peer, 0, sizeof(peer));
        length = sizeof(peer);
        if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &length) != 0)
            return native_failure();
        if (length != sizeof(peer) || peer.pid <= 0 ||
            peer.uid == (uid_t)-1 || peer.gid == (gid_t)-1)
            return fail_with(EPROTO);
        pid = peer.pid;
        uid = peer.uid;
    }
#elif defined(__APPLE__) && defined(LOCAL_PEERPID)
    {
        gid_t gid;
        length = sizeof(pid);
        if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &length) != 0)
            return native_failure();
        if (length != sizeof(pid) || pid <= 0)
            return fail_with(EPROTO);
        if (getpeereid(fd, &uid, &gid) != 0)
            return native_failure();
        if (uid == (uid_t)-1 || gid == (gid_t)-1)
            return fail_with(EPROTO);
    }
#else
    return fail_with(ENOTSUP);
#endif
    return pid == expected_pid && uid == expected_uid ? 0 : fail_with(EPERM);
}

int monitor_parent_guard(pid_t expected_parent)
{
    if (expected_parent <= 0)
        return fail_with(EINVAL);
#if defined(__linux__)
    {
        int signal_number = 0;
        if (prctl(PR_SET_PDEATHSIG, (unsigned long)SIGKILL, 0UL, 0UL, 0UL) != 0)
            return native_failure();
        if (getppid() != expected_parent)
            return fail_with(ESRCH);
        if (prctl(PR_GET_PDEATHSIG, &signal_number, 0UL, 0UL, 0UL) != 0)
            return native_failure();
        if (signal_number != SIGKILL)
            return fail_with(EPROTO);
        return 0;
    }
#else
    return fail_with(ENOTSUP);
#endif
}
