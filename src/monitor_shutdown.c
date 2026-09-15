/*
 * monitor_shutdown.c — fixed listener-monitor M-C worker retirement proof
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE
#define _DARWIN_C_SOURCE
#include "monitor_shutdown.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef MONITOR_SHUTDOWN_NATIVE
#if defined(__linux__) && defined(__LP64__) && \
    (defined(__x86_64__) || defined(__aarch64__)) && \
    defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ && \
    defined(SOCK_NONBLOCK) && defined(SOCK_CLOEXEC)
#define MONITOR_SHUTDOWN_NATIVE 1
#else
#define MONITOR_SHUTDOWN_NATIVE 0
#endif
#endif

#if MONITOR_SHUTDOWN_NATIVE && !defined(MONITOR_SHUTDOWN_TEST)
#define MONITOR_SHUTDOWN_SOCKET_FLAGS \
    (SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC)
#else
#define MONITOR_SHUTDOWN_SOCKET_FLAGS SOCK_STREAM
#endif

#ifndef MONITOR_SHUTDOWN_SOCKETPAIR
#define MONITOR_SHUTDOWN_SOCKETPAIR socketpair
#define MONITOR_SHUTDOWN_READ read
#define MONITOR_SHUTDOWN_WRITE write
#define MONITOR_SHUTDOWN_CLOSE close
#define MONITOR_SHUTDOWN_FCNTL fcntl
#define MONITOR_SHUTDOWN_GETSOCKOPT getsockopt
#endif

enum { SHUTDOWN_VERSION = 1U, SHUTDOWN_STOP = 1U, SHUTDOWN_REAPED = 2U };
enum { ROLE_C = 1U, ROLE_M = 2U };
enum {
    PHASE_EMPTY = 0U,
    PHASE_M_LIVE = 1U,
    PHASE_M_SEND_STOP = 2U,
    PHASE_M_WAIT_REAPED = 3U,
    PHASE_M_RESULT = 4U,
    PHASE_C_WAIT_STOP = 5U,
    PHASE_C_ACTION = 6U,
    PHASE_C_SEND_REAPED = 7U,
    PHASE_DONE = 8U,
    PHASE_FAILED = 9U,
    PHASE_DISPOSED = 10U
};

_Static_assert(sizeof(monitor_shutdown_t) == 28U,
               "shutdown owner budget changed");
_Static_assert(sizeof(monitor_shutdown_wait_t) == 8U,
               "shutdown wait budget changed");

static int error_with(int cause)
{
    errno = cause > 0 ? cause : EIO;
    return -1;
}

static int zero_owner(const monitor_shutdown_t *owner)
{
    static const monitor_shutdown_t empty;
    return owner != NULL && memcmp(owner, &empty, sizeof(empty)) == 0;
}

static int owner_valid(const monitor_shutdown_t *owner)
{
    if (owner == NULL || owner->fd < -1 || owner->tx_n > 4U ||
        owner->rx_n > 4U || owner->flags != 0U ||
        owner->reserved[0] != 0U || owner->reserved[1] != 0U)
        return 0;
    if (owner->role == ROLE_M)
        return owner->phase >= PHASE_M_LIVE &&
               owner->phase <= PHASE_M_RESULT;
    if (owner->role == ROLE_C)
        return owner->phase >= PHASE_C_WAIT_STOP &&
               owner->phase <= PHASE_C_SEND_REAPED;
    return owner->phase == PHASE_DONE || owner->phase == PHASE_FAILED ||
           owner->phase == PHASE_DISPOSED;
}

static void note_cleanup(monitor_shutdown_t *owner, int cause)
{
    if (owner->cleanup_errno == 0)
        owner->cleanup_errno = cause > 0 ? cause : EIO;
}

static void close_owned(monitor_shutdown_t *owner)
{
    int descriptor;
    if (owner == NULL || owner->fd < 0)
        return;
    descriptor = owner->fd;
    owner->fd = -1;
    if (MONITOR_SHUTDOWN_CLOSE(descriptor) != 0)
        note_cleanup(owner, errno);
}

static int fail_owner(monitor_shutdown_t *owner, int cause)
{
    if (owner == NULL)
        return error_with(cause);
    if (owner->failure_errno == 0)
        owner->failure_errno = cause > 0 ? cause : EIO;
    owner->role = 0U;
    owner->phase = PHASE_FAILED;
    close_owned(owner);
    return error_with(owner->failure_errno);
}

int monitor_shutdown_supported(void)
{
    return MONITOR_SHUTDOWN_NATIVE;
}

int monitor_shutdown_pair_create(int pair[2])
{
    int made[2] = MONITOR_SHUTDOWN_PAIR_EMPTY;
    if (pair == NULL || pair[0] != -1 || pair[1] != -1)
        return error_with(EINVAL);
#if MONITOR_SHUTDOWN_NATIVE
    if (MONITOR_SHUTDOWN_SOCKETPAIR(AF_UNIX, MONITOR_SHUTDOWN_SOCKET_FLAGS,
                                    0, made) != 0)
        return -1;
    if (made[0] < 3 || made[1] < 3 || made[0] == made[1]) {
        int cause = EPROTO;
        if (made[0] >= 0) (void)MONITOR_SHUTDOWN_CLOSE(made[0]);
        if (made[1] >= 0) (void)MONITOR_SHUTDOWN_CLOSE(made[1]);
        return error_with(cause);
    }
    pair[0] = made[0];
    pair[1] = made[1];
    return 0;
#else
    (void)made;
    return error_with(ENOTSUP);
#endif
}

#if MONITOR_SHUTDOWN_NATIVE
static int endpoint_valid(int descriptor)
{
    int type = 0;
    socklen_t length = sizeof(type);
    int flags;
    if (descriptor < 3)
        return error_with(EINVAL);
    if (MONITOR_SHUTDOWN_GETSOCKOPT(descriptor, SOL_SOCKET, SO_TYPE,
                                    &type, &length) != 0)
        return -1;
    if (length != sizeof(type) || type != SOCK_STREAM)
        return error_with(EPROTO);
    flags = MONITOR_SHUTDOWN_FCNTL(descriptor, F_GETFL, 0);
    if (flags < 0)
        return -1;
    if ((flags & O_ACCMODE) != O_RDWR || (flags & O_NONBLOCK) == 0)
        return error_with(EPROTO);
    flags = MONITOR_SHUTDOWN_FCNTL(descriptor, F_GETFD, 0);
    if (flags < 0)
        return -1;
    return flags == FD_CLOEXEC ? 0 : error_with(EPROTO);
}
#endif

static int initialize(monitor_shutdown_t *owner, int *endpoint, uint8_t role)
{
    monitor_shutdown_t initialized;
    if (!zero_owner(owner) || endpoint == NULL || *endpoint < 3 ||
        (role != ROLE_C && role != ROLE_M))
        return error_with(EINVAL);
#if MONITOR_SHUTDOWN_NATIVE
    if (endpoint_valid(*endpoint) != 0)
        return -1;
    memset(&initialized, 0, sizeof(initialized));
    initialized.fd = *endpoint;
    initialized.role = role;
    initialized.phase = role == ROLE_C ? PHASE_C_WAIT_STOP : PHASE_M_LIVE;
    *owner = initialized;
    *endpoint = -1;
    return 0;
#else
    (void)initialized;
    return error_with(ENOTSUP);
#endif
}

int monitor_shutdown_c_init(monitor_shutdown_t *owner, int *endpoint)
{
    return initialize(owner, endpoint, ROLE_C);
}

int monitor_shutdown_m_init(monitor_shutdown_t *owner, int *endpoint)
{
    return initialize(owner, endpoint, ROLE_M);
}

int monitor_shutdown_interest(const monitor_shutdown_t *owner,
                              monitor_shutdown_wait_t *wait)
{
    monitor_shutdown_wait_t value = {-1, 0U, 0U, 0U};
    if (!owner_valid(owner) || wait == NULL || owner->failure_errno != 0 ||
        owner->cleanup_errno != 0)
        return error_with(owner && owner->failure_errno
                              ? owner->failure_errno : EINVAL);
    if (owner->phase == PHASE_M_SEND_STOP ||
        owner->phase == PHASE_C_SEND_REAPED) {
        value.fd = owner->fd;
        value.events = (uint16_t)(POLLIN | POLLOUT);
    } else if (owner->phase == PHASE_M_WAIT_REAPED ||
               owner->phase == PHASE_C_WAIT_STOP) {
        value.fd = owner->fd;
        value.events = POLLIN;
    } else {
        value.immediate = 1U;
    }
    *wait = value;
    return 0;
}

static int decode_received(monitor_shutdown_t *owner)
{
    uint8_t expected_kind;
    uint8_t expected_value;
    if (owner->rx_n != MONITOR_SHUTDOWN_RECORD_BYTES)
        return 0;
    expected_kind = owner->phase == PHASE_C_WAIT_STOP
        ? SHUTDOWN_STOP : SHUTDOWN_REAPED;
    expected_value = expected_kind == SHUTDOWN_STOP
        ? 0U : MONITOR_SHUTDOWN_WORKER_EXIT;
    if (owner->rx[0] != SHUTDOWN_VERSION ||
        owner->rx[1] != expected_kind || owner->rx[2] != expected_value ||
        owner->rx[3] != 0U)
        return fail_owner(owner, EPROTO);
    memset(owner->rx, 0, sizeof(owner->rx));
    owner->rx_n = 0U;
    owner->phase = expected_kind == SHUTDOWN_STOP
        ? PHASE_C_ACTION : PHASE_M_RESULT;
    return 1;
}

static monitor_shutdown_step_result_t send_record(monitor_shutdown_t *owner)
{
    ssize_t amount = MONITOR_SHUTDOWN_WRITE(
        owner->fd, owner->tx + owner->tx_n,
        MONITOR_SHUTDOWN_RECORD_BYTES - owner->tx_n);
    if (amount < 0) {
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
            return MONITOR_SHUTDOWN_WAIT;
        (void)fail_owner(owner, errno);
        return MONITOR_SHUTDOWN_ERROR;
    }
    if (amount == 0 || (size_t)amount >
        MONITOR_SHUTDOWN_RECORD_BYTES - owner->tx_n) {
        (void)fail_owner(owner, EPIPE);
        return MONITOR_SHUTDOWN_ERROR;
    }
    owner->tx_n = (uint8_t)(owner->tx_n + (uint8_t)amount);
    if (owner->tx_n == MONITOR_SHUTDOWN_RECORD_BYTES) {
        memset(owner->tx, 0, sizeof(owner->tx));
        owner->tx_n = 0U;
        owner->phase = owner->phase == PHASE_M_SEND_STOP
            ? PHASE_M_WAIT_REAPED : PHASE_DONE;
        if (owner->phase == PHASE_DONE)
            owner->role = 0U;
    }
    return MONITOR_SHUTDOWN_PROGRESS;
}

static monitor_shutdown_step_result_t receive_record(monitor_shutdown_t *owner)
{
    size_t offered = sizeof(owner->rx) - owner->rx_n;
    ssize_t amount = MONITOR_SHUTDOWN_READ(
        owner->fd, owner->rx + owner->rx_n, offered);
    if (amount < 0) {
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
            return MONITOR_SHUTDOWN_WAIT;
        (void)fail_owner(owner, errno);
        return MONITOR_SHUTDOWN_ERROR;
    }
    if (amount == 0) {
        (void)fail_owner(owner, EPIPE);
        return MONITOR_SHUTDOWN_ERROR;
    }
    if ((size_t)amount > offered) {
        (void)fail_owner(owner, EPROTO);
        return MONITOR_SHUTDOWN_ERROR;
    }
    owner->rx_n = (uint8_t)(owner->rx_n + (uint8_t)amount);
    if (owner->rx_n > MONITOR_SHUTDOWN_RECORD_BYTES) {
        (void)fail_owner(owner, EPROTO);
        return MONITOR_SHUTDOWN_ERROR;
    }
    if (decode_received(owner) < 0)
        return MONITOR_SHUTDOWN_ERROR;
    if (owner->phase == PHASE_C_ACTION)
        return MONITOR_SHUTDOWN_ACTION;
    if (owner->phase == PHASE_M_RESULT)
        return MONITOR_SHUTDOWN_RESULT;
    return MONITOR_SHUTDOWN_PROGRESS;
}

monitor_shutdown_step_result_t
monitor_shutdown_step(monitor_shutdown_t *owner, short revents)
{
    if (!owner_valid(owner) || owner->failure_errno != 0 ||
        owner->cleanup_errno != 0) {
        errno = owner && owner->failure_errno ? owner->failure_errno : EINVAL;
        return MONITOR_SHUTDOWN_ERROR;
    }
    if ((revents & POLLNVAL) != 0) {
        (void)fail_owner(owner, EBADF);
        return MONITOR_SHUTDOWN_ERROR;
    }
    if (owner->phase == PHASE_C_ACTION)
        return MONITOR_SHUTDOWN_ACTION;
    if (owner->phase == PHASE_M_RESULT)
        return MONITOR_SHUTDOWN_RESULT;
    if (owner->phase == PHASE_DONE)
        return MONITOR_SHUTDOWN_DONE;
    if ((owner->phase == PHASE_M_SEND_STOP ||
         owner->phase == PHASE_C_SEND_REAPED) &&
        (revents & POLLOUT) != 0)
        return send_record(owner);
    if ((owner->phase == PHASE_M_WAIT_REAPED ||
         owner->phase == PHASE_C_WAIT_STOP) &&
        (revents & (POLLIN | POLLHUP | POLLERR)) != 0)
        return receive_record(owner);
    if ((revents & (POLLHUP | POLLERR)) != 0) {
        uint8_t unexpected;
        ssize_t amount = MONITOR_SHUTDOWN_READ(owner->fd, &unexpected, 1U);
        if (amount < 0 && (errno == EINTR || errno == EAGAIN ||
                           errno == EWOULDBLOCK))
            return MONITOR_SHUTDOWN_WAIT;
        (void)fail_owner(owner, amount == 0 ? EPIPE : EPROTO);
        return MONITOR_SHUTDOWN_ERROR;
    }
    return MONITOR_SHUTDOWN_WAIT;
}

int monitor_shutdown_m_request_stop(monitor_shutdown_t *owner)
{
    if (!owner_valid(owner) || owner->role != ROLE_M ||
        owner->phase != PHASE_M_LIVE || owner->fd < 0 ||
        owner->failure_errno != 0 || owner->cleanup_errno != 0)
        return error_with(EINVAL);
    owner->tx[0] = SHUTDOWN_VERSION;
    owner->tx[1] = SHUTDOWN_STOP;
    owner->tx[2] = 0U;
    owner->tx[3] = 0U;
    owner->phase = PHASE_M_SEND_STOP;
    return 0;
}

int monitor_shutdown_c_report_reaped(monitor_shutdown_t *owner,
                                     int wait_status)
{
    if (!owner_valid(owner) || owner->role != ROLE_C ||
        owner->phase != PHASE_C_ACTION || owner->fd < 0 ||
        owner->failure_errno != 0 || owner->cleanup_errno != 0)
        return error_with(EINVAL);
    if (!WIFEXITED(wait_status) ||
        WEXITSTATUS(wait_status) != MONITOR_SHUTDOWN_WORKER_EXIT)
        return fail_owner(owner, EPROTO);
    owner->tx[0] = SHUTDOWN_VERSION;
    owner->tx[1] = SHUTDOWN_REAPED;
    owner->tx[2] = MONITOR_SHUTDOWN_WORKER_EXIT;
    owner->tx[3] = 0U;
    owner->phase = PHASE_C_SEND_REAPED;
    return 0;
}

int monitor_shutdown_m_take_reaped(monitor_shutdown_t *owner, int *worker_exit)
{
    if (!owner_valid(owner) || owner->role != ROLE_M ||
        owner->phase != PHASE_M_RESULT || worker_exit == NULL ||
        *worker_exit != 0 || owner->failure_errno != 0 ||
        owner->cleanup_errno != 0)
        return error_with(EINVAL);
    *worker_exit = MONITOR_SHUTDOWN_WORKER_EXIT;
    owner->role = 0U;
    owner->phase = PHASE_DONE;
    return 0;
}

int monitor_shutdown_abort(monitor_shutdown_t *owner, int cause_errno)
{
    if (owner == NULL || cause_errno <= 0)
        return error_with(EINVAL);
    if (owner->phase == PHASE_DISPOSED)
        return error_with(EALREADY);
    return fail_owner(owner, cause_errno);
}

int monitor_shutdown_dispose(monitor_shutdown_t *owner)
{
    int cause;
    if (owner == NULL)
        return error_with(EINVAL);
    if (owner->phase == PHASE_DISPOSED) {
        cause = owner->failure_errno ? owner->failure_errno
              : owner->cleanup_errno;
        return cause ? error_with(cause) : 0;
    }
    if (owner->phase != PHASE_EMPTY && owner->phase != PHASE_DONE &&
        owner->phase != PHASE_FAILED && owner->failure_errno == 0)
        owner->failure_errno = ECANCELED;
    close_owned(owner);
    owner->role = 0U;
    owner->phase = PHASE_DISPOSED;
    cause = owner->failure_errno ? owner->failure_errno
          : owner->cleanup_errno;
    return cause ? error_with(cause) : 0;
}
