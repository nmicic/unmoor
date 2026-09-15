/*
 * monitor_session_backend.c — fixed listener-monitor existing-engine adapter
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE
#define _DARWIN_C_SOURCE
#include "monitor_session_backend.h"
#include "session.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef MONITOR_BACKEND_WORK_INTERESTS
#define MONITOR_BACKEND_WORK_INTERESTS sync_work_interests
#define MONITOR_BACKEND_SYNC_SERVICE sync_monitor_service
#define MONITOR_BACKEND_CUSTODY_REQUEST_OPEN monitor_pty_custody_request_open
#define MONITOR_BACKEND_CUSTODY_REQUEST_RETIRE monitor_pty_custody_request_retire
#define MONITOR_BACKEND_CUSTODY_INTEREST monitor_pty_custody_interest
#define MONITOR_BACKEND_CUSTODY_STEP monitor_pty_custody_step
#define MONITOR_BACKEND_CUSTODY_TAKE monitor_pty_custody_take_result
#define MONITOR_BACKEND_CUSTODY_READ monitor_pty_custody_read
#define MONITOR_BACKEND_CUSTODY_WRITE monitor_pty_custody_write
#define MONITOR_BACKEND_CUSTODY_RESIZE monitor_pty_custody_resize
#define MONITOR_BACKEND_CUSTODY_SIGNAL monitor_pty_custody_signal
#define MONITOR_BACKEND_CUSTODY_ABORT monitor_pty_custody_abort
#define MONITOR_BACKEND_POLL poll
#define MONITOR_BACKEND_FCNTL fcntl
#define MONITOR_BACKEND_GETSOCKOPT getsockopt
#define MONITOR_BACKEND_READ read
#define MONITOR_BACKEND_WRITE write
#endif

_Static_assert(sizeof(monitor_session_backend_t) == 48U,
               "monitor backend owner budget changed");
_Static_assert(sizeof(monitor_session_backend_wait_t) == 8U,
               "monitor backend wait budget changed");

static int error_with(int cause)
{
    errno = cause > 0 ? cause : EIO;
    return -1;
}

static int backend_attached(const monitor_session_backend_t *backend)
{
    return backend != NULL && backend->bound == 1U &&
           backend->disposed == 0U && backend->prepared == 1U &&
           backend->session != NULL && backend->binding != NULL &&
           backend->custody != NULL && backend->worker_fd >= 3 &&
           backend->binding->session == backend->session;
}

static int backend_healthy(const monitor_session_backend_t *backend)
{
    return backend_attached(backend) && backend->failure_errno == 0;
}

static int backend_has_unissued_source(const monitor_session_backend_t *backend)
{
    return backend != NULL && backend->binding != NULL &&
           backend->binding->source != NULL &&
           backend->binding->source->pending.append_length != 0U &&
           backend->binding->source->pending.operation == 0U;
}

static int worker_fd_valid(int descriptor)
{
    int type = 0;
    socklen_t length = sizeof(type);
    int flags;
    if (descriptor < 3)
        return error_with(EINVAL);
    if (MONITOR_BACKEND_GETSOCKOPT(descriptor, SOL_SOCKET, SO_TYPE,
                                   &type, &length) != 0)
        return -1;
    if (length != sizeof(type) || type != SOCK_STREAM)
        return error_with(EPROTO);
    flags = MONITOR_BACKEND_FCNTL(descriptor, F_GETFL, 0);
    if (flags < 0)
        return -1;
    if ((flags & O_ACCMODE) != O_RDWR || (flags & O_NONBLOCK) == 0)
        return error_with(EPROTO);
    flags = MONITOR_BACKEND_FCNTL(descriptor, F_GETFD, 0);
    if (flags < 0)
        return -1;
    return flags == FD_CLOEXEC ? 0 : error_with(EPROTO);
}

static int backend_fail(monitor_session_backend_t *backend, int cause)
{
    if (backend == NULL)
        return error_with(cause);
    if (backend->failure_errno == 0)
        backend->failure_errno = cause > 0 ? cause : EIO;
    if (backend->custody != NULL)
        (void)MONITOR_BACKEND_CUSTODY_ABORT(
            backend->custody, backend->failure_errno);
    return error_with(backend->failure_errno);
}

static int custody_ready(const monitor_pty_custody_t *custody, int worker_fd)
{
    return custody != NULL && custody->role == MONITOR_PTY_M &&
           custody->protocol.phase == MONITOR_PTY_IDLE &&
           custody->channel_fd >= 3 && custody->result.kind == 0U &&
           custody->pair[0] == -1 && custody->pair[1] == -1 &&
           worker_fd >= 3 && worker_fd != custody->channel_fd;
}

int monitor_session_backend_prepare(monitor_session_backend_t *backend,
                                    monitor_pty_custody_t *custody,
                                    int worker_fd)
{
    monitor_session_backend_t initialized;
    static const monitor_session_backend_t empty;

    if (backend == NULL || memcmp(backend, &empty, sizeof(empty)) != 0 ||
        !custody_ready(custody, worker_fd))
        return error_with(EINVAL);
    if (worker_fd_valid(worker_fd) != 0)
        return -1;
    memset(&initialized, 0, sizeof(initialized));
    initialized.custody = custody;
    initialized.worker_fd = worker_fd;
    initialized.master_fd = -1;
    initialized.pidfd = -1;
    initialized.prepared = 1U;
    *backend = initialized;
    return 0;
}

int monitor_session_backend_attach(struct session *session,
                                   monitor_session_backend_t *backend,
                                   sync_monitor_binding_t *binding)
{
    if (session == NULL || backend == NULL || binding == NULL ||
        backend->prepared != 1U || backend->bound != 0U ||
        backend->disposed != 0U || backend->failure_errno != 0 ||
        backend->session != NULL || backend->binding != NULL ||
        !custody_ready(backend->custody, backend->worker_fd) ||
        session->monitor_backend != NULL || !session->is_server ||
        session->services_started || session->channelised_requested ||
        session->bulk_enabled || session->sync_monitor != binding ||
        binding->session != session || binding->life != SYNC_MONITOR_PREBOUND ||
        binding->work == NULL ||
        binding->work->control.role != SYNC_WORK_MONITOR)
        return error_with(EINVAL);
    backend->session = session;
    backend->binding = binding;
    backend->bound = 1U;
    session->monitor_backend = backend;
    return 0;
}

int monitor_session_backend_bind(struct session *session,
                                 monitor_session_backend_t *backend,
                                 sync_monitor_binding_t *binding,
                                 monitor_pty_custody_t *custody,
                                 int worker_fd)
{
    static const monitor_session_backend_t empty;

    if (session == NULL || backend == NULL || binding == NULL ||
        custody == NULL || memcmp(backend, &empty, sizeof(empty)) != 0 ||
        session->monitor_backend != NULL || !session->is_server ||
        session->services_started || session->channelised_requested ||
        session->bulk_enabled || session->sync_monitor != binding ||
        binding->session != session || binding->life != SYNC_MONITOR_PREBOUND ||
        binding->work == NULL ||
        binding->work->control.role != SYNC_WORK_MONITOR ||
        !custody_ready(custody, worker_fd))
        return error_with(EINVAL);
    if (monitor_session_backend_prepare(backend, custody, worker_fd) != 0)
        return -1;
    return monitor_session_backend_attach(session, backend, binding);
}

int monitor_session_backend_is_bound(const struct session *session)
{
    const monitor_session_backend_t *backend;
    if (session == NULL || session->monitor_backend == NULL)
        return 0;
    backend = session->monitor_backend;
    return backend_attached(backend) && backend->session == session;
}

static ptrdiff_t io_result(ssize_t amount, size_t offered)
{
    if (amount >= 0)
        return (size_t)amount <= offered ? (ptrdiff_t)amount
                                         : SYNC_WORK_IO_ERROR;
    if (errno == EINTR)
        return SYNC_WORK_IO_INTR;
    if (errno == EAGAIN || errno == EWOULDBLOCK)
        return SYNC_WORK_IO_AGAIN;
    return SYNC_WORK_IO_ERROR;
}

static ptrdiff_t worker_read(void *context, uint8_t *output, size_t offered)
{
    monitor_session_backend_t *backend = context;
    return backend_healthy(backend)
        ? io_result(MONITOR_BACKEND_READ(
              backend->worker_fd, output, offered), offered)
        : SYNC_WORK_IO_ERROR;
}

static ptrdiff_t worker_write(void *context, const uint8_t *input,
                              size_t offered)
{
    monitor_session_backend_t *backend = context;
    return backend_healthy(backend)
        ? io_result(MONITOR_BACKEND_WRITE(
              backend->worker_fd, input, offered), offered)
        : SYNC_WORK_IO_ERROR;
}

int monitor_session_backend_interest(const struct session *session,
                                     monitor_session_backend_wait_t *wait)
{
    monitor_session_backend_t *backend;
    monitor_session_backend_wait_t value = {-1, 0U, 0U, 0U};
    unsigned interest;

    if (session == NULL || wait == NULL ||
        !monitor_session_backend_is_bound(session))
        return error_with(EINVAL);
    backend = session->monitor_backend;
    if (!backend_healthy(backend))
        return error_with(backend->failure_errno);
    if (backend->binding->life == SYNC_MONITOR_PREBOUND ||
        backend->binding->life == SYNC_MONITOR_STOPPED) {
        *wait = value;
        return 0;
    }
    if (backend->binding->life != SYNC_MONITOR_LIVE)
        return backend_fail(backend, EPROTO);
    interest = MONITOR_BACKEND_WORK_INTERESTS(backend->binding->work);
    if (interest == 0U)
        return backend_fail(backend, EPIPE);
    /* A full source unit is accepted before its STORE exists.  That
     * transition is local work owned by sync_monitor_service(), not worker
     * socket readability: waiting for POLLIN here would deadlock because no
     * request has yet been issued for the worker to answer. */
    if (backend_has_unissued_source(backend) ||
        (interest & SYNC_WORK_LOCAL) != 0U)
        value.immediate = 1U;
    else {
        value.fd = backend->worker_fd;
        if ((interest & SYNC_WORK_READ) != 0U)
            value.events |= POLLIN;
        if ((interest & SYNC_WORK_WRITE) != 0U)
            value.events |= POLLOUT;
        if (value.events == 0U)
            return backend_fail(backend, EPROTO);
    }
    *wait = value;
    return 0;
}

int monitor_session_backend_service(struct session *session, short revents)
{
    monitor_session_backend_t *backend;
    sync_work_io_t io;
    unsigned interest;
    short expected = 0;

    if (session == NULL || !monitor_session_backend_is_bound(session))
        return error_with(EINVAL);
    backend = session->monitor_backend;
    if (!backend_healthy(backend))
        return error_with(backend->failure_errno);
    if (backend->binding->life != SYNC_MONITOR_LIVE)
        return error_with(EAGAIN);
    if ((revents & POLLNVAL) != 0)
        return backend_fail(backend, EBADF);
    interest = MONITOR_BACKEND_WORK_INTERESTS(backend->binding->work);
    if ((interest & SYNC_WORK_READ) != 0U)
        expected |= POLLIN;
    if ((interest & SYNC_WORK_WRITE) != 0U)
        expected |= POLLOUT;
    if (!backend_has_unissued_source(backend) &&
        (interest & SYNC_WORK_LOCAL) == 0U &&
        (revents & (short)(expected | POLLHUP | POLLERR)) == 0)
        return 0;
    io = (sync_work_io_t){backend, worker_read, worker_write};
    if (MONITOR_BACKEND_SYNC_SERVICE(session, &io) != 0)
        return backend_fail(backend, EIO);
    return 0;
}

static int drive_custody(monitor_session_backend_t *backend)
{
    for (;;) {
        monitor_pty_custody_wait_t wait = {0};
        monitor_pty_custody_step_result_t result;
        short revents = 0;

        if (MONITOR_BACKEND_CUSTODY_INTEREST(backend->custody, &wait) != 0)
            return backend_fail(backend, errno);
        if (!wait.immediate) {
            struct pollfd pfd = {wait.fd, (short)wait.events, 0};
            int polled = MONITOR_BACKEND_POLL(&pfd, 1, -1);
            if (polled < 0)
                return backend_fail(backend, errno);
            if (polled != 1)
                return backend_fail(backend, EPROTO);
            revents = pfd.revents;
        }
        result = MONITOR_BACKEND_CUSTODY_STEP(backend->custody, revents);
        if (result == MONITOR_PTY_CUSTODY_ERROR)
            return backend_fail(backend,
                backend->custody->failure_errno
                    ? backend->custody->failure_errno : EIO);
        if (result == MONITOR_PTY_CUSTODY_ACTION)
            return backend_fail(backend, EPROTO);
        if (result == MONITOR_PTY_CUSTODY_RESULT)
            return 0;
    }
}

int monitor_session_backend_open(struct session *session, uint16_t rows,
                                 uint16_t columns, uint32_t *public_pid)
{
    monitor_session_backend_t *backend;
    monitor_pty_custody_result_t result = MONITOR_PTY_CUSTODY_RESULT_EMPTY;
    int cause;

    if (session == NULL || public_pid == NULL || *public_pid != 0U ||
        !monitor_session_backend_is_bound(session))
        return error_with(EINVAL);
    backend = session->monitor_backend;
    if (!backend_healthy(backend))
        return error_with(backend->failure_errno);
    if (backend->live || session->pty_master_fd >= 0 ||
        session->pty_child_pid > 0 || rows == 0U || columns == 0U)
        return error_with(EBUSY);
    if (MONITOR_BACKEND_CUSTODY_REQUEST_OPEN(
            backend->custody, rows, columns) != 0 ||
        drive_custody(backend) != 0)
        return backend_fail(backend, errno);
    if (MONITOR_BACKEND_CUSTODY_TAKE(backend->custody, &result) != 0)
        return backend_fail(backend, errno);
    if (result.kind == MONITOR_PTY_CUSTODY_RESULT_REFUSED) {
        cause = result.value > 0 ? result.value : EIO;
        return error_with(cause);
    }
    if (result.kind != MONITOR_PTY_CUSTODY_RESULT_OPENED ||
        result.master_fd < 3 || result.pidfd < 3 || result.public_pid == 0U)
        return backend_fail(backend, EPROTO);
    backend->master_fd = result.master_fd;
    backend->pidfd = result.pidfd;
    backend->public_pid = result.public_pid;
    backend->live = 1U;
    session->pty_master_fd = result.master_fd;
    session->pty_child_pid = (pid_t)result.public_pid;
    *public_pid = result.public_pid;
    return 0;
}

static monitor_session_backend_t *live_backend(struct session *session)
{
    monitor_session_backend_t *backend;
    if (!monitor_session_backend_is_bound(session))
        return NULL;
    backend = session->monitor_backend;
    if (!backend_healthy(backend) || !backend->live ||
        backend->master_fd < 3 || backend->pidfd < 3 ||
        backend->public_pid == 0U ||
        session->pty_master_fd != backend->master_fd ||
        session->pty_child_pid != (pid_t)backend->public_pid)
        return NULL;
    return backend;
}

ssize_t monitor_session_backend_read(struct session *session,
                                     void *buffer, size_t length)
{
    monitor_session_backend_t *backend = live_backend(session);
    if (backend == NULL || buffer == NULL || length == 0U)
        return error_with(EINVAL);
    return MONITOR_BACKEND_CUSTODY_READ(backend->custody, buffer, length);
}

ssize_t monitor_session_backend_write(struct session *session,
                                      const void *buffer, size_t length)
{
    monitor_session_backend_t *backend = live_backend(session);
    if (backend == NULL || buffer == NULL || length == 0U)
        return error_with(EINVAL);
    return MONITOR_BACKEND_CUSTODY_WRITE(backend->custody, buffer, length);
}

int monitor_session_backend_resize(struct session *session, uint16_t rows,
                                   uint16_t columns)
{
    monitor_session_backend_t *backend = live_backend(session);
    return backend && rows && columns
        ? MONITOR_BACKEND_CUSTODY_RESIZE(backend->custody, rows, columns)
        : error_with(EINVAL);
}

int monitor_session_backend_signal(struct session *session, int signum)
{
    monitor_session_backend_t *backend = live_backend(session);
    return backend && signum > 0 && signum < 64
        ? MONITOR_BACKEND_CUSTODY_SIGNAL(backend->custody, signum)
        : error_with(EINVAL);
}

int monitor_session_backend_retire(struct session *session, int *exit_code)
{
    monitor_session_backend_t *backend;
    monitor_pty_custody_result_t result = MONITOR_PTY_CUSTODY_RESULT_EMPTY;

    if (session == NULL || exit_code == NULL || *exit_code != -1 ||
        (backend = live_backend(session)) == NULL)
        return error_with(EINVAL);
    /* Borrowed fields are invalid before RETIRE can cross to C. */
    session->pty_master_fd = -1;
    session->pty_child_pid = 0;
    backend->master_fd = -1;
    backend->pidfd = -1;
    backend->public_pid = 0U;
    backend->live = 0U;
    if (MONITOR_BACKEND_CUSTODY_REQUEST_RETIRE(backend->custody) != 0 ||
        drive_custody(backend) != 0 ||
        MONITOR_BACKEND_CUSTODY_TAKE(backend->custody, &result) != 0)
        return backend_fail(backend, errno);
    if (result.kind != MONITOR_PTY_CUSTODY_RESULT_REAPED ||
        result.master_fd != -1 || result.pidfd != -1 ||
        result.value < 0 || result.value > 255)
        return backend_fail(backend, EPROTO);
    *exit_code = result.value;
    return 0;
}

int monitor_session_backend_detach(struct session *session)
{
    monitor_session_backend_t *backend;
    if (session == NULL || session->monitor_backend == NULL)
        return error_with(EINVAL);
    backend = session->monitor_backend;
    if (backend->session != session || backend->live ||
        session->pty_master_fd >= 0 || session->pty_child_pid > 0)
        return error_with(EBUSY);
    session->monitor_backend = NULL;
    backend->session = NULL;
    backend->bound = 0U;
    return 0;
}

int monitor_session_backend_dispose(monitor_session_backend_t *backend)
{
    int cause;
    if (backend == NULL)
        return error_with(EINVAL);
    if (backend->disposed) {
        cause = backend->failure_errno;
        return cause ? error_with(cause) : 0;
    }
    if (backend->bound || backend->session != NULL || backend->live)
        return error_with(EBUSY);
    backend->disposed = 1U;
    cause = backend->failure_errno;
    return cause ? error_with(cause) : 0;
}
