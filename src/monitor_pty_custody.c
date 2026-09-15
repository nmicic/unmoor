/*
 * monitor_pty_custody.c — standalone native listener-monitor C-M PTY owner
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE
#define _DARWIN_C_SOURCE
#include "monitor_pty_custody.h"
#include "monitor_child_pidfd.h"
#include "pty.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef PTY_CUSTODY_NATIVE
#if defined(__linux__) && defined(__LP64__) && \
    (defined(__x86_64__) || defined(__aarch64__)) && \
    defined(MSG_CMSG_CLOEXEC) && defined(SOCK_NONBLOCK) && \
    defined(SOCK_CLOEXEC) && defined(MSG_NOSIGNAL)
#define PTY_CUSTODY_NATIVE 1
#else
#define PTY_CUSTODY_NATIVE 0
#endif
#endif

#if PTY_CUSTODY_NATIVE && !defined(MONITOR_PTY_CUSTODY_TEST)
#define PTY_CUSTODY_RECV_FLAGS MSG_CMSG_CLOEXEC
#define PTY_CUSTODY_SEND_FLAGS MSG_NOSIGNAL
#define PTY_CUSTODY_SOCKET_FLAGS (SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC)
#else
#define PTY_CUSTODY_RECV_FLAGS 0
#define PTY_CUSTODY_SEND_FLAGS 0
#define PTY_CUSTODY_SOCKET_FLAGS SOCK_STREAM
#endif

#ifndef MONITOR_PTY_CUSTODY_SOCKETPAIR
#define MONITOR_PTY_CUSTODY_SOCKETPAIR socketpair
#define MONITOR_PTY_CUSTODY_SENDMSG sendmsg
#define MONITOR_PTY_CUSTODY_RECVMSG recvmsg
#define MONITOR_PTY_CUSTODY_CLOSE close
#define MONITOR_PTY_CUSTODY_FCNTL fcntl
#define MONITOR_PTY_CUSTODY_GETSOCKOPT getsockopt
#define MONITOR_PTY_CUSTODY_PTY_SPAWN pty_spawn
#define MONITOR_PTY_CUSTODY_PTY_CLOSE pty_close
#define MONITOR_PTY_CUSTODY_PTY_RESIZE pty_resize
#define MONITOR_PTY_CUSTODY_PIDFD_OPEN monitor_child_pidfd_open
#define MONITOR_PTY_CUSTODY_PIDFD_SIGNAL monitor_child_pidfd_signal
#define MONITOR_PTY_CUSTODY_READ read
#define MONITOR_PTY_CUSTODY_WRITE write
#endif

enum { ROLE_C = MONITOR_PTY_C, ROLE_M = MONITOR_PTY_M };
enum { ACTION_NONE, ACTION_SPAWN, ACTION_RELEASE, ACTION_REAP };
enum {
    FLAG_TX = 1U,
    FLAG_RIGHTS_SENT = 2U,
    FLAG_RESULT = 4U,
    FLAG_DISPOSED = 8U
};
enum { CONTROL_BYTES = 24 };

typedef struct custody_io {
    struct msghdr msg;
    struct iovec iov;
    union { struct cmsghdr align; unsigned char bytes[CONTROL_BYTES]; } control;
} custody_io_t;

_Static_assert(sizeof(monitor_pty_custody_result_t) == 32U &&
               sizeof(monitor_pty_custody_wait_t) == 8U &&
               sizeof(monitor_pty_custody_t) == 176U,
               "PTY custody caller-storage contract changed");
#if PTY_CUSTODY_NATIVE && !defined(MONITOR_PTY_CUSTODY_TEST)
_Static_assert(sizeof(custody_io_t) == 96U &&
               CMSG_LEN(2U * sizeof(int)) == CONTROL_BYTES &&
               CMSG_SPACE(2U * sizeof(int)) == CONTROL_BYTES,
               "PTY custody Linux ancillary layout changed");
#endif

static int error_with(int cause)
{
    errno = cause;
    return -1;
}

static int zero_bytes(const void *pointer, size_t length)
{
    const unsigned char *bytes = pointer;
    for (size_t i = 0; i < length; ++i)
        if (bytes[i] != 0U) return 0;
    return 1;
}

static int map_is_released(const sync_source_map_t *map)
{
    return map != NULL && map->state == SYNC_SOURCE_MAP_RELEASED &&
           map->payload == NULL && map->control == NULL &&
           map->payload_length == 0U && map->page_length == 0U &&
           map->nrecords == 0U;
}

static void empty_result(monitor_pty_custody_result_t *result)
{
    memset(result, 0, sizeof(*result));
    result->master_fd = -1;
    result->pidfd = -1;
}

static void note_cleanup(monitor_pty_custody_t *owner, int cause)
{
    if (owner->cleanup_errno == 0)
        owner->cleanup_errno = cause > 0 ? cause : EIO;
}

static void retire_slot(monitor_pty_custody_t *owner, int *slot)
{
    int descriptor = *slot;
    *slot = -1;
    if (descriptor >= 0 && MONITOR_PTY_CUSTODY_CLOSE(descriptor) != 0)
        note_cleanup(owner, errno);
}

static void retire_pair(monitor_pty_custody_t *owner)
{
    retire_slot(owner, &owner->pair[0]);
    retire_slot(owner, &owner->pair[1]);
    owner->received_n = 0;
}

static int fail_owner(monitor_pty_custody_t *owner, int cause)
{
    if (owner->failure_errno == 0)
        owner->failure_errno = cause > 0 ? cause : EIO;
    owner->protocol.phase = MONITOR_PTY_FAILED;
    owner->action = ACTION_NONE;
    retire_pair(owner);
    return error_with(owner->failure_errno);
}

static int owner_valid(const monitor_pty_custody_t *owner)
{
    if (owner == NULL || (owner->role != ROLE_C && owner->role != ROLE_M))
        return error_with(EINVAL);
    if (owner->failure_errno != 0)
        return error_with(owner->failure_errno);
    if ((owner->flags & FLAG_DISPOSED) != 0)
        return error_with(ECANCELED);
    return 0;
}

static int descriptor_cloexec(int descriptor)
{
    int flags = MONITOR_PTY_CUSTODY_FCNTL(descriptor, F_GETFD);
    if (flags < 0) return -1;
    return (flags & FD_CLOEXEC) != 0 ? 0 : error_with(EPERM);
}

static int endpoint_valid(int descriptor)
{
    int type = 0;
    socklen_t length = sizeof(type);
    int flags;
    if (descriptor < 0 || descriptor_cloexec(descriptor) != 0)
        return -1;
    flags = MONITOR_PTY_CUSTODY_FCNTL(descriptor, F_GETFL);
    if (flags < 0) return -1;
    if ((flags & O_NONBLOCK) == 0)
        return error_with(EPERM);
    if (MONITOR_PTY_CUSTODY_GETSOCKOPT(descriptor, SOL_SOCKET, SO_TYPE,
                                      &type, &length) != 0)
        return -1;
    return length == sizeof(type) && type == SOCK_STREAM ? 0 : error_with(EPERM);
}

static int master_valid(int descriptor)
{
    int flags;
    if (descriptor < 0 || descriptor_cloexec(descriptor) != 0)
        return -1;
    flags = MONITOR_PTY_CUSTODY_FCNTL(descriptor, F_GETFL);
    if (flags < 0) return -1;
#ifdef O_PATH
    if ((flags & O_PATH) != 0) return error_with(EPERM);
#endif
    return (flags & O_ACCMODE) == O_RDWR && (flags & O_NONBLOCK) != 0 ?
           0 : error_with(EPERM);
}

int monitor_pty_custody_supported(void)
{
    return PTY_CUSTODY_NATIVE;
}

int monitor_pty_custody_pair_create(int pair[2])
{
    int made[2] = { -1, -1 };
    if (pair == NULL || pair[0] != -1 || pair[1] != -1)
        return error_with(EINVAL);
    if (!PTY_CUSTODY_NATIVE)
        return error_with(ENOTSUP);
    if (MONITOR_PTY_CUSTODY_SOCKETPAIR(AF_UNIX,
            PTY_CUSTODY_SOCKET_FLAGS, 0, made) != 0)
        return -1;
    /* The atomic socketpair flags are the factory operation.  Do not add a
     * fallible post-success query here: there is no owner yet in which to
     * retain close uncertainty.  Role init validates the exact endpoint. */
    pair[0] = made[0];
    pair[1] = made[1];
    return 0;
}

static int queue_record(monitor_pty_custody_t *owner,
                        const monitor_pty_record_t *record)
{
    if ((owner->flags & FLAG_TX) != 0 || owner->tx_n != 0)
        return error_with(EBUSY);
    if (monitor_pty_encode(owner->tx, sizeof(owner->tx), record) != 0)
        return error_with(EPROTO);
    owner->flags |= FLAG_TX;
    owner->flags &= (uint8_t)~FLAG_RIGHTS_SENT;
    return 0;
}

static int initialize(monitor_pty_custody_t *owner, int *endpoint,
                      uint64_t incarnation, uint8_t role,
                      const sync_source_map_t *map)
{
    monitor_pty_record_t launch = {0};
    if (owner == NULL || endpoint == NULL || incarnation == 0U)
        return error_with(EINVAL);
    if (!zero_bytes(owner, sizeof(*owner)))
        return error_with(EALREADY);
    if (!PTY_CUSTODY_NATIVE)
        return error_with(ENOTSUP);
    if (endpoint_valid(*endpoint) != 0)
        return -1;
    if (role == ROLE_C && !map_is_released(map))
        return error_with(EPERM);

    owner->channel_fd = *endpoint;
    owner->pair[0] = owner->pair[1] = -1;
    owner->child_pid = -1;
    owner->child_status = -1;
    owner->role = role;
    owner->released_map = map;
    empty_result(&owner->result);
    if (monitor_pty_protocol_init(&owner->protocol, incarnation) != 0) {
        memset(owner, 0, sizeof(*owner));
        return error_with(EPROTO);
    }
    if (role == ROLE_C) {
        launch.incarnation = incarnation;
        launch.kind = MONITOR_PTY_LAUNCH;
        if (queue_record(owner, &launch) != 0) {
            memset(owner, 0, sizeof(*owner));
            return error_with(EPROTO);
        }
    }
    *endpoint = -1;
    return 0;
}

int monitor_pty_custody_c_init(monitor_pty_custody_t *owner, int *endpoint,
                               uint64_t incarnation,
                               const sync_source_map_t *released_map)
{
    return initialize(owner, endpoint, incarnation, ROLE_C, released_map);
}

int monitor_pty_custody_m_init(monitor_pty_custody_t *owner, int *endpoint,
                               uint64_t incarnation)
{
    return initialize(owner, endpoint, incarnation, ROLE_M, NULL);
}

int monitor_pty_custody_interest(const monitor_pty_custody_t *owner,
                                 monitor_pty_custody_wait_t *wait)
{
    if (owner_valid(owner) != 0) return -1;
    if (wait == NULL) return error_with(EINVAL);
    memset(wait, 0, sizeof(*wait));
    wait->fd = owner->channel_fd;
    wait->events = POLLIN;
    if ((owner->flags & FLAG_TX) != 0) wait->events |= POLLOUT;
    wait->immediate = owner->action != ACTION_NONE;
    return 0;
}

static int observe(monitor_pty_custody_t *owner, uint8_t sender,
                   const monitor_pty_record_t *record)
{
    monitor_pty_protocol_t preview = owner->protocol;
    if (monitor_pty_protocol_observe(&preview, sender, record) != 0)
        return fail_owner(owner, EPROTO);
    owner->protocol = preview;
    return 0;
}

static monitor_pty_custody_step_result_t send_record(monitor_pty_custody_t *owner)
{
    custody_io_t io;
    ssize_t sent;
    int offer = owner->tx[1] == MONITOR_PTY_OFFER;
    memset(&io, 0, sizeof(io));
    io.iov.iov_base = owner->tx + owner->tx_n;
    io.iov.iov_len = sizeof(owner->tx) - owner->tx_n;
    io.msg.msg_iov = &io.iov;
    io.msg.msg_iovlen = 1;
    if (offer && (owner->flags & FLAG_RIGHTS_SENT) == 0) {
        struct cmsghdr *control;
        io.msg.msg_control = io.control.bytes;
        io.msg.msg_controllen = sizeof(io.control.bytes);
        control = CMSG_FIRSTHDR(&io.msg);
        control->cmsg_level = SOL_SOCKET;
        control->cmsg_type = SCM_RIGHTS;
        control->cmsg_len = (socklen_t)CMSG_LEN(2U * sizeof(int));
        memcpy(CMSG_DATA(control), owner->pair, 2U * sizeof(int));
    }
    sent = MONITOR_PTY_CUSTODY_SENDMSG(owner->channel_fd, &io.msg,
                                       PTY_CUSTODY_SEND_FLAGS);
    if (sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            return MONITOR_PTY_CUSTODY_WAIT;
        (void)fail_owner(owner, errno);
        return MONITOR_PTY_CUSTODY_ERROR;
    }
    if (sent == 0 || (size_t)sent > sizeof(owner->tx) - owner->tx_n) {
        (void)fail_owner(owner, sent == 0 ? EPIPE : EPROTO);
        return MONITOR_PTY_CUSTODY_ERROR;
    }
    if (offer) owner->flags |= FLAG_RIGHTS_SENT;
    owner->tx_n = (uint8_t)(owner->tx_n + (size_t)sent);
    if (owner->tx_n != sizeof(owner->tx))
        return MONITOR_PTY_CUSTODY_PROGRESS;

    monitor_pty_record_t record;
    if (monitor_pty_decode(&record, owner->tx, sizeof(owner->tx)) != 0 ||
        observe(owner, owner->role, &record) != 0)
        return MONITOR_PTY_CUSTODY_ERROR;
    owner->tx_n = 0;
    owner->flags &= (uint8_t)~(FLAG_TX | FLAG_RIGHTS_SENT);
    memset(owner->tx, 0, sizeof(owner->tx));
    return MONITOR_PTY_CUSTODY_PROGRESS;
}

static void accept_right(monitor_pty_custody_t *owner, int descriptor,
                         int allowed, int *bad)
{
    if (descriptor < 0) {
        *bad = 1;
    } else if (allowed && owner->received_n < 2U) {
        owner->pair[owner->received_n++] = descriptor;
    } else {
        if (MONITOR_PTY_CUSTODY_CLOSE(descriptor) != 0)
            note_cleanup(owner, errno);
        *bad = 1;
    }
}

static int receive_rights(monitor_pty_custody_t *owner, struct msghdr *message,
                          ssize_t got)
{
    size_t offset = 0, length = message->msg_controllen;
    unsigned headers = 0, count = 0;
    int allowed = owner->role == ROLE_M &&
                  owner->protocol.phase == MONITOR_PTY_WAIT_OFFER &&
                  owner->rx_n == 0 && got > 0 && owner->received_n == 0 &&
                  owner->pair[0] == -1 && owner->pair[1] == -1;
    int bad = (message->msg_flags & (MSG_CTRUNC | MSG_TRUNC)) != 0;

    if (length > CONTROL_BYTES) {
        length = CONTROL_BYTES;
        bad = 1;
    }
    while (length - offset >= sizeof(struct cmsghdr)) {
        struct cmsghdr *control =
            (struct cmsghdr *)((unsigned char *)message->msg_control + offset);
        size_t size = control->cmsg_len;
        size_t payload;
        ++headers;
        if (size < CMSG_LEN(0) || size > length - offset) {
            bad = 1;
            break;
        }
        payload = size - CMSG_LEN(0);
        if (control->cmsg_level != SOL_SOCKET ||
            control->cmsg_type != SCM_RIGHTS || payload % sizeof(int) != 0) {
            bad = 1;
        } else {
            for (size_t i = 0; i < payload / sizeof(int); ++i) {
                int descriptor;
                memcpy(&descriptor, CMSG_DATA(control) + i * sizeof(int),
                       sizeof(descriptor));
                ++count;
                accept_right(owner, descriptor, allowed, &bad);
            }
        }
        size = CMSG_SPACE(payload);
        if (size > length - offset) break;
        offset += size;
    }
    if (length != 0 && headers == 0) bad = 1;
    if (headers > 1U || count > 2U) bad = 1;
    if (bad || owner->cleanup_errno != 0)
        return fail_owner(owner, owner->cleanup_errno ? owner->cleanup_errno : EPROTO);
    return 0;
}

static int validate_received_pair(monitor_pty_custody_t *owner)
{
    if (owner->received_n != 2U || owner->pair[0] < 0 || owner->pair[1] < 0 ||
        owner->pair[0] == owner->pair[1] ||
        owner->pair[0] == owner->channel_fd || owner->pair[1] == owner->channel_fd)
        return fail_owner(owner, EPROTO);
    if (master_valid(owner->pair[0]) != 0)
        return fail_owner(owner, errno ? errno : EIO);
    if (descriptor_cloexec(owner->pair[1]) != 0)
        return fail_owner(owner, errno ? errno : EIO);
    return 0;
}

static int set_result(monitor_pty_custody_t *owner, uint8_t kind,
                      const monitor_pty_record_t *record)
{
    if ((owner->flags & FLAG_RESULT) != 0)
        return fail_owner(owner, EPROTO);
    empty_result(&owner->result);
    owner->result.kind = kind;
    if (kind == MONITOR_PTY_CUSTODY_RESULT_OPENED) {
        owner->result.token = owner->protocol.shell_token;
        owner->result.master_fd = owner->pair[0];
        owner->result.pidfd = owner->pair[1];
        owner->result.public_pid = owner->protocol.public_pid;
    } else {
        owner->result.value = (int)record->arg0;
    }
    owner->flags |= FLAG_RESULT;
    return 0;
}

static int handle_received(monitor_pty_custody_t *owner,
                           const monitor_pty_record_t *record)
{
    monitor_pty_protocol_t preview = owner->protocol;
    uint8_t peer = owner->role == ROLE_C ? ROLE_M : ROLE_C;
    if (monitor_pty_protocol_observe(&preview, peer, record) != 0)
        return fail_owner(owner, EPROTO);
    if (owner->role == ROLE_M && record->kind == MONITOR_PTY_OFFER) {
        if (validate_received_pair(owner) != 0) return -1;
    } else if (owner->received_n != 0U) {
        return fail_owner(owner, EPROTO);
    }
    owner->protocol = preview;

    if (owner->role == ROLE_C && record->kind == MONITOR_PTY_OPEN) {
        owner->rows = (uint16_t)(record->arg0 & UINT32_C(0xffff));
        owner->columns = (uint16_t)(record->arg0 >> 16);
        owner->action = ACTION_SPAWN;
    } else if (owner->role == ROLE_M && record->kind == MONITOR_PTY_OFFER) {
        monitor_pty_record_t acquired = {0};
        acquired.incarnation = owner->protocol.incarnation;
        acquired.serial = owner->protocol.last_serial;
        acquired.kind = MONITOR_PTY_ACQUIRED;
        if (queue_record(owner, &acquired) != 0)
            return fail_owner(owner, EPROTO);
    } else if (owner->role == ROLE_C && record->kind == MONITOR_PTY_ACQUIRED) {
        owner->action = ACTION_RELEASE;
    } else if (owner->role == ROLE_M && record->kind == MONITOR_PTY_COMMIT) {
        if (set_result(owner, MONITOR_PTY_CUSTODY_RESULT_OPENED, record) != 0)
            return -1;
    } else if (owner->role == ROLE_M && record->kind == MONITOR_PTY_REFUSED) {
        if (set_result(owner, MONITOR_PTY_CUSTODY_RESULT_REFUSED, record) != 0)
            return -1;
    } else if (owner->role == ROLE_C && record->kind == MONITOR_PTY_RETIRE) {
        owner->action = ACTION_REAP;
    } else if (owner->role == ROLE_M && record->kind == MONITOR_PTY_REAPED) {
        if (set_result(owner, MONITOR_PTY_CUSTODY_RESULT_REAPED, record) != 0)
            return -1;
    }
    return 0;
}

static monitor_pty_custody_step_result_t receive_record(monitor_pty_custody_t *owner)
{
    custody_io_t io;
    ssize_t got;
    memset(&io, 0, sizeof(io));
    io.iov.iov_base = owner->rx + owner->rx_n;
    io.iov.iov_len = sizeof(owner->rx) - owner->rx_n;
    io.msg.msg_iov = &io.iov;
    io.msg.msg_iovlen = 1;
    io.msg.msg_control = io.control.bytes;
    io.msg.msg_controllen = sizeof(io.control.bytes);
    got = MONITOR_PTY_CUSTODY_RECVMSG(owner->channel_fd, &io.msg,
                                      PTY_CUSTODY_RECV_FLAGS);
    if (got < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            return MONITOR_PTY_CUSTODY_WAIT;
        (void)fail_owner(owner, errno);
        return MONITOR_PTY_CUSTODY_ERROR;
    }
    if (receive_rights(owner, &io.msg, got) != 0)
        return MONITOR_PTY_CUSTODY_ERROR;
    if (got == 0) {
        (void)fail_owner(owner, EPIPE);
        return MONITOR_PTY_CUSTODY_ERROR;
    }
    if ((size_t)got > sizeof(owner->rx) - owner->rx_n) {
        (void)fail_owner(owner, EPROTO);
        return MONITOR_PTY_CUSTODY_ERROR;
    }
    owner->rx_n = (uint8_t)(owner->rx_n + (size_t)got);
    if (owner->rx_n != sizeof(owner->rx))
        return MONITOR_PTY_CUSTODY_PROGRESS;

    monitor_pty_record_t record;
    if (monitor_pty_decode(&record, owner->rx, sizeof(owner->rx)) != 0 ||
        handle_received(owner, &record) != 0)
        return MONITOR_PTY_CUSTODY_ERROR;
    owner->rx_n = 0;
    owner->received_n = 0;
    memset(owner->rx, 0, sizeof(owner->rx));
    if (owner->action != ACTION_NONE) return MONITOR_PTY_CUSTODY_ACTION;
    if ((owner->flags & FLAG_RESULT) != 0) return MONITOR_PTY_CUSTODY_RESULT;
    return MONITOR_PTY_CUSTODY_PROGRESS;
}

monitor_pty_custody_step_result_t
monitor_pty_custody_step(monitor_pty_custody_t *owner, short revents)
{
    if (owner_valid(owner) != 0) return MONITOR_PTY_CUSTODY_ERROR;
    if (owner->action != ACTION_NONE) return MONITOR_PTY_CUSTODY_ACTION;
    if ((revents & POLLNVAL) != 0) {
        (void)fail_owner(owner, EBADF);
        return MONITOR_PTY_CUSTODY_ERROR;
    }
    if ((revents & (POLLIN | POLLHUP | POLLERR)) != 0)
        return receive_record(owner);
    if ((revents & POLLOUT) != 0 && (owner->flags & FLAG_TX) != 0)
        return send_record(owner);
    return (owner->flags & FLAG_RESULT) != 0 ?
           MONITOR_PTY_CUSTODY_RESULT : MONITOR_PTY_CUSTODY_WAIT;
}

int monitor_pty_custody_request_open(monitor_pty_custody_t *owner,
                                     uint16_t rows, uint16_t columns)
{
    monitor_pty_record_t record = {0};
    if (owner_valid(owner) != 0) return -1;
    if (owner->role != ROLE_M || rows < 1U || rows > 1000U ||
        columns < 1U || columns > 1000U)
        return error_with(EINVAL);
    if (owner->protocol.phase != MONITOR_PTY_IDLE ||
        (owner->flags & (FLAG_TX | FLAG_RESULT)) != 0 ||
        owner->action != ACTION_NONE)
        return error_with(EBUSY);
    if (owner->protocol.last_serial == UINT64_MAX)
        return fail_owner(owner, EOVERFLOW);
    record.incarnation = owner->protocol.incarnation;
    record.serial = owner->protocol.last_serial + 1U;
    record.arg0 = (uint32_t)rows | ((uint32_t)columns << 16);
    record.kind = MONITOR_PTY_OPEN;
    return queue_record(owner, &record);
}

static int queue_refused(monitor_pty_custody_t *owner, int cause)
{
    monitor_pty_record_t record = {0};
    if (cause <= 0 || cause > INT32_MAX) cause = EIO;
    record.incarnation = owner->protocol.incarnation;
    record.serial = owner->protocol.last_serial;
    record.arg0 = (uint32_t)cause;
    record.kind = MONITOR_PTY_REFUSED;
    record.status = 1;
    return queue_record(owner, &record);
}

static int cleanup_spawn(monitor_pty_custody_t *owner, int cause,
                         int master, pid_t child, int pidfd)
{
    int result;
    if (pidfd >= 0 && MONITOR_PTY_CUSTODY_CLOSE(pidfd) != 0)
        note_cleanup(owner, errno);
    if (master >= 0 && MONITOR_PTY_CUSTODY_CLOSE(master) != 0)
        note_cleanup(owner, errno);
    errno = 0;
    result = child > 0 ? MONITOR_PTY_CUSTODY_PTY_CLOSE(-1, child) : 0;
    if (result < 0) note_cleanup(owner, errno ? errno : ECHILD);
    if (owner->cleanup_errno != 0)
        return fail_owner(owner, cause);
    if (queue_refused(owner, cause) != 0)
        return fail_owner(owner, EPROTO);
    return 0;
}

int monitor_pty_custody_perform_action(monitor_pty_custody_t *owner)
{
    monitor_pty_record_t record = {0};
    int action;
    if (owner_valid(owner) != 0) return -1;
    if (owner->role != ROLE_C || owner->action == ACTION_NONE)
        return error_with(EINVAL);
    action = owner->action;
    owner->action = ACTION_NONE;

    if (action == ACTION_SPAWN) {
        int master = -1, pidfd = -1;
        pid_t child = -1;
        int cause;
        if (!map_is_released(owner->released_map))
            return fail_owner(owner, EPERM);
        if (MONITOR_PTY_CUSTODY_PTY_SPAWN(NULL, owner->rows, owner->columns,
                                          &master, &child) != 0) {
            cause = errno ? errno : EIO;
            return cleanup_spawn(owner, cause, master, child, pidfd);
        }
        if (master_valid(master) != 0) {
            cause = errno ? errno : EIO;
            return cleanup_spawn(owner, cause, master, child, pidfd);
        }
        pidfd = MONITOR_PTY_CUSTODY_PIDFD_OPEN(child);
        if (pidfd < 0 || descriptor_cloexec(pidfd) != 0) {
            cause = errno ? errno : EIO;
            return cleanup_spawn(owner, cause, master, child, pidfd);
        }
        owner->pair[0] = master;
        owner->pair[1] = pidfd;
        owner->child_pid = child;
        record.incarnation = owner->protocol.incarnation;
        record.serial = owner->protocol.last_serial;
        record.arg0 = (uint32_t)child;
        record.kind = MONITOR_PTY_OFFER;
        record.rights = 2;
        if (queue_record(owner, &record) != 0)
            return fail_owner(owner, EPROTO);
        return 0;
    }
    if (action == ACTION_RELEASE) {
        retire_pair(owner);
        if (owner->cleanup_errno != 0)
            return fail_owner(owner, owner->cleanup_errno);
        record.incarnation = owner->protocol.incarnation;
        record.serial = owner->protocol.last_serial;
        record.kind = MONITOR_PTY_COMMIT;
        if (queue_record(owner, &record) != 0)
            return fail_owner(owner, EPROTO);
        return 0;
    }
    if (action == ACTION_REAP) {
        pid_t child = owner->child_pid;
        int status;
        owner->child_pid = -1;
        errno = 0;
        status = MONITOR_PTY_CUSTODY_PTY_CLOSE(-1, child);
        if (status < 0)
            return fail_owner(owner, errno ? errno : ECHILD);
        owner->child_status = status;
        record.incarnation = owner->protocol.incarnation;
        record.serial = owner->protocol.last_serial;
        record.arg0 = (uint32_t)status;
        record.kind = MONITOR_PTY_REAPED;
        if (queue_record(owner, &record) != 0)
            return fail_owner(owner, EPROTO);
        return 0;
    }
    return fail_owner(owner, EPROTO);
}

int monitor_pty_custody_c_role_ready(const monitor_pty_custody_t *owner)
{
    if (owner_valid(owner) != 0 || owner->role != ROLE_C)
        return error_with(EINVAL);
    return owner->protocol.phase == MONITOR_PTY_WAIT_COMMIT &&
           owner->action == ACTION_NONE && owner->child_pid > 0 &&
           owner->pair[0] == -1 && owner->pair[1] == -1 &&
           (owner->flags & FLAG_TX) != 0 && owner->tx_n == 0U &&
           owner->tx[1] == MONITOR_PTY_COMMIT;
}

int monitor_pty_custody_take_result(monitor_pty_custody_t *owner,
                                    monitor_pty_custody_result_t *result)
{
    uintptr_t owner_address, result_address;
    if (owner_valid(owner) != 0) return -1;
    if (result == NULL) return error_with(EINVAL);
    owner_address = (uintptr_t)owner;
    result_address = (uintptr_t)result;
    if (owner_address <= result_address ?
        result_address - owner_address < sizeof(*owner) :
        owner_address - result_address < sizeof(*result))
        return error_with(EINVAL);
    monitor_pty_custody_result_t empty = MONITOR_PTY_CUSTODY_RESULT_EMPTY;
    if (memcmp(result, &empty, sizeof(empty)) != 0)
        return error_with(EINVAL);
    if ((owner->flags & FLAG_RESULT) == 0)
        return error_with(EAGAIN);
    *result = owner->result;
    empty_result(&owner->result);
    owner->flags &= (uint8_t)~FLAG_RESULT;
    return 0;
}

int monitor_pty_custody_request_retire(monitor_pty_custody_t *owner)
{
    monitor_pty_record_t record = {0};
    uint64_t token;
    if (owner_valid(owner) != 0) return -1;
    if (owner->role != ROLE_M) return error_with(EINVAL);
    if (owner->protocol.phase != MONITOR_PTY_LIVE ||
        (owner->flags & (FLAG_TX | FLAG_RESULT)) != 0 ||
        owner->action != ACTION_NONE)
        return error_with(EBUSY);
    token = owner->protocol.shell_token;
    retire_pair(owner);
    if (owner->cleanup_errno != 0)
        return fail_owner(owner, owner->cleanup_errno);
    if (owner->protocol.last_serial == UINT64_MAX)
        return fail_owner(owner, EOVERFLOW);
    record.incarnation = owner->protocol.incarnation;
    record.serial = owner->protocol.last_serial + 1U;
    record.arg0 = (uint32_t)token;
    record.arg1 = (uint32_t)(token >> 32);
    record.kind = MONITOR_PTY_RETIRE;
    if (queue_record(owner, &record) != 0)
        return fail_owner(owner, EPROTO);
    return 0;
}

static int live_m(const monitor_pty_custody_t *owner)
{
    if (owner_valid(owner) != 0) return -1;
    if (owner->role != ROLE_M || owner->protocol.phase != MONITOR_PTY_LIVE ||
        owner->pair[0] < 0 || owner->pair[1] < 0)
        return error_with(EPIPE);
    return 0;
}

ssize_t monitor_pty_custody_read(monitor_pty_custody_t *owner,
                                 void *buffer, size_t length)
{
    if (live_m(owner) != 0) return -1;
    if (buffer == NULL && length != 0U) return error_with(EINVAL);
    return MONITOR_PTY_CUSTODY_READ(owner->pair[0], buffer, length);
}

ssize_t monitor_pty_custody_write(monitor_pty_custody_t *owner,
                                  const void *buffer, size_t length)
{
    if (live_m(owner) != 0) return -1;
    if (buffer == NULL && length != 0U) return error_with(EINVAL);
    return MONITOR_PTY_CUSTODY_WRITE(owner->pair[0], buffer, length);
}

int monitor_pty_custody_resize(monitor_pty_custody_t *owner,
                               uint16_t rows, uint16_t columns)
{
    if (live_m(owner) != 0) return -1;
    if (rows < 1U || rows > 1000U || columns < 1U || columns > 1000U)
        return error_with(EINVAL);
    return MONITOR_PTY_CUSTODY_PTY_RESIZE(owner->pair[0], rows, columns);
}

int monitor_pty_custody_signal(monitor_pty_custody_t *owner, int signum)
{
    if (live_m(owner) != 0) return -1;
    if (signum < 1 || signum > 63) return error_with(EINVAL);
    return MONITOR_PTY_CUSTODY_PIDFD_SIGNAL(owner->pair[1], signum);
}

int monitor_pty_custody_abort(monitor_pty_custody_t *owner, int cause)
{
    if (cause <= 0)
        return error_with(EINVAL);
    if (owner_valid(owner) != 0) return -1;
    return fail_owner(owner, cause);
}

int monitor_pty_custody_dispose(monitor_pty_custody_t *owner)
{
    if (owner == NULL) return error_with(EINVAL);
    if (zero_bytes(owner, sizeof(*owner))) return 0;
    if (owner->role != ROLE_C && owner->role != ROLE_M)
        return error_with(EINVAL);
    if ((owner->flags & FLAG_DISPOSED) == 0) {
        retire_pair(owner);
        retire_slot(owner, &owner->channel_fd);
        if (owner->role == ROLE_C && owner->child_pid > 0) {
            pid_t child = owner->child_pid;
            int status;
            owner->child_pid = -1;
            errno = 0;
            status = MONITOR_PTY_CUSTODY_PTY_CLOSE(-1, child);
            if (status < 0) note_cleanup(owner, errno ? errno : ECHILD);
            else owner->child_status = status;
        }
        owner->flags |= FLAG_DISPOSED;
    }
    if (owner->failure_errno != 0) return error_with(owner->failure_errno);
    if (owner->cleanup_errno != 0) return error_with(owner->cleanup_errno);
    return 0;
}
