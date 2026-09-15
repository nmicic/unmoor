/*
 * monitor_startup.c — standalone fixed listener-monitor P-C public handoff
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE
#define _DARWIN_C_SOURCE
#include "monitor_startup.h"
#include "monitor_platform.h"
#include "deaddrop.h"
#include "fd_stat.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#if defined(__linux__) && defined(__LP64__) && \
    (defined(__x86_64__) || defined(__aarch64__))
#define STARTUP_NATIVE 1
#define STARTUP_RECV_FLAGS MSG_CMSG_CLOEXEC
#else
#define STARTUP_NATIVE 0
#define STARTUP_RECV_FLAGS 0 /* Unreachable: requested init refuses first. */
#endif

enum { ROLE_P = 1, ROLE_C = 2 };
enum {
    P_LISTEN = 1, P_RX_READY, P_BUNDLE_ACTION, P_TX_BUNDLE,
    P_RX_ACQUIRED, P_ACQUIRED_ACTION, P_TX_COMMIT,
    C_CONNECT, C_TX_READY, C_RX_BUNDLE, C_VALIDATE_ACTION,
    C_TX_ACQUIRED, C_RX_COMMIT, C_RX_EOF, FINISHED, FAILED
};
enum { READY = 1, BUNDLE = 2, ACQUIRED = 3, COMMIT = 4 };
enum { RIGHTS_SENT = 1, TAKEN = 2 };
enum { NAME_BYTES = 48, CONTROL_BYTES = 40 };

/* The address and I/O workspace never coexist in this helper. Approve's
 * separately called validator does not nest either with its stat scratch. */
typedef union startup_io {
    struct sockaddr_un address;
    struct {
        struct msghdr msg;
        struct iovec iov;
        union { struct cmsghdr align; unsigned char bytes[CONTROL_BYTES]; } control;
    } io;
} startup_io_t;
typedef struct startup_validation {
    struct stat st;
    dev_t device;
    ino_t inode;
    char name[33];
} startup_validation_t;

_Static_assert(sizeof(monitor_startup_t) == 136U &&
               sizeof(monitor_startup_bundle_t) == 20U &&
               sizeof(monitor_startup_wait_t) == 16U,
               "startup caller storage contract changed");
#if STARTUP_NATIVE
_Static_assert(sizeof(startup_io_t) == 112U &&
               offsetof(struct sockaddr_un, sun_path) == 2U &&
               CMSG_LEN(6U * sizeof(int)) == CONTROL_BYTES &&
               CMSG_SPACE(5U * sizeof(int)) == CONTROL_BYTES,
               "startup Linux ancillary/address layout changed");
#if defined(__x86_64__)
_Static_assert(sizeof(startup_validation_t) == 200U,
               "startup x86_64 validation budget changed");
#else
_Static_assert(sizeof(startup_validation_t) == 184U,
               "startup aarch64 validation budget changed");
#endif
#endif

static int error_with(int cause)
{
    errno = cause;
    return -1;
}

static int *bundle_slot(monitor_startup_bundle_t *b, unsigned index)
{
    switch (index) {
    case 0: return &b->parent_fd;
    case 1: return &b->attempt_fd;
    case 2: return &b->status_write_fd;
    case 3: return &b->control_read_fd;
    default: return &b->stderr_fd;
    }
}

static int bundle_value(const monitor_startup_bundle_t *b, unsigned index)
{
    switch (index) {
    case 0: return b->parent_fd;
    case 1: return b->attempt_fd;
    case 2: return b->status_write_fd;
    case 3: return b->control_read_fd;
    default: return b->stderr_fd;
    }
}

static void empty_bundle(monitor_startup_bundle_t *b)
{
    for (unsigned i = 0; i < 5U; ++i)
        *bundle_slot(b, i) = -1;
}

static void retire_value(monitor_startup_t *o, int fd)
{
    if (fd >= 0 && close(fd) != 0 && !o->cleanup_errno)
        o->cleanup_errno = errno ? errno : EIO;
}

static void retire_slot(monitor_startup_t *o, int *slot)
{
    int fd = *slot;
    *slot = -1; /* An uncertain numeric descriptor must never be retried. */
    retire_value(o, fd);
}

static void retire_owned(monitor_startup_t *o)
{
    retire_slot(o, &o->listener_fd);
    retire_slot(o, &o->stream_fd);
    if (o->role == ROLE_C) {
        for (unsigned i = 0; i < 5U; ++i) {
            unsigned bit = 1U << i;
            if ((o->owned_mask & bit) != 0) {
                o->owned_mask &= (uint8_t)~bit;
                retire_slot(o, bundle_slot(&o->bundle, i));
            }
        }
    }
}

static int startup_fail(monitor_startup_t *o, int cause)
{
    if (!o->failure_errno)
        o->failure_errno = cause > 0 ? cause : EIO;
    o->phase = FAILED;
    retire_owned(o);
    return error_with(o->failure_errno);
}

static int owner_valid(const monitor_startup_t *o)
{
    if (!o || (o->role != ROLE_P && o->role != ROLE_C))
        return error_with(EINVAL);
    if (o->failure_errno)
        return error_with(o->failure_errno);
    return 0;
}

static int time_valid(monitor_startup_t *o, int64_t now)
{
    if (owner_valid(o) != 0)
        return -1;
    if (now < 0)
        return error_with(EINVAL);
    if (now < o->last_now_ms)
        return startup_fail(o, EPROTO);
    o->last_now_ms = now;
    if (o->phase != FINISHED && now >= o->deadline_ms)
        return startup_fail(o, ETIMEDOUT);
    if (o->role == ROLE_C && o->phase != FINISHED &&
        getppid() != o->expected_pid)
        return startup_fail(o, ESRCH);
    return 0;
}

static int fresh_owner(const monitor_startup_t *o, const uint8_t *id,
                       pid_t pid, uid_t uid, int stderr_expected,
                       int64_t deadline, int64_t now)
{
    if (!o)
        return error_with(EINVAL);
    if (o->role || o->phase)
        return error_with(EALREADY);
    if (!id || !deaddrop_id_valid(id) || pid <= 0 || uid == (uid_t)-1 ||
        (stderr_expected != 0 && stderr_expected != 1) || now < 0 || deadline < 0)
        return error_with(EINVAL);
    for (size_t i = 0; i < sizeof(*o); ++i) {
        if (((const unsigned char *)o)[i] != 0)
            return error_with(EINVAL);
    }
    if (now >= deadline)
        return error_with(ETIMEDOUT);
    if (!STARTUP_NATIVE)
        return error_with(ENOTSUP);
    return 0;
}

static void initialize(monitor_startup_t *o, const uint8_t *id,
                       pid_t pid, uid_t uid, int stderr_expected,
                       int64_t deadline, int64_t now, uint8_t role)
{
    o->deadline_ms = deadline;
    o->next_connect_ms = now;
    o->last_now_ms = now;
    o->expected_pid = pid;
    o->expected_uid = uid;
    memcpy(o->id, id, sizeof(o->id));
    o->listener_fd = o->stream_fd = -1;
    empty_bundle(&o->bundle);
    o->expected_n = (uint8_t)(4 + stderr_expected);
    o->role = role;
}

static int native_socket(void)
{
#if STARTUP_NATIVE
    return socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
#else
    return error_with(ENOTSUP);
#endif
}

static int native_accept(int listener)
{
#if STARTUP_NATIVE
    return accept4(listener, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
#else
    (void)listener;
    return error_with(ENOTSUP);
#endif
}

static socklen_t make_address(startup_io_t *scratch, const uint8_t *id)
{
    memset(scratch, 0, sizeof(*scratch));
    scratch->address.sun_family = AF_UNIX;
    memcpy(scratch->address.sun_path + 1, "unmoor.startup.", 15U);
    /* The codec's terminating NUL is storage, excluded from address length. */
    (void)deaddrop_id_to_hex(id, scratch->address.sun_path + 16);
    return (socklen_t)(offsetof(struct sockaddr_un, sun_path) + NAME_BYTES);
}

int monitor_startup_parent_init(monitor_startup_t *o, const uint8_t id[16],
    pid_t child, uid_t uid, int stderr_expected, int64_t deadline, int64_t now)
{
    startup_io_t scratch;
    socklen_t length;
    if (fresh_owner(o, id, child, uid, stderr_expected, deadline, now) != 0)
        return -1;
    initialize(o, id, child, uid, stderr_expected, deadline, now, ROLE_P);
    o->phase = P_LISTEN;
    o->listener_fd = native_socket();
    if (o->listener_fd < 0)
        return startup_fail(o, errno);
    length = make_address(&scratch, o->id);
    if (bind(o->listener_fd, (struct sockaddr *)&scratch.address, length) != 0 ||
        listen(o->listener_fd, 1) != 0)
        return startup_fail(o, errno);
    return 0;
}

int monitor_startup_child_init(monitor_startup_t *o, const uint8_t id[16],
    pid_t parent, uid_t uid, int stderr_expected, int64_t deadline, int64_t now)
{
    if (fresh_owner(o, id, parent, uid, stderr_expected, deadline, now) != 0)
        return -1;
    initialize(o, id, parent, uid, stderr_expected, deadline, now, ROLE_C);
    o->phase = C_CONNECT;
    if (getppid() != parent)
        return startup_fail(o, ESRCH);
    return 0;
}

int monitor_startup_interest(const monitor_startup_t *o, monitor_startup_wait_t *w)
{
    if (owner_valid(o) != 0)
        return -1;
    if (!w)
        return error_with(EINVAL);
    memset(w, 0, sizeof(*w));
    w->fd = -1;
    w->wake_ms = o->deadline_ms;
    switch (o->phase) {
    case P_LISTEN: w->fd = o->listener_fd; w->events = POLLIN; break;
    case P_RX_READY: case P_RX_ACQUIRED:
    case C_RX_BUNDLE: case C_RX_COMMIT: case C_RX_EOF:
        w->fd = o->stream_fd; w->events = POLLIN; break;
    case P_TX_BUNDLE: case P_TX_COMMIT: case C_TX_READY: case C_TX_ACQUIRED:
        w->fd = o->stream_fd; w->events = POLLOUT; break;
    case C_CONNECT:
        w->wake_ms = o->next_connect_ms;
        w->immediate = (uint8_t)(o->last_now_ms >= o->next_connect_ms);
        break;
    case P_BUNDLE_ACTION: case C_VALIDATE_ACTION: case P_ACQUIRED_ACTION:
    case FINISHED: w->immediate = 1; break;
    default: return error_with(EPROTO);
    }
    return 0;
}

static void prepare_record(monitor_startup_t *o, uint8_t kind)
{
    o->tx[0] = 1;
    o->tx[1] = kind;
    o->tx[2] = kind == BUNDLE ? o->expected_n : 0;
    o->tx[3] = 0;
    memcpy(o->tx + 4, o->id, sizeof(o->id));
    o->tx_n = 0;
}

static monitor_startup_result_t initial_connect(monitor_startup_t *o, int64_t now)
{
    startup_io_t scratch;
    socklen_t length;
    int cause;
    if (now < o->next_connect_ms)
        return MONITOR_STARTUP_WAIT;
    o->stream_fd = native_socket();
    if (o->stream_fd < 0)
        return (monitor_startup_result_t)startup_fail(o, errno);
    length = make_address(&scratch, o->id);
    if (connect(o->stream_fd, (struct sockaddr *)&scratch.address, length) != 0) {
        cause = errno;
        if (cause != ECONNREFUSED)
            return (monitor_startup_result_t)startup_fail(o, cause);
        retire_slot(o, &o->stream_fd);
        if (o->cleanup_errno)
            return (monitor_startup_result_t)startup_fail(o, o->cleanup_errno);
        o->next_connect_ms = o->deadline_ms - now <= MONITOR_STARTUP_RETRY_MS ?
            o->deadline_ms : now + MONITOR_STARTUP_RETRY_MS;
        return MONITOR_STARTUP_WAIT;
    }
    if (monitor_peer_matches(o->stream_fd, o->expected_pid, o->expected_uid) != 0)
        return (monitor_startup_result_t)startup_fail(o, errno);
    prepare_record(o, READY);
    o->phase = C_TX_READY;
    return MONITOR_STARTUP_PROGRESS;
}

static monitor_startup_result_t initial_accept(monitor_startup_t *o)
{
    o->stream_fd = native_accept(o->listener_fd);
    if (o->stream_fd < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            return MONITOR_STARTUP_WAIT;
        return (monitor_startup_result_t)startup_fail(o, errno);
    }
    if (monitor_peer_matches(o->stream_fd, o->expected_pid, o->expected_uid) != 0)
        return (monitor_startup_result_t)startup_fail(o, errno);
    retire_slot(o, &o->listener_fd);
    if (o->cleanup_errno)
        return (monitor_startup_result_t)startup_fail(o, o->cleanup_errno);
    o->phase = P_RX_READY;
    return MONITOR_STARTUP_PROGRESS;
}

static monitor_startup_result_t send_record(monitor_startup_t *o)
{
    startup_io_t scratch;
    ssize_t sent;
    memset(&scratch, 0, sizeof(scratch));
    scratch.io.iov.iov_base = o->tx + o->tx_n;
    scratch.io.iov.iov_len = sizeof(o->tx) - o->tx_n;
    scratch.io.msg.msg_iov = &scratch.io.iov;
    scratch.io.msg.msg_iovlen = 1;
    if (o->phase == P_TX_BUNDLE && !(o->flags & RIGHTS_SENT)) {
        struct cmsghdr *cmsg;
        scratch.io.msg.msg_control = scratch.io.control.bytes;
        scratch.io.msg.msg_controllen = (socklen_t)CMSG_SPACE((unsigned)o->expected_n * sizeof(int));
        cmsg = CMSG_FIRSTHDR(&scratch.io.msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        /* Four/five rights fit the POSIX socklen_t member used by musl;
         * glibc widens that member to size_t. The fixed layout is gated above. */
        cmsg->cmsg_len = (socklen_t)CMSG_LEN((unsigned)o->expected_n * sizeof(int));
        for (unsigned i = 0; i < o->expected_n; ++i) {
            int fd = bundle_value(&o->bundle, i);
            memcpy(CMSG_DATA(cmsg) + i * sizeof(int), &fd, sizeof(fd));
        }
    }
    sent = sendmsg(o->stream_fd, &scratch.io.msg, MSG_NOSIGNAL);
    if (sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            return MONITOR_STARTUP_WAIT;
        return (monitor_startup_result_t)startup_fail(o, errno);
    }
    if (sent == 0 || (size_t)sent > sizeof(o->tx) - o->tx_n)
        return (monitor_startup_result_t)startup_fail(o, sent == 0 ? EPIPE : EPROTO);
    if (o->phase == P_TX_BUNDLE)
        o->flags |= RIGHTS_SENT;
    o->tx_n = (uint8_t)(o->tx_n + (size_t)sent);
    if (o->tx_n != sizeof(o->tx))
        return MONITOR_STARTUP_PROGRESS;
    o->rx_n = 0;
    switch (o->phase) {
    case C_TX_READY: o->phase = C_RX_BUNDLE; break;
    case P_TX_BUNDLE: o->phase = P_RX_ACQUIRED; break;
    case C_TX_ACQUIRED: o->phase = C_RX_COMMIT; break;
    case P_TX_COMMIT:
        retire_slot(o, &o->stream_fd);
        if (o->cleanup_errno)
            return (monitor_startup_result_t)startup_fail(o, o->cleanup_errno);
        o->phase = FINISHED;
        return MONITOR_STARTUP_DONE;
    default: return (monitor_startup_result_t)startup_fail(o, EPROTO);
    }
    return MONITOR_STARTUP_PROGRESS;
}

/* Control metadata is produced by the local kernel, not a peer-defined byte
 * grammar. Still check every length before indexing; retire every delivered
 * right, including the sixth int which fits Linux's five-right padding.
 * No rights outside the sole first BUNDLE read are retained. */
static int receive_rights(monitor_startup_t *o, struct msghdr *msg, ssize_t got)
{
    size_t offset = 0, length = msg->msg_controllen;
    unsigned count = 0, headers = 0;
    int allowed = o->phase == C_RX_BUNDLE && o->rx_n == 0 && got > 0;
    int bad = (msg->msg_flags & (MSG_CTRUNC | MSG_TRUNC)) != 0;

    if (length > CONTROL_BYTES) {
        length = CONTROL_BYTES;
        bad = 1;
    }
    while (length - offset >= sizeof(struct cmsghdr)) {
        struct cmsghdr *cmsg = (struct cmsghdr *)((unsigned char *)msg->msg_control + offset);
        size_t csize = cmsg->cmsg_len;
        size_t payload;
        ++headers;
        if (csize < CMSG_LEN(0) || csize > length - offset) {
            bad = 1;
            break;
        }
        payload = csize - CMSG_LEN(0);
        if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
            bad = 1;
        } else {
            if (payload % sizeof(int) != 0)
                bad = 1;
            for (size_t i = 0; i < payload / sizeof(int); ++i) {
                int fd;
                memcpy(&fd, CMSG_DATA(cmsg) + i * sizeof(int), sizeof(fd));
                ++count;
                if (fd < 0) {
                    bad = 1;
                } else if (allowed && o->received_n < 5U) {
                    *bundle_slot(&o->bundle, o->received_n) = fd;
                    o->owned_mask |= (uint8_t)(1U << o->received_n);
                    ++o->received_n;
                } else {
                    retire_value(o, fd);
                }
            }
        }
        /* CMSG_SPACE is the native alignment of this exact payload. */
        csize = CMSG_SPACE(payload);
        if (csize > length - offset) {
            break;
        }
        offset += csize;
    }
    if (length != 0 && headers == 0)
        bad = 1;
    if (allowed ? (headers != 1U || count != o->expected_n) : headers != 0U)
        bad = 1;
    if (bad)
        return startup_fail(o, EPROTO);
    if (o->cleanup_errno)
        return startup_fail(o, o->cleanup_errno);
    return 0;
}

static monitor_startup_result_t receive_record(monitor_startup_t *o)
{
    startup_io_t scratch;
    ssize_t got;
    int eof_probe = o->phase == C_RX_EOF;
    uint8_t expected;
    memset(&scratch, 0, sizeof(scratch));
    scratch.io.iov.iov_base = o->rx + (eof_probe ? 0 : o->rx_n);
    scratch.io.iov.iov_len = eof_probe ? 1U : sizeof(o->rx) - o->rx_n;
    scratch.io.msg.msg_iov = &scratch.io.iov;
    scratch.io.msg.msg_iovlen = 1;
    scratch.io.msg.msg_control = scratch.io.control.bytes;
    scratch.io.msg.msg_controllen = sizeof(scratch.io.control.bytes);
    got = recvmsg(o->stream_fd, &scratch.io.msg, STARTUP_RECV_FLAGS);
    if (got < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            return MONITOR_STARTUP_WAIT;
        return (monitor_startup_result_t)startup_fail(o, errno);
    }
    if (receive_rights(o, &scratch.io.msg, got) != 0)
        return MONITOR_STARTUP_ERROR;
    if (got == 0) {
        if (!eof_probe)
            return (monitor_startup_result_t)startup_fail(o, EPIPE);
        retire_slot(o, &o->stream_fd);
        if (o->cleanup_errno)
            return (monitor_startup_result_t)startup_fail(o, o->cleanup_errno);
        o->phase = FINISHED;
        return MONITOR_STARTUP_DONE;
    }
    if (eof_probe || (size_t)got > sizeof(o->rx) - o->rx_n)
        return (monitor_startup_result_t)startup_fail(o, EPROTO);
    o->rx_n = (uint8_t)(o->rx_n + (size_t)got);
    if (o->rx_n != sizeof(o->rx))
        return MONITOR_STARTUP_PROGRESS;
    expected = o->phase == P_RX_READY ? READY :
               o->phase == C_RX_BUNDLE ? BUNDLE :
               o->phase == P_RX_ACQUIRED ? ACQUIRED : COMMIT;
    if (o->rx[0] != 1 || o->rx[1] != expected || o->rx[3] != 0 ||
        o->rx[2] != (expected == BUNDLE ? o->expected_n : 0) ||
        memcmp(o->rx + 4, o->id, sizeof(o->id)) != 0)
        return (monitor_startup_result_t)startup_fail(o, EPROTO);
    o->rx_n = 0;
    switch (o->phase) {
    case P_RX_READY: o->phase = P_BUNDLE_ACTION; return MONITOR_STARTUP_P_BUNDLE;
    case C_RX_BUNDLE: o->phase = C_VALIDATE_ACTION; return MONITOR_STARTUP_C_VALIDATE;
    case P_RX_ACQUIRED: o->phase = P_ACQUIRED_ACTION; return MONITOR_STARTUP_P_ACQUIRED;
    case C_RX_COMMIT: o->phase = C_RX_EOF; return MONITOR_STARTUP_PROGRESS;
    default: return (monitor_startup_result_t)startup_fail(o, EPROTO);
    }
}

monitor_startup_result_t monitor_startup_step(monitor_startup_t *o, int64_t now)
{
    if (time_valid(o, now) != 0)
        return MONITOR_STARTUP_ERROR;
    switch (o->phase) {
    case P_LISTEN: return initial_accept(o);
    case C_CONNECT: return initial_connect(o, now);
    case C_TX_READY: case P_TX_BUNDLE: case C_TX_ACQUIRED: case P_TX_COMMIT:
        return send_record(o);
    case P_RX_READY: case C_RX_BUNDLE: case P_RX_ACQUIRED:
    case C_RX_COMMIT: case C_RX_EOF: return receive_record(o);
    case P_BUNDLE_ACTION: return MONITOR_STARTUP_P_BUNDLE;
    case C_VALIDATE_ACTION: return MONITOR_STARTUP_C_VALIDATE;
    case P_ACQUIRED_ACTION: return MONITOR_STARTUP_P_ACQUIRED;
    case FINISHED: return MONITOR_STARTUP_DONE;
    default: return (monitor_startup_result_t)startup_fail(o, EPROTO);
    }
}

int monitor_startup_parent_offer(monitor_startup_t *o,
    const monitor_startup_bundle_t *b, int64_t now)
{
    if (owner_valid(o) != 0)
        return -1;
    if (!b || now < 0)
        return error_with(EINVAL);
    for (unsigned i = 0; i < o->expected_n; ++i) {
        int fd = bundle_value(b, i);
        if (fd < 0 || fd == o->listener_fd || fd == o->stream_fd)
            return error_with(EINVAL);
        for (unsigned j = 0; j < i; ++j) {
            if (fd == bundle_value(b, j))
                return error_with(EINVAL);
        }
    }
    if (o->expected_n == 4 && b->stderr_fd != -1)
        return error_with(EINVAL);
    if (time_valid(o, now) != 0)
        return -1;
    if (o->role != ROLE_P || o->phase != P_BUNDLE_ACTION)
        return startup_fail(o, EPROTO);
    o->bundle = *b;
    prepare_record(o, BUNDLE);
    o->phase = P_TX_BUNDLE;
    return 0;
}

static int cloexec_valid(int fd)
{
    int flags = fcntl(fd, F_GETFD);
    if (flags < 0)
        return -1;
    return (flags & FD_CLOEXEC) != 0 ? 0 : error_with(EPERM);
}

static int access_valid(int fd, int wanted)
{
    int flags;
    if (cloexec_valid(fd) != 0)
        return -1;
    flags = fcntl(fd, F_GETFL);
    if (flags < 0)
        return -1;
#ifdef O_PATH
    if ((flags & O_PATH) != 0)
        return error_with(EPERM);
#endif
    return (flags & O_ACCMODE) == wanted ? 0 : error_with(EPERM);
}

static int directory_valid(const struct stat *st)
{
    return S_ISDIR(st->st_mode) && st->st_uid == geteuid() &&
           (st->st_mode & 07777) == 0700 ? 0 : error_with(EPERM);
}

static int validate_bundle(const monitor_startup_t *o)
{
    startup_validation_t v;
    const monitor_startup_bundle_t *b = &o->bundle;
    if (access_valid(b->parent_fd, O_RDONLY) != 0 ||
        unmoor_fd_stat(b->parent_fd, &v.st) != 0 || directory_valid(&v.st) != 0 ||
        access_valid(b->attempt_fd, O_RDONLY) != 0 ||
        unmoor_fd_stat(b->attempt_fd, &v.st) != 0 || directory_valid(&v.st) != 0)
        return -1;
    v.device = v.st.st_dev;
    v.inode = v.st.st_ino;
    (void)deaddrop_id_to_hex(o->id, v.name);
    if (fstatat(b->parent_fd, v.name, &v.st, AT_SYMLINK_NOFOLLOW) != 0 ||
        directory_valid(&v.st) != 0)
        return -1;
    if (v.device != v.st.st_dev || v.inode != v.st.st_ino)
        return error_with(EPERM);
    if (access_valid(b->status_write_fd, O_WRONLY) != 0 ||
        unmoor_fd_stat(b->status_write_fd, &v.st) != 0)
        return -1;
    if (!S_ISFIFO(v.st.st_mode))
        return error_with(EPERM);
    v.device = v.st.st_dev;
    v.inode = v.st.st_ino;
    if (access_valid(b->control_read_fd, O_RDONLY) != 0 ||
        unmoor_fd_stat(b->control_read_fd, &v.st) != 0)
        return -1;
    if (!S_ISFIFO(v.st.st_mode) ||
        (v.device == v.st.st_dev && v.inode == v.st.st_ino))
        return error_with(EPERM);
    if (o->expected_n == 5 && cloexec_valid(b->stderr_fd) != 0)
        return -1;
    return 0;
}

int monitor_startup_child_approve(monitor_startup_t *o, int64_t now)
{
    if (time_valid(o, now) != 0)
        return -1;
    if (o->role != ROLE_C || o->phase != C_VALIDATE_ACTION)
        return startup_fail(o, EPROTO);
    if (validate_bundle(o) != 0)
        return startup_fail(o, errno);
    prepare_record(o, ACQUIRED);
    o->phase = C_TX_ACQUIRED;
    return 0;
}

int monitor_startup_parent_commit(monitor_startup_t *o, int64_t now)
{
    if (time_valid(o, now) != 0)
        return -1;
    if (o->role != ROLE_P || o->phase != P_ACQUIRED_ACTION)
        return startup_fail(o, EPROTO);
    /* The trusted caller has retired its pipe aliases. Their stale numbers
     * are deliberately not inspected, validated or closed here. */
    prepare_record(o, COMMIT);
    o->phase = P_TX_COMMIT;
    return 0;
}

int monitor_startup_child_take(monitor_startup_t *o, monitor_startup_bundle_t *b)
{
    uintptr_t owner, out;
    if (owner_valid(o) != 0)
        return -1;
    if (!b)
        return error_with(EINVAL);
    owner = (uintptr_t)o;
    out = (uintptr_t)b;
    if (owner <= out ? out - owner < sizeof(*o) : owner - out < sizeof(*b))
        return error_with(EINVAL);
    if ((o->flags & TAKEN) != 0)
        return error_with(EALREADY);
    for (unsigned i = 0; i < 5U; ++i) {
        if (bundle_value(b, i) != -1)
            return error_with(EINVAL);
    }
    if (o->role != ROLE_C || o->phase != FINISHED)
        return startup_fail(o, EPROTO);
    *b = o->bundle;
    o->owned_mask = 0;
    empty_bundle(&o->bundle);
    o->flags |= TAKEN;
    return 0;
}

int monitor_startup_abort(monitor_startup_t *o, int cause)
{
    if (!o || (o->role != ROLE_P && o->role != ROLE_C) || cause <= 0)
        return error_with(EINVAL);
    return startup_fail(o, cause);
}

int monitor_startup_dispose(monitor_startup_t *o)
{
    if (!o)
        return error_with(EINVAL);
    if (!o->role && !o->phase)
        return 0; /* Fresh storage has no descriptor custody, even fd zero. */
    if (o->role != ROLE_P && o->role != ROLE_C)
        return error_with(EINVAL);
    if (o->phase != FINISHED || (o->role == ROLE_C && !(o->flags & TAKEN)))
        (void)startup_fail(o, ECANCELED);
    else
        retire_owned(o);
    return o->cleanup_errno ? error_with(o->cleanup_errno) : 0;
}
