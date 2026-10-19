/*
 * transport_unix.c — UNIX domain socket transport
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * Listen mode:  unlink if exists, bind, listen, accept one connection.
 * Connect mode: socket + connect with retry on ECONNREFUSED for up to 1s.
 *
 * Framing: each send writes a 2-byte LE length prefix followed by the bytes.
 *          recv reads one length-prefixed frame and returns the body.
 *          This length prefix is transport framing only; the bytes inside
 *          it are one complete Unmoor frame, with nothing wrapped around it.
 */

#if defined(__APPLE__)
#define _DARWIN_C_SOURCE
#else
#define _GNU_SOURCE
#endif
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>

#include "transport.h"
#include "frame.h" /* FRAME_MAX_LEN */

/* -------------------------------------------------------------------------
 * Internal state
 * ---------------------------------------------------------------------- */

typedef struct {
    transport_t     base;       /* must be first */
    int             fd;         /* connected socket fd */
    int             listen_fd;  /* listener fd (only if listen mode) */
    char            path[108];  /* saved path for unlink on close */
    int             is_listener;
    int             send_epipe_logged;
    transport_stream_tx_t tx;
    transport_stats_t stats;
} transport_unix_t;

/* The listener hands the session to exactly one peer, and that peer must be
 * this user. The 0600 inode is the first line; the credential check holds
 * when a directory race or a lenient platform default gets past it. */
static int unix_peer_is_same_user(int fd)
{
#if defined(__linux__) && defined(SO_PEERCRED)
    struct ucred peer;
    socklen_t length = sizeof(peer);

    memset(&peer, 0, sizeof(peer));
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &length) != 0 ||
        length != sizeof(peer))
        return 0;
    return peer.uid == geteuid();
#else
    uid_t uid = (uid_t)-1;
    gid_t gid = (gid_t)-1;

    if (getpeereid(fd, &uid, &gid) != 0)
        return 0;
    return uid == geteuid();
#endif
}

static void unix_log_send_failure(transport_unix_t *t, int error)
{
    if (error == EPIPE) {
        if (t->send_epipe_logged)
            return;
        t->send_epipe_logged = 1;
    }
    fprintf(stderr, "transport_unix: send failed: %s\n", strerror(error));
}

static ssize_t unix_write_step(void *ctx, const uint8_t *buf, size_t len)
{
    transport_unix_t *t = ctx;
    int flags = 0;
#ifdef MSG_NOSIGNAL
    flags |= MSG_NOSIGNAL;
#endif
    return send(t->fd, buf, len, flags);
}

static int unix_arm_nonblocking(transport_unix_t *t)
{
    int flags = fcntl(t->fd, F_GETFL);
    if (flags < 0 || fcntl(t->fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        fprintf(stderr,
                "transport_unix: cannot arm nonblocking socket: %s\n",
                strerror(errno));
        return -1;
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * Write all bytes (retry on EINTR/partial write)
 * ---------------------------------------------------------------------- */

static int write_all(int fd, const uint8_t *buf, size_t len)
{
    size_t written = 0;
    while (written < len) {
        ssize_t n = write(fd, buf + written, len - written);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        written += (size_t)n;
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * Read exactly N bytes (retry on EINTR/partial read)
 * Returns 0 on success, -1 on EOF or error.
 * ---------------------------------------------------------------------- */

/* Compute remaining ms against a CLOCK_MONOTONIC deadline instead of
 * mutating the caller-provided timeout value. */
static int ts_remaining_ms(const struct timespec *deadline)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    int64_t rem = (int64_t)(deadline->tv_sec - now.tv_sec) * 1000
                + (int64_t)(deadline->tv_nsec - now.tv_nsec) / 1000000;
    if (rem < 0) rem = 0;
    if (rem > 2147483647) rem = 2147483647;
    return (int)rem;
}

/* Returns 0 on success, -1 on timeout, -2 on EOF/hangup, -3 on other error. */
static int read_exact(int fd, uint8_t *buf, size_t len, int timeout_ms)
{
    struct timespec deadline;
    int use_deadline = (timeout_ms >= 0);
    if (use_deadline) {
        clock_gettime(CLOCK_MONOTONIC, &deadline);
        deadline.tv_sec  += timeout_ms / 1000;
        deadline.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
        if (deadline.tv_nsec >= 1000000000L) {
            deadline.tv_sec++;
            deadline.tv_nsec -= 1000000000L;
        }
    }
    size_t got = 0;
    while (got < len) {
        int this_to = use_deadline ? ts_remaining_ms(&deadline) : -1;
        if (use_deadline && this_to == 0 && got < len) return -1; /* timeout */
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int r = poll(&pfd, 1, this_to);
        if (r < 0 && errno == EINTR) continue;
        if (r < 0) return -3;
        if (r == 0) return -1; /* timeout */
        /* A bare POLLHUP with no POLLIN means the peer closed and we
         * have no more bytes to read. Treat as EOF so session_run can tear
         * down immediately rather than spinning. */
        if ((pfd.revents & POLLHUP) && !(pfd.revents & POLLIN)) {
            return -2;
        }
        if (pfd.revents & (POLLERR | POLLNVAL)) return -3;
        ssize_t n = read(fd, buf + got, len - got);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            return -3;
        }
        if (n == 0) return -2; /* EOF */
        got += (size_t)n;
    }
    return 0;
}

/* Drain N bytes from the socket into a scratch buffer (used when we need
 * to discard an oversized frame body to preserve framing alignment).
 *
 * timeout_ms is a *wall* budget across
 * the entire drain, not a per-chunk timeout. Compute the deadline once and
 * recompute the remaining slice each loop iteration. The previous version
 * passed timeout_ms to each read_exact call so a slowloris peer dribbling
 * 1 byte every (timeout_ms - 1) ms could hold the loop for
 * ceil(N/1) * timeout_ms total — defeating the fix's stated bound. */
static int drain_bytes(int fd, size_t count, int timeout_ms)
{
    uint8_t scratch[256];
    struct timespec deadline;
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec  += timeout_ms / 1000;
    deadline.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec++;
        deadline.tv_nsec -= 1000000000L;
    }
    while (count > 0) {
        size_t chunk = count > sizeof(scratch) ? sizeof(scratch) : count;
        int rem = ts_remaining_ms(&deadline);
        if (rem == 0) return -1;
        if (read_exact(fd, scratch, chunk, rem) < 0) return -1;
        count -= chunk;
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * open
 * ---------------------------------------------------------------------- */

static int unix_open(const transport_config_t *cfg, transport_t **out)
{
    if (!cfg || !cfg->path) {
        fprintf(stderr, "transport_unix: path required\n");
        return -1;
    }

    transport_unix_t *t = calloc(1, sizeof(*t));
    if (!t) {
        fprintf(stderr, "transport_unix: calloc failed\n");
        return -1;
    }
    t->base.ops = &transport_unix;
    t->fd = -1;
    t->listen_fd = -1;
    {
        struct sockaddr_un probe;
        size_t path_len = strlen(cfg->path);

        if (path_len >= sizeof(probe.sun_path) ||
            path_len >= sizeof(t->path)) {
            fprintf(stderr, "transport_unix: path too long: %s\n",
                    cfg->path);
            free(t);
            return -1;
        }
    }
    snprintf(t->path, sizeof(t->path), "%s", cfg->path);

    if (cfg->listen) {
        struct stat existing;
        mode_t previous_umask;
        int bind_rc;
        int bind_error;

        /* Listener mode */
        t->is_listener = 1;

        /* Replace only a stale socket of our own. A regular file, a
         * directory or a symlink at the path is left alone. */
        if (lstat(cfg->path, &existing) == 0) {
            if (!S_ISSOCK(existing.st_mode) ||
                existing.st_uid != geteuid()) {
                fprintf(stderr,
                        "transport_unix: %s exists and is not our socket\n",
                        cfg->path);
                free(t);
                return -1;
            }
            (void)unlink(cfg->path);
        } else if (errno != ENOENT) {
            fprintf(stderr, "transport_unix: lstat(%s): %s\n", cfg->path,
                    strerror(errno));
            free(t);
            return -1;
        }

        t->listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (t->listen_fd < 0) {
            fprintf(stderr, "transport_unix: socket: %s\n", strerror(errno));
            free(t);
            return -1;
        }

        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", cfg->path);

        /* The inode is born 0600; the chmod below only confirms it. */
        previous_umask = umask(0077);
        bind_rc = bind(t->listen_fd, (struct sockaddr *)&addr, sizeof(addr));
        bind_error = errno;
        (void)umask(previous_umask);
        if (bind_rc != 0) {
            fprintf(stderr, "transport_unix: bind(%s): %s\n", cfg->path,
                    strerror(bind_error));
            close(t->listen_fd);
            free(t);
            return -1;
        }

        /* Chmod the filesystem inode, not the fd. */
        if (chmod(cfg->path, 0600) != 0) {
            fprintf(stderr, "transport_unix: chmod(%s, 0600): %s\n",
                    cfg->path, strerror(errno));
            close(t->listen_fd);
            unlink(cfg->path);
            free(t);
            return -1;
        }

        if (listen(t->listen_fd, 1) != 0) {
            fprintf(stderr, "transport_unix: listen: %s\n", strerror(errno));
            close(t->listen_fd);
            unlink(cfg->path);
            free(t);
            return -1;
        }

        fprintf(stderr, "transport_unix: listening on %s\n", cfg->path);

        /* Accept one connection (blocking) */
        t->fd = accept(t->listen_fd, NULL, NULL);
        if (t->fd < 0) {
            fprintf(stderr, "transport_unix: accept: %s\n", strerror(errno));
            close(t->listen_fd);
            unlink(cfg->path);
            free(t);
            return -1;
        }
        if (!unix_peer_is_same_user(t->fd)) {
            fprintf(stderr,
                    "transport_unix: rejecting a connection from another "
                    "user\n");
            close(t->fd);
            close(t->listen_fd);
            unlink(cfg->path);
            free(t);
            return -1;
        }
        /* FD_CLOEXEC on both listener and connected fd. */
        (void)fcntl(t->listen_fd, F_SETFD, FD_CLOEXEC);
        (void)fcntl(t->fd,        F_SETFD, FD_CLOEXEC);
        if (unix_arm_nonblocking(t) != 0) {
            close(t->fd);
            close(t->listen_fd);
            unlink(cfg->path);
            free(t);
            return -1;
        }
#ifdef SO_NOSIGPIPE
        {
            int one = 1;
            (void)setsockopt(t->fd, SOL_SOCKET, SO_NOSIGPIPE,
                             &one, sizeof(one));
        }
#endif
        fprintf(stderr, "transport_unix: accepted connection\n");

    } else {
        /* Connect mode with retry on ECONNREFUSED for up to 1s */
        t->fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (t->fd < 0) {
            fprintf(stderr, "transport_unix: socket: %s\n", strerror(errno));
            free(t);
            return -1;
        }

        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", cfg->path);

        struct timespec deadline, now;
        clock_gettime(CLOCK_MONOTONIC, &deadline);
        deadline.tv_sec += 1; /* 1s retry window */

        int connected = 0;
        while (!connected) {
            if (connect(t->fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
                connected = 1;
            } else if (errno == ECONNREFUSED) {
                clock_gettime(CLOCK_MONOTONIC, &now);
                if (now.tv_sec > deadline.tv_sec ||
                    (now.tv_sec == deadline.tv_sec && now.tv_nsec >= deadline.tv_nsec)) {
                    fprintf(stderr, "transport_unix: connect(%s): timed out\n", cfg->path);
                    close(t->fd);
                    free(t);
                    return -1;
                }
                struct timespec ts = { .tv_sec = 0, .tv_nsec = 50000000 }; /* 50ms */
                nanosleep(&ts, NULL);
            } else {
                fprintf(stderr, "transport_unix: connect(%s): %s\n", cfg->path, strerror(errno));
                close(t->fd);
                free(t);
                return -1;
            }
        }
        /* FD_CLOEXEC. */
        (void)fcntl(t->fd, F_SETFD, FD_CLOEXEC);
        if (unix_arm_nonblocking(t) != 0) {
            close(t->fd);
            free(t);
            return -1;
        }
#ifdef SO_NOSIGPIPE
        {
            int one = 1;
            (void)setsockopt(t->fd, SOL_SOCKET, SO_NOSIGPIPE,
                             &one, sizeof(one));
        }
#endif
        fprintf(stderr, "transport_unix: connected to %s\n", cfg->path);
    }

    *out = &t->base;
    return 0;
}

/* -------------------------------------------------------------------------
 * send: 2-byte LE length prefix + body
 * ---------------------------------------------------------------------- */

static int unix_send(transport_t *base, const uint8_t *data, size_t len)
{
    transport_unix_t *t = (transport_unix_t *)base;
    if (len > 0xFFFF) {
        fprintf(stderr, "transport_unix: send: frame too large (%zu)\n", len);
        return -1;
    }
    uint8_t hdr[2];
    hdr[0] = (uint8_t)(len & 0xFF);
    hdr[1] = (uint8_t)((len >> 8) & 0xFF);

    if (write_all(t->fd, hdr, 2) != 0 ||
        write_all(t->fd, data, len) != 0) {
        int saved_errno = errno;

        unix_log_send_failure(t, saved_errno);
        t->stats.tx_fail++;
        errno = saved_errno;
        return -1;
    }
    t->stats.tx_ok++;
    t->stats.tx_bytes += (uint64_t)len;
    return 0;
}

static int unix_send_step(transport_t *base,
                          const uint8_t *data, size_t len)
{
    transport_unix_t *t = (transport_unix_t *)base;
    int rc = transport_stream_tx_step(&t->tx, data, len,
                                      unix_write_step, t);
    if (rc == TRANSPORT_SEND_COMPLETE) {
        t->stats.tx_ok++;
        t->stats.tx_bytes += (uint64_t)len;
    } else if (rc == TRANSPORT_SEND_FAILED) {
        int saved_errno = errno;

        if (saved_errno == EPIPE)
            unix_log_send_failure(t, saved_errno);
        t->stats.tx_fail++;
        errno = saved_errno;
    }
    return rc;
}

static int unix_send_cancel_untouched(transport_t *base)
{
    transport_unix_t *t = (transport_unix_t *)base;
    return transport_stream_tx_cancel_untouched(&t->tx);
}

/* -------------------------------------------------------------------------
 * recv: read 2-byte LE length, then body
 * Returns body length on success, -1 on error/timeout.
 * ---------------------------------------------------------------------- */

static int unix_recv(transport_t *base, uint8_t *buf, size_t max, int timeout_ms)
{
    transport_unix_t *t = (transport_unix_t *)base;

    uint8_t hdr[2];
    int rr = read_exact(t->fd, hdr, 2, timeout_ms);
    if (rr == -2) {
        /* Peer closed the socket. Signal hangup via errno=EPIPE so
         * session_run's recv-error check fires and triggers teardown. */
        errno = EPIPE;
        return -1;
    }
    if (rr < 0) return -1;

    size_t body_len = (size_t)hdr[0] | ((size_t)hdr[1] << 8);
    /* Cap body_len at FRAME_MAX_LEN and the caller's max.
     * If oversized, drain the bytes from the socket before returning so we
     * don't leave the stream mid-frame (framing corruption). */
    if (body_len > max || body_len > FRAME_MAX_LEN) {
        fprintf(stderr, "transport_unix: recv: frame %zu > max %zu (or > FRAME_MAX_LEN %u) — draining\n",
                body_len, max, (unsigned)FRAME_MAX_LEN);
        /* Bound drain at 100 ms (was 5000 ms — DoS amplifier). On
         * stall, close the transport so the session unwinds via EPIPE. */
        if (drain_bytes(t->fd, body_len, 100) < 0) {
            errno = EPIPE;
        }
        t->stats.rx_drop++;
        return -1;
    }
    /* bound legitimate body read at 1000 ms.
     * UNIX-socket peers are local and a 510-byte body needs sub-millisecond
     * actual time; 1 s is forgiving but still rules out a slowloris-style
     * stall on a valid length header. Treat stall as EPIPE so session_run
     * tears down cleanly. */
    rr = read_exact(t->fd, buf, body_len, 1000);
    if (rr == -2) {
        errno = EPIPE;
        return -1;
    }
    if (rr < 0) {
        fprintf(stderr, "transport_unix: recv body: %s\n", strerror(errno));
        errno = EPIPE;
        return -1;
    }
    t->stats.rx_ok++;
    t->stats.rx_bytes += (uint64_t)body_len;
    return (int)body_len;
}

/* -------------------------------------------------------------------------
 * close
 * ---------------------------------------------------------------------- */

static void unix_close(transport_t *base)
{
    transport_unix_t *t = (transport_unix_t *)base;
    if (t->fd >= 0) {
        shutdown(t->fd, SHUT_RDWR);
        close(t->fd);
        t->fd = -1;
    }
    if (t->listen_fd >= 0) {
        close(t->listen_fd);
        t->listen_fd = -1;
    }
    if (t->is_listener && t->path[0])
        unlink(t->path);
    free(t);
}

/* -------------------------------------------------------------------------
 * stats
 * ---------------------------------------------------------------------- */

static int unix_stats(transport_t *base, transport_stats_t *out)
{
    transport_unix_t *t = (transport_unix_t *)base;
    *out = t->stats;
    out->rssi_last = INT16_MIN;    /* UNIX socket has no RSSI */
    out->snr_last  = INT8_MIN;
    out->transport_id = 0;
    return 0;
}

/* -------------------------------------------------------------------------
 * Export
 * ---------------------------------------------------------------------- */

static int unix_get_fd(transport_t *base)
{
    transport_unix_t *t = (transport_unix_t *)base;
    return t->fd;
}

const transport_ops_t transport_unix = {
    .name  = "unix",
    .open  = unix_open,
    .send  = unix_send,
    .send_step = unix_send_step,
    .send_cancel_untouched = unix_send_cancel_untouched,
    .recv  = unix_recv,
    .close = unix_close,
    .stats = unix_stats,
    .get_fd = unix_get_fd,
    .get_send_fd = unix_get_fd,
};
