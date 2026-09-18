/*
 * transport_stdio.c — stdio / pipe transport
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * If cfg->exec is NULL: use fd 0/1 directly (stdin/stdout).
 * If cfg->exec is set: fork() + execvp(argv[0], argv) with a socketpair(AF_UNIX),
 * keeping the parent end. exec is split on spaces into argv[].
 *
 * Framing: same 2-byte LE length prefix as transport_unix.c. The prefix is
 * transport framing only; the bytes inside it are one complete Unmoor frame,
 * with nothing wrapped around it.
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>

#include "transport.h"
#include "frame.h" /* FRAME_MAX_LEN */
#include "process_hygiene.h"

/* -------------------------------------------------------------------------
 * Internal state
 * ---------------------------------------------------------------------- */

typedef struct {
    transport_t      base;
    int              read_fd;
    int              write_fd;
    int              write_flags;
    int              write_flags_valid;
    pid_t            child_pid;    /* -1 if no child */
    int              send_epipe_logged;
    transport_stream_tx_t tx;
    transport_stats_t stats;
} transport_stdio_t;

static void stdio_close(transport_t *base);

static void stdio_log_send_failure(transport_stdio_t *t, int error)
{
    if (error == EPIPE) {
        if (t->send_epipe_logged)
            return;
        t->send_epipe_logged = 1;
    }
    fprintf(stderr, "transport_stdio: send failed: %s\n", strerror(error));
}

static ssize_t stdio_write_step(void *ctx, const uint8_t *buf, size_t len)
{
    transport_stdio_t *t = ctx;
    return write(t->write_fd, buf, len);
}

/* -------------------------------------------------------------------------
 * Write all bytes
 * ---------------------------------------------------------------------- */

static int stdio_write_all(int fd, const uint8_t *buf, size_t len)
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
 * Read exactly N bytes
 * ---------------------------------------------------------------------- */

/* wall-clock deadline so the total budget is bounded.
 * Mirrors transport_unix.c:read_exact. The previous version reset
 * timeout_ms after every byte received, letting a hostile peer dribble
 * one byte every 4.9 s and stall the call indefinitely. */
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

static int stdio_read_exact(int fd, uint8_t *buf, size_t len, int timeout_ms)
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
        if (use_deadline && this_to == 0)
            return -1; /* total budget exhausted */
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int r = poll(&pfd, 1, this_to);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return -1;
        ssize_t n = read(fd, buf + got, len - got);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            return -1;
        }
        if (n == 0) return -1; /* EOF */
        got += (size_t)n;
    }
    return 0;
}

/* Drain N bytes to discard an oversized frame body (preserves framing).
 * One wall-clock deadline covers the entire drain, matching
 * transport_unix.c:drain_bytes. */
static int stdio_drain(int fd, size_t count, int budget_ms)
{
    struct timespec deadline;
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec  += budget_ms / 1000;
    deadline.tv_nsec += (long)(budget_ms % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec++;
        deadline.tv_nsec -= 1000000000L;
    }

    uint8_t scratch[256];
    while (count > 0) {
        int remaining = ts_remaining_ms(&deadline);
        if (remaining <= 0) return -1;
        size_t chunk = count > sizeof(scratch) ? sizeof(scratch) : count;
        if (stdio_read_exact(fd, scratch, chunk, remaining) != 0) return -1;
        count -= chunk;
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * Split exec string on spaces → argv[]
 * Caller must free argv and argv[0] ptr block.
 * ---------------------------------------------------------------------- */

/* Caller receives the strdup'd base pointer in *out_copy_base so it
 * can free it safely, independent of where argv[0] ends up pointing. */
static char **split_exec(const char *exec_str, int *argc_out, char **out_copy_base)
{
    *out_copy_base = NULL;
    /* Count tokens */
    int count = 0;
    const char *p = exec_str;
    while (*p) {
        while (*p == ' ') p++;
        if (*p) {
            count++;
            while (*p && *p != ' ') p++;
        }
    }
    if (count == 0) return NULL;

    char **argv = calloc((size_t)(count + 1), sizeof(char *));
    if (!argv) return NULL;

    char *copy = strdup(exec_str);
    if (!copy) { free(argv); return NULL; }
    *out_copy_base = copy;

    int i = 0;
    char *tok = strtok(copy, " ");
    while (tok && i < count) {
        argv[i++] = tok;
        tok = strtok(NULL, " ");
    }
    argv[i] = NULL;
    *argc_out = i;
    return argv;
}

/* -------------------------------------------------------------------------
 * open
 * ---------------------------------------------------------------------- */

static int stdio_open(const transport_config_t *cfg, transport_t **out)
{
    transport_stdio_t *t = calloc(1, sizeof(*t));
    if (!t) {
        fprintf(stderr, "transport_stdio: calloc failed\n");
        return -1;
    }
    t->base.ops = &transport_stdio;
    t->child_pid = -1;

    if (!cfg || !cfg->exec) {
        /* Use stdin/stdout directly */
        t->read_fd  = STDIN_FILENO;
        t->write_fd = STDOUT_FILENO;
        fprintf(stderr, "transport_stdio: using stdin/stdout\n");
    } else {
        /* Fork + execvp with socketpair */
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
            fprintf(stderr, "transport_stdio: socketpair: %s\n", strerror(errno));
            free(t);
            return -1;
        }

        int argc = 0;
        char *argv_copy_base = NULL;
        char **argv = split_exec(cfg->exec, &argc, &argv_copy_base);
        if (!argv || argc == 0) {
            fprintf(stderr, "transport_stdio: failed to parse exec: %s\n", cfg->exec);
            close(sv[0]); close(sv[1]);
            free(argv_copy_base);
            free(argv);
            free(t);
            return -1;
        }

        pid_t pid = fork();
        if (pid < 0) {
            fprintf(stderr, "transport_stdio: fork: %s\n", strerror(errno));
            close(sv[0]); close(sv[1]);
            /* Free the strdup'd copy base pointer explicitly. */
            free(argv_copy_base);
            free(argv);
            free(t);
            return -1;
        }

        if (pid == 0) {
            /* Child: close parent end, map child end to stdin/stdout */
            process_reset_child_signals();
            close(sv[0]);
            if (dup2(sv[1], STDIN_FILENO) < 0 ||
                dup2(sv[1], STDOUT_FILENO) < 0) {
                _exit(127);
            }
            if (sv[1] != STDIN_FILENO && sv[1] != STDOUT_FILENO)
                close(sv[1]);
            if (process_close_from(STDERR_FILENO + 1, NULL, 0U) != 0)
                _exit(127);
            execvp(argv[0], argv);
            /* execvp failed */
            fprintf(stderr, "transport_stdio: execvp(%s): %s\n",
                    argv[0], strerror(errno));
            _exit(127);
        }

        /* Parent: close child end.
         * NOTE: read_fd == write_fd == sv[0]; stdio_close must only close once. */
        close(sv[1]);
        t->read_fd   = sv[0];
        t->write_fd  = sv[0];
        t->child_pid = pid;

        /* Free the strdup'd copy base pointer explicitly. */
        free(argv_copy_base);
        free(argv);

        fprintf(stderr, "transport_stdio: forked exec, child pid %d\n", (int)pid);
    }

    t->write_flags = fcntl(t->write_fd, F_GETFL);
    if (t->write_flags < 0 ||
        fcntl(t->write_fd, F_SETFL, t->write_flags | O_NONBLOCK) != 0) {
        fprintf(stderr,
                "transport_stdio: cannot arm nonblocking output: %s\n",
                strerror(errno));
        stdio_close(&t->base);
        return -1;
    }
    t->write_flags_valid = 1;

    *out = &t->base;
    return 0;
}

/* -------------------------------------------------------------------------
 * send: 2-byte LE length prefix + body
 * ---------------------------------------------------------------------- */

static int stdio_send(transport_t *base, const uint8_t *data, size_t len)
{
    transport_stdio_t *t = (transport_stdio_t *)base;
    if (len > 0xFFFF) {
        fprintf(stderr, "transport_stdio: send: frame too large (%zu)\n", len);
        return -1;
    }
    uint8_t hdr[2];
    hdr[0] = (uint8_t)(len & 0xFF);
    hdr[1] = (uint8_t)((len >> 8) & 0xFF);

    if (stdio_write_all(t->write_fd, hdr, 2) != 0 ||
        stdio_write_all(t->write_fd, data, len) != 0) {
        int saved_errno = errno;

        stdio_log_send_failure(t, saved_errno);
        t->stats.tx_fail++;
        errno = saved_errno;
        return -1;
    }
    t->stats.tx_ok++;
    t->stats.tx_bytes += (uint64_t)len;
    return 0;
}

static int stdio_send_step(transport_t *base,
                           const uint8_t *data, size_t len)
{
    transport_stdio_t *t = (transport_stdio_t *)base;
    int rc = transport_stream_tx_step(&t->tx, data, len,
                                      stdio_write_step, t);
    if (rc == TRANSPORT_SEND_COMPLETE) {
        t->stats.tx_ok++;
        t->stats.tx_bytes += (uint64_t)len;
    } else if (rc == TRANSPORT_SEND_FAILED) {
        int saved_errno = errno;

        if (saved_errno == EPIPE)
            stdio_log_send_failure(t, saved_errno);
        t->stats.tx_fail++;
        errno = saved_errno;
    }
    return rc;
}

static int stdio_send_cancel_untouched(transport_t *base)
{
    transport_stdio_t *t = (transport_stdio_t *)base;
    return transport_stream_tx_cancel_untouched(&t->tx);
}

/* -------------------------------------------------------------------------
 * recv: read 2-byte LE length, then body
 * ---------------------------------------------------------------------- */

static int stdio_recv(transport_t *base, uint8_t *buf, size_t max, int timeout_ms)
{
    transport_stdio_t *t = (transport_stdio_t *)base;

    uint8_t hdr[2];
    if (stdio_read_exact(t->read_fd, hdr, 2, timeout_ms) != 0)
        return -1;

    size_t body_len = (size_t)hdr[0] | ((size_t)hdr[1] << 8);
    /* Enforce protocol cap and drain on oversized body.
     * Drain uses a single 100 ms wall-clock deadline for the entire
     * operation, matching transport_unix.c:drain_bytes. */
    if (body_len > max || body_len > FRAME_MAX_LEN) {
        fprintf(stderr, "transport_stdio: recv: frame %zu > max %zu (or > FRAME_MAX_LEN %u) — draining\n",
                body_len, max, (unsigned)FRAME_MAX_LEN);
        if (stdio_drain(t->read_fd, body_len, 100) < 0) {
            errno = EPIPE;
        }
        t->stats.rx_drop++;
        return -1;
    }
    if (stdio_read_exact(t->read_fd, buf, body_len, 5000) != 0) {
        fprintf(stderr, "transport_stdio: recv body failed\n");
        return -1;
    }
    t->stats.rx_ok++;
    t->stats.rx_bytes += (uint64_t)body_len;
    return (int)body_len;
}

/* -------------------------------------------------------------------------
 * close
 * ---------------------------------------------------------------------- */

static void stdio_close(transport_t *base)
{
    transport_stdio_t *t = (transport_stdio_t *)base;
    if (t->write_flags_valid && t->write_fd >= 0) {
        if (fcntl(t->write_fd, F_SETFL, t->write_flags) != 0)
            fprintf(stderr,
                    "transport_stdio: restore output flags failed: %s\n",
                    strerror(errno));
        t->write_flags_valid = 0;
    }
    if (t->child_pid > 0) {
        /* Close the socketpair fd — this signals EOF to the child */
        if (t->read_fd >= 0) {
            shutdown(t->read_fd, SHUT_RDWR);
            close(t->read_fd);
            t->read_fd  = -1;
            t->write_fd = -1;
        }
        /* SIGTERM the child first, then wait with short polls, then
         * escalate to SIGKILL if needed. Avoids indefinite blocking. */
        kill(t->child_pid, SIGTERM);
        int status;
        for (int i = 0; i < 50; i++) { /* up to ~500ms */
            pid_t r = waitpid(t->child_pid, &status, WNOHANG);
            if (r == t->child_pid || r < 0) goto reaped;
            struct timespec ts = { .tv_sec = 0, .tv_nsec = 10000000 };
            nanosleep(&ts, NULL);
        }
        kill(t->child_pid, SIGKILL);
        waitpid(t->child_pid, &status, 0);
    reaped:
        t->child_pid = -1;
    } else {
        /* stdin/stdout mode: just flush */
        if (t->write_fd == STDOUT_FILENO)
            fflush(stdout);
    }
    free(t);
}

/* -------------------------------------------------------------------------
 * stats
 * ---------------------------------------------------------------------- */

static int stdio_stats(transport_t *base, transport_stats_t *out)
{
    transport_stdio_t *t = (transport_stdio_t *)base;
    *out = t->stats;
    out->rssi_last = INT16_MIN;
    out->snr_last  = INT8_MIN;
    out->transport_id = 2;
    return 0;
}

/* -------------------------------------------------------------------------
 * Export
 * ---------------------------------------------------------------------- */

static int stdio_get_fd(transport_t *base)
{
    transport_stdio_t *t = (transport_stdio_t *)base;
    return t->read_fd;
}

static int stdio_get_send_fd(transport_t *base)
{
    transport_stdio_t *t = (transport_stdio_t *)base;
    return t->write_fd;
}

const transport_ops_t transport_stdio = {
    .name   = "stdio",
    .open   = stdio_open,
    .send   = stdio_send,
    .send_step = stdio_send_step,
    .send_cancel_untouched = stdio_send_cancel_untouched,
    .recv   = stdio_recv,
    .close  = stdio_close,
    .stats  = stdio_stats,
    .get_fd = stdio_get_fd,
    .get_send_fd = stdio_get_send_fd,
};
