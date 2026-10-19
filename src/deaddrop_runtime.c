/*
 * deaddrop_runtime.c — epoch-rekey process and SSH bootstrap integration
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */

#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "bulk.h"
#include "bulk_engine.h"
#include "attach_local.h"
#include "crypto.h"
#include "deaddrop.h"
#include "deaddrop_exchange.h"
#include "deaddrop_runtime.h"
#include "confine.h"
#include "epoch_crypto.h"
#include "monitor_endpoint.h"
#include "monitor_platform.h"
#include "monitor_pty_custody.h"
#include "monitor_roles.h"
#include "monitor_shutdown.h"
#include "monitor_startup.h"
#include "monitor_worker.h"
#include "pq_deaddrop.h"
#include "pq_deaddrop_exchange.h"
#include "pq_policy.h"
#include "process_hygiene.h"
#include "rss.h"
#include "sync_source_map.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define D28_MAX_TIMEOUT_SECS 3600
#define D28_CHILD_REAP_GRACE_MS 500
#define D28_FOREGROUND_TRAILING_QUIET_MS 100
#define D28_PUBLIC_LINE_MAX PQ_DEADDROP_RESPONSE_LINE_LEN
#define D49_LOCAL_SHUTDOWN_MS 2000

#define D28_CONTROL_RESPONSE ((uint8_t)'R')
#define D28_CONTROL_BURN     ((uint8_t)'B')

typedef struct child_armed_context {
    int status_fd;
    int64_t deadline_ms;
    const deaddrop_response_t *response;
    const pq_deaddrop_offer_t *pq_offer;
    const pq_deaddrop_response_t *pq_response;
    uint8_t pq_hybrid;
} child_armed_context_t;

/* Fixed constructor-owned mode. The ordinary path uses the constant below;
 * the monitored path may enter only after it has adopted stdio/logging and
 * installed process hardening before the final M role. */
typedef struct listener_child_mode {
    struct d28_monitor_endpoint *monitor_endpoint;
    uint8_t environment_prepared;
    uint8_t cleanup_attempt;
    uint8_t parent_public_records;
    uint8_t reserved[5];
} listener_child_mode_t;

static const listener_child_mode_t ordinary_listener_child = {
    NULL, 0U, 1U, 0U, {0}
};

static volatile sig_atomic_t runtime_stop;
static volatile sig_atomic_t runtime_child_pid;
static uint8_t * volatile runtime_secret_a;
static size_t volatile runtime_secret_a_len;
static uint8_t * volatile runtime_secret_b;
static size_t volatile runtime_secret_b_len;

static int64_t monotonic_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return -1;
    return (int64_t)ts.tv_sec * INT64_C(1000) +
           (int64_t)ts.tv_nsec / INT64_C(1000000);
}

static void runtime_wipe_registered(void)
{
    if (runtime_secret_a)
        crypto_memzero(runtime_secret_a, runtime_secret_a_len);
    if (runtime_secret_b)
        crypto_memzero(runtime_secret_b, runtime_secret_b_len);
}

static void runtime_term_handler(int sig)
{
    pid_t child;
    (void)sig;
    runtime_stop = 1;
    runtime_wipe_registered();
    child = (pid_t)runtime_child_pid;
    if (child > 0)
        (void)kill(child, SIGTERM);
}

static void runtime_fault_handler(int sig)
{
    struct sigaction action;
    pid_t child;

    runtime_wipe_registered();
    child = (pid_t)runtime_child_pid;
    if (child > 0)
        (void)kill(child, SIGTERM);
    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_DFL;
    (void)sigaction(sig, &action, NULL);
    (void)raise(sig);
}

static int install_runtime_handlers(void)
{
    static const int terms[] = { SIGINT, SIGHUP, SIGTERM, SIGQUIT };
    static const int faults[] = { SIGSEGV, SIGBUS, SIGFPE };
    struct sigaction action;
    size_t i;

    runtime_stop = 0;
    runtime_child_pid = 0;
    runtime_secret_a = NULL;
    runtime_secret_a_len = 0;
    runtime_secret_b = NULL;
    runtime_secret_b_len = 0;

    memset(&action, 0, sizeof(action));
    action.sa_handler = runtime_term_handler;
    sigemptyset(&action.sa_mask);
    for (i = 0; i < sizeof(terms) / sizeof(terms[0]); i++) {
        if (sigaction(terms[i], &action, NULL) != 0)
            return -1;
    }
    memset(&action, 0, sizeof(action));
    action.sa_handler = runtime_fault_handler;
    action.sa_flags = (int)SA_RESETHAND;
    sigemptyset(&action.sa_mask);
    for (i = 0; i < sizeof(faults) / sizeof(faults[0]); i++) {
        if (sigaction(faults[i], &action, NULL) != 0)
            return -1;
    }
    return 0;
}

static int ensure_standard_fds(void)
{
    int fd;
    int target;

    for (target = STDIN_FILENO; target <= STDERR_FILENO; target++) {
        if (fcntl(target, F_GETFD, 0) >= 0)
            continue;
        if (errno != EBADF)
            return -1;
        fd = open("/dev/null", O_RDWR | O_CLOEXEC);
        if (fd < 0)
            return -1;
        if (fd != target) {
            if (dup2(fd, target) < 0) {
                (void)close(fd);
                return -1;
            }
            (void)close(fd);
        }
    }
    return 0;
}

static int pipe_cloexec(int fds[2])
{
    int flags;

    if (pipe(fds) != 0)
        return -1;
    flags = fcntl(fds[0], F_GETFD, 0);
    if (flags < 0 || fcntl(fds[0], F_SETFD, flags | FD_CLOEXEC) != 0)
        goto fail;
    flags = fcntl(fds[1], F_GETFD, 0);
    if (flags < 0 || fcntl(fds[1], F_SETFD, flags | FD_CLOEXEC) != 0)
        goto fail;
    return 0;

fail:
    (void)close(fds[0]);
    (void)close(fds[1]);
    fds[0] = -1;
    fds[1] = -1;
    return -1;
}

static int stream_pair_cloexec_nonblock(int fds[2])
{
    if (fds == NULL || fds[0] != -1 || fds[1] != -1) {
        errno = EINVAL;
        return -1;
    }
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
        return -1;
    for (unsigned index = 0U; index < 2U; ++index) {
        int status = fcntl(fds[index], F_GETFL, 0);
        int descriptor = fcntl(fds[index], F_GETFD, 0);
        if (status < 0 || descriptor < 0 ||
            fcntl(fds[index], F_SETFL, status | O_NONBLOCK) != 0 ||
            fcntl(fds[index], F_SETFD, descriptor | FD_CLOEXEC) != 0)
            goto fail;
    }
    return 0;

fail:
    (void)close(fds[0]);
    (void)close(fds[1]);
    fds[0] = fds[1] = -1;
    return -1;
}

static int wait_fd(int fd, short events, int64_t deadline_ms)
{
    struct pollfd pollfd_value;

    for (;;) {
        int64_t now;
        int64_t remaining;
        int timeout;
        int rc;

        if (runtime_stop) {
            errno = EINTR;
            return -1;
        }
        now = monotonic_ms();
        if (now < 0)
            return -1;
        remaining = deadline_ms - now;
        if (remaining <= 0) {
            errno = ETIMEDOUT;
            return -1;
        }
        timeout = remaining > INT_MAX ? INT_MAX : (int)remaining;
        memset(&pollfd_value, 0, sizeof(pollfd_value));
        pollfd_value.fd = fd;
        pollfd_value.events = events;
        rc = poll(&pollfd_value, 1, timeout);
        if (rc < 0 && errno == EINTR)
            continue;
        if (rc == 0) {
            errno = ETIMEDOUT;
            return -1;
        }
        if (rc < 0)
            return -1;
        if ((pollfd_value.revents & (events | POLLHUP | POLLERR | POLLNVAL)) != 0)
            return 0;
    }
}

static int poll_component(int fd, short events, int timeout_ms,
                          short *revents_out)
{
    struct pollfd item;
    int result;

    if (fd < 0 || events == 0 || timeout_ms < 0 || revents_out == NULL) {
        errno = EINVAL;
        return -1;
    }
    memset(&item, 0, sizeof(item));
    item.fd = fd;
    item.events = events;
    do {
        result = poll(&item, 1U, timeout_ms);
    } while (result < 0 && errno == EINTR && !runtime_stop);
    if (result < 0)
        return -1;
    *revents_out = result > 0 ? item.revents : 0;
    return result;
}

static monitor_startup_result_t
drive_monitor_startup(monitor_startup_t *startup, int64_t deadline_ms)
{
    monitor_startup_wait_t interest;
    int64_t now;

    if (startup == NULL || runtime_stop) {
        errno = EINTR;
        return MONITOR_STARTUP_ERROR;
    }
    memset(&interest, 0, sizeof(interest));
    if (monitor_startup_interest(startup, &interest) != 0)
        return MONITOR_STARTUP_ERROR;
    now = monotonic_ms();
    if (now < 0)
        return MONITOR_STARTUP_ERROR;
    if (!interest.immediate) {
        int64_t wake = interest.wake_ms < deadline_ms
            ? interest.wake_ms : deadline_ms;
        int64_t remaining = wake - now;
        int timeout = remaining <= 0 ? 0 :
            remaining > INT_MAX ? INT_MAX : (int)remaining;
        short revents = 0;
        if (interest.fd >= 0) {
            if (poll_component(interest.fd, (short)interest.events,
                               timeout, &revents) < 0)
                return MONITOR_STARTUP_ERROR;
            (void)revents;
        } else if (timeout > 0) {
            do {
                int result = poll(NULL, 0, timeout);
                if (result == 0)
                    break;
                if (result < 0 && errno == EINTR && !runtime_stop)
                    continue;
                if (result < 0)
                    return MONITOR_STARTUP_ERROR;
            } while (!runtime_stop);
        }
    }
    if (runtime_stop) {
        errno = EINTR;
        return MONITOR_STARTUP_ERROR;
    }
    now = monotonic_ms();
    return now >= 0 ? monitor_startup_step(startup, now)
                    : MONITOR_STARTUP_ERROR;
}

static int write_all_deadline(int fd, const uint8_t *bytes, size_t length,
                              int64_t deadline_ms)
{
    size_t offset = 0;

    while (offset < length) {
        ssize_t count;
        if (wait_fd(fd, POLLOUT, deadline_ms) != 0)
            return -1;
        count = write(fd, bytes + offset, length - offset);
        if (count > 0) {
            offset += (size_t)count;
            continue;
        }
        if (count < 0 && errno == EINTR)
            continue;
        if (count == 0)
            errno = EPIPE;
        return -1;
    }
    return 0;
}

static int read_all_deadline(int fd, uint8_t *bytes, size_t length,
                             int64_t deadline_ms)
{
    size_t offset = 0U;

    if (bytes == NULL && length != 0U) {
        errno = EINVAL;
        return -1;
    }
    while (offset < length) {
        ssize_t amount;
        if (wait_fd(fd, POLLIN, deadline_ms) != 0)
            return -1;
        amount = read(fd, bytes + offset, length - offset);
        if (amount > 0) {
            offset += (size_t)amount;
            continue;
        }
        if (amount < 0 && errno == EINTR)
            continue;
        errno = amount == 0 ? EPIPE : (errno ? errno : EIO);
        return -1;
    }
    return 0;
}

static int write_public_line(int fd, const char *line, size_t line_len,
                             int64_t deadline_ms)
{
    uint8_t buffer[D28_PUBLIC_LINE_MAX + 2U];

    if (!line || line_len > D28_PUBLIC_LINE_MAX ||
        memchr(line, '\n', line_len) != NULL ||
        memchr(line, '\r', line_len) != NULL) {
        errno = EINVAL;
        return -1;
    }
    memcpy(buffer, line, line_len);
    buffer[line_len] = (uint8_t)'\n';
    if (write_all_deadline(fd, buffer, line_len + 1U, deadline_ms) != 0) {
        crypto_memzero(buffer, sizeof(buffer));
        return -1;
    }
    crypto_memzero(buffer, sizeof(buffer));
    return 0;
}

static int read_public_line(int fd, char *line, size_t expected_len,
                            int64_t deadline_ms)
{
    size_t offset = 0;

    if (!line || expected_len > D28_PUBLIC_LINE_MAX) {
        errno = EINVAL;
        return -1;
    }
    memset(line, 0, expected_len + 1U);
    for (;;) {
        uint8_t byte;
        ssize_t count;

        if (wait_fd(fd, POLLIN, deadline_ms) != 0)
            goto fail;
        count = read(fd, &byte, 1U);
        if (count == 0) {
            errno = EPIPE;
            goto fail;
        }
        if (count < 0) {
            if (errno == EINTR)
                continue;
            goto fail;
        }
        if (byte == (uint8_t)'\n') {
            if (offset != expected_len) {
                fprintf(stderr,
                        "unmoor: public record length mismatch "
                        "(got=%zu expected=%zu)\n",
                        offset, expected_len);
                errno = EPROTO;
                goto fail;
            }
            line[offset] = '\0';
            return 0;
        }
        if (byte == (uint8_t)'\r' || byte == 0 || offset >= expected_len) {
            fprintf(stderr,
                    "unmoor: public record contains a forbidden byte "
                    "or exceeds %zu bytes at offset %zu\n",
                    expected_len, offset);
            errno = EPROTO;
            goto fail;
        }
        line[offset++] = (char)byte;
    }

fail:
    crypto_memzero(line, expected_len + 1U);
    return -1;
}

/* A final protocol record owns the stream through EOF.  Requiring EOF after
 * its LF turns an appended or duplicated line into a deterministic protocol
 * error instead of leaving attacker-controlled bytes unread. */
static int require_stream_eof(int fd, int64_t deadline_ms)
{
    uint8_t byte;
    ssize_t count;

    for (;;) {
        if (wait_fd(fd, POLLIN, deadline_ms) != 0)
            return -1;
        count = read(fd, &byte, 1U);
        if (count == 0)
            return 0;
        if (count < 0 && errno == EINTR)
            continue;
        if (count > 0)
            errno = EPROTO;
        return -1;
    }
}

/* OpenSSH exposes no stdout-only EOF while a remote command remains alive.
 * Foreground lifecycle mode therefore pins the final record with a short
 * trailing-byte guard rather than the normal whole-stream EOF.  This catches
 * a coalesced/appended record without turning the intentionally live SSH
 * process into a bootstrap deadlock. */
static int require_stream_quiet(int fd, int timeout_ms)
{
    struct pollfd stream;
    uint8_t byte;
    ssize_t count;
    int ready;

    if (fd < 0 || timeout_ms < 0) {
        errno = EINVAL;
        return -1;
    }
    memset(&stream, 0, sizeof(stream));
    stream.fd = fd;
    stream.events = POLLIN;
    do {
        ready = poll(&stream, 1, timeout_ms);
    } while (ready < 0 && errno == EINTR);
    if (ready == 0)
        return 0;
    if (ready < 0 || (stream.revents & (POLLERR | POLLNVAL)) != 0)
        return -1;
    if ((stream.revents & (POLLIN | POLLHUP)) == 0) {
        errno = EIO;
        return -1;
    }
    do {
        count = read(fd, &byte, 1U);
    } while (count < 0 && errno == EINTR);
    if (count == 0)
        return 0;
    if (count > 0)
        errno = EPROTO;
    return -1;
}

static int write_control(int fd, uint8_t command, int64_t deadline_ms)
{
    return write_all_deadline(fd, &command, 1U, deadline_ms);
}

static int read_control(int fd, uint8_t *command, int64_t deadline_ms)
{
    ssize_t count;

    if (!command) {
        errno = EINVAL;
        return -1;
    }
    for (;;) {
        if (wait_fd(fd, POLLIN, deadline_ms) != 0)
            return -1;
        count = read(fd, command, 1U);
        if (count == 1)
            return 0;
        if (count < 0 && errno == EINTR)
            continue;
        if (count == 0)
            errno = EPIPE;
        return -1;
    }
}

static int reject_secret_environment(
    d28_application_profile_t application_profile)
{
    char *key = getenv("UNMOOR_KEY");
    const char *sync = getenv("UNMOOR_SYNC");

    if (key) {
        crypto_memzero(key, strlen(key));
        (void)unsetenv("UNMOOR_KEY");
        fprintf(stderr,
                "unmoor: deaddrop bootstrap rejects UNMOOR_KEY; "
                "no secret may enter SSH or the environment\n");
        return -1;
    }
    if (application_profile == D28_APPLICATION_PROFILE_TERMINAL &&
        sync && strcmp(sync, "0") == 0) {
        fprintf(stderr,
                "unmoor: deaddrop bootstrap requires terminal sync and epoch-rekey\n");
        return -1;
    }
    return 0;
}

static int parse_timeout(int value)
{
    return value > 0 && value <= D28_MAX_TIMEOUT_SECS;
}

static int valid_remote_command(const char *command)
{
    size_t i;

    if (!command || command[0] == '\0' || command[0] == '-')
        return 0;
    for (i = 0; command[i] != '\0'; i++) {
        unsigned char c = (unsigned char)command[i];
        if (!(isalnum(c) || c == '/' || c == '.' || c == '_' || c == '-' ||
              c == '+' || (c == '~' && i == 0U)))
            return 0;
    }
    return 1;
}

/* This value is appended to the authenticated remote shell command.  Keep
 * the accepted alphabet intentionally narrower than getaddrinfo(): ordinary
 * hostnames plus numeric IPv4/IPv6 literals and a zone identifier, with no
 * quoting or shell metacharacters. */
static int valid_remote_bind_host(const char *host)
{
    size_t i;

    if (!host)
        return 1;
    if (host[0] == '\0' || host[0] == '-')
        return 0;
    for (i = 0U; host[i] != '\0'; i++) {
        unsigned char c = (unsigned char)host[i];

        if (!(isalnum(c) || c == '.' || c == ':' || c == '_' ||
              c == '-' || c == '%'))
            return 0;
    }
    return i <= 253U;
}

static int valid_decimal_environment(const char *value)
{
    size_t i;
    if (!value || value[0] == '\0')
        return 0;
    for (i = 0; value[i] != '\0'; i++) {
        if (value[i] < '0' || value[i] > '9')
            return 0;
    }
    return 1;
}

static int waitpid_nointr(pid_t pid, int *status, int options)
{
    int rc;
    do {
        rc = (int)waitpid(pid, status, options);
    } while (rc < 0 && errno == EINTR && !runtime_stop);
    return rc;
}

static int terminate_and_reap(pid_t pid)
{
    int status = 0;
    int rc;
    int64_t end;

    if (pid <= 0)
        return -1;
    rc = waitpid_nointr(pid, &status, WNOHANG);
    if (rc == (int)pid || (rc < 0 && errno == ECHILD))
        return 0;
    (void)kill(pid, SIGTERM);
    end = monotonic_ms() + D28_CHILD_REAP_GRACE_MS;
    while (monotonic_ms() < end) {
        struct timespec pause = { .tv_sec = 0, .tv_nsec = 10000000L };
        rc = waitpid_nointr(pid, &status, WNOHANG);
        if (rc == (int)pid || (rc < 0 && errno == ECHILD))
            return 0;
        (void)nanosleep(&pause, NULL);
    }
    (void)kill(pid, SIGKILL);
    rc = waitpid_nointr(pid, &status, 0);
    return rc == (int)pid || (rc < 0 && errno == ECHILD) ? 0 : -1;
}

static int wait_child_grace(pid_t pid, int grace_ms, int *status_out)
{
    int64_t end;

    if (pid <= 0 || !status_out)
        return -1;
    end = monotonic_ms();
    if (end < 0)
        return -1;
    end += grace_ms;
    for (;;) {
        struct timespec pause = { .tv_sec = 0, .tv_nsec = 10000000L };
        pid_t waited = waitpid(pid, status_out, WNOHANG);
        if (waited == pid)
            return 1;
        if (waited < 0 && errno == ECHILD)
            return -1;
        if (waited < 0 && errno != EINTR)
            return -1;
        if (monotonic_ms() >= end)
            return 0;
        (void)nanosleep(&pause, NULL);
    }
}

static int response_matches_offer(const deaddrop_response_t *response,
                                  const deaddrop_offer_t *offer)
{
    return response && offer &&
           memcmp(response->id, offer->id, DEADDROP_ID_LEN) == 0 &&
           response->port == offer->port &&
           response->required_caps == offer->required_caps &&
           memcmp(response->server_public_key, offer->server_public_key,
                  DEADDROP_PUBLIC_KEY_LEN) == 0 &&
           memcmp(response->client_public_key, offer->server_public_key,
                  DEADDROP_PUBLIC_KEY_LEN) != 0 &&
           crypto_verify32_exact(response->offer_fingerprint,
                                 offer->offer_fingerprint) == 0;
}

static int compare_offers(const deaddrop_offer_t *left,
                          const deaddrop_offer_t *right)
{
    uint8_t a[DEADDROP_OFFER_RECORD_SIZE];
    uint8_t b[DEADDROP_OFFER_RECORD_SIZE];
    int equal = 0;

    if (deaddrop_offer_encode(left, a) == DEADDROP_OK &&
        deaddrop_offer_encode(right, b) == DEADDROP_OK &&
        memcmp(a, b, sizeof(a)) == 0)
        equal = 1;
    crypto_memzero(a, sizeof(a));
    crypto_memzero(b, sizeof(b));
    return equal;
}

static int open_or_create_parent(const char *path, int *fd_out)
{
    if (mkdir(path, 0700) != 0 && errno != EEXIST)
        return -1;
    return deaddrop_dir_open(path, fd_out) == DEADDROP_OK ? 0 : -1;
}

static int default_parent_path(char out[PATH_MAX])
{
    const char *home = getenv("HOME");
    int count;

    if (!home || home[0] != '/')
        return -1;
    count = snprintf(out, PATH_MAX, "%s/.deaddrop", home);
    return count > 0 && count < PATH_MAX ? 0 : -1;
}

static int open_listener_log(const char *log_path)
{
    struct stat state;
    int logfd;

    if (log_path == NULL) {
        errno = EINVAL;
        return -1;
    }
    logfd = open(log_path,
                 O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW,
                 0600);
    if (logfd < 0)
        return -1;
    /* O_NOFOLLOW covers only the final component. A FIFO, a device or
     * another user's file planted at the path is not a log of ours. */
    if (fstat(logfd, &state) != 0) {
        int cause = errno;
        (void)close(logfd);
        errno = cause;
        return -1;
    }
    if (!S_ISREG(state.st_mode) || state.st_uid != geteuid()) {
        (void)close(logfd);
        errno = EPERM;
        return -1;
    }
    if (fchmod(logfd, 0600) != 0) {
        int cause = errno;
        (void)close(logfd);
        errno = cause;
        return -1;
    }
    return logfd;
}

static int redirect_listener_child(const char *log_path, int preopened_log_fd,
                                   int foreground)
{
    int devnull = -1;
    int logfd = preopened_log_fd;

    if (preopened_log_fd < -1 ||
        (log_path != NULL && preopened_log_fd >= 0) ||
        preopened_log_fd == STDIN_FILENO ||
        preopened_log_fd == STDOUT_FILENO) {
        errno = EINVAL;
        return -1;
    }

    if (!foreground && setsid() < 0)
        goto fail;
    devnull = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (devnull < 0)
        goto fail;
    if (dup2(devnull, STDIN_FILENO) < 0 ||
        dup2(devnull, STDOUT_FILENO) < 0)
        goto fail;
    if (log_path != NULL) {
        logfd = open_listener_log(log_path);
        if (logfd < 0)
            goto fail;
    }
    if (logfd >= 0) {
        if (dup2(logfd, STDERR_FILENO) < 0)
            goto fail;
    } else if (!foreground && dup2(devnull, STDERR_FILENO) < 0) {
        goto fail;
    }
    if (logfd > STDERR_FILENO)
        (void)close(logfd);
    if (devnull > STDERR_FILENO)
        (void)close(devnull);
    return 0;

fail:
    if (logfd >= 0)
        (void)close(logfd);
    if (devnull >= 0)
        (void)close(devnull);
    return -1;
}

static int prepare_listener_child(const char *log_path, int preopened_log_fd,
                                  int foreground, int debuggable)
{
    if (redirect_listener_child(log_path, preopened_log_fd, foreground) != 0)
        return -1;
    if (process_harden(debuggable) != 0) {
        fprintf(stderr,
                "unmoor: listener child process hardening failed: %s\n",
                strerror(errno));
        return -1;
    }
    return 0;
}

static int child_armed(void *opaque)
{
    child_armed_context_t *context = opaque;
    char line[PQ_DEADDROP_ACCEPT_LINE_LEN + 1U];
    size_t line_len;
    int rc;

    if (!context || context->status_fd < 0)
        return -1;
    if (context->pq_hybrid != 0U) {
        if (!context->pq_offer || !context->pq_response ||
            pq_deaddrop_accept_line_encode(context->pq_offer,
                                           context->pq_response, line) != 0)
            return -1;
        line_len = PQ_DEADDROP_ACCEPT_LINE_LEN;
    } else {
        if (!context->response ||
            d28_accept_line_encode(context->response, line) != 0)
            return -1;
        line_len = D28_ACCEPT_LINE_LEN;
    }
    rc = write_public_line(context->status_fd, line, line_len,
                           context->deadline_ms);
    crypto_memzero(line, sizeof(line));
    if (rc == 0) {
        (void)close(context->status_fd);
        context->status_fd = -1;
    }
    return rc;
}

static int cleanup_attempt(int attempt_fd, int parent_fd,
                           const uint8_t id[DEADDROP_ID_LEN])
{
    deaddrop_status_t contents = DEADDROP_OK;
    deaddrop_status_t directory = DEADDROP_OK;

    if (attempt_fd >= 0)
        contents = deaddrop_cleanup_id(attempt_fd, id);
    if (attempt_fd >= 0)
        (void)close(attempt_fd);
    if (parent_fd >= 0)
        directory = deaddrop_attempt_remove(parent_fd, id);
    if (parent_fd >= 0)
        (void)close(parent_fd);
    if (contents != DEADDROP_OK || directory != DEADDROP_OK) {
        fprintf(stderr,
                "unmoor: deaddrop cleanup failed: contents=%s directory=%s\n",
                deaddrop_status_string(contents),
                deaddrop_status_string(directory));
        return -1;
    }
    return 0;
}

static int runtime_policy_resolve(
    const d28_endpoint_policy_t *policy,
    d28_application_profile_t application_profile,
    traffic_profile_result_t *resolved_out)
{
    traffic_application_t application;

    if (!policy || !resolved_out ||
        (policy->log_format != EVENT_LOG_FORMAT_TEXT &&
         policy->log_format != EVENT_LOG_FORMAT_JSON) ||
        policy->channelised > 1U ||
        policy->pq_hybrid > 1U ||
        (policy->channelised != 0U &&
         application_profile != D28_APPLICATION_PROFILE_TERMINAL) ||
        (policy->multipath_option != TRAFFIC_MULTIPATH_OPTION_NONE &&
         policy->multipath_option != TRAFFIC_MULTIPATH_OPTION_BARE &&
         policy->multipath_option != TRAFFIC_MULTIPATH_OPTION_EXACT))
        return -1;
    if (application_profile == D28_APPLICATION_PROFILE_TERMINAL)
        application = TRAFFIC_APPLICATION_TERMINAL;
    else if (application_profile == D28_APPLICATION_PROFILE_BULK_D33)
        application = TRAFFIC_APPLICATION_BULK;
    else
        return -1;
    return traffic_profile_resolve(policy->traffic_profile, application, 1,
                                   policy->multipath_option,
                                   policy->exact_paths, resolved_out);
}

static int listener_monitor_native_supported(void)
{
    return monitor_role_supported() && monitor_worker_supported() &&
           monitor_pty_custody_supported() && sync_source_map_supported();
}

static int listener_child_run(transport_t *transport,
                              int parent_fd, int attempt_fd,
                              const uint8_t id[DEADDROP_ID_LEN],
                              uint16_t port,
                              int status_fd, int control_fd,
                              int64_t deadline_ms,
                              const char *log_path, int foreground,
                              int debuggable,
                              d28_application_profile_t application_profile,
                              void *runner_context,
                              const d28_endpoint_policy_t *policy,
                              uint8_t pq_hybrid,
                              d28_endpoint_runner_fn runner,
                              const listener_child_mode_t *mode)
{
    deaddrop_offer_t offer;
    deaddrop_response_t response;
    pq_deaddrop_offer_t pq_offer;
    pq_deaddrop_response_t pq_response;
    pq_deaddrop_server_secrets_t pq_secrets;
    child_armed_context_t armed_context;
    uint8_t server_private[32];
    uint8_t root[32];
    uint8_t pair_seed[4];
    uint8_t parent_response_wire[PQ_DEADDROP_RESPONSE_SIZE];
    uint8_t command = 0;
    char offer_line[PQ_DEADDROP_OFFER_LINE_LEN + 1U];
    uint32_t required_caps;
    d28_endpoint_policy_t effective_policy;
    int runner_called = 0;
    int cleanup_owned_attempt = 1;
    int rc = 1;

    memset(&offer, 0, sizeof(offer));
    memset(&response, 0, sizeof(response));
    memset(&pq_offer, 0, sizeof(pq_offer));
    memset(&pq_response, 0, sizeof(pq_response));
    crypto_memzero(&pq_secrets, sizeof(pq_secrets));
    crypto_memzero(server_private, sizeof(server_private));
    crypto_memzero(root, sizeof(root));
    crypto_memzero(pair_seed, sizeof(pair_seed));
    crypto_memzero(parent_response_wire, sizeof(parent_response_wire));
    memset(&armed_context, 0, sizeof(armed_context));
    armed_context.status_fd = status_fd;
    armed_context.deadline_ms = deadline_ms;
    armed_context.pq_hybrid = pq_hybrid;
    if (mode == NULL || mode->environment_prepared > 1U ||
        mode->cleanup_attempt > 1U ||
        mode->parent_public_records > 1U ||
        (mode->environment_prepared == 0U &&
         mode->monitor_endpoint != NULL))
        goto cleanup;
    cleanup_owned_attempt = mode->cleanup_attempt != 0U;
    effective_policy = *policy;
    effective_policy.pq_hybrid = pq_hybrid;
    required_caps = d28_application_profile_required_caps(application_profile);
    if (pq_hybrid != 0U)
        required_caps |= UNMOOR_CAP_PQ_HYBRID_D45_V1;

    runtime_child_pid = 0;
    if (mode->environment_prepared == 0U &&
        prepare_listener_child(log_path, -1, foreground, debuggable) != 0)
        goto cleanup;
    fprintf(stderr,
            "unmoor: deaddrop listener child pid %ld; descriptors sealed\n",
            (long)getpid());

    /* Descriptor topology is final before the first private byte exists. */
    if (pq_hybrid != 0U) {
        runtime_secret_a = (uint8_t *)&pq_secrets;
        runtime_secret_a_len = sizeof(pq_secrets);
        if (pq_deaddrop_server_offer_generate(
                id, port, required_caps, &pq_offer, &pq_secrets) != 0 ||
            (mode->parent_public_records == 0U &&
             pq_deaddrop_publish_offer(attempt_fd, &pq_offer) !=
                 DEADDROP_OK) ||
            pq_deaddrop_offer_line_encode(&pq_offer, offer_line) != 0 ||
            write_public_line(status_fd, offer_line,
                              PQ_DEADDROP_OFFER_LINE_LEN,
                              deadline_ms) != 0)
            goto cleanup;
    } else {
        (void)crypto_mlock(server_private, sizeof(server_private));
        crypto_mark_dontdump(server_private, sizeof(server_private));
        runtime_secret_a = server_private;
        runtime_secret_a_len = sizeof(server_private);
        if (d28_server_offer_generate_for_profile(
                id, port, application_profile, &offer, server_private) != 0 ||
            (mode->parent_public_records == 0U &&
             deaddrop_publish_offer(attempt_fd, &offer) != DEADDROP_OK) ||
            d28_offer_line_encode(&offer, offer_line) != 0 ||
            write_public_line(status_fd, offer_line, D28_OFFER_LINE_LEN,
                              deadline_ms) != 0)
            goto cleanup;
    }

    if (read_control(control_fd, &command, deadline_ms) != 0 ||
        command != D28_CONTROL_RESPONSE) {
        if (mode->parent_public_records == 0U && pq_hybrid != 0U) {
            pq_deaddrop_response_t burned;
            memset(&burned, 0, sizeof(burned));
            (void)pq_deaddrop_claim_response(attempt_fd, id, &burned);
            crypto_memzero(&burned, sizeof(burned));
        } else if (mode->parent_public_records == 0U) {
            deaddrop_response_t burned;
            memset(&burned, 0, sizeof(burned));
            (void)deaddrop_claim_response(attempt_fd, id, &burned);
            crypto_memzero(&burned, sizeof(burned));
        }
        goto cleanup;
    }
    if (mode->parent_public_records != 0U && pq_hybrid != 0U) {
        if (read_all_deadline(control_fd, parent_response_wire,
                              PQ_DEADDROP_RESPONSE_SIZE,
                              deadline_ms) != 0 ||
            pq_deaddrop_response_decode(parent_response_wire,
                                        PQ_DEADDROP_RESPONSE_SIZE,
                                        &pq_response) != 0 ||
            pq_deaddrop_response_verify(&pq_offer, &pq_response) != 0)
            goto cleanup;
    } else if (mode->parent_public_records != 0U) {
        if (read_all_deadline(control_fd, parent_response_wire,
                              DEADDROP_RESPONSE_RECORD_SIZE,
                              deadline_ms) != 0 ||
            deaddrop_response_decode(parent_response_wire, &response) !=
                DEADDROP_OK ||
            !response_matches_offer(&response, &offer))
            goto cleanup;
    } else if (pq_hybrid != 0U) {
        if (pq_deaddrop_claim_response(attempt_fd, id, &pq_response) !=
            DEADDROP_OK)
            goto cleanup;
    } else if (deaddrop_claim_response(attempt_fd, id, &response) !=
               DEADDROP_OK) {
        goto cleanup;
    }

    (void)crypto_mlock(root, sizeof(root));
    crypto_mark_dontdump(root, sizeof(root));
    runtime_secret_b = root;
    runtime_secret_b_len = sizeof(root);
    if (pq_hybrid != 0U) {
        if (pq_deaddrop_server_accept(&pq_secrets, &pq_offer, &pq_response,
                                      root, pair_seed) != 0)
            goto cleanup;
    } else if (d28_server_accept_response(server_private, &offer, &response,
                                          root, pair_seed) != 0) {
        goto cleanup;
    }
    runtime_secret_a = NULL;
    runtime_secret_a_len = 0;
    if (pq_hybrid != 0U) {
        armed_context.pq_offer = &pq_offer;
        armed_context.pq_response = &pq_response;
    } else {
        armed_context.response = &response;
    }
    runner_called = 1;
    rc = runner(transport, root, pair_seed, 1,
                application_profile, runner_context,
                &effective_policy, mode->monitor_endpoint, deadline_ms,
                child_armed, &armed_context);
    transport = NULL;

cleanup:
    if (!runner_called && transport)
        transport->ops->close(transport);
    if (armed_context.status_fd >= 0)
        (void)close(armed_context.status_fd);
    (void)close(control_fd);
    runtime_secret_a = NULL;
    runtime_secret_a_len = 0;
    runtime_secret_b = NULL;
    runtime_secret_b_len = 0;
    crypto_memzero(server_private, sizeof(server_private));
    (void)crypto_munlock(server_private, sizeof(server_private));
    pq_deaddrop_server_secrets_wipe(&pq_secrets);
    crypto_memzero(root, sizeof(root));
    (void)crypto_munlock(root, sizeof(root));
    crypto_memzero(pair_seed, sizeof(pair_seed));
    crypto_memzero(parent_response_wire, sizeof(parent_response_wire));
    crypto_memzero(offer_line, sizeof(offer_line));
    crypto_memzero(&offer, sizeof(offer));
    crypto_memzero(&response, sizeof(response));
    crypto_memzero(&pq_offer, sizeof(pq_offer));
    crypto_memzero(&pq_response, sizeof(pq_response));
    if (cleanup_owned_attempt) {
        if (cleanup_attempt(attempt_fd, parent_fd, id) != 0)
            rc = 1;
    } else {
        if (attempt_fd >= 0)
            (void)close(attempt_fd);
        if (parent_fd >= 0)
            (void)close(parent_fd);
    }
    return rc >= 0 && rc <= 255 ? rc : 1;
}

static int pq_offers_equal(const pq_deaddrop_offer_t *left,
                           const pq_deaddrop_offer_t *right)
{
    return left && right &&
           memcmp(left->id, right->id, DEADDROP_ID_LEN) == 0 &&
           left->port == right->port &&
           left->required_caps == right->required_caps &&
           memcmp(left->server_x25519, right->server_x25519,
                  sizeof(left->server_x25519)) == 0 &&
           memcmp(left->mlkem_public, right->mlkem_public,
                  sizeof(left->mlkem_public)) == 0 &&
           crypto_verify32_exact(left->offer_fingerprint,
                                 right->offer_fingerprint) == 0;
}

static int responses_equal(const deaddrop_response_t *left,
                           const deaddrop_response_t *right)
{
    uint8_t a[DEADDROP_RESPONSE_RECORD_SIZE];
    uint8_t b[DEADDROP_RESPONSE_RECORD_SIZE];
    int equal = 0;

    if (deaddrop_response_encode(left, a) == DEADDROP_OK &&
        deaddrop_response_encode(right, b) == DEADDROP_OK &&
        memcmp(a, b, sizeof(a)) == 0)
        equal = 1;
    crypto_memzero(a, sizeof(a));
    crypto_memzero(b, sizeof(b));
    return equal;
}

static int pq_responses_equal(const pq_deaddrop_response_t *left,
                              const pq_deaddrop_response_t *right)
{
    uint8_t a[PQ_DEADDROP_RESPONSE_SIZE];
    uint8_t b[PQ_DEADDROP_RESPONSE_SIZE];
    int equal = 0;

    if (pq_deaddrop_response_encode(left, a) == 0 &&
        pq_deaddrop_response_encode(right, b) == 0 &&
        memcmp(a, b, sizeof(a)) == 0)
        equal = 1;
    crypto_memzero(a, sizeof(a));
    crypto_memzero(b, sizeof(b));
    return equal;
}

/* Public-record oracle shared by the ordinary listener and the later
 * monitored P constructor. All descriptors and the exact child are already
 * owned by the caller. This helper creates no resource and never cleans the
 * attempt; it only consumes the existing OFFER/RESPONSE/ACCEPT transcript and
 * transfers or reaps the exact child on success. */
static int listener_parent_relay(const d28_listener_config_t *config,
                                 pid_t child,
                                 int parent_fd, int attempt_fd,
                                 const uint8_t id[DEADDROP_ID_LEN],
                                 int status_fd, int *control_fd,
                                 int64_t deadline_ms, pid_t *child_out)
{
    deaddrop_offer_t status_offer;
    deaddrop_offer_t disk_offer;
    deaddrop_response_t response;
    deaddrop_response_t disk_response;
    pq_deaddrop_offer_t pq_status_offer;
    pq_deaddrop_offer_t pq_disk_offer;
    pq_deaddrop_response_t pq_response;
    pq_deaddrop_response_t pq_disk_response;
    uint8_t response_wire[PQ_DEADDROP_RESPONSE_SIZE];
    char offer_line[PQ_DEADDROP_OFFER_LINE_LEN + 1U];
    char response_line[PQ_DEADDROP_RESPONSE_LINE_LEN + 1U];
    char accept_line[PQ_DEADDROP_ACCEPT_LINE_LEN + 1U];
    int status = 0;
    int success = 0;

    memset(&status_offer, 0, sizeof(status_offer));
    memset(&disk_offer, 0, sizeof(disk_offer));
    memset(&response, 0, sizeof(response));
    memset(&disk_response, 0, sizeof(disk_response));
    memset(&pq_status_offer, 0, sizeof(pq_status_offer));
    memset(&pq_disk_offer, 0, sizeof(pq_disk_offer));
    memset(&pq_response, 0, sizeof(pq_response));
    memset(&pq_disk_response, 0, sizeof(pq_disk_response));
    crypto_memzero(response_wire, sizeof(response_wire));
    memset(offer_line, 0, sizeof(offer_line));
    memset(response_line, 0, sizeof(response_line));
    memset(accept_line, 0, sizeof(accept_line));
    if (!config || child <= 0 || parent_fd < 0 || attempt_fd < 0 || !id ||
        status_fd < 0 || !control_fd || *control_fd < 0 || !child_out) {
        errno = EINVAL;
        goto done;
    }

    if (config->pq_carrier_required != 0U) {
        if (read_public_line(status_fd, offer_line,
                             PQ_DEADDROP_OFFER_LINE_LEN, deadline_ms) != 0 ||
            pq_deaddrop_offer_line_decode(
                offer_line, PQ_DEADDROP_OFFER_LINE_LEN,
                &pq_status_offer) != 0 ||
            (config->listener_monitor != 0U &&
             pq_deaddrop_publish_offer(attempt_fd, &pq_status_offer) !=
                 DEADDROP_OK) ||
            pq_deaddrop_claim_offer(attempt_fd, id, &pq_disk_offer) !=
                DEADDROP_OK ||
            !pq_offers_equal(&pq_status_offer, &pq_disk_offer)) {
            fprintf(stderr,
                    "unmoor: listener offer did not match its one-shot deaddrop\n");
            goto done;
        }
    } else if (read_public_line(status_fd, offer_line,
                                D28_OFFER_LINE_LEN, deadline_ms) != 0 ||
               d28_offer_line_decode(offer_line, D28_OFFER_LINE_LEN,
                                     &status_offer) != 0 ||
               (config->listener_monitor != 0U &&
                deaddrop_publish_offer(attempt_fd, &status_offer) !=
                    DEADDROP_OK) ||
               deaddrop_claim_offer(attempt_fd, id, &disk_offer) !=
                   DEADDROP_OK ||
               !compare_offers(&status_offer, &disk_offer)) {
        fprintf(stderr,
                "unmoor: listener offer did not match its one-shot deaddrop\n");
        goto done;
    }
    if (write_public_line(
            STDOUT_FILENO, offer_line,
            config->pq_carrier_required != 0U
                ? PQ_DEADDROP_OFFER_LINE_LEN : D28_OFFER_LINE_LEN,
            deadline_ms) != 0) {
        fprintf(stderr, "unmoor: could not emit public offer\n");
        goto done;
    }
    if (config->pq_carrier_required != 0U) {
        if (read_public_line(STDIN_FILENO, response_line,
                             PQ_DEADDROP_RESPONSE_LINE_LEN,
                             deadline_ms) != 0 ||
            require_stream_eof(STDIN_FILENO, deadline_ms) != 0 ||
            pq_deaddrop_response_line_decode(
                response_line, PQ_DEADDROP_RESPONSE_LINE_LEN,
                &pq_status_offer, &pq_response) != 0) {
            fprintf(stderr,
                    "unmoor: malformed or mismatched deaddrop response; "
                    "attempt burned\n");
            (void)write_control(*control_fd, D28_CONTROL_BURN, deadline_ms);
            goto done;
        }
        if (pq_deaddrop_publish_response(attempt_fd, &pq_response) !=
            DEADDROP_OK ||
            (config->listener_monitor != 0U &&
             (pq_deaddrop_claim_response(attempt_fd, id,
                                         &pq_disk_response) != DEADDROP_OK ||
              !pq_responses_equal(&pq_response, &pq_disk_response))))
            goto publish_failed;
    } else {
        if (read_public_line(STDIN_FILENO, response_line,
                             D28_RESPONSE_LINE_LEN, deadline_ms) != 0 ||
            require_stream_eof(STDIN_FILENO, deadline_ms) != 0 ||
            d28_response_line_decode(response_line, D28_RESPONSE_LINE_LEN,
                                     &response) != 0 ||
            !response_matches_offer(&response, &status_offer)) {
            fprintf(stderr,
                    "unmoor: malformed or mismatched deaddrop response; "
                    "attempt burned\n");
            (void)write_control(*control_fd, D28_CONTROL_BURN, deadline_ms);
            goto done;
        }
        if (deaddrop_publish_response(attempt_fd, &response) != DEADDROP_OK ||
            (config->listener_monitor != 0U &&
             (deaddrop_claim_response(attempt_fd, id, &disk_response) !=
                  DEADDROP_OK ||
              !responses_equal(&response, &disk_response))))
            goto publish_failed;
    }
    if (write_control(*control_fd, D28_CONTROL_RESPONSE, deadline_ms) != 0 ||
        (config->listener_monitor != 0U &&
         (config->pq_carrier_required != 0U
              ? (pq_deaddrop_response_encode(&pq_disk_response,
                                             response_wire) != 0 ||
                 write_all_deadline(*control_fd, response_wire,
                                    PQ_DEADDROP_RESPONSE_SIZE,
                                    deadline_ms) != 0)
              : (deaddrop_response_encode(&disk_response, response_wire) !=
                     DEADDROP_OK ||
                 write_all_deadline(*control_fd, response_wire,
                                    DEADDROP_RESPONSE_RECORD_SIZE,
                                    deadline_ms) != 0)))) {
publish_failed:
        fprintf(stderr, "unmoor: could not publish one-shot response\n");
        goto done;
    }
    (void)close(*control_fd);
    *control_fd = -1;
    if (read_public_line(
            status_fd, accept_line,
            config->pq_carrier_required != 0U
                ? PQ_DEADDROP_ACCEPT_LINE_LEN : D28_ACCEPT_LINE_LEN,
            deadline_ms) != 0 ||
        (config->pq_carrier_required != 0U
             ? pq_deaddrop_accept_line_verify(
                   accept_line, PQ_DEADDROP_ACCEPT_LINE_LEN,
                   &pq_status_offer, &pq_response)
             : d28_accept_line_verify(accept_line, D28_ACCEPT_LINE_LEN,
                                      &response)) != 0) {
        fprintf(stderr,
                "unmoor: listener did not arm the exact accepted response\n");
        goto done;
    }
    if (write_public_line(
            STDOUT_FILENO, accept_line,
            config->pq_carrier_required != 0U
                ? PQ_DEADDROP_ACCEPT_LINE_LEN : D28_ACCEPT_LINE_LEN,
            deadline_ms) != 0) {
        fprintf(stderr, "unmoor: could not emit public acceptance\n");
        goto done;
    }
    /* ACCEPT is the last public carrier record.  Close the protocol stream
     * before a foreground parent waits for its owned listener child: real
     * OpenSSH cannot otherwise publish EOF, while the client correctly waits
     * for exact ACCEPT+EOF before it opens UDP. */
    if (close(STDOUT_FILENO) != 0) {
        fprintf(stderr,
                "unmoor: could not close the public acceptance stream\n");
        goto done;
    }
    if (!config->quiet_success) {
        fprintf(stderr,
                "unmoor: public deaddrop accepted; listener pid %ld armed\n",
                (long)child);
    }
    success = 1;

    if (config->foreground) {
        int waited = waitpid_nointr(child, &status, 0);
        if (waited == (int)child) {
            fprintf(stderr,
                    "unmoor: foreground listener child pid %ld reaped status %d\n",
                    (long)child,
                    WIFEXITED(status) ? WEXITSTATUS(status) : 128);
            runtime_child_pid = 0;
            *child_out = -1;
        }
        if (waited < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
            success = 0;
    } else {
        /* ACCEPT transfers exact-attempt cleanup to the detached child. */
        runtime_child_pid = 0;
        *child_out = -1;
    }

done:
    crypto_memzero(&status_offer, sizeof(status_offer));
    crypto_memzero(&disk_offer, sizeof(disk_offer));
    crypto_memzero(&response, sizeof(response));
    crypto_memzero(&disk_response, sizeof(disk_response));
    crypto_memzero(&pq_status_offer, sizeof(pq_status_offer));
    crypto_memzero(&pq_disk_offer, sizeof(pq_disk_offer));
    crypto_memzero(&pq_response, sizeof(pq_response));
    crypto_memzero(&pq_disk_response, sizeof(pq_disk_response));
    crypto_memzero(response_wire, sizeof(response_wire));
    crypto_memzero(offer_line, sizeof(offer_line));
    crypto_memzero(response_line, sizeof(response_line));
    crypto_memzero(accept_line, sizeof(accept_line));
    return success ? 0 : -1;
}

static int close_owned_fd(int *slot)
{
    int descriptor;

    if (slot == NULL) {
        errno = EINVAL;
        return -1;
    }
    descriptor = *slot;
    *slot = -1;
    return descriptor < 0 || close(descriptor) == 0 ? 0 : -1;
}

static int wait_exact_child_until(pid_t child, int64_t deadline_ms,
                                  int *status_out)
{
    if (child <= 0 || status_out == NULL) {
        errno = EINVAL;
        return -1;
    }
    for (;;) {
        pid_t result = waitpid(child, status_out, WNOHANG);
        if (result == child)
            return 0;
        if (result < 0 && errno != EINTR)
            return -1;
        if (monotonic_ms() >= deadline_ms) {
            errno = ETIMEDOUT;
            return -1;
        }
        if (poll(NULL, 0, 10) < 0 && errno != EINTR)
            return -1;
    }
}

static int wait_worker_ready(int fd, int64_t deadline_ms)
{
    uint8_t ready = 0;

    for (;;) {
        ssize_t amount;
        if (wait_fd(fd, POLLIN, deadline_ms) != 0)
            return -1;
        amount = read(fd, &ready, 1U);
        if (amount == 1)
            return ready == MONITOR_WORKER_READY ? 0 :
                (errno = EPROTO, -1);
        if (amount < 0 && errno == EINTR)
            continue;
        errno = amount == 0 ? EPIPE : (errno ? errno : EIO);
        return -1;
    }
}

static int wait_custody_launch(monitor_pty_custody_t *custody,
                               int64_t deadline_ms)
{
    while (custody != NULL &&
           custody->protocol.phase != MONITOR_PTY_IDLE) {
        monitor_pty_custody_wait_t interest;
        monitor_pty_custody_step_result_t result;
        int64_t remaining = deadline_ms - monotonic_ms();
        short revents = 0;

        if (remaining <= 0 || runtime_stop) {
            errno = runtime_stop ? EINTR : ETIMEDOUT;
            return -1;
        }
        memset(&interest, 0, sizeof(interest));
        if (monitor_pty_custody_interest(custody, &interest) != 0)
            return -1;
        if (!interest.immediate) {
            int timeout = remaining > INT_MAX ? INT_MAX : (int)remaining;
            if (poll_component(interest.fd, (short)interest.events,
                               timeout, &revents) <= 0) {
                if (errno == 0)
                    errno = ETIMEDOUT;
                return -1;
            }
        }
        result = monitor_pty_custody_step(custody, revents);
        if (result == MONITOR_PTY_CUSTODY_ERROR ||
            result == MONITOR_PTY_CUSTODY_ACTION ||
            result == MONITOR_PTY_CUSTODY_RESULT) {
            errno = result == MONITOR_PTY_CUSTODY_ERROR && errno
                ? errno : EPROTO;
            return -1;
        }
    }
    return custody != NULL ? 0 : (errno = EINVAL, -1);
}

static int endpoint_slot_used(const void *context, size_t slot)
{
    return sync_source_slot_used(context, slot);
}

static int monitor_shutdown_m_finish(monitor_shutdown_t *shutdown,
                                     int64_t deadline_ms)
{
    int worker_exit = 0;

    if (monitor_shutdown_m_request_stop(shutdown) != 0)
        return -1;
    for (;;) {
        monitor_shutdown_wait_t interest;
        monitor_shutdown_step_result_t result;
        int64_t remaining = deadline_ms - monotonic_ms();
        short revents = 0;

        if (remaining <= 0) {
            errno = ETIMEDOUT;
            return -1;
        }
        memset(&interest, 0, sizeof(interest));
        if (monitor_shutdown_interest(shutdown, &interest) != 0)
            return -1;
        if (!interest.immediate) {
            int timeout = remaining > INT_MAX ? INT_MAX : (int)remaining;
            if (poll_component(interest.fd, (short)interest.events,
                               timeout, &revents) <= 0) {
                if (errno == 0)
                    errno = ETIMEDOUT;
                return -1;
            }
        }
        result = monitor_shutdown_step(shutdown, revents);
        if (result == MONITOR_SHUTDOWN_ERROR)
            return -1;
        if (result == MONITOR_SHUTDOWN_RESULT)
            return monitor_shutdown_m_take_reaped(shutdown, &worker_exit) == 0 &&
                   worker_exit == MONITOR_SHUTDOWN_WORKER_EXIT
                ? 0 : (errno = EPROTO, -1);
    }
}

static _Noreturn void monitored_listener_m(
    const d28_listener_config_t *config,
    d28_endpoint_runner_fn runner,
    transport_t *transport,
    uint16_t bound_port,
    const uint8_t id[DEADDROP_ID_LEN],
    monitor_startup_bundle_t bundle,
    sync_source_map_t *map,
    int work_fd,
    int custody_c_endpoint,
    int custody_endpoint,
    int shutdown_c_endpoint,
    int shutdown_endpoint,
    uint64_t incarnation,
    uint64_t quota,
    pid_t custodian,
    int64_t deadline_ms)
{
    d28_monitor_endpoint_t endpoint;
    monitor_pty_custody_t custody;
    monitor_shutdown_t shutdown;
    listener_child_mode_t mode;
    size_t inventory_nrecords = 0U;
    int endpoint_prepared = 0;
    int custody_initialized = 0;
    int shutdown_initialized = 0;
    int worker_reaped = 0;
    int child_rc = 1;
    int result = 1;
    int inherited_log_fd;

    memset(&endpoint, 0, sizeof(endpoint));
    memset(&custody, 0, sizeof(custody));
    memset(&shutdown, 0, sizeof(shutdown));
    memset(&mode, 0, sizeof(mode));
    if (close_owned_fd(&custody_c_endpoint) != 0 ||
        close_owned_fd(&shutdown_c_endpoint) != 0)
        goto done;
    if (monitor_parent_guard(custodian) != 0 ||
        monitor_pty_custody_m_init(&custody, &custody_endpoint,
                                   incarnation) != 0)
        goto done;
    custody_initialized = 1;
    if (monitor_shutdown_m_init(&shutdown, &shutdown_endpoint) != 0)
        goto done;
    shutdown_initialized = 1;

    /* The inherited logging descriptor must be adopted before this call.
     * Re-open through a path is never permitted in monitored M. */
    inherited_log_fd = bundle.stderr_fd;
    bundle.stderr_fd = -1;
    if (prepare_listener_child(NULL, inherited_log_fd,
                               config->foreground,
                               config->debuggable) != 0)
        goto done;
    if (wait_custody_launch(&custody, deadline_ms) != 0 ||
        d28_monitor_endpoint_prepare(&endpoint, map, &custody, work_fd,
                                     incarnation, quota) != 0)
        goto done;
    endpoint_prepared = 1;
    inventory_nrecords = map->nrecords;
    if (monitor_role_install_m(custody.channel_fd) != 0)
        goto done;

    mode.monitor_endpoint = &endpoint;
    mode.environment_prepared = 1U;
    mode.cleanup_attempt = 0U;
    mode.parent_public_records = 1U;
    child_rc = listener_child_run(
        transport, bundle.parent_fd, bundle.attempt_fd, id, bound_port,
        bundle.status_write_fd, bundle.control_read_fd, deadline_ms,
        NULL, config->foreground, config->debuggable,
        config->application_profile, config->runner_context,
        &config->policy, config->pq_carrier_required, runner, &mode);
    transport = NULL;
    bundle.parent_fd = bundle.attempt_fd = -1;
    bundle.status_write_fd = bundle.control_read_fd = -1;

    if (close_owned_fd(&work_fd) != 0)
        goto done;
    if (monitor_shutdown_m_finish(
            &shutdown, monotonic_ms() + D49_LOCAL_SHUTDOWN_MS) != 0)
        goto done;
    worker_reaped = 1;
    if (sync_source_map_wipe_after_reap(
            map, inventory_nrecords, endpoint_slot_used,
            &endpoint.source) != SYNC_SOURCE_MAP_OK)
        goto done;
    result = child_rc;

done:
    if (work_fd >= 0)
        (void)close_owned_fd(&work_fd);
    if (endpoint_prepared &&
        d28_monitor_endpoint_dispose(&endpoint) != 0)
        result = 1;
    if (shutdown_initialized &&
        monitor_shutdown_dispose(&shutdown) != 0)
        result = 1;
    if (custody_initialized &&
        monitor_pty_custody_dispose(&custody) != 0)
        result = 1;
    if (sync_source_map_release(map) != SYNC_SOURCE_MAP_OK)
        result = 1;
    if (transport != NULL)
        transport_udp.close(transport);
    (void)close_owned_fd(&custody_endpoint);
    (void)close_owned_fd(&custody_c_endpoint);
    (void)close_owned_fd(&shutdown_endpoint);
    (void)close_owned_fd(&shutdown_c_endpoint);
    (void)close_owned_fd(&bundle.parent_fd);
    (void)close_owned_fd(&bundle.attempt_fd);
    (void)close_owned_fd(&bundle.status_write_fd);
    (void)close_owned_fd(&bundle.control_read_fd);
    (void)close_owned_fd(&bundle.stderr_fd);
    if (!worker_reaped)
        result = 1;
    _exit(result >= 0 && result <= 255 ? result : 1);
}

static int custody_terminal_result(pid_t monitor_pid, int *monitor_status,
                                   int cause)
{
    int64_t now;
    int original = cause > 0 ? cause : EIO;

    /* A terminal custody condition has no recovery path. Resolve it against
     * the exact M child rather than racing its final close against waitpid.
     * The caller still requires M=0, W=72 and a completed shutdown owner, so
     * this bounded reap cannot turn premature monitor death into success. */
    now = monotonic_ms();
    if (now >= 0 &&
        wait_exact_child_until(monitor_pid,
                               now + D49_LOCAL_SHUTDOWN_MS,
                               monitor_status) == 0)
        return 1;
    errno = original;
    return -1;
}

static int monitored_c_service(monitor_pty_custody_t *custody,
                               monitor_shutdown_t *shutdown,
                               pid_t monitor_pid,
                               pid_t *worker_pid,
                               const monitor_startup_bundle_t *bundle,
                               int *monitor_status,
                               int *role_installed)
{
    struct pollfd items[2];
    monitor_pty_custody_wait_t custody_interest;
    monitor_shutdown_wait_t shutdown_interest;
    nfds_t count = 0U;
    int ready;
    pid_t observed;

    if (custody == NULL || shutdown == NULL || monitor_pid <= 0 ||
        worker_pid == NULL || *worker_pid == 0 || *worker_pid < -1 ||
        bundle == NULL ||
        monitor_status == NULL || role_installed == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (custody->action != 0U) {
        if (monitor_pty_custody_perform_action(custody) != 0)
            return custody_terminal_result(monitor_pid, monitor_status, errno);
    }
    if (*role_installed == 0) {
        int role_ready = monitor_pty_custody_c_role_ready(custody);
        if (role_ready < 0)
            return custody_terminal_result(monitor_pid, monitor_status, errno);
        if (role_ready != 0) {
            monitor_custodian_role_config_t role =
                MONITOR_CUSTODIAN_ROLE_CONFIG_EMPTY;
            role.channel_fd = custody->channel_fd;
            role.children[0] = monitor_pid;
            role.children[1] = *worker_pid;
            role.children[2] = custody->child_pid;
            role.attempt_fds[0] = bundle->attempt_fd;
            role.attempt_fds[1] = bundle->parent_fd;
            role.child_count = MONITOR_ROLE_C_CHILDREN;
            role.attempt_count = MONITOR_ROLE_C_ATTEMPT_FDS;
            if (monitor_role_install_c(&role) != 0)
                return -1;
            *role_installed = 1;
        }
    }
    if (shutdown->role != 0U) {
        monitor_shutdown_step_result_t step =
            monitor_shutdown_step(shutdown, 0);
        if (step == MONITOR_SHUTDOWN_ERROR)
            return -1;
        if (step == MONITOR_SHUTDOWN_ACTION) {
            int status = 0;
            if (wait_exact_child_until(
                    *worker_pid,
                    monotonic_ms() + D49_LOCAL_SHUTDOWN_MS,
                    &status) != 0 ||
                monitor_shutdown_c_report_reaped(shutdown, status) != 0)
                return -1;
            *worker_pid = -1;
        }
    }
    observed = waitpid(monitor_pid, monitor_status, WNOHANG);
    if (observed == monitor_pid)
        return 1;
    if (observed < 0 && errno != EINTR)
        return -1;

    memset(&custody_interest, 0, sizeof(custody_interest));
    memset(&shutdown_interest, 0, sizeof(shutdown_interest));
    if (monitor_pty_custody_interest(custody, &custody_interest) != 0)
        return custody_terminal_result(monitor_pid, monitor_status, errno);
    if (custody_interest.immediate) {
        if (monitor_pty_custody_step(custody, 0) ==
            MONITOR_PTY_CUSTODY_ERROR)
            return custody_terminal_result(monitor_pid, monitor_status, errno);
    } else {
        items[count].fd = custody_interest.fd;
        items[count].events = (short)custody_interest.events;
        items[count].revents = 0;
        count++;
    }
    if (shutdown->role != 0U) {
        if (monitor_shutdown_interest(shutdown, &shutdown_interest) != 0)
            return -1;
        if (shutdown_interest.immediate) {
            if (monitor_shutdown_step(shutdown, 0) ==
                MONITOR_SHUTDOWN_ERROR)
                return -1;
        } else {
            items[count].fd = shutdown_interest.fd;
            items[count].events = (short)shutdown_interest.events;
            items[count].revents = 0;
            count++;
        }
    }
    do {
        ready = poll(items, count, 100);
    } while (ready < 0 && errno == EINTR && !runtime_stop);
    if (ready < 0 || runtime_stop)
        return -1;
    observed = waitpid(monitor_pid, monitor_status, WNOHANG);
    if (observed == monitor_pid)
        return 1;
    if (observed < 0 && errno != EINTR)
        return -1;
    for (nfds_t index = 0U; index < count; ++index) {
        if (items[index].fd == custody_interest.fd && items[index].revents != 0) {
            if (monitor_pty_custody_step(custody, items[index].revents) ==
                MONITOR_PTY_CUSTODY_ERROR)
                return custody_terminal_result(monitor_pid, monitor_status,
                                               errno);
        } else if (shutdown->role != 0U &&
                   items[index].fd == shutdown_interest.fd &&
                   items[index].revents != 0) {
            if (monitor_shutdown_step(shutdown, items[index].revents) ==
                MONITOR_SHUTDOWN_ERROR)
                return -1;
        }
    }
    return 0;
}

static _Noreturn void monitored_listener_c(
    const d28_listener_config_t *config,
    d28_endpoint_runner_fn runner,
    const traffic_profile_result_t *resolved_policy,
    const uint8_t id[DEADDROP_ID_LEN],
    uint64_t incarnation,
    uint64_t quota,
    pid_t parent,
    int64_t deadline_ms)
{
    monitor_startup_t startup;
    monitor_startup_bundle_t bundle = MONITOR_STARTUP_BUNDLE_EMPTY;
    monitor_pty_custody_t custody;
    monitor_shutdown_t shutdown;
    sync_source_map_t map;
    monitor_worker_birth_t birth;
    transport_config_t transport_config;
    transport_t *transport = NULL;
    int work[2] = {-1, -1};
    int custody_pair[2] = MONITOR_PTY_CUSTODY_PAIR_EMPTY;
    int shutdown_pair[2] = MONITOR_SHUTDOWN_PAIR_EMPTY;
    uint64_t saved_mask = 0U;
    uint16_t bound_port = 0U;
    pid_t worker = -1;
    pid_t monitor = -1;
    int startup_initialized = 0;
    int custody_initialized = 0;
    int shutdown_initialized = 0;
    int role_installed = 0;
    int monitor_status = 0;
    int monitor_reaped = 0;
    int success = 0;

    memset(&startup, 0, sizeof(startup));
    memset(&custody, 0, sizeof(custody));
    memset(&shutdown, 0, sizeof(shutdown));
    memset(&map, 0, sizeof(map));
    memset(&birth, 0, sizeof(birth));
    memset(&transport_config, 0, sizeof(transport_config));
    if (monitor_birth_fds() != 0 ||
        sync_source_map_create(&map, quota) != SYNC_SOURCE_MAP_OK ||
        stream_pair_cloexec_nonblock(work) != 0 ||
        work[0] != MONITOR_WORKER_FD ||
        work[1] != MONITOR_WORKER_OTHER_FD)
        goto done;

    birth.incarnation = incarnation;
    birth.quota = quota;
    birth.expected_c_pid = (int32_t)getpid();
    birth.direction = 1U;
    if (monitor_worker_block_for_fork(&saved_mask) != 0)
        goto done;
    worker = fork();
    if (worker == 0)
        monitor_worker_enter(&map, &birth);
    if (worker < 0 || monitor_worker_restore_after_fork(saved_mask) != 0)
        goto done;
    if (close_owned_fd(&work[0]) != 0 ||
        wait_worker_ready(work[1], deadline_ms) != 0)
        goto done;

    if (monitor_startup_child_init(
            &startup, id, parent, geteuid(), config->log_path != NULL,
            deadline_ms, monotonic_ms()) != 0)
        goto done;
    startup_initialized = 1;
    for (;;) {
        monitor_startup_result_t step =
            drive_monitor_startup(&startup, deadline_ms);
        if (step == MONITOR_STARTUP_ERROR)
            goto done;
        if (step == MONITOR_STARTUP_C_VALIDATE &&
            monitor_startup_child_approve(
                &startup, monotonic_ms()) != 0)
            goto done;
        if (step == MONITOR_STARTUP_DONE)
            break;
    }
    if (monitor_startup_child_take(&startup, &bundle) != 0 ||
        monitor_startup_dispose(&startup) != 0)
        goto done;
    startup_initialized = 0;

    transport_config.transport = "udp";
    transport_config.listen = 1;
    transport_config.udp_host = config->udp_bind_host;
    transport_config.udp_port = config->udp_port ? config->udp_port : "0";
    transport_config.udp_multipath_paths =
        resolved_policy->multipath_mode == TRAFFIC_MULTIPATH_MODE_NONE
            ? 0U : resolved_policy->configured_paths;
    transport_config.quiet_open_success =
        (uint8_t)(config->quiet_success != 0);
    transport_config.udp_bound_port_out = &bound_port;
    if (transport_udp.open(&transport_config, &transport) != 0 ||
        bound_port == 0U ||
        sync_source_map_enter_monitor(&map) != SYNC_SOURCE_MAP_OK ||
        monitor_pty_custody_pair_create(custody_pair) != 0 ||
        monitor_shutdown_pair_create(shutdown_pair) != 0)
        goto done;

    monitor = fork();
    if (monitor == 0)
        monitored_listener_m(
            config, runner, transport, bound_port, id, bundle, &map,
            work[1], custody_pair[0], custody_pair[1],
            shutdown_pair[0], shutdown_pair[1], incarnation,
            quota, getppid(), deadline_ms);
    if (monitor < 0)
        goto done;
    runtime_child_pid = monitor;
    transport_udp.close(transport);
    transport = NULL;
    if (close_owned_fd(&work[1]) != 0 ||
        close_owned_fd(&custody_pair[1]) != 0 ||
        close_owned_fd(&shutdown_pair[1]) != 0 ||
        close_owned_fd(&bundle.status_write_fd) != 0 ||
        close_owned_fd(&bundle.control_read_fd) != 0 ||
        close_owned_fd(&bundle.stderr_fd) != 0 ||
        sync_source_map_release(&map) != SYNC_SOURCE_MAP_OK)
        goto done;
    if (monitor_pty_custody_c_init(&custody, &custody_pair[0],
                                   incarnation, &map) != 0)
        goto done;
    custody_initialized = 1;
    if (monitor_shutdown_c_init(&shutdown, &shutdown_pair[0]) != 0)
        goto done;
    shutdown_initialized = 1;

    while (!monitor_reaped) {
        int service = monitored_c_service(
            &custody, &shutdown, monitor, &worker, &bundle,
            &monitor_status, &role_installed);
        if (service < 0)
            goto done;
        if (service > 0) {
            monitor_reaped = 1;
            monitor = -1;
        }
    }
    runtime_child_pid = 0;
    if (worker != -1 || shutdown.role != 0U ||
        !WIFEXITED(monitor_status) || WEXITSTATUS(monitor_status) != 0)
        goto done;
    if (cleanup_attempt(bundle.attempt_fd, bundle.parent_fd, id) != 0) {
        bundle.attempt_fd = bundle.parent_fd = -1;
        goto done;
    }
    bundle.attempt_fd = bundle.parent_fd = -1;
    success = 1;

done:
    runtime_child_pid = 0;
    if (monitor > 0)
        (void)terminate_and_reap(monitor);
    if (worker > 0)
        (void)terminate_and_reap(worker);
    if (custody_initialized)
        (void)monitor_pty_custody_dispose(&custody);
    if (shutdown_initialized)
        (void)monitor_shutdown_dispose(&shutdown);
    if (startup_initialized)
        (void)monitor_startup_dispose(&startup);
    if (transport != NULL)
        transport_udp.close(transport);
    (void)close_owned_fd(&work[0]);
    (void)close_owned_fd(&work[1]);
    (void)close_owned_fd(&custody_pair[0]);
    (void)close_owned_fd(&custody_pair[1]);
    (void)close_owned_fd(&shutdown_pair[0]);
    (void)close_owned_fd(&shutdown_pair[1]);
    (void)close_owned_fd(&bundle.status_write_fd);
    (void)close_owned_fd(&bundle.control_read_fd);
    (void)close_owned_fd(&bundle.stderr_fd);
    if (bundle.attempt_fd >= 0 || bundle.parent_fd >= 0) {
        if (cleanup_attempt(bundle.attempt_fd, bundle.parent_fd, id) != 0)
            success = 0;
        bundle.attempt_fd = bundle.parent_fd = -1;
    }
    (void)sync_source_map_release(&map);
    _exit(success ? 0 : 1);
}

static int monitored_public_prepare(const d28_listener_config_t *config,
                                    const char *path,
                                    const uint8_t id[DEADDROP_ID_LEN],
                                    int *parent_fd,
                                    int *attempt_fd,
                                    int status_pipe[2],
                                    int control_pipe[2],
                                    int *log_fd,
                                    monitor_startup_bundle_t *bundle)
{
    if (open_or_create_parent(path, parent_fd) != 0 ||
        deaddrop_attempt_create(*parent_fd, id, attempt_fd) != DEADDROP_OK ||
        pipe_cloexec(status_pipe) != 0 ||
        pipe_cloexec(control_pipe) != 0)
        return -1;
    if (config->log_path != NULL) {
        *log_fd = open_listener_log(config->log_path);
        if (*log_fd < 0)
            return -1;
    }
    bundle->parent_fd = *parent_fd;
    bundle->attempt_fd = *attempt_fd;
    bundle->status_write_fd = status_pipe[1];
    bundle->control_read_fd = control_pipe[0];
    bundle->stderr_fd = *log_fd;
    return 0;
}

static int d28_runtime_listen_monitored(
    const d28_listener_config_t *config,
    d28_endpoint_runner_fn runner,
    const traffic_profile_result_t *resolved_policy,
    const char *path,
    int64_t deadline_ms)
{
    monitor_startup_t startup;
    monitor_startup_bundle_t bundle = MONITOR_STARTUP_BUNDLE_EMPTY;
    uint8_t id[DEADDROP_ID_LEN];
    int status_pipe[2] = {-1, -1};
    int control_pipe[2] = {-1, -1};
    int parent_fd = -1;
    int attempt_fd = -1;
    int log_fd = -1;
    int attempt_owned = 0;
    int startup_initialized = 0;
    int public_made = 0;
    int startup_done = 0;
    int success = 0;
    uint64_t incarnation = 0U;
    uint64_t quota = sync_classic_backlog_quota();
    pid_t custodian = -1;

    memset(&startup, 0, sizeof(startup));
    crypto_memzero(id, sizeof(id));
    if (d28_drop_id_generate(id) != 0)
        goto done;
    memcpy(&incarnation, id, sizeof(incarnation));
    if (incarnation == 0U)
        incarnation = 1U;
    (void)fflush(NULL);
    custodian = fork();
    if (custodian == 0)
        monitored_listener_c(config, runner, resolved_policy, id,
                             incarnation, quota, getppid(), deadline_ms);
    if (custodian < 0)
        goto done;
    runtime_child_pid = custodian;
    if (monitor_startup_parent_init(
            &startup, id, custodian, geteuid(), config->log_path != NULL,
            deadline_ms, monotonic_ms()) != 0)
        goto done;
    startup_initialized = 1;
    while (!startup_done) {
        monitor_startup_result_t step =
            drive_monitor_startup(&startup, deadline_ms);
        if (step == MONITOR_STARTUP_ERROR)
            goto done;
        if (step == MONITOR_STARTUP_P_BUNDLE) {
            if (public_made)
                goto done;
            if (monitored_public_prepare(
                    config, path, id, &parent_fd, &attempt_fd,
                    status_pipe, control_pipe, &log_fd, &bundle) != 0) {
                attempt_owned = parent_fd >= 0 && attempt_fd >= 0;
                goto done;
            }
            public_made = 1;
            attempt_owned = 1;
            if (monitor_startup_parent_offer(
                    &startup, &bundle, monotonic_ms()) != 0)
                goto done;
        }
        if (step == MONITOR_STARTUP_P_ACQUIRED) {
            if (!public_made ||
                close_owned_fd(&status_pipe[1]) != 0 ||
                close_owned_fd(&control_pipe[0]) != 0 ||
                close_owned_fd(&log_fd) != 0 ||
                monitor_startup_parent_commit(
                    &startup, monotonic_ms()) != 0)
                goto done;
        }
        if (step == MONITOR_STARTUP_DONE)
            startup_done = 1;
    }
    if (monitor_startup_dispose(&startup) != 0)
        goto done;
    startup_initialized = 0;
    if (listener_parent_relay(
            config, custodian, parent_fd, attempt_fd, id,
            status_pipe[0], &control_pipe[1], deadline_ms,
            &custodian) != 0)
        goto done;
    success = 1;
    attempt_owned = 0;

done:
    if (!success && custodian > 0)
        (void)terminate_and_reap(custodian);
    runtime_child_pid = 0;
    if (startup_initialized)
        (void)monitor_startup_dispose(&startup);
    (void)close_owned_fd(&status_pipe[0]);
    (void)close_owned_fd(&status_pipe[1]);
    (void)close_owned_fd(&control_pipe[0]);
    (void)close_owned_fd(&control_pipe[1]);
    (void)close_owned_fd(&log_fd);
    if (!success && attempt_owned) {
        if (cleanup_attempt(attempt_fd, parent_fd, id) != 0)
            success = 0;
        attempt_fd = parent_fd = -1;
    } else {
        (void)close_owned_fd(&attempt_fd);
        (void)close_owned_fd(&parent_fd);
    }
    crypto_memzero(id, sizeof(id));
    return success ? 0 : 1;
}

int d28_runtime_listen(const d28_listener_config_t *config,
                       d28_endpoint_runner_fn runner)
{
    transport_config_t transport_config;
    traffic_profile_result_t resolved_policy;
    transport_t *transport = NULL;
    uint8_t id[DEADDROP_ID_LEN];
    uint16_t bound_port = 0;
    int status_pipe[2] = { -1, -1 };
    int control_pipe[2] = { -1, -1 };
    int parent_fd = -1;
    int attempt_fd = -1;
    int64_t now;
    int64_t deadline_ms;
    char parent_path[PATH_MAX];
    char attempt_path[PATH_MAX];
    char attempt_name[DEADDROP_ID_HEX_LEN + 1U];
    const char *path;
    pid_t child = -1;
    int success = 0;
    int attempt_owned = 0;

    crypto_memzero(id, sizeof(id));
    if (!config || !runner ||
        d28_application_profile_required_caps(
            config->application_profile) == 0 ||
        !parse_timeout(config->timeout_secs) ||
        config->pq_carrier_required > 1U ||
        config->server_confine > 1U ||
        (config->server_confine != 0U &&
         config->application_profile != D28_APPLICATION_PROFILE_BULK_D33) ||
        (config->quiet_success != 0 && config->quiet_success != 1) ||
        (config->debuggable != 0 && config->debuggable != 1) ||
        config->listener_monitor > 1U ||
        (config->listener_monitor != 0U &&
         (config->application_profile != D28_APPLICATION_PROFILE_TERMINAL ||
          config->policy.channelised != 0U || config->debuggable != 0)) ||
        runtime_policy_resolve(&config->policy,
                               config->application_profile,
                               &resolved_policy) != 0 ||
        reject_secret_environment(config->application_profile) != 0 ||
        ensure_standard_fds() != 0 ||
        install_runtime_handlers() != 0) {
        fprintf(stderr, "unmoor: invalid deaddrop listener configuration\n");
        return 1;
    }
    if (config->listener_monitor != 0U) {
        if (!listener_monitor_native_supported()) {
            fprintf(stderr,
                    "listen: --listener-monitor requires native Linux x86_64 or aarch64\n");
            return 1;
        }
    }
    now = monotonic_ms();
    if (now < 0)
        return 1;
    deadline_ms = now + (int64_t)config->timeout_secs * INT64_C(1000);

    path = config->deaddrop_parent;
    if (!path) {
        if (default_parent_path(parent_path) != 0) {
            fprintf(stderr, "unmoor: HOME is not an absolute deaddrop parent\n");
            goto cleanup;
        }
        path = parent_path;
    }
    if (config->listener_monitor != 0U)
        return d28_runtime_listen_monitored(
            config, runner, &resolved_policy, path, deadline_ms);
    if (open_or_create_parent(path, &parent_fd) != 0) {
        fprintf(stderr, "unmoor: unsafe deaddrop parent '%s': %s\n",
                path, strerror(errno));
        goto cleanup;
    }
    if (d28_drop_id_generate(id) != 0) {
        fprintf(stderr, "unmoor: could not generate one-shot deaddrop id\n");
        goto cleanup;
    }
    if (deaddrop_attempt_create(parent_fd, id, &attempt_fd) != DEADDROP_OK) {
        fprintf(stderr, "unmoor: could not create one-shot deaddrop attempt\n");
        goto cleanup;
    }
    attempt_owned = 1;
    if (config->server_confine != 0U) {
        int path_length;

        if (deaddrop_id_to_hex(id, attempt_name) != DEADDROP_OK) {
            fprintf(stderr,
                    "unmoor: could not name one-shot confinement scope\n");
            goto cleanup;
        }
        path_length = snprintf(attempt_path, sizeof(attempt_path), "%s/%s",
                               path, attempt_name);
        if (path_length <= 0 ||
            (size_t)path_length >= sizeof(attempt_path) ||
            confine_scope_set_cleanup_dirs("bulk-server", path,
                                           attempt_path) != 0)
            goto cleanup;
    }

    memset(&transport_config, 0, sizeof(transport_config));
    transport_config.transport = "udp";
    transport_config.listen = 1;
    transport_config.udp_host = config->udp_bind_host;
    transport_config.udp_port = config->udp_port ? config->udp_port : "0";
    transport_config.udp_multipath_paths =
        resolved_policy.multipath_mode == TRAFFIC_MULTIPATH_MODE_NONE
            ? 0U : resolved_policy.configured_paths;
    transport_config.quiet_open_success =
        (uint8_t)(config->quiet_success != 0);
    transport_config.udp_bound_port_out = &bound_port;
    if (transport_udp.open(&transport_config, &transport) != 0 ||
        bound_port == 0) {
        fprintf(stderr, "unmoor: deaddrop UDP bind failed\n");
        goto cleanup;
    }
    if (pipe_cloexec(status_pipe) != 0 || pipe_cloexec(control_pipe) != 0) {
        fprintf(stderr, "unmoor: deaddrop status pipe failed: %s\n",
                strerror(errno));
        goto cleanup;
    }
    (void)fflush(NULL);
    child = fork();
    if (child < 0) {
        fprintf(stderr, "unmoor: deaddrop listener fork failed: %s\n",
                strerror(errno));
        goto cleanup;
    }
    if (child == 0) {
        int child_rc;
        (void)close(status_pipe[0]);
        (void)close(control_pipe[1]);
        child_rc = listener_child_run(
            transport, parent_fd, attempt_fd, id, bound_port,
            status_pipe[1], control_pipe[0], deadline_ms,
            config->log_path, config->foreground,
            config->debuggable,
            config->application_profile, config->runner_context,
            &config->policy, config->pq_carrier_required, runner,
            &ordinary_listener_child);
        _exit(child_rc);
    }
    runtime_child_pid = child;
    transport_udp.close(transport);
    transport = NULL;
    (void)close(status_pipe[1]);
    status_pipe[1] = -1;
    (void)close(control_pipe[0]);
    control_pipe[0] = -1;

    if (listener_parent_relay(config, child, parent_fd, attempt_fd, id,
                              status_pipe[0], &control_pipe[1], deadline_ms,
                              &child) != 0)
        goto cleanup;
    success = 1;
    (void)close(status_pipe[0]);
    status_pipe[0] = -1;
    (void)close(attempt_fd);
    attempt_fd = -1;
    (void)close(parent_fd);
    parent_fd = -1;
    /* The detached child already owns cleanup; a successful foreground child
     * performed it before the exact wait above returned. */
    attempt_owned = 0;

cleanup:
    if (!success && child > 0)
        (void)terminate_and_reap(child);
    runtime_child_pid = 0;
    if (transport)
        transport_udp.close(transport);
    if (status_pipe[0] >= 0)
        (void)close(status_pipe[0]);
    if (status_pipe[1] >= 0)
        (void)close(status_pipe[1]);
    if (control_pipe[0] >= 0)
        (void)close(control_pipe[0]);
    if (control_pipe[1] >= 0)
        (void)close(control_pipe[1]);
    if (!success && attempt_owned &&
        cleanup_attempt(attempt_fd, parent_fd, id) != 0) {
        attempt_fd = -1;
        parent_fd = -1;
    } else if (!attempt_owned) {
        if (attempt_fd >= 0)
            (void)close(attempt_fd);
        if (parent_fd >= 0)
            (void)close(parent_fd);
    }
    crypto_memzero(id, sizeof(id));
    return success ? 0 : 1;
}

static int confine_level_word_valid(const char *level)
{
    return level != NULL &&
        (strcmp(level, "off") == 0 || strcmp(level, "best-effort") == 0 ||
         strcmp(level, "require") == 0);
}

static int build_remote_command(const d28_ssh_connect_config_t *config,
                                int pq_hybrid, char out[PATH_MAX])
{
    const char *pace = getenv("UNMOOR_PACE_BPS");
    char multipath[32] = "";
    char profile[32] = "";
    char log_format[32] = "";
    char bind_host[288] = "";
    char bulk_options[96] = "";
    char server_confine[48] = "";
    const char *channelised = config->policy.channelised != 0U
        ? " --channelised" : "";
    const char *listener_monitor = config->listener_monitor != 0U
        ? " --listener-monitor" : "";
    const char *foreground = config->remote_foreground ?
                             " --bootstrap-foreground" : "";
    const char *pq_carrier = pq_hybrid ? " --pq-carrier=require" : "";
    int count;

    if (!valid_remote_command(config->remote_command) ||
        !valid_remote_bind_host(config->remote_bind_host) ||
        config->listener_monitor > 1U ||
        (config->listener_monitor != 0U &&
         (config->application_profile != D28_APPLICATION_PROFILE_TERMINAL ||
          config->policy.channelised != 0U ||
          config->attach_socket_path != NULL)) ||
        (config->remote_confine_level != NULL &&
         (config->application_profile != D28_APPLICATION_PROFILE_BULK_D33 ||
          !confine_level_word_valid(config->remote_confine_level))))
        return -1;
    if (config->remote_confine_level != NULL &&
        snprintf(server_confine, sizeof(server_confine), " --confine %s",
                 config->remote_confine_level) <= 0)
        return -1;
    if (config->policy.multipath_option == TRAFFIC_MULTIPATH_OPTION_BARE) {
        if (snprintf(multipath, sizeof(multipath), " --multipath") <= 0)
            return -1;
    } else if (config->policy.multipath_option ==
               TRAFFIC_MULTIPATH_OPTION_EXACT) {
        if (!multipath_path_count_valid(config->policy.exact_paths) ||
            snprintf(multipath, sizeof(multipath), " --multipath=%u",
                     (unsigned int)config->policy.exact_paths) <= 0)
            return -1;
    }
    if (traffic_profile_name(config->policy.traffic_profile) == NULL)
        return -1;
    /* Preserve one-version-old epoch-rekey bootstrap compatibility. Enterprise is
     * the new local default and text is the historical output, so neither
     * default token may be placed in the remote command: a pre-traffic-profile peer
     * would reject it before capability-negotiation can negotiate fallback. Non-default policy
     * remains explicit and therefore fails loudly on an old endpoint. */
    if (config->policy.traffic_profile != TRAFFIC_PROFILE_ENTERPRISE &&
        snprintf(profile, sizeof(profile), " --profile %s",
                 traffic_profile_name(config->policy.traffic_profile)) <= 0)
        return -1;
    if (config->policy.log_format != EVENT_LOG_FORMAT_TEXT &&
        config->policy.log_format != EVENT_LOG_FORMAT_JSON)
        return -1;
    if (config->policy.log_format == EVENT_LOG_FORMAT_JSON &&
        snprintf(log_format, sizeof(log_format),
                 " --log-format json") <= 0)
        return -1;
    if (config->remote_bind_host &&
        snprintf(bind_host, sizeof(bind_host), " --bind-host %s",
                 config->remote_bind_host) <= 0)
        return -1;
    if (config->application_profile == D28_APPLICATION_PROFILE_BULK_D33) {
        if (!bulk_wire_budget_valid(config->bulk_wire_budget) ||
            config->bulk_stall_secs < 1 ||
            config->bulk_stall_secs >
                (int)(BULK_ENGINE_STALL_MAX_MS / INT64_C(1000)) ||
            snprintf(bulk_options, sizeof(bulk_options),
                     " --bulk-mtu %u --bulk-stall-secs %d",
                     (unsigned int)config->bulk_wire_budget,
                     config->bulk_stall_secs) <= 0)
            return -1;
    } else if (config->bulk_wire_budget != 0U ||
               config->bulk_stall_secs != 0) {
        return -1;
    }
    if (pace && !valid_decimal_environment(pace)) {
        fprintf(stderr,
                "unmoor: UNMOOR_PACE_BPS must be decimal bytes/s\n");
        return -1;
    }
    if (pace && strspn(pace, "0") != strlen(pace)) {
        if (config->application_profile ==
            D28_APPLICATION_PROFILE_BULK_D33) {
            count = snprintf(out, PATH_MAX,
                             "UNMOOR_PACE_BPS=%s exec %s --bulk-server "
                             "--timeout %d%s%s%s%s%s%s%s%s",
                             pace, config->remote_command,
                             config->timeout_secs, bulk_options,
                             server_confine, bind_host, profile, log_format,
                             multipath,
                             foreground, pq_carrier);
        } else {
            count = snprintf(out, PATH_MAX,
                             "UNMOOR_PACE_BPS=%s exec %s listen "
                             "--deaddrop-bootstrap%s --timeout %d%s%s%s%s%s%s%s",
                             pace, config->remote_command,
                             listener_monitor, config->timeout_secs,
                             bind_host, profile,
                             log_format, multipath, channelised, foreground,
                             pq_carrier);
        }
    } else {
        if (config->application_profile ==
            D28_APPLICATION_PROFILE_BULK_D33) {
            count = snprintf(out, PATH_MAX,
                             "exec %s --bulk-server --timeout %d%s%s%s%s%s%s%s%s",
                             config->remote_command, config->timeout_secs,
                             bulk_options, server_confine, bind_host, profile,
                             log_format, multipath, foreground, pq_carrier);
        } else {
            count = snprintf(
                out, PATH_MAX,
                "exec %s listen --deaddrop-bootstrap%s --timeout %d%s%s%s%s%s%s%s",
                config->remote_command, listener_monitor,
                config->timeout_secs,
                bind_host, profile, log_format, multipath, channelised,
                foreground, pq_carrier);
        }
    }
    return count > 0 && count < PATH_MAX ? 0 : -1;
}

/* Every carrier child, including the feature probe, keeps the parent's
 * stderr: OpenSSH prints its pre-authentication banner and diagnostics
 * there, and they belong to the operator rather than to a captured stream. */
static pid_t spawn_argv(char *const arguments[],
                        int to_child[2], int from_child[2])
{
    pid_t pid;

    (void)fflush(NULL);
    pid = fork();
    if (pid == 0) {
        process_reset_child_signals();
        if (dup2(to_child[0], STDIN_FILENO) < 0 ||
            dup2(from_child[1], STDOUT_FILENO) < 0)
            _exit(126);
        (void)close(to_child[0]);
        (void)close(to_child[1]);
        (void)close(from_child[0]);
        (void)close(from_child[1]);
        if (process_close_from(STDERR_FILENO + 1, NULL, 0U) != 0)
            _exit(126);
        execvp(arguments[0], arguments);
        fprintf(stderr, "unmoor: exec %s failed: %s\n",
                arguments[0], strerror(errno));
        _exit(127);
    }
    return pid;
}

static pid_t spawn_ssh(const d28_ssh_connect_config_t *config,
                       const char *remote_command,
                       int to_child[2], int from_child[2])
{
    char **arguments;
    pid_t pid;
    int i;
    int output = 0;

    arguments = calloc((size_t)config->ssh_argc + 5U, sizeof(*arguments));
    if (!arguments)
        return -1;
    arguments[output++] = (char *)"ssh";
    for (i = 0; i + 1 < config->ssh_argc; i++)
        arguments[output++] = config->ssh_argv[i];
    arguments[output++] = (char *)"--";
    arguments[output++] = config->ssh_argv[config->ssh_argc - 1];
    arguments[output++] = (char *)remote_command;
    arguments[output] = NULL;
    pid = spawn_argv(arguments, to_child, from_child);
    free(arguments);
    return pid;
}

#define D45_PROBE_OUTPUT_MAX 128U

/* Only the probe's stdout is captured, one byte at a time, within the fixed
 * bound.  Its stderr is inherited, so a banner or diagnostic of any length
 * neither consumes this bound nor waits on a pipe this process must drain. */
static int capture_probe_stdout(int stdout_fd,
                                uint8_t stdout_bytes[D45_PROBE_OUTPUT_MAX],
                                size_t *stdout_len, int64_t deadline_ms)
{
    struct pollfd stream;
    size_t length = 0U;

    if (!stdout_len)
        return -1;
    memset(&stream, 0, sizeof(stream));
    stream.fd = stdout_fd;
    stream.events = POLLIN;
    for (;;) {
        int64_t now = monotonic_ms();
        int64_t remaining;
        int timeout;
        int ready;
        uint8_t byte;
        ssize_t count;

        if (runtime_stop || now < 0)
            return -1;
        remaining = deadline_ms - now;
        if (remaining <= 0) {
            errno = ETIMEDOUT;
            return -1;
        }
        timeout = remaining > INT_MAX ? INT_MAX : (int)remaining;
        ready = poll(&stream, 1, timeout);
        if (ready < 0 && errno == EINTR)
            continue;
        if (ready <= 0) {
            if (ready == 0)
                errno = ETIMEDOUT;
            return -1;
        }
        count = read(stream.fd, &byte, 1U);
        if (count == 0)
            break;
        if (count < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (length >= D45_PROBE_OUTPUT_MAX) {
            errno = EOVERFLOW;
            return -1;
        }
        stdout_bytes[length++] = byte;
    }
    *stdout_len = length;
    return 0;
}

static pq_probe_result_t run_ssh_pq_probe(
    const d28_ssh_connect_config_t *config, int64_t deadline_ms)
{
    int to_probe[2] = { -1, -1 };
    int from_probe[2] = { -1, -1 };
    uint8_t stdout_bytes[D45_PROBE_OUTPUT_MAX];
    size_t stdout_len = 0U;
    char command[PATH_MAX];
    pid_t child = -1;
    int status = 0;
    int waited = 0;
    pq_probe_result_t result = PQ_PROBE_ERROR;

    memset(stdout_bytes, 0, sizeof(stdout_bytes));
    if (!config || !valid_remote_command(config->remote_command) ||
        snprintf(command, sizeof(command), "%s version --pq-probe",
                 config->remote_command) <= 0 ||
        pipe_cloexec(to_probe) != 0 || pipe_cloexec(from_probe) != 0)
        goto cleanup;
    /* The same spawn as the bootstrap carrier: stdin and stdout piped,
     * stderr inherited.  Exact stdout and exit status decide the result. */
    child = spawn_ssh(config, command, to_probe, from_probe);
    if (child < 0)
        goto cleanup;
    runtime_child_pid = child;
    (void)close(to_probe[0]);
    to_probe[0] = -1;
    (void)close(to_probe[1]);
    to_probe[1] = -1;
    (void)close(from_probe[1]);
    from_probe[1] = -1;
    if (capture_probe_stdout(from_probe[0], stdout_bytes, &stdout_len,
                             deadline_ms) != 0)
        goto cleanup;
    {
        int64_t remaining = deadline_ms - monotonic_ms();
        int grace = remaining > INT_MAX ? INT_MAX : (int)remaining;
        if (grace <= 0)
            goto cleanup;
        waited = wait_child_grace(child, grace, &status);
    }
    if (waited != 1)
        goto cleanup;
    child = -1;
    runtime_child_pid = 0;
    result = pq_probe_classify(
        stdout_bytes, stdout_len,
        WIFEXITED(status) ? 1 : 0,
        WIFEXITED(status) ? WEXITSTATUS(status) : 0);

cleanup:
    if (to_probe[0] >= 0)
        (void)close(to_probe[0]);
    if (to_probe[1] >= 0)
        (void)close(to_probe[1]);
    if (from_probe[0] >= 0)
        (void)close(from_probe[0]);
    if (from_probe[1] >= 0)
        (void)close(from_probe[1]);
    if (child > 0)
        (void)terminate_and_reap(child);
    runtime_child_pid = 0;
    crypto_memzero(stdout_bytes, sizeof(stdout_bytes));
    crypto_memzero(command, sizeof(command));
    return result;
}

#define D28_EXEC_ARGV_MAX 32U

typedef struct d28_exec_arguments {
    char *argv[D28_EXEC_ARGV_MAX];
    char timeout[16];
    char wire_budget[16];
    char stall_seconds[16];
    char pace_bps[32];
    char multipath[32];
} d28_exec_arguments_t;

static int append_exec_argument(d28_exec_arguments_t *arguments,
                                size_t *count, char *value)
{
    if (!arguments || !count || !value ||
        *count + 1U >= D28_EXEC_ARGV_MAX)
        return -1;
    arguments->argv[(*count)++] = value;
    arguments->argv[*count] = NULL;
    return 0;
}

/* child-transfer no-shell carrier. Only public policy appears in argv. The epoch-rekey
 * offer/response/accept records still cross the same pipes below. */
static int build_exec_arguments(const d28_ssh_connect_config_t *config,
                                d28_exec_arguments_t *arguments)
{
    const char *pace = getenv("UNMOOR_PACE_BPS");
    const char *profile;
    size_t count = 0U;
    int timeout_count;
    int budget_count;
    int stall_count;
    int pace_count;

    if (!config || !arguments ||
        config->application_profile != D28_APPLICATION_PROFILE_BULK_D33 ||
        !config->attach_socket_path ||
        !attach_local_path_fits(config->attach_socket_path) ||
        !config->local_command || config->local_command[0] == '\0' ||
        !confine_level_word_valid(config->local_confine_level) ||
        (config->remote_confine_level != NULL &&
         !confine_level_word_valid(config->remote_confine_level)) ||
        !valid_remote_command(config->remote_command) ||
        !valid_remote_bind_host(config->remote_bind_host) ||
        config->remote_foreground ||
        !bulk_wire_budget_valid(config->bulk_wire_budget) ||
        config->bulk_stall_secs < 1 ||
        config->bulk_stall_secs >
            (int)(BULK_ENGINE_STALL_MAX_MS / INT64_C(1000)) ||
        (pace && !valid_decimal_environment(pace)))
        return -1;

    profile = traffic_profile_name(config->policy.traffic_profile);
    timeout_count = snprintf(arguments->timeout, sizeof(arguments->timeout),
                             "%d", config->timeout_secs);
    budget_count = snprintf(arguments->wire_budget,
                            sizeof(arguments->wire_budget), "%u",
                            (unsigned int)config->bulk_wire_budget);
    stall_count = snprintf(arguments->stall_seconds,
                           sizeof(arguments->stall_seconds), "%d",
                           config->bulk_stall_secs);
    pace_count = snprintf(arguments->pace_bps, sizeof(arguments->pace_bps),
                          "%s", pace && pace[0] != '\0' ? pace : "0");
    if (!profile || timeout_count <= 0 ||
        (size_t)timeout_count >= sizeof(arguments->timeout) ||
        budget_count <= 0 ||
        (size_t)budget_count >= sizeof(arguments->wire_budget) ||
        stall_count <= 0 ||
        (size_t)stall_count >= sizeof(arguments->stall_seconds) ||
        pace_count <= 0 ||
        (size_t)pace_count >= sizeof(arguments->pace_bps))
        return -1;

#define APPEND(value) do { \
        if (append_exec_argument(arguments, &count, (char *)(value)) != 0) \
            return -1; \
    } while (0)
    APPEND(config->local_command);
    APPEND("attach");
    APPEND("--socket");
    APPEND(config->attach_socket_path);
    APPEND("--confine");
    APPEND(config->local_confine_level);
    APPEND("exec");
    APPEND("--");
    APPEND(config->remote_command);
    APPEND("--bulk-server");
    if (config->remote_confine_level != NULL) {
        APPEND("--confine");
        APPEND(config->remote_confine_level);
        APPEND("--bootstrap-exec-carrier");
    }
    APPEND("--timeout");
    APPEND(arguments->timeout);
    APPEND("--bulk-mtu");
    APPEND(arguments->wire_budget);
    APPEND("--bulk-stall-secs");
    APPEND(arguments->stall_seconds);
    if (config->remote_bind_host) {
        APPEND("--bind-host");
        APPEND(config->remote_bind_host);
    }
    if (config->policy.traffic_profile != TRAFFIC_PROFILE_ENTERPRISE) {
        APPEND("--profile");
        APPEND(profile);
    }
    if (config->policy.log_format == EVENT_LOG_FORMAT_JSON) {
        APPEND("--log-format");
        APPEND("json");
    } else if (config->policy.log_format != EVENT_LOG_FORMAT_TEXT) {
        return -1;
    }
    if (config->policy.multipath_option == TRAFFIC_MULTIPATH_OPTION_BARE) {
        APPEND("--multipath");
    } else if (config->policy.multipath_option ==
               TRAFFIC_MULTIPATH_OPTION_EXACT) {
        if (!multipath_path_count_valid(config->policy.exact_paths) ||
            snprintf(arguments->multipath, sizeof(arguments->multipath),
                     "--multipath=%u",
                     (unsigned int)config->policy.exact_paths) <= 0)
            return -1;
        APPEND(arguments->multipath);
    } else if (config->policy.multipath_option !=
               TRAFFIC_MULTIPATH_OPTION_NONE) {
        return -1;
    }
    APPEND("--pace-bps");
    APPEND(arguments->pace_bps);
    APPEND("--bootstrap-quiet");
    if (config->pq_carrier_required != 0U)
        APPEND("--pq-carrier=require");
#undef APPEND
    return 0;
}

int d28_runtime_ssh_connect(const d28_ssh_connect_config_t *config,
                            d28_endpoint_runner_fn runner)
{
    deaddrop_offer_t offer;
    deaddrop_response_t response;
    pq_deaddrop_offer_t pq_offer;
    pq_deaddrop_response_t pq_response;
    transport_config_t transport_config;
    traffic_profile_result_t resolved_policy;
    transport_t *transport = NULL;
    uint8_t root[32];
    uint8_t pair_seed[4];
    int to_ssh[2] = { -1, -1 };
    int from_ssh[2] = { -1, -1 };
    int64_t now;
    int64_t deadline_ms;
    char remote_command[PATH_MAX];
    char port[6];
    char offer_line[PQ_DEADDROP_OFFER_LINE_LEN + 1U];
    char response_line[PQ_DEADDROP_RESPONSE_LINE_LEN + 1U];
    char accept_line[PQ_DEADDROP_ACCEPT_LINE_LEN + 1U];
    char fingerprint[EPOCH_CRYPTO_FINGERPRINT_TEXT_BUFSZ];
    d28_exec_arguments_t exec_arguments;
    d28_endpoint_policy_t effective_policy;
    pid_t ssh_pid = -1;
    sigset_t blocked;
    sigset_t previous;
    int signals_blocked = 0;
    int runner_called = 0;
    int ssh_status = 0;
    int use_exec_carrier = 0;
    int use_pq = 0;
    int rc = 1;

    memset(&offer, 0, sizeof(offer));
    memset(&response, 0, sizeof(response));
    memset(&pq_offer, 0, sizeof(pq_offer));
    memset(&pq_response, 0, sizeof(pq_response));
    memset(&exec_arguments, 0, sizeof(exec_arguments));
    memset(&effective_policy, 0, sizeof(effective_policy));
    crypto_memzero(root, sizeof(root));
    crypto_memzero(pair_seed, sizeof(pair_seed));
    if (!config || !runner ||
        d28_application_profile_required_caps(
            config->application_profile) == 0 ||
        !pq_policy_valid(config->pq_policy) ||
        config->pq_carrier_required > 1U ||
        config->listener_monitor > 1U ||
        (config->listener_monitor != 0U &&
         (config->application_profile != D28_APPLICATION_PROFILE_TERMINAL ||
          config->policy.channelised != 0U ||
          config->attach_socket_path != NULL)) ||
        (config->remote_confine_level != NULL &&
         (config->application_profile != D28_APPLICATION_PROFILE_BULK_D33 ||
          !confine_level_word_valid(config->remote_confine_level))) ||
        !config->udp_host ||
        config->udp_host[0] == '\0' || !parse_timeout(config->timeout_secs) ||
        runtime_policy_resolve(&config->policy,
                               config->application_profile,
                               &resolved_policy) != 0 ||
        config->udp_port_layout > TRANSPORT_UDP_PORT_LAYOUT_RANDOM ||
        config->udp_port_mask_explicit > 1U ||
        (resolved_policy.multipath_mode == TRAFFIC_MULTIPATH_MODE_NONE &&
         (config->udp_port_layout != TRANSPORT_UDP_PORT_LAYOUT_BLOCK ||
          config->udp_port_mask_explicit != 0U ||
          config->udp_port_mask != 0U)) ||
        (config->udp_port_layout != TRANSPORT_UDP_PORT_LAYOUT_CUBE &&
         (config->udp_port_mask_explicit != 0U ||
          config->udp_port_mask != 0U)) ||
        (config->udp_port_layout == TRANSPORT_UDP_PORT_LAYOUT_CUBE &&
         ((config->udp_port_mask_explicit != 0U &&
           !d33_cube_mask_valid(resolved_policy.configured_paths,
                                config->udp_port_mask)) ||
          (config->udp_port_mask_explicit == 0U &&
           config->udp_port_mask != 0U))) ||
        (config->application_profile != D28_APPLICATION_PROFILE_BULK_D33 &&
         (config->udp_port_layout != TRANSPORT_UDP_PORT_LAYOUT_BLOCK ||
          config->udp_port_mask_explicit != 0U ||
          config->udp_port_mask != 0U)) ||
        reject_secret_environment(config->application_profile) != 0 ||
        ensure_standard_fds() != 0 ||
        install_runtime_handlers() != 0) {
        fprintf(stderr, "unmoor: invalid ssh-connect configuration\n");
        return 1;
    }
    use_exec_carrier = config->attach_socket_path != NULL;
    use_pq = config->pq_carrier_required != 0U;
    effective_policy = config->policy;
    /* Pure carrier argv grammar must be settled before the optional SSH
     * feature probe makes any remote contact.  Preflight the longer PQ form
     * so its fixed carrier marker makes this a strict bound superset of the
     * legacy form.  Keep the post-probe build below as a second check. */
    if ((use_exec_carrier &&
         (config->ssh_argc != 0 || config->ssh_argv != NULL ||
          (use_pq && config->pq_policy == PQ_POLICY_OFF) ||
          (!use_pq && config->pq_policy == PQ_POLICY_REQUIRE) ||
          build_exec_arguments(config, &exec_arguments) != 0)) ||
        (!use_exec_carrier &&
         (config->local_command != NULL ||
          config->local_confine_level != NULL || config->ssh_argc < 1 ||
          !config->ssh_argv || config->pq_carrier_required != 0U ||
          build_remote_command(config, 1, remote_command) != 0))) {
        fprintf(stderr, "unmoor: invalid ssh-connect configuration\n");
        return 1;
    }
    now = monotonic_ms();
    if (now < 0)
        return 1;
    deadline_ms = now + (int64_t)config->timeout_secs * INT64_C(1000);

    if (!use_exec_carrier) {
        if (config->pq_policy != PQ_POLICY_OFF) {
            pq_probe_result_t probe = run_ssh_pq_probe(config, deadline_ms);

            if (probe == PQ_PROBE_SUPPORTED) {
                use_pq = 1;
            } else if (probe == PQ_PROBE_INCOMPATIBLE_V1) {
                /* This experimental protocol has no downgrade path. */
                (void)fputs(PQ_PROBE_V1_REFUSAL_NOTICE, stderr);
                goto cleanup;
            } else {
                fprintf(stderr,
                        "unmoor: PQ feature probe did not return an exact supported or frozen-v1 result\n");
                goto cleanup;
            }
        }
        if (build_remote_command(config, use_pq, remote_command) != 0) {
            fprintf(stderr, "unmoor: invalid ssh-connect configuration\n");
            goto cleanup;
        }
    }
    effective_policy.pq_hybrid = (uint8_t)use_pq;

    if (pipe_cloexec(to_ssh) != 0 || pipe_cloexec(from_ssh) != 0) {
        fprintf(stderr, "unmoor: SSH control pipe failed: %s\n",
                strerror(errno));
        goto cleanup;
    }
    ssh_pid = use_exec_carrier
        ? spawn_argv(exec_arguments.argv, to_ssh, from_ssh)
        : spawn_ssh(config, remote_command, to_ssh, from_ssh);
    if (ssh_pid < 0) {
        fprintf(stderr, "unmoor: could not fork epoch-rekey carrier: %s\n",
                strerror(errno));
        goto cleanup;
    }
    runtime_child_pid = ssh_pid;
    (void)close(to_ssh[0]);
    to_ssh[0] = -1;
    (void)close(from_ssh[1]);
    from_ssh[1] = -1;

    if ((use_pq &&
         (read_public_line(from_ssh[0], offer_line,
                           PQ_DEADDROP_OFFER_LINE_LEN, deadline_ms) != 0 ||
          pq_deaddrop_offer_line_decode(offer_line,
                                        PQ_DEADDROP_OFFER_LINE_LEN,
                                        &pq_offer) != 0)) ||
        (!use_pq &&
         (read_public_line(from_ssh[0], offer_line, D28_OFFER_LINE_LEN,
                           deadline_ms) != 0 ||
          d28_offer_line_decode(offer_line, D28_OFFER_LINE_LEN,
                                &offer) != 0))) {
        fprintf(stderr,
                "unmoor: carrier returned no exact public deaddrop offer: %s\n",
                strerror(errno));
        goto cleanup;
    }

    (void)crypto_mlock(root, sizeof(root));
    crypto_mark_dontdump(root, sizeof(root));
    runtime_secret_a = root;
    runtime_secret_a_len = sizeof(root);
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGINT);
    sigaddset(&blocked, SIGHUP);
    sigaddset(&blocked, SIGTERM);
    sigaddset(&blocked, SIGQUIT);
    if (sigprocmask(SIG_BLOCK, &blocked, &previous) != 0)
        goto cleanup;
    signals_blocked = 1;
    if (use_pq) {
        if (pq_deaddrop_client_accept(&pq_offer, &pq_response,
                                      root, pair_seed) != 0)
            goto cleanup;
    } else if (d28_client_accept_offer_for_profile(
                   &offer, config->application_profile,
                   &response, root, pair_seed) != 0) {
        goto cleanup;
    }
    if (sigprocmask(SIG_SETMASK, &previous, NULL) != 0)
        goto cleanup;
    signals_blocked = 0;
    if ((use_pq &&
         (pq_deaddrop_response_line_encode(
              &pq_offer, &pq_response, response_line) != 0 ||
          write_public_line(to_ssh[1], response_line,
                            PQ_DEADDROP_RESPONSE_LINE_LEN,
                            deadline_ms) != 0)) ||
        (!use_pq &&
         (d28_response_line_encode(&response, response_line) != 0 ||
          write_public_line(to_ssh[1], response_line,
                            D28_RESPONSE_LINE_LEN, deadline_ms) != 0))) {
        fprintf(stderr, "unmoor: could not send public deaddrop response\n");
        goto cleanup;
    }
    (void)close(to_ssh[1]);
    to_ssh[1] = -1;
    if (read_public_line(from_ssh[0], accept_line,
                         use_pq ? PQ_DEADDROP_ACCEPT_LINE_LEN
                                : D28_ACCEPT_LINE_LEN,
                         deadline_ms) != 0 ||
        /* A real SSH channel has one lifecycle EOF for stdout and stderr.
         * --remote-foreground deliberately keeps that channel alive while
         * the UDP endpoint runs, even after the remote program closes fd 1.
         * The fixed-length ACCEPT is therefore the carrier boundary in that
         * explicit lifecycle-test mode, with a short guard against a
         * coalesced duplicate.  Every normal and EXEC carrier still has to
         * prove immediate EOF before UDP is opened. */
        (config->remote_foreground
             ? require_stream_quiet(
                   from_ssh[0], D28_FOREGROUND_TRAILING_QUIET_MS) != 0
             : require_stream_eof(from_ssh[0], deadline_ms) != 0) ||
        (use_pq
             ? pq_deaddrop_accept_line_verify(
                   accept_line, PQ_DEADDROP_ACCEPT_LINE_LEN,
                   &pq_offer, &pq_response)
             : d28_accept_line_verify(accept_line, D28_ACCEPT_LINE_LEN,
                                      &response)) != 0) {
        fprintf(stderr,
                "unmoor: deaddrop fingerprint acceptance missing or wrong\n");
        goto cleanup;
    }
    if (use_exec_carrier) {
        int waited = wait_child_grace(ssh_pid, 1000, &ssh_status);

        if (waited != 1 || !WIFEXITED(ssh_status) ||
            WEXITSTATUS(ssh_status) != 0) {
            fprintf(stderr,
                    "unmoor: child-transfer EXEC bootstrap carrier did not exit cleanly\n");
            goto cleanup;
        }
        ssh_pid = -1;
        runtime_child_pid = 0;
    }
    (void)close(from_ssh[0]);
    from_ssh[0] = -1;
    if (epoch_crypto_fingerprint_encode(
            use_pq ? pq_response.transcript_fingerprint
                   : response.transcript_fingerprint,
                                        fingerprint) != 0)
        goto cleanup;
    fprintf(stderr, "unmoor: verified public bootstrap %s\n", fingerprint);

    memset(&transport_config, 0, sizeof(transport_config));
    transport_config.transport = "udp";
    transport_config.listen = 0;
    transport_config.udp_host = config->udp_host;
    (void)snprintf(port, sizeof(port), "%u",
                   (unsigned)(use_pq ? pq_offer.port : offer.port));
    transport_config.udp_port = port;
    transport_config.udp_multipath_paths =
        resolved_policy.multipath_mode == TRAFFIC_MULTIPATH_MODE_NONE
            ? 0U : resolved_policy.configured_paths;
    transport_config.udp_port_layout = config->udp_port_layout;
    transport_config.udp_port_mask_explicit =
        config->udp_port_mask_explicit;
    transport_config.udp_port_mask = config->udp_port_mask;
    memcpy(transport_config.pair_id, pair_seed, sizeof(pair_seed));
    if (transport_udp.open(&transport_config, &transport) != 0) {
        fprintf(stderr, "unmoor: could not open deaddrop UDP endpoint\n");
        goto cleanup;
    }
    runner_called = 1;
    rc = runner(transport, root, pair_seed, 0,
                config->application_profile, config->runner_context,
                &effective_policy, NULL, deadline_ms, NULL, NULL);
    transport = NULL;

cleanup:
    if (signals_blocked)
        (void)sigprocmask(SIG_SETMASK, &previous, NULL);
    if (!runner_called && transport)
        transport_udp.close(transport);
    if (to_ssh[0] >= 0)
        (void)close(to_ssh[0]);
    if (to_ssh[1] >= 0)
        (void)close(to_ssh[1]);
    if (from_ssh[0] >= 0)
        (void)close(from_ssh[0]);
    if (from_ssh[1] >= 0)
        (void)close(from_ssh[1]);
    if (ssh_pid > 0) {
        if (!use_exec_carrier && config->remote_foreground && rc < 128) {
            int waited = wait_child_grace(ssh_pid, 3000, &ssh_status);
            if (waited == 1) {
                if ((!WIFEXITED(ssh_status) || WEXITSTATUS(ssh_status) != 0) &&
                    rc == 0)
                    rc = 1;
                ssh_pid = -1;
            } else if (rc == 0) {
                fprintf(stderr,
                        "unmoor: completed session; terminating lingering "
                        "foreground SSH carrier\n");
                if (terminate_and_reap(ssh_pid) == 0)
                    ssh_pid = -1;
                else
                    rc = 1;
            }
        }
        if (ssh_pid > 0)
            (void)terminate_and_reap(ssh_pid);
    }
    runtime_child_pid = 0;
    runtime_secret_a = NULL;
    runtime_secret_a_len = 0;
    crypto_memzero(root, sizeof(root));
    (void)crypto_munlock(root, sizeof(root));
    crypto_memzero(pair_seed, sizeof(pair_seed));
    crypto_memzero(&offer, sizeof(offer));
    crypto_memzero(&response, sizeof(response));
    crypto_memzero(&pq_offer, sizeof(pq_offer));
    crypto_memzero(&pq_response, sizeof(pq_response));
    crypto_memzero(&exec_arguments, sizeof(exec_arguments));
    crypto_memzero(remote_command, sizeof(remote_command));
    crypto_memzero(offer_line, sizeof(offer_line));
    crypto_memzero(response_line, sizeof(response_line));
    crypto_memzero(accept_line, sizeof(accept_line));
    crypto_memzero(fingerprint, sizeof(fingerprint));
    return rc >= 0 && rc <= 255 ? rc : 1;
}
