/*
 * channel_pty.c — PTY channel handler (ch 1)
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * Frame types (CHAN=1):
 *   0x01  PTY_OPEN       client → server    body: rows u16, cols u16, xpix u16, ypix u16
 *   0x02  PTY_OPEN_ACK   server → client    body: pid u32
 *   0x03  PTY_OPEN_ERR   server → client    body: error_code u16, reserved u16
 *   0x04  PTY_DATA       both               body: raw bytes (MTU-limited)
 *   0x05  PTY_RESIZE     client → server    body: rows u16, cols u16, xpix u16, ypix u16
 *   0x06  PTY_SIGNAL     client → server    body: signum u8 + 3 reserved
 *   0x07  PTY_CLOSE      both               body: empty
 *   0x08  PTY_EOF        server → client    body: exit_code i32
 *   0x09  PTY_SYNC_DATA  both               terminal state sync offset stream (sync.c)
 *   0x0A  PTY_SYNC_ACK   both               terminal state sync frontier/bitmap/chain
 *
 * when UNMOOR_CAP_PTY_SYNC_V1 is negotiated, the byte
 * streams ride 0x09/0x0A exclusively and PTY_DATA/PTY_EOF become fatal
 * protocol errors — and vice versa. Control subtypes
 * (OPEN/RESIZE/SIGNAL/CLOSE) are unchanged in both modes.
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "channel.h"
#include "channel_pty.h"
#include "frame.h"
#include "monitor_session_backend.h"
#include "pty.h"
#include "session.h"

/* -------------------------------------------------------------------------
 * Helpers
 * ---------------------------------------------------------------------- */

static uint16_t load16le(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | (uint16_t)((uint16_t)p[1] << 8));
}

static uint8_t pty_chan_byte(void)
{
    /* chan 1, FF=1, MF=0 (single fragment) */
    return (1 << 4) | CHAN_FF_BIT;
}

static int send_pty(session_t *s, uint8_t type,
                    const uint8_t *body, size_t len)
{
    return session_send(s, pty_chan_byte(), type, body, len);
}

static int pty_owner_is_monitored(const session_t *s)
{
    return monitor_session_backend_is_bound(s);
}

static int pty_owner_failure(session_t *s, const char *operation)
{
    int cause = errno ? errno : EIO;

    fprintf(stderr,
            "channel_pty: monitored PTY %s failed: %s — closing loudly\n",
            operation, strerror(cause));
    s->run_failed = 1;
    if (s->state != SESSION_IDLE && s->state != SESSION_CLOSING)
        session_close(s);
    errno = cause;
    return -1;
}

static ssize_t pty_owner_read(session_t *s, void *buffer, size_t length)
{
    return pty_owner_is_monitored(s)
        ? monitor_session_backend_read(s, buffer, length)
        : read(s->pty_master_fd, buffer, length);
}

static ssize_t pty_owner_write(session_t *s, const void *buffer, size_t length)
{
    return pty_owner_is_monitored(s)
        ? monitor_session_backend_write(s, buffer, length)
        : write(s->pty_master_fd, buffer, length);
}

static int pty_owner_retire(session_t *s, int *exit_code)
{
    if (pty_owner_is_monitored(s))
        return monitor_session_backend_retire(s, exit_code);
    *exit_code = pty_close(s->pty_master_fd, s->pty_child_pid);
    s->pty_master_fd = -1;
    s->pty_child_pid = 0;
    return 0;
}

/* -------------------------------------------------------------------------
 * OTP challenge (server side only)
 * State lives on session_t (per-session, not static globals).
 * ---------------------------------------------------------------------- */


/* -------------------------------------------------------------------------
 * Server: handle PTY_OPEN → spawn, reply with PTY_OPEN_ACK or PTY_OPEN_ERR
 * ---------------------------------------------------------------------- */

static int handle_pty_open(session_t *s, const uint8_t *data, size_t len)
{
    /* The protocol fixes PTY_OPEN body at 8 bytes exactly. */
    if (len != 8) {
        fprintf(stderr, "channel_pty: PTY_OPEN wrong length %zu (expected 8)\n", len);
        return CHAN_OK;
    }
    uint16_t rows = load16le(data);
    uint16_t cols = load16le(data + 2);
    if (!rows) rows = 24;
    if (!cols) cols = 80;
    /* Clamp to sane range. */
    if (rows > 1000) rows = 1000;
    if (cols > 1000) cols = 1000;

    if (session_classic_pty_source_ended(s)) {
        const uint8_t body[4] = {ERR_SESSION, 0, 0, 0};
        fprintf(stderr, "channel_pty: PTY_OPEN refused — terminal stream has ended\n");
        (void)send_pty(s, PTY_OPEN_ERR, body, sizeof(body));
        return CHAN_OK;
    }

    if (s->pty_master_fd >= 0) {
        /* Preserve the legacy duplicate path byte-for-byte.  Channel-session never
         * enters this handler; its immutable OPEN decision lives on channel
         * zero instead. */
        fprintf(stderr, "channel_pty: duplicate PTY_OPEN — re-ACK (pid=%d)\n",
                (int)s->pty_child_pid);
        uint8_t ack[4];
        uint32_t pid = (uint32_t)s->pty_child_pid;
        ack[0] = (uint8_t)(pid & 0xFF);
        ack[1] = (uint8_t)((pid >> 8) & 0xFF);
        ack[2] = (uint8_t)((pid >> 16) & 0xFF);
        ack[3] = (uint8_t)((pid >> 24) & 0xFF);
        send_pty(s, PTY_OPEN_ACK, ack, 4);
        return CHAN_OK;
    }

    uint32_t pid = 0U;
    if (channel_pty_server_start(s, rows, cols, &pid) != 0) {
        uint16_t code = ERR_RESOURCE;
        uint8_t body[4];
        body[0] = (uint8_t)(code & 0xFF);
        body[1] = (uint8_t)((code >> 8) & 0xFF);
        body[2] = 0; body[3] = 0;
        send_pty(s, PTY_OPEN_ERR, body, 4);
        fprintf(stderr, "channel_pty: %s failed: %s\n",
                pty_owner_is_monitored(s) ? "monitored PTY open"
                                          : "pty_spawn",
                strerror(errno));
        return CHAN_OK;
    }

    uint8_t ack[4];
    ack[0] = (uint8_t)(pid & 0xFF);
    ack[1] = (uint8_t)((pid >> 8) & 0xFF);
    ack[2] = (uint8_t)((pid >> 16) & 0xFF);
    ack[3] = (uint8_t)((pid >> 24) & 0xFF);
    send_pty(s, PTY_OPEN_ACK, ack, 4);


    return CHAN_OK;
}

/* -------------------------------------------------------------------------
 * Client: handle PTY_OPEN_ACK / PTY_OPEN_ERR / PTY_DATA / PTY_EOF
 * ---------------------------------------------------------------------- */

channel_pty_on_ack_fn channel_pty_on_client_ack = NULL;

int channel_pty_server_start(session_t *s, uint16_t rows, uint16_t cols,
                             uint32_t *pid_out)
{
    int master = -1;
    pid_t pid = 0;

    if (!s || !pid_out || !s->is_server || rows == 0U || cols == 0U)
        return -1;
    if (session_classic_pty_source_ended(s)) {
        fprintf(stderr, "channel_pty: local PTY start refused — terminal stream has ended\n");
        errno = EPIPE;
        return -1;
    }
    if (rows > 1000U)
        rows = 1000U;
    if (cols > 1000U)
        cols = 1000U;
    if (s->pty_master_fd >= 0) {
        *pid_out = (uint32_t)s->pty_child_pid;
        fprintf(stderr,
                "channel_pty: duplicate local PTY start — pid=%d\n",
                (int)s->pty_child_pid);
        return 0;
    }
    if (pty_owner_is_monitored(s)) {
        if (monitor_session_backend_open(s, rows, cols, pid_out) != 0)
            return -1;
        fprintf(stderr,
                "channel_pty: monitored PTY opened pid=%u fd=%d (%ux%u)\n",
                (unsigned)*pid_out, s->pty_master_fd, cols, rows);
        return 0;
    }
    if (pty_spawn(NULL, rows, cols, &master, &pid) != 0)
        return -1;
    s->pty_master_fd = master;
    s->pty_child_pid = pid;
    *pid_out = (uint32_t)pid;
    fprintf(stderr, "channel_pty: server spawned PTY pid=%d fd=%d (%ux%u)\n",
            (int)pid, master, cols, rows);
    return 0;
}

void channel_pty_client_open_accepted(session_t *s)
{
    if (!s || s->is_server)
        return;
    s->pty_open_ack_seen = 1;
    s->pty_open_err_seen = 0;
    fprintf(stderr, "channel_pty: client terminal channel accepted\n");
    if (channel_pty_on_client_ack)
        channel_pty_on_client_ack(s);
}

void channel_pty_client_open_refused(session_t *s, uint32_t code)
{
    if (!s || s->is_server)
        return;
    s->pty_open_err_seen = 1;
    fprintf(stderr,
            "channel_pty: terminal channel refused code=%u\n",
            (unsigned int)code);
}

static int handle_pty_open_ack(session_t *s, const uint8_t *data, size_t len)
{
    (void)data; (void)len;
    s->pty_open_ack_seen = 1;
    fprintf(stderr, "channel_pty: client received PTY_OPEN_ACK\n");
    if (channel_pty_on_client_ack)
        channel_pty_on_client_ack(s);
    return CHAN_OK;
}

static int handle_pty_open_err(session_t *s, const uint8_t *data, size_t len)
{
    s->pty_open_err_seen = 1; /* server refused — stop the retransmit timer */
    uint16_t code = 0;
    if (len >= 2) code = load16le(data);
    if (code == ERR_SESSION)
        fprintf(stderr, "channel_pty: PTY_OPEN refused — terminal stream has ended; staying ESTABLISHED\n");
    else
        fprintf(stderr, "channel_pty: PTY_OPEN_ERR code=0x%04X — staying ESTABLISHED\n",
                code);
    return CHAN_OK;
}

static int handle_pty_data_server(session_t *s, const uint8_t *data, size_t len)
{

    /* Server: write stdin bytes from client to PTY master */
    if (s->pty_master_fd < 0) return CHAN_OK;

    /* If we have a backlog, append first (preserving order).
     * If the append would overflow, do NOT silently drop bytes —
     * tear down the session via CTRL_CLOSE so the peer learns it stopped
     * making progress instead of seeing corrupted shell input. */
    if (s->pty_master_backlog_len > 0) {
        size_t room = sizeof(s->pty_master_backlog) - s->pty_master_backlog_len;
        if (len > room) {
            fprintf(stderr,
                    "channel_pty: master backlog overflow (%zu > %zu) — closing session\n",
                    len, room);
            /* zero the backlog before
             * session_close so the in-flight CTRL_CLOSE retransmit window
             * doesn't try to flush stale bytes to the master fd. */
            s->pty_master_backlog_len = 0;
            session_close(s);
            return CHAN_ERR;
        }
        memcpy(s->pty_master_backlog + s->pty_master_backlog_len, data, len);
        s->pty_master_backlog_len += len;
        return CHAN_OK;
    }

    size_t off = 0;
    while (off < len) {
        ssize_t n = pty_owner_write(s, data + off, len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* Stash remaining bytes in backlog for POLLOUT flush.
                 * If remainder won't fit, close the session rather
                 * than silently truncating shell stdin. */
                size_t remain = len - off;
                size_t room = sizeof(s->pty_master_backlog);
                if (remain > room) {
                    fprintf(stderr,
                            "channel_pty: master backlog cannot hold %zu bytes — closing session\n",
                            remain);
                    /* zero before close (see above). */
                    s->pty_master_backlog_len = 0;
                    session_close(s);
                    return CHAN_ERR;
                }
                memcpy(s->pty_master_backlog, data + off, remain);
                s->pty_master_backlog_len = remain;
                return CHAN_OK;
            }
            if (pty_owner_is_monitored(s)) {
                (void)pty_owner_failure(s, "write");
                return CHAN_ERR;
            }
            fprintf(stderr, "channel_pty: write to master: %s\n", strerror(errno));
            return CHAN_OK;
        }
        off += (size_t)n;
    }
    return CHAN_OK;
}

/* Flush master backlog when POLLOUT fires. Called from session_run. */
int channel_pty_flush_master_backlog(session_t *s)
{
    if (s->pty_master_fd < 0 || s->pty_master_backlog_len == 0) return 0;
    size_t off = 0;
    while (off < s->pty_master_backlog_len) {
        ssize_t n = pty_owner_write(s, s->pty_master_backlog + off,
                                    s->pty_master_backlog_len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            if (pty_owner_is_monitored(s)) {
                (void)pty_owner_failure(s, "backlog write");
            } else {
                fprintf(stderr, "channel_pty: flush_master_backlog: %s\n",
                        strerror(errno));
            }
            s->pty_master_backlog_len = 0;
            return -1;
        }
        off += (size_t)n;
    }
    if (off > 0) {
        memmove(s->pty_master_backlog,
                s->pty_master_backlog + off,
                s->pty_master_backlog_len - off);
        s->pty_master_backlog_len -= off;
    }
    return 0;
}

static int handle_pty_data_client(session_t *s, const uint8_t *data, size_t len)
{
    (void)s;
    /* Client: write bytes received from server to stdout */
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(STDOUT_FILENO, data + off, len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        off += (size_t)n;
    }
    return CHAN_OK;
}

static int handle_pty_resize(session_t *s, const uint8_t *data, size_t len)
{
    /* The protocol fixes PTY_RESIZE body at 8 bytes exactly. */
    if (len != 8) {
        fprintf(stderr, "channel_pty: PTY_RESIZE wrong length %zu (expected 8)\n", len);
        return CHAN_OK;
    }
    if (s->pty_master_fd < 0) return CHAN_OK;
    uint16_t rows = load16le(data);
    uint16_t cols = load16le(data + 2);
    /* Clamp to [1, 1000] to prevent ncurses/readline DoS. */
    if (rows == 0 || cols == 0) return CHAN_OK;
    if (rows > 1000) rows = 1000;
    if (cols > 1000) cols = 1000;
    if (pty_owner_is_monitored(s)) {
        if (monitor_session_backend_resize(s, rows, cols) != 0) {
            (void)pty_owner_failure(s, "resize");
            return CHAN_ERR;
        }
    } else {
        pty_resize(s->pty_master_fd, rows, cols);
    }
    return CHAN_OK;
}

static int handle_pty_signal(session_t *s, const uint8_t *data, size_t len)
{
    /* The protocol fixes PTY_SIGNAL body at 4 bytes exactly. */
    if (len != 4) {
        fprintf(stderr, "channel_pty: PTY_SIGNAL wrong length %zu (expected 4)\n", len);
        return CHAN_OK;
    }
    if (s->pty_child_pid <= 0) return CHAN_OK;
    int signum = data[0];
    if (signum > 0 && signum < 64) {
        if (pty_owner_is_monitored(s)) {
            if (monitor_session_backend_signal(s, signum) != 0) {
                (void)pty_owner_failure(s, "signal");
                return CHAN_ERR;
            }
        } else {
            kill(s->pty_child_pid, signum);
        }
    }
    return CHAN_OK;
}

static int handle_pty_eof(session_t *s, const uint8_t *data, size_t len)
{
    int32_t code = 0;
    if (len >= 4) {
        code = (int32_t)((uint32_t)data[0]
                | ((uint32_t)data[1] << 8)
                | ((uint32_t)data[2] << 16)
                | ((uint32_t)data[3] << 24));
    }
    fprintf(stderr, "channel_pty: PTY_EOF exit_code=%d\n", code);
    /* Write a newline for clean terminal state */
    (void)!write(STDOUT_FILENO, "\r\n", 2);
    s->client_exit_code = code;
    s->should_exit      = 1;
    s->pty_eof_seen     = 1;
    return CHAN_OK;
}

/* the legacy PTY_DATA/PTY_EOF family and the sync 0x09/0x0A
 * family are mutually exclusive per session. A frame from the wrong family
 * is authenticated (AEAD passed) yet impossible under the negotiated
 * contract — a peer running the other delivery path. Mixing them would
 * corrupt display ordering silently, so fail the run loudly instead. */
static int pty_wrong_path_fatal(session_t *s, uint8_t type)
{
    fprintf(stderr,
            "channel_pty: FATAL: PTY type 0x%02X is invalid %s negotiated "
            "pty-sync-v1 — closing session\n",
            type, sync_active(s) ? "under" : "without");
    s->run_failed = 1;
    session_close(s);
    return CHAN_ERR;
}

/* Log misdirected PTY subtypes once per session so a flooding peer
 * cannot fill stderr with the same drop message. The bitmask lives on
 * session_t (pty_quiet_log_mask); bit (1 << type) gates the log. */
static void log_misdirected_once(session_t *s, const char *side, uint8_t type)
{
    uint16_t bit = (uint16_t)(1u << (type & 0x0F));
    if (s->pty_quiet_log_mask & bit) return;
    s->pty_quiet_log_mask |= bit;
    fprintf(stderr,
            "channel_pty: %s received misdirected PTY subtype 0x%02X — "
            "dropped (further drops will be silent)\n",
            side, type);
}

/* Mutation-free product grammar used only by the epoch-rekey implicit-proof
 * boundary. Established dispatch keeps its historical tolerant behavior,
 * but malformed, misdirected, wrong-path, and no-op records cannot advance
 * an epoch before the real handler sees them. */
static int pty_prevalidate(const session_t *s, uint8_t chan_byte,
                           uint8_t type, const uint8_t *data, size_t len)
{
    if (!s || (chan_byte >> 4) != 1U ||
        (chan_byte & 0x0fU) != CHAN_FF_BIT || (!data && len != 0))
        return CHAN_ERR;
    if (session_channelised_active(s) &&
        (type == PTY_OPEN || type == PTY_OPEN_ACK ||
         type == PTY_OPEN_ERR || type == PTY_CLOSE))
        return CHAN_ERR;
    switch (type) {
    case PTY_OPEN:
        return s->is_server && len == 8 ? CHAN_OK : CHAN_ERR;
    case PTY_OPEN_ACK:
        return !s->is_server && len == 4 ? CHAN_OK : CHAN_ERR;
    case PTY_OPEN_ERR:
        return !s->is_server && len == 4 &&
               data[2] == 0 && data[3] == 0 ? CHAN_OK : CHAN_ERR;
    case PTY_DATA:
        return !sync_active(s) && len != 0 && len <= REASM_MAX_BUFFER
             ? CHAN_OK : CHAN_ERR;
    case PTY_RESIZE:
        return s->is_server && len == 8 ? CHAN_OK : CHAN_ERR;
    case PTY_SIGNAL:
        return s->is_server && len == 4 && data[0] != 0 && data[0] < 64 &&
               data[1] == 0 && data[2] == 0 && data[3] == 0
             ? CHAN_OK : CHAN_ERR;
    case PTY_CLOSE:
        return len == 0 ? CHAN_OK : CHAN_ERR;
    case PTY_EOF:
        return !s->is_server && !sync_active(s) && len == 4
             ? CHAN_OK : CHAN_ERR;
    case PTY_SYNC_DATA:
        return sync_active(s) && sync_prevalidate_data(s, data, len) == 0
             ? CHAN_OK : CHAN_ERR;
    case PTY_SYNC_ACK:
        return sync_active(s) && sync_prevalidate_ack(s, data, len) == 0
             ? CHAN_OK : CHAN_ERR;
    default:
        return CHAN_ERR;
    }
}

/* -------------------------------------------------------------------------
 * Dispatch
 * ---------------------------------------------------------------------- */

static int pty_on_open(session_t *s)
{
    /* Client side: auto-request a PTY immediately on ESTABLISHED if flagged
     * via is_client_pty. Server side: nothing to do until we receive
     * PTY_OPEN from the peer. */
    if (!s->is_server && s->is_client_pty) {
        uint16_t rows = 24, cols = 80;
        struct winsize ws;
        if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_row && ws.ws_col) {
            rows = ws.ws_row;
            cols = ws.ws_col;
        }
        fprintf(stderr, "channel_pty: client sending PTY_OPEN (%ux%u)\n", cols, rows);
        channel_pty_client_send_open(s, rows, cols);
    }
    return 0;
}

static int pty_on_data(session_t *s, uint8_t chan_byte, uint8_t type,
                       const uint8_t *data, size_t len)
{
    (void)chan_byte;

    /* channel-session moves lifecycle authority to authenticated channel-zero
     * OPEN/ACCEPT/REFUSE/CLOSE/CLOSE_ACK.  Keeping the legacy PTY lifecycle
     * grammar alive inside class 1 would create a second opener/closer and
     * could make an authenticated peer amplify legacy replies.  RESIZE,
     * SIGNAL and the exact-stream records remain the channel-session terminal body. */
    if (session_channelised_active(s) &&
        (type == PTY_OPEN || type == PTY_OPEN_ACK ||
         type == PTY_OPEN_ERR || type == PTY_CLOSE)) {
        fprintf(stderr,
                "channel_pty: FATAL: legacy PTY lifecycle type 0x%02X is invalid under channel-session-v1\n",
                type);
        s->run_failed = 1;
        session_close(s);
        return CHAN_ERR;
    }

    switch (type) {
    case PTY_OPEN:
        if (!s->is_server) {
            log_misdirected_once(s, "client", type);
            return CHAN_OK;
        }
        return handle_pty_open(s, data, len);

    case PTY_OPEN_ACK:
        if (s->is_server) {
            log_misdirected_once(s, "server", type);
            return CHAN_OK;
        }
        return handle_pty_open_ack(s, data, len);

    case PTY_OPEN_ERR:
        if (s->is_server) {
            log_misdirected_once(s, "server", type);
            return CHAN_OK;
        }
        return handle_pty_open_err(s, data, len);

    case PTY_DATA:
        if (sync_active(s)) return pty_wrong_path_fatal(s, type);
        if (s->is_server) return handle_pty_data_server(s, data, len);
        else              return handle_pty_data_client(s, data, len);

    case PTY_SYNC_DATA:
        if (!sync_active(s)) return pty_wrong_path_fatal(s, type);
        sync_handle_data(s, data, len);
        return CHAN_OK;

    case PTY_SYNC_ACK:
        if (!sync_active(s)) return pty_wrong_path_fatal(s, type);
        sync_handle_ack(s, data, len);
        return CHAN_OK;

    case PTY_RESIZE:
        if (!s->is_server) {
            log_misdirected_once(s, "client", type);
            return CHAN_OK;
        }
        return handle_pty_resize(s, data, len);

    case PTY_SIGNAL:
        if (!s->is_server) {
            log_misdirected_once(s, "client", type);
            return CHAN_OK;
        }
        return handle_pty_signal(s, data, len);

    case PTY_EOF:
        if (sync_active(s)) return pty_wrong_path_fatal(s, type);
        if (s->is_server) {
            log_misdirected_once(s, "server", type);
            return CHAN_OK;
        }
        return handle_pty_eof(s, data, len);

    case PTY_CLOSE:
        fprintf(stderr, "channel_pty: PTY_CLOSE received\n");
        return CHAN_OK;

    default:
        fprintf(stderr, "channel_pty: unknown type 0x%02X\n", type);
        return CHAN_OK;
    }
}

int channel_pty_close_instance(session_t *s)
{
    if (session_channelised_active(s) &&
        s->terminal_channel_handle != 0U) {
        uint8_t slot = 0U;
        uint32_t generation = 0U;

        if (channel_session_handle_decode(s->terminal_channel_handle,
                                          &slot, &generation) == 0)
            (void)sync_instance_detach_io(
                s, slot, s->terminal_channel_handle);
    }
    if (s->pty_master_fd >= 0 || s->pty_child_pid > 0) {
        int code = -1;
        if (pty_owner_retire(s, &code) != 0)
            return pty_owner_failure(s, "retire");
        fprintf(stderr, "channel_pty: PTY closed (exit=%d)\n", code);
    }
    /* OTP state cleaned up automatically by session_destroy (calloc'd struct) */
    return 0;
}

static int pty_on_close(session_t *s)
{
    return channel_pty_close_instance(s);
}

const channel_ops_t channel_pty = {
    .id       = 1,
    .name     = "pty",
    .required_caps = UNMOOR_CAP_PTY_V1,
    .prevalidate = pty_prevalidate,
    .on_open  = pty_on_open,
    .on_data  = pty_on_data,
    .on_close = pty_on_close,
};

/* -------------------------------------------------------------------------
 * Server pump: PTY master → transport
 * ---------------------------------------------------------------------- */

int channel_pty_pump_master(session_t *s)
{
    if (s->pty_master_fd < 0) return 0;

    int sync_on = sync_active(s);
    size_t mtu = s->current_mtu ? s->current_mtu : UNMOOR_TERMINAL_PLAINTEXT_MAX;
    uint8_t buf[UNMOOR_TERMINAL_PLAINTEXT_MAX];
    size_t cap = mtu > sizeof(buf) ? sizeof(buf) : mtu;
    if (sync_on) {
        /* Include the sync record envelope in the read geometry. Under the
         * initial open credit window, one source read fits one DATA frame and
         * preserves read-pacer's startup proof. A later credit boundary may split
         * or release backlog; wire scheduling remains future work. */
        cap = sync_tx_read_limit(s);
        if (cap == 0) return 0;
    }
    if (cap > sizeof(buf)) cap = sizeof(buf);

    ssize_t n = pty_owner_read(s, buf, cap);
    if (n > 0) {
        session_pacer_charge_read(s, (size_t)n);
        if (sync_on) {
            /* First transmission is billed here at the source; only sync
             * retransmits charge the pacer again inside sync.c. */
            return sync_tx_append(s, buf, (size_t)n) == 0 ? 0 : -1;
        }
        /* session_send_data handles fragmentation above current_mtu. */
        session_send_data(s, 1, PTY_DATA, buf, (size_t)n);
        return 0;
    }

    if (n == 0 || (n < 0 && (errno == EIO || errno == 0))) {
        session_classic_pty_source_end(s);
        if (sync_on) {
            /* exactly one FIN, carrying the real
             * exit code — no early codeless probe, no legacy PTY_EOF, and
             * no session_close here. The FIN rides the stream at offset
             * tip, retransmits on the probe timer, and the linger logic in
             * sync_tick closes only once the peer has acknowledged every
             * byte (or the linger window expires). */
            if (session_channelised_active(s) &&
                s->terminal_channel_handle != 0U) {
                uint8_t slot = 0U;
                uint32_t generation = 0U;

                if (channel_session_handle_decode(
                        s->terminal_channel_handle,
                        &slot, &generation) == 0)
                    (void)sync_instance_detach_io(
                        s, slot, s->terminal_channel_handle);
            }
            int code = -1;
            if (pty_owner_retire(s, &code) != 0)
                return pty_owner_failure(s, "EOF retire");
            fprintf(stderr,
                    "channel_pty: shell exited (code=%d) — sync FIN at stream end\n",
                    code);
            sync_tx_fin(s, 1, (int32_t)code);
            return 0;
        }

        /* Child exited — shell closed PTY. Send-scheduler admits one accurate EOF as
         * the final NEW-lane record, then its transport-completion callback
         * begins the bounded close. The source read was armed only while the
         * NEW lane was empty, so this preserves all earlier PTY_DATA without
         * adding a second queue slot or erasing EOF during CLOSING. */
        int code = -1;
        if (pty_owner_retire(s, &code) != 0)
            return pty_owner_failure(s, "EOF retire");

        int32_t code32 = (int32_t)code;
        uint8_t body[4];
        body[0] = (uint8_t)(code32 & 0xFF);
        body[1] = (uint8_t)((code32 >> 8) & 0xFF);
        body[2] = (uint8_t)((code32 >> 16) & 0xFF);
        body[3] = (uint8_t)((code32 >> 24) & 0xFF);
        if (session_send_lane_tracked(
                s, SEND_LANE_NEW, pty_chan_byte(), PTY_EOF,
                body, sizeof(body), SESSION_TX_DONE_LEGACY_EOF,
                0, 0) != 0) {
            fprintf(stderr,
                    "channel_pty: terminal PTY_EOF admission failed — closing loudly\n");
            s->run_failed = 1;
            session_close(s);
            return -1;
        }
        fprintf(stderr,
                "channel_pty: shell exited (code=%d) — PTY_EOF admitted before CTRL_CLOSE\n",
                code);
        return 0;
    }

    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
        return 0;
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * Client pump: stdin → transport
 * ---------------------------------------------------------------------- */

int channel_pty_finish_stdin(session_t *s)
{
    uint8_t held[1];
    size_t held_len;
    int sync_on;

    if (s == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (s->stdin_closed)
        return 0;
    sync_on = sync_active(s);
    held_len = client_escape_finish(&s->client_escape,
                                    held, sizeof(held));
    if (held_len == SIZE_MAX) {
        fprintf(stderr, "channel_pty: cannot flush held local escape\n");
        s->run_failed = 1;
        session_close(s);
        return -1;
    }
    if (held_len > 0) {
        session_pacer_charge_read(s, held_len);
        if (sync_on) {
            if (sync_tx_append(s, held, held_len) != 0)
                return -1;
        } else if (session_send_data(s, 1, PTY_DATA,
                                     held, held_len) != 0) {
            return -1;
        }
    }
    /* stdin EOF/unavailability ends only the input half.  The peer's output
     * and coded stream end still have to arrive normally. */
    fprintf(stderr, "channel_pty: stdin EOF — stopping stdin pump\n");
    s->stdin_closed = 1;
    if (sync_on)
        sync_tx_fin(s, 0, 0);
    return 0;
}

int channel_pty_pump_stdin(session_t *s)
{
    uint8_t input[UNMOOR_TERMINAL_PLAINTEXT_MAX];
    uint8_t filtered[UNMOOR_TERMINAL_PLAINTEXT_MAX];
    _Static_assert(sizeof(filtered) >= sizeof(input),
                   "escape filter output buffer must not be smaller than its input");
    int sync_on = sync_active(s);
    int escape_on = s->raw_mode_active;
    size_t mtu = s->current_mtu ? s->current_mtu : UNMOOR_TERMINAL_PLAINTEXT_MAX;
    size_t cap = mtu > sizeof(input) ? sizeof(input) : mtu;
    if (sync_on) {
        cap = sync_tx_read_limit(s); /* quota + one-record bound (see master) */
        if (cap == 0) return 0;
    }
    if (cap > sizeof(input)) cap = sizeof(input);
    /* A held escape plus an unknown second byte emits two bytes. Reserve one
     * input byte so the filtered chunk never exceeds the pre-filter wire/read
     * bound and never creates a new userspace queue. */
    if (escape_on && s->client_escape.pending && cap > 0)
        cap--;
    if (cap == 0)
        return 0;

    ssize_t n = read(STDIN_FILENO, input, cap);
    if (n > 0) {
        unsigned queries = 0;
        unsigned disconnects = 0;
        size_t out_len = client_escape_filter(&s->client_escape, escape_on,
                                              input, (size_t)n,
                                              filtered, sizeof(filtered),
                                              &queries, &disconnects);
        if (out_len == SIZE_MAX) {
            fprintf(stderr, "channel_pty: local escape filter overflow\n");
            s->run_failed = 1;
            session_close(s);
            return -1;
        }
        if (queries > 0)
            session_status_query(s);
        if (out_len != 0) {
            session_pacer_charge_read(s, out_len);
            if (sync_on) {
                if (sync_tx_append(s, filtered, out_len) != 0)
                    return -1;
            } else if (session_send_data(s, 1, PTY_DATA,
                                         filtered, out_len) != 0) {
                return -1;
            }
        }
        if (disconnects > 0)
            session_local_disconnect(s);
        return 0;
    }
    if (n == 0)
        return channel_pty_finish_stdin(s);
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return 0;
    return -1;
}

/* -------------------------------------------------------------------------
 * Client-side helpers used by main.c
 * ---------------------------------------------------------------------- */

int channel_pty_client_send_open(session_t *s, uint16_t rows, uint16_t cols)
{
    uint8_t body[8];
    body[0] = (uint8_t)(rows & 0xFF);
    body[1] = (uint8_t)((rows >> 8) & 0xFF);
    body[2] = (uint8_t)(cols & 0xFF);
    body[3] = (uint8_t)((cols >> 8) & 0xFF);
    body[4] = 0; body[5] = 0; body[6] = 0; body[7] = 0;

    /* send-scheduler arms count/backoff only from the terminal transport-result
     * callback. A record waiting for scheduler credit is not an attempt. */
    if (s->pty_open_tx_count == 0 && s->pty_open_backoff_ms == 0)
        s->pty_open_backoff_ms = 1000;
    s->pty_open_rows = rows;
    s->pty_open_cols = cols;

    return session_send_lane_tracked(s, SEND_LANE_INTERACTIVE,
                                     pty_chan_byte(), PTY_OPEN,
                                     body, sizeof(body),
                                     SESSION_TX_DONE_PTY_OPEN, 0, 0);
}

int channel_pty_client_send_resize(session_t *s, uint16_t rows, uint16_t cols)
{
    uint8_t body[8];
    body[0] = (uint8_t)(rows & 0xFF);
    body[1] = (uint8_t)((rows >> 8) & 0xFF);
    body[2] = (uint8_t)(cols & 0xFF);
    body[3] = (uint8_t)((cols >> 8) & 0xFF);
    body[4] = 0; body[5] = 0; body[6] = 0; body[7] = 0;
    return send_pty(s, PTY_RESIZE, body, sizeof(body));
}

int channel_pty_client_send_signal(session_t *s, uint8_t signum)
{
    uint8_t body[4];
    body[0] = signum;
    body[1] = 0; body[2] = 0; body[3] = 0;
    return send_pty(s, PTY_SIGNAL, body, sizeof(body));
}

void channel_pty_client_queue_signal(session_t *s, uint8_t signum)
{
    if (!s)
        return;
    s->pty_pending_signal = signum;
    s->pty_signal_pending = 1;
}

void channel_pty_client_queue_resize(session_t *s,
                                     uint16_t rows, uint16_t cols)
{
    if (!s)
        return;
    s->pty_pending_rows = rows;
    s->pty_pending_cols = cols;
    s->pty_resize_pending = 1;
}

int channel_pty_client_flush_control(session_t *s)
{
    if (!s)
        return -1;

    /* SIGNAL is an exact event. Do not clear it until the bounded scheduler
     * owns the record; a full INTERACTIVE lane is backpressure, not loss. */
    if (s->pty_signal_pending) {
        if (channel_pty_client_send_signal(s, s->pty_pending_signal) != 0)
            return -1;
        s->pty_signal_pending = 0;
    }

    /* RESIZE is latest-state-wins. A newer local sample may replace these
     * dimensions while admission is blocked, but the pending bit survives. */
    if (s->pty_resize_pending) {
        if (channel_pty_client_send_resize(s, s->pty_pending_rows,
                                           s->pty_pending_cols) != 0)
            return -1;
        s->pty_resize_pending = 0;
    }
    return 0;
}
