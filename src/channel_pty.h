/*
 * channel_pty.h — PTY channel handler (ch 1)
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * Implements channel_ops_t for chan 1 using the frame types defined in
 * (PTY_OPEN / PTY_OPEN_ACK / PTY_OPEN_ERR / PTY_DATA /
 * PTY_RESIZE / PTY_SIGNAL / PTY_EOF).
 */
#ifndef UNMOOR_CHANNEL_PTY_H
#define UNMOOR_CHANNEL_PTY_H

#include "channel.h"

/* Registered on both sides. Server spawns on PTY_OPEN; client enters raw
 * mode on PTY_OPEN_ACK. */
extern const channel_ops_t channel_pty;

/* Weak hook: called from channel_pty.c when the client receives
 * PTY_OPEN_ACK. main.c provides the implementation to enter raw mode.
 * If NULL, no raw-mode transition happens. */
typedef void (*channel_pty_on_ack_fn)(session_t *s);
extern channel_pty_on_ack_fn channel_pty_on_client_ack;

/* channel-session lifecycle seams. They perform only the local PTY transition; channel
 * zero owns ACCEPT/REFUSE and therefore no legacy PTY control is emitted.
 * Also used by classic OPEN: accepted server source end refuses local start
 * with -1/EPIPE and unchanged pid_out; channel-session remains outside that rule. */
int channel_pty_server_start(session_t *s, uint16_t rows, uint16_t cols,
                             uint32_t *pid_out);
void channel_pty_client_open_accepted(session_t *s);
void channel_pty_client_open_refused(session_t *s, uint32_t code);
int channel_pty_close_instance(session_t *s);

/* Called by session_run when PTY master fd is readable (server side).
 * Reads up to s->current_mtu bytes, wraps as PTY_DATA and sends encrypted.
 * On EOF/EIO: sends PTY_EOF + CTRL_CLOSE. */
int channel_pty_pump_master(session_t *s);

/* Called by session_run when stdin is readable (client side). Reads up to
 * s->current_mtu bytes and sends as PTY_DATA. EOF finishes only the input
 * direction and returns 0; a local failure returns -1. */
int channel_pty_pump_stdin(session_t *s);

/* Convert an unavailable local stdin into the same one-time codeless input
 * FIN as read(2) EOF.  This also flushes a locally held escape byte before
 * closing the input direction. */
int channel_pty_finish_stdin(session_t *s);

/* Flush the server's PTY master write backlog when POLLOUT fires. */
int channel_pty_flush_master_backlog(session_t *s);

/* Helpers used by main.c on the client side. */
int channel_pty_client_send_open(session_t *s, uint16_t rows, uint16_t cols);
int channel_pty_client_send_resize(session_t *s, uint16_t rows, uint16_t cols);
int channel_pty_client_send_signal(session_t *s, uint8_t signum);

/* Signal-handler handoff: queue one exact signal and latest resize in fixed
 * session state, then retry admission until the send-scheduler INTERACTIVE lane has
 * room. `flush` returns 0 only when both pending values were admitted. */
void channel_pty_client_queue_signal(session_t *s, uint8_t signum);
void channel_pty_client_queue_resize(session_t *s,
                                     uint16_t rows, uint16_t cols);
int channel_pty_client_flush_control(session_t *s);

#endif /* UNMOOR_CHANNEL_PTY_H */
