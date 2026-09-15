/*
 * channel_control.c — control channel handler (ch 0)
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * Ch 0 control frame handling (CTRL_HELLO/ACK/READY/KEEPALIVE/CLOSE/ERROR)
 * is driven directly from session.c's dispatch_control() — the state machine
 * lives there because control frames are tightly coupled to the handshake
 * and replay state. This file exists so the channel_ops_t vtable has a
 * registered handler for chan 0 that channel_dispatch() can fall through
 * harmlessly; in practice ch 0 never reaches channel_dispatch — session.c
 * routes it directly.
 *
 * See the channel 0 control-message definitions and the channel handler
 * interface).
 */

#define _POSIX_C_SOURCE 200809L

#include "channel.h"

static int ctrl_on_open(session_t *s)
{
    (void)s;
    return 0;
}

static int ctrl_on_data(session_t *s, uint8_t chan_byte, uint8_t type,
                        const uint8_t *data, size_t len)
{
    /* Ch 0 frames are dispatched directly by session.c after AEAD verify.
     * This fallback is reached only if something unusual routes through
     * channel_dispatch — do nothing. */
    (void)s; (void)chan_byte; (void)type; (void)data; (void)len;
    return CHAN_OK;
}

static int ctrl_on_close(session_t *s)
{
    (void)s;
    return 0;
}

const channel_ops_t channel_control = {
    .id       = 0,
    .name     = "control",
    .required_caps = 0,
    .on_open  = ctrl_on_open,
    .on_data  = ctrl_on_data,
    .on_close = ctrl_on_close,
};
