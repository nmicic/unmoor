/*
 * channel.c — channel mux/demux (registry + dispatch only)
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * Per-channel handlers live in:
 *   channel_control.c — ch 0 (control)
 *   channel_pty.c     — ch 1 (PTY)
 *
 * channel_control_ops / channel_pty_ops are kept as thin aliases for the
 * extern names published by those files, so main.c can register them via
 * stable symbols.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>
#include "channel.h"
#include "channel_pty.h"
#include "session.h"
#include "frame.h"

/* -------------------------------------------------------------------------
 * Aliases so existing registration call sites (channel_control_ops /
 * channel_pty_ops) keep working after the channel split.
 * ---------------------------------------------------------------------- */

extern const channel_ops_t channel_control; /* channel_control.c */
extern const channel_ops_t channel_pty;     /* channel_pty.c */

const channel_ops_t channel_control_ops = {
    .id       = 0,
    .name     = "control",
    .required_caps = 0,
    .on_open  = NULL,
    .on_data  = NULL,
    .on_close = NULL,
};

const channel_ops_t channel_pty_ops = {
    .id       = 1,
    .name     = "pty",
    .required_caps = UNMOOR_CAP_PTY_V1,
    .on_open  = NULL,
    .on_data  = NULL,
    .on_close = NULL,
};

/* -------------------------------------------------------------------------
 * channel_register
 * ---------------------------------------------------------------------- */

int channel_register(session_t *s, const channel_ops_t *ops)
{
    if (!ops || ops->id >= CHANNEL_MAX) {
        fprintf(stderr, "channel_register: invalid channel id %u\n",
                ops ? ops->id : 255);
        return -1;
    }
    /* Transparent rewrite: the alias stubs above get replaced by the real
     * handler from channel_control.c / channel_pty.c. This keeps call sites
     * in main.c compatible. */
    const channel_ops_t *effective = ops;
    if (ops == &channel_control_ops) effective = &channel_control;
    else if (ops == &channel_pty_ops) effective = &channel_pty;

    if (s->channels[effective->id]) {
        fprintf(stderr, "channel_register: channel %u already registered\n",
                effective->id);
        return -1;
    }
    s->channels[effective->id] = effective;
    return 0;
}

/* -------------------------------------------------------------------------
 * channel_dispatch
 * ---------------------------------------------------------------------- */

int channel_dispatch(session_t *s, uint8_t chan_byte, uint8_t type,
                     const uint8_t *data, size_t len)
{
    uint8_t chan_id = (chan_byte >> 4) & 0x0F;

    if (chan_id >= CHANNEL_MAX || !s->channels[chan_id]) {
        fprintf(stderr, "channel_dispatch: no handler for ch %u — sending ERR_CAPS\n",
                chan_id);
        if (s->state == SESSION_ESTABLISHED) {
            session_protocol_error_close(s, ERR_CAPS);
        }
        return CHAN_UNNEGOTIATED;
    }

    const channel_ops_t *ops = s->channels[chan_id];
    if (!channel_is_negotiated(s, chan_id)) {
        fprintf(stderr,
                "channel_dispatch: ch %u requires caps=0x%08X "
                "selected=0x%08X — ERR_CAPS\n",
                chan_id, ops->required_caps, s->selected_caps);
        if (s->state == SESSION_ESTABLISHED) {
            session_protocol_error_close(s, ERR_CAPS);
        }
        return CHAN_UNNEGOTIATED;
    }
    if (!ops->on_data) return CHAN_OK;
    return ops->on_data(s, chan_byte, type, data, len);
}

int channel_is_negotiated(const session_t *s, uint8_t chan_id)
{
    if (!s || chan_id >= CHANNEL_MAX || !s->channels[chan_id])
        return 0;
    uint32_t required = s->channels[chan_id]->required_caps;
    return (required & ~s->selected_caps) == 0;
}

int channel_prevalidate(const session_t *s, uint8_t chan_byte, uint8_t type,
                        const uint8_t *data, size_t len)
{
    uint8_t chan_id = (uint8_t)((chan_byte >> 4) & 0x0fU);

    if (!s || chan_id >= CHANNEL_MAX || !s->channels[chan_id] ||
        !channel_is_negotiated(s, chan_id) ||
        !s->channels[chan_id]->prevalidate)
        return CHAN_ERR;
    return s->channels[chan_id]->prevalidate(
        s, chan_byte, type, data, len);
}

/* -------------------------------------------------------------------------
 * channel_open_all / channel_close_all
 * ---------------------------------------------------------------------- */

void channel_open_all(session_t *s)
{
    for (int i = 0; i < CHANNEL_MAX; i++) {
        if (s->channels[i] && channel_is_negotiated(s, (uint8_t)i) &&
            s->channels[i]->on_open)
            s->channels[i]->on_open(s);
    }
}

void channel_close_all(session_t *s)
{
    for (int i = 0; i < CHANNEL_MAX; i++) {
        if (s->channels[i] && s->channels[i]->on_close)
            s->channels[i]->on_close(s);
    }
}
