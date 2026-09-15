/*
 * channel.h — channel mux/demux interface
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * Channel handler interface.
 * Registration and dispatch via channel_register / channel_dispatch.
 */
#ifndef UNMOOR_CHANNEL_H
#define UNMOOR_CHANNEL_H

#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stddef.h>

/* Forward declaration */
typedef struct session session_t;

/* -------------------------------------------------------------------------
 * Channel handler interface (independent-channel-families)
 * ---------------------------------------------------------------------- */

/*
 * Channel handler return codes:
 *   CHAN_OK         0 — frame handled successfully
 *   CHAN_ERR       -1 — fatal error
 *   CHAN_SUPPRESSED -2 — frame intentionally dropped; CTRL_ERROR already sent
 */
enum {
    CHAN_OK         =  0,
    CHAN_ERR        = -1,
    CHAN_SUPPRESSED = -2,
    CHAN_UNNEGOTIATED = -3,
};

typedef struct channel_ops {
    uint8_t      id;
    const char  *name;
    /* All-of mask. Zero means the channel has no negotiated feature gate. */
    uint32_t     required_caps;
    /* Pure grammar/role check for epoch-rekey implicit epoch proof. It must not
     * mutate session or application state. NULL means this channel can never
     * supply implicit proof. */
    int  (*prevalidate)(const session_t *s, uint8_t chan_byte, uint8_t type,
                       const uint8_t *data, size_t len);
    int  (*on_open)  (session_t *s);
    /* on_data receives the full CHAN byte, type, body, body_len. */
    int  (*on_data)  (session_t *s, uint8_t chan_byte, uint8_t type,
                      const uint8_t *data, size_t len);
    int  (*on_close) (session_t *s);
} channel_ops_t;

/* -------------------------------------------------------------------------
 * Channel registry operations
 * ---------------------------------------------------------------------- */

/* Maximum number of channels (4-bit channel ID = 16 channels) */
#define CHANNEL_MAX 16

/*
 * Register a channel handler with a session.
 * Returns 0 on success, -1 if id >= CHANNEL_MAX or already registered.
 */
int channel_register(session_t *s, const channel_ops_t *ops);

/*
 * Dispatch a received plaintext payload to the appropriate channel handler.
 * chan is the full CHAN byte (bits 7-4 = channel id, bits 1-0 = fragment flags).
 * If no handler registered for the channel: sends CTRL_ERROR(ERR_CAPS) and drops.
 * Returns 0 on success, -1 on error.
 */
int channel_dispatch(session_t *s, uint8_t chan, uint8_t type,
                     const uint8_t *data, size_t len);

/* True only when the channel is registered and its complete required-
 * capability mask was selected. */
int channel_is_negotiated(const session_t *s, uint8_t chan_id);

/* Run the registered channel's mutation-free implicit-proof validator. */
int channel_prevalidate(const session_t *s, uint8_t chan, uint8_t type,
                        const uint8_t *data, size_t len);

/*
 * Call on_open for all registered channels.
 */
void channel_open_all(session_t *s);

/*
 * Call on_close for all registered channels.
 */
void channel_close_all(session_t *s);

/* -------------------------------------------------------------------------
 * Built-in channel ops (defined in channel.c)
 * ---------------------------------------------------------------------- */

extern const channel_ops_t channel_control_ops; /* ch 0 */
extern const channel_ops_t channel_pty_ops;     /* ch 1 — stub */

#endif /* UNMOOR_CHANNEL_H */
