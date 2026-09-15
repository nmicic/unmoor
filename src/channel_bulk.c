/*
 * channel_bulk.c — bulk-file transfer channel
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * Session owns authentication, replay, epoch authority and the fixed
 * bulk engine.  This file is deliberately only the canonical channel-3
 * dispatch boundary.
 */

#define _POSIX_C_SOURCE 200809L

#include "channel_bulk.h"
#include "bulk.h"
#include "frame.h"
#include "negotiation.h"
#include "session.h"

static int bulk_prevalidate(const session_t *s, uint8_t chan_byte,
                            uint8_t type, const uint8_t *data, size_t len)
{
    if ((chan_byte >> 4) != BULK_CHANNEL_ID ||
        (chan_byte & 0x0fU) != CHAN_FF_BIT)
        return CHAN_ERR;
    return session_bulk_prevalidate(s, type, data, len) == 0
         ? CHAN_OK : CHAN_ERR;
}

static int bulk_on_data(session_t *s, uint8_t chan_byte, uint8_t type,
                        const uint8_t *data, size_t len)
{
    if ((chan_byte >> 4) != BULK_CHANNEL_ID ||
        (chan_byte & 0x0fU) != CHAN_FF_BIT)
        return CHAN_ERR;
    return session_bulk_receive(s, type, data, len) == 0
         ? CHAN_OK : CHAN_ERR;
}

const channel_ops_t channel_bulk_ops = {
    .id = BULK_CHANNEL_ID,
    .name = "bulk-file-v1",
    .required_caps = UNMOOR_CAP_BULK_FILE_D33_V1,
    .prevalidate = bulk_prevalidate,
    .on_open = NULL,
    .on_data = bulk_on_data,
    .on_close = NULL,
};
