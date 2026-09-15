/*
 * channel_delivery.c — delivery-class latest-block channel
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * The fixed delivery engine and session scheduler own all state.  This file
 * is deliberately only the channel-2 dispatch boundary, matching the split
 * between channel_pty.c and the terminal state sync engine.
 */

#define _POSIX_C_SOURCE 200809L

#include "channel_delivery.h"
#include "frame.h"
#include "negotiation.h"
#include "session.h"

static int delivery_prevalidate(const session_t *s, uint8_t chan_byte,
                                uint8_t type, const uint8_t *data, size_t len)
{
    uint16_t object_id = 0;

    if ((chan_byte >> 4) != DELIVERY_CHANNEL_ID ||
        (chan_byte & 0x0fU) != CHAN_FF_BIT)
        return CHAN_ERR;
    return session_delivery_prevalidate_latest(
               s, type, data, len, &object_id) == DELIVERY_RESULT_OK
         ? CHAN_OK : CHAN_ERR;
}

static int delivery_on_data(session_t *s, uint8_t chan_byte, uint8_t type,
                            const uint8_t *data, size_t len)
{
    if ((chan_byte >> 4) != DELIVERY_CHANNEL_ID ||
        (chan_byte & 0x0fU) != CHAN_FF_BIT)
        return CHAN_ERR;
    return session_delivery_receive_latest(s, type, data, len) == 0
         ? CHAN_OK : CHAN_ERR;
}

const channel_ops_t channel_delivery_ops = {
    .id = DELIVERY_CHANNEL_ID,
    .name = "latest-block-v1",
    .required_caps = UNMOOR_CAP_LATEST_BLOCK_D31_V1,
    .prevalidate = delivery_prevalidate,
    .on_open = NULL,
    .on_data = delivery_on_data,
    .on_close = NULL,
};
