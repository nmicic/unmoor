/*
 * transport_tx.c — one-frame nonblocking stream-framing writer
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#include "transport_tx.h"

#include <errno.h>
#include <string.h>

void transport_stream_tx_reset(transport_stream_tx_t *tx)
{
    if (tx)
        memset(tx, 0, sizeof(*tx));
}

int transport_stream_tx_cancel_untouched(transport_stream_tx_t *tx)
{
    if (!tx || !tx->active || tx->offset != 0)
        return -1;
    transport_stream_tx_reset(tx);
    return 0;
}

int transport_stream_tx_step(transport_stream_tx_t *tx,
                             const uint8_t *frame, size_t frame_len,
                             transport_tx_write_fn write_fn, void *write_ctx)
{
    const uint8_t *part;
    size_t part_len;
    ssize_t written;

    if (!tx || !frame || !write_fn || frame_len == 0 || frame_len > 0xffffU)
        return TRANSPORT_SEND_FAILED;
    if (!tx->active) {
        tx->frame_len = frame_len;
        tx->offset = 0;
        tx->prefix[0] = (uint8_t)(frame_len & 0xffU);
        tx->prefix[1] = (uint8_t)((frame_len >> 8) & 0xffU);
        tx->active = 1;
    } else if (tx->frame_len != frame_len) {
        /* A second frame must never interleave with the retained one. */
        return TRANSPORT_SEND_FAILED;
    }

    if (tx->offset < sizeof(tx->prefix)) {
        part = tx->prefix + tx->offset;
        part_len = sizeof(tx->prefix) - tx->offset;
    } else {
        size_t body_off = tx->offset - sizeof(tx->prefix);
        if (body_off >= frame_len) {
            transport_stream_tx_reset(tx);
            return TRANSPORT_SEND_COMPLETE;
        }
        part = frame + body_off;
        part_len = frame_len - body_off;
    }

    written = write_fn(write_ctx, part, part_len);
    if (written < 0) {
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
            errno = 0;
            return TRANSPORT_SEND_WOULD_BLOCK;
        }
        transport_stream_tx_reset(tx);
        return TRANSPORT_SEND_FAILED;
    }
    if (written == 0)
        return TRANSPORT_SEND_WOULD_BLOCK;
    if ((size_t)written > part_len) {
        transport_stream_tx_reset(tx);
        return TRANSPORT_SEND_FAILED;
    }
    tx->offset += (size_t)written;
    if (tx->offset == sizeof(tx->prefix) + frame_len) {
        transport_stream_tx_reset(tx);
        return TRANSPORT_SEND_COMPLETE;
    }
    return TRANSPORT_SEND_PROGRESS;
}
