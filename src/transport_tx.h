/*
 * transport_tx.h — one-frame nonblocking stream-framing writer
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef UNMOOR_TRANSPORT_TX_H
#define UNMOOR_TRANSPORT_TX_H

#define _POSIX_C_SOURCE 200809L

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* Shared with transport_ops.send_step. */
#define TRANSPORT_SEND_FAILED      (-1)
#define TRANSPORT_SEND_COMPLETE      0
#define TRANSPORT_SEND_WOULD_BLOCK   1
#define TRANSPORT_SEND_PROGRESS      2
/* Datagram rejected because the complete payload exceeds the selected path.
 * bulk-transfer consumes this as per-leg MTU state; other users treat it as FAILED. */
#define TRANSPORT_SEND_TOO_LARGE     3

typedef ssize_t (*transport_tx_write_fn)(void *ctx,
                                         const uint8_t *buf, size_t len);

/* No payload copy: the session retains exactly one immutable encoded frame.
 * This state owns only the two-byte stream prefix and an offset. */
typedef struct {
    size_t frame_len;
    size_t offset;       /* prefix + body bytes completed */
    uint8_t prefix[2];
    uint8_t active;
} transport_stream_tx_t;

void transport_stream_tx_reset(transport_stream_tx_t *tx);

/* Discard a retained frame only before any prefix/body byte was written.
 * Returns -1 for an inactive writer or after any progress. */
int transport_stream_tx_cancel_untouched(transport_stream_tx_t *tx);

/* Performs at most one write callback. Repeated calls must provide the same
 * immutable frame until COMPLETE/FAILED. */
int transport_stream_tx_step(transport_stream_tx_t *tx,
                             const uint8_t *frame, size_t frame_len,
                             transport_tx_write_fn write_fn, void *write_ctx);

#endif /* UNMOOR_TRANSPORT_TX_H */
