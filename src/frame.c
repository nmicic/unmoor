/*
 * frame.c — Unmoor wire frame encode/decode
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * Little-endian throughout. Ten header bytes (everything except LEN) form
 * base AEAD associated data. Multi-fragment records extend that AD with their
 * clear descriptor; see session.c.
 */

#define _POSIX_C_SOURCE 200809L

#include <string.h>
#include "frame.h"

int unmoor_frame_encode(const uint8_t pair_id[4], uint32_t seq,
                        uint8_t chan, uint8_t type,
                        const uint8_t *ct, size_t ct_len,
                        uint8_t *out, size_t out_max)
{
    if (ct_len < FRAME_MIN_CT_LEN) return -1;
    if (ct_len > UINT16_MAX) return -1;
    if (out_max < FRAME_HEADER_LEN ||
        ct_len > out_max - FRAME_HEADER_LEN) return -1;

    memcpy(out, pair_id, 4);
    out[4]  = (uint8_t)(seq        & 0xFF);
    out[5]  = (uint8_t)((seq >> 8)  & 0xFF);
    out[6]  = (uint8_t)((seq >> 16) & 0xFF);
    out[7]  = (uint8_t)((seq >> 24) & 0xFF);
    out[8]  = chan;
    out[9]  = type;
    out[10] = (uint8_t)(ct_len & 0xFF);
    out[11] = (uint8_t)((ct_len >> 8) & 0xFF);
    /* bulk-transfer encodes ciphertext directly into its retained frame arena after
     * the header.  memmove keeps the legacy separate-buffer path identical
     * and makes that exact in-arena source/destination overlap defined. */
    memmove(out + FRAME_HEADER_LEN, ct, ct_len);
    return (int)(FRAME_HEADER_LEN + ct_len);
}

int unmoor_frame_decode(const uint8_t *frame, size_t frame_len,
                        uint8_t pair_id_out[4], uint32_t *seq_out,
                        uint8_t *chan_out, uint8_t *type_out,
                        const uint8_t **ct_out, size_t *ct_len_out)
{
    if (frame_len < FRAME_HEADER_LEN) return -1;

    size_t ct_len = (size_t)frame[10] | ((size_t)frame[11] << 8);
    if (ct_len < FRAME_MIN_CT_LEN) return -1;
    if (FRAME_HEADER_LEN + ct_len != frame_len) return -1;

    if (pair_id_out) memcpy(pair_id_out, frame, 4);
    if (seq_out) {
        *seq_out = (uint32_t)frame[4]
                 | ((uint32_t)frame[5] << 8)
                 | ((uint32_t)frame[6] << 16)
                 | ((uint32_t)frame[7] << 24);
    }
    if (chan_out)   *chan_out   = frame[8];
    if (type_out)   *type_out   = frame[9];
    if (ct_out)     *ct_out     = frame + FRAME_HEADER_LEN;
    if (ct_len_out) *ct_len_out = ct_len;
    return 0;
}
