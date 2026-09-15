/*
 * frame.h — Unmoor wire frame encode/decode
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef UNMOOR_FRAME_H
#define UNMOOR_FRAME_H

#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stddef.h>

/* -------------------------------------------------------------------------
 * Constants
 * ---------------------------------------------------------------------- */

/* Protocol v2 moves ordinary terminal traffic from the small radio-oriented
 * budget inherited from URTB to an Internet-sized UDP datagram. A mismatched
 * peer is refused; this experimental protocol has no downgrade path. */
#define UNMOOR_VERSION       "0.2.0"
#define UNMOOR_PROTO_VERSION 2

/* Wire frame layout. For multi-fragment data, CIPHERTEXT begins with a clear
 * 16-byte descriptor whose bytes are authenticated as extended AEAD AD; the
 * remainder is the actual ciphertext and tag. LEN covers both. */
#define FRAME_HEADER_LEN    12  /* PAIR_ID[4] SEQ[4] CHAN[1] TYPE[1] LEN[2] */
#define FRAME_TAG_LEN       16  /* Poly1305 auth tag */
#define FRAME_MIN_CT_LEN    16  /* empty plaintext + tag */
#define FRAME_MIN_LEN       (FRAME_HEADER_LEN + FRAME_MIN_CT_LEN)  /* 28 */

/* Complete ordinary terminal datagram, including the Unmoor header and tag.
 * The separate control budget keeps the hybrid bootstrap/rekey geometry
 * stable while terminal traffic can efficiently use normal network paths. */
#define UNMOOR_TERMINAL_WIRE_MAX       1200
#define UNMOOR_TERMINAL_PLAINTEXT_MAX  \
    (UNMOOR_TERMINAL_WIRE_MAX - FRAME_HEADER_LEN - FRAME_TAG_LEN) /* 1172 */
#define UNMOOR_CONTROL_PLAINTEXT_MAX   222

#define FRAME_MAX_LEN       UNMOOR_TERMINAL_WIRE_MAX

/* Channel byte fragment flags */
#define CHAN_FF_BIT          0x02  /* FIRST_FRAGMENT */
#define CHAN_MF_BIT          0x01  /* MORE_FRAGMENTS */

/* Control channel types (CHAN=0) */
#define CTRL_HELLO          0x01
#define CTRL_HELLO_ACK      0x02
#define CTRL_READY          0x03
#define CTRL_CLOSE          0x04
#define CTRL_KEEPALIVE      0x05
#define CTRL_KEEPALIVE_ACK  0x06
#define CTRL_STATUS_HEARTBEAT 0x07
#define CTRL_ERROR          0x08
/* epoch-rekey authenticated epoch-rekey control. All are channel-zero,
 * single-frame records and require EPOCH_REKEY_D28_V1. */
#define CTRL_REKEY_REQUEST  0x09
#define CTRL_REKEY_INIT     0x0A
#define CTRL_REKEY_REPLY    0x0B
#define CTRL_REKEY_CONFIRM  0x0C
#define CTRL_REKEY_COMMIT   0x0D
#define CTRL_REKEY_ACK      0x0E
/* delivery-class bounded reliable-datagram control. These are ordinary current-epoch
 * single-frame records and require RELIABLE_DGRAM_D31_V1. */
#define CTRL_RD_DATA        0x0F
#define CTRL_RD_STATUS      0x10
/* multipath current-epoch, exact-ingress path validation. */
#define CTRL_PATH_CHALLENGE 0x11
#define CTRL_PATH_RESPONSE  0x12
/* pq-hybrid bounded current-epoch hybrid-rekey repair. SHARE carries a clear
 * authenticated descriptor plus an encrypted slice; BITMAP is one ordinary
 * encrypted control plaintext. */
#define CTRL_REKEY_PQ_SHARE  0x18
#define CTRL_REKEY_PQ_BITMAP 0x19

/* Error codes */
#define ERR_AUTH_FAIL       0x0001
#define ERR_REPLAY          0x0002
#define ERR_VERSION         0x0003
#define ERR_CAPS            0x0004
#define ERR_SESSION         0x0005
#define ERR_RESOURCE        0x0006
#define ERR_TIMEOUT         0x0007

/* PTY channel types (CHAN=1) */
#define PTY_OPEN            0x01
#define PTY_OPEN_ACK        0x02
#define PTY_OPEN_ERR        0x03
#define PTY_DATA            0x04
#define PTY_RESIZE          0x05
#define PTY_SIGNAL          0x06
#define PTY_CLOSE           0x07
#define PTY_EOF             0x08
/* terminal state sync. Carried only when PTY_SYNC_V1 was
 * negotiated; PTY_DATA/PTY_EOF and these two are mutually exclusive per
 * session. */
#define PTY_SYNC_DATA       0x09
#define PTY_SYNC_ACK        0x0A

/* delivery-class latest-block telemetry channel (CHAN=2). Every record is canonical
 * FF=1/MF=0 and requires LATEST_BLOCK_D31_V1. */
#define DELIVERY_CHANNEL_ID 2
#define LATEST_HEAD         0x01
#define LATEST_BLOCK        0x02
#define LATEST_STATUS       0x03

/* -------------------------------------------------------------------------
 * Frame encode/decode
 * ---------------------------------------------------------------------- */

/*
 * Encode a frame (header + ciphertext).
 * ct must already be the full CIPHERTEXT (ciphertext + tag concatenated).
 * Returns total bytes written, or -1 on error.
 */
int unmoor_frame_encode(const uint8_t pair_id[4], uint32_t seq,
                        uint8_t chan, uint8_t type,
                        const uint8_t *ct, size_t ct_len,
                        uint8_t *out, size_t out_max);

/*
 * Decode a frame header.
 * Fills pair_id_out, seq_out, chan_out, type_out.
 * Sets ct_out to point into frame (zero-copy). Sets ct_len_out.
 * Returns 0 on success, -1 on truncated/invalid frame.
 * Does NOT validate the AEAD tag — the caller must decrypt.
 */
int unmoor_frame_decode(const uint8_t *frame, size_t frame_len,
                        uint8_t pair_id_out[4], uint32_t *seq_out,
                        uint8_t *chan_out, uint8_t *type_out,
                        const uint8_t **ct_out, size_t *ct_len_out);

#endif /* UNMOOR_FRAME_H */
