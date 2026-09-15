/*
 * negotiation.h — authenticated HELLO capability negotiation
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef UNMOOR_NEGOTIATION_H
#define UNMOOR_NEGOTIATION_H

#include <stddef.h>
#include <stdint.h>

#include "frame.h"

#define NEGOTIATION_PLAIN_LEN 32U
#define NEGOTIATION_NONCE_LEN 16U
#define NEGOTIATION_READY_LEN 8U

#define NEGOTIATION_HELLO_VERSION 0x02U
#define NEGOTIATION_MARKER_BIT    0x80U
#define NEGOTIATION_READY_VERSION 0x01U
#define NEGOTIATION_READY_NEED_ACK 0x01U

/* Exact, immutable feature-format identities. A later incompatible format
 * gets another bit; these are not a numeric compatibility range. */
#define UNMOOR_CAP_PTY_V1          UINT32_C(0x00000001)
#define UNMOOR_CAP_FRAGMENT_D21_V1 UINT32_C(0x00000002)
#define UNMOOR_CAP_PTY_SYNC_V1     UINT32_C(0x00000004)
#define UNMOOR_CAP_EPOCH_REKEY_D28_V1 UINT32_C(0x00000008)
#define UNMOOR_CAP_STATUS_HEARTBEAT_V1 UINT32_C(0x00000010)
#define UNMOOR_CAP_LATEST_BLOCK_D31_V1 UINT32_C(0x00000020)
#define UNMOOR_CAP_RELIABLE_DGRAM_D31_V1 UINT32_C(0x00000040)
#define UNMOOR_CAP_MULTIPATH_2_D32_V1  UINT32_C(0x00000080)
#define UNMOOR_CAP_MULTIPATH_4_D32_V1  UINT32_C(0x00000100)
#define UNMOOR_CAP_MULTIPATH_8_D32_V1  UINT32_C(0x00000200)
#define UNMOOR_CAP_MULTIPATH_16_D32_V1 UINT32_C(0x00000400)
#define UNMOOR_CAP_MULTIPATH_32_D32_V1 UINT32_C(0x00000800)
#define UNMOOR_CAP_MULTIPATH_D32_MASK  UINT32_C(0x00000f80)
#define UNMOOR_CAP_BULK_FILE_D33_V1    UINT32_C(0x00001000)
/* 0x00002000 remains deliberately unallocated pending a future capability assignment. */
#define UNMOOR_CAP_CHANNEL_SESSION_D36_V1   UINT32_C(0x00004000)
#define UNMOOR_CAP_CHANNEL_TERMINAL_D36_V1  UINT32_C(0x00008000)
#define UNMOOR_CAP_CHANNEL_EXEC_D36_V1      UINT32_C(0x00010000)
/* child-transfer withdrew the unpromoted channel-session bulk grammar.  0x00020000 and
 * 0x00040000 are unallocated and intentionally have no public names. */
#define UNMOOR_CAP_PQ_HYBRID_D45_V1       UINT32_C(0x00080000)
#define UNMOOR_CAP_CHANNEL_KINDS_D36_MASK \
    (UNMOOR_CAP_CHANNEL_TERMINAL_D36_V1 | \
     UNMOOR_CAP_CHANNEL_EXEC_D36_V1)
/* Source compatibility for the original two-path capability spelling. */
#define UNMOOR_CAP_MULTIPATH_D32_V1 UNMOOR_CAP_MULTIPATH_2_D32_V1

/* Exact delivery-class plaintext geometry. A capability is withheld before HELLO when
 * the configured plaintext MTU cannot carry its largest mandatory control
 * record. */
#define UNMOOR_LATEST_BLOCK_D31_MIN_MTU 216U
#define UNMOOR_RELIABLE_DGRAM_D31_MIN_MTU 208U
#define UNMOOR_LATEST_BLOCK_D31_CHANNEL_MIN_MTU \
    (UNMOOR_LATEST_BLOCK_D31_MIN_MTU + 4U)
#define UNMOOR_RELIABLE_DGRAM_D31_CHANNEL_MIN_MTU \
    (UNMOOR_RELIABLE_DGRAM_D31_MIN_MTU + 4U)

#define UNMOOR_CAP_DEFAULT_SUPPORTED \
    (UNMOOR_CAP_PTY_V1 | UNMOOR_CAP_FRAGMENT_D21_V1 | \
     UNMOOR_CAP_PTY_SYNC_V1 | UNMOOR_CAP_STATUS_HEARTBEAT_V1 | \
     UNMOOR_CAP_LATEST_BLOCK_D31_V1 | \
     UNMOOR_CAP_RELIABLE_DGRAM_D31_V1)
#define UNMOOR_CAP_DEFAULT_REQUIRED UNMOOR_CAP_PTY_V1

typedef enum {
    NEGOTIATION_INVALID = -1,
    NEGOTIATION_LEGACY  = 0,
    NEGOTIATION_NEG1    = 1,
} negotiation_kind_t;

typedef struct {
    negotiation_kind_t kind;
    uint8_t             nonce[NEGOTIATION_NONCE_LEN];
    uint32_t            supported_caps; /* ACK: selected capabilities */
    uint32_t            required_caps;
    uint16_t            status;         /* HELLO: always zero */
} negotiation_message_t;

/* Encode one canonical 32-byte plaintext. */
void negotiation_encode_legacy(uint8_t out[NEGOTIATION_PLAIN_LEN],
                               const uint8_t nonce[NEGOTIATION_NONCE_LEN],
                               uint8_t legacy_caps);
void negotiation_encode_hello(uint8_t out[NEGOTIATION_PLAIN_LEN],
                              const uint8_t nonce[NEGOTIATION_NONCE_LEN],
                              uint32_t supported_caps,
                              uint32_t required_caps);
void negotiation_encode_ack(uint8_t out[NEGOTIATION_PLAIN_LEN],
                            const uint8_t nonce[NEGOTIATION_NONCE_LEN],
                            uint32_t selected_caps,
                            uint32_t required_caps,
                            uint16_t status);

/* Decode and validate canonical grammar. Returns 0 or ERR_VERSION/ERR_CAPS.
 * A legacy plaintext is exactly version 0x02, marker clear, and fourteen
 * zero reserved bytes. Unknown legacy caps are ignored except PTY_V1. */
uint16_t negotiation_decode(const uint8_t *plain, size_t plain_len,
                            int is_ack, negotiation_message_t *out);

/* Server selection and client validation. Both operate only on NEG1 input.
 * ACK supported_caps is the selected intersection, not the server offer. */
uint16_t negotiation_select(const negotiation_message_t *hello,
                            uint32_t local_supported,
                            uint32_t local_required,
                            uint32_t *selected_out);
uint16_t negotiation_validate_ack(const negotiation_message_t *ack,
                                  uint32_t offered_caps,
                                  uint32_t local_required,
                                  uint32_t *selected_out);

/* multipath path count is an exact one-hot capability, not a numeric range.
 * `path_count_out` receives 0 when no multipath bit is present. Multiple bits are
 * noncanonical and return -1. Unsupported counts map to capability 0. */
uint32_t negotiation_multipath_capability(unsigned int path_count);
int negotiation_multipath_path_count(uint32_t caps,
                                     uint8_t *path_count_out);

void negotiation_ready_encode(uint8_t out[NEGOTIATION_READY_LEN],
                              uint8_t flags, uint32_t selected_caps);
int negotiation_ready_decode(const uint8_t *plain, size_t plain_len,
                             uint32_t expected_caps, uint8_t *flags_out);

#endif /* UNMOOR_NEGOTIATION_H */
