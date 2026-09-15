/*
 * negotiation.c — authenticated HELLO capability negotiation
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include "negotiation.h"

#define OFF_VERSION   0U
#define OFF_CAPS8     1U
#define OFF_NONCE     2U
#define OFF_SUPPORTED 18U
#define OFF_REQUIRED  22U
#define OFF_STATUS    26U
#define OFF_MAGIC     28U

static const uint8_t neg1_magic[4] = { 'N', 'E', 'G', '1' };

/* Capability bits identify exact grammars, but some grammars deliberately
 * depend on another negotiated service.  Epoch-rekey is an epoch barrier for the
 * terminal-sync path; selecting it without both PTY and PTY_SYNC would make
 * the same authenticated bit mean a different state machine. */
static int capability_dependencies_valid(uint32_t caps)
{
    const uint32_t d28_dependencies = UNMOOR_CAP_PTY_V1 |
                                      UNMOOR_CAP_PTY_SYNC_V1;
    const uint32_t status_dependencies = UNMOOR_CAP_PTY_V1 |
                                         UNMOOR_CAP_PTY_SYNC_V1;
    const uint32_t terminal_application_caps =
        UNMOOR_CAP_PTY_V1 |
        UNMOOR_CAP_FRAGMENT_D21_V1 |
        UNMOOR_CAP_PTY_SYNC_V1 |
        UNMOOR_CAP_STATUS_HEARTBEAT_V1 |
        UNMOOR_CAP_LATEST_BLOCK_D31_V1 |
        UNMOOR_CAP_RELIABLE_DGRAM_D31_V1;
    const uint32_t d36_kinds = caps & UNMOOR_CAP_CHANNEL_KINDS_D36_MASK;
    const int d36 = (caps & UNMOOR_CAP_CHANNEL_SESSION_D36_V1) != 0;
    const int d36_terminal =
        (caps & UNMOOR_CAP_CHANNEL_TERMINAL_D36_V1) != 0;
    uint8_t multipath_count = 0U;

    if ((d36_kinds != 0U) != d36 || (d36 && d36_kinds == 0U))
        return 0;
    if (d36) {
        const uint32_t terminal_required =
            UNMOOR_CAP_PTY_V1 | UNMOOR_CAP_FRAGMENT_D21_V1 |
            UNMOOR_CAP_PTY_SYNC_V1;

        /* Class 2 has no channel-session kind in v1. Its legacy session services must
         * not be silently selected into a grammar with no inner route. */
        if ((caps & (UNMOOR_CAP_LATEST_BLOCK_D31_V1 |
                     UNMOOR_CAP_RELIABLE_DGRAM_D31_V1)) != 0U)
            return 0;
        if (d36_terminal &&
            (caps & terminal_required) != terminal_required)
            return 0;
        if (!d36_terminal &&
            (caps & (UNMOOR_CAP_PTY_V1 |
                     UNMOOR_CAP_FRAGMENT_D21_V1 |
                     UNMOOR_CAP_PTY_SYNC_V1 |
                     UNMOOR_CAP_STATUS_HEARTBEAT_V1)) != 0U)
            return 0;
        /* child-transfer launches byte-identical bulk-transfer child sessions.  Bulk-transfer never
         * becomes a grammar inside a channel-session control session. */
        if ((caps & UNMOOR_CAP_BULK_FILE_D33_V1) != 0U)
            return 0;
    }
    if ((caps & UNMOOR_CAP_BULK_FILE_D33_V1) != 0) {
        if ((caps & UNMOOR_CAP_EPOCH_REKEY_D28_V1) == 0 ||
            (!d36 && (caps & terminal_application_caps) != 0))
            return 0;
    }
    if ((caps & UNMOOR_CAP_EPOCH_REKEY_D28_V1) != 0 &&
        (caps & UNMOOR_CAP_BULK_FILE_D33_V1) == 0 &&
        !d36 && (caps & d28_dependencies) != d28_dependencies)
        return 0;
    if ((caps & UNMOOR_CAP_PQ_HYBRID_D45_V1) != 0 &&
        (caps & UNMOOR_CAP_EPOCH_REKEY_D28_V1) == 0)
        return 0;
    if ((caps & UNMOOR_CAP_STATUS_HEARTBEAT_V1) != 0 &&
        (caps & status_dependencies) != status_dependencies)
        return 0;
    if (negotiation_multipath_path_count(caps, &multipath_count) != 0)
        return 0;
    return 1;
}

uint32_t negotiation_multipath_capability(unsigned int path_count)
{
    switch (path_count) {
    case 2U:  return UNMOOR_CAP_MULTIPATH_2_D32_V1;
    case 4U:  return UNMOOR_CAP_MULTIPATH_4_D32_V1;
    case 8U:  return UNMOOR_CAP_MULTIPATH_8_D32_V1;
    case 16U: return UNMOOR_CAP_MULTIPATH_16_D32_V1;
    case 32U: return UNMOOR_CAP_MULTIPATH_32_D32_V1;
    default:  return 0U;
    }
}

int negotiation_multipath_path_count(uint32_t caps,
                                     uint8_t *path_count_out)
{
    uint32_t selected;

    if (!path_count_out)
        return -1;
    *path_count_out = 0U;
    selected = caps & UNMOOR_CAP_MULTIPATH_D32_MASK;
    if (selected == 0U)
        return 0;
    if ((selected & (selected - 1U)) != 0U)
        return -1;
    if (selected == UNMOOR_CAP_MULTIPATH_2_D32_V1)
        *path_count_out = 2U;
    else if (selected == UNMOOR_CAP_MULTIPATH_4_D32_V1)
        *path_count_out = 4U;
    else if (selected == UNMOOR_CAP_MULTIPATH_8_D32_V1)
        *path_count_out = 8U;
    else if (selected == UNMOOR_CAP_MULTIPATH_16_D32_V1)
        *path_count_out = 16U;
    else if (selected == UNMOOR_CAP_MULTIPATH_32_D32_V1)
        *path_count_out = 32U;
    else
        return -1;
    return 0;
}

static uint16_t load16le(const uint8_t *p)
{
    return (uint16_t)p[0] | (uint16_t)((uint16_t)p[1] << 8);
}

static uint32_t load32le(const uint8_t *p)
{
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static void store16le(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xffU);
    p[1] = (uint8_t)(v >> 8);
}

static void store32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xffU);
    p[1] = (uint8_t)((v >> 8) & 0xffU);
    p[2] = (uint8_t)((v >> 16) & 0xffU);
    p[3] = (uint8_t)(v >> 24);
}

static void encode_neg1(uint8_t out[NEGOTIATION_PLAIN_LEN],
                        const uint8_t nonce[NEGOTIATION_NONCE_LEN],
                        uint32_t supported_caps, uint32_t required_caps,
                        uint16_t status)
{
    memset(out, 0, NEGOTIATION_PLAIN_LEN);
    out[OFF_VERSION] = NEGOTIATION_HELLO_VERSION;
    out[OFF_CAPS8] = (uint8_t)(NEGOTIATION_MARKER_BIT |
                               (supported_caps & UINT32_C(0x7f)));
    memcpy(out + OFF_NONCE, nonce, NEGOTIATION_NONCE_LEN);
    store32le(out + OFF_SUPPORTED, supported_caps);
    store32le(out + OFF_REQUIRED, required_caps);
    store16le(out + OFF_STATUS, status);
    memcpy(out + OFF_MAGIC, neg1_magic, sizeof(neg1_magic));
}

void negotiation_encode_legacy(uint8_t out[NEGOTIATION_PLAIN_LEN],
                               const uint8_t nonce[NEGOTIATION_NONCE_LEN],
                               uint8_t legacy_caps)
{
    memset(out, 0, NEGOTIATION_PLAIN_LEN);
    out[OFF_VERSION] = NEGOTIATION_HELLO_VERSION;
    out[OFF_CAPS8] = (uint8_t)(legacy_caps & 0x7fU);
    memcpy(out + OFF_NONCE, nonce, NEGOTIATION_NONCE_LEN);
}

void negotiation_encode_hello(uint8_t out[NEGOTIATION_PLAIN_LEN],
                              const uint8_t nonce[NEGOTIATION_NONCE_LEN],
                              uint32_t supported_caps,
                              uint32_t required_caps)
{
    encode_neg1(out, nonce, supported_caps, required_caps, 0);
}

void negotiation_encode_ack(uint8_t out[NEGOTIATION_PLAIN_LEN],
                            const uint8_t nonce[NEGOTIATION_NONCE_LEN],
                            uint32_t selected_caps,
                            uint32_t required_caps,
                            uint16_t status)
{
    encode_neg1(out, nonce, selected_caps, required_caps, status);
}

uint16_t negotiation_decode(const uint8_t *plain, size_t plain_len,
                            int is_ack, negotiation_message_t *out)
{
    if (!plain || !out || plain_len != NEGOTIATION_PLAIN_LEN)
        return ERR_VERSION;

    memset(out, 0, sizeof(*out));
    out->kind = NEGOTIATION_INVALID;
    memcpy(out->nonce, plain + OFF_NONCE, NEGOTIATION_NONCE_LEN);

    if (plain[OFF_VERSION] != NEGOTIATION_HELLO_VERSION)
        return ERR_VERSION;

    int marker = (plain[OFF_CAPS8] & NEGOTIATION_MARKER_BIT) != 0;
    int magic = memcmp(plain + OFF_MAGIC, neg1_magic,
                       sizeof(neg1_magic)) == 0;

    if (!marker) {
        uint8_t zeros[14] = { 0 };
        if (magic || memcmp(plain + OFF_SUPPORTED, zeros, sizeof(zeros)) != 0)
            return ERR_VERSION;
        out->kind = NEGOTIATION_LEGACY;
        out->supported_caps = (plain[OFF_CAPS8] & 0x01U)
                                  ? UNMOOR_CAP_PTY_V1 : 0;
        return 0;
    }

    if (!magic)
        return ERR_VERSION;

    out->supported_caps = load32le(plain + OFF_SUPPORTED);
    out->required_caps = load32le(plain + OFF_REQUIRED);
    out->status = load16le(plain + OFF_STATUS);
    out->kind = NEGOTIATION_NEG1;

    if ((plain[OFF_CAPS8] & 0x7fU) !=
        (uint8_t)(out->supported_caps & UINT32_C(0x7f)))
        return ERR_CAPS;
    if (!is_ack && out->status != 0)
        return ERR_CAPS;
    if (is_ack && out->status != 0 &&
        out->status != ERR_VERSION && out->status != ERR_CAPS)
        return ERR_VERSION;
    if ((!is_ack || out->status == 0) &&
        (out->required_caps & ~out->supported_caps) != 0)
        return ERR_CAPS;
    return 0;
}

uint16_t negotiation_select(const negotiation_message_t *hello,
                            uint32_t local_supported,
                            uint32_t local_required,
                            uint32_t *selected_out)
{
    if (!hello || !selected_out || hello->kind != NEGOTIATION_NEG1)
        return ERR_VERSION;
    if ((local_required & ~local_supported) != 0)
        return ERR_CAPS;

    uint32_t selected = hello->supported_caps & local_supported;
    *selected_out = selected;
    if (!capability_dependencies_valid(hello->supported_caps) ||
        !capability_dependencies_valid(local_supported) ||
        (hello->required_caps & ~selected) != 0 ||
        (local_required & ~selected) != 0 ||
        !capability_dependencies_valid(selected))
        return ERR_CAPS;
    return 0;
}

uint16_t negotiation_validate_ack(const negotiation_message_t *ack,
                                  uint32_t offered_caps,
                                  uint32_t local_required,
                                  uint32_t *selected_out)
{
    if (!ack || !selected_out || ack->kind != NEGOTIATION_NEG1)
        return ERR_VERSION;
    *selected_out = ack->supported_caps;
    if (ack->status != 0)
        return ack->status;
    if (!capability_dependencies_valid(offered_caps) ||
        (ack->supported_caps & ~offered_caps) != 0 ||
        (local_required & ~ack->supported_caps) != 0 ||
        (ack->required_caps & ~ack->supported_caps) != 0 ||
        !capability_dependencies_valid(ack->supported_caps))
        return ERR_CAPS;
    return 0;
}

void negotiation_ready_encode(uint8_t out[NEGOTIATION_READY_LEN],
                              uint8_t flags, uint32_t selected_caps)
{
    memset(out, 0, NEGOTIATION_READY_LEN);
    out[0] = NEGOTIATION_READY_VERSION;
    out[1] = flags;
    store32le(out + 4, selected_caps);
}

int negotiation_ready_decode(const uint8_t *plain, size_t plain_len,
                             uint32_t expected_caps, uint8_t *flags_out)
{
    if (!plain || !flags_out || plain_len != NEGOTIATION_READY_LEN ||
        !capability_dependencies_valid(expected_caps) ||
        plain[0] != NEGOTIATION_READY_VERSION ||
        (plain[1] & (uint8_t)~NEGOTIATION_READY_NEED_ACK) != 0 ||
        plain[2] != 0 || plain[3] != 0 ||
        load32le(plain + 4) != expected_caps)
        return -1;
    *flags_out = plain[1];
    return 0;
}
