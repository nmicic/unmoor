/*
 * deaddrop_exchange.h — epoch-rekey public bootstrap transcript and DH lifecycle
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * Only the two functions explicitly named "server_offer" expose a private
 * scalar to their caller, and only so a long-lived listener can retain it
 * until the one-shot public response arrives.  No codec in this API accepts
 * or emits private, raw-DH, root, traffic, confirmation, or epoch-key bytes.
 */
#ifndef UNMOOR_DEADDROP_EXCHANGE_H
#define UNMOOR_DEADDROP_EXCHANGE_H

#include <stddef.h>
#include <stdint.h>

#include "deaddrop.h"
#include "epoch_crypto.h"
#include "negotiation.h"

#define D28_BOOTSTRAP_TERMINAL_REQUIRED_CAPS \
    (UNMOOR_CAP_PTY_V1 | UNMOOR_CAP_PTY_SYNC_V1 | \
     UNMOOR_CAP_EPOCH_REKEY_D28_V1 | \
     UNMOOR_CAP_STATUS_HEARTBEAT_V1)
#define D28_BOOTSTRAP_BULK_D33_REQUIRED_CAPS \
    (UNMOOR_CAP_EPOCH_REKEY_D28_V1 | UNMOOR_CAP_BULK_FILE_D33_V1)

/* Source-compatible spelling for the original terminal-only bootstrap. */
#define D28_BOOTSTRAP_REQUIRED_CAPS D28_BOOTSTRAP_TERMINAL_REQUIRED_CAPS

typedef enum d28_application_profile {
    D28_APPLICATION_PROFILE_TERMINAL = 0,
    D28_APPLICATION_PROFILE_BULK_D33 = 1
} d28_application_profile_t;

/* Map only the two exact public-bootstrap bundles.  Zero/negative return
 * values and any mixed terminal+bulk mask are invalid. */
uint32_t d28_application_profile_required_caps(
    d28_application_profile_t profile);
int d28_application_profile_from_required_caps(
    uint32_t required_caps, d28_application_profile_t *profile_out);

#define D28_OFFER_RECORD_HEX_LEN    (DEADDROP_OFFER_RECORD_SIZE * 2U)
#define D28_RESPONSE_RECORD_HEX_LEN (DEADDROP_RESPONSE_RECORD_SIZE * 2U)

/* No trailing newline is part of either canonical line. */
#define D28_OFFER_LINE_LEN \
    (16U + D28_OFFER_RECORD_HEX_LEN + 1U + \
     EPOCH_CRYPTO_FINGERPRINT_TEXT_LEN)
#define D28_RESPONSE_LINE_LEN \
    (19U + D28_RESPONSE_RECORD_HEX_LEN + 1U + \
     EPOCH_CRYPTO_FINGERPRINT_TEXT_LEN)
#define D28_ACCEPT_LINE_LEN \
    (17U + D28_RESPONSE_RECORD_HEX_LEN + 1U + \
     EPOCH_CRYPTO_FINGERPRINT_TEXT_LEN)

/* Generate a nonzero 128-bit public capability id. */
int d28_drop_id_generate(uint8_t id_out[DEADDROP_ID_LEN]);

/* Create the listener's public offer and caller-owned ephemeral scalar. */
int d28_server_offer_generate(
    const uint8_t id[DEADDROP_ID_LEN], uint16_t udp_port,
    deaddrop_offer_t *offer_out,
    uint8_t server_private_out[EPOCH_CRYPTO_KEY_LEN]);
int d28_server_offer_generate_for_profile(
    const uint8_t id[DEADDROP_ID_LEN], uint16_t udp_port,
    d28_application_profile_t profile,
    deaddrop_offer_t *offer_out,
    uint8_t server_private_out[EPOCH_CRYPTO_KEY_LEN]);

/* Validate a public offer, create a fresh client key inside this call, derive
 * epoch-zero material, and build the public response.  The client scalar and
 * raw DH are wiped before return on every path. */
int d28_client_accept_offer(
    const deaddrop_offer_t *offer,
    deaddrop_response_t *response_out,
    uint8_t root_out[EPOCH_CRYPTO_KEY_LEN],
    uint8_t pair_seed_out[EPOCH_CRYPTO_PAIR_ID_LEN]);
int d28_client_accept_offer_for_profile(
    const deaddrop_offer_t *offer,
    d28_application_profile_t profile,
    deaddrop_response_t *response_out,
    uint8_t root_out[EPOCH_CRYPTO_KEY_LEN],
    uint8_t pair_seed_out[EPOCH_CRYPTO_PAIR_ID_LEN]);

/* Validate the exact response against the retained offer, derive epoch-zero
 * material, and always wipe the caller-owned server scalar before return. */
int d28_server_accept_response(
    uint8_t server_private[EPOCH_CRYPTO_KEY_LEN],
    const deaddrop_offer_t *offer,
    const deaddrop_response_t *response,
    uint8_t root_out[EPOCH_CRYPTO_KEY_LEN],
    uint8_t pair_seed_out[EPOCH_CRYPTO_PAIR_ID_LEN]);

/* Strict public SSH/control-channel lines.  The encoded fingerprint is
 * redundant by design and is checked in constant time against the canonical
 * binary record.  Uppercase, truncation, extra bytes, or extra lines fail. */
int d28_offer_line_encode(
    const deaddrop_offer_t *offer,
    char out[D28_OFFER_LINE_LEN + 1U]);
int d28_offer_line_decode(
    const char *line, size_t line_len, deaddrop_offer_t *offer_out);
int d28_response_line_encode(
    const deaddrop_response_t *response,
    char out[D28_RESPONSE_LINE_LEN + 1U]);
int d28_response_line_decode(
    const char *line, size_t line_len, deaddrop_response_t *response_out);
int d28_accept_line_encode(
    const deaddrop_response_t *accepted_response,
    char out[D28_ACCEPT_LINE_LEN + 1U]);
int d28_accept_line_verify(
    const char *line, size_t line_len,
    const deaddrop_response_t *expected_response);

#endif /* UNMOOR_DEADDROP_EXCHANGE_H */
