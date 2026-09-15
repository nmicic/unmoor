/*
 * deaddrop_exchange.c — epoch-rekey public bootstrap transcript and DH lifecycle
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "crypto.h"
#include "deaddrop_exchange.h"

static const char offer_prefix[] = "UNMOOR OFFER v1 ";
static const char response_prefix[] = "UNMOOR RESPONSE v1 ";
static const char accept_prefix[] = "UNMOOR ACCEPT v1 ";
static const char lowercase_hex[] = "0123456789abcdef";

static int bytes_are_zero(const uint8_t *bytes, size_t len)
{
    uint8_t combined = 0;
    if (!bytes)
        return 1;
    for (size_t i = 0; i < len; i++)
        combined |= bytes[i];
    return combined == 0;
}

static int lowercase_hex_value(char c, uint8_t *value_out)
{
    if (c >= '0' && c <= '9') {
        *value_out = (uint8_t)(c - '0');
        return 0;
    }
    if (c >= 'a' && c <= 'f') {
        *value_out = (uint8_t)(10 + (c - 'a'));
        return 0;
    }
    return -1;
}

static void bytes_to_hex(const uint8_t *bytes, size_t len, char *out)
{
    for (size_t i = 0; i < len; i++) {
        out[2U * i] = lowercase_hex[bytes[i] >> 4];
        out[2U * i + 1U] = lowercase_hex[bytes[i] & UINT8_C(0x0f)];
    }
}

static int hex_to_bytes(const char *hex, size_t hex_len,
                        uint8_t *out, size_t out_len)
{
    if (!hex || !out || hex_len != out_len * 2U)
        return -1;
    for (size_t i = 0; i < out_len; i++) {
        uint8_t high;
        uint8_t low;
        if (lowercase_hex_value(hex[2U * i], &high) != 0 ||
            lowercase_hex_value(hex[2U * i + 1U], &low) != 0) {
            crypto_memzero(out, out_len);
            return -1;
        }
        out[i] = (uint8_t)((uint8_t)(high << 4) | low);
    }
    return 0;
}

uint32_t d28_application_profile_required_caps(
    d28_application_profile_t profile)
{
    switch (profile) {
    case D28_APPLICATION_PROFILE_TERMINAL:
        return D28_BOOTSTRAP_TERMINAL_REQUIRED_CAPS;
    case D28_APPLICATION_PROFILE_BULK_D33:
        return D28_BOOTSTRAP_BULK_D33_REQUIRED_CAPS;
    }
    return 0;
}

int d28_application_profile_from_required_caps(
    uint32_t required_caps, d28_application_profile_t *profile_out)
{
    d28_application_profile_t profile;

    if (required_caps == D28_BOOTSTRAP_TERMINAL_REQUIRED_CAPS)
        profile = D28_APPLICATION_PROFILE_TERMINAL;
    else if (required_caps == D28_BOOTSTRAP_BULK_D33_REQUIRED_CAPS)
        profile = D28_APPLICATION_PROFILE_BULK_D33;
    else
        return -1;
    if (profile_out)
        *profile_out = profile;
    return 0;
}

static int offer_validate(const deaddrop_offer_t *offer)
{
    uint8_t expected[DEADDROP_FINGERPRINT_LEN];
    int rc = -1;

    if (!offer || !deaddrop_id_valid(offer->id) || offer->port == 0 ||
        d28_application_profile_from_required_caps(
            offer->required_caps, NULL) != 0 ||
        !epoch_crypto_public_key_is_canonical(offer->server_public_key))
        return -1;
    if (epoch_crypto_offer_fingerprint(offer->id, offer->port,
                                       offer->required_caps,
                                       offer->server_public_key,
                                       expected) == 0 &&
        crypto_verify32_exact(expected, offer->offer_fingerprint) == 0)
        rc = 0;
    crypto_memzero(expected, sizeof(expected));
    return rc;
}

static int response_validate(const deaddrop_response_t *response)
{
    uint8_t expected_offer[DEADDROP_FINGERPRINT_LEN];
    uint8_t expected_full[DEADDROP_FINGERPRINT_LEN];
    int rc = -1;

    if (!response || !deaddrop_id_valid(response->id) ||
        response->port == 0 ||
        d28_application_profile_from_required_caps(
            response->required_caps, NULL) != 0 ||
        !epoch_crypto_public_key_is_canonical(response->server_public_key) ||
        !epoch_crypto_public_key_is_canonical(response->client_public_key) ||
        memcmp(response->server_public_key, response->client_public_key,
               DEADDROP_PUBLIC_KEY_LEN) == 0)
        goto cleanup;
    if (epoch_crypto_offer_fingerprint(response->id, response->port,
                                       response->required_caps,
                                       response->server_public_key,
                                       expected_offer) != 0 ||
        epoch_crypto_transcript_fingerprint(
            response->id, response->port, response->required_caps,
            response->client_public_key, response->server_public_key,
            expected_full) != 0)
        goto cleanup;
    if (crypto_verify32_exact(expected_offer,
                              response->offer_fingerprint) == 0 &&
        crypto_verify32_exact(expected_full,
                              response->transcript_fingerprint) == 0)
        rc = 0;

cleanup:
    crypto_memzero(expected_offer, sizeof(expected_offer));
    crypto_memzero(expected_full, sizeof(expected_full));
    return rc;
}

static int response_equal(const deaddrop_response_t *left,
                          const deaddrop_response_t *right)
{
    return left && right &&
           memcmp(left->id, right->id, DEADDROP_ID_LEN) == 0 &&
           left->port == right->port &&
           left->required_caps == right->required_caps &&
           memcmp(left->server_public_key, right->server_public_key,
                  DEADDROP_PUBLIC_KEY_LEN) == 0 &&
           memcmp(left->client_public_key, right->client_public_key,
                  DEADDROP_PUBLIC_KEY_LEN) == 0 &&
           crypto_verify32_exact(left->offer_fingerprint,
                                 right->offer_fingerprint) == 0 &&
           crypto_verify32_exact(left->transcript_fingerprint,
                                 right->transcript_fingerprint) == 0;
}

int d28_drop_id_generate(uint8_t id_out[DEADDROP_ID_LEN])
{
    if (!id_out)
        return -1;
    for (unsigned int attempt = 0; attempt < 8U; attempt++) {
        if (crypto_random_bytes(id_out, DEADDROP_ID_LEN) != 0)
            break;
        if (!bytes_are_zero(id_out, DEADDROP_ID_LEN))
            return 0;
    }
    crypto_memzero(id_out, DEADDROP_ID_LEN);
    return -1;
}

int d28_server_offer_generate(const uint8_t id[DEADDROP_ID_LEN],
                              uint16_t udp_port,
                              deaddrop_offer_t *offer_out,
                              uint8_t server_private_out[32])
{
    return d28_server_offer_generate_for_profile(
        id, udp_port, D28_APPLICATION_PROFILE_TERMINAL,
        offer_out, server_private_out);
}

int d28_server_offer_generate_for_profile(
                              const uint8_t id[DEADDROP_ID_LEN],
                              uint16_t udp_port,
                              d28_application_profile_t profile,
                              deaddrop_offer_t *offer_out,
                              uint8_t server_private_out[32])
{
    deaddrop_offer_t offer;
    uint32_t required_caps =
        d28_application_profile_required_caps(profile);

    if (offer_out)
        memset(offer_out, 0, sizeof(*offer_out));
    if (server_private_out)
        crypto_memzero(server_private_out, 32);
    if (!id || !offer_out || !server_private_out || required_caps == 0 ||
        !deaddrop_id_valid(id) || udp_port == 0)
        return -1;
    memset(&offer, 0, sizeof(offer));
    memcpy(offer.id, id, DEADDROP_ID_LEN);
    offer.port = udp_port;
    offer.required_caps = required_caps;
    if (epoch_crypto_keypair_generate(server_private_out,
                                      offer.server_public_key) != 0 ||
        epoch_crypto_offer_fingerprint(
            offer.id, offer.port, offer.required_caps,
            offer.server_public_key, offer.offer_fingerprint) != 0) {
        crypto_memzero(server_private_out, 32);
        memset(offer_out, 0, sizeof(*offer_out));
        crypto_memzero(&offer, sizeof(offer));
        return -1;
    }
    *offer_out = offer;
    crypto_memzero(&offer, sizeof(offer));
    return 0;
}

int d28_client_accept_offer(const deaddrop_offer_t *offer,
                            deaddrop_response_t *response_out,
                            uint8_t root_out[32], uint8_t pair_seed_out[4])
{
    return d28_client_accept_offer_for_profile(
        offer, D28_APPLICATION_PROFILE_TERMINAL, response_out,
        root_out, pair_seed_out);
}

int d28_client_accept_offer_for_profile(
                            const deaddrop_offer_t *offer,
                            d28_application_profile_t profile,
                            deaddrop_response_t *response_out,
                            uint8_t root_out[32], uint8_t pair_seed_out[4])
{
    uint8_t client_private[32];
    uint8_t client_public[32];
    deaddrop_response_t response;
    int rc = -1;

    if (response_out)
        memset(response_out, 0, sizeof(*response_out));
    if (root_out)
        crypto_memzero(root_out, 32);
    if (pair_seed_out)
        crypto_memzero(pair_seed_out, 4);
    if (!response_out || !root_out || !pair_seed_out)
        return -1;
    crypto_memzero(client_private, sizeof(client_private));
    crypto_memzero(client_public, sizeof(client_public));
    memset(&response, 0, sizeof(response));
    (void)crypto_mlock(client_private, sizeof(client_private));
    crypto_mark_dontdump(client_private, sizeof(client_private));

    if (d28_application_profile_required_caps(profile) == 0 ||
        offer_validate(offer) != 0 ||
        offer->required_caps !=
            d28_application_profile_required_caps(profile) ||
        epoch_crypto_keypair_generate(client_private, client_public) != 0)
        goto cleanup;
    memcpy(response.id, offer->id, sizeof(response.id));
    response.port = offer->port;
    response.required_caps = offer->required_caps;
    memcpy(response.server_public_key, offer->server_public_key,
           sizeof(response.server_public_key));
    memcpy(response.client_public_key, client_public,
           sizeof(response.client_public_key));
    memcpy(response.offer_fingerprint, offer->offer_fingerprint,
           sizeof(response.offer_fingerprint));
    if (epoch_crypto_transcript_fingerprint(
            response.id, response.port, response.required_caps,
            response.client_public_key, response.server_public_key,
            response.transcript_fingerprint) != 0 ||
        epoch_crypto_bootstrap_derive(
            client_private, EPOCH_CRYPTO_ROLE_CLIENT,
            response.id, response.port, response.required_caps,
            response.client_public_key, response.server_public_key,
            root_out, pair_seed_out) != 0)
        goto cleanup;
    *response_out = response;
    rc = 0;

cleanup:
    crypto_memzero(client_private, sizeof(client_private));
    (void)crypto_munlock(client_private, sizeof(client_private));
    crypto_memzero(client_public, sizeof(client_public));
    crypto_memzero(&response, sizeof(response));
    if (rc != 0) {
        memset(response_out, 0, sizeof(*response_out));
        crypto_memzero(root_out, 32);
        crypto_memzero(pair_seed_out, 4);
    }
    return rc;
}

int d28_server_accept_response(uint8_t server_private[32],
                               const deaddrop_offer_t *offer,
                               const deaddrop_response_t *response,
                               uint8_t root_out[32],
                               uint8_t pair_seed_out[4])
{
    int rc = -1;

    if (root_out)
        crypto_memzero(root_out, 32);
    if (pair_seed_out)
        crypto_memzero(pair_seed_out, 4);
    if (!root_out || !pair_seed_out)
        goto cleanup;
    if (!server_private || offer_validate(offer) != 0 ||
        response_validate(response) != 0 ||
        memcmp(response->id, offer->id, DEADDROP_ID_LEN) != 0 ||
        response->port != offer->port ||
        response->required_caps != offer->required_caps ||
        memcmp(response->server_public_key, offer->server_public_key,
               DEADDROP_PUBLIC_KEY_LEN) != 0 ||
        crypto_verify32_exact(response->offer_fingerprint,
                              offer->offer_fingerprint) != 0)
        goto cleanup;
    if (epoch_crypto_bootstrap_derive(
            server_private, EPOCH_CRYPTO_ROLE_SERVER,
            response->id, response->port, response->required_caps,
            response->client_public_key, response->server_public_key,
            root_out, pair_seed_out) != 0)
        goto cleanup;
    rc = 0;

cleanup:
    if (server_private)
        crypto_memzero(server_private, 32);
    if (rc != 0 && root_out)
        crypto_memzero(root_out, 32);
    if (rc != 0 && pair_seed_out)
        crypto_memzero(pair_seed_out, 4);
    return rc;
}

int d28_offer_line_encode(const deaddrop_offer_t *offer,
                          char out[D28_OFFER_LINE_LEN + 1U])
{
    uint8_t wire[DEADDROP_OFFER_RECORD_SIZE];
    char fingerprint[EPOCH_CRYPTO_FINGERPRINT_TEXT_BUFSZ];
    size_t off = 0;
    int rc = -1;

    if (!out)
        return -1;
    memset(out, 0, D28_OFFER_LINE_LEN + 1U);
    if (offer_validate(offer) != 0 ||
        deaddrop_offer_encode(offer, wire) != DEADDROP_OK ||
        epoch_crypto_fingerprint_encode(offer->offer_fingerprint,
                                        fingerprint) != 0)
        goto cleanup;
    memcpy(out + off, offer_prefix, sizeof(offer_prefix) - 1U);
    off += sizeof(offer_prefix) - 1U;
    bytes_to_hex(wire, sizeof(wire), out + off);
    off += D28_OFFER_RECORD_HEX_LEN;
    out[off++] = ' ';
    memcpy(out + off, fingerprint, EPOCH_CRYPTO_FINGERPRINT_TEXT_LEN);
    off += EPOCH_CRYPTO_FINGERPRINT_TEXT_LEN;
    out[off] = '\0';
    rc = off == D28_OFFER_LINE_LEN ? 0 : -1;

cleanup:
    crypto_memzero(wire, sizeof(wire));
    crypto_memzero(fingerprint, sizeof(fingerprint));
    if (rc != 0)
        memset(out, 0, D28_OFFER_LINE_LEN + 1U);
    return rc;
}

int d28_offer_line_decode(const char *line, size_t line_len,
                          deaddrop_offer_t *offer_out)
{
    uint8_t wire[DEADDROP_OFFER_RECORD_SIZE];
    deaddrop_offer_t offer;
    const size_t prefix_len = sizeof(offer_prefix) - 1U;
    const size_t fp_off = prefix_len + D28_OFFER_RECORD_HEX_LEN + 1U;
    int rc = -1;

    if (!offer_out)
        return -1;
    memset(offer_out, 0, sizeof(*offer_out));
    memset(&offer, 0, sizeof(offer));
    crypto_memzero(wire, sizeof(wire));
    if (!line || line_len != D28_OFFER_LINE_LEN ||
        memcmp(line, offer_prefix, prefix_len) != 0 ||
        line[prefix_len + D28_OFFER_RECORD_HEX_LEN] != ' ' ||
        memchr(line, '\0', line_len) != NULL ||
        hex_to_bytes(line + prefix_len, D28_OFFER_RECORD_HEX_LEN,
                     wire, sizeof(wire)) != 0 ||
        deaddrop_offer_decode(wire, &offer) != DEADDROP_OK ||
        offer_validate(&offer) != 0 ||
        epoch_crypto_fingerprint_verify(
            line + fp_off, EPOCH_CRYPTO_FINGERPRINT_TEXT_LEN,
            offer.offer_fingerprint) != 0)
        goto cleanup;
    *offer_out = offer;
    rc = 0;

cleanup:
    crypto_memzero(wire, sizeof(wire));
    crypto_memzero(&offer, sizeof(offer));
    return rc;
}

int d28_response_line_encode(const deaddrop_response_t *response,
                             char out[D28_RESPONSE_LINE_LEN + 1U])
{
    uint8_t wire[DEADDROP_RESPONSE_RECORD_SIZE];
    char fingerprint[EPOCH_CRYPTO_FINGERPRINT_TEXT_BUFSZ];
    size_t off = 0;
    int rc = -1;

    if (!out)
        return -1;
    memset(out, 0, D28_RESPONSE_LINE_LEN + 1U);
    if (response_validate(response) != 0 ||
        deaddrop_response_encode(response, wire) != DEADDROP_OK ||
        epoch_crypto_fingerprint_encode(response->transcript_fingerprint,
                                        fingerprint) != 0)
        goto cleanup;
    memcpy(out + off, response_prefix, sizeof(response_prefix) - 1U);
    off += sizeof(response_prefix) - 1U;
    bytes_to_hex(wire, sizeof(wire), out + off);
    off += D28_RESPONSE_RECORD_HEX_LEN;
    out[off++] = ' ';
    memcpy(out + off, fingerprint, EPOCH_CRYPTO_FINGERPRINT_TEXT_LEN);
    off += EPOCH_CRYPTO_FINGERPRINT_TEXT_LEN;
    out[off] = '\0';
    rc = off == D28_RESPONSE_LINE_LEN ? 0 : -1;

cleanup:
    crypto_memzero(wire, sizeof(wire));
    crypto_memzero(fingerprint, sizeof(fingerprint));
    if (rc != 0)
        memset(out, 0, D28_RESPONSE_LINE_LEN + 1U);
    return rc;
}

int d28_response_line_decode(const char *line, size_t line_len,
                             deaddrop_response_t *response_out)
{
    uint8_t wire[DEADDROP_RESPONSE_RECORD_SIZE];
    deaddrop_response_t response;
    const size_t prefix_len = sizeof(response_prefix) - 1U;
    const size_t fp_off = prefix_len + D28_RESPONSE_RECORD_HEX_LEN + 1U;
    int rc = -1;

    if (!response_out)
        return -1;
    memset(response_out, 0, sizeof(*response_out));
    memset(&response, 0, sizeof(response));
    crypto_memzero(wire, sizeof(wire));
    if (!line || line_len != D28_RESPONSE_LINE_LEN ||
        memcmp(line, response_prefix, prefix_len) != 0 ||
        line[prefix_len + D28_RESPONSE_RECORD_HEX_LEN] != ' ' ||
        memchr(line, '\0', line_len) != NULL ||
        hex_to_bytes(line + prefix_len, D28_RESPONSE_RECORD_HEX_LEN,
                     wire, sizeof(wire)) != 0 ||
        deaddrop_response_decode(wire, &response) != DEADDROP_OK ||
        response_validate(&response) != 0 ||
        epoch_crypto_fingerprint_verify(
            line + fp_off, EPOCH_CRYPTO_FINGERPRINT_TEXT_LEN,
            response.transcript_fingerprint) != 0)
        goto cleanup;
    *response_out = response;
    rc = 0;

cleanup:
    crypto_memzero(wire, sizeof(wire));
    crypto_memzero(&response, sizeof(response));
    return rc;
}

int d28_accept_line_encode(const deaddrop_response_t *accepted_response,
                           char out[D28_ACCEPT_LINE_LEN + 1U])
{
    uint8_t wire[DEADDROP_RESPONSE_RECORD_SIZE];
    char fingerprint[EPOCH_CRYPTO_FINGERPRINT_TEXT_BUFSZ];
    size_t off = 0;
    int rc = -1;

    if (!out)
        return -1;
    memset(out, 0, D28_ACCEPT_LINE_LEN + 1U);
    if (response_validate(accepted_response) != 0 ||
        deaddrop_response_encode(accepted_response, wire) != DEADDROP_OK ||
        epoch_crypto_fingerprint_encode(
            accepted_response->transcript_fingerprint, fingerprint) != 0)
        goto cleanup;
    memcpy(out + off, accept_prefix, sizeof(accept_prefix) - 1U);
    off += sizeof(accept_prefix) - 1U;
    bytes_to_hex(wire, sizeof(wire), out + off);
    off += D28_RESPONSE_RECORD_HEX_LEN;
    out[off++] = ' ';
    memcpy(out + off, fingerprint, EPOCH_CRYPTO_FINGERPRINT_TEXT_LEN);
    off += EPOCH_CRYPTO_FINGERPRINT_TEXT_LEN;
    out[off] = '\0';
    rc = off == D28_ACCEPT_LINE_LEN ? 0 : -1;

cleanup:
    crypto_memzero(wire, sizeof(wire));
    crypto_memzero(fingerprint, sizeof(fingerprint));
    if (rc != 0)
        memset(out, 0, D28_ACCEPT_LINE_LEN + 1U);
    return rc;
}

int d28_accept_line_verify(const char *line, size_t line_len,
                           const deaddrop_response_t *expected_response)
{
    uint8_t wire[DEADDROP_RESPONSE_RECORD_SIZE];
    deaddrop_response_t decoded_response;
    const size_t prefix_len = sizeof(accept_prefix) - 1U;
    const size_t fp_off = prefix_len + D28_RESPONSE_RECORD_HEX_LEN + 1U;
    int rc = -1;

    crypto_memzero(wire, sizeof(wire));
    memset(&decoded_response, 0, sizeof(decoded_response));
    if (!line || line_len != D28_ACCEPT_LINE_LEN ||
        response_validate(expected_response) != 0 ||
        memcmp(line, accept_prefix, prefix_len) != 0 ||
        line[prefix_len + D28_RESPONSE_RECORD_HEX_LEN] != ' ' ||
        memchr(line, '\0', line_len) != NULL ||
        hex_to_bytes(line + prefix_len, D28_RESPONSE_RECORD_HEX_LEN,
                     wire, sizeof(wire)) != 0 ||
        deaddrop_response_decode(wire, &decoded_response) != DEADDROP_OK ||
        response_validate(&decoded_response) != 0 ||
        epoch_crypto_fingerprint_verify(
            line + fp_off, EPOCH_CRYPTO_FINGERPRINT_TEXT_LEN,
            decoded_response.transcript_fingerprint) != 0)
        goto cleanup;
    if (response_equal(&decoded_response, expected_response))
        rc = 0;

cleanup:
    crypto_memzero(wire, sizeof(wire));
    crypto_memzero(&decoded_response, sizeof(decoded_response));
    return rc;
}
