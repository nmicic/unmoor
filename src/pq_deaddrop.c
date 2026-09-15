/*
 * pq_deaddrop.c — pq-hybrid public deaddrop v2 records and strict text carriage
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */

#include "pq_deaddrop.h"

#include <errno.h>
#include <string.h>

#include "crypto.h"
#include "monocypher.h"
#include "negotiation.h"

#define PQ_DD_HEADER_SIZE 36U
#define PQ_DD_OFFER_PREFIX_SIZE 1636U
#define PQ_DD_RESPONSE_PREFIX_SIZE 1668U

static const uint8_t pq_dd_magic[8] = {
    'U', 'N', 'M', 'D', 'D', 'P', '2', '8'
};
static const uint8_t offer_domain[] =
    "unmoor-pq-offer-fingerprint-v1";
static const uint8_t transcript_domain[] =
    "unmoor-pq-transcript-fingerprint-v1";
static const char lowercase_hex[] = "0123456789abcdef";

static void store16be(uint8_t *out, uint16_t value)
{
    out[0] = (uint8_t)(value >> 8);
    out[1] = (uint8_t)value;
}

static void store32be(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

static uint16_t load16be(const uint8_t *in)
{
    return (uint16_t)(((uint16_t)in[0] << 8) | in[1]);
}

static uint32_t load32be(const uint8_t *in)
{
    return ((uint32_t)in[0] << 24) |
           ((uint32_t)in[1] << 16) |
           ((uint32_t)in[2] << 8) |
           (uint32_t)in[3];
}

static int required_caps_valid(uint32_t caps)
{
    return (caps & UNMOOR_CAP_EPOCH_REKEY_D28_V1) != 0 &&
           (caps & UNMOOR_CAP_PQ_HYBRID_D45_V1) != 0;
}

static int encode_header(uint8_t *out, size_t out_len, uint8_t type,
                         const uint8_t id[16], uint16_t port,
                         uint32_t required_caps)
{
    if (!out || out_len < PQ_DD_HEADER_SIZE || !deaddrop_id_valid(id) ||
        port == 0 || !required_caps_valid(required_caps) ||
        (type != 1 && type != 2))
        return -1;
    memset(out, 0, out_len);
    memcpy(out, pq_dd_magic, sizeof(pq_dd_magic));
    out[8] = PQ_DEADDROP_RECORD_VERSION;
    out[9] = type;
    memcpy(out + 12, id, 16);
    store16be(out + 28, port);
    out[30] = DEADDROP_TRANSPORT_UDP;
    store32be(out + 32, required_caps);
    return 0;
}

static int decode_header(const uint8_t *wire, size_t wire_len,
                         uint8_t expected_type, uint8_t id[16],
                         uint16_t *port, uint32_t *required_caps)
{
    if (!wire || wire_len < PQ_DD_HEADER_SIZE || !id || !port ||
        !required_caps || memcmp(wire, pq_dd_magic, sizeof(pq_dd_magic)) != 0 ||
        wire[8] != PQ_DEADDROP_RECORD_VERSION || wire[9] != expected_type ||
        wire[10] != 0 || wire[11] != 0 ||
        wire[30] != DEADDROP_TRANSPORT_UDP || wire[31] != 0)
        return -1;
    memcpy(id, wire + 12, 16);
    *port = load16be(wire + 28);
    *required_caps = load32be(wire + 32);
    if (!deaddrop_id_valid(id) || *port == 0 ||
        !required_caps_valid(*required_caps)) {
        memset(id, 0, 16);
        *port = 0;
        *required_caps = 0;
        return -1;
    }
    return 0;
}

int pq_deaddrop_offer_encode(const pq_deaddrop_offer_t *offer,
                             uint8_t out[PQ_DEADDROP_OFFER_SIZE])
{
    if (!offer || !out ||
        encode_header(out, PQ_DEADDROP_OFFER_SIZE, 1, offer->id,
                      offer->port, offer->required_caps) != 0)
        return -1;
    memcpy(out + 36, offer->server_x25519, 32);
    memcpy(out + 68, offer->mlkem_public, PQ_DEADDROP_MLKEM_LEN);
    memcpy(out + 1636, offer->offer_fingerprint, 32);
    return 0;
}

int pq_deaddrop_offer_decode(const uint8_t *wire, size_t wire_len,
                             pq_deaddrop_offer_t *out)
{
    pq_deaddrop_offer_t decoded;
    if (!wire || !out || wire_len != PQ_DEADDROP_OFFER_SIZE)
        return -1;
    memset(&decoded, 0, sizeof(decoded));
    if (decode_header(wire, wire_len, 1, decoded.id, &decoded.port,
                      &decoded.required_caps) != 0)
        goto fail;
    memcpy(decoded.server_x25519, wire + 36, 32);
    memcpy(decoded.mlkem_public, wire + 68, PQ_DEADDROP_MLKEM_LEN);
    memcpy(decoded.offer_fingerprint, wire + 1636, 32);
    *out = decoded;
    return 0;
fail:
    crypto_memzero(&decoded, sizeof(decoded));
    memset(out, 0, sizeof(*out));
    return -1;
}

int pq_deaddrop_response_encode(const pq_deaddrop_response_t *response,
                                uint8_t out[PQ_DEADDROP_RESPONSE_SIZE])
{
    if (!response || !out ||
        encode_header(out, PQ_DEADDROP_RESPONSE_SIZE, 2, response->id,
                      response->port, response->required_caps) != 0)
        return -1;
    memcpy(out + 36, response->server_x25519, 32);
    memcpy(out + 68, response->client_x25519, 32);
    memcpy(out + 100, response->mlkem_ciphertext, PQ_DEADDROP_MLKEM_LEN);
    memcpy(out + 1668, response->offer_fingerprint, 32);
    memcpy(out + 1700, response->transcript_fingerprint, 32);
    return 0;
}

int pq_deaddrop_response_decode(const uint8_t *wire, size_t wire_len,
                                pq_deaddrop_response_t *out)
{
    pq_deaddrop_response_t decoded;
    if (!wire || !out || wire_len != PQ_DEADDROP_RESPONSE_SIZE)
        return -1;
    memset(&decoded, 0, sizeof(decoded));
    if (decode_header(wire, wire_len, 2, decoded.id, &decoded.port,
                      &decoded.required_caps) != 0)
        goto fail;
    memcpy(decoded.server_x25519, wire + 36, 32);
    memcpy(decoded.client_x25519, wire + 68, 32);
    memcpy(decoded.mlkem_ciphertext, wire + 100, PQ_DEADDROP_MLKEM_LEN);
    memcpy(decoded.offer_fingerprint, wire + 1668, 32);
    memcpy(decoded.transcript_fingerprint, wire + 1700, 32);
    *out = decoded;
    return 0;
fail:
    crypto_memzero(&decoded, sizeof(decoded));
    memset(out, 0, sizeof(*out));
    return -1;
}

int pq_deaddrop_offer_fingerprint(const pq_deaddrop_offer_t *offer,
                                  uint8_t out[32])
{
    crypto_blake2b_ctx ctx;
    uint8_t wire[PQ_DEADDROP_OFFER_SIZE];
    if (!out)
        return -1;
    memset(out, 0, 32);
    if (!offer || pq_deaddrop_offer_encode(offer, wire) != 0)
        return -1;
    crypto_blake2b_init(&ctx, 32);
    crypto_blake2b_update(&ctx, offer_domain, sizeof(offer_domain) - 1U);
    crypto_blake2b_update(&ctx, wire, PQ_DD_OFFER_PREFIX_SIZE);
    crypto_blake2b_final(&ctx, out);
    crypto_memzero(&ctx, sizeof(ctx));
    crypto_memzero(wire, sizeof(wire));
    return 0;
}

int pq_deaddrop_offer_seal(pq_deaddrop_offer_t *offer)
{
    uint8_t fingerprint[32];
    if (!offer || pq_deaddrop_offer_fingerprint(offer, fingerprint) != 0)
        return -1;
    memcpy(offer->offer_fingerprint, fingerprint, 32);
    crypto_memzero(fingerprint, sizeof(fingerprint));
    return 0;
}

int pq_deaddrop_offer_verify(const pq_deaddrop_offer_t *offer)
{
    uint8_t fingerprint[32];
    int result = -1;
    if (offer && pq_deaddrop_offer_fingerprint(offer, fingerprint) == 0 &&
        crypto_verify32_exact(fingerprint, offer->offer_fingerprint) == 0)
        result = 0;
    crypto_memzero(fingerprint, sizeof(fingerprint));
    return result;
}

static int response_matches_offer(const pq_deaddrop_offer_t *offer,
                                  const pq_deaddrop_response_t *response)
{
    return offer && response &&
           memcmp(offer->id, response->id, 16) == 0 &&
           offer->port == response->port &&
           offer->required_caps == response->required_caps &&
           memcmp(offer->server_x25519, response->server_x25519, 32) == 0 &&
           crypto_verify32_exact(offer->offer_fingerprint,
                                 response->offer_fingerprint) == 0;
}

static int response_fingerprint(const pq_deaddrop_offer_t *offer,
                                const pq_deaddrop_response_t *response,
                                uint8_t out[32])
{
    crypto_blake2b_ctx ctx;
    uint8_t offer_wire[PQ_DEADDROP_OFFER_SIZE];
    uint8_t response_wire[PQ_DEADDROP_RESPONSE_SIZE];
    if (!out)
        return -1;
    memset(out, 0, 32);
    if (pq_deaddrop_offer_verify(offer) != 0 ||
        !response_matches_offer(offer, response) ||
        pq_deaddrop_offer_encode(offer, offer_wire) != 0 ||
        pq_deaddrop_response_encode(response, response_wire) != 0)
        return -1;
    crypto_blake2b_init(&ctx, 32);
    crypto_blake2b_update(&ctx, transcript_domain,
                          sizeof(transcript_domain) - 1U);
    crypto_blake2b_update(&ctx, offer_wire, sizeof(offer_wire));
    crypto_blake2b_update(&ctx, response_wire, PQ_DD_RESPONSE_PREFIX_SIZE);
    crypto_blake2b_final(&ctx, out);
    crypto_memzero(&ctx, sizeof(ctx));
    crypto_memzero(offer_wire, sizeof(offer_wire));
    crypto_memzero(response_wire, sizeof(response_wire));
    return 0;
}

int pq_deaddrop_response_seal(const pq_deaddrop_offer_t *offer,
                              pq_deaddrop_response_t *response)
{
    uint8_t fingerprint[32];
    if (!offer || !response || pq_deaddrop_offer_verify(offer) != 0)
        return -1;
    memcpy(response->id, offer->id, 16);
    response->port = offer->port;
    response->required_caps = offer->required_caps;
    memcpy(response->server_x25519, offer->server_x25519, 32);
    memcpy(response->offer_fingerprint, offer->offer_fingerprint, 32);
    memset(response->transcript_fingerprint, 0, 32);
    if (response_fingerprint(offer, response, fingerprint) != 0)
        return -1;
    memcpy(response->transcript_fingerprint, fingerprint, 32);
    crypto_memzero(fingerprint, sizeof(fingerprint));
    return 0;
}

int pq_deaddrop_response_verify(const pq_deaddrop_offer_t *offer,
                                const pq_deaddrop_response_t *response)
{
    uint8_t fingerprint[32];
    int result = -1;
    if (response_fingerprint(offer, response, fingerprint) == 0 &&
        crypto_verify32_exact(fingerprint,
                              response->transcript_fingerprint) == 0)
        result = 0;
    crypto_memzero(fingerprint, sizeof(fingerprint));
    return result;
}

static void bytes_to_hex(const uint8_t *bytes, size_t length, char *out)
{
    for (size_t i = 0; i < length; i++) {
        out[2U * i] = lowercase_hex[bytes[i] >> 4];
        out[2U * i + 1U] = lowercase_hex[bytes[i] & UINT8_C(0x0f)];
    }
}

static int hex_value(char c, uint8_t *out)
{
    if (c >= '0' && c <= '9')
        *out = (uint8_t)(c - '0');
    else if (c >= 'a' && c <= 'f')
        *out = (uint8_t)(c - 'a' + 10);
    else
        return -1;
    return 0;
}

static int hex_to_bytes(const char *text, size_t text_len,
                        uint8_t *out, size_t out_len)
{
    if (!text || !out || text_len != 2U * out_len)
        return -1;
    for (size_t i = 0; i < out_len; i++) {
        uint8_t high;
        uint8_t low;
        if (hex_value(text[2U * i], &high) != 0 ||
            hex_value(text[2U * i + 1U], &low) != 0) {
            crypto_memzero(out, out_len);
            return -1;
        }
        out[i] = (uint8_t)((high << 4) | low);
    }
    return 0;
}

static void fingerprint_text(const uint8_t fingerprint[32], char out[71])
{
    memcpy(out, "b2b256:", 7);
    bytes_to_hex(fingerprint, 32, out + 7);
}

static int fingerprint_text_verify(const char text[71],
                                   const uint8_t expected[32])
{
    uint8_t decoded[32];
    int result = -1;
    if (memcmp(text, "b2b256:", 7) == 0 &&
        hex_to_bytes(text + 7, 64, decoded, sizeof(decoded)) == 0 &&
        crypto_verify32_exact(decoded, expected) == 0)
        result = 0;
    crypto_memzero(decoded, sizeof(decoded));
    return result;
}

static int line_encode(const char *prefix, const uint8_t *wire,
                       size_t wire_len, const uint8_t fingerprint[32],
                       char *out, size_t expected_len)
{
    size_t prefix_len = strlen(prefix);
    size_t offset = 0;
    if (!wire || !fingerprint || !out ||
        prefix_len + 2U * wire_len + 1U + 71U != expected_len)
        return -1;
    memcpy(out + offset, prefix, prefix_len);
    offset += prefix_len;
    bytes_to_hex(wire, wire_len, out + offset);
    offset += 2U * wire_len;
    out[offset++] = ' ';
    fingerprint_text(fingerprint, out + offset);
    offset += 71;
    out[offset] = '\0';
    return offset == expected_len ? 0 : -1;
}

static int line_decode(const char *line, size_t line_len, const char *prefix,
                       size_t record_len, size_t expected_len, uint8_t *wire,
                       char fingerprint[71])
{
    size_t prefix_len = strlen(prefix);
    size_t separator = prefix_len + 2U * record_len;
    if (!line || !wire || !fingerprint || line_len != expected_len ||
        memcmp(line, prefix, prefix_len) != 0 || line[separator] != ' ' ||
        memchr(line, '\0', line_len) != NULL ||
        hex_to_bytes(line + prefix_len, 2U * record_len,
                     wire, record_len) != 0)
        return -1;
    memcpy(fingerprint, line + separator + 1U, 71);
    return 0;
}

int pq_deaddrop_offer_line_encode(const pq_deaddrop_offer_t *offer,
                                  char out[PQ_DEADDROP_OFFER_LINE_LEN + 1U])
{
    uint8_t wire[PQ_DEADDROP_OFFER_SIZE];
    int result;
    if (!out)
        return -1;
    memset(out, 0, PQ_DEADDROP_OFFER_LINE_LEN + 1U);
    if (pq_deaddrop_offer_verify(offer) != 0 ||
        pq_deaddrop_offer_encode(offer, wire) != 0)
        return -1;
    result = line_encode(PQ_DEADDROP_OFFER_PREFIX, wire, sizeof(wire),
                         offer->offer_fingerprint, out,
                         PQ_DEADDROP_OFFER_LINE_LEN);
    crypto_memzero(wire, sizeof(wire));
    return result;
}

int pq_deaddrop_offer_line_decode(const char *line, size_t line_len,
                                  pq_deaddrop_offer_t *out)
{
    uint8_t wire[PQ_DEADDROP_OFFER_SIZE];
    char fingerprint[71];
    int result = -1;
    if (!out)
        return -1;
    memset(out, 0, sizeof(*out));
    if (line_decode(line, line_len, PQ_DEADDROP_OFFER_PREFIX,
                    sizeof(wire), PQ_DEADDROP_OFFER_LINE_LEN,
                    wire, fingerprint) == 0 &&
        pq_deaddrop_offer_decode(wire, sizeof(wire), out) == 0 &&
        pq_deaddrop_offer_verify(out) == 0 &&
        fingerprint_text_verify(fingerprint, out->offer_fingerprint) == 0)
        result = 0;
    if (result != 0)
        crypto_memzero(out, sizeof(*out));
    crypto_memzero(wire, sizeof(wire));
    crypto_memzero(fingerprint, sizeof(fingerprint));
    return result;
}

static int response_line_encode_with_prefix(
    const char *prefix, size_t expected_len, const pq_deaddrop_offer_t *offer,
    const pq_deaddrop_response_t *response, char *out)
{
    uint8_t wire[PQ_DEADDROP_RESPONSE_SIZE];
    int result;
    if (!out)
        return -1;
    memset(out, 0, expected_len + 1U);
    if (pq_deaddrop_response_verify(offer, response) != 0 ||
        pq_deaddrop_response_encode(response, wire) != 0)
        return -1;
    result = line_encode(prefix, wire, sizeof(wire),
                         response->transcript_fingerprint, out, expected_len);
    crypto_memzero(wire, sizeof(wire));
    return result;
}

int pq_deaddrop_response_line_encode(
    const pq_deaddrop_offer_t *offer,
    const pq_deaddrop_response_t *response,
    char out[PQ_DEADDROP_RESPONSE_LINE_LEN + 1U])
{
    return response_line_encode_with_prefix(
        PQ_DEADDROP_RESPONSE_PREFIX, PQ_DEADDROP_RESPONSE_LINE_LEN,
        offer, response, out);
}

static int response_line_decode_with_prefix(
    const char *line, size_t line_len, const char *prefix,
    size_t expected_len, const pq_deaddrop_offer_t *offer,
    pq_deaddrop_response_t *out)
{
    uint8_t wire[PQ_DEADDROP_RESPONSE_SIZE];
    char fingerprint[71];
    int result = -1;
    if (!out)
        return -1;
    memset(out, 0, sizeof(*out));
    if (line_decode(line, line_len, prefix, sizeof(wire), expected_len,
                    wire, fingerprint) == 0 &&
        pq_deaddrop_response_decode(wire, sizeof(wire), out) == 0 &&
        pq_deaddrop_response_verify(offer, out) == 0 &&
        fingerprint_text_verify(
            fingerprint, out->transcript_fingerprint) == 0)
        result = 0;
    if (result != 0)
        crypto_memzero(out, sizeof(*out));
    crypto_memzero(wire, sizeof(wire));
    crypto_memzero(fingerprint, sizeof(fingerprint));
    return result;
}

int pq_deaddrop_response_line_decode(
    const char *line, size_t line_len, const pq_deaddrop_offer_t *offer,
    pq_deaddrop_response_t *out)
{
    return response_line_decode_with_prefix(
        line, line_len, PQ_DEADDROP_RESPONSE_PREFIX,
        PQ_DEADDROP_RESPONSE_LINE_LEN, offer, out);
}

int pq_deaddrop_accept_line_encode(
    const pq_deaddrop_offer_t *offer,
    const pq_deaddrop_response_t *response,
    char out[PQ_DEADDROP_ACCEPT_LINE_LEN + 1U])
{
    return response_line_encode_with_prefix(
        PQ_DEADDROP_ACCEPT_PREFIX, PQ_DEADDROP_ACCEPT_LINE_LEN,
        offer, response, out);
}

int pq_deaddrop_accept_line_verify(
    const char *line, size_t line_len, const pq_deaddrop_offer_t *offer,
    const pq_deaddrop_response_t *response)
{
    pq_deaddrop_response_t decoded;
    int result = -1;
    if (response_line_decode_with_prefix(
            line, line_len, PQ_DEADDROP_ACCEPT_PREFIX,
            PQ_DEADDROP_ACCEPT_LINE_LEN, offer, &decoded) == 0 &&
        memcmp(&decoded, response, sizeof(decoded)) == 0)
        result = 0;
    crypto_memzero(&decoded, sizeof(decoded));
    return result;
}

deaddrop_status_t pq_deaddrop_publish_offer(
    int dirfd, const pq_deaddrop_offer_t *offer)
{
    uint8_t wire[PQ_DEADDROP_OFFER_SIZE];
    deaddrop_status_t status;

    if (offer == NULL || pq_deaddrop_offer_encode(offer, wire) != 0) {
        errno = EINVAL;
        return DEADDROP_ERR_ARGUMENT;
    }
    status = deaddrop_public_publish(dirfd, offer->id,
                                     DEADDROP_PUBLIC_OFFER,
                                     wire, sizeof(wire));
    crypto_memzero(wire, sizeof(wire));
    return status;
}

deaddrop_status_t pq_deaddrop_publish_response(
    int dirfd, const pq_deaddrop_response_t *response)
{
    uint8_t wire[PQ_DEADDROP_RESPONSE_SIZE];
    deaddrop_status_t status;

    if (response == NULL ||
        pq_deaddrop_response_encode(response, wire) != 0) {
        errno = EINVAL;
        return DEADDROP_ERR_ARGUMENT;
    }
    status = deaddrop_public_publish(dirfd, response->id,
                                     DEADDROP_PUBLIC_RESPONSE,
                                     wire, sizeof(wire));
    crypto_memzero(wire, sizeof(wire));
    return status;
}

deaddrop_status_t pq_deaddrop_offer_present(
    int dirfd, const uint8_t id[DEADDROP_ID_LEN], int *present_out)
{
    return deaddrop_public_present(dirfd, id, DEADDROP_PUBLIC_OFFER,
                                   PQ_DEADDROP_OFFER_SIZE, present_out);
}

deaddrop_status_t pq_deaddrop_response_present(
    int dirfd, const uint8_t id[DEADDROP_ID_LEN], int *present_out)
{
    return deaddrop_public_present(dirfd, id, DEADDROP_PUBLIC_RESPONSE,
                                   PQ_DEADDROP_RESPONSE_SIZE, present_out);
}

deaddrop_status_t pq_deaddrop_claim_offer(
    int dirfd, const uint8_t id[DEADDROP_ID_LEN],
    pq_deaddrop_offer_t *offer_out)
{
    uint8_t wire[PQ_DEADDROP_OFFER_SIZE];
    pq_deaddrop_offer_t decoded;
    deaddrop_status_t status;

    if (offer_out == NULL) {
        errno = EINVAL;
        return DEADDROP_ERR_ARGUMENT;
    }
    memset(offer_out, 0, sizeof(*offer_out));
    memset(&decoded, 0, sizeof(decoded));
    memset(wire, 0, sizeof(wire));
    status = deaddrop_public_claim(dirfd, id, DEADDROP_PUBLIC_OFFER,
                                   wire, sizeof(wire));
    if (status == DEADDROP_OK &&
        (pq_deaddrop_offer_decode(wire, sizeof(wire), &decoded) != 0 ||
         memcmp(decoded.id, id, DEADDROP_ID_LEN) != 0)) {
        errno = EPROTO;
        status = DEADDROP_ERR_FORMAT;
    }
    if (status == DEADDROP_OK)
        *offer_out = decoded;
    crypto_memzero(&decoded, sizeof(decoded));
    crypto_memzero(wire, sizeof(wire));
    return status;
}

deaddrop_status_t pq_deaddrop_claim_response(
    int dirfd, const uint8_t id[DEADDROP_ID_LEN],
    pq_deaddrop_response_t *response_out)
{
    uint8_t wire[PQ_DEADDROP_RESPONSE_SIZE];
    pq_deaddrop_response_t decoded;
    deaddrop_status_t status;

    if (response_out == NULL) {
        errno = EINVAL;
        return DEADDROP_ERR_ARGUMENT;
    }
    memset(response_out, 0, sizeof(*response_out));
    memset(&decoded, 0, sizeof(decoded));
    memset(wire, 0, sizeof(wire));
    status = deaddrop_public_claim(dirfd, id, DEADDROP_PUBLIC_RESPONSE,
                                   wire, sizeof(wire));
    if (status == DEADDROP_OK &&
        (pq_deaddrop_response_decode(wire, sizeof(wire), &decoded) != 0 ||
         memcmp(decoded.id, id, DEADDROP_ID_LEN) != 0)) {
        errno = EPROTO;
        status = DEADDROP_ERR_FORMAT;
    }
    if (status == DEADDROP_OK)
        *response_out = decoded;
    crypto_memzero(&decoded, sizeof(decoded));
    crypto_memzero(wire, sizeof(wire));
    return status;
}
