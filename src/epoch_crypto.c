/*
 * epoch_crypto.c — epoch-rekey public bootstrap and epoch-rekey crypto helpers
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "crypto.h"
#include "epoch_crypto.h"
#include "monocypher.h"

static const uint8_t protocol_version = 1U;
static const uint8_t role_client[] = "client";
static const uint8_t role_server[] = "server";

static const uint8_t domain_offer[] =
    "unmoor-deaddrop-offer-fingerprint-v1";
static const uint8_t domain_transcript[] =
    "unmoor-deaddrop-transcript-fingerprint-v1";
static const uint8_t domain_bootstrap_root[] =
    "unmoor-deaddrop-root-v1";
static const uint8_t domain_pair_seed[] =
    "unmoor-epoch-pair-seed-v1";
static const uint8_t domain_session_context[] =
    "unmoor-session-context-v1";
static const uint8_t domain_rekey_transcript[] =
    "unmoor-rekey-transcript-v1";
static const uint8_t domain_rekey_combine[] =
    "unmoor-rekey-combine-v1";
static const uint8_t domain_rekey_traffic[] =
    "unmoor-rekey-traffic-v1";
static const uint8_t domain_rekey_confirm[] =
    "unmoor-rekey-confirm-v1";
static const uint8_t domain_rekey_fingerprint[] =
    "unmoor-rekey-fingerprint-v1";
static const uint8_t label_offer_fingerprint[] = "offer-fingerprint";
static const uint8_t label_client_hello[] = "client-hello";
static const uint8_t label_server_ack[] = "server-ack";
static const uint8_t label_pair_seed[] = "pair-seed";

static void store16le(uint8_t out[2], uint16_t value)
{
    out[0] = (uint8_t)(value & UINT16_C(0x00ff));
    out[1] = (uint8_t)(value >> 8);
}

static void store32le(uint8_t out[4], uint32_t value)
{
    out[0] = (uint8_t)(value & UINT32_C(0x000000ff));
    out[1] = (uint8_t)((value >> 8) & UINT32_C(0x000000ff));
    out[2] = (uint8_t)((value >> 16) & UINT32_C(0x000000ff));
    out[3] = (uint8_t)(value >> 24);
}

static int role_is_valid(epoch_crypto_role_t role)
{
    return role == EPOCH_CRYPTO_ROLE_CLIENT ||
           role == EPOCH_CRYPTO_ROLE_SERVER;
}

int epoch_crypto_public_key_is_canonical(const uint8_t public_key[32])
{
    /* p = 2^255 - 19, in little-endian canonical form. */
    static const uint8_t field_prime[32] = {
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
    };

    if (!public_key || (public_key[31] & UINT8_C(0x80)) != 0)
        return 0;

    /* Public-data comparison: canonical iff the integer is strictly < p. */
    for (size_t i = 32; i > 0; i--) {
        size_t j = i - 1;
        if (public_key[j] < field_prime[j]) return 1;
        if (public_key[j] > field_prime[j]) return 0;
    }
    return 0; /* u == p is noncanonical */
}

int epoch_crypto_keypair_generate(uint8_t private_key[32],
                                  uint8_t public_key[32])
{
    if (!private_key || !public_key)
        return -1;
    if (crypto_random_bytes(private_key, 32) != 0) {
        crypto_memzero(private_key, 32);
        crypto_memzero(public_key, 32);
        return -1;
    }
    crypto_x25519_public_key(public_key, private_key);
    if (!epoch_crypto_public_key_is_canonical(public_key)) {
        crypto_memzero(private_key, 32);
        crypto_memzero(public_key, 32);
        return -1;
    }
    return 0;
}

static void update_public_prefix(crypto_blake2b_ctx *ctx,
                                 const uint8_t *domain, size_t domain_len,
                                 const uint8_t drop_id[16], uint16_t udp_port,
                                 uint32_t bootstrap_policy)
{
    uint8_t port_le[2];
    uint8_t policy_le[4];
    store16le(port_le, udp_port);
    store32le(policy_le, bootstrap_policy);
    crypto_blake2b_update(ctx, domain, domain_len);
    crypto_blake2b_update(ctx, &protocol_version, 1);
    crypto_blake2b_update(ctx, drop_id, 16);
    crypto_blake2b_update(ctx, port_le, sizeof(port_le));
    crypto_blake2b_update(ctx, policy_le, sizeof(policy_le));
    crypto_memzero(port_le, sizeof(port_le));
    crypto_memzero(policy_le, sizeof(policy_le));
}

int epoch_crypto_offer_fingerprint(const uint8_t drop_id[16],
                                   uint16_t udp_port,
                                   uint32_t bootstrap_policy,
                                   const uint8_t server_public[32],
                                   uint8_t fingerprint_out[32])
{
    crypto_blake2b_ctx ctx;
    if (!drop_id || !server_public || !fingerprint_out || udp_port == 0 ||
        !epoch_crypto_public_key_is_canonical(server_public)) {
        if (fingerprint_out) crypto_memzero(fingerprint_out, 32);
        return -1;
    }

    crypto_blake2b_init(&ctx, 32);
    update_public_prefix(&ctx, domain_offer, sizeof(domain_offer) - 1,
                         drop_id, udp_port, bootstrap_policy);
    crypto_blake2b_update(&ctx, role_server, sizeof(role_server) - 1);
    crypto_blake2b_update(&ctx, server_public, 32);
    crypto_blake2b_final(&ctx, fingerprint_out);
    crypto_memzero(&ctx, sizeof(ctx));
    return 0;
}

int epoch_crypto_transcript_fingerprint(const uint8_t drop_id[16],
                                        uint16_t udp_port,
                                        uint32_t bootstrap_policy,
                                        const uint8_t client_public[32],
                                        const uint8_t server_public[32],
                                        uint8_t fingerprint_out[32])
{
    uint8_t offer_fingerprint[32];
    crypto_blake2b_ctx ctx;
    if (!drop_id || !client_public || !server_public || !fingerprint_out ||
        udp_port == 0 ||
        !epoch_crypto_public_key_is_canonical(client_public) ||
        !epoch_crypto_public_key_is_canonical(server_public) ||
        crypto_verify32(client_public, server_public) == 0) {
        if (fingerprint_out) crypto_memzero(fingerprint_out, 32);
        return -1;
    }
    if (epoch_crypto_offer_fingerprint(drop_id, udp_port, bootstrap_policy,
                                       server_public,
                                       offer_fingerprint) != 0) {
        crypto_memzero(fingerprint_out, 32);
        return -1;
    }

    crypto_blake2b_init(&ctx, 32);
    update_public_prefix(&ctx, domain_transcript,
                         sizeof(domain_transcript) - 1,
                         drop_id, udp_port, bootstrap_policy);
    crypto_blake2b_update(&ctx, role_client, sizeof(role_client) - 1);
    crypto_blake2b_update(&ctx, client_public, 32);
    crypto_blake2b_update(&ctx, role_server, sizeof(role_server) - 1);
    crypto_blake2b_update(&ctx, server_public, 32);
    crypto_blake2b_update(&ctx, label_offer_fingerprint,
                          sizeof(label_offer_fingerprint) - 1);
    crypto_blake2b_update(&ctx, offer_fingerprint, 32);
    crypto_blake2b_final(&ctx, fingerprint_out);
    crypto_memzero(&ctx, sizeof(ctx));
    crypto_memzero(offer_fingerprint, sizeof(offer_fingerprint));
    return 0;
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

int epoch_crypto_fingerprint_encode(const uint8_t fingerprint[32],
                                    char text_out[72])
{
    static const char prefix[] = "b2b256:";
    static const char hex[] = "0123456789abcdef";
    if (!fingerprint || !text_out)
        return -1;
    memcpy(text_out, prefix, sizeof(prefix) - 1);
    for (size_t i = 0; i < 32; i++) {
        text_out[7 + 2 * i] = hex[fingerprint[i] >> 4];
        text_out[8 + 2 * i] = hex[fingerprint[i] & UINT8_C(0x0f)];
    }
    text_out[EPOCH_CRYPTO_FINGERPRINT_TEXT_LEN] = '\0';
    return 0;
}

int epoch_crypto_fingerprint_decode(const char *text, size_t text_len,
                                    uint8_t fingerprint_out[32])
{
    static const char prefix[] = "b2b256:";
    if (!text || !fingerprint_out ||
        text_len != EPOCH_CRYPTO_FINGERPRINT_TEXT_LEN ||
        memcmp(text, prefix, sizeof(prefix) - 1) != 0) {
        if (fingerprint_out) crypto_memzero(fingerprint_out, 32);
        return -1;
    }

    for (size_t i = 0; i < 32; i++) {
        uint8_t hi;
        uint8_t lo;
        if (lowercase_hex_value(text[7 + 2 * i], &hi) != 0 ||
            lowercase_hex_value(text[8 + 2 * i], &lo) != 0) {
            crypto_memzero(fingerprint_out, 32);
            return -1;
        }
        fingerprint_out[i] = (uint8_t)((uint8_t)(hi << 4) | lo);
    }
    return 0;
}

int epoch_crypto_fingerprint_verify(const char *text, size_t text_len,
                                    const uint8_t expected[32])
{
    uint8_t decoded[32];
    int rc = -1;
    if (expected &&
        epoch_crypto_fingerprint_decode(text, text_len, decoded) == 0 &&
        crypto_verify32(decoded, expected) == 0)
        rc = 0;
    crypto_memzero(decoded, sizeof(decoded));
    return rc;
}

/* Validate the exact role declaration and produce an internal raw DH value.
 * The caller owns local_private; this helper owns and wipes derived_local but
 * transfers ownership of raw_out to its caller. */
static int validated_raw_dh(const uint8_t local_private[32],
                            epoch_crypto_role_t local_role,
                            const uint8_t client_public[32],
                            const uint8_t server_public[32],
                            uint8_t raw_out[32])
{
    static const uint8_t zero[32] = { 0 };
    uint8_t derived_local[32];
    const uint8_t *declared_local;
    const uint8_t *peer_public;

    if (!local_private || !client_public || !server_public || !raw_out ||
        !role_is_valid(local_role) ||
        !epoch_crypto_public_key_is_canonical(client_public) ||
        !epoch_crypto_public_key_is_canonical(server_public) ||
        crypto_verify32(client_public, server_public) == 0) {
        if (raw_out) crypto_memzero(raw_out, 32);
        return -1;
    }

    declared_local = local_role == EPOCH_CRYPTO_ROLE_CLIENT
                         ? client_public : server_public;
    peer_public = local_role == EPOCH_CRYPTO_ROLE_CLIENT
                      ? server_public : client_public;
    crypto_x25519_public_key(derived_local, local_private);
    if (crypto_verify32(derived_local, declared_local) != 0) {
        crypto_memzero(derived_local, sizeof(derived_local));
        crypto_memzero(raw_out, 32);
        return -1;
    }

    crypto_x25519(raw_out, local_private, peer_public);
    crypto_memzero(derived_local, sizeof(derived_local));
    if (crypto_verify32(raw_out, zero) == 0) {
        crypto_memzero(raw_out, 32);
        return -1;
    }
    return 0;
}

static void update_bootstrap_transcript(crypto_blake2b_ctx *ctx,
                                        const uint8_t drop_id[16],
                                        uint16_t udp_port,
                                        uint32_t bootstrap_policy,
                                        const uint8_t client_public[32],
                                        const uint8_t server_public[32])
{
    update_public_prefix(ctx, domain_bootstrap_root,
                         sizeof(domain_bootstrap_root) - 1,
                         drop_id, udp_port, bootstrap_policy);
    crypto_blake2b_update(ctx, role_client, sizeof(role_client) - 1);
    crypto_blake2b_update(ctx, client_public, 32);
    crypto_blake2b_update(ctx, role_server, sizeof(role_server) - 1);
    crypto_blake2b_update(ctx, server_public, 32);
}

int epoch_crypto_bootstrap_derive(const uint8_t local_private[32],
                                  epoch_crypto_role_t local_role,
                                  const uint8_t drop_id[16],
                                  uint16_t udp_port,
                                  uint32_t bootstrap_policy,
                                  const uint8_t client_public[32],
                                  const uint8_t server_public[32],
                                  uint8_t root_out[32],
                                  uint8_t pair_seed_out[4])
{
    uint8_t raw_dh[32];
    uint8_t root[32];
    uint8_t full_fingerprint[32];
    uint8_t pair_hash[32];
    crypto_blake2b_ctx ctx;
    int rc = -1;

    if (!root_out || !pair_seed_out)
        return -1;
    crypto_memzero(root_out, 32);
    crypto_memzero(pair_seed_out, 4);
    if (!drop_id || udp_port == 0 ||
        validated_raw_dh(local_private, local_role, client_public,
                         server_public, raw_dh) != 0)
        goto cleanup;
    if (epoch_crypto_transcript_fingerprint(drop_id, udp_port,
                                             bootstrap_policy,
                                             client_public, server_public,
                                             full_fingerprint) != 0)
        goto cleanup;

    crypto_blake2b_keyed_init(&ctx, 32, raw_dh, 32);
    update_bootstrap_transcript(&ctx, drop_id, udp_port, bootstrap_policy,
                                client_public, server_public);
    crypto_blake2b_final(&ctx, root);
    crypto_memzero(&ctx, sizeof(ctx));

    crypto_blake2b_keyed_init(&ctx, 32, root, 32);
    crypto_blake2b_update(&ctx, domain_pair_seed,
                          sizeof(domain_pair_seed) - 1);
    crypto_blake2b_update(&ctx, full_fingerprint, 32);
    crypto_blake2b_final(&ctx, pair_hash);
    crypto_memzero(&ctx, sizeof(ctx));

    memcpy(root_out, root, 32);
    memcpy(pair_seed_out, pair_hash, 4);
    rc = 0;

cleanup:
    crypto_memzero(raw_dh, sizeof(raw_dh));
    crypto_memzero(root, sizeof(root));
    crypto_memzero(full_fingerprint, sizeof(full_fingerprint));
    crypto_memzero(pair_hash, sizeof(pair_hash));
    crypto_memzero(&ctx, sizeof(ctx));
    return rc;
}

int epoch_crypto_session_context(const uint8_t client_hello[32],
                                 const uint8_t server_ack[32],
                                 uint32_t selected_caps,
                                 const uint8_t pair_seed[4],
                                 uint8_t context_out[32])
{
    uint8_t caps_le[4];
    crypto_blake2b_ctx ctx;
    if (!client_hello || !server_ack || !pair_seed || !context_out) {
        if (context_out) crypto_memzero(context_out, 32);
        return -1;
    }
    store32le(caps_le, selected_caps);
    crypto_blake2b_init(&ctx, 32);
    crypto_blake2b_update(&ctx, domain_session_context,
                          sizeof(domain_session_context) - 1);
    crypto_blake2b_update(&ctx, &protocol_version, 1);
    crypto_blake2b_update(&ctx, label_client_hello,
                          sizeof(label_client_hello) - 1);
    crypto_blake2b_update(&ctx, client_hello, 32);
    crypto_blake2b_update(&ctx, label_server_ack,
                          sizeof(label_server_ack) - 1);
    crypto_blake2b_update(&ctx, server_ack, 32);
    crypto_blake2b_update(&ctx, caps_le, sizeof(caps_le));
    crypto_blake2b_update(&ctx, label_pair_seed,
                          sizeof(label_pair_seed) - 1);
    crypto_blake2b_update(&ctx, pair_seed, 4);
    crypto_blake2b_final(&ctx, context_out);
    crypto_memzero(&ctx, sizeof(ctx));
    crypto_memzero(caps_le, sizeof(caps_le));
    return 0;
}

static void rekey_transcript_hash(
    const uint8_t session_context[32], uint32_t selected_caps,
    uint32_t from_epoch, uint32_t to_epoch, const uint8_t rekey_id[16],
    const uint8_t client_public[32], const uint8_t server_public[32],
    uint8_t transcript_out[32])
{
    uint8_t caps_le[4];
    uint8_t from_le[4];
    uint8_t to_le[4];
    crypto_blake2b_ctx ctx;
    store32le(caps_le, selected_caps);
    store32le(from_le, from_epoch);
    store32le(to_le, to_epoch);

    crypto_blake2b_init(&ctx, 32);
    crypto_blake2b_update(&ctx, domain_rekey_transcript,
                          sizeof(domain_rekey_transcript) - 1);
    crypto_blake2b_update(&ctx, &protocol_version, 1);
    crypto_blake2b_update(&ctx, session_context, 32);
    crypto_blake2b_update(&ctx, caps_le, sizeof(caps_le));
    crypto_blake2b_update(&ctx, from_le, sizeof(from_le));
    crypto_blake2b_update(&ctx, to_le, sizeof(to_le));
    crypto_blake2b_update(&ctx, rekey_id, 16);
    crypto_blake2b_update(&ctx, role_client, sizeof(role_client) - 1);
    crypto_blake2b_update(&ctx, client_public, 32);
    crypto_blake2b_update(&ctx, role_server, sizeof(role_server) - 1);
    crypto_blake2b_update(&ctx, server_public, 32);
    crypto_blake2b_final(&ctx, transcript_out);
    crypto_memzero(&ctx, sizeof(ctx));
    crypto_memzero(caps_le, sizeof(caps_le));
    crypto_memzero(from_le, sizeof(from_le));
    crypto_memzero(to_le, sizeof(to_le));
}

static void keyed_expand(const uint8_t key[32],
                         const uint8_t *domain, size_t domain_len,
                         const uint8_t transcript[32], uint8_t out[32])
{
    crypto_blake2b_ctx ctx;
    crypto_blake2b_keyed_init(&ctx, 32, key, 32);
    crypto_blake2b_update(&ctx, domain, domain_len);
    crypto_blake2b_update(&ctx, transcript, 32);
    crypto_blake2b_final(&ctx, out);
    crypto_memzero(&ctx, sizeof(ctx));
}

int epoch_crypto_rekey_derive(
    const uint8_t current_traffic_key[32],
    const uint8_t local_private[32], epoch_crypto_role_t local_role,
    const uint8_t session_context[32], uint32_t selected_caps,
    uint32_t from_epoch, uint32_t to_epoch, const uint8_t rekey_id[16],
    const uint8_t client_public[32], const uint8_t server_public[32],
    epoch_crypto_rekey_material_t *out)
{
    uint8_t raw_dh[32];
    uint8_t transcript[32];
    uint8_t intermediate[32];
    epoch_crypto_rekey_material_t material;
    crypto_blake2b_ctx ctx;
    int rc = -1;

    if (!out)
        return -1;
    crypto_memzero(out, sizeof(*out));
    crypto_memzero(&material, sizeof(material));
    if (!current_traffic_key || !local_private || !session_context ||
        !rekey_id || !client_public || !server_public ||
        from_epoch == UINT32_MAX || to_epoch != from_epoch + UINT32_C(1) ||
        validated_raw_dh(local_private, local_role, client_public,
                         server_public, raw_dh) != 0)
        goto cleanup;

    rekey_transcript_hash(session_context, selected_caps,
                          from_epoch, to_epoch, rekey_id,
                          client_public, server_public, transcript);

    crypto_blake2b_keyed_init(&ctx, 32, current_traffic_key, 32);
    crypto_blake2b_update(&ctx, domain_rekey_combine,
                          sizeof(domain_rekey_combine) - 1);
    crypto_blake2b_update(&ctx, raw_dh, 32);
    crypto_blake2b_update(&ctx, transcript, 32);
    crypto_blake2b_final(&ctx, intermediate);
    crypto_memzero(&ctx, sizeof(ctx));

    memcpy(material.transcript_hash, transcript, 32);
    keyed_expand(intermediate, domain_rekey_traffic,
                 sizeof(domain_rekey_traffic) - 1, transcript,
                 material.traffic_key);
    keyed_expand(intermediate, domain_rekey_confirm,
                 sizeof(domain_rekey_confirm) - 1, transcript,
                 material.confirm_key);
    keyed_expand(material.confirm_key, domain_rekey_fingerprint,
                 sizeof(domain_rekey_fingerprint) - 1, transcript,
                 material.epoch_fingerprint);
    memcpy(out, &material, sizeof(material));
    rc = 0;

cleanup:
    crypto_memzero(raw_dh, sizeof(raw_dh));
    crypto_memzero(transcript, sizeof(transcript));
    crypto_memzero(intermediate, sizeof(intermediate));
    crypto_memzero(&material, sizeof(material));
    crypto_memzero(&ctx, sizeof(ctx));
    return rc;
}

int epoch_crypto_pair_id(const uint8_t pair_seed[4], uint32_t epoch,
                         uint8_t pair_id_out[4])
{
    uint8_t epoch_le[4];
    if (!pair_seed || !pair_id_out)
        return -1;
    store32le(epoch_le, epoch);
    for (size_t i = 0; i < 4; i++)
        pair_id_out[i] = (uint8_t)(pair_seed[i] ^ epoch_le[i]);
    crypto_memzero(epoch_le, sizeof(epoch_le));
    return 0;
}
