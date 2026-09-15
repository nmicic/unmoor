/*
 * pq_epoch_crypto.c — pq-hybrid epoch derivation
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */

#include "pq_epoch_crypto.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "crypto.h"
#include "monocypher.h"
#include "negotiation.h"
#include "pq_hybrid.h"

#define PQ_REKEY_TRANSCRIPT_MAX 3400U

static const uint8_t role_client[] = "client";
static const uint8_t role_server[] = "server";
static const uint8_t domain_transcript[] =
    "unmoor-pq-rekey-transcript-v1";
static const uint8_t domain_traffic[] =
    "unmoor-pq-rekey-traffic-v1";
static const uint8_t domain_confirm[] =
    "unmoor-pq-rekey-confirm-v1";
static const uint8_t domain_fingerprint[] =
    "unmoor-pq-rekey-fingerprint-v1";

static void store32le(uint8_t out[4], uint32_t value)
{
    out[0] = (uint8_t)value;
    out[1] = (uint8_t)(value >> 8);
    out[2] = (uint8_t)(value >> 16);
    out[3] = (uint8_t)(value >> 24);
}

static int append_field(uint8_t *out, size_t capacity, size_t *used,
                        const uint8_t *bytes, size_t length)
{
    if (!out || !used || (!bytes && length != 0U) ||
        length > UINT16_MAX || *used > capacity ||
        length + 2U > capacity - *used)
        return -1;
    out[*used] = (uint8_t)length;
    out[*used + 1U] = (uint8_t)(length >> 8);
    if (length != 0U)
        memcpy(out + *used + 2U, bytes, length);
    *used += length + 2U;
    return 0;
}

static int canonical_transcript(
    uint8_t out[PQ_REKEY_TRANSCRIPT_MAX], size_t *length_out,
    const uint8_t session_context[32],
    const uint8_t client_hello[32], const uint8_t server_ack[32],
    uint32_t selected_caps, uint32_t from_epoch, uint32_t to_epoch,
    const uint8_t rekey_id[16],
    const uint8_t client_public[32], const uint8_t server_public[32],
    const uint8_t mlkem_public[PQ_MLKEM_PUBLIC_LEN],
    const uint8_t mlkem_ciphertext[PQ_MLKEM_CIPHERTEXT_LEN])
{
    const uint8_t suite = 1U;
    uint8_t from_le[4];
    uint8_t to_le[4];
    uint8_t caps_le[4];
    size_t used = 0U;
    int rc = -1;

    if (!out || !length_out || !session_context || !client_hello ||
        !server_ack || !rekey_id || !client_public || !server_public ||
        !mlkem_public || !mlkem_ciphertext)
        return -1;
    store32le(from_le, from_epoch);
    store32le(to_le, to_epoch);
    store32le(caps_le, selected_caps);
    if (append_field(out, PQ_REKEY_TRANSCRIPT_MAX, &used,
                     &suite, sizeof(suite)) != 0 ||
        append_field(out, PQ_REKEY_TRANSCRIPT_MAX, &used,
                     role_client, sizeof(role_client) - 1U) != 0 ||
        append_field(out, PQ_REKEY_TRANSCRIPT_MAX, &used,
                     role_server, sizeof(role_server) - 1U) != 0 ||
        append_field(out, PQ_REKEY_TRANSCRIPT_MAX, &used,
                     from_le, sizeof(from_le)) != 0 ||
        append_field(out, PQ_REKEY_TRANSCRIPT_MAX, &used,
                     to_le, sizeof(to_le)) != 0 ||
        append_field(out, PQ_REKEY_TRANSCRIPT_MAX, &used,
                     rekey_id, 16U) != 0 ||
        append_field(out, PQ_REKEY_TRANSCRIPT_MAX, &used,
                     client_hello, 32U) != 0 ||
        append_field(out, PQ_REKEY_TRANSCRIPT_MAX, &used,
                     server_ack, 32U) != 0 ||
        append_field(out, PQ_REKEY_TRANSCRIPT_MAX, &used,
                     caps_le, sizeof(caps_le)) != 0 ||
        append_field(out, PQ_REKEY_TRANSCRIPT_MAX, &used,
                     session_context, 32U) != 0 ||
        append_field(out, PQ_REKEY_TRANSCRIPT_MAX, &used,
                     client_public, 32U) != 0 ||
        append_field(out, PQ_REKEY_TRANSCRIPT_MAX, &used,
                     server_public, 32U) != 0 ||
        append_field(out, PQ_REKEY_TRANSCRIPT_MAX, &used,
                     mlkem_public, PQ_MLKEM_PUBLIC_LEN) != 0 ||
        append_field(out, PQ_REKEY_TRANSCRIPT_MAX, &used,
                     mlkem_ciphertext, PQ_MLKEM_CIPHERTEXT_LEN) != 0)
        goto out;
    *length_out = used;
    rc = 0;
out:
    crypto_memzero(from_le, sizeof(from_le));
    crypto_memzero(to_le, sizeof(to_le));
    crypto_memzero(caps_le, sizeof(caps_le));
    if (rc != 0) {
        crypto_memzero(out, PQ_REKEY_TRANSCRIPT_MAX);
        *length_out = 0U;
    }
    return rc;
}

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
        (local_role != EPOCH_CRYPTO_ROLE_CLIENT &&
         local_role != EPOCH_CRYPTO_ROLE_SERVER) ||
        !epoch_crypto_public_key_is_canonical(client_public) ||
        !epoch_crypto_public_key_is_canonical(server_public) ||
        crypto_verify32(client_public, server_public) == 0) {
        if (raw_out)
            crypto_memzero(raw_out, 32U);
        return -1;
    }
    declared_local = local_role == EPOCH_CRYPTO_ROLE_CLIENT
        ? client_public : server_public;
    peer_public = local_role == EPOCH_CRYPTO_ROLE_CLIENT
        ? server_public : client_public;
    crypto_x25519_public_key(derived_local, local_private);
    if (crypto_verify32(derived_local, declared_local) != 0) {
        crypto_memzero(derived_local, sizeof(derived_local));
        crypto_memzero(raw_out, 32U);
        return -1;
    }
    crypto_x25519(raw_out, local_private, peer_public);
    crypto_memzero(derived_local, sizeof(derived_local));
    if (crypto_verify32(raw_out, zero) == 0) {
        crypto_memzero(raw_out, 32U);
        return -1;
    }
    return 0;
}

static void keyed_expand(const uint8_t key[32], const uint8_t *domain,
                         size_t domain_len, const uint8_t transcript[32],
                         uint8_t out[32])
{
    crypto_blake2b_ctx ctx;

    crypto_blake2b_keyed_init(&ctx, 32U, key, 32U);
    crypto_blake2b_update(&ctx, domain, domain_len);
    crypto_blake2b_update(&ctx, transcript, 32U);
    crypto_blake2b_final(&ctx, out);
    crypto_memzero(&ctx, sizeof(ctx));
}

int pq_epoch_crypto_rekey_derive(
    const uint8_t current_traffic_key[32],
    const uint8_t local_private[32], epoch_crypto_role_t local_role,
    const uint8_t session_context[32],
    const uint8_t client_hello[32], const uint8_t server_ack[32],
    uint32_t selected_caps, uint32_t from_epoch, uint32_t to_epoch,
    const uint8_t rekey_id[16],
    const uint8_t client_public[32], const uint8_t server_public[32],
    const uint8_t mlkem_public[PQ_MLKEM_PUBLIC_LEN],
    const uint8_t mlkem_ciphertext[PQ_MLKEM_CIPHERTEXT_LEN],
    const uint8_t mlkem_shared[PQ_MLKEM_SECRET_LEN],
    epoch_crypto_rekey_material_t *out)
{
    uint8_t transcript_bytes[PQ_REKEY_TRANSCRIPT_MAX];
    uint8_t raw_dh[32];
    uint8_t combined[32];
    epoch_crypto_rekey_material_t material;
    crypto_blake2b_ctx hash;
    size_t transcript_len = 0U;
    int rc = -1;

    if (!out)
        return -1;
    crypto_memzero(out, sizeof(*out));
    crypto_memzero(&material, sizeof(material));
    crypto_memzero(transcript_bytes, sizeof(transcript_bytes));
    crypto_memzero(raw_dh, sizeof(raw_dh));
    crypto_memzero(combined, sizeof(combined));
    crypto_memzero(&hash, sizeof(hash));
    if (!current_traffic_key || !local_private || !session_context ||
        !client_hello || !server_ack || !rekey_id || !client_public ||
        !server_public || !mlkem_public || !mlkem_ciphertext ||
        !mlkem_shared || from_epoch == UINT32_MAX ||
        to_epoch != from_epoch + UINT32_C(1) ||
        (selected_caps & (UNMOOR_CAP_EPOCH_REKEY_D28_V1 |
                          UNMOOR_CAP_PQ_HYBRID_D45_V1)) !=
            (UNMOOR_CAP_EPOCH_REKEY_D28_V1 |
             UNMOOR_CAP_PQ_HYBRID_D45_V1) ||
        pq_mlkem_public_key_valid(mlkem_public) != 1 ||
        validated_raw_dh(local_private, local_role, client_public,
                         server_public, raw_dh) != 0 ||
        canonical_transcript(transcript_bytes, &transcript_len,
                             session_context, client_hello, server_ack,
                             selected_caps, from_epoch, to_epoch, rekey_id,
                             client_public, server_public, mlkem_public,
                             mlkem_ciphertext) != 0 ||
        pq_hybrid_rekey_combine(current_traffic_key, raw_dh, mlkem_shared,
                                transcript_bytes, transcript_len,
                                combined) != 0)
        goto cleanup;

    crypto_blake2b_init(&hash, 32U);
    crypto_blake2b_update(&hash, domain_transcript,
                          sizeof(domain_transcript) - 1U);
    crypto_blake2b_update(&hash, transcript_bytes, transcript_len);
    crypto_blake2b_final(&hash, material.transcript_hash);
    crypto_memzero(&hash, sizeof(hash));
    keyed_expand(combined, domain_traffic, sizeof(domain_traffic) - 1U,
                 material.transcript_hash, material.traffic_key);
    keyed_expand(combined, domain_confirm, sizeof(domain_confirm) - 1U,
                 material.transcript_hash, material.confirm_key);
    keyed_expand(material.confirm_key, domain_fingerprint,
                 sizeof(domain_fingerprint) - 1U,
                 material.transcript_hash, material.epoch_fingerprint);
    memcpy(out, &material, sizeof(material));
    rc = 0;

cleanup:
    crypto_memzero(transcript_bytes, sizeof(transcript_bytes));
    crypto_memzero(raw_dh, sizeof(raw_dh));
    crypto_memzero(combined, sizeof(combined));
    crypto_memzero(&material, sizeof(material));
    crypto_memzero(&hash, sizeof(hash));
    return rc;
}
