/*
 * pq_deaddrop_exchange.c — in-memory pq-hybrid bootstrap lifecycle
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */

#include "pq_deaddrop_exchange.h"

#include <string.h>

#include "crypto.h"
#include "epoch_crypto.h"
#include "monocypher.h"
#include "negotiation.h"
#include "pq_hybrid.h"

#define PQ_BOOTSTRAP_TRANSCRIPT_LEN \
    (PQ_DEADDROP_OFFER_SIZE + 1668U)

static const uint8_t pair_seed_domain[] =
    "unmoor-pq-pair-seed-v1";

static int equal32(const uint8_t a[32], const uint8_t b[32])
{
    return crypto_verify32_exact(a, b) == 0;
}

static int raw_x25519(const uint8_t local_private[32],
                      const uint8_t local_public[32],
                      const uint8_t peer_public[32], uint8_t raw_out[32])
{
    static const uint8_t zero[32] = { 0 };
    uint8_t derived[32];
    int result = -1;

    if (!local_private || !local_public || !peer_public || !raw_out ||
        !epoch_crypto_public_key_is_canonical(local_public) ||
        !epoch_crypto_public_key_is_canonical(peer_public) ||
        equal32(local_public, peer_public)) {
        if (raw_out)
            crypto_memzero(raw_out, 32);
        return -1;
    }
    crypto_x25519_public_key(derived, local_private);
    if (!equal32(derived, local_public))
        goto cleanup;
    crypto_x25519(raw_out, local_private, peer_public);
    if (equal32(raw_out, zero)) {
        crypto_memzero(raw_out, 32);
        goto cleanup;
    }
    result = 0;
cleanup:
    crypto_memzero(derived, sizeof(derived));
    return result;
}

static int bootstrap_transcript(const pq_deaddrop_offer_t *offer,
                                const pq_deaddrop_response_t *response,
                                uint8_t out[PQ_BOOTSTRAP_TRANSCRIPT_LEN])
{
    uint8_t response_wire[PQ_DEADDROP_RESPONSE_SIZE];
    if (!offer || !response || !out ||
        pq_deaddrop_response_verify(offer, response) != 0 ||
        pq_deaddrop_offer_encode(offer, out) != 0 ||
        pq_deaddrop_response_encode(response, response_wire) != 0)
        return -1;
    memcpy(out + PQ_DEADDROP_OFFER_SIZE, response_wire, 1668);
    crypto_memzero(response_wire, sizeof(response_wire));
    return 0;
}

static int derive_root(const uint8_t local_private[32],
                       const uint8_t local_public[32],
                       const uint8_t peer_public[32],
                       const uint8_t mlkem_shared[32],
                       const pq_deaddrop_offer_t *offer,
                       const pq_deaddrop_response_t *response,
                       uint8_t root_out[32], uint8_t pair_seed_out[4])
{
    uint8_t raw[32];
    uint8_t transcript[PQ_BOOTSTRAP_TRANSCRIPT_LEN];
    uint8_t pair_hash[32];
    crypto_blake2b_ctx ctx;
    int result = -1;

    if (!root_out || !pair_seed_out)
        return -1;
    crypto_memzero(root_out, 32);
    crypto_memzero(pair_seed_out, 4);
    crypto_memzero(raw, sizeof(raw));
    crypto_memzero(transcript, sizeof(transcript));
    crypto_memzero(pair_hash, sizeof(pair_hash));

    if (!mlkem_shared ||
        raw_x25519(local_private, local_public, peer_public, raw) != 0 ||
        bootstrap_transcript(offer, response, transcript) != 0 ||
        pq_hybrid_bootstrap_root(raw, mlkem_shared, transcript,
                                 sizeof(transcript), root_out) != 0)
        goto cleanup;

    crypto_blake2b_keyed_init(&ctx, 32, root_out, 32);
    crypto_blake2b_update(&ctx, pair_seed_domain,
                          sizeof(pair_seed_domain) - 1U);
    crypto_blake2b_update(&ctx, response->transcript_fingerprint, 32);
    crypto_blake2b_final(&ctx, pair_hash);
    memcpy(pair_seed_out, pair_hash, 4);
    result = 0;

cleanup:
    if (result != 0) {
        crypto_memzero(root_out, 32);
        crypto_memzero(pair_seed_out, 4);
    }
    crypto_memzero(raw, sizeof(raw));
    crypto_memzero(transcript, sizeof(transcript));
    crypto_memzero(pair_hash, sizeof(pair_hash));
    crypto_memzero(&ctx, sizeof(ctx));
    return result;
}

void pq_deaddrop_server_secrets_wipe(pq_deaddrop_server_secrets_t *secrets)
{
    if (!secrets)
        return;
    crypto_memzero(secrets, sizeof(*secrets));
    (void)crypto_munlock(secrets, sizeof(*secrets));
}

int pq_deaddrop_server_offer_generate(
    const uint8_t id[DEADDROP_ID_LEN], uint16_t port, uint32_t required_caps,
    pq_deaddrop_offer_t *offer_out,
    pq_deaddrop_server_secrets_t *secrets_out)
{
    pq_deaddrop_offer_t offer;
    int result = -1;

    if (offer_out)
        memset(offer_out, 0, sizeof(*offer_out));
    if (secrets_out)
        crypto_memzero(secrets_out, sizeof(*secrets_out));
    memset(&offer, 0, sizeof(offer));
    if (!id || !offer_out || !secrets_out || !deaddrop_id_valid(id) ||
        port == 0 ||
        (required_caps & UNMOOR_CAP_EPOCH_REKEY_D28_V1) == 0 ||
        (required_caps & UNMOOR_CAP_PQ_HYBRID_D45_V1) == 0)
        return -1;

    (void)crypto_mlock(secrets_out, sizeof(*secrets_out));
    crypto_mark_dontdump(secrets_out, sizeof(*secrets_out));
    memcpy(offer.id, id, DEADDROP_ID_LEN);
    offer.port = port;
    offer.required_caps = required_caps;
    if (epoch_crypto_keypair_generate(secrets_out->x25519_private,
                                      offer.server_x25519) != 0 ||
        pq_mlkem_keypair(offer.mlkem_public,
                         secrets_out->mlkem_private) != 0 ||
        pq_deaddrop_offer_seal(&offer) != 0)
        goto cleanup;
    *offer_out = offer;
    result = 0;

cleanup:
    crypto_memzero(&offer, sizeof(offer));
    if (result != 0) {
        memset(offer_out, 0, sizeof(*offer_out));
        pq_deaddrop_server_secrets_wipe(secrets_out);
    }
    return result;
}

int pq_deaddrop_client_accept(const pq_deaddrop_offer_t *offer,
                              pq_deaddrop_response_t *response_out,
                              uint8_t root_out[32],
                              uint8_t pair_seed_out[4])
{
    uint8_t client_private[32];
    uint8_t mlkem_shared[32];
    pq_deaddrop_response_t response;
    int result = -1;

    if (response_out)
        memset(response_out, 0, sizeof(*response_out));
    if (root_out)
        crypto_memzero(root_out, 32);
    if (pair_seed_out)
        crypto_memzero(pair_seed_out, 4);
    crypto_memzero(client_private, sizeof(client_private));
    crypto_memzero(mlkem_shared, sizeof(mlkem_shared));
    memset(&response, 0, sizeof(response));
    if (!offer || !response_out || !root_out || !pair_seed_out)
        return -1;

    (void)crypto_mlock(client_private, sizeof(client_private));
    (void)crypto_mlock(mlkem_shared, sizeof(mlkem_shared));
    crypto_mark_dontdump(client_private, sizeof(client_private));
    crypto_mark_dontdump(mlkem_shared, sizeof(mlkem_shared));
    if (pq_deaddrop_offer_verify(offer) != 0 ||
        !epoch_crypto_public_key_is_canonical(offer->server_x25519) ||
        pq_mlkem_public_key_valid(offer->mlkem_public) != 1 ||
        epoch_crypto_keypair_generate(client_private,
                                      response.client_x25519) != 0 ||
        pq_mlkem_encapsulate(response.mlkem_ciphertext, mlkem_shared,
                             offer->mlkem_public) != 0 ||
        pq_deaddrop_response_seal(offer, &response) != 0 ||
        derive_root(client_private, response.client_x25519,
                    offer->server_x25519, mlkem_shared, offer, &response,
                    root_out, pair_seed_out) != 0)
        goto cleanup;
    *response_out = response;
    result = 0;

cleanup:
    crypto_memzero(client_private, sizeof(client_private));
    (void)crypto_munlock(client_private, sizeof(client_private));
    crypto_memzero(mlkem_shared, sizeof(mlkem_shared));
    (void)crypto_munlock(mlkem_shared, sizeof(mlkem_shared));
    crypto_memzero(&response, sizeof(response));
    if (result != 0) {
        memset(response_out, 0, sizeof(*response_out));
        crypto_memzero(root_out, 32);
        crypto_memzero(pair_seed_out, 4);
    }
    return result;
}

int pq_deaddrop_server_accept(
    pq_deaddrop_server_secrets_t *secrets,
    const pq_deaddrop_offer_t *offer,
    const pq_deaddrop_response_t *response,
    uint8_t root_out[32], uint8_t pair_seed_out[4])
{
    uint8_t mlkem_shared[32];
    int result = -1;

    if (root_out)
        crypto_memzero(root_out, 32);
    if (pair_seed_out)
        crypto_memzero(pair_seed_out, 4);
    crypto_memzero(mlkem_shared, sizeof(mlkem_shared));
    (void)crypto_mlock(mlkem_shared, sizeof(mlkem_shared));
    crypto_mark_dontdump(mlkem_shared, sizeof(mlkem_shared));
    if (!secrets || !offer || !response || !root_out || !pair_seed_out ||
        pq_deaddrop_offer_verify(offer) != 0 ||
        pq_deaddrop_response_verify(offer, response) != 0 ||
        !epoch_crypto_public_key_is_canonical(response->client_x25519) ||
        equal32(offer->server_x25519, response->client_x25519) ||
        pq_mlkem_decapsulate(mlkem_shared, response->mlkem_ciphertext,
                             secrets->mlkem_private) != 0 ||
        derive_root(secrets->x25519_private, offer->server_x25519,
                    response->client_x25519, mlkem_shared, offer, response,
                    root_out, pair_seed_out) != 0)
        goto cleanup;
    result = 0;

cleanup:
    crypto_memzero(mlkem_shared, sizeof(mlkem_shared));
    (void)crypto_munlock(mlkem_shared, sizeof(mlkem_shared));
    pq_deaddrop_server_secrets_wipe(secrets);
    if (result != 0) {
        if (root_out)
            crypto_memzero(root_out, 32);
        if (pair_seed_out)
            crypto_memzero(pair_seed_out, 4);
    }
    return result;
}
