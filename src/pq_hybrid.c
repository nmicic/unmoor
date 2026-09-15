/*
 * pq_hybrid.c — pq-hybrid root and epoch-chain combiner
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */

#include "pq_hybrid.h"

#include <string.h>

#include "crypto.h"
#include "monocypher.h"

static const uint8_t bootstrap_domain[] =
    "unmoor-pq-bootstrap-root-v1";
static const uint8_t rekey_fresh_domain[] =
    "unmoor-pq-rekey-fresh-v1";
static const uint8_t rekey_chain_domain[] =
    "unmoor-pq-rekey-chain-v1";

static void build_ikm(uint8_t ikm[64], const uint8_t x25519_shared[32],
                      const uint8_t mlkem_shared[32])
{
    memcpy(ikm, x25519_shared, 32);
    memcpy(ikm + 32, mlkem_shared, 32);
}

static void keyed_hash_parts(uint8_t out[32], const uint8_t *key,
                             size_t key_len, const uint8_t *domain,
                             size_t domain_len, const uint8_t *first,
                             size_t first_len, const uint8_t *second,
                             size_t second_len)
{
    crypto_blake2b_ctx ctx;
    crypto_blake2b_keyed_init(&ctx, 32, key, key_len);
    crypto_blake2b_update(&ctx, domain, domain_len);
    if (first_len != 0)
        crypto_blake2b_update(&ctx, first, first_len);
    if (second_len != 0)
        crypto_blake2b_update(&ctx, second, second_len);
    crypto_blake2b_final(&ctx, out);
    crypto_memzero(&ctx, sizeof(ctx));
}

int pq_hybrid_bootstrap_root(const uint8_t x25519_shared[32],
                             const uint8_t mlkem_shared[32],
                             const uint8_t *transcript,
                             size_t transcript_len,
                             uint8_t root_out[32])
{
    uint8_t ikm[64];

    if (!root_out)
        return -1;
    memset(root_out, 0, 32);
    if (!x25519_shared || !mlkem_shared || !transcript ||
        transcript_len == 0)
        return -1;

    build_ikm(ikm, x25519_shared, mlkem_shared);
    keyed_hash_parts(root_out, ikm, sizeof(ikm), bootstrap_domain,
                     sizeof(bootstrap_domain) - 1U, transcript,
                     transcript_len, NULL, 0);
    crypto_memzero(ikm, sizeof(ikm));
    return 0;
}

int pq_hybrid_rekey_combine(const uint8_t current_traffic_key[32],
                            const uint8_t x25519_shared[32],
                            const uint8_t mlkem_shared[32],
                            const uint8_t *transcript,
                            size_t transcript_len,
                            uint8_t combined_out[32])
{
    uint8_t ikm[64];
    uint8_t fresh[32];
    uint8_t chain[32];

    if (!combined_out)
        return -1;
    memset(combined_out, 0, 32);
    if (!current_traffic_key || !x25519_shared || !mlkem_shared ||
        !transcript || transcript_len == 0)
        return -1;

    build_ikm(ikm, x25519_shared, mlkem_shared);
    keyed_hash_parts(fresh, ikm, sizeof(ikm), rekey_fresh_domain,
                     sizeof(rekey_fresh_domain) - 1U,
                     current_traffic_key, 32, transcript, transcript_len);
    keyed_hash_parts(chain, current_traffic_key, 32, rekey_chain_domain,
                     sizeof(rekey_chain_domain) - 1U, ikm, sizeof(ikm),
                     transcript, transcript_len);
    for (size_t i = 0; i < 32; i++)
        combined_out[i] = (uint8_t)(fresh[i] ^ chain[i]);

    crypto_memzero(ikm, sizeof(ikm));
    crypto_memzero(fresh, sizeof(fresh));
    crypto_memzero(chain, sizeof(chain));
    return 0;
}
