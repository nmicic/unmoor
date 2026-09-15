/*
 * pq_crypto.c — fixed ML-KEM-1024 component boundary for pq-hybrid
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#include "pq_crypto.h"

#include "vendor/mlkem-native/mlkem/mlkem_native.h"

_Static_assert(MLKEM1024_PUBLICKEYBYTES == PQ_MLKEM_PUBLIC_LEN,
               "ML-KEM public-key size mismatch");
_Static_assert(MLKEM1024_SECRETKEYBYTES == PQ_MLKEM_PRIVATE_LEN,
               "ML-KEM private-key size mismatch");
_Static_assert(MLKEM1024_CIPHERTEXTBYTES == PQ_MLKEM_CIPHERTEXT_LEN,
               "ML-KEM ciphertext size mismatch");
_Static_assert(MLKEM1024_BYTES == PQ_MLKEM_SECRET_LEN,
               "ML-KEM shared-secret size mismatch");

int pq_mlkem_keypair(uint8_t public_key[PQ_MLKEM_PUBLIC_LEN],
                     uint8_t private_key[PQ_MLKEM_PRIVATE_LEN])
{
    if (!public_key || !private_key)
        return -1;
    return UNMOOR_MLKEM1024_keypair(public_key, private_key) == 0 ? 0 : -1;
}

int pq_mlkem_encapsulate(
    uint8_t ciphertext[PQ_MLKEM_CIPHERTEXT_LEN],
    uint8_t shared_secret[PQ_MLKEM_SECRET_LEN],
    const uint8_t public_key[PQ_MLKEM_PUBLIC_LEN])
{
    if (!ciphertext || !shared_secret || !public_key)
        return -1;
    return UNMOOR_MLKEM1024_enc(ciphertext, shared_secret, public_key) == 0
        ? 0 : -1;
}

int pq_mlkem_decapsulate(
    uint8_t shared_secret[PQ_MLKEM_SECRET_LEN],
    const uint8_t ciphertext[PQ_MLKEM_CIPHERTEXT_LEN],
    const uint8_t private_key[PQ_MLKEM_PRIVATE_LEN])
{
    if (!shared_secret || !ciphertext || !private_key)
        return -1;
    return UNMOOR_MLKEM1024_dec(shared_secret, ciphertext, private_key) == 0
        ? 0 : -1;
}

int pq_mlkem_public_key_valid(
    const uint8_t public_key[PQ_MLKEM_PUBLIC_LEN])
{
    if (!public_key)
        return -1;
    return UNMOOR_MLKEM1024_check_pk(public_key) == 0 ? 1 : 0;
}

int pq_mlkem_keypair_deterministic(
    uint8_t public_key[PQ_MLKEM_PUBLIC_LEN],
    uint8_t private_key[PQ_MLKEM_PRIVATE_LEN],
    const uint8_t coins[PQ_MLKEM_KEYGEN_COINS_LEN])
{
    if (!public_key || !private_key || !coins)
        return -1;
    return UNMOOR_MLKEM1024_keypair_derand(public_key, private_key, coins) == 0
        ? 0 : -1;
}

int pq_mlkem_encapsulate_deterministic(
    uint8_t ciphertext[PQ_MLKEM_CIPHERTEXT_LEN],
    uint8_t shared_secret[PQ_MLKEM_SECRET_LEN],
    const uint8_t public_key[PQ_MLKEM_PUBLIC_LEN],
    const uint8_t coins[PQ_MLKEM_ENCAP_COINS_LEN])
{
    if (!ciphertext || !shared_secret || !public_key || !coins)
        return -1;
    return UNMOOR_MLKEM1024_enc_derand(
               ciphertext, shared_secret, public_key, coins) == 0 ? 0 : -1;
}
