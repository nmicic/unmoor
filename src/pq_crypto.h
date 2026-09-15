/*
 * pq_crypto.h — fixed ML-KEM-1024 component boundary for pq-hybrid
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef UNMOOR_PQ_CRYPTO_H
#define UNMOOR_PQ_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define PQ_MLKEM_PUBLIC_LEN 1568U
#define PQ_MLKEM_PRIVATE_LEN 3168U
#define PQ_MLKEM_CIPHERTEXT_LEN 1568U
#define PQ_MLKEM_SECRET_LEN 32U
#define PQ_MLKEM_KEYGEN_COINS_LEN 64U
#define PQ_MLKEM_ENCAP_COINS_LEN 32U

int pq_mlkem_keypair(uint8_t public_key[PQ_MLKEM_PUBLIC_LEN],
                     uint8_t private_key[PQ_MLKEM_PRIVATE_LEN]);
int pq_mlkem_encapsulate(
    uint8_t ciphertext[PQ_MLKEM_CIPHERTEXT_LEN],
    uint8_t shared_secret[PQ_MLKEM_SECRET_LEN],
    const uint8_t public_key[PQ_MLKEM_PUBLIC_LEN]);
int pq_mlkem_decapsulate(
    uint8_t shared_secret[PQ_MLKEM_SECRET_LEN],
    const uint8_t ciphertext[PQ_MLKEM_CIPHERTEXT_LEN],
    const uint8_t private_key[PQ_MLKEM_PRIVATE_LEN]);
/* Public modulus/encoding check only. Returns 1 for a valid encapsulation
 * key, 0 for an invalid key, and -1 for a null argument. */
int pq_mlkem_public_key_valid(
    const uint8_t public_key[PQ_MLKEM_PUBLIC_LEN]);

/* Deterministic APIs exist only for public-input KATs. Caller-owned coins are
 * not production session secrets; all derived private/shared output remains
 * runtime-only and must be wiped by the caller. */
int pq_mlkem_keypair_deterministic(
    uint8_t public_key[PQ_MLKEM_PUBLIC_LEN],
    uint8_t private_key[PQ_MLKEM_PRIVATE_LEN],
    const uint8_t coins[PQ_MLKEM_KEYGEN_COINS_LEN]);
int pq_mlkem_encapsulate_deterministic(
    uint8_t ciphertext[PQ_MLKEM_CIPHERTEXT_LEN],
    uint8_t shared_secret[PQ_MLKEM_SECRET_LEN],
    const uint8_t public_key[PQ_MLKEM_PUBLIC_LEN],
    const uint8_t coins[PQ_MLKEM_ENCAP_COINS_LEN]);

#endif /* UNMOOR_PQ_CRYPTO_H */
