/*
 * pq_crypto_test.c — ML-KEM-1024 component tests for pq-hybrid
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * The ACVP fixture contains only public deterministic coins and the digest of
 * a public encapsulation key.  Decapsulation keys and shared secrets are
 * created at runtime, never printed, and wiped before return.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "crypto.h"
#include "monocypher.h"
#include "pq_crypto.h"

static int passed;
static int failed;

#define CHECK(name, condition) do {                                      \
    if (condition) { printf("PASS %s\n", name); passed++; }             \
    else { printf("FAIL %s\n", name); failed++; }                       \
} while (0)

static int bytes_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t difference = 0;
    for (size_t i = 0; i < len; i++)
        difference |= (uint8_t)(a[i] ^ b[i]);
    return difference == 0;
}

static void wipe_component_state(uint8_t public_key[PQ_MLKEM_PUBLIC_LEN],
                                 uint8_t private_key[PQ_MLKEM_PRIVATE_LEN],
                                 uint8_t ciphertext[PQ_MLKEM_CIPHERTEXT_LEN],
                                 uint8_t first_secret[PQ_MLKEM_SECRET_LEN],
                                 uint8_t second_secret[PQ_MLKEM_SECRET_LEN])
{
    crypto_memzero(public_key, PQ_MLKEM_PUBLIC_LEN);
    crypto_memzero(private_key, PQ_MLKEM_PRIVATE_LEN);
    crypto_memzero(ciphertext, PQ_MLKEM_CIPHERTEXT_LEN);
    crypto_memzero(first_secret, PQ_MLKEM_SECRET_LEN);
    crypto_memzero(second_secret, PQ_MLKEM_SECRET_LEN);
}

static void test_acvp_keygen(void)
{
    /* ACVP ML-KEM-keyGen-FIPS203, ML-KEM-1024, tgId 3, tcId 51.
     * ML-KEM.KeyGen_Internal consumes d || z. */
    static const uint8_t coins[PQ_MLKEM_KEYGEN_COINS_LEN] = {
        0x2b, 0x53, 0x30, 0xc4, 0xf2, 0x3b, 0xfd, 0xfd,
        0x5c, 0x31, 0xf0, 0x50, 0xba, 0x3b, 0x38, 0x23,
        0x53, 0x24, 0xbf, 0x03, 0x23, 0x72, 0xfc, 0x12,
        0xd0, 0x4d, 0xd0, 0x89, 0x20, 0xf0, 0xbd, 0x59,
        0x0a, 0x06, 0x4d, 0x6c, 0x06, 0xce, 0xab, 0x73,
        0xe5, 0x9c, 0xfc, 0xa9, 0xff, 0x64, 0x02, 0x25,
        0x5a, 0x32, 0x6a, 0xef, 0x1e, 0x9c, 0xb6, 0x78,
        0xbf, 0x36, 0x92, 0x9d, 0xaf, 0xe2, 0x9a, 0x58
    };
    static const uint8_t expected_public_digest[32] = {
        0x2c, 0x9e, 0x13, 0x18, 0x62, 0x87, 0xd8, 0x1a,
        0x1f, 0x69, 0x31, 0xda, 0x89, 0x6c, 0xa9, 0x19,
        0xec, 0x05, 0x49, 0x44, 0xdb, 0x48, 0x53, 0x3e,
        0xdf, 0xcf, 0xcb, 0x93, 0x2b, 0x4c, 0x60, 0xac
    };
    uint8_t public_key[PQ_MLKEM_PUBLIC_LEN];
    uint8_t private_key[PQ_MLKEM_PRIVATE_LEN];
    uint8_t digest[32];

    memset(public_key, 0, sizeof(public_key));
    memset(private_key, 0, sizeof(private_key));
    memset(digest, 0, sizeof(digest));

    CHECK("ACVP keygen tcId 51 executes",
          pq_mlkem_keypair_deterministic(public_key, private_key, coins) == 0);
    crypto_blake2b(digest, sizeof(digest), public_key, sizeof(public_key));
    CHECK("ACVP keygen tcId 51 public key matches",
          bytes_equal(digest, expected_public_digest, sizeof(digest)));

    crypto_memzero(public_key, sizeof(public_key));
    crypto_memzero(private_key, sizeof(private_key));
    crypto_memzero(digest, sizeof(digest));
}

static void test_deterministic_roundtrip(void)
{
    uint8_t key_coins[PQ_MLKEM_KEYGEN_COINS_LEN];
    uint8_t encaps_coins[PQ_MLKEM_ENCAP_COINS_LEN];
    uint8_t public_key[PQ_MLKEM_PUBLIC_LEN];
    uint8_t private_key[PQ_MLKEM_PRIVATE_LEN];
    uint8_t ciphertext[PQ_MLKEM_CIPHERTEXT_LEN];
    uint8_t encaps_secret[PQ_MLKEM_SECRET_LEN];
    uint8_t decaps_secret[PQ_MLKEM_SECRET_LEN];

    for (size_t i = 0; i < sizeof(key_coins); i++)
        key_coins[i] = (uint8_t)i;
    for (size_t i = 0; i < sizeof(encaps_coins); i++)
        encaps_coins[i] = (uint8_t)(0xa0U + i);

    CHECK("deterministic keypair succeeds",
          pq_mlkem_keypair_deterministic(public_key, private_key,
                                           key_coins) == 0);
    CHECK("generated encapsulation key passes public check",
          pq_mlkem_public_key_valid(public_key) == 1);
    CHECK("deterministic encapsulation succeeds",
          pq_mlkem_encapsulate_deterministic(ciphertext, encaps_secret,
                                               public_key,
                                               encaps_coins) == 0);
    CHECK("deterministic decapsulation succeeds",
          pq_mlkem_decapsulate(decaps_secret, ciphertext, private_key) == 0);
    CHECK("deterministic shared secrets agree",
          bytes_equal(encaps_secret, decaps_secret,
                      PQ_MLKEM_SECRET_LEN));

    ciphertext[0] ^= UINT8_C(0x01);
    CHECK("modified ciphertext still takes implicit-rejection path",
          pq_mlkem_decapsulate(decaps_secret, ciphertext, private_key) == 0);
    CHECK("implicit rejection changes the shared secret",
          !bytes_equal(encaps_secret, decaps_secret,
                       PQ_MLKEM_SECRET_LEN));

    crypto_memzero(key_coins, sizeof(key_coins));
    crypto_memzero(encaps_coins, sizeof(encaps_coins));
    wipe_component_state(public_key, private_key, ciphertext,
                         encaps_secret, decaps_secret);
}

static void test_randomized_roundtrip(void)
{
    uint8_t public_key[PQ_MLKEM_PUBLIC_LEN];
    uint8_t private_key[PQ_MLKEM_PRIVATE_LEN];
    uint8_t ciphertext[PQ_MLKEM_CIPHERTEXT_LEN];
    uint8_t encaps_secret[PQ_MLKEM_SECRET_LEN];
    uint8_t decaps_secret[PQ_MLKEM_SECRET_LEN];

    CHECK("randomized keypair succeeds",
          pq_mlkem_keypair(public_key, private_key) == 0);
    CHECK("randomized encapsulation succeeds",
          pq_mlkem_encapsulate(ciphertext, encaps_secret, public_key) == 0);
    CHECK("randomized decapsulation succeeds",
          pq_mlkem_decapsulate(decaps_secret, ciphertext, private_key) == 0);
    CHECK("randomized shared secrets agree",
          bytes_equal(encaps_secret, decaps_secret,
                      PQ_MLKEM_SECRET_LEN));

    wipe_component_state(public_key, private_key, ciphertext,
                         encaps_secret, decaps_secret);
}

static void test_input_rejection(void)
{
    uint8_t invalid_public[PQ_MLKEM_PUBLIC_LEN];
    uint8_t ciphertext[PQ_MLKEM_CIPHERTEXT_LEN];
    uint8_t shared_secret[PQ_MLKEM_SECRET_LEN];
    uint8_t coins[PQ_MLKEM_ENCAP_COINS_LEN] = { 0 };

    memset(invalid_public, 0xff, sizeof(invalid_public));
    CHECK("noncanonical public key fails public check",
          pq_mlkem_public_key_valid(invalid_public) == 0);
    CHECK("noncanonical public key is rejected",
          pq_mlkem_encapsulate_deterministic(ciphertext, shared_secret,
                                               invalid_public, coins) != 0);
    CHECK("keypair rejects null public output",
          pq_mlkem_keypair(NULL, (uint8_t[PQ_MLKEM_PRIVATE_LEN]){ 0 }) != 0);
    CHECK("encapsulation rejects null public input",
          pq_mlkem_encapsulate(ciphertext, shared_secret, NULL) != 0);
    CHECK("decapsulation rejects null private input",
          pq_mlkem_decapsulate(shared_secret, ciphertext, NULL) != 0);
    CHECK("public-key check rejects null input",
          pq_mlkem_public_key_valid(NULL) < 0);

    crypto_memzero(invalid_public, sizeof(invalid_public));
    crypto_memzero(ciphertext, sizeof(ciphertext));
    crypto_memzero(shared_secret, sizeof(shared_secret));
    crypto_memzero(coins, sizeof(coins));
}

static uint64_t monotonic_ns(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0U;
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) +
           (uint64_t)now.tv_nsec;
}

static int benchmark_components(void)
{
    enum { ITERATIONS = 100 };
    uint8_t public_key[PQ_MLKEM_PUBLIC_LEN];
    uint8_t private_key[PQ_MLKEM_PRIVATE_LEN];
    uint8_t ciphertext[PQ_MLKEM_CIPHERTEXT_LEN];
    uint8_t encaps_secret[PQ_MLKEM_SECRET_LEN];
    uint8_t decaps_secret[PQ_MLKEM_SECRET_LEN];
    uint64_t start;
    uint64_t keygen_ns;
    uint64_t encaps_ns;
    uint64_t decaps_ns;
    int result = 1;

    start = monotonic_ns();
    if (start == 0U)
        goto out;
    for (unsigned int i = 0U; i < ITERATIONS; i++)
        if (pq_mlkem_keypair(public_key, private_key) != 0)
            goto out;
    keygen_ns = monotonic_ns() - start;
    start = monotonic_ns();
    if (start == 0U)
        goto out;
    for (unsigned int i = 0U; i < ITERATIONS; i++)
        if (pq_mlkem_encapsulate(ciphertext, encaps_secret,
                                 public_key) != 0)
            goto out;
    encaps_ns = monotonic_ns() - start;
    start = monotonic_ns();
    if (start == 0U)
        goto out;
    for (unsigned int i = 0U; i < ITERATIONS; i++)
        if (pq_mlkem_decapsulate(decaps_secret, ciphertext,
                                 private_key) != 0)
            goto out;
    decaps_ns = monotonic_ns() - start;
    if (!bytes_equal(encaps_secret, decaps_secret,
                     PQ_MLKEM_SECRET_LEN))
        goto out;
    printf("pq_crypto_bench iterations=%u keygen-us=%llu "
           "encaps-us=%llu decaps-us=%llu\n",
           ITERATIONS,
           (unsigned long long)(keygen_ns / ITERATIONS / 1000U),
           (unsigned long long)(encaps_ns / ITERATIONS / 1000U),
           (unsigned long long)(decaps_ns / ITERATIONS / 1000U));
    result = 0;
out:
    wipe_component_state(public_key, private_key, ciphertext,
                         encaps_secret, decaps_secret);
    return result;
}

int main(int argc, char *argv[])
{
    if (argc == 2 && strcmp(argv[1], "--benchmark") == 0)
        return benchmark_components();
    if (argc != 1) {
        fprintf(stderr, "usage: pq_crypto_test [--benchmark]\n");
        return 2;
    }
    test_acvp_keygen();
    test_deterministic_roundtrip();
    test_randomized_roundtrip();
    test_input_rejection();
    printf("pq_crypto_test: %d PASS, %d FAIL\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
