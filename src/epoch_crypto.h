/*
 * epoch_crypto.h — epoch-rekey public bootstrap and epoch-rekey crypto helpers
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef UNMOOR_EPOCH_CRYPTO_H
#define UNMOOR_EPOCH_CRYPTO_H

#define _POSIX_C_SOURCE 200809L

#include <stddef.h>
#include <stdint.h>

#define EPOCH_CRYPTO_KEY_LEN               32U
#define EPOCH_CRYPTO_DROP_ID_LEN           16U
#define EPOCH_CRYPTO_PAIR_ID_LEN            4U
#define EPOCH_CRYPTO_FINGERPRINT_LEN       32U
#define EPOCH_CRYPTO_FINGERPRINT_TEXT_LEN  71U
#define EPOCH_CRYPTO_FINGERPRINT_TEXT_BUFSZ \
    (EPOCH_CRYPTO_FINGERPRINT_TEXT_LEN + 1U)

typedef enum {
    EPOCH_CRYPTO_ROLE_CLIENT = 0,
    EPOCH_CRYPTO_ROLE_SERVER = 1,
} epoch_crypto_role_t;

typedef struct {
    uint8_t transcript_hash[EPOCH_CRYPTO_FINGERPRINT_LEN];
    uint8_t traffic_key[EPOCH_CRYPTO_KEY_LEN];
    uint8_t confirm_key[EPOCH_CRYPTO_KEY_LEN];
    uint8_t epoch_fingerprint[EPOCH_CRYPTO_FINGERPRINT_LEN];
} epoch_crypto_rekey_material_t;

/* Generate a fresh X25519 scalar and its canonical public u-coordinate.
 * The caller owns private_key after success and is responsible for wiping it. */
int epoch_crypto_keypair_generate(
    uint8_t private_key[EPOCH_CRYPTO_KEY_LEN],
    uint8_t public_key[EPOCH_CRYPTO_KEY_LEN]);

/* Return 1 only for the canonical little-endian encoding 0 <= u < 2^255-19
 * with the high bit clear. This is an encoding check, not a group check. */
int epoch_crypto_public_key_is_canonical(
    const uint8_t public_key[EPOCH_CRYPTO_KEY_LEN]);

/* Public BLAKE2b-256 fingerprints. bootstrap_policy is encoded uint32 LE and
 * udp_port is encoded uint16 LE. Port zero is not an announced UDP endpoint
 * and is rejected. All public keys must be canonical; the full transcript
 * also rejects client_public == server_public. */
int epoch_crypto_offer_fingerprint(
    const uint8_t drop_id[EPOCH_CRYPTO_DROP_ID_LEN],
    uint16_t udp_port,
    uint32_t bootstrap_policy,
    const uint8_t server_public[EPOCH_CRYPTO_KEY_LEN],
    uint8_t fingerprint_out[EPOCH_CRYPTO_FINGERPRINT_LEN]);

int epoch_crypto_transcript_fingerprint(
    const uint8_t drop_id[EPOCH_CRYPTO_DROP_ID_LEN],
    uint16_t udp_port,
    uint32_t bootstrap_policy,
    const uint8_t client_public[EPOCH_CRYPTO_KEY_LEN],
    const uint8_t server_public[EPOCH_CRYPTO_KEY_LEN],
    uint8_t fingerprint_out[EPOCH_CRYPTO_FINGERPRINT_LEN]);

/* Canonical text is exactly "b2b256:" plus 64 lowercase hex digits. */
int epoch_crypto_fingerprint_encode(
    const uint8_t fingerprint[EPOCH_CRYPTO_FINGERPRINT_LEN],
    char text_out[EPOCH_CRYPTO_FINGERPRINT_TEXT_BUFSZ]);
int epoch_crypto_fingerprint_decode(
    const char *text,
    size_t text_len,
    uint8_t fingerprint_out[EPOCH_CRYPTO_FINGERPRINT_LEN]);
/* Returns 0 on exact decoded equality, -1 on malformed text or mismatch. */
int epoch_crypto_fingerprint_verify(
    const char *text,
    size_t text_len,
    const uint8_t expected[EPOCH_CRYPTO_FINGERPRINT_LEN]);

/* Derive the epoch-rekey bootstrap root and session pair seed. The function derives
 * the declared local role public key from local_private and compares it in
 * constant time before DH. It validates both role public keys, rejects equal
 * role keys, and rejects an all-zero X25519 result in constant time.
 *
 * local_private remains caller-owned and is never wiped here. Internal raw DH
 * and intermediate values are always wiped. Outputs must not alias inputs. */
int epoch_crypto_bootstrap_derive(
    const uint8_t local_private[EPOCH_CRYPTO_KEY_LEN],
    epoch_crypto_role_t local_role,
    const uint8_t drop_id[EPOCH_CRYPTO_DROP_ID_LEN],
    uint16_t udp_port,
    uint32_t bootstrap_policy,
    const uint8_t client_public[EPOCH_CRYPTO_KEY_LEN],
    const uint8_t server_public[EPOCH_CRYPTO_KEY_LEN],
    uint8_t root_out[EPOCH_CRYPTO_KEY_LEN],
    uint8_t pair_seed_out[EPOCH_CRYPTO_PAIR_ID_LEN]);

/* Immutable context for all later epoch transcripts. HELLO and ACK are the
 * exact canonical capability-negotiation plaintexts in client/server order. */
int epoch_crypto_session_context(
    const uint8_t client_hello[32],
    const uint8_t server_ack[32],
    uint32_t selected_caps,
    const uint8_t pair_seed[EPOCH_CRYPTO_PAIR_ID_LEN],
    uint8_t context_out[EPOCH_CRYPTO_FINGERPRINT_LEN]);

/* Derive one adjacent epoch. to_epoch must equal from_epoch + 1 without
 * uint32 wrap. The role/public validation and ownership rules are identical
 * to epoch_crypto_bootstrap_derive. On failure, out is zeroed. */
int epoch_crypto_rekey_derive(
    const uint8_t current_traffic_key[EPOCH_CRYPTO_KEY_LEN],
    const uint8_t local_private[EPOCH_CRYPTO_KEY_LEN],
    epoch_crypto_role_t local_role,
    const uint8_t session_context[EPOCH_CRYPTO_FINGERPRINT_LEN],
    uint32_t selected_caps,
    uint32_t from_epoch,
    uint32_t to_epoch,
    const uint8_t rekey_id[EPOCH_CRYPTO_DROP_ID_LEN],
    const uint8_t client_public[EPOCH_CRYPTO_KEY_LEN],
    const uint8_t server_public[EPOCH_CRYPTO_KEY_LEN],
    epoch_crypto_rekey_material_t *out);

/* pair_id(epoch) = pair_seed XOR little_endian32(epoch). */
int epoch_crypto_pair_id(
    const uint8_t pair_seed[EPOCH_CRYPTO_PAIR_ID_LEN],
    uint32_t epoch,
    uint8_t pair_id_out[EPOCH_CRYPTO_PAIR_ID_LEN]);

#endif /* UNMOOR_EPOCH_CRYPTO_H */
