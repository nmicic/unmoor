/*
 * crypto.h — crypto wrappers
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 * Provides:
 *   KDF:     crypto_derive_session_key, crypto_derive_hello_key (BLAKE2b)
 *   AEAD:    crypto_encrypt, crypto_decrypt (XChaCha20-Poly1305 via monocypher)
 *   Util:    crypto_memzero, crypto_mlock, crypto_random_bytes
 */
#ifndef UNMOOR_CRYPTO_H
#define UNMOOR_CRYPTO_H

#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stddef.h>

/* -------------------------------------------------------------------------
 * Key derivation
 * ---------------------------------------------------------------------- */

/*
 * Derive session key from PSK + nonces.
 * session_key = BLAKE2b_keyed(key=PSK, msg="unmoor-v1"||nonce_a||nonce_b)
 * Returns 0 on success, -1 on error.
 */
int crypto_derive_session_key(const uint8_t psk[32],
                              const uint8_t nonce_a[16],
                              const uint8_t nonce_b[16],
                              uint8_t session_key_out[32]);

/* NEG1 transcript-bound session KDF. The two canonical 32-byte handshake
 * plaintexts and selected capability mask are authenticated by the READY
 * exchange under the resulting key. The legacy KDF above stays unchanged. */
int crypto_derive_negotiated_session_key(const uint8_t psk[32],
                                         const uint8_t client_hello[32],
                                         const uint8_t server_ack[32],
                                         uint32_t selected_caps,
                                         uint8_t session_key_out[32]);

/*
 * Derive pre-session hello key from PSK.
 * hello_key = BLAKE2b_keyed(key=PSK, msg="unmoor-hello")
 * Returns 0 on success, -1 on error.
 */
int crypto_derive_hello_key(const uint8_t psk[32],
                            uint8_t hello_key_out[32]);

/*
 * Derive 4-byte PAIR_ID deterministically from PSK.
 * pair_id = BLAKE2b_keyed(key=PSK, msg="unmoor-pairid")[:4]
 * Domain-separated from session/hello key derivations.
 */
int crypto_derive_pair_id(const uint8_t psk[32],
                          uint8_t pair_id_out[4]);

/* -------------------------------------------------------------------------
 * AEAD wrappers
 *
 * Base AD = PAIR_ID(4) || SEQ(4) || CHAN(1) || TYPE(1) = 10 bytes.
 * Multi-fragment frames append the clear 16-byte fragment descriptor to this
 * base. CHAN always includes the authenticated FF/MF bits.
 *
 * Nonce construction (internal):
 *   nonce[0]     = direction byte
 *   nonce[1..4]  = SEQ as uint32_t little-endian
 *   nonce[5..23] = 0x00
 * ---------------------------------------------------------------------- */

/*
 * Encrypt plaintext into ciphertext (includes 16-byte appended tag).
 * ciphertext_out must be at least plaintext_len + 16 bytes.
 * Returns 0 on success, -1 on error.
 */
int crypto_encrypt(const uint8_t key[32],
                   uint32_t seq,
                   uint8_t direction,        /* 0x00=client→server, 0x01=server→client */
                   const uint8_t ad[10],
                   const uint8_t *plaintext, size_t plaintext_len,
                   uint8_t *ciphertext_out, size_t *ciphertext_len_out);

/*
 * Decrypt ciphertext. ciphertext_len must include the 16-byte tag.
 * Returns 0 on success, -1 on auth failure.
 */
int crypto_decrypt(const uint8_t key[32],
                   uint32_t seq,
                   uint8_t direction,
                   const uint8_t ad[10],
                   const uint8_t *ciphertext, size_t ciphertext_len,
                   uint8_t *plaintext_out, size_t *plaintext_len_out);

/* Variable-length AD variants used by authenticated fragment descriptors.
 * The legacy wrappers above remain the ten-byte base-header API. */
int crypto_encrypt_ad(const uint8_t key[32],
                      uint32_t seq, uint8_t direction,
                      const uint8_t *ad, size_t ad_len,
                      const uint8_t *plaintext, size_t plaintext_len,
                      uint8_t *ciphertext_out, size_t *ciphertext_len_out);

int crypto_decrypt_ad(const uint8_t key[32],
                      uint32_t seq, uint8_t direction,
                      const uint8_t *ad, size_t ad_len,
                      const uint8_t *ciphertext, size_t ciphertext_len,
                      uint8_t *plaintext_out, size_t *plaintext_len_out);

/* BLAKE2b-256 commitment repeated inside every encrypted fragment.  The
 * fixed-width metadata is encoded little-endian and domain-separated from
 * every KDF in this file. */
void crypto_fragment_hash(uint8_t out[32],
                          uint8_t direction, uint8_t channel, uint8_t type,
                          uint32_t message_id,
                          uint16_t fragment_count,
                          uint16_t total_length,
                          uint16_t fragment_stride,
                          const uint8_t *message, size_t message_len);

/*
 * Explicit-nonce AEAD variants — used by the CTRL_HELLO / CTRL_HELLO_ACK
 * handshake (hello-nonce) where the nonce is sampled
 * randomly per send and carried in cleartext in the frame body, not
 * derived from (direction, seq). Required to avoid Poly1305 one-time-key
 * reuse across sessions for keys that are deterministic from PSK alone
 * (hello_key). All other frames keep the (direction, seq) path above.
 *
 * nonce[24] is the full 24-byte XChaCha20 nonce, supplied by the caller.
 * AD layout is identical to crypto_encrypt above.
 */
int crypto_encrypt_with_nonce(const uint8_t key[32],
                              const uint8_t nonce[24],
                              const uint8_t ad[10],
                              const uint8_t *plaintext, size_t plaintext_len,
                              uint8_t *ciphertext_out, size_t *ciphertext_len_out);

int crypto_decrypt_with_nonce(const uint8_t key[32],
                              const uint8_t nonce[24],
                              const uint8_t ad[10],
                              const uint8_t *ciphertext, size_t ciphertext_len,
                              uint8_t *plaintext_out, size_t *plaintext_len_out);

/* -------------------------------------------------------------------------
 * Terminal state sync stream chain
 *
 * Running BLAKE2b-256 over one direction's PTY byte stream. Both ends absorb
 * every stream byte exactly once, in offset order, as their frontier (or
 * verified base) advances; equal finalized values authorize backlog pruning.
 * Divergence detector, not an attacker barrier (AEAD already covers that).
 *
 * Domain: "unmoor-sync-chain-v1" || direction, where direction is the wire
 * direction byte of the DATA stream (0x00 client→server, 0x01 server→client).
 * ---------------------------------------------------------------------- */

/* Opaque storage for a monocypher crypto_blake2b_ctx; crypto.c statically
 * asserts the fit. uint64_t members guarantee alignment. */
typedef struct { uint64_t opaque[32]; } crypto_sync_chain_t;

void crypto_sync_chain_init(crypto_sync_chain_t *c, uint8_t direction);
void crypto_sync_chain_absorb(crypto_sync_chain_t *c,
                              const uint8_t *data, size_t len);
/* Finalize a snapshot copy into out[32]; the running state is untouched. */
void crypto_sync_chain_value(const crypto_sync_chain_t *c, uint8_t out[32]);

/* -------------------------------------------------------------------------
 * Memory security
 * ---------------------------------------------------------------------- */

/* Zero a buffer in a way the compiler cannot optimize away (calls crypto_wipe). */
void crypto_memzero(void *buf, size_t len);

/* Lock a buffer into RAM (mlock). Returns 0 on success, -1 on failure (non-fatal). */
int crypto_mlock(void *buf, size_t len);

/* Unlock a previously crypto_mlock'd buffer. Returns 0 on success, -1 on failure. */
int crypto_munlock(void *buf, size_t len);

/* Fill buf with cryptographically random bytes via getrandom(). */
int crypto_random_bytes(void *buf, size_t len);

/* Constant-time exact comparison for fixed 32-byte authentication values.
 * Returns 0 on equality and -1 otherwise. */
int crypto_verify32_exact(const uint8_t left[32], const uint8_t right[32]);

/* Mark a buffer as excluded from core dumps (MADV_DONTDUMP on Linux).
 * No-op on platforms where MADV_DONTDUMP is unavailable. Non-fatal. */
void crypto_mark_dontdump(void *addr, size_t len);

#endif /* UNMOOR_CRYPTO_H */
