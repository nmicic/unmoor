/*
 * crypto.c — BLAKE2b KDF + XChaCha20-Poly1305 AEAD wrappers
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#ifdef __APPLE__
#include <sys/random.h>   /* getentropy() */
#else
#include <sys/random.h>   /* getrandom() */
#endif

#include "monocypher.h"
#include "crypto.h"

/* -------------------------------------------------------------------------
 * Key derivation
 * ---------------------------------------------------------------------- */

int crypto_derive_session_key(const uint8_t psk[32],
                              const uint8_t nonce_a[16],
                              const uint8_t nonce_b[16],
                              uint8_t session_key_out[32])
{
    /* msg = "unmoor-v1" || nonce_a || nonce_b  (9 + 16 + 16 = 41 bytes) */
    uint8_t msg[41];
    memcpy(msg,      "unmoor-v1", 9);
    memcpy(msg + 9,  nonce_a, 16);
    memcpy(msg + 25, nonce_b, 16);
    crypto_blake2b_keyed(session_key_out, 32, psk, 32, msg, sizeof(msg));
    crypto_wipe(msg, sizeof(msg));
    return 0;
}

int crypto_derive_negotiated_session_key(const uint8_t psk[32],
                                         const uint8_t client_hello[32],
                                         const uint8_t server_ack[32],
                                         uint32_t selected_caps,
                                         uint8_t session_key_out[32])
{
    static const uint8_t domain[] = "unmoor-session-neg-v1";
    static const uint8_t client_label[] = "client-hello";
    static const uint8_t server_label[] = "server-ack";
    uint8_t selected_le[4];
    selected_le[0] = (uint8_t)(selected_caps & 0xffU);
    selected_le[1] = (uint8_t)((selected_caps >> 8) & 0xffU);
    selected_le[2] = (uint8_t)((selected_caps >> 16) & 0xffU);
    selected_le[3] = (uint8_t)(selected_caps >> 24);

    crypto_blake2b_ctx ctx;
    crypto_blake2b_keyed_init(&ctx, 32, psk, 32);
    crypto_blake2b_update(&ctx, domain, sizeof(domain) - 1);
    crypto_blake2b_update(&ctx, client_label, sizeof(client_label) - 1);
    crypto_blake2b_update(&ctx, client_hello, 32);
    crypto_blake2b_update(&ctx, server_label, sizeof(server_label) - 1);
    crypto_blake2b_update(&ctx, server_ack, 32);
    crypto_blake2b_update(&ctx, selected_le, sizeof(selected_le));
    crypto_blake2b_final(&ctx, session_key_out);
    crypto_wipe(&ctx, sizeof(ctx));
    crypto_wipe(selected_le, sizeof(selected_le));
    return 0;
}

int crypto_derive_hello_key(const uint8_t psk[32],
                            uint8_t hello_key_out[32])
{
    crypto_blake2b_keyed(hello_key_out, 32, psk, 32,
                         (const uint8_t *)"unmoor-hello", 12);
    return 0;
}

int crypto_derive_pair_id(const uint8_t psk[32],
                          uint8_t pair_id_out[4])
{
    uint8_t hash[32];
    crypto_blake2b_keyed(hash, 32, psk, 32,
                         (const uint8_t *)"unmoor-pairid", 13);
    memcpy(pair_id_out, hash, 4);
    crypto_wipe(hash, sizeof(hash));
    return 0;
}

/* -------------------------------------------------------------------------
 * AEAD helpers
 * ---------------------------------------------------------------------- */

static void build_nonce(uint8_t direction, uint32_t seq, uint8_t nonce[24])
{
    memset(nonce, 0, 24);
    nonce[0] = direction;
    nonce[1] = (uint8_t)(seq        & 0xFF);
    nonce[2] = (uint8_t)((seq >>  8) & 0xFF);
    nonce[3] = (uint8_t)((seq >> 16) & 0xFF);
    nonce[4] = (uint8_t)((seq >> 24) & 0xFF);
}

/* An all-zero key is never a live key here: every AEAD key is KDF output
 * or a wiped buffer. Refusing it makes an upstream selection mistake fail
 * closed instead of authenticating anything built with the zero key. */
static int key_is_zero(const uint8_t key[32])
{
    uint8_t acc = 0;
    for (size_t i = 0; i < 32; i++)
        acc |= key[i];
    return acc == 0;
}

/* -------------------------------------------------------------------------
 * AEAD encrypt
 * Wire format: ciphertext_out = cipher_text || mac[16]
 * ---------------------------------------------------------------------- */

int crypto_encrypt_ad(const uint8_t key[32],
                      uint32_t seq,
                      uint8_t direction,
                      const uint8_t *ad, size_t ad_len,
                      const uint8_t *plaintext, size_t plaintext_len,
                      uint8_t *ciphertext_out, size_t *ciphertext_len_out)
{
    if (!key || (!ad && ad_len != 0) ||
        (!plaintext && plaintext_len != 0) || !ciphertext_out ||
        !ciphertext_len_out || key_is_zero(key))
        return -1;

    uint8_t nonce[24];
    build_nonce(direction, seq, nonce);

    /* crypto_aead_lock writes cipher_text in-place, mac separately */
    uint8_t mac[16];
    crypto_aead_lock(ciphertext_out, mac,
                     key, nonce,
                     ad, ad_len,
                     plaintext, plaintext_len);

    /* Append mac after ciphertext (wire format: ct || tag) */
    memcpy(ciphertext_out + plaintext_len, mac, 16);
    crypto_wipe(mac, 16);
    crypto_wipe(nonce, 24);

    if (ciphertext_len_out)
        *ciphertext_len_out = plaintext_len + 16;
    return 0;
}

int crypto_encrypt(const uint8_t key[32],
                   uint32_t seq,
                   uint8_t direction,
                   const uint8_t ad[10],
                   const uint8_t *plaintext, size_t plaintext_len,
                   uint8_t *ciphertext_out, size_t *ciphertext_len_out)
{
    return crypto_encrypt_ad(key, seq, direction, ad, 10,
                             plaintext, plaintext_len,
                             ciphertext_out, ciphertext_len_out);
}

/* -------------------------------------------------------------------------
 * AEAD decrypt
 * Wire format: ciphertext = cipher_text || mac[16]
 * ---------------------------------------------------------------------- */

int crypto_decrypt_ad(const uint8_t key[32],
                      uint32_t seq,
                      uint8_t direction,
                      const uint8_t *ad, size_t ad_len,
                      const uint8_t *ciphertext, size_t ciphertext_len,
                      uint8_t *plaintext_out, size_t *plaintext_len_out)
{
    if (!key || (!ad && ad_len != 0) || !ciphertext || !plaintext_out ||
        !plaintext_len_out || key_is_zero(key))
        return -1;
    if (ciphertext_len < 16) {
        fprintf(stderr, "crypto_decrypt: ciphertext too short (%zu)\n",
                ciphertext_len);
        return -1;
    }
    size_t pt_len = ciphertext_len - 16;
    const uint8_t *mac = ciphertext + pt_len;

    uint8_t nonce[24];
    build_nonce(direction, seq, nonce);

    int r = crypto_aead_unlock(plaintext_out, mac,
                               key, nonce,
                               ad, ad_len,
                               ciphertext, pt_len);
    crypto_wipe(nonce, 24);

    if (r != 0) return -1;  /* auth failure */

    *plaintext_len_out = pt_len;
    return 0;
}

int crypto_decrypt(const uint8_t key[32],
                   uint32_t seq,
                   uint8_t direction,
                   const uint8_t ad[10],
                   const uint8_t *ciphertext, size_t ciphertext_len,
                   uint8_t *plaintext_out, size_t *plaintext_len_out)
{
    return crypto_decrypt_ad(key, seq, direction, ad, 10,
                             ciphertext, ciphertext_len,
                             plaintext_out, plaintext_len_out);
}

/* -------------------------------------------------------------------------
 * Whole-message fragment commitment
 * ---------------------------------------------------------------------- */

void crypto_fragment_hash(uint8_t out[32],
                          uint8_t direction, uint8_t channel, uint8_t type,
                          uint32_t message_id,
                          uint16_t fragment_count,
                          uint16_t total_length,
                          uint16_t fragment_stride,
                          const uint8_t *message, size_t message_len)
{
    static const uint8_t domain[] = "unmoor-fragment-v1";
    uint8_t meta[13];
    meta[0] = direction;
    meta[1] = channel;
    meta[2] = type;
    meta[3] = (uint8_t)(message_id & 0xff);
    meta[4] = (uint8_t)((message_id >> 8) & 0xff);
    meta[5] = (uint8_t)((message_id >> 16) & 0xff);
    meta[6] = (uint8_t)((message_id >> 24) & 0xff);
    meta[7] = (uint8_t)(fragment_count & 0xff);
    meta[8] = (uint8_t)(fragment_count >> 8);
    meta[9] = (uint8_t)(total_length & 0xff);
    meta[10] = (uint8_t)(total_length >> 8);
    meta[11] = (uint8_t)(fragment_stride & 0xff);
    meta[12] = (uint8_t)(fragment_stride >> 8);

    crypto_blake2b_ctx ctx;
    crypto_blake2b_init(&ctx, 32);
    crypto_blake2b_update(&ctx, domain, sizeof(domain) - 1);
    crypto_blake2b_update(&ctx, meta, sizeof(meta));
    if (message_len != 0)
        crypto_blake2b_update(&ctx, message, message_len);
    crypto_blake2b_final(&ctx, out);
    crypto_wipe(&ctx, sizeof(ctx));
    crypto_wipe(meta, sizeof(meta));
}

/* -------------------------------------------------------------------------
 * Terminal state sync stream chain
 *
 * Thin wrappers over an incremental BLAKE2b-256. The context lives inside
 * the caller-owned crypto_sync_chain_t so sync.c never needs monocypher.h.
 * value() finalizes a stack snapshot so the running state keeps absorbing.
 * ---------------------------------------------------------------------- */

_Static_assert(sizeof(crypto_blake2b_ctx) <= sizeof(crypto_sync_chain_t),
               "crypto_sync_chain_t opaque storage too small for blake2b ctx");

void crypto_sync_chain_init(crypto_sync_chain_t *c, uint8_t direction)
{
    static const uint8_t domain[] = "unmoor-sync-chain-v1";
    crypto_blake2b_ctx *ctx = (crypto_blake2b_ctx *)(void *)c->opaque;
    memset(c, 0, sizeof(*c));
    crypto_blake2b_init(ctx, 32);
    crypto_blake2b_update(ctx, domain, sizeof(domain) - 1);
    crypto_blake2b_update(ctx, &direction, 1);
}

void crypto_sync_chain_absorb(crypto_sync_chain_t *c,
                              const uint8_t *data, size_t len)
{
    if (len == 0) return;
    crypto_blake2b_update((crypto_blake2b_ctx *)(void *)c->opaque, data, len);
}

void crypto_sync_chain_value(const crypto_sync_chain_t *c, uint8_t out[32])
{
    crypto_blake2b_ctx snap;
    memcpy(&snap, c->opaque, sizeof(snap));
    crypto_blake2b_final(&snap, out);
    crypto_wipe(&snap, sizeof(snap));
}

/* -------------------------------------------------------------------------
 * Explicit-nonce AEAD (hello handshake)
 *
 * Identical to crypto_encrypt/decrypt except the 24-byte XChaCha20 nonce
 * is supplied by the caller instead of derived from (direction, seq).
 * Used only for CTRL_HELLO / CTRL_HELLO_ACK; all other frames continue
 * to use the (direction, seq) path. See hello-nonce.
 * ---------------------------------------------------------------------- */

int crypto_encrypt_with_nonce(const uint8_t key[32],
                              const uint8_t nonce[24],
                              const uint8_t ad[10],
                              const uint8_t *plaintext, size_t plaintext_len,
                              uint8_t *ciphertext_out, size_t *ciphertext_len_out)
{
    uint8_t mac[16];
    if (!key || !nonce || !ad || (!plaintext && plaintext_len != 0) ||
        !ciphertext_out || key_is_zero(key))
        return -1;
    crypto_aead_lock(ciphertext_out, mac,
                     key, nonce,
                     ad, 10,
                     plaintext, plaintext_len);
    memcpy(ciphertext_out + plaintext_len, mac, 16);
    crypto_wipe(mac, 16);
    if (ciphertext_len_out)
        *ciphertext_len_out = plaintext_len + 16;
    return 0;
}

int crypto_decrypt_with_nonce(const uint8_t key[32],
                              const uint8_t nonce[24],
                              const uint8_t ad[10],
                              const uint8_t *ciphertext, size_t ciphertext_len,
                              uint8_t *plaintext_out, size_t *plaintext_len_out)
{
    if (!key || !nonce || !ad || !ciphertext || !plaintext_out ||
        !plaintext_len_out || key_is_zero(key))
        return -1;
    if (ciphertext_len < 16) {
        fprintf(stderr, "crypto_decrypt_with_nonce: ciphertext too short (%zu)\n",
                ciphertext_len);
        return -1;
    }
    size_t pt_len = ciphertext_len - 16;
    const uint8_t *mac = ciphertext + pt_len;

    int r = crypto_aead_unlock(plaintext_out, mac,
                               key, nonce,
                               ad, 10,
                               ciphertext, pt_len);
    if (r != 0) return -1;

    *plaintext_len_out = pt_len;
    return 0;
}

/* -------------------------------------------------------------------------
 * Memory security
 * ---------------------------------------------------------------------- */

void crypto_memzero(void *buf, size_t len)
{
    crypto_wipe(buf, len);
}

int crypto_mlock(void *buf, size_t len)
{
    if (mlock(buf, len) != 0) {
        fprintf(stderr, "crypto_mlock: mlock failed (non-fatal): %s\n",
                strerror(errno));
        return -1;
    }
    return 0;
}

int crypto_munlock(void *buf, size_t len)
{
    if (munlock(buf, len) != 0) {
        /* Non-fatal: matches crypto_mlock failure semantics. The caller
         * has already wiped (or is about to wipe) the buffer. */
        return -1;
    }
    return 0;
}

void crypto_mark_dontdump(void *addr, size_t len)
{
#ifdef MADV_DONTDUMP
    long pgsz = sysconf(_SC_PAGESIZE);
    if (pgsz <= 0) return;
    uintptr_t base = (uintptr_t)addr & ~(uintptr_t)(pgsz - 1);
    size_t rlen    = len + ((uintptr_t)addr - base);
    madvise((void *)base, rlen, MADV_DONTDUMP);
#else
    (void)addr; (void)len;
#endif
}

int crypto_random_bytes(void *buf, size_t len)
{
    /* Loop on EINTR and short reads. */
    uint8_t *p = (uint8_t *)buf;
    size_t off = 0;
#ifdef __APPLE__
    /* macOS: getentropy(3) caps each call at 256 bytes, never short-returns,
     * and is documented as uninterruptible (no EINTR), so just loop in
     * chunks and bail on any failure. */
    while (off < len) {
        size_t chunk = len - off;
        if (chunk > 256) chunk = 256;
        if (getentropy(p + off, chunk) != 0) {
            fprintf(stderr, "crypto_random_bytes: getentropy failed: %s\n",
                    strerror(errno));
            return -1;
        }
        off += chunk;
    }
#else
    while (off < len) {
        ssize_t got = getrandom(p + off, len - off, 0);
        if (got < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "crypto_random_bytes: getrandom failed: %s\n",
                    strerror(errno));
            return -1;
        }
        if (got == 0) {
            fprintf(stderr, "crypto_random_bytes: getrandom returned 0\n");
            return -1;
        }
        off += (size_t)got;
    }
#endif
    return 0;
}

int crypto_verify32_exact(const uint8_t left[32], const uint8_t right[32])
{
    if (!left || !right)
        return -1;
    return crypto_verify32(left, right);
}
