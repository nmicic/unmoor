/*
 * frame_test.c — wire-format and crypto test harness
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * Standalone wire-format and crypto harness. The wire encoder here is a
 * deliberate second implementation of — it does not call
 * src/frame.c, so a bug in the production encoder cannot hide behind the
 * same bug in the test. Reassembly and the KDF/AEAD do link the production
 * src/reasm.c and src/crypto.c, because those are what is under test.
 *
 * The test groups are numbered 2..7. Group 1 covered a serial transport's
 * own framing layer and was retired with that transport.
 *
 * Build:  make test
 *
 * Run:
 *   .build/<os>-<arch>/frame_test   # PASS/FAIL per test, exit 0 = all pass
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "monocypher.h"
#include "reasm.h"
#include "crypto.h"
#include "negotiation.h"

/* ------------------------------------------------------------------------- */
/* Test harness                                                              */
/* ------------------------------------------------------------------------- */

static int  g_total;
static int  g_failed;

#define CHECK(name, cond) do { \
    g_total++; \
    if (!(cond)) { \
        g_failed++; \
        fprintf(stderr, "FAIL %s   (%s:%d)\n", (name), __FILE__, __LINE__); \
    } else { \
        printf("PASS %s\n", (name)); \
    } \
} while (0)

/* ------------------------------------------------------------------------- */
/* Wire constants (mirror the protocol wire format)                          */
/* ------------------------------------------------------------------------- */

#define FRAME_DEFAULT_DGRAM UNMOOR_TERMINAL_WIRE_MAX
#define MAX_PT_DEFAULT      UNMOOR_TERMINAL_PLAINTEXT_MAX
#define MAX_PT_CEILING      (FRAME_MAX_LEN - FRAME_HEADER_LEN - FRAME_TAG_LEN)

/* Replay window */
#define REPLAY_WINDOW       256

/* ------------------------------------------------------------------------- */
/* Frame encode + receiver-side PAIR_ID prefilter                            */
/* ------------------------------------------------------------------------- */

static int frame_encode(const uint8_t pair_id[4], uint32_t seq,
                        uint8_t chan, uint8_t type,
                        const uint8_t *ct, size_t ct_len,
                        uint8_t *out, size_t out_max)
{
    if (ct_len < FRAME_MIN_CT_LEN) return -1;
    if (FRAME_HEADER_LEN + ct_len > out_max) return -1;

    memcpy(out, pair_id, 4);
    out[4] = (uint8_t)(seq      & 0xFF);
    out[5] = (uint8_t)(seq >> 8 & 0xFF);
    out[6] = (uint8_t)(seq >> 16 & 0xFF);
    out[7] = (uint8_t)(seq >> 24 & 0xFF);
    out[8] = chan;
    out[9] = type;
    out[10] = (uint8_t)(ct_len & 0xFF);
    out[11] = (uint8_t)((ct_len >> 8) & 0xFF);
    memcpy(out + FRAME_HEADER_LEN, ct, ct_len);
    return (int)(FRAME_HEADER_LEN + ct_len);
}

#define PREFILTER_ACCEPT 0
#define PREFILTER_REJECT 1

static int pair_id_prefilter(const uint8_t configured_pair_id[4],
                             const uint8_t *frame, size_t frame_len)
{
    if (frame_len < FRAME_HEADER_LEN) return PREFILTER_REJECT;
    if (memcmp(frame, configured_pair_id, 4) != 0) return PREFILTER_REJECT;
    return PREFILTER_ACCEPT;
}

/* ------------------------------------------------------------------------- */
/* Crypto helpers                                                            */
/* ------------------------------------------------------------------------- */

/* Build the 24-byte XChaCha20 nonce: direction byte, SEQ little-endian,
 * remaining bytes zero. Mirrors build_nonce() in src/crypto.c. */
static void build_nonce(uint8_t direction, uint32_t seq, uint8_t nonce_out[24])
{
    memset(nonce_out, 0, 24);
    nonce_out[0] = direction;
    nonce_out[1] = (uint8_t)(seq      & 0xFF);
    nonce_out[2] = (uint8_t)(seq >> 8 & 0xFF);
    nonce_out[3] = (uint8_t)(seq >> 16 & 0xFF);
    nonce_out[4] = (uint8_t)(seq >> 24 & 0xFF);
}

/* Build the 10-byte AEAD AD: PAIR_ID || SEQ || CHAN || TYPE */
static void build_ad(const uint8_t pair_id[4], uint32_t seq,
                     uint8_t chan, uint8_t type, uint8_t ad_out[10])
{
    memcpy(ad_out, pair_id, 4);
    ad_out[4] = (uint8_t)(seq      & 0xFF);
    ad_out[5] = (uint8_t)(seq >> 8 & 0xFF);
    ad_out[6] = (uint8_t)(seq >> 16 & 0xFF);
    ad_out[7] = (uint8_t)(seq >> 24 & 0xFF);
    ad_out[8] = chan;
    ad_out[9] = type;
}

/* ------------------------------------------------------------------------- */
/* Replay window — additive form, see */
/* ------------------------------------------------------------------------- */

typedef struct {
    uint32_t hwm;
    int      initialized;
    uint8_t  bitmap[REPLAY_WINDOW]; /* 0 = unseen, 1 = seen */
} replay_t;

/*
 * Accept rule (additive form):
 *   if !initialized → accept, set HWM, set bitmap slot
 *   if SEQ > HWM → accept, advance HWM, slide bitmap slots out
 *   else if SEQ + 256 > HWM AND bitmap[SEQ % 256] == 0 → accept, set bit
 *   else reject
 *
 * Returns 1 = accept, 0 = reject.
 */
static int replay_accept(replay_t *r, uint32_t seq)
{
    if (!r->initialized) {
        r->hwm = seq;
        memset(r->bitmap, 0, sizeof(r->bitmap));
        r->bitmap[seq % REPLAY_WINDOW] = 1;
        r->initialized = 1;
        return 1;
    }
    if (seq > r->hwm) {
        /* Advance: clear slots that slid out of the window. */
        uint32_t advance = seq - r->hwm;
        if (advance >= REPLAY_WINDOW) {
            memset(r->bitmap, 0, sizeof(r->bitmap));
        } else {
            for (uint32_t i = 1; i <= advance; i++) {
                /* Slot for (hwm - 256 + i) is no longer reachable. */
                uint32_t evict = r->hwm + i - REPLAY_WINDOW;
                /* When hwm+i < REPLAY_WINDOW the eviction slot wraps; the additive
                 * rule below still rejects those low SEQs because hwm advanced. */
                r->bitmap[evict % REPLAY_WINDOW] = 0;
            }
        }
        r->hwm = seq;
        r->bitmap[seq % REPLAY_WINDOW] = 1;
        return 1;
    }
    /* SEQ <= HWM: in-window only if SEQ + 256 > HWM (strict) */
    if ((uint64_t)seq + REPLAY_WINDOW > (uint64_t)r->hwm) {
        if (r->bitmap[seq % REPLAY_WINDOW]) return 0;
        r->bitmap[seq % REPLAY_WINDOW] = 1;
        return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Reference vector — Monocypher AEAD                                        */
/* ------------------------------------------------------------------------- */

/*
 * Reference vector for crypto_aead_lock (XChaCha20-Poly1305 IETF) with:
 *   key   = 0x00 * 32
 *   nonce = 0x00 * 24
 *   ad    = empty
 *   plain = "test" (4 bytes)
 * Output: ciphertext[4] || mac[16] = 20 bytes total.
 *
 * Verified two ways when the vector was taken:
 *   1) Built against this exact src/vendor/monocypher.c (4.0.3)
 *   2) Cross-checked against PyNaCl's libsodium binding
 *      (crypto_aead_xchacha20poly1305_ietf_encrypt) — byte-identical.
 *
 * Purpose: detect a wrong primitive (AES-GCM, ChaCha20 without X-nonce
 * extension, an unintended monocypher upgrade) that would still produce
 * deterministic but different bytes.
 */
static const uint8_t kAeadRefVector[20] = {
    /* ciphertext[4] */
    0x0C, 0xFB, 0xE5, 0xFD,
    /* mac[16] */
    0xE7, 0x53, 0x56, 0x56, 0x5F, 0x5E, 0xE3, 0x6A,
    0x75, 0xE5, 0x9F, 0xD8, 0x1D, 0x63, 0x47, 0x9D,
};
/* If the test fails on first run, set this to 1, run, copy printed bytes
 * into kAeadRefVector, set back to 0. */
#define REF_VECTOR_BOOTSTRAP 0

/* ------------------------------------------------------------------------- */
/* Group 2 — frame encode/decode + PAIR_ID check                             */
/* ------------------------------------------------------------------------- */

static void test_group2_frames(void)
{
    uint8_t pair_id[4]   = { 0xDE, 0xAD, 0xBE, 0xEF };
    uint8_t pair_other[4] = { 0xCA, 0xFE, 0xBA, 0xBE };
    uint8_t ct[16]        = { 0 };
    uint8_t frame[256];

    /* 2-01: PAIR_ID at bytes 0..3 */
    {
        int n = frame_encode(pair_id, 0, 0x12, 0x05, ct, sizeof(ct),
                             frame, sizeof(frame));
        CHECK("2-01 pair_id_bytes_0_3",
              n > 0 && memcmp(frame, pair_id, 4) == 0);
    }

    /* 2-02: SEQ at bytes 4..7 little-endian */
    {
        uint32_t seq = 0x11223344;
        int n = frame_encode(pair_id, seq, 0x10, 0x01, ct, sizeof(ct),
                             frame, sizeof(frame));
        CHECK("2-02 seq_bytes_4_7_le",
              n > 0
              && frame[4] == 0x44 && frame[5] == 0x33
              && frame[6] == 0x22 && frame[7] == 0x11);
    }

    /* 2-03: CHAN field — channel ID upper nibble + FF/MF bits */
    {
        /* channel 1, FIRST_FRAGMENT=1, MORE_FRAGMENTS=1 */
        uint8_t chan = (uint8_t)((1 << 4) | CHAN_FF_BIT | CHAN_MF_BIT);
        int n = frame_encode(pair_id, 0, chan, 0x04, ct, sizeof(ct),
                             frame, sizeof(frame));
        CHECK("2-03 chan_byte_layout",
              n > 0
              && ((frame[8] >> 4) & 0x0F) == 1
              && (frame[8] & CHAN_FF_BIT)
              && (frame[8] & CHAN_MF_BIT));
    }

    /* 2-04: wrong PAIR_ID → prefilter REJECT */
    {
        int n = frame_encode(pair_other, 0, 0x10, 0x01, ct, sizeof(ct),
                             frame, sizeof(frame));
        CHECK("2-04 wrong_pair_id_rejected",
              n > 0 && pair_id_prefilter(pair_id, frame, (size_t)n) ==
                           PREFILTER_REJECT);
    }

    /* 2-05: matching PAIR_ID → prefilter ACCEPT */
    {
        int n = frame_encode(pair_id, 0, 0x10, 0x01, ct, sizeof(ct),
                             frame, sizeof(frame));
        CHECK("2-05 matching_pair_id_accepted",
              n > 0 && pair_id_prefilter(pair_id, frame, (size_t)n) ==
                           PREFILTER_ACCEPT);
    }

    /* 2-06: ordinary terminal datagram and its plaintext budget */
    CHECK("2-06 terminal_datagram_1200_plaintext_1172",
          FRAME_DEFAULT_DGRAM == 1200 && MAX_PT_DEFAULT == 1172);

    /* 2-07: absolute plaintext ceiling at FRAME_MAX_LEN */
    CHECK("2-07 ceiling_is_the_terminal_datagram",
          FRAME_MAX_LEN == FRAME_DEFAULT_DGRAM && MAX_PT_CEILING == 1172);

    /* 2-08: a frame at the wire cap encodes; one byte over is rejected */
    {
        uint8_t big[MAX_PT_CEILING + FRAME_TAG_LEN];
        uint8_t out[FRAME_MAX_LEN + 8];
        memset(big, 0xA5, sizeof(big));
        int ok  = frame_encode(pair_id, 0, 0x10, 0x01, big, sizeof(big),
                               out, FRAME_MAX_LEN);
        int bad = frame_encode(pair_id, 0, 0x10, 0x01, big, sizeof(big) + 1,
                               out, FRAME_MAX_LEN);
        CHECK("2-08 wire_cap_1200_boundary",
              ok == FRAME_MAX_LEN && bad < 0);
    }

    /* The production decoder owns one complete datagram.  Accepting bytes
     * after LEN would make parser composition depend on the caller. */
    {
        const uint8_t *decoded_ct = NULL;
        size_t decoded_len = 0U;
        int n = unmoor_frame_encode(pair_id, 9U, 0x10U, 0x01U, ct,
                                    sizeof(ct), frame, sizeof(frame));
        int exact = unmoor_frame_decode(frame, (size_t)n, NULL, NULL, NULL,
                                        NULL, &decoded_ct, &decoded_len);

        if (n > 0)
            frame[n] = 0xA5U;
        CHECK("2-09 product_decoder_rejects_trailing_datagram_bytes",
              n > 0 && exact == 0 && decoded_ct == frame + FRAME_HEADER_LEN &&
              decoded_len == sizeof(ct) &&
              unmoor_frame_decode(frame, (size_t)n + 1U, NULL, NULL, NULL,
                                  NULL, NULL, NULL) != 0);
    }
}

/* ------------------------------------------------------------------------- */
/* Group 3 — AEAD round-trip + nonce + AD authentication                     */
/* ------------------------------------------------------------------------- */

static void test_group3_aead(void)
{
    uint8_t key[32];
    uint8_t nonce[24];
    uint8_t ad[10];
    uint8_t pair_id[4] = { 0x01, 0x02, 0x03, 0x04 };

    /* 3-00: reference vector (catches wrong primitive) */
    {
        uint8_t k0[32] = { 0 };
        uint8_t n0[24] = { 0 };
        const uint8_t plain[4] = { 't', 'e', 's', 't' };
        uint8_t ct[4];
        uint8_t mac[16];
        crypto_aead_lock(ct, mac, k0, n0, NULL, 0, plain, sizeof(plain));

#if REF_VECTOR_BOOTSTRAP
        printf("REF_VECTOR ct: ");
        for (size_t i = 0; i < 4; i++)  printf("0x%02X, ", ct[i]);
        printf("\nREF_VECTOR mac: ");
        for (size_t i = 0; i < 16; i++) printf("0x%02X, ", mac[i]);
        printf("\n");
#endif
        int ok = (memcmp(ct,  kAeadRefVector + 0,  4)  == 0)
              && (memcmp(mac, kAeadRefVector + 4,  16) == 0);
        CHECK("3-00 monocypher_aead_reference_vector", ok);
    }

    /* Set up a non-trivial key for the rest of the group. */
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i + 1);

    /* 3-01: round-trip OK */
    {
        build_nonce(0x00, 100, nonce);
        build_ad(pair_id, 100, 0x10, 0x05, ad);
        const uint8_t plain[] = "UNMOOR AEAD-test";
        uint8_t ct[sizeof(plain) - 1], mac[16], out[sizeof(plain) - 1];
        crypto_aead_lock(ct, mac, key, nonce, ad, 10,
                         plain, sizeof(plain) - 1);
        int r = crypto_aead_unlock(out, mac, key, nonce, ad, 10, ct, sizeof(ct));
        CHECK("3-01 aead_round_trip",
              r == 0 && memcmp(out, plain, sizeof(out)) == 0);
    }

    /* 3-02: encrypt with one key, decrypt with another → fail */
    {
        uint8_t key2[32];
        for (int i = 0; i < 32; i++) key2[i] = (uint8_t)(0xAA - i);
        build_nonce(0x00, 101, nonce);
        build_ad(pair_id, 101, 0x10, 0x05, ad);
        const uint8_t plain[] = "abcdefgh";
        uint8_t ct[sizeof(plain) - 1], mac[16], out[sizeof(plain) - 1];
        crypto_aead_lock(ct, mac, key, nonce, ad, 10,
                         plain, sizeof(plain) - 1);
        int r = crypto_aead_unlock(out, mac, key2, nonce, ad, 10, ct, sizeof(ct));
        CHECK("3-02 aead_wrong_key_rejected", r != 0);
    }

    /* 3-03: flip one bit in ciphertext → fail */
    {
        build_nonce(0x00, 102, nonce);
        build_ad(pair_id, 102, 0x10, 0x05, ad);
        const uint8_t plain[] = "12345678";
        uint8_t ct[sizeof(plain) - 1], mac[16], out[sizeof(plain) - 1];
        crypto_aead_lock(ct, mac, key, nonce, ad, 10,
                         plain, sizeof(plain) - 1);
        ct[3] ^= 0x01;
        int r = crypto_aead_unlock(out, mac, key, nonce, ad, 10, ct, sizeof(ct));
        CHECK("3-03 aead_ciphertext_bitflip_rejected", r != 0);
    }

    /* 3-04: flip one bit in tag → fail */
    {
        build_nonce(0x00, 103, nonce);
        build_ad(pair_id, 103, 0x10, 0x05, ad);
        const uint8_t plain[] = "ABCDEFGH";
        uint8_t ct[sizeof(plain) - 1], mac[16], out[sizeof(plain) - 1];
        crypto_aead_lock(ct, mac, key, nonce, ad, 10,
                         plain, sizeof(plain) - 1);
        mac[7] ^= 0x80;
        int r = crypto_aead_unlock(out, mac, key, nonce, ad, 10, ct, sizeof(ct));
        CHECK("3-04 aead_tag_bitflip_rejected", r != 0);
    }

    /* 3-05: same SEQ used twice — caller MUST NOT reuse. We assert that
     *        identical (key, nonce, plaintext) gives identical ciphertext —
     *        i.e. nonce reuse is detectable as deterministic output, which
     *        is the catastrophic property the protocol layer must avoid. */
    {
        build_nonce(0x00, 104, nonce);
        build_ad(pair_id, 104, 0x10, 0x05, ad);
        const uint8_t plain[] = "noncereu";
        uint8_t ct1[sizeof(plain) - 1], mac1[16];
        uint8_t ct2[sizeof(plain) - 1], mac2[16];
        crypto_aead_lock(ct1, mac1, key, nonce, ad, 10,
                         plain, sizeof(plain) - 1);
        crypto_aead_lock(ct2, mac2, key, nonce, ad, 10,
                         plain, sizeof(plain) - 1);
        CHECK("3-05 aead_same_nonce_deterministic_output",
              memcmp(ct1, ct2, 8) == 0 && memcmp(mac1, mac2, 16) == 0);
    }

    /* 3-06: nonce construction client direction */
    {
        build_nonce(0x00, 0x12345678u, nonce);
        int ok = nonce[0] == 0x00
              && nonce[1] == 0x78 && nonce[2] == 0x56
              && nonce[3] == 0x34 && nonce[4] == 0x12;
        for (int i = 5; i < 24; i++) ok = ok && nonce[i] == 0x00;
        CHECK("3-06 nonce_client_direction", ok);
    }

    /* 3-06b: nonce construction server direction */
    {
        build_nonce(0x01, 0x12345678u, nonce);
        int ok = nonce[0] == 0x01
              && nonce[1] == 0x78 && nonce[2] == 0x56
              && nonce[3] == 0x34 && nonce[4] == 0x12;
        for (int i = 5; i < 24; i++) ok = ok && nonce[i] == 0x00;
        CHECK("3-06b nonce_server_direction", ok);
    }

    /* 3-07: AD PAIR_ID authenticated — flipping a PAIR_ID bit fails AEAD */
    {
        build_nonce(0x00, 200, nonce);
        build_ad(pair_id, 200, 0x10, 0x05, ad);
        const uint8_t plain[] = "padbinda";
        uint8_t ct[sizeof(plain) - 1], mac[16], out[sizeof(plain) - 1];
        crypto_aead_lock(ct, mac, key, nonce, ad, 10,
                         plain, sizeof(plain) - 1);
        uint8_t ad_bad[10];
        memcpy(ad_bad, ad, 10);
        ad_bad[2] ^= 0x40;
        int r = crypto_aead_unlock(out, mac, key, nonce, ad_bad, 10, ct, sizeof(ct));
        CHECK("3-07 ad_pair_id_authenticated", r != 0);
    }

    /* 3-08: CHAN bits 0 and 1 are in AD — flipping FIRST/MORE bits fails */
    {
        build_nonce(0x00, 201, nonce);
        uint8_t chan = (uint8_t)((1 << 4) | CHAN_FF_BIT | CHAN_MF_BIT);
        build_ad(pair_id, 201, chan, 0x04, ad);
        const uint8_t plain[] = "fragbits";
        uint8_t ct[sizeof(plain) - 1], mac[16], out[sizeof(plain) - 1];
        crypto_aead_lock(ct, mac, key, nonce, ad, 10,
                         plain, sizeof(plain) - 1);

        uint8_t ad_bad[10];
        memcpy(ad_bad, ad, 10);
        ad_bad[8] ^= CHAN_MF_BIT;
        int r1 = crypto_aead_unlock(out, mac, key, nonce, ad_bad, 10,
                                    ct, sizeof(ct));

        memcpy(ad_bad, ad, 10);
        ad_bad[8] ^= CHAN_FF_BIT;
        int r2 = crypto_aead_unlock(out, mac, key, nonce, ad_bad, 10,
                                    ct, sizeof(ct));

        CHECK("3-08 ad_chan_frag_bits_authenticated", r1 != 0 && r2 != 0);
    }

    /* 3-09: client and server SEQ=100 give DIFFERENT ciphertexts */
    {
        const uint8_t plain[] = "samebody";
        uint8_t ct_c[sizeof(plain) - 1], mac_c[16];
        uint8_t ct_s[sizeof(plain) - 1], mac_s[16];
        uint8_t nonce_c[24], nonce_s[24];

        build_nonce(0x00, 100, nonce_c);
        build_nonce(0x01, 100, nonce_s);
        build_ad(pair_id, 100, 0x10, 0x05, ad);
        crypto_aead_lock(ct_c, mac_c, key, nonce_c, ad, 10,
                         plain, sizeof(plain) - 1);
        crypto_aead_lock(ct_s, mac_s, key, nonce_s, ad, 10,
                         plain, sizeof(plain) - 1);
        CHECK("3-09 client_server_nonces_disjoint",
              memcmp(ct_c, ct_s, 8) != 0 || memcmp(mac_c, mac_s, 16) != 0);
    }

    /* ------------------------------------------------------------------------ *
     * 3-10..3-13: hello_nonce per-send uniqueness (hello-nonce).
     *
     * SCOPE — what these tests do and do not catch.
     *
     * These tests exercise crypto_encrypt_with_nonce /
     * crypto_decrypt_with_nonce directly. They DO catch:
     *   - a regression that makes the wrapper ignore its caller-supplied
     *     nonce (3-10 + 3-13: distinct nonces -> distinct outputs, fixed
     *     nonce -> identical output)
     *   - a regression that drops integrity protection on the cleartext
     *     nonce copy (3-11: tampered nonce -> Poly1305 tag failure)
     *   - a regression that makes the wrapper sample its own nonce
     *     internally and discard the caller's (3-13)
     *
     * They DO NOT catch a regression in src/session.c's send_hello()
     * itself — for example, a refactor that calls plain crypto_encrypt
     * (deterministic build_nonce(direction, seq)) instead of
     * crypto_encrypt_with_nonce. Catching that requires linking
     * session.c into the test, which pulls in transport/channel/pty and
     * is out of scope for this harness. If you change send_hello, audit
     * its AEAD call site by hand and verify it still uses
     * crypto_encrypt_with_nonce with a freshly-sampled per-send nonce.
     * ------------------------------------------------------------------------ */

    /* 3-10: crypto_encrypt_with_nonce honors its nonce parameter — same
     *       inputs except for the nonce produce DIFFERENT ciphertexts.
     *       Catches a regression where the wrapper drops or overwrites
     *       its caller-supplied nonce. */
    {
        uint8_t hello_key[32];
        for (int i = 0; i < 32; i++) hello_key[i] = (uint8_t)(0x55 ^ i);

        uint8_t hello_pt[32];
        memset(hello_pt, 0, sizeof(hello_pt));
        hello_pt[0] = NEGOTIATION_HELLO_VERSION;
        hello_pt[1] = 0x01;  /* caps = PTY */
        for (int i = 0; i < 16; i++) hello_pt[2 + i] = (uint8_t)(0x10 + i);

        build_ad(pair_id, /*seq=*/0, /*chan=*/0x02,
                 /*type=*/0x01 /* CTRL_HELLO */, ad);

        uint8_t nonce_a[24], nonce_b[24];
        if (getentropy(nonce_a, 24) != 0 || getentropy(nonce_b, 24) != 0) {
            CHECK("3-10 hello_nonce_csprng_available", 0);
        } else {
            uint8_t out_a[48], out_b[48];
            size_t  out_a_len = 0, out_b_len = 0;
            int ra = crypto_encrypt_with_nonce(hello_key, nonce_a, ad,
                                               hello_pt, sizeof(hello_pt),
                                               out_a, &out_a_len);
            int rb = crypto_encrypt_with_nonce(hello_key, nonce_b, ad,
                                               hello_pt, sizeof(hello_pt),
                                               out_b, &out_b_len);

            int both_ok        = (ra == 0 && rb == 0);
            int len_ok         = (out_a_len == 48 && out_b_len == 48);
            int nonces_distinct = (memcmp(nonce_a, nonce_b, 24) != 0);
            int outputs_distinct = (memcmp(out_a, out_b, 48) != 0);
            CHECK("3-10 hello_nonce_per_send_unique_ciphertexts",
                  both_ok && len_ok && nonces_distinct && outputs_distinct);
        }
    }

    /* 3-11: an attacker who tampers with the cleartext hello_nonce in the
     *       wire body — without changing the ciphertext — gets a decrypt
     *       failure from crypto_decrypt_with_nonce, because XChaCha20
     *       derives a different keystream and Poly1305 one-time key.
     *       This is what "the nonce is not in AD but is still authenticated
     *       by the AEAD tag" means. */
    {
        uint8_t hello_key[32];
        for (int i = 0; i < 32; i++) hello_key[i] = (uint8_t)(0x77 ^ i);

        const uint8_t hello_pt[] = "UNMOOR hello plaintext 32 bytes.";
        _Static_assert(sizeof(hello_pt) - 1 == 32,
                       "hello test plaintext must be 32 bytes");
        build_ad(pair_id, /*seq=*/0, /*chan=*/0x02, /*type=*/0x01, ad);

        uint8_t hello_nonce[24];
        if (getentropy(hello_nonce, 24) != 0) {
            CHECK("3-11 hello_nonce_csprng_available", 0);
        } else {
            uint8_t ct[48];
            size_t  ct_len = 0;
            int re = crypto_encrypt_with_nonce(hello_key, hello_nonce, ad,
                                               hello_pt, sizeof(hello_pt) - 1,
                                               ct, &ct_len);

            /* Tamper with the cleartext nonce as it would appear in BODY[0..23]. */
            uint8_t tampered_nonce[24];
            memcpy(tampered_nonce, hello_nonce, 24);
            tampered_nonce[5] ^= 0x40;

            uint8_t pt_out[32];
            size_t  pt_out_len = 0;
            int rd = crypto_decrypt_with_nonce(hello_key, tampered_nonce, ad,
                                               ct, ct_len,
                                               pt_out, &pt_out_len);
            CHECK("3-11 hello_nonce_tamper_rejected_by_aead_tag",
                  re == 0 && rd != 0);
        }
    }

    /* 3-12: the one-time-key reuse defect this design fixed — two sessions
     *       under the SAME hello_key (deterministic from PSK alone) sending
     *       CTRL_HELLO at SEQ=0 from the SAME direction with IDENTICAL
     *       plaintext and AD. A derived nonce = (direction || SEQ || zeros)
     *       via crypto_encrypt would produce the SAME (key, nonce) pair
     *       across the two sessions — catastrophic for Poly1305.
     *
     *       The shipped path calls crypto_encrypt_with_nonce with a
     *       fresh per-send nonce. This test calls crypto_encrypt_with_nonce
     *       twice with two distinct random nonces and asserts the outputs
     *       differ — proving the wrapper does NOT silently fall back to
     *       deterministic nonce derivation. If a future refactor restores
     *       the build_nonce(direction, seq) path here, the wrapper
     *       contract breaks and this CHECK fails. */
    {
        uint8_t psk_derived_hello_key[32];
        for (int i = 0; i < 32; i++)
            psk_derived_hello_key[i] = (uint8_t)(0x33 ^ (i * 7));

        const uint8_t hello_pt[] = "session CTRL_HELLO plaintext .. ";
        _Static_assert(sizeof(hello_pt) - 1 == 32,
                       "hello test plaintext must be 32 bytes");

        build_ad(pair_id, /*seq=*/0, /*chan=*/0x02, /*type=*/0x01, ad);

        uint8_t nonce_session_a[24], nonce_session_b[24];
        if (getentropy(nonce_session_a, 24) != 0 ||
            getentropy(nonce_session_b, 24) != 0) {
            CHECK("3-12 hello_nonce_csprng_available", 0);
        } else {
            uint8_t out_a[48], out_b[48];
            size_t  out_a_len = 0, out_b_len = 0;
            int ra = crypto_encrypt_with_nonce(psk_derived_hello_key,
                                               nonce_session_a, ad,
                                               hello_pt, sizeof(hello_pt) - 1,
                                               out_a, &out_a_len);
            int rb = crypto_encrypt_with_nonce(psk_derived_hello_key,
                                               nonce_session_b, ad,
                                               hello_pt, sizeof(hello_pt) - 1,
                                               out_b, &out_b_len);

            CHECK("3-12 cross_session_hello_distinct_under_same_psk",
                  ra == 0 && rb == 0 &&
                  out_a_len == 48 && out_b_len == 48 &&
                  memcmp(out_a, out_b, 48) != 0);
        }
    }

    /* 3-13: positive control — same nonce, same key, same plaintext, same
     *       AD MUST produce byte-identical output. This pairs with 3-10
     *       to prove crypto_encrypt_with_nonce actually consumes its
     *       nonce parameter (rather than, say, sampling its own internally
     *       and ignoring the caller's). Without this, a wrapper that just
     *       called crypto_random_bytes() and threw the caller's nonce on
     *       the floor would still pass 3-10 and 3-12 by accident. */
    {
        uint8_t hello_key[32];
        for (int i = 0; i < 32; i++) hello_key[i] = (uint8_t)(0xA5 ^ i);

        const uint8_t hello_pt[] = "UNMOOR hello 3-13 fixed input!!!";
        _Static_assert(sizeof(hello_pt) - 1 == 32,
                       "hello test plaintext must be 32 bytes");
        build_ad(pair_id, /*seq=*/0, /*chan=*/0x02, /*type=*/0x01, ad);

        uint8_t fixed_nonce[24];
        for (int i = 0; i < 24; i++) fixed_nonce[i] = (uint8_t)(0xC0 + i);

        uint8_t out_a[48], out_b[48];
        size_t  out_a_len = 0, out_b_len = 0;
        int ra = crypto_encrypt_with_nonce(hello_key, fixed_nonce, ad,
                                           hello_pt, sizeof(hello_pt) - 1,
                                           out_a, &out_a_len);
        int rb = crypto_encrypt_with_nonce(hello_key, fixed_nonce, ad,
                                           hello_pt, sizeof(hello_pt) - 1,
                                           out_b, &out_b_len);
        CHECK("3-13 same_nonce_same_inputs_byte_identical",
              ra == 0 && rb == 0 &&
              out_a_len == 48 && out_b_len == 48 &&
              memcmp(out_a, out_b, 48) == 0);
    }
}

/* ------------------------------------------------------------------------- */
/* Group 4 — Replay window (additive form, fencepost test)                    */
/* ------------------------------------------------------------------------- */

static void test_group4_replay(void)
{
    /* 4-01: SEQ=300 accepted, SEQ=300 again rejected */
    {
        replay_t r = { 0 };
        int a = replay_accept(&r, 300);
        int b = replay_accept(&r, 300);
        CHECK("4-01 first_accepted_replay_rejected", a == 1 && b == 0);
    }

    /* 4-02: HWM=300, SEQ=44 (additive boundary, 44+256=300, NOT > 300) → reject */
    {
        replay_t r = { 0 };
        replay_accept(&r, 300);
        int a44 = replay_accept(&r, 44);
        int a43 = replay_accept(&r, 43);
        CHECK("4-02 fencepost_44_43_rejected", a44 == 0 && a43 == 0);
    }

    /* 4-03: HWM=300, SEQ=45 (45+256=301 > 300) → accept */
    {
        replay_t r = { 0 };
        replay_accept(&r, 300);
        int a = replay_accept(&r, 45);
        CHECK("4-03 first_inside_window_accepted", a == 1);
    }

    /* 4-04: SEQ=600 after HWM=300 → accept, HWM advances */
    {
        replay_t r = { 0 };
        replay_accept(&r, 300);
        int a = replay_accept(&r, 600);
        CHECK("4-04 advance_to_higher_seq", a == 1 && r.hwm == 600);
    }

    /* 4-05: HWM=600, SEQ=44 well below window → reject */
    {
        replay_t r = { 0 };
        replay_accept(&r, 600);
        int a = replay_accept(&r, 44);
        CHECK("4-05 well_below_window_rejected", a == 0);
    }
}

/* ------------------------------------------------------------------------- */
/* Group 5 — KDF (BLAKE2b keyed-hash)                                        */
/* ------------------------------------------------------------------------- */

/* These wrap the production entry points in src/crypto.c rather than
 * re-deriving the keys locally. A local re-implementation passes every
 * property check below no matter what the shipped derivation does. */
static void derive_session_key(const uint8_t psk[32],
                               const uint8_t nonce_a[16],
                               const uint8_t nonce_b[16],
                               uint8_t out[32])
{
    crypto_derive_session_key(psk, nonce_a, nonce_b, out);
}

static void derive_hello_key(const uint8_t psk[32], uint8_t out[32])
{
    crypto_derive_hello_key(psk, out);
}

static void test_group5_kdf(void)
{
    uint8_t psk[32];
    for (int i = 0; i < 32; i++) psk[i] = (uint8_t)(i * 7 + 3);
    uint8_t na[16] = { 0 }, nb1[16] = { 1 }, nb2[16] = { 2 };

    /* 5-01: 32 bytes out */
    {
        uint8_t k[32];
        derive_session_key(psk, na, nb1, k);
        int nonzero = 0;
        for (int i = 0; i < 32; i++) if (k[i]) nonzero = 1;
        CHECK("5-01 session_key_32_bytes", nonzero);
    }

    /* 5-02: different nonce_b → different key */
    {
        uint8_t k1[32], k2[32];
        derive_session_key(psk, na, nb1, k1);
        derive_session_key(psk, na, nb2, k2);
        CHECK("5-02 different_nonce_different_key", memcmp(k1, k2, 32) != 0);
    }

    /* 5-03: deterministic */
    {
        uint8_t k1[32], k2[32];
        derive_session_key(psk, na, nb1, k1);
        derive_session_key(psk, na, nb1, k2);
        CHECK("5-03 deterministic", memcmp(k1, k2, 32) == 0);
    }

    /* 5-04: not identity (key != psk) */
    {
        uint8_t k[32];
        derive_session_key(psk, na, nb1, k);
        CHECK("5-04 session_key_not_psk", memcmp(k, psk, 32) != 0);
    }

    /* 5-05: hello_key differs from session_key */
    {
        uint8_t hk[32], sk[32];
        derive_hello_key(psk, hk);
        derive_session_key(psk, na, nb1, sk);
        CHECK("5-05 hello_key_distinct", memcmp(hk, sk, 32) != 0);
    }

    /* 5-06: CTRL_HELLO body encrypted with hello_key cannot be decrypted with
     * session_key. Round-trip with hello_key works. */
    {
        uint8_t hk[32], sk[32];
        derive_hello_key(psk, hk);
        derive_session_key(psk, na, nb1, sk);

        uint8_t pair_id[4] = { 1, 2, 3, 4 };
        uint8_t ad[10];
        build_ad(pair_id, 0, 0x00 /* CHAN=0 control */, 0x01 /* CTRL_HELLO */, ad);

        uint8_t nonce[24];
        build_nonce(0x00, 0, nonce);

        uint8_t plain[32] = { 0 };
        plain[0] = 0x01; /* version */
        plain[1] = 0x00; /* caps */
        for (int i = 0; i < 16; i++) plain[2 + i] = (uint8_t)i;

        uint8_t ct[32], mac[16], out[32];
        crypto_aead_lock(ct, mac, hk, nonce, ad, 10, plain, sizeof(plain));

        int r_hk = crypto_aead_unlock(out, mac, hk, nonce, ad, 10, ct, sizeof(ct));
        int r_sk = crypto_aead_unlock(out, mac, sk, nonce, ad, 10, ct, sizeof(ct));
        CHECK("5-06 hello_key_round_trip_session_key_rejects",
              r_hk == 0 && r_sk != 0);
    }

    /* 5-07: nonce_a/nonce_b swap in KDF gives different keys → AEAD fails */
    {
        uint8_t k_ab[32], k_ba[32];
        derive_session_key(psk, na,  nb1, k_ab);
        derive_session_key(psk, nb1, na,  k_ba);
        /* Encrypt with k_ab, decrypt with k_ba → must fail */
        uint8_t pair_id[4] = { 9, 9, 9, 9 };
        uint8_t ad[10];
        build_ad(pair_id, 0, 0x00, 0x03 /* CTRL_READY */, ad);
        uint8_t nonce[24];
        build_nonce(0x01, 0, nonce);
        uint8_t plain[1] = { 0 };
        uint8_t ct[1], mac[16], out[1];
        crypto_aead_lock(ct, mac, k_ab, nonce, ad, 10, plain, 0);
        int r = crypto_aead_unlock(out, mac, k_ba, nonce, ad, 10, ct, 0);
        CHECK("5-07 nonce_swap_aead_rejects", r != 0);
    }

    /* 5-08: wrong direction byte fails AEAD */
    {
        uint8_t k[32];
        derive_session_key(psk, na, nb1, k);
        uint8_t pair_id[4] = { 1, 1, 1, 1 };
        uint8_t ad[10];
        build_ad(pair_id, 7, 0x00, 0x03, ad);

        uint8_t nonce_s[24], nonce_c[24];
        build_nonce(0x01, 7, nonce_s);
        build_nonce(0x00, 7, nonce_c);
        uint8_t plain[1] = { 0 };
        uint8_t ct[1], mac[16], out[1];
        /* Encrypt as server (0x01), decrypt as client (0x00 nonce) */
        crypto_aead_lock(ct, mac, k, nonce_s, ad, 10, plain, 0);
        int r = crypto_aead_unlock(out, mac, k, nonce_c, ad, 10, ct, 0);
        CHECK("5-08 wrong_direction_byte_aead_rejects", r != 0);
    }

    /* 5-09: PAIR_ID derivation (pair-id-derivation).
     * crypto_derive_pair_id mirrors derive_session_key/derive_hello_key:
     * BLAKE2b_keyed(key=PSK, msg="unmoor-pairid") truncated to 4 bytes.
     * Verify (a) deterministic for a fixed PSK, (b) different PSKs
     * produce different pair_ids, (c) pair_id is not just the first
     * 4 bytes of PSK. */
    {
        uint8_t psk_a[32], psk_b[32];
        for (int i = 0; i < 32; i++) psk_a[i] = 0xAB;
        for (int i = 0; i < 32; i++) psk_b[i] = 0x5C;

        uint8_t pid_a1[4], pid_a2[4], pid_b[4];
        crypto_derive_pair_id(psk_a, pid_a1);
        crypto_derive_pair_id(psk_a, pid_a2);
        crypto_derive_pair_id(psk_b, pid_b);

        CHECK("5-09a pair_id_deterministic_same_psk",
              memcmp(pid_a1, pid_a2, 4) == 0);
        CHECK("5-09b pair_id_distinct_per_psk",
              memcmp(pid_a1, pid_b, 4) != 0);
        CHECK("5-09c pair_id_not_psk_prefix",
              memcmp(pid_a1, psk_a, 4) != 0);
    }

    /* 5-10: known-answer vectors.
     * Every check above holds for any domain string, so none of them notices
     * a changed or truncated one. These pin the three derivations to their
     * exact output. Changing a domain string is a wire-compatibility break
     * and must fail here rather than in the field. */
    {
        static const uint8_t want_sk[32] = {
            0xb5, 0x43, 0x46, 0x7e, 0xbe, 0x69, 0x85, 0xef,
            0xcf, 0x2a, 0xaf, 0x2e, 0x10, 0xf0, 0xf4, 0x8a,
            0x55, 0x80, 0xb7, 0xf3, 0xde, 0xd6, 0xaf, 0xcc,
            0x13, 0x98, 0xe4, 0xc7, 0xd9, 0x2d, 0x9b, 0x67,
        };
        static const uint8_t want_hk[32] = {
            0x8c, 0xe2, 0x8f, 0x08, 0x69, 0x0e, 0xcd, 0x04,
            0xaf, 0x3f, 0x31, 0x5f, 0xdf, 0x3c, 0x31, 0x59,
            0xb3, 0x51, 0x3c, 0xb1, 0xc1, 0xa7, 0x7e, 0x7b,
            0x78, 0xcc, 0x2d, 0xe4, 0x61, 0xc1, 0x27, 0x6f,
        };
        static const uint8_t want_pid[4] = { 0x1d, 0xa4, 0xd5, 0x35 };

        uint8_t sk[32], hk[32], pid[4];
        uint8_t psk_ab[32];
        for (int i = 0; i < 32; i++) psk_ab[i] = 0xAB;

        crypto_derive_session_key(psk, na, nb1, sk);
        crypto_derive_hello_key(psk, hk);
        crypto_derive_pair_id(psk_ab, pid);

        CHECK("5-10a session_key_known_answer", memcmp(sk, want_sk, 32) == 0);
        CHECK("5-10b hello_key_known_answer", memcmp(hk, want_hk, 32) == 0);
        CHECK("5-10c pair_id_known_answer", memcmp(pid, want_pid, 4) == 0);
    }
}

/* ------------------------------------------------------------------------- */
/* Group 6 — stdio transport (socketpair + execvp cat)                       */
/* ------------------------------------------------------------------------- */

/* Minimal length-framed write/read used to simulate a stream transport. */
static int write_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        p += n; len -= (size_t)n;
    }
    return 0;
}

static int read_all(int fd, void *buf, size_t len)
{
    uint8_t *p = (uint8_t *)buf;
    while (len > 0) {
        ssize_t n = read(fd, p, len);
        if (n == 0)  return -1;
        if (n < 0)   { if (errno == EINTR) continue; return -1; }
        p += n; len -= (size_t)n;
    }
    return 0;
}

static void test_group6_stdio_transport(void)
{
    /* 6-00: socketpair round-trip */
    {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
            CHECK("6-00 stdio_socketpair_round_trip", 0);
        } else {
            uint8_t pair_id[4] = { 0xAA, 0xBB, 0xCC, 0xDD };
            uint8_t ct[16] = { 0 };
            uint8_t frame[64];
            int n = frame_encode(pair_id, 1, 0x10, 0x05, ct, sizeof(ct),
                                 frame, sizeof(frame));

            uint16_t flen = (uint16_t)n;
            uint8_t fb[2] = { (uint8_t)(flen & 0xFF), (uint8_t)(flen >> 8) };
            int wok = write_all(sv[0], fb, 2) == 0
                   && write_all(sv[0], frame, (size_t)n) == 0;

            uint8_t back_len_buf[2];
            uint8_t back[64];
            int rok = read_all(sv[1], back_len_buf, 2) == 0;
            uint16_t back_len = (uint16_t)(
                (uint16_t)back_len_buf[0] |
                ((uint16_t)back_len_buf[1] << 8));
            rok = rok && back_len == flen;
            rok = rok && read_all(sv[1], back, back_len) == 0;
            int eq = memcmp(back, frame, (size_t)n) == 0;
            close(sv[0]); close(sv[1]);
            CHECK("6-00 stdio_socketpair_round_trip", wok && rok && eq);
        }
    }

    /* 6-00b: execvp("cat") echo round-trip — validates the --exec fork mechanism. */
    {
        int parent_to_child[2];
        int child_to_parent[2];
        if (pipe(parent_to_child) != 0 || pipe(child_to_parent) != 0) {
            CHECK("6-00b stdio_exec_cat_round_trip", 0);
            return;
        }
        pid_t pid = fork();
        if (pid < 0) {
            CHECK("6-00b stdio_exec_cat_round_trip", 0);
            return;
        }
        if (pid == 0) {
            /* child: dup pipes onto stdin/stdout, exec cat */
            dup2(parent_to_child[0], 0);
            dup2(child_to_parent[1], 1);
            close(parent_to_child[0]); close(parent_to_child[1]);
            close(child_to_parent[0]); close(child_to_parent[1]);
            char *argv[] = { (char *)"cat", NULL };
            execvp(argv[0], argv);
            _exit(127);
        }
        close(parent_to_child[0]);
        close(child_to_parent[1]);

        /* parent: send a frame, read it back, compare */
        uint8_t pair_id[4] = { 1, 2, 3, 4 };
        uint8_t ct[16] = { 0xA5 };
        uint8_t frame[64];
        int n = frame_encode(pair_id, 42, 0x10, 0x04, ct, sizeof(ct),
                             frame, sizeof(frame));

        int wr = write_all(parent_to_child[1], frame, (size_t)n);
        close(parent_to_child[1]);  /* signal EOF so cat exits */

        uint8_t back[64];
        int rr = read_all(child_to_parent[0], back, (size_t)n);
        close(child_to_parent[0]);
        int status = 0;
        waitpid(pid, &status, 0);

        int eq = (memcmp(back, frame, (size_t)n) == 0);
        CHECK("6-00b stdio_exec_cat_round_trip",
              wr == 0 && rr == 0 && eq && WIFEXITED(status));
    }
}

/* ------------------------------------------------------------------------- */
/* Group 7 — authenticated whole-message fragmentation                       */
/* ------------------------------------------------------------------------- */

static fragment_desc_t test_fragment_desc(uint32_t message_id,
                                          size_t total, size_t stride,
                                          uint16_t index)
{
    fragment_desc_t d;
    memset(&d, 0, sizeof(d));
    d.version = FRAGMENT_VERSION;
    d.message_id = message_id;
    d.index = index;
    d.count = (uint16_t)((total + stride - 1) / stride);
    d.total_length = (uint16_t)total;
    d.stride = (uint16_t)stride;
    size_t offset = (size_t)index * stride;
    size_t remaining = total - offset;
    d.fragment_length = (uint16_t)(remaining > stride ? stride : remaining);
    return d;
}

static int feed_test_fragment(reasm_t *r,
                              uint8_t direction, uint8_t channel, uint8_t type,
                              uint32_t message_id,
                              const uint8_t *message, size_t total, size_t stride,
                              uint16_t index, int64_t now_ms,
                              const uint8_t **out, size_t *out_len)
{
    fragment_desc_t d = test_fragment_desc(message_id, total, stride, index);
    uint8_t hash[FRAGMENT_HASH_LEN];
    crypto_fragment_hash(hash, direction, channel, type, message_id,
                         d.count, d.total_length, d.stride, message, total);
    size_t offset = (size_t)index * stride;
    int rc = reasm_feed_fragment(r, direction, channel, type,
                                 index == 0, index + 1 < d.count,
                                 &d, hash, message + offset,
                                 d.fragment_length, now_ms, REASM_TIMEOUT_MS,
                                 out, out_len);
    crypto_memzero(hash, sizeof(hash));
    return rc;
}

static void fill_pattern(uint8_t *buf, size_t len, uint8_t salt)
{
    for (size_t i = 0; i < len; i++)
        buf[i] = (uint8_t)(salt + (uint8_t)(i * 29U));
}

static void test_group7_reasm(void)
{
    /* 7-01: descriptor encoding is fixed-width little-endian. */
    {
        fragment_desc_t d = {
            .version = 1, .reserved = 0, .message_id = 0x78563412U,
            .index = 1, .count = 3, .total_length = 350,
            .stride = 174, .fragment_length = 174
        };
        uint8_t wire[FRAGMENT_DESC_LEN];
        const uint8_t want[FRAGMENT_DESC_LEN] = {
            1, 0, 0x12, 0x34, 0x56, 0x78, 1, 0, 3, 0,
            0x5e, 0x01, 0xae, 0x00, 0xae, 0x00
        };
        fragment_desc_t decoded;
        fragment_desc_encode(&d, wire);
        int rc = fragment_desc_decode(wire, &decoded);
        CHECK("7-01 fragment_descriptor_wire",
              rc == 0 && memcmp(wire, want, sizeof(want)) == 0 &&
              decoded.version == d.version &&
              decoded.reserved == d.reserved &&
              decoded.message_id == d.message_id &&
              decoded.index == d.index && decoded.count == d.count &&
              decoded.total_length == d.total_length &&
              decoded.stride == d.stride &&
              decoded.fragment_length == d.fragment_length);
    }

    /* 7-02: the clear descriptor is authenticated as extended AD. */
    {
        uint8_t key[32], ad[10 + FRAGMENT_DESC_LEN], pt[40], ct[64], out[40];
        memset(key, 0x41, sizeof(key));
        fill_pattern(ad, sizeof(ad), 3);
        fill_pattern(pt, sizeof(pt), 9);
        size_t ct_len = 0, out_len = 0;
        int enc = crypto_encrypt_ad(key, 77, 0, ad, sizeof(ad),
                                    pt, sizeof(pt), ct, &ct_len);
        int good = crypto_decrypt_ad(key, 77, 0, ad, sizeof(ad),
                                     ct, ct_len, out, &out_len);
        ad[10] ^= 1;
        int changed = crypto_decrypt_ad(key, 77, 0, ad, sizeof(ad),
                                        ct, ct_len, out, &out_len);
        int legacy = crypto_decrypt(key, 77, 0, ad, ct, ct_len,
                                    out, &out_len);
        CHECK("7-02 fragment_descriptor_is_aead_ad",
              enc == 0 && good == 0 && out_len == sizeof(pt) &&
              memcmp(out, pt, sizeof(pt)) == 0 &&
              changed != 0 && legacy != 0);
    }

    /* 7-03: complete in-order assembly delivers exactly once. */
    {
        reasm_t r; reasm_reset(&r);
        uint8_t msg[350]; fill_pattern(msg, sizeof(msg), 11);
        const uint8_t *out = NULL; size_t out_len = 0;
        int r0 = feed_test_fragment(&r, 0, 1, 4, 100, msg, sizeof(msg), 174,
                                    0, 10, &out, &out_len);
        int r1 = feed_test_fragment(&r, 0, 1, 4, 100, msg, sizeof(msg), 174,
                                    1, 11, &out, &out_len);
        int r2 = feed_test_fragment(&r, 0, 1, 4, 100, msg, sizeof(msg), 174,
                                    2, 12, &out, &out_len);
        CHECK("7-03 in_order_whole_message",
              r0 == REASM_DROP && r1 == REASM_DROP &&
              r2 == REASM_DELIVER && out_len == sizeof(msg) &&
              memcmp(out, msg, sizeof(msg)) == 0 &&
              reasm_active_count(&r) == 0);
    }

    /* 7-04: any fragment may arrive first; reverse order is byte-exact. */
    {
        reasm_t r; reasm_reset(&r);
        uint8_t msg[350]; fill_pattern(msg, sizeof(msg), 21);
        const uint8_t *out = NULL; size_t out_len = 0;
        int r2 = feed_test_fragment(&r, 0, 1, 4, 101, msg, sizeof(msg), 174,
                                    2, 10, &out, &out_len);
        int r1 = feed_test_fragment(&r, 0, 1, 4, 101, msg, sizeof(msg), 174,
                                    1, 11, &out, &out_len);
        int r0 = feed_test_fragment(&r, 0, 1, 4, 101, msg, sizeof(msg), 174,
                                    0, 12, &out, &out_len);
        CHECK("7-04 reverse_order_whole_message",
              r2 == REASM_DROP && r1 == REASM_DROP &&
              r0 == REASM_DELIVER && out_len == sizeof(msg) &&
              memcmp(out, msg, sizeof(msg)) == 0);
    }

    /* 7-05: two same-channel messages can interleave without splicing. */
    {
        reasm_t r; reasm_reset(&r);
        uint8_t a[350], b[350];
        fill_pattern(a, sizeof(a), 31); fill_pattern(b, sizeof(b), 131);
        const uint8_t *out = NULL; size_t out_len = 0;
        int ok = 1, deliveries = 0;
        int schedule[6][2] = {{0,0}, {1,0}, {0,2}, {1,1}, {0,1}, {1,2}};
        for (size_t i = 0; i < 6; i++) {
            int which = schedule[i][0];
            uint16_t index = (uint16_t)schedule[i][1];
            const uint8_t *msg = which ? b : a;
            uint32_t id = which ? 201U : 200U;
            int rc = feed_test_fragment(&r, 0, 1, 4, id, msg, 350, 174,
                                        index, (int64_t)i, &out, &out_len);
            if (rc == REASM_DELIVER) {
                deliveries++;
                ok = ok && out_len == 350 && memcmp(out, msg, 350) == 0;
            } else {
                ok = ok && rc == REASM_DROP;
            }
        }
        CHECK("7-05 same_channel_interleave_no_splice",
              ok && deliveries == 2 && reasm_active_count(&r) == 0);
    }

    /* 7-06: a missing fragment blocks only that identity; another progresses. */
    {
        reasm_t r; reasm_reset(&r);
        uint8_t a[200], b[200];
        fill_pattern(a, sizeof(a), 41); fill_pattern(b, sizeof(b), 141);
        const uint8_t *out = NULL; size_t out_len = 0;
        int a0 = feed_test_fragment(&r, 0, 1, 4, 300, a, 200, 174,
                                    0, 100, &out, &out_len);
        int b1 = feed_test_fragment(&r, 0, 1, 4, 301, b, 200, 174,
                                    1, 101, &out, &out_len);
        int b0 = feed_test_fragment(&r, 0, 1, 4, 301, b, 200, 174,
                                    0, 102, &out, &out_len);
        int b_exact = b0 == REASM_DELIVER && out_len == sizeof(b) &&
                      memcmp(out, b, sizeof(b)) == 0;
        size_t before_tick = reasm_active_count(&r);
        reasm_tick(&r, 100 + REASM_TIMEOUT_MS + 1);
        CHECK("7-06 loss_isolated_then_timeout",
              a0 == REASM_DROP && b1 == REASM_DROP && b_exact &&
              before_tick == 1 && reasm_active_count(&r) == 0);
    }

    /* 7-07: identical duplicates are idempotent and completed IDs stay done. */
    {
        reasm_t r; reasm_reset(&r);
        uint8_t msg[200]; fill_pattern(msg, sizeof(msg), 51);
        const uint8_t *out = NULL; size_t out_len = 0;
        int first = feed_test_fragment(&r, 0, 1, 4, 400, msg, 200, 174,
                                       0, 0, &out, &out_len);
        int duplicate = feed_test_fragment(&r, 0, 1, 4, 400, msg, 200, 174,
                                           0, 1, &out, &out_len);
        int final = feed_test_fragment(&r, 0, 1, 4, 400, msg, 200, 174,
                                       1, 2, &out, &out_len);
        int late = feed_test_fragment(&r, 0, 1, 4, 400, msg, 200, 174,
                                      1, 3, &out, &out_len);
        CHECK("7-07 duplicate_idempotent_no_redelivery",
              first == REASM_DROP && duplicate == REASM_DROP &&
              final == REASM_DELIVER && late == REASM_DROP &&
              out_len == sizeof(msg) && memcmp(out, msg, sizeof(msg)) == 0);
    }

    /* 7-08: conflicting bytes for one index poison only that identity. */
    {
        reasm_t r; reasm_reset(&r);
        uint8_t msg[200], bad[174], hash[FRAGMENT_HASH_LEN];
        fill_pattern(msg, sizeof(msg), 61);
        memcpy(bad, msg, sizeof(bad)); bad[7] ^= 0x80;
        fragment_desc_t d = test_fragment_desc(500, 200, 174, 0);
        crypto_fragment_hash(hash, 0, 1, 4, 500, d.count, d.total_length,
                             d.stride, msg, sizeof(msg));
        const uint8_t *out = NULL; size_t out_len = 0;
        int first = feed_test_fragment(&r, 0, 1, 4, 500, msg, 200, 174,
                                       0, 0, &out, &out_len);
        int conflict = reasm_feed_fragment(&r, 0, 1, 4, 1, 1, &d, hash,
                                           bad, sizeof(bad), 1,
                                           REASM_TIMEOUT_MS, &out, &out_len);
        int remainder = feed_test_fragment(&r, 0, 1, 4, 500, msg, 200, 174,
                                           1, 2, &out, &out_len);
        CHECK("7-08 conflicting_duplicate_poisoned",
              first == REASM_DROP && conflict == REASM_ERROR &&
              remainder == REASM_DROP && reasm_active_count(&r) == 0);
    }

    /* 7-09: descriptor/type inconsistency cannot reset another message. */
    {
        reasm_t r; reasm_reset(&r);
        uint8_t a[200], b[200], hash[FRAGMENT_HASH_LEN];
        fill_pattern(a, sizeof(a), 71); fill_pattern(b, sizeof(b), 171);
        const uint8_t *out = NULL; size_t out_len = 0;
        feed_test_fragment(&r, 0, 1, 4, 600, a, 200, 174,
                           0, 0, &out, &out_len);
        feed_test_fragment(&r, 0, 1, 4, 601, b, 200, 174,
                           0, 0, &out, &out_len);
        fragment_desc_t d = test_fragment_desc(600, 200, 174, 1);
        crypto_fragment_hash(hash, 0, 1, 5, 600, d.count, d.total_length,
                             d.stride, a, sizeof(a));
        int mismatch = reasm_feed_fragment(&r, 0, 1, 5, 0, 0, &d, hash,
                                           a + 174, 26, 1,
                                           REASM_TIMEOUT_MS, &out, &out_len);
        int bdone = feed_test_fragment(&r, 0, 1, 4, 601, b, 200, 174,
                                       1, 2, &out, &out_len);
        CHECK("7-09 mismatch_is_identity_local",
              mismatch == REASM_ERROR && bdone == REASM_DELIVER &&
              out_len == sizeof(b) && memcmp(out, b, sizeof(b)) == 0);
    }

    /* 7-10: complete byte coverage is still rejected if the whole hash fails. */
    {
        reasm_t r; reasm_reset(&r);
        uint8_t msg[200], bad_tail[26], hash[FRAGMENT_HASH_LEN];
        fill_pattern(msg, sizeof(msg), 81);
        memcpy(bad_tail, msg + 174, sizeof(bad_tail)); bad_tail[0] ^= 1;
        fragment_desc_t d0 = test_fragment_desc(700, 200, 174, 0);
        fragment_desc_t d1 = test_fragment_desc(700, 200, 174, 1);
        crypto_fragment_hash(hash, 0, 1, 4, 700, d0.count, d0.total_length,
                             d0.stride, msg, sizeof(msg));
        const uint8_t *out = NULL; size_t out_len = 0;
        int first = reasm_feed_fragment(&r, 0, 1, 4, 1, 1, &d0, hash,
                                        msg, 174, 0, REASM_TIMEOUT_MS,
                                        &out, &out_len);
        int final = reasm_feed_fragment(&r, 0, 1, 4, 0, 0, &d1, hash,
                                        bad_tail, sizeof(bad_tail), 1,
                                        REASM_TIMEOUT_MS, &out, &out_len);
        CHECK("7-10 whole_message_hash_rejects_mutation",
              first == REASM_DROP && final == REASM_ERROR &&
              reasm_active_count(&r) == 0);
    }

    /* 7-11: impossible versions, geometry and flags fail closed. */
    {
        uint8_t msg[200], hash[FRAGMENT_HASH_LEN];
        fill_pattern(msg, sizeof(msg), 91);
        const uint8_t *out = NULL; size_t out_len = 0;
        reasm_t a, b, c, dstate;
        reasm_reset(&a); reasm_reset(&b); reasm_reset(&c);
        reasm_reset(&dstate);

        fragment_desc_t bad_version = test_fragment_desc(800, 200, 174, 0);
        bad_version.version = 2;
        crypto_fragment_hash(hash, 0, 1, 4, 800, 2, 200, 174,
                             msg, sizeof(msg));
        int rv = reasm_feed_fragment(&a, 0, 1, 4, 1, 1, &bad_version, hash,
                                     msg, 174, 0, REASM_TIMEOUT_MS,
                                     &out, &out_len);

        fragment_desc_t bad_total = test_fragment_desc(801, 200, 174, 0);
        bad_total.total_length = 4097;
        int rt = reasm_feed_fragment(&b, 0, 1, 4, 1, 1, &bad_total, hash,
                                     msg, 174, 0, REASM_TIMEOUT_MS,
                                     &out, &out_len);

        fragment_desc_t bad_flags = test_fragment_desc(802, 200, 174, 1);
        int rf = reasm_feed_fragment(&c, 0, 1, 4, 1, 0, &bad_flags, hash,
                                     msg + 174, 26, 0, REASM_TIMEOUT_MS,
                                     &out, &out_len);

        fragment_desc_t bad_reserved = test_fragment_desc(803, 200, 174, 0);
        bad_reserved.reserved = 1;
        int rr = reasm_feed_fragment(&dstate, 0, 1, 4, 1, 1,
                                     &bad_reserved, hash, msg, 174, 0,
                                     REASM_TIMEOUT_MS, &out, &out_len);
        CHECK("7-11 invalid_descriptor_geometry_flags",
              rv == REASM_ERROR && rt == REASM_ERROR &&
              rf == REASM_ERROR && rr == REASM_ERROR);
    }

    /* 7-12: the fixed pool never evicts an active identity. */
    {
        reasm_t r; reasm_reset(&r);
        uint8_t messages[REASM_MAX_SLOTS][2];
        uint8_t extra[2] = {0xfe, 0xff};
        const uint8_t *out = NULL; size_t out_len = 0;
        int ok = 1;
        for (uint32_t i = 0; i < REASM_MAX_SLOTS; i++) {
            messages[i][0] = (uint8_t)(i + 1);
            messages[i][1] = (uint8_t)(0xa0U + i);
            int rc = feed_test_fragment(&r, 0, 1, 4, 901 + i,
                                        messages[i], sizeof(messages[i]),
                                        1, 0, 0,
                                        &out, &out_len);
            ok = ok && rc == REASM_DROP;
        }
        int full = feed_test_fragment(&r, 0, 1, 4, 999,
                                      extra, sizeof(extra), 1,
                                      0, 1, &out, &out_len);
        size_t active_full = reasm_active_count(&r);
        unsigned deliveries = 0;
        for (uint32_t i = 0; i < REASM_MAX_SLOTS; i++) {
            int rc = feed_test_fragment(&r, 0, 1, 4, 901 + i,
                                        messages[i], sizeof(messages[i]),
                                        1, 1, 2 + (int64_t)i,
                                        &out, &out_len);
            if (rc == REASM_DELIVER && out_len == sizeof(messages[i]) &&
                memcmp(out, messages[i], sizeof(messages[i])) == 0)
                deliveries++;
            else
                ok = 0;
        }
        int reclaimed = feed_test_fragment(&r, 0, 1, 4, 999,
                                           extra, sizeof(extra), 1, 0,
                                           100,
                                           &out, &out_len);
        CHECK("7-12 pool_bound_no_active_eviction_then_reclaim",
              ok && full == REASM_DROP && active_full == REASM_MAX_SLOTS &&
              deliveries == REASM_MAX_SLOTS && reclaimed == REASM_DROP &&
              reasm_active_count(&r) == 1);
    }

    /* 7-13: equal IDs on different channel/direction never combine. */
    {
        reasm_t r; reasm_reset(&r);
        uint8_t a[2] = {1,2}, b[2] = {3,4}, c[2] = {5,6};
        const uint8_t *out = NULL; size_t out_len = 0;
        feed_test_fragment(&r, 0, 1, 4, 1000, a, 2, 1, 0, 0, &out, &out_len);
        feed_test_fragment(&r, 0, 2, 4, 1000, b, 2, 1, 0, 0, &out, &out_len);
        feed_test_fragment(&r, 1, 1, 4, 1000, c, 2, 1, 0, 0, &out, &out_len);
        int da = feed_test_fragment(&r, 0, 1, 4, 1000, a, 2, 1, 1, 1,
                                    &out, &out_len);
        int aok = da == REASM_DELIVER && out_len == 2 && memcmp(out, a, 2) == 0;
        int db = feed_test_fragment(&r, 0, 2, 4, 1000, b, 2, 1, 1, 1,
                                    &out, &out_len);
        int bok = db == REASM_DELIVER && out_len == 2 && memcmp(out, b, 2) == 0;
        int dc = feed_test_fragment(&r, 1, 1, 4, 1000, c, 2, 1, 1, 1,
                                    &out, &out_len);
        int cok = dc == REASM_DELIVER && out_len == 2 && memcmp(out, c, 2) == 0;
        CHECK("7-13 channel_direction_identity_isolation",
              aok && bok && cok && reasm_active_count(&r) == 0);
    }

    /* 7-14: full 4096-byte boundary succeeds in reverse order (24 fragments). */
    {
        reasm_t r; reasm_reset(&r);
        uint8_t msg[REASM_MAX_BUFFER]; fill_pattern(msg, sizeof(msg), 101);
        const uint8_t *out = NULL; size_t out_len = 0;
        fragment_desc_t d = test_fragment_desc(1100, sizeof(msg), 174, 0);
        int ok = d.count == 24;
        int final_rc = REASM_DROP;
        for (int index = (int)d.count - 1; index >= 0; index--) {
            final_rc = feed_test_fragment(&r, 0, 15, 0x51, 1100,
                                          msg, sizeof(msg), 174,
                                          (uint16_t)index, 10 + index,
                                          &out, &out_len);
            if (index != 0) ok = ok && final_rc == REASM_DROP;
        }
        CHECK("7-14 max_message_reverse_order",
              ok && final_rc == REASM_DELIVER &&
              out_len == sizeof(msg) && memcmp(out, msg, sizeof(msg)) == 0);
    }

    /* 7-15: hash identity binds direction, channel, type and message id. */
    {
        uint8_t msg[32], a[32], b[32], c[32], d[32], e[32];
        fill_pattern(msg, sizeof(msg), 111);
        crypto_fragment_hash(a, 0, 1, 4, 1200, 2, 32, 16, msg, 32);
        crypto_fragment_hash(b, 1, 1, 4, 1200, 2, 32, 16, msg, 32);
        crypto_fragment_hash(c, 0, 2, 4, 1200, 2, 32, 16, msg, 32);
        crypto_fragment_hash(d, 0, 1, 5, 1200, 2, 32, 16, msg, 32);
        crypto_fragment_hash(e, 0, 1, 4, 1201, 2, 32, 16, msg, 32);
        CHECK("7-15 hash_binds_logical_identity",
              memcmp(a,b,32) != 0 && memcmp(a,c,32) != 0 &&
              memcmp(a,d,32) != 0 && memcmp(a,e,32) != 0);
    }
}

/* ------------------------------------------------------------------------- */
/* Group 8 — NEG1 capability grammar and transcript KDF                       */
/* ------------------------------------------------------------------------- */

static void test_group8_negotiation(void)
{
    uint8_t na[16], nb[16];
    for (size_t i = 0; i < sizeof(na); i++) {
        na[i] = (uint8_t)i;
        nb[i] = (uint8_t)(0x80U + i);
    }

    /* 8-01: the old all-zero-reserved payload remains an exact legacy
     * grammar and maps only its historical PTY bit. */
    {
        uint8_t plain[NEGOTIATION_PLAIN_LEN];
        negotiation_message_t msg;
        negotiation_encode_legacy(plain, na, 0x01);
        uint16_t rc = negotiation_decode(plain, sizeof(plain), 0, &msg);
        CHECK("8-01 legacy_zero_reserved_round_trip",
              rc == 0 && msg.kind == NEGOTIATION_LEGACY &&
              msg.supported_caps == UNMOOR_CAP_PTY_V1 &&
              memcmp(msg.nonce, na, sizeof(na)) == 0);
    }

    /* 8-02: canonical NEG1 layout is fixed at 32 bytes. Pins the CURRENT
     * default supported mask (pty|fragment|pty-sync|status|latest|reliable
     * = 0x77) in both the caps8 mirror (0x80|0x77) and the LE word at
     * offset 18 — a silent change to the default offer fails here first. */
    {
        static const uint8_t want[NEGOTIATION_PLAIN_LEN] = {
            0x03,0xf7,0x00,0x01,0x02,0x03,0x04,0x05,
            0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,
            0x0e,0x0f,0x77,0x00,0x00,0x00,0x01,0x00,
            0x00,0x00,0x00,0x00,0x4e,0x45,0x47,0x31,
        };
        uint8_t plain[NEGOTIATION_PLAIN_LEN];
        negotiation_message_t msg;
        negotiation_encode_hello(plain, na,
                                 UNMOOR_CAP_DEFAULT_SUPPORTED,
                                 UNMOOR_CAP_DEFAULT_REQUIRED);
        uint16_t rc = negotiation_decode(plain, sizeof(plain), 0, &msg);
        CHECK("8-02 neg1_canonical_layout",
              memcmp(plain, want, sizeof(want)) == 0 && rc == 0 &&
              msg.kind == NEGOTIATION_NEG1 &&
              msg.supported_caps == UNMOOR_CAP_DEFAULT_SUPPORTED &&
              msg.required_caps == UNMOOR_CAP_DEFAULT_REQUIRED);
    }

    /* 8-03..05: marker and grammar cannot partially fall back to legacy. */
    {
        uint8_t plain[NEGOTIATION_PLAIN_LEN];
        negotiation_message_t msg;
        negotiation_encode_hello(plain, na, 3, 1);
        plain[31] = '2';
        CHECK("8-03 unknown_neg2_is_version_error",
              negotiation_decode(plain, sizeof(plain), 0, &msg) == ERR_VERSION);
        negotiation_encode_hello(plain, na, 3, 1);
        plain[1] &= (uint8_t)~NEGOTIATION_MARKER_BIT;
        CHECK("8-04 marker_missing_never_falls_back",
              negotiation_decode(plain, sizeof(plain), 0, &msg) == ERR_VERSION);
        negotiation_encode_legacy(plain, na, 1);
        plain[18] = 1;
        CHECK("8-05 legacy_reserved_nonzero_rejected",
              negotiation_decode(plain, sizeof(plain), 0, &msg) == ERR_VERSION);
    }

    /* A previous protocol version is incompatible in either direction. */
    {
        uint8_t plain[NEGOTIATION_PLAIN_LEN];
        negotiation_message_t msg;
        negotiation_encode_hello(plain, na,
                                 UNMOOR_CAP_DEFAULT_SUPPORTED,
                                 UNMOOR_CAP_DEFAULT_REQUIRED);
        plain[0] = (uint8_t)(NEGOTIATION_HELLO_VERSION - 1U);
        uint16_t hello_rc = negotiation_decode(plain, sizeof(plain), 0, &msg);
        uint16_t ack_rc = negotiation_decode(plain, sizeof(plain), 1, &msg);
        CHECK("8-05a previous_wire_version_is_incompatible",
              hello_rc == ERR_VERSION && ack_rc == ERR_VERSION);
    }

    /* 8-06..08: redundant low bits, required subset, and HELLO status are
     * canonical rather than advisory. */
    {
        uint8_t plain[NEGOTIATION_PLAIN_LEN];
        negotiation_message_t msg;
        negotiation_encode_hello(plain, na, 3, 1);
        plain[1] ^= 0x02;
        CHECK("8-06 low_cap_mirror_mismatch_rejected",
              negotiation_decode(plain, sizeof(plain), 0, &msg) == ERR_CAPS);
        negotiation_encode_hello(plain, na, 1, 3);
        CHECK("8-07 required_not_supported_rejected",
              negotiation_decode(plain, sizeof(plain), 0, &msg) == ERR_CAPS);
        negotiation_encode_ack(plain, na, 3, 1, ERR_CAPS);
        CHECK("8-08 nonzero_hello_status_rejected",
              negotiation_decode(plain, sizeof(plain), 0, &msg) == ERR_CAPS);
    }

    /* 8-09..12: exact intersection, optional downgrade, unknown optional
     * removal, and a required mismatch. */
    {
        uint8_t plain[NEGOTIATION_PLAIN_LEN];
        negotiation_message_t msg;
        uint32_t selected = 0;
        negotiation_encode_hello(plain, na, 3, 1);
        uint16_t dec = negotiation_decode(plain, sizeof(plain), 0, &msg);
        uint16_t full = negotiation_select(&msg, 3, 1, &selected);
        CHECK("8-09 full_capability_intersection",
              dec == 0 && full == 0 && selected == 3);
        uint16_t base = negotiation_select(&msg, 1, 1, &selected);
        CHECK("8-10 optional_fragment_downgrades_to_baseline",
              base == 0 && selected == 1);
        negotiation_encode_hello(plain, na, UINT32_C(0x80000003), 1);
        dec = negotiation_decode(plain, sizeof(plain), 0, &msg);
        uint16_t unknown = negotiation_select(&msg, 3, 1, &selected);
        CHECK("8-11 unknown_optional_intersects_away",
              dec == 0 && unknown == 0 && selected == 3);
        negotiation_encode_hello(plain, na, 3, 3);
        dec = negotiation_decode(plain, sizeof(plain), 0, &msg);
        uint16_t missing = negotiation_select(&msg, 1, 1, &selected);
        CHECK("8-12 required_capability_mismatch",
              dec == 0 && missing == ERR_CAPS && selected == 1);
    }

    /* 8-13..14: ACK cannot select an unoffered capability and an explicit
     * refusal remains distinguishable from malformed grammar. */
    {
        uint8_t plain[NEGOTIATION_PLAIN_LEN];
        negotiation_message_t msg;
        uint32_t selected = 0;
        negotiation_encode_ack(plain, nb, 3, 1, 0);
        uint16_t dec = negotiation_decode(plain, sizeof(plain), 1, &msg);
        uint16_t rc = negotiation_validate_ack(&msg, 1, 1, &selected);
        CHECK("8-13 ack_selected_unoffered_rejected",
              dec == 0 && rc == ERR_CAPS && selected == 3);
        negotiation_encode_ack(plain, nb, 1, 1, ERR_CAPS);
        dec = negotiation_decode(plain, sizeof(plain), 1, &msg);
        rc = negotiation_validate_ack(&msg, 3, 1, &selected);
        CHECK("8-14 authenticated_caps_refusal",
              dec == 0 && rc == ERR_CAPS && selected == 1);
    }

    /* 8-15..17: structured READY pins the selected tuple and has only one
     * defined flag; both request and acknowledgement forms are valid. */
    {
        uint8_t ready[NEGOTIATION_READY_LEN];
        uint8_t flags = 0xff;
        negotiation_ready_encode(ready, NEGOTIATION_READY_NEED_ACK, 3);
        int need = negotiation_ready_decode(ready, sizeof(ready), 3, &flags);
        CHECK("8-15 ready_need_ack_round_trip",
              need == 0 && flags == NEGOTIATION_READY_NEED_ACK);
        negotiation_ready_encode(ready, 0, 3);
        int ack = negotiation_ready_decode(ready, sizeof(ready), 3, &flags);
        CHECK("8-16 ready_ack_round_trip", ack == 0 && flags == 0);
        ready[4] ^= 0x02;
        CHECK("8-17 ready_selected_tuple_mismatch",
              negotiation_ready_decode(ready, sizeof(ready), 3, &flags) != 0);
    }

    /* 8-18..20: pin the exact transcript KDF and prove that either transcript
     * or the selected mask changes the key. */
    {
        static const uint8_t want[32] = {
            0xca,0x71,0xac,0xf4,0xd4,0x0b,0x2c,0x24,
            0xed,0x06,0xa3,0x2c,0x47,0x16,0x0a,0xe3,
            0x42,0xa4,0x54,0x60,0xe6,0xb1,0x6d,0xb9,
            0xbc,0x79,0x72,0xa4,0x55,0xa8,0xc0,0x70,
        };
        uint8_t psk[32], hello[32], ack[32];
        uint8_t k1[32], k2[32], k3[32], legacy[32];
        for (size_t i = 0; i < sizeof(psk); i++)
            psk[i] = (uint8_t)(i * 7U + 3U);
        negotiation_encode_hello(hello, na, 3, 1);
        negotiation_encode_ack(ack, nb, 3, 1, 0);
        crypto_derive_negotiated_session_key(psk, hello, ack, 3, k1);
        CHECK("8-18 negotiated_kdf_known_answer",
              memcmp(k1, want, sizeof(want)) == 0);
        ack[2] ^= 1;
        crypto_derive_negotiated_session_key(psk, hello, ack, 3, k2);
        ack[2] ^= 1;
        crypto_derive_negotiated_session_key(psk, hello, ack, 1, k3);
        crypto_derive_session_key(psk, na, nb, legacy);
        CHECK("8-19 negotiated_kdf_binds_transcript_and_selection",
              memcmp(k1, k2, 32) != 0 && memcmp(k1, k3, 32) != 0);
        CHECK("8-20 negotiated_kdf_distinct_from_legacy",
              memcmp(k1, legacy, 32) != 0);
    }

    /* 8-21..22: the epoch-rekey bit has one exact service dependency in either
     * direction.  Neither endpoint may create a control-only or legacy-PTY
     * interpretation of the same authenticated capability bit. */
    {
        const uint32_t d28 = UNMOOR_CAP_EPOCH_REKEY_D28_V1;
        const uint32_t full = UNMOOR_CAP_PTY_V1 |
                              UNMOOR_CAP_PTY_SYNC_V1 | d28;
        uint8_t plain[NEGOTIATION_PLAIN_LEN];
        negotiation_message_t msg;
        uint32_t selected = 0;
        negotiation_encode_hello(plain, na, d28, d28);
        uint16_t dec = negotiation_decode(plain, sizeof(plain), 0, &msg);
        uint16_t bad_offer = negotiation_select(&msg, d28, d28, &selected);
        CHECK("8-21 d28_without_sync_dependency_rejected",
              dec == 0 && bad_offer == ERR_CAPS && selected == d28);

        negotiation_encode_ack(plain, nb, d28, d28, 0);
        dec = negotiation_decode(plain, sizeof(plain), 1, &msg);
        uint16_t bad_ack = negotiation_validate_ack(&msg, full, d28,
                                                    &selected);
        negotiation_encode_ack(plain, nb, full, full, 0);
        dec |= negotiation_decode(plain, sizeof(plain), 1, &msg);
        uint16_t good_ack = negotiation_validate_ack(&msg, full, full,
                                                     &selected);
        CHECK("8-22 d28_full_dependency_tuple_accepted",
              bad_ack == ERR_CAPS && dec == 0 && good_ack == 0 &&
              selected == full);
    }

    /* 8-23..24: status names the terminal-state-sync terminal stream and cannot be selected
     * as a generic heartbeat without both PTY and PTY_SYNC. */
    {
        const uint32_t status = UNMOOR_CAP_STATUS_HEARTBEAT_V1;
        const uint32_t full = UNMOOR_CAP_PTY_V1 |
                              UNMOOR_CAP_PTY_SYNC_V1 | status;
        uint8_t plain[NEGOTIATION_PLAIN_LEN];
        negotiation_message_t msg;
        uint32_t selected = 0;
        negotiation_encode_hello(plain, na, status, status);
        uint16_t dec = negotiation_decode(plain, sizeof(plain), 0, &msg);
        uint16_t bad_offer = negotiation_select(&msg, status, status,
                                                &selected);
        CHECK("8-23 status_without_sync_dependency_rejected",
              dec == 0 && bad_offer == ERR_CAPS && selected == status);

        negotiation_encode_ack(plain, nb, full, full, 0);
        dec = negotiation_decode(plain, sizeof(plain), 1, &msg);
        uint16_t good_ack = negotiation_validate_ack(&msg, full, full,
                                                     &selected);
        CHECK("8-24 status_full_dependency_tuple_accepted",
              dec == 0 && good_ack == 0 && selected == full);
    }

    /* 8-25..27: delivery-class's two exact grammars are independently optional,
     * intersect away for an older peer, and fail closed when required. */
    {
        const uint32_t latest = UNMOOR_CAP_LATEST_BLOCK_D31_V1;
        const uint32_t rd = UNMOOR_CAP_RELIABLE_DGRAM_D31_V1;
        const uint32_t both = latest | rd;
        uint8_t plain[NEGOTIATION_PLAIN_LEN];
        negotiation_message_t msg;
        uint32_t selected = 0;

        negotiation_encode_hello(plain, na,
                                 UNMOOR_CAP_PTY_V1 | both,
                                 UNMOOR_CAP_PTY_V1);
        uint16_t dec = negotiation_decode(plain, sizeof(plain), 0, &msg);
        uint16_t full = negotiation_select(
            &msg, UNMOOR_CAP_PTY_V1 | both, UNMOOR_CAP_PTY_V1, &selected);
        CHECK("8-25 d31_exact_optional_bits_select",
              dec == 0 && full == 0 &&
              selected == (UNMOOR_CAP_PTY_V1 | both));

        uint16_t old = negotiation_select(
            &msg, UNMOOR_CAP_PTY_V1, UNMOOR_CAP_PTY_V1, &selected);
        CHECK("8-26 d31_optional_bits_intersect_away",
              old == 0 && selected == UNMOOR_CAP_PTY_V1);

        negotiation_encode_hello(plain, na,
                                 UNMOOR_CAP_PTY_V1 | latest,
                                 UNMOOR_CAP_PTY_V1 | latest);
        dec = negotiation_decode(plain, sizeof(plain), 0, &msg);
        uint16_t missing = negotiation_select(
            &msg, UNMOOR_CAP_PTY_V1,
            UNMOOR_CAP_PTY_V1, &selected);
        CHECK("8-27 d31_required_bit_missing_refused",
              dec == 0 && missing == ERR_CAPS &&
              selected == UNMOOR_CAP_PTY_V1);
    }

    /* 8-28..32: multipath is the first exact capability above the legacy
     * low-seven mirror. NEG1's marker byte remains unchanged while the
     * authenticated full 32-bit masks carry and require bit 0x80. */
    {
        const uint32_t mp = UNMOOR_CAP_MULTIPATH_D32_V1;
        const uint32_t full = UNMOOR_CAP_PTY_V1 | mp;
        uint8_t plain[NEGOTIATION_PLAIN_LEN];
        negotiation_message_t msg;
        uint32_t selected = 0;

        negotiation_encode_hello(plain, na, full, full);
        uint16_t dec = negotiation_decode(plain, sizeof(plain), 0, &msg);
        CHECK("8-28 d32_full_mask_survives_low_seven_mirror",
              dec == 0 && plain[1] == 0x81U &&
              msg.supported_caps == full && msg.required_caps == full);
        uint16_t ok = negotiation_select(&msg, full, full, &selected);
        CHECK("8-29 d32_exact_required_bit_selects",
              ok == 0 && selected == full);
        uint16_t missing = negotiation_select(
            &msg, UNMOOR_CAP_PTY_V1, UNMOOR_CAP_PTY_V1, &selected);
        CHECK("8-30 d32_required_bit_missing_refused",
              missing == ERR_CAPS && selected == UNMOOR_CAP_PTY_V1);

        negotiation_encode_hello(plain, na, full,
                                 UNMOOR_CAP_PTY_V1);
        dec = negotiation_decode(plain, sizeof(plain), 0, &msg);
        uint16_t optional_old = negotiation_select(
            &msg, UNMOOR_CAP_PTY_V1, UNMOOR_CAP_PTY_V1, &selected);
        CHECK("8-31 d32_optional_peer_bit_intersects_away exactly",
              dec == 0 && optional_old == 0 &&
              selected == UNMOOR_CAP_PTY_V1);

        negotiation_encode_ack(plain, nb, UNMOOR_CAP_PTY_V1,
                               UNMOOR_CAP_PTY_V1, 0);
        dec = negotiation_decode(plain, sizeof(plain), 1, &msg);
        uint16_t missing_ack = negotiation_validate_ack(
            &msg, full, full, &selected);
        CHECK("8-32 d32_required_client_rejects_absent_ack_bit",
              dec == 0 && missing_ack == ERR_CAPS &&
              selected == UNMOOR_CAP_PTY_V1);
    }

    /* 8-33..36: scaled multipath spends one exact authenticated bit per supported
     * power-of-two. The five counts never negotiate a minimum and two bits in
     * one tuple are noncanonical. */
    {
        static const unsigned int count[5] = { 2U, 4U, 8U, 16U, 32U };
        static const uint32_t cap[5] = {
            UNMOOR_CAP_MULTIPATH_2_D32_V1,
            UNMOOR_CAP_MULTIPATH_4_D32_V1,
            UNMOOR_CAP_MULTIPATH_8_D32_V1,
            UNMOOR_CAP_MULTIPATH_16_D32_V1,
            UNMOOR_CAP_MULTIPATH_32_D32_V1,
        };
        uint8_t plain[NEGOTIATION_PLAIN_LEN];
        negotiation_message_t msg;
        uint32_t selected = 0U;
        uint8_t decoded_count = 0xffU;
        unsigned int i;
        unsigned int j;
        int mapping_ok = 1;
        int matrix_ok = 1;

        for (i = 0U; i < 5U; i++) {
            if (negotiation_multipath_capability(count[i]) != cap[i] ||
                negotiation_multipath_path_count(cap[i], &decoded_count) != 0 ||
                decoded_count != count[i])
                mapping_ok = 0;
        }
        CHECK("8-33 d32_power_of_two_counts_have_exact_one_hot_identities",
              mapping_ok &&
              negotiation_multipath_capability(1U) == 0U &&
              negotiation_multipath_capability(3U) == 0U &&
              negotiation_multipath_capability(64U) == 0U &&
              negotiation_multipath_path_count(0U, &decoded_count) == 0 &&
              decoded_count == 0U);

        for (i = 0U; i < 5U; i++) {
            for (j = 0U; j < 5U; j++) {
                uint32_t offered = UNMOOR_CAP_PTY_V1 | cap[i];
                uint32_t local = UNMOOR_CAP_PTY_V1 | cap[j];
                uint16_t rc;

                negotiation_encode_hello(plain, na, offered, offered);
                if (negotiation_decode(plain, sizeof(plain), 0, &msg) != 0) {
                    matrix_ok = 0;
                    continue;
                }
                rc = negotiation_select(&msg, local, local, &selected);
                if (i == j) {
                    if (rc != 0 || selected != offered)
                        matrix_ok = 0;
                } else if (rc != ERR_CAPS ||
                           selected != UNMOOR_CAP_PTY_V1) {
                    matrix_ok = 0;
                }
            }
        }
        CHECK("8-34 all_twenty_five_d32_count_pairs_select_only_exact_diagonal",
              matrix_ok);

        decoded_count = 0U;
        CHECK("8-35 multiple_d32_count_bits_are_noncanonical",
              negotiation_multipath_path_count(cap[0] | cap[4],
                                               &decoded_count) != 0 &&
              decoded_count == 0U);
        negotiation_encode_hello(plain, na,
                                 UNMOOR_CAP_PTY_V1 | cap[0] | cap[4],
                                 UNMOOR_CAP_PTY_V1);
        CHECK("8-36 selection_rejects_authenticated_multi_count_tuple",
              negotiation_decode(plain, sizeof(plain), 0, &msg) == 0 &&
              negotiation_select(
                  &msg, UNMOOR_CAP_PTY_V1 | cap[0] | cap[4],
                  UNMOOR_CAP_PTY_V1, &selected) == ERR_CAPS);
        CHECK("8-37 intersection_cannot_sanitize_a_multi_count_peer_offer",
              negotiation_select(
                  &msg, UNMOOR_CAP_PTY_V1 | cap[0],
                  UNMOOR_CAP_PTY_V1, &selected) == ERR_CAPS);

        negotiation_encode_ack(plain, nb,
                               UNMOOR_CAP_PTY_V1 | cap[0],
                               UNMOOR_CAP_PTY_V1, 0);
        CHECK("8-38 local_multi_count_offer_cannot_be_sanitized_by_ack",
              negotiation_decode(plain, sizeof(plain), 1, &msg) == 0 &&
              negotiation_validate_ack(
                  &msg, UNMOOR_CAP_PTY_V1 | cap[0] | cap[4],
                  UNMOOR_CAP_PTY_V1, &selected) == ERR_CAPS);
    }

    /* 8-39..46: channel-session leaves the reserved bit empty, binds every kind to one
     * exact base grammar, and never sanitizes an explicitly required channel
     * session into a legacy profile. */
    {
        const uint32_t base = UNMOOR_CAP_CHANNEL_SESSION_D36_V1;
        const uint32_t terminal = UNMOOR_CAP_CHANNEL_TERMINAL_D36_V1;
        const uint32_t terminal_deps = UNMOOR_CAP_PTY_V1 |
            UNMOOR_CAP_FRAGMENT_D21_V1 | UNMOOR_CAP_PTY_SYNC_V1;
        const uint32_t terminal_bundle = base | terminal | terminal_deps;
        const uint32_t exec_bundle = base | UNMOOR_CAP_CHANNEL_EXEC_D36_V1;
        const uint32_t withdrawn_bulk_bits = UINT32_C(0x00060000);
        uint8_t plain[NEGOTIATION_PLAIN_LEN];
        negotiation_message_t msg;
        uint32_t selected = 0U;

        CHECK("8-39 d36_allocations_preserve_p020_gap",
              base == UINT32_C(0x00004000) &&
              terminal == UINT32_C(0x00008000) &&
              UNMOOR_CAP_CHANNEL_EXEC_D36_V1 == UINT32_C(0x00010000) &&
              UNMOOR_CAP_CHANNEL_KINDS_D36_MASK ==
                  (terminal | UNMOOR_CAP_CHANNEL_EXEC_D36_V1) &&
              ((base | UNMOOR_CAP_CHANNEL_KINDS_D36_MASK) &
                  (UINT32_C(0x00002000) | withdrawn_bulk_bits)) == 0U);

        negotiation_encode_hello(plain, na, base, base);
        CHECK("8-40 d36_base_without_kind_is_noncanonical",
              negotiation_decode(plain, sizeof(plain), 0, &msg) == 0 &&
              negotiation_select(&msg, base, base, &selected) == ERR_CAPS);

        negotiation_encode_hello(plain, na, terminal, terminal);
        CHECK("8-41 d36_kind_without_base_is_noncanonical",
              negotiation_decode(plain, sizeof(plain), 0, &msg) == 0 &&
              negotiation_select(&msg, terminal, terminal,
                                 &selected) == ERR_CAPS);

        negotiation_encode_hello(plain, na, terminal_bundle,
                                 terminal_bundle);
        CHECK("8-42 d36_terminal_exact_dependency_selects",
              negotiation_decode(plain, sizeof(plain), 0, &msg) == 0 &&
              negotiation_select(&msg, terminal_bundle, terminal_bundle,
                                 &selected) == 0 &&
              selected == terminal_bundle);

        negotiation_encode_hello(
            plain, na,
            terminal_bundle | UNMOOR_CAP_STATUS_HEARTBEAT_V1,
            terminal_bundle);
        CHECK("8-42A d29_status_is_optional_beside_required_d36_d26",
              negotiation_decode(plain, sizeof(plain), 0, &msg) == 0 &&
              negotiation_select(
                  &msg,
                  terminal_bundle | UNMOOR_CAP_STATUS_HEARTBEAT_V1,
                  terminal_bundle, &selected) == 0 &&
              selected ==
                  (terminal_bundle | UNMOOR_CAP_STATUS_HEARTBEAT_V1));

        negotiation_encode_hello(plain, na, exec_bundle, exec_bundle);
        CHECK("8-43 d36_exec_is_a_closed_independent_kind",
              negotiation_decode(plain, sizeof(plain), 0, &msg) == 0 &&
              negotiation_select(&msg, exec_bundle, exec_bundle,
                                 &selected) == 0 && selected == exec_bundle);

        negotiation_encode_hello(
            plain, na, terminal_bundle | withdrawn_bulk_bits,
            terminal_bundle);
        CHECK("8-44 withdrawn_optional_d36_bulk_bits_intersect_away",
              negotiation_decode(plain, sizeof(plain), 0, &msg) == 0 &&
              negotiation_select(&msg, terminal_bundle, terminal_bundle,
                                 &selected) == 0 &&
              selected == terminal_bundle);

        negotiation_encode_hello(plain, na,
            terminal_bundle | UNMOOR_CAP_LATEST_BLOCK_D31_V1,
            terminal_bundle);
        CHECK("8-45 d36_class2_is_incompatible_until_a_kind_exists",
              negotiation_decode(plain, sizeof(plain), 0, &msg) == 0 &&
              negotiation_select(&msg,
                  terminal_bundle | UNMOOR_CAP_LATEST_BLOCK_D31_V1,
                  terminal_bundle, &selected) == ERR_CAPS);

        negotiation_encode_hello(plain, na, terminal_bundle,
                                 base | terminal);
        CHECK("8-46 required_d36_never_falls_back_to_old_pty",
              negotiation_decode(plain, sizeof(plain), 0, &msg) == 0 &&
              negotiation_select(&msg, terminal_deps, UNMOOR_CAP_PTY_V1,
                                 &selected) == ERR_CAPS &&
              selected == terminal_deps);

        for (unsigned int bit = 0U; bit < 3U; bit++) {
            const uint32_t dep[3] = {
                UNMOOR_CAP_PTY_V1, UNMOOR_CAP_FRAGMENT_D21_V1,
                UNMOOR_CAP_PTY_SYNC_V1
            };
            char name[96];
            uint32_t incomplete = terminal_bundle & ~dep[bit];

            (void)snprintf(name, sizeof(name),
                           "8-47.%u d36_terminal_rejects_missing_dependency",
                           bit + 1U);
            negotiation_encode_hello(plain, na, incomplete, incomplete);
            CHECK(name,
                  negotiation_decode(plain, sizeof(plain), 0, &msg) == 0 &&
                  negotiation_select(&msg, incomplete, incomplete,
                                     &selected) == ERR_CAPS);
        }

        negotiation_encode_hello(
            plain, na, terminal_bundle | withdrawn_bulk_bits,
            terminal_bundle | UINT32_C(0x00020000));
        CHECK("8-48 required_withdrawn_d36_bulk_bit_fails_loudly",
              negotiation_decode(plain, sizeof(plain), 0, &msg) == 0 &&
              negotiation_select(&msg, terminal_bundle, terminal_bundle,
                                 &selected) == ERR_CAPS);
    }

    /* 8-49..54: pq-hybrid is an exact epoch-rekey-dependent identity.  Prefer may
     * intersect it away only when the peer never offered it; require cannot.
     * Once both authenticated offers select it, changing either the
     * transcript bit or selected mask derives a different READY key, so the
     * attempted downgrade fails authentication rather than becoming v1. */
    {
        const uint32_t d28 = UNMOOR_CAP_EPOCH_REKEY_D28_V1;
        const uint32_t pq = UNMOOR_CAP_PQ_HYBRID_D45_V1;
        const uint32_t base = UNMOOR_CAP_DEFAULT_SUPPORTED | d28;
        const uint32_t hybrid = base | pq;
        uint8_t hello[NEGOTIATION_PLAIN_LEN];
        uint8_t ack[NEGOTIATION_PLAIN_LEN];
        uint8_t ready[NEGOTIATION_READY_LEN];
        uint8_t ciphertext[NEGOTIATION_READY_LEN + 16U];
        uint8_t decoded[NEGOTIATION_READY_LEN];
        uint8_t ad[10];
        uint8_t pq_key[32], changed_transcript_key[32], fallback_key[32];
        size_t ciphertext_len = 0U, decoded_len = 0U;
        negotiation_message_t msg;
        uint32_t selected = 0U;
        uint16_t rc;

        negotiation_encode_hello(hello, na, pq, pq);
        CHECK("8-49 d45_without_d28_dependency_is_noncanonical",
              negotiation_decode(hello, sizeof(hello), 0, &msg) == 0 &&
              negotiation_select(&msg, pq | d28, pq | d28,
                                 &selected) == ERR_CAPS);

        negotiation_encode_hello(hello, na, hybrid, base);
        rc = negotiation_decode(hello, sizeof(hello), 0, &msg);
        rc |= negotiation_select(&msg, base, base, &selected);
        CHECK("8-50 prefer_intersects_unoffered_d45_to_classical_bundle",
              rc == 0 && selected == base);

        negotiation_encode_hello(hello, na, hybrid, hybrid);
        rc = negotiation_decode(hello, sizeof(hello), 0, &msg);
        rc |= negotiation_select(&msg, base, base, &selected);
        CHECK("8-51 required_d45_refuses_classical_only_peer",
              rc == ERR_CAPS && selected == base);

        negotiation_encode_hello(hello, na, hybrid, hybrid);
        rc = negotiation_decode(hello, sizeof(hello), 0, &msg);
        rc |= negotiation_select(&msg, hybrid, hybrid, &selected);
        CHECK("8-52 mutual_d45_selects_the_exact_hybrid_bundle",
              rc == 0 && selected == hybrid);

        negotiation_encode_ack(ack, nb, base, base, 0);
        rc = negotiation_decode(ack, sizeof(ack), 1, &msg);
        rc |= negotiation_validate_ack(&msg, hybrid, hybrid, &selected);
        CHECK("8-53 d45_offer_rejects_ack_that_removes_the_required_bit",
              rc == ERR_CAPS && selected == base);

        negotiation_encode_hello(hello, na, hybrid, hybrid);
        negotiation_encode_ack(ack, nb, hybrid, hybrid, 0);
        crypto_derive_negotiated_session_key(
            (const uint8_t[32]){ 1U }, hello, ack, hybrid, pq_key);
        hello[20] ^= 0x08U; /* bit 19: PQ_HYBRID_D45_V1 */
        crypto_derive_negotiated_session_key(
            (const uint8_t[32]){ 1U }, hello, ack, hybrid,
            changed_transcript_key);
        hello[20] ^= 0x08U;
        crypto_derive_negotiated_session_key(
            (const uint8_t[32]){ 1U }, hello, ack, base, fallback_key);
        negotiation_ready_encode(ready, 0U, hybrid);
        build_ad((const uint8_t[4]){ 2U }, 7U, CHAN_FF_BIT, 0x04U, ad);
        CHECK("8-54 tampered_d45_mask_cannot_authenticate_as_fallback",
              crypto_encrypt(pq_key, 7U, 0U, ad, ready, sizeof(ready),
                             ciphertext, &ciphertext_len) == 0 &&
              crypto_decrypt(changed_transcript_key, 7U, 0U, ad,
                             ciphertext, ciphertext_len,
                             decoded, &decoded_len) != 0 &&
              crypto_decrypt(fallback_key, 7U, 0U, ad,
                             ciphertext, ciphertext_len,
                             decoded, &decoded_len) != 0);
        crypto_memzero(pq_key, sizeof(pq_key));
        crypto_memzero(changed_transcript_key,
                       sizeof(changed_transcript_key));
        crypto_memzero(fallback_key, sizeof(fallback_key));
    }
}

/* ------------------------------------------------------------------------- */
/* main                                                                      */
/* ------------------------------------------------------------------------- */

int main(void)
{
    printf("frame_test starting\n");
    test_group2_frames();
    test_group3_aead();
    test_group4_replay();
    test_group5_kdf();
    test_group6_stdio_transport();
    test_group7_reasm();
    test_group8_negotiation();
    printf("\n%d tests, %d failed\n", g_total, g_failed);
    return g_failed == 0 ? 0 : 1;
}
