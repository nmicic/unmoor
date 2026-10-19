/*
 * session_key_gate_test.c — key-liveness gate on the receive path
 *
 * A session owns three AEAD key buffers: the bootstrap hello key, the
 * session key and the pending-epoch key. Each is all zero until a KDF fills
 * it and again after it is wiped. These tests pin the rule that the receive
 * path never selects a buffer that holds no live key, because an all-zero
 * key authenticates anything built with it, and that the AEAD wrappers
 * refuse such a key outright. They also pin that the pair id, not the frame
 * type, selects the key: a pending-pair control frame is verified under the
 * pending key alone even while the hello key is live. Under a live key they
 * also pin the replay window, which is all that stops an authenticated
 * datagram from being accepted twice.
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */

#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "crypto.h"
#include "frame.h"
#include "monocypher.h"
#include "multipath.h"
#include "session.h"

static int total;
static int failed;

#define CHECK(name, condition) do {                                      \
    total++;                                                             \
    if (!(condition)) {                                                  \
        failed++;                                                        \
        fprintf(stderr, "FAIL %s (%s:%d)\n", name, __FILE__, __LINE__); \
    } else {                                                             \
        printf("PASS %s\n", name);                                     \
    }                                                                    \
} while (0)

typedef struct {
    transport_t base;
    unsigned int sends;
    unsigned int peer_confirms;
} capture_transport_t;

static int capture_send(transport_t *base, const uint8_t *data, size_t len)
{
    capture_transport_t *capture = (capture_transport_t *)base;

    if (!data || len == 0U)
        return -1;
    capture->sends++;
    return 0;
}

static int capture_send_step(transport_t *base, const uint8_t *data,
                             size_t len)
{
    return capture_send(base, data, len) == 0
        ? TRANSPORT_SEND_COMPLETE : TRANSPORT_SEND_FAILED;
}

static int capture_peer_confirm(transport_t *base)
{
    capture_transport_t *capture = (capture_transport_t *)base;

    capture->peer_confirms++;
    return 0;
}

static const transport_ops_t capture_ops = {
    .name = "key-gate-capture",
    .send = capture_send,
    .send_step = capture_send_step,
    .peer_confirm = capture_peer_confirm,
};

static const uint8_t zero_key[32];

static void fill_key(uint8_t key[32], uint8_t seed)
{
    for (int i = 0; i < 32; i++)
        key[i] = (uint8_t)(seed ^ (uint8_t)(i * 13));
}

static session_t *fixture_create(capture_transport_t *capture,
                                 const uint8_t pair[4], int is_server,
                                 int state)
{
    uint8_t psk[32];
    session_t *session;

    fill_key(psk, 0x90U);
    memset(capture, 0, sizeof(*capture));
    capture->base.ops = &capture_ops;
    session = session_create(&capture->base, psk, pair);
    if (!session)
        return NULL;
    session->is_server = is_server;
    session->state = state;
    session->last_authenticated_ms = 1234;
    return session;
}

static multipath_token_t token4(uint16_t port, uint8_t last)
{
    const uint8_t address[4] = { 192U, 0U, 2U, last };
    multipath_token_t token;

    if (multipath_token_init(&token, 0U, 4U, port, 0U,
                             address, sizeof(address)) != 0)
        memset(&token, 0, sizeof(token));
    return token;
}

static void build_ad(uint8_t ad[10], const uint8_t pair[4], uint32_t seq,
                     uint8_t type)
{
    memcpy(ad, pair, 4U);
    ad[4] = (uint8_t)seq;
    ad[5] = (uint8_t)(seq >> 8);
    ad[6] = (uint8_t)(seq >> 16);
    ad[7] = (uint8_t)(seq >> 24);
    ad[8] = CHAN_FF_BIT;
    ad[9] = type;
}

/* The counter nonce layout the session uses for every non-hello frame. */
static void counter_nonce(uint8_t direction, uint32_t seq, uint8_t nonce[24])
{
    memset(nonce, 0, 24);
    nonce[0] = direction;
    nonce[1] = (uint8_t)seq;
    nonce[2] = (uint8_t)(seq >> 8);
    nonce[3] = (uint8_t)(seq >> 16);
    nonce[4] = (uint8_t)(seq >> 24);
}

/* A session-format frame with an empty body sealed under an arbitrary key. */
static int forge_counter_frame_under(const uint8_t key[32],
                                     const uint8_t pair[4],
                                     uint8_t direction, uint32_t seq,
                                     uint8_t type,
                                     uint8_t frame[FRAME_MAX_LEN],
                                     size_t *length_out)
{
    uint8_t ad[10];
    uint8_t nonce[24];
    uint8_t ct[1] = {0};
    uint8_t mac[16];
    int encoded;

    build_ad(ad, pair, seq, type);
    counter_nonce(direction, seq, nonce);
    crypto_aead_lock(ct, mac, key, nonce, ad, 10U, ct, 0U);
    encoded = unmoor_frame_encode(pair, seq, CHAN_FF_BIT, type, mac, 16U,
                                  frame, FRAME_MAX_LEN);
    if (encoded < 0)
        return -1;
    *length_out = (size_t)encoded;
    return 0;
}

/* A session-format frame sealed under the all-zero key: what an attacker
 * who holds no key at all can build. */
static int forge_counter_frame(const uint8_t pair[4], uint8_t direction,
                               uint32_t seq, uint8_t type,
                               uint8_t frame[FRAME_MAX_LEN],
                               size_t *length_out)
{
    return forge_counter_frame_under(zero_key, pair, direction, seq, type,
                                     frame, length_out);
}

/* A hello-format frame (explicit 24-byte nonce) sealed under the all-zero
 * key with 32 bytes of attacker-chosen body. */
static int forge_hello_frame(const uint8_t pair[4], uint32_t seq,
                             uint8_t type, uint8_t frame[FRAME_MAX_LEN],
                             size_t *length_out)
{
    uint8_t ad[10];
    uint8_t nonce[24];
    uint8_t plain[32];
    uint8_t body[24U + 32U + 16U];
    uint8_t mac[16];
    int encoded;

    for (size_t i = 0; i < sizeof(nonce); i++)
        nonce[i] = (uint8_t)(0x5aU + i);
    memset(plain, 0x42, sizeof(plain));
    build_ad(ad, pair, seq, type);
    memcpy(body, nonce, sizeof(nonce));
    crypto_aead_lock(body + sizeof(nonce), mac, zero_key, nonce, ad, 10U,
                     plain, sizeof(plain));
    memcpy(body + sizeof(nonce) + sizeof(plain), mac, sizeof(mac));
    encoded = unmoor_frame_encode(pair, seq, CHAN_FF_BIT, type, body,
                                  sizeof(body), frame, FRAME_MAX_LEN);
    if (encoded < 0)
        return -1;
    *length_out = (size_t)encoded;
    return 0;
}

/* A genuine session frame under a live key, through the product wrapper. */
static int build_live_frame(const uint8_t pair[4], const uint8_t key[32],
                            uint8_t direction, uint32_t seq, uint8_t type,
                            uint8_t frame[FRAME_MAX_LEN], size_t *length_out)
{
    uint8_t ad[10];
    uint8_t ciphertext[FRAME_TAG_LEN];
    uint8_t empty = 0U;
    size_t ciphertext_length = 0U;
    int encoded;

    build_ad(ad, pair, seq, type);
    if (crypto_encrypt(key, seq, direction, ad, &empty, 0U,
                       ciphertext, &ciphertext_length) != 0)
        return -1;
    encoded = unmoor_frame_encode(pair, seq, CHAN_FF_BIT, type,
                                  ciphertext, ciphertext_length,
                                  frame, FRAME_MAX_LEN);
    if (encoded < 0)
        return -1;
    *length_out = (size_t)encoded;
    return 0;
}

static void test_pending_pair_hello_uses_pending_key(void)
{
    const uint8_t pair[4] = { 0x10U, 0x11U, 0x12U, 0x13U };
    const uint8_t pending_pair[4] = { 0x20U, 0x21U, 0x22U, 0x23U };
    const uint8_t types[2] = { CTRL_HELLO, CTRL_HELLO_ACK };

    for (int role = 0; role < 2; role++) {
        int is_server = role == 0;
        capture_transport_t capture;
        session_t *session = fixture_create(&capture, pair, is_server,
                                            SESSION_ESTABLISHED);
        multipath_token_t source = token4(9000U, 1U);
        replay_window_t pending_before;
        uint8_t frame[FRAME_MAX_LEN];
        size_t frame_length = 0U;
        int ok = session != NULL;

        if (ok) {
            /* After the D-28 READY exchange: live session and pending keys,
             * bootstrap key wiped. */
            fill_key(session->session_key, 0xa1U);
            session->have_session_key = 1;
            session->services_started = 1;
            session->have_hello_key = 0;
            session->pending_epoch_valid = 1;
            memcpy(session->pending_pair_id, pending_pair, 4U);
            fill_key(session->pending_key, 0xb2U);
            pending_before = session->pending_replay;
            ok = forge_counter_frame(pending_pair, is_server ? 0x00U : 0x01U,
                                     1U, types[role], frame,
                                     &frame_length) == 0;
        }
        if (ok)
            session_process_datagram_from_at(session, frame, frame_length,
                                             &source, 5000);
        CHECK(is_server
              ? "KG-00 server: pending-pair CTRL_HELLO is verified under the pending key only"
              : "KG-01 client: pending-pair CTRL_HELLO_ACK is verified under the pending key only",
              ok &&
              session->preauth_budget.counters.aead_attempt == 1U &&
              session->preauth_budget.counters.aead_failure == 1U &&
              session->preauth_budget.counters.no_key_drop == 0U &&
              capture.sends == 0U && capture.peer_confirms == 0U &&
              session->last_authenticated_ms == 1234 &&
              session->state == SESSION_ESTABLISHED && !session->run_failed &&
              session->pending_epoch_valid == 1 &&
              memcmp(&session->pending_replay, &pending_before,
                     sizeof(pending_before)) == 0);
        session_destroy(session);
    }
}

/* The selection rule itself, independent of the zero-key backstop: with a
 * live hello key, a pending-pair control frame sealed under that hello key
 * must still fail, because only the pending key may verify a pending-pair
 * frame. Selecting the key by frame type first verified this frame and then
 * closed the session as an invalid pending-epoch control. */
static void test_pending_pair_hello_ignores_live_hello_key(void)
{
    const uint8_t pair[4] = { 0x10U, 0x11U, 0x12U, 0x13U };
    const uint8_t pending_pair[4] = { 0x20U, 0x21U, 0x22U, 0x23U };
    const uint8_t types[2] = { CTRL_HELLO, CTRL_HELLO_ACK };

    for (int role = 0; role < 2; role++) {
        int is_server = role == 0;
        capture_transport_t capture;
        session_t *session = fixture_create(&capture, pair, is_server,
                                            SESSION_ESTABLISHED);
        multipath_token_t source = token4(9000U, 1U);
        replay_window_t pending_before;
        uint8_t frame[FRAME_MAX_LEN];
        size_t frame_length = 0U;
        int ok = session != NULL;

        if (ok) {
            /* Plain-PSK shape: the hello key stays live for the whole
             * session, next to the live session and pending keys. */
            fill_key(session->hello_key, 0xc3U);
            session->have_hello_key = 1;
            fill_key(session->session_key, 0xa1U);
            session->have_session_key = 1;
            session->services_started = 1;
            session->pending_epoch_valid = 1;
            memcpy(session->pending_pair_id, pending_pair, 4U);
            fill_key(session->pending_key, 0xb2U);
            pending_before = session->pending_replay;
            ok = forge_counter_frame_under(session->hello_key, pending_pair,
                                           is_server ? 0x00U : 0x01U, 1U,
                                           types[role], frame,
                                           &frame_length) == 0;
        }
        if (ok)
            session_process_datagram_from_at(session, frame, frame_length,
                                             &source, 5000);
        CHECK(is_server
              ? "KG-10 server: pending-pair CTRL_HELLO under the live hello key is refused"
              : "KG-11 client: pending-pair CTRL_HELLO_ACK under the live hello key is refused",
              ok &&
              session->preauth_budget.counters.aead_attempt == 1U &&
              session->preauth_budget.counters.aead_failure == 1U &&
              session->preauth_budget.counters.no_key_drop == 0U &&
              capture.sends == 0U && capture.peer_confirms == 0U &&
              session->last_authenticated_ms == 1234 &&
              session->state == SESSION_ESTABLISHED && !session->run_failed &&
              session->pending_epoch_valid == 1 &&
              memcmp(&session->pending_replay, &pending_before,
                     sizeof(pending_before)) == 0);
        session_destroy(session);
    }
}

static void test_wiped_hello_key_drops_before_aead(void)
{
    const uint8_t pair[4] = { 0x30U, 0x31U, 0x32U, 0x33U };

    for (int role = 0; role < 2; role++) {
        int is_server = role == 0;
        capture_transport_t capture;
        session_t *session = fixture_create(
            &capture, pair, is_server,
            is_server ? SESSION_ESTABLISHED : SESSION_KEY_DERIVING);
        multipath_token_t source = token4(9001U, 2U);
        uint8_t frame[FRAME_MAX_LEN];
        size_t frame_length = 0U;
        int ok = session != NULL;

        if (ok) {
            fill_key(session->session_key, 0xc3U);
            session->have_session_key = 1;
            session->services_started = is_server;
            session->have_hello_key = 0;
            ok = forge_hello_frame(pair, 7U,
                                   is_server ? CTRL_HELLO : CTRL_HELLO_ACK,
                                   frame, &frame_length) == 0;
        }
        if (ok)
            session_process_datagram_from_at(session, frame, frame_length,
                                             &source, 5000);
        CHECK(is_server
              ? "KG-02 server: CTRL_HELLO after the hello-key wipe is dropped before AEAD"
              : "KG-03 client: CTRL_HELLO_ACK after the hello-key wipe is dropped before AEAD",
              ok &&
              session->preauth_budget.counters.no_key_drop == 1U &&
              session->preauth_budget.counters.aead_attempt == 0U &&
              session->preauth_budget.counters.aead_failure == 0U &&
              capture.sends == 0U && capture.peer_confirms == 0U &&
              session->last_authenticated_ms == 1234 &&
              session->state == (is_server ? SESSION_ESTABLISHED
                                           : SESSION_KEY_DERIVING) &&
              !session->run_failed);
        session_destroy(session);
    }
}

static void test_idle_listener_has_no_session_key(void)
{
    const uint8_t pair[4] = { 0x40U, 0x41U, 0x42U, 0x43U };
    const uint8_t types[2] = { CTRL_KEEPALIVE_ACK, CTRL_READY };
    capture_transport_t capture;
    session_t *session = fixture_create(&capture, pair, 1, SESSION_IDLE);
    multipath_token_t source = token4(9002U, 3U);
    replay_window_t replay_before;
    int ok = session != NULL;

    if (ok) {
        /* Listening: bootstrap key derived, session key not yet derived. */
        fill_key(session->hello_key, 0xd4U);
        session->have_hello_key = 1;
        session->have_session_key = 0;
        replay_before = session->replay;
    }
    for (int index = 0; ok && index < 2; index++) {
        uint8_t frame[FRAME_MAX_LEN];
        size_t frame_length = 0U;

        ok = forge_counter_frame(pair, 0x00U, (uint32_t)(index + 1),
                                 types[index], frame, &frame_length) == 0;
        if (ok)
            session_process_datagram_from_at(session, frame, frame_length,
                                             &source, 5000 + index);
    }
    CHECK("KG-04 idle listener drops session frames before AEAD",
          ok &&
          session->preauth_budget.counters.no_key_drop == 2U &&
          session->preauth_budget.counters.aead_attempt == 0U &&
          session->preauth_budget.counters.aead_failure == 0U &&
          capture.sends == 0U && capture.peer_confirms == 0U &&
          session->last_authenticated_ms == 1234 &&
          session->state == SESSION_IDLE && !session->run_failed &&
          memcmp(&session->replay, &replay_before,
                 sizeof(replay_before)) == 0);
    session_destroy(session);
}

static void test_connecting_stash_is_kept(void)
{
    const uint8_t pair[4] = { 0x50U, 0x51U, 0x52U, 0x53U };
    capture_transport_t capture;
    session_t *session = fixture_create(&capture, pair, 0,
                                        SESSION_CONNECTING);
    multipath_token_t source = token4(9003U, 4U);
    uint8_t frame[FRAME_MAX_LEN];
    size_t frame_length = 0U;
    int ok = session != NULL;

    if (ok) {
        fill_key(session->hello_key, 0xe5U);
        session->have_hello_key = 1;
        session->have_session_key = 0;
        ok = forge_counter_frame(pair, 0x01U, 1U, CTRL_READY,
                                 frame, &frame_length) == 0;
    }
    if (ok)
        session_process_datagram_from_at(session, frame, frame_length,
                                         &source, 5000);
    CHECK("KG-05 CONNECTING still stashes an early session frame instead of dropping it",
          ok && session->stashed_valid == 1 &&
          session->preauth_budget.counters.no_key_drop == 0U &&
          session->preauth_budget.counters.aead_attempt == 0U &&
          capture.sends == 0U && session->state == SESSION_CONNECTING &&
          !session->run_failed);
    session_destroy(session);
}

static void test_live_session_key_still_authenticates(void)
{
    const uint8_t pair[4] = { 0x60U, 0x61U, 0x62U, 0x63U };
    uint8_t key[32];
    capture_transport_t capture;
    session_t *session = fixture_create(&capture, pair, 1,
                                        SESSION_ESTABLISHED);
    multipath_token_t source = token4(9004U, 5U);
    uint8_t frame[FRAME_MAX_LEN];
    size_t frame_length = 0U;
    int ok = session != NULL;

    fill_key(key, 0xf6U);
    if (ok) {
        memcpy(session->session_key, key, 32U);
        session->have_session_key = 1;
        session->services_started = 1;
        session->have_hello_key = 0;
        ok = build_live_frame(pair, key, 0x00U, 1U, CTRL_KEEPALIVE_ACK,
                              frame, &frame_length) == 0;
    }
    if (ok)
        session_process_datagram_from_at(session, frame, frame_length,
                                         &source, 5000);
    CHECK("KG-06 a frame under the live session key still authenticates",
          ok &&
          session->preauth_budget.counters.aead_attempt == 1U &&
          session->preauth_budget.counters.aead_failure == 0U &&
          session->preauth_budget.counters.no_key_drop == 0U &&
          session->last_authenticated_ms == 5000 &&
          session->state == SESSION_ESTABLISHED && !session->run_failed);
    session_destroy(session);
}

static int feed_live(session_t *session, const uint8_t pair[4],
                     const uint8_t key[32], uint32_t seq,
                     const multipath_token_t *source, int64_t now_ms)
{
    uint8_t frame[FRAME_MAX_LEN];
    size_t frame_length = 0U;

    if (build_live_frame(pair, key, 0x00U, seq, CTRL_KEEPALIVE_ACK,
                         frame, &frame_length) != 0)
        return -1;
    session_process_datagram_from_at(session, frame, frame_length, source,
                                     now_ms);
    return 0;
}

/* Feed authenticated frames under the live session key and pin the replay
 * window's four answers: a new sequence is accepted and advances the
 * high-water mark; an exact duplicate authenticates, is dropped and counted,
 * and refreshes no liveness; an older sequence inside the window is accepted
 * exactly once; a sequence that fell below the window is dropped for good. */
static void test_replay_window_drops_duplicates_and_stale_sequences(void)
{
    const uint8_t pair[4] = { 0x70U, 0x71U, 0x72U, 0x73U };
    uint8_t key[32];
    capture_transport_t capture;
    session_t *session = fixture_create(&capture, pair, 1,
                                        SESSION_ESTABLISHED);
    multipath_token_t source = token4(9005U, 6U);
    int ok = session != NULL;

    fill_key(key, 0xf7U);
    if (ok) {
        memcpy(session->session_key, key, 32U);
        session->have_session_key = 1;
        session->services_started = 1;
        session->have_hello_key = 0;
    }

    ok = ok && feed_live(session, pair, key, 10U, &source, 5000) == 0;
    CHECK("KG-10a a fresh sequence is accepted and sets the high-water mark",
          ok && session->replay.hwm == 10U &&
          session->replay_drop_count == 0U &&
          session->last_authenticated_ms == 5000);

    ok = ok && feed_live(session, pair, key, 10U, &source, 5001) == 0;
    CHECK("KG-10b an exact duplicate is dropped after it authenticates",
          ok && session->preauth_budget.counters.aead_attempt == 2U &&
          session->preauth_budget.counters.aead_failure == 0U &&
          session->replay_drop_count == 1U &&
          session->last_authenticated_ms == 5000);

    ok = ok && feed_live(session, pair, key, 12U, &source, 5002) == 0;
    ok = ok && feed_live(session, pair, key, 11U, &source, 5003) == 0;
    CHECK("KG-10c an older sequence inside the window is accepted once",
          ok && session->replay.hwm == 12U &&
          session->replay_drop_count == 1U &&
          session->last_authenticated_ms == 5003);

    ok = ok && feed_live(session, pair, key, 11U, &source, 5004) == 0;
    CHECK("KG-10d the same older sequence is dropped the second time",
          ok && session->replay_drop_count == 2U &&
          session->last_authenticated_ms == 5003);

    ok = ok && feed_live(session, pair, key, 12U + REPLAY_WINDOW, &source,
                         5005) == 0;
    ok = ok && feed_live(session, pair, key, 11U, &source, 5006) == 0;
    ok = ok && feed_live(session, pair, key, 10U, &source, 5007) == 0;
    CHECK("KG-10e sequences below the window are dropped for good",
          ok && session->replay.hwm == 12U + REPLAY_WINDOW &&
          session->replay_drop_count == 4U &&
          session->last_authenticated_ms == 5005 &&
          session->state == SESSION_ESTABLISHED && !session->run_failed);
    session_destroy(session);
}

static void test_wrappers_refuse_zero_key_and_null_arguments(void)
{
    uint8_t live[32];
    uint8_t ad[10];
    uint8_t nonce[24];
    const uint8_t plain[8] = { 'g', 'a', 't', 'e', 't', 'e', 's', 't' };
    uint8_t ct[sizeof(plain) + 16U];
    uint8_t out[sizeof(plain)];
    size_t ct_len = 0U;
    size_t out_len = 0U;
    int ok;

    fill_key(live, 0x33U);
    for (size_t i = 0; i < sizeof(ad); i++)
        ad[i] = (uint8_t)i;
    for (size_t i = 0; i < sizeof(nonce); i++)
        nonce[i] = (uint8_t)(0x5aU + i);

    ok = crypto_encrypt_ad(zero_key, 1U, 0U, ad, sizeof(ad), plain,
                           sizeof(plain), ct, &ct_len) == -1;
    ok = ok && crypto_encrypt_ad(live, 1U, 0U, ad, sizeof(ad), plain,
                                 sizeof(plain), ct, &ct_len) == 0 &&
         ct_len == sizeof(ct);
    ok = ok && crypto_decrypt_ad(zero_key, 1U, 0U, ad, sizeof(ad), ct,
                                 ct_len, out, &out_len) == -1;
    ok = ok && crypto_decrypt_ad(live, 1U, 0U, ad, sizeof(ad), ct, ct_len,
                                 out, &out_len) == 0 &&
         out_len == sizeof(plain) && memcmp(out, plain, sizeof(plain)) == 0;
    CHECK("KG-07 counter-nonce wrappers refuse the all-zero key and keep the live key", ok);

    ct_len = 0U;
    out_len = 0U;
    memset(out, 0, sizeof(out));
    ok = crypto_encrypt_with_nonce(zero_key, nonce, ad, plain, sizeof(plain),
                                   ct, &ct_len) == -1;
    ok = ok && crypto_encrypt_with_nonce(live, NULL, ad, plain,
                                         sizeof(plain), ct, &ct_len) == -1;
    ok = ok && crypto_encrypt_with_nonce(live, nonce, NULL, plain,
                                         sizeof(plain), ct, &ct_len) == -1;
    ok = ok && crypto_encrypt_with_nonce(live, nonce, ad, plain,
                                         sizeof(plain), ct, &ct_len) == 0 &&
         ct_len == sizeof(ct);
    ok = ok && crypto_decrypt_with_nonce(zero_key, nonce, ad, ct, ct_len,
                                         out, &out_len) == -1;
    ok = ok && crypto_decrypt_with_nonce(live, nonce, ad, ct, ct_len,
                                         NULL, &out_len) == -1;
    ok = ok && crypto_decrypt_with_nonce(live, nonce, ad, ct, ct_len,
                                         out, &out_len) == 0 &&
         out_len == sizeof(plain) && memcmp(out, plain, sizeof(plain)) == 0;
    CHECK("KG-08 explicit-nonce wrappers refuse the all-zero key and null arguments", ok);
}

static void test_wipe_clears_liveness_flags(void)
{
    const uint8_t pair[4] = { 0x70U, 0x71U, 0x72U, 0x73U };
    capture_transport_t capture;
    session_t *session = fixture_create(&capture, pair, 1,
                                        SESSION_ESTABLISHED);
    int ok = session != NULL;

    if (ok) {
        fill_key(session->hello_key, 0x17U);
        fill_key(session->session_key, 0x28U);
        session->have_hello_key = 1;
        session->have_session_key = 1;
        session_wipe_key_material(session);
    }
    CHECK("KG-09 wiping key material clears both liveness flags",
          ok && session->have_hello_key == 0 &&
          session->have_session_key == 0 &&
          memcmp(session->hello_key, zero_key, 32U) == 0 &&
          memcmp(session->session_key, zero_key, 32U) == 0);
    session_destroy(session);
}

int main(void)
{
    test_pending_pair_hello_uses_pending_key();
    test_pending_pair_hello_ignores_live_hello_key();
    test_wiped_hello_key_drops_before_aead();
    test_idle_listener_has_no_session_key();
    test_connecting_stash_is_kept();
    test_live_session_key_still_authenticates();
    test_replay_window_drops_duplicates_and_stale_sequences();
    test_wrappers_refuse_zero_key_and_null_arguments();
    test_wipe_clears_liveness_flags();
    printf("session_key_gate_test: %d/%d passed\n", total - failed, total);
    return failed == 0 ? 0 : 1;
}
