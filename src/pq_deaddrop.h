/*
 * pq_deaddrop.h — pq-hybrid public deaddrop v2 records and strict text carriage
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef UNMOOR_PQ_DEADDROP_H
#define UNMOOR_PQ_DEADDROP_H

#include <stddef.h>
#include <stdint.h>

#include "deaddrop.h"

#define PQ_DEADDROP_RECORD_VERSION 2U
#define PQ_DEADDROP_MLKEM_LEN 1568U
#define PQ_DEADDROP_OFFER_SIZE 1668U
#define PQ_DEADDROP_RESPONSE_SIZE 1732U
#define PQ_DEADDROP_OFFER_PREFIX "UNMOOR OFFER v2 "
#define PQ_DEADDROP_RESPONSE_PREFIX "UNMOOR RESPONSE v2 "
#define PQ_DEADDROP_ACCEPT_PREFIX "UNMOOR ACCEPT v2 "
#define PQ_DEADDROP_FINGERPRINT_TEXT_LEN 71U
#define PQ_DEADDROP_OFFER_LINE_LEN 3424U
#define PQ_DEADDROP_RESPONSE_LINE_LEN 3555U
#define PQ_DEADDROP_ACCEPT_LINE_LEN 3553U

typedef struct {
    uint8_t id[DEADDROP_ID_LEN];
    uint16_t port;
    uint32_t required_caps;
    uint8_t server_x25519[32];
    uint8_t mlkem_public[PQ_DEADDROP_MLKEM_LEN];
    uint8_t offer_fingerprint[32];
} pq_deaddrop_offer_t;

typedef struct {
    uint8_t id[DEADDROP_ID_LEN];
    uint16_t port;
    uint32_t required_caps;
    uint8_t server_x25519[32];
    uint8_t client_x25519[32];
    uint8_t mlkem_ciphertext[PQ_DEADDROP_MLKEM_LEN];
    uint8_t offer_fingerprint[32];
    uint8_t transcript_fingerprint[32];
} pq_deaddrop_response_t;

int pq_deaddrop_offer_encode(const pq_deaddrop_offer_t *offer,
                             uint8_t out[PQ_DEADDROP_OFFER_SIZE]);
int pq_deaddrop_offer_decode(const uint8_t *wire, size_t wire_len,
                             pq_deaddrop_offer_t *out);
int pq_deaddrop_response_encode(const pq_deaddrop_response_t *response,
                                uint8_t out[PQ_DEADDROP_RESPONSE_SIZE]);
int pq_deaddrop_response_decode(const uint8_t *wire, size_t wire_len,
                                pq_deaddrop_response_t *out);

int pq_deaddrop_offer_fingerprint(const pq_deaddrop_offer_t *offer,
                                  uint8_t out[32]);
int pq_deaddrop_offer_seal(pq_deaddrop_offer_t *offer);
int pq_deaddrop_offer_verify(const pq_deaddrop_offer_t *offer);
int pq_deaddrop_response_seal(const pq_deaddrop_offer_t *offer,
                              pq_deaddrop_response_t *response);
int pq_deaddrop_response_verify(const pq_deaddrop_offer_t *offer,
                                const pq_deaddrop_response_t *response);

int pq_deaddrop_offer_line_encode(
    const pq_deaddrop_offer_t *offer,
    char out[PQ_DEADDROP_OFFER_LINE_LEN + 1U]);
int pq_deaddrop_offer_line_decode(const char *line, size_t line_len,
                                  pq_deaddrop_offer_t *out);
int pq_deaddrop_response_line_encode(
    const pq_deaddrop_offer_t *offer,
    const pq_deaddrop_response_t *response,
    char out[PQ_DEADDROP_RESPONSE_LINE_LEN + 1U]);
int pq_deaddrop_response_line_decode(
    const char *line, size_t line_len, const pq_deaddrop_offer_t *offer,
    pq_deaddrop_response_t *out);
int pq_deaddrop_accept_line_encode(
    const pq_deaddrop_offer_t *offer,
    const pq_deaddrop_response_t *response,
    char out[PQ_DEADDROP_ACCEPT_LINE_LEN + 1U]);
int pq_deaddrop_accept_line_verify(
    const char *line, size_t line_len, const pq_deaddrop_offer_t *offer,
    const pq_deaddrop_response_t *response);

deaddrop_status_t pq_deaddrop_publish_offer(
    int dirfd, const pq_deaddrop_offer_t *offer);
deaddrop_status_t pq_deaddrop_publish_response(
    int dirfd, const pq_deaddrop_response_t *response);
deaddrop_status_t pq_deaddrop_offer_present(
    int dirfd, const uint8_t id[DEADDROP_ID_LEN], int *present_out);
deaddrop_status_t pq_deaddrop_response_present(
    int dirfd, const uint8_t id[DEADDROP_ID_LEN], int *present_out);
deaddrop_status_t pq_deaddrop_claim_offer(
    int dirfd, const uint8_t id[DEADDROP_ID_LEN],
    pq_deaddrop_offer_t *offer_out);
deaddrop_status_t pq_deaddrop_claim_response(
    int dirfd, const uint8_t id[DEADDROP_ID_LEN],
    pq_deaddrop_response_t *response_out);

#endif /* UNMOOR_PQ_DEADDROP_H */
