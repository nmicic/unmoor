/*
 * pq_deaddrop_exchange.h — in-memory pq-hybrid bootstrap lifecycle
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef UNMOOR_PQ_DEADDROP_EXCHANGE_H
#define UNMOOR_PQ_DEADDROP_EXCHANGE_H

#include <stdint.h>

#include "pq_crypto.h"
#include "pq_deaddrop.h"

typedef struct {
    uint8_t x25519_private[32];
    uint8_t mlkem_private[PQ_MLKEM_PRIVATE_LEN];
} pq_deaddrop_server_secrets_t;

int pq_deaddrop_server_offer_generate(
    const uint8_t id[DEADDROP_ID_LEN], uint16_t port, uint32_t required_caps,
    pq_deaddrop_offer_t *offer_out,
    pq_deaddrop_server_secrets_t *secrets_out);

int pq_deaddrop_client_accept(
    const pq_deaddrop_offer_t *offer,
    pq_deaddrop_response_t *response_out,
    uint8_t root_out[32], uint8_t pair_seed_out[4]);

/* Always wipes and unlocks secrets, including on validation failure. */
int pq_deaddrop_server_accept(
    pq_deaddrop_server_secrets_t *secrets,
    const pq_deaddrop_offer_t *offer,
    const pq_deaddrop_response_t *response,
    uint8_t root_out[32], uint8_t pair_seed_out[4]);

void pq_deaddrop_server_secrets_wipe(
    pq_deaddrop_server_secrets_t *secrets);

#endif /* UNMOOR_PQ_DEADDROP_EXCHANGE_H */
