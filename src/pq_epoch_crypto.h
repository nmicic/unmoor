/*
 * pq_epoch_crypto.h — pq-hybrid epoch derivation
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef UNMOOR_PQ_EPOCH_CRYPTO_H
#define UNMOOR_PQ_EPOCH_CRYPTO_H

#include <stdint.h>

#include "epoch_crypto.h"
#include "pq_crypto.h"

/* Derive one adjacent pq-hybrid epoch after the caller has completed ML-KEM
 * encapsulation/decapsulation.  Every public input is included in the
 * canonical transcript; the caller retains and must wipe mlkem_shared. */
int pq_epoch_crypto_rekey_derive(
    const uint8_t current_traffic_key[32],
    const uint8_t local_private[32], epoch_crypto_role_t local_role,
    const uint8_t session_context[32],
    const uint8_t client_hello[32], const uint8_t server_ack[32],
    uint32_t selected_caps, uint32_t from_epoch, uint32_t to_epoch,
    const uint8_t rekey_id[16],
    const uint8_t client_public[32], const uint8_t server_public[32],
    const uint8_t mlkem_public[PQ_MLKEM_PUBLIC_LEN],
    const uint8_t mlkem_ciphertext[PQ_MLKEM_CIPHERTEXT_LEN],
    const uint8_t mlkem_shared[PQ_MLKEM_SECRET_LEN],
    epoch_crypto_rekey_material_t *out);

#endif /* UNMOOR_PQ_EPOCH_CRYPTO_H */
