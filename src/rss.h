/*
 * rss.h — bulk-transfer portable port-cube and RSS prediction primitives
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * The bit loop is normative.  These helpers configure no socket or NIC and
 * make no claim that a predicted queue is the hardware-observed queue.
 */
#ifndef UNMOOR_RSS_H
#define UNMOOR_RSS_H

#include <stddef.h>
#include <stdint.h>

#define D33_PORT_CUBE_BITS UINT16_C(0x3fff)
#define D33_PORT_CUBE_PREFIX UINT16_C(0xc000)
#define D33_RSS_KEY_BYTES_MAX 64U
#define D33_RSS_RETA_DEFAULT 512U
#define D33_RSS_QUEUES_MAX 1024U

typedef enum {
    D33_RSS_DIRECTION_C2S = 1,
    D33_RSS_DIRECTION_S2C = 2
} d33_rss_direction_t;

uint16_t d33_pdep16(uint16_t value, uint16_t mask);
uint16_t d33_pext16(uint16_t value, uint16_t mask);

int d33_cube_mask_valid(uint8_t path_count, uint16_t mask);
uint16_t d33_cube_default_mask(uint8_t path_count);
int d33_cube_next_mask(uint8_t path_count, uint16_t current,
                       uint16_t *next_out);
int d33_cube_base_candidate(uint16_t ephemeral_port, uint8_t path_count,
                            uint16_t mask, unsigned int attempt,
                            uint16_t *base_out);
int d33_cube_port(uint16_t base, uint8_t path_count, uint16_t mask,
                  uint8_t leg, uint16_t *port_out);
int d33_cube_leg(uint16_t base, uint8_t path_count, uint16_t mask,
                 uint16_t port, uint8_t *leg_out);

/* Exact MSB-first Toeplitz over `input_length` bytes.  The key must contain
 * at least input_bits + 31 bits. */
int d33_toeplitz_hash(const uint8_t *key, size_t key_length,
                      const uint8_t *input, size_t input_length,
                      uint32_t *hash_out);

/* Rank of the port-bit delta rows after the power-of-two queue mask. */
int d33_rss_mask_rank(const uint8_t *key, size_t key_length,
                      uint16_t port_mask, unsigned int queues,
                      d33_rss_direction_t direction,
                      unsigned int *rank_out);

/* Queue prediction for the cyclic RETA model reta[i] = i % queues.  IPv4
 * addresses are supplied in network-byte order. */
int d33_rss_ipv4_queue(const uint8_t *key, size_t key_length,
                       const uint8_t src_ip[4], const uint8_t dst_ip[4],
                       uint16_t src_port, uint16_t dst_port,
                       unsigned int reta_size, unsigned int queues,
                       uint32_t *hash_out, unsigned int *queue_out);

#endif /* UNMOOR_RSS_H */
