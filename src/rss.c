/*
 * rss.c — bulk-transfer portable port-cube and RSS prediction primitives
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#include "rss.h"

#include <limits.h>
#include <string.h>

#include "multipath.h"
#include "transport.h"

static unsigned int popcount16(uint16_t value)
{
    unsigned int count = 0U;

    while (value != 0U) {
        value = (uint16_t)(value & (uint16_t)(value - 1U));
        count++;
    }
    return count;
}

static unsigned int path_log2(uint8_t path_count)
{
    unsigned int value = path_count;
    unsigned int result = 0U;

    while (value > 1U) {
        value >>= 1;
        result++;
    }
    return result;
}

static int power_of_two(unsigned int value)
{
    return value != 0U && (value & (value - 1U)) == 0U;
}

uint16_t d33_pdep16(uint16_t value, uint16_t mask)
{
    uint32_t source = value;
    uint32_t remaining = mask;
    uint32_t result = 0U;
    uint32_t source_bit = 1U;

    while (remaining != 0U) {
        uint32_t destination_bit = remaining & (~remaining + 1U);

        if ((source & source_bit) != 0U)
            result |= destination_bit;
        remaining &= remaining - 1U;
        source_bit <<= 1;
    }
    return (uint16_t)result;
}

uint16_t d33_pext16(uint16_t value, uint16_t mask)
{
    uint32_t source = value;
    uint32_t remaining = mask;
    uint32_t result = 0U;
    uint32_t destination_bit = 1U;

    while (remaining != 0U) {
        uint32_t source_bit = remaining & (~remaining + 1U);

        if ((source & source_bit) != 0U)
            result |= destination_bit;
        remaining &= remaining - 1U;
        destination_bit <<= 1;
    }
    return (uint16_t)result;
}

int d33_cube_mask_valid(uint8_t path_count, uint16_t mask)
{
    return multipath_path_count_valid(path_count) && mask != 0U &&
           (mask & (uint16_t)~D33_PORT_CUBE_BITS) == 0U &&
           popcount16(mask) == path_log2(path_count);
}

uint16_t d33_cube_default_mask(uint8_t path_count)
{
    if (!multipath_path_count_valid(path_count))
        return 0U;
    return (uint16_t)((unsigned int)path_count - 1U);
}

int d33_cube_next_mask(uint8_t path_count, uint16_t current,
                       uint16_t *next_out)
{
    unsigned int candidate;

    if (!next_out || !d33_cube_mask_valid(path_count, current))
        return -1;
    *next_out = 0U;
    for (candidate = (unsigned int)current + 1U;
         candidate <= D33_PORT_CUBE_BITS; candidate++) {
        if (d33_cube_mask_valid(path_count, (uint16_t)candidate)) {
            *next_out = (uint16_t)candidate;
            return 0;
        }
    }
    for (candidate = 1U; candidate <= (unsigned int)current; candidate++) {
        if (d33_cube_mask_valid(path_count, (uint16_t)candidate)) {
            *next_out = (uint16_t)candidate;
            return 0;
        }
    }
    return -1;
}

int d33_cube_base_candidate(uint16_t ephemeral_port, uint8_t path_count,
                            uint16_t mask, unsigned int attempt,
                            uint16_t *base_out)
{
    uint16_t available;
    uint16_t suffix;
    unsigned int base_count;
    unsigned int start;
    unsigned int index;
    unsigned int k;

    if (!base_out || !d33_cube_mask_valid(path_count, mask) ||
        attempt >= TRANSPORT_UDP_D32_BIND_ATTEMPTS)
        return -1;
    *base_out = 0U;
    k = path_log2(path_count);
    available = (uint16_t)(D33_PORT_CUBE_BITS & (uint16_t)~mask);
    base_count = 1U << (14U - k);
    suffix = ephemeral_port >= D33_PORT_CUBE_PREFIX
           ? (uint16_t)(ephemeral_port - D33_PORT_CUBE_PREFIX) : 0U;
    start = d33_pext16(suffix, available);
    index = (start + attempt) & (base_count - 1U);
    *base_out = (uint16_t)(D33_PORT_CUBE_PREFIX |
                           d33_pdep16((uint16_t)index, available));
    return 0;
}

int d33_cube_port(uint16_t base, uint8_t path_count, uint16_t mask,
                  uint8_t leg, uint16_t *port_out)
{
    uint16_t port;

    if (!port_out || !d33_cube_mask_valid(path_count, mask) ||
        leg >= path_count || (base & D33_PORT_CUBE_PREFIX) !=
                             D33_PORT_CUBE_PREFIX ||
        (base & mask) != 0U)
        return -1;
    port = (uint16_t)(base ^ d33_pdep16(leg, mask));
    if (port < TRANSPORT_UDP_D32_PORT_MIN)
        return -1;
    *port_out = port;
    return 0;
}

int d33_cube_leg(uint16_t base, uint8_t path_count, uint16_t mask,
                 uint16_t port, uint8_t *leg_out)
{
    uint16_t difference;
    uint16_t leg;

    if (!leg_out || port < TRANSPORT_UDP_D32_PORT_MIN ||
        !d33_cube_mask_valid(path_count, mask) ||
        (base & D33_PORT_CUBE_PREFIX) != D33_PORT_CUBE_PREFIX ||
        (base & mask) != 0U)
        return -1;
    difference = (uint16_t)(port ^ base);
    if ((difference & (uint16_t)~mask) != 0U)
        return -1;
    leg = d33_pext16(difference, mask);
    if (leg >= path_count)
        return -1;
    *leg_out = (uint8_t)leg;
    return 0;
}

static unsigned int bit_at(const uint8_t *bytes, size_t bit)
{
    return (unsigned int)((bytes[bit >> 3] >>
                           (7U - (unsigned int)(bit & 7U))) & 1U);
}

int d33_toeplitz_hash(const uint8_t *key, size_t key_length,
                      const uint8_t *input, size_t input_length,
                      uint32_t *hash_out)
{
    size_t input_bits;
    size_t key_bits;
    size_t input_bit;
    uint32_t result = 0U;

    if (!key || !input || !hash_out || input_length == 0U ||
        input_length > (SIZE_MAX - 31U) / 8U ||
        key_length > SIZE_MAX / 8U)
        return -1;
    input_bits = input_length * 8U;
    key_bits = key_length * 8U;
    if (key_bits < input_bits + 31U)
        return -1;
    for (input_bit = 0U; input_bit < input_bits; input_bit++) {
        unsigned int output_bit;
        uint32_t window = 0U;

        if (bit_at(input, input_bit) == 0U)
            continue;
        for (output_bit = 0U; output_bit < 32U; output_bit++)
            window = (window << 1) |
                     bit_at(key, input_bit + output_bit);
        result ^= window;
    }
    *hash_out = result;
    return 0;
}

static unsigned int gf2_rank(uint32_t *rows, unsigned int row_count,
                             unsigned int bits)
{
    unsigned int rank = 0U;
    unsigned int column;

    for (column = 0U; column < bits && rank < row_count; column++) {
        uint32_t pivot_bit = UINT32_C(1) << column;
        unsigned int pivot = rank;
        unsigned int row;

        while (pivot < row_count && (rows[pivot] & pivot_bit) == 0U)
            pivot++;
        if (pivot == row_count)
            continue;
        if (pivot != rank) {
            uint32_t temporary = rows[rank];
            rows[rank] = rows[pivot];
            rows[pivot] = temporary;
        }
        for (row = 0U; row < row_count; row++)
            if (row != rank && (rows[row] & pivot_bit) != 0U)
                rows[row] ^= rows[rank];
        rank++;
    }
    return rank;
}

int d33_rss_mask_rank(const uint8_t *key, size_t key_length,
                      uint16_t port_mask, unsigned int queues,
                      d33_rss_direction_t direction,
                      unsigned int *rank_out)
{
    uint32_t rows[16];
    unsigned int row_count = 0U;
    unsigned int queue_bits = 0U;
    unsigned int bit;

    if (!key || !rank_out || port_mask == 0U ||
        (port_mask & (uint16_t)~D33_PORT_CUBE_BITS) != 0U ||
        !power_of_two(queues) || queues > D33_RSS_QUEUES_MAX ||
        (direction != D33_RSS_DIRECTION_C2S &&
         direction != D33_RSS_DIRECTION_S2C))
        return -1;
    while ((UINT32_C(1) << queue_bits) < queues)
        queue_bits++;
    memset(rows, 0, sizeof(rows));
    for (bit = 0U; bit < 14U; bit++) {
        if ((port_mask & (UINT16_C(1) << bit)) != 0U) {
            uint8_t tuple[12] = { 0U };
            uint16_t port = (uint16_t)(UINT16_C(1) << bit);
            uint32_t hash = 0U;
            size_t offset = direction == D33_RSS_DIRECTION_C2S ? 8U : 10U;

            tuple[offset] = (uint8_t)(port >> 8);
            tuple[offset + 1U] = (uint8_t)port;
            if (d33_toeplitz_hash(key, key_length, tuple, sizeof(tuple),
                                  &hash) != 0)
                return -1;
            rows[row_count++] = hash & (queues - 1U);
        }
    }
    *rank_out = gf2_rank(rows, row_count, queue_bits);
    return 0;
}

int d33_rss_ipv4_queue(const uint8_t *key, size_t key_length,
                       const uint8_t src_ip[4], const uint8_t dst_ip[4],
                       uint16_t src_port, uint16_t dst_port,
                       unsigned int reta_size, unsigned int queues,
                       uint32_t *hash_out, unsigned int *queue_out)
{
    uint8_t tuple[12];
    uint32_t hash;

    if (!key || !src_ip || !dst_ip || src_port == 0U || dst_port == 0U ||
        !hash_out || !queue_out || !power_of_two(reta_size) ||
        !power_of_two(queues) || queues > D33_RSS_QUEUES_MAX ||
        queues > reta_size)
        return -1;
    memcpy(tuple, src_ip, 4U);
    memcpy(tuple + 4U, dst_ip, 4U);
    tuple[8] = (uint8_t)(src_port >> 8);
    tuple[9] = (uint8_t)src_port;
    tuple[10] = (uint8_t)(dst_port >> 8);
    tuple[11] = (uint8_t)dst_port;
    if (d33_toeplitz_hash(key, key_length, tuple, sizeof(tuple), &hash) != 0)
        return -1;
    *hash_out = hash;
    *queue_out = (unsigned int)(hash & (reta_size - 1U)) % queues;
    return 0;
}
