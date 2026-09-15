/*
 * Unmoor integration configuration for mlkem-native v1.1.0.
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef UNMOOR_MLKEM_CONFIG_H
#define UNMOOR_MLKEM_CONFIG_H

#define MLK_CONFIG_PARAMETER_SET 1024
#define MLK_CONFIG_NAMESPACE_PREFIX UNMOOR_MLKEM1024
#define MLK_CONFIG_NO_ASM
#define MLK_CONFIG_NO_SUPERCOP
#define MLK_CONFIG_KEYGEN_PCT
#define MLK_CONFIG_CUSTOM_RANDOMBYTES
#define MLK_CONFIG_CUSTOM_ZEROIZE

#if !defined(__ASSEMBLER__)
#include <stddef.h>
#include <stdint.h>

#include "crypto.h"
#include "src/sys.h"

static MLK_INLINE int mlk_randombytes(uint8_t *ptr, size_t len)
{
    return crypto_random_bytes(ptr, len);
}

static MLK_INLINE void mlk_zeroize(void *ptr, size_t len)
{
    crypto_memzero(ptr, len);
}
#endif

#endif /* UNMOOR_MLKEM_CONFIG_H */
