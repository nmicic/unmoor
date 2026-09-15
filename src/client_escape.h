/*
 * client_escape.h — bounded local raw-mode command filter
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef UNMOOR_CLIENT_ESCAPE_H
#define UNMOOR_CLIENT_ESCAPE_H

#include <stddef.h>
#include <stdint.h>

#define CLIENT_ESCAPE_BYTE UINT8_C(0x1d) /* Ctrl-] */
#define CLIENT_LINE_ESCAPE_BYTE UINT8_C(0x7e) /* ~ */

enum {
    CLIENT_ESCAPE_PENDING_NONE = 0,
    CLIENT_ESCAPE_PENDING_STATUS = 1,
    CLIENT_ESCAPE_PENDING_LINE = 2
};

typedef struct {
    uint8_t pending;
    uint8_t line_start;
} client_escape_t;

void client_escape_init(client_escape_t *state);

/* Filters one chunk. Ctrl-] s is consumed and increments queries; doubled
 * Ctrl-] sends one literal; unknown pairs are byte-exact. At the beginning of
 * input or immediately after CR/LF, ~. is consumed and increments disconnects,
 * ~~ sends one literal tilde, and unknown pairs are byte-exact. Recognition
 * stops at the first disconnect so later bytes from that local read cannot
 * cross the peer boundary. The caller must reserve one output byte whenever
 * state->pending is nonzero. Returns SIZE_MAX on a too-small output buffer. */
size_t client_escape_filter(client_escape_t *state, int enabled,
                            const uint8_t *input, size_t input_len,
                            uint8_t *output, size_t output_len,
                            unsigned *queries_out,
                            unsigned *disconnects_out);

/* At EOF, emit a held literal Ctrl-] or line-start tilde before FIN. */
size_t client_escape_finish(client_escape_t *state,
                            uint8_t *output, size_t output_len);

#endif /* UNMOOR_CLIENT_ESCAPE_H */
