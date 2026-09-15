/*
 * client_escape.c — bounded local raw-mode command filter
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>

#include "client_escape.h"

void client_escape_init(client_escape_t *state)
{
    if (state) {
        state->pending = CLIENT_ESCAPE_PENDING_NONE;
        state->line_start = 1U;
    }
}

static int append_byte(uint8_t value, uint8_t *output, size_t output_len,
                       size_t *used)
{
    if (*used >= output_len)
        return -1;
    output[(*used)++] = value;
    return 0;
}

static void note_peer_byte(client_escape_t *state, uint8_t value)
{
    state->line_start = value == (uint8_t)'\r' || value == (uint8_t)'\n';
}

static int append_peer_byte(client_escape_t *state, uint8_t value,
                            uint8_t *output, size_t output_len, size_t *used)
{
    if (append_byte(value, output, output_len, used) != 0)
        return -1;
    note_peer_byte(state, value);
    return 0;
}

size_t client_escape_filter(client_escape_t *state, int enabled,
                            const uint8_t *input, size_t input_len,
                            uint8_t *output, size_t output_len,
                            unsigned *queries_out,
                            unsigned *disconnects_out)
{
    size_t used = 0;
    unsigned queries = 0;
    unsigned disconnects = 0;

    if (!state || (!input && input_len != 0) ||
        (!output && output_len != 0))
        return SIZE_MAX;
    if (!enabled) {
        if (state->pending) {
            uint8_t held = state->pending == CLIENT_ESCAPE_PENDING_LINE
                ? CLIENT_LINE_ESCAPE_BYTE : CLIENT_ESCAPE_BYTE;

            if (append_peer_byte(state, held, output, output_len,
                                 &used) != 0)
                return SIZE_MAX;
            state->pending = CLIENT_ESCAPE_PENDING_NONE;
        }
        if (input_len > output_len - used)
            return SIZE_MAX;
        for (size_t i = 0; i < input_len; i++) {
            output[used++] = input[i];
            note_peer_byte(state, input[i]);
        }
        if (queries_out)
            *queries_out = 0;
        if (disconnects_out)
            *disconnects_out = 0;
        return used;
    }

    for (size_t i = 0; i < input_len; i++) {
        uint8_t value = input[i];
        if (state->pending == CLIENT_ESCAPE_PENDING_NONE) {
            if (value == CLIENT_ESCAPE_BYTE) {
                state->pending = CLIENT_ESCAPE_PENDING_STATUS;
            } else if (state->line_start &&
                       value == CLIENT_LINE_ESCAPE_BYTE) {
                state->pending = CLIENT_ESCAPE_PENDING_LINE;
            } else if (append_peer_byte(state, value, output, output_len,
                                        &used) != 0) {
                return SIZE_MAX;
            }
            continue;
        }

        if (state->pending == CLIENT_ESCAPE_PENDING_STATUS) {
            state->pending = CLIENT_ESCAPE_PENDING_NONE;
            if (value == (uint8_t)'s') {
                queries++;
            } else if (value == CLIENT_ESCAPE_BYTE) {
                if (append_peer_byte(state, value, output, output_len,
                                     &used) != 0)
                    return SIZE_MAX;
            } else {
                if (append_peer_byte(state, CLIENT_ESCAPE_BYTE,
                                     output, output_len, &used) != 0 ||
                    append_peer_byte(state, value, output, output_len,
                                     &used) != 0)
                    return SIZE_MAX;
            }
        } else {
            state->pending = CLIENT_ESCAPE_PENDING_NONE;
            if (value == (uint8_t)'.') {
                disconnects++;
                break;
            }
            if (value == CLIENT_LINE_ESCAPE_BYTE) {
                if (append_peer_byte(state, value, output, output_len,
                                     &used) != 0)
                    return SIZE_MAX;
            } else if (append_peer_byte(state, CLIENT_LINE_ESCAPE_BYTE,
                                        output, output_len, &used) != 0 ||
                       append_peer_byte(state, value, output, output_len,
                                        &used) != 0) {
                return SIZE_MAX;
            }
        }
    }
    if (queries_out)
        *queries_out = queries;
    if (disconnects_out)
        *disconnects_out = disconnects;
    return used;
}

size_t client_escape_finish(client_escape_t *state,
                            uint8_t *output, size_t output_len)
{
    if (!state || !state->pending)
        return 0;
    if (!output || output_len == 0)
        return SIZE_MAX;
    output[0] = state->pending == CLIENT_ESCAPE_PENDING_LINE
        ? CLIENT_LINE_ESCAPE_BYTE : CLIENT_ESCAPE_BYTE;
    note_peer_byte(state, output[0]);
    state->pending = CLIENT_ESCAPE_PENDING_NONE;
    return 1;
}
