/*
 * attach_client.h — channel-session bounded local attach command and client runtime
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef UNMOOR_ATTACH_CLIENT_H
#define UNMOOR_ATTACH_CLIENT_H

#include <stddef.h>
#include <stdint.h>

#include "attach_local.h"

typedef struct {
    const char *socket_path;
    uint8_t kind;
    size_t argument_count;
    char *const *arguments;
    const char *local_path;
    const char *remote_path;
    size_t local_path_length;
    size_t remote_path_length;
    uint16_t wire_budget;
    uint16_t stall_seconds;
    uint8_t bulk_options;
} attach_client_options_t;

/*
 * Exact accepted argument forms (the leading "attach" is already removed):
 *   --socket PATH terminal
 *   --socket PATH exec -- ARGV...
 *   --socket PATH push [--bulk-mtu B] [--bulk-stall-secs S] [--force]
 *                      -- LOCAL REMOTE
 *   --socket PATH pull [--bulk-mtu B] [--bulk-stall-secs S] [--force]
 *                      -- REMOTE LOCAL
 * No aliases, reordered options, shell text, or network options are accepted.
 */
int attach_client_parse_options(int argc, char *const argv[],
                                attach_client_options_t *options_out);

/*
 * Drive one already-connected local socket.  The function owns and closes
 * socket_fd; it borrows input_fd/output_fd and restores any flags/termios it
 * changes. V1 returns the received process status when it is 0..255. V2 bulk
 * emits no stream records and returns zero only for exact bulk-transfer result zero.
 * Refusal, protocol/I/O failure, or an unrepresentable result returns one.
 */
int attach_client_run_connected(int socket_fd, int input_fd, int output_fd,
                                const attach_local_record_t *open_record);

/* Entry point used by main.c after removing the leading "attach" token. */
int attach_client_command(int argc, char *argv[]);

#endif /* UNMOOR_ATTACH_CLIENT_H */
