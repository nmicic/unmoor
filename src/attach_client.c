/*
 * attach_client.c — channel-session bounded local attach command and client runtime
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif

#include "attach_client.h"

#include "confine.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

#include "process_hygiene.h"

#define ATTACH_CLIENT_TERMINAL_KIND ATTACH_LOCAL_KIND_TERMINAL
#define ATTACH_CLIENT_EXEC_KIND ATTACH_LOCAL_KIND_EXEC
#define ATTACH_CLIENT_BULK_PUSH_KIND ATTACH_LOCAL_KIND_BULK_PUSH
#define ATTACH_CLIENT_BULK_PULL_KIND ATTACH_LOCAL_KIND_BULK_PULL
#define ATTACH_CLIENT_CLOSE_PROTOCOL UINT32_C(7)

typedef struct {
    struct sigaction old_int;
    struct sigaction old_winch;
    struct sigaction old_hup;
    struct sigaction old_term;
    struct sigaction old_quit;
    struct sigaction old_pipe;
    unsigned int installed_mask;
} attach_client_signals_t;

typedef struct {
    struct termios value;
    int valid;
} attach_client_termios_t;

static volatile sig_atomic_t g_attach_signal;
static volatile sig_atomic_t g_attach_signal_overflow;
static volatile sig_atomic_t g_attach_resize;
static volatile sig_atomic_t g_attach_cancel_signal;
static struct termios g_attach_panic_termios;
static volatile sig_atomic_t g_attach_panic_armed;
static int g_attach_panic_fd = -1;

static void attach_restore_termios_only(void)
{
    int fd;

    if (!g_attach_panic_armed)
        return;
    g_attach_panic_armed = 0;
    fd = g_attach_panic_fd;
    if (fd >= 0)
        (void)tcsetattr(fd, TCSANOW, &g_attach_panic_termios);
}

static void attach_panic_prepare(void)
{
    g_attach_panic_armed = 0;
    g_attach_panic_fd = -1;
    confine_set_panic_hook(attach_restore_termios_only);
}

static void attach_panic_arm(int fd, const struct termios *saved)
{
    if (saved == NULL)
        return;
    g_attach_panic_termios = *saved;
    g_attach_panic_fd = fd;
    /* Publish last: a SIGSYS before this store observes an unarmed hook. */
    g_attach_panic_armed = 1;
}

static void attach_panic_clear(void)
{
    g_attach_panic_armed = 0;
    g_attach_panic_fd = -1;
    confine_set_panic_hook(NULL);
}

static void attach_signal_handler(int signum)
{
    if (signum == SIGWINCH) {
        g_attach_resize = 1;
        return;
    }
    if (signum == SIGHUP || signum == SIGTERM || signum == SIGQUIT) {
        if (g_attach_cancel_signal == 0)
            g_attach_cancel_signal = signum;
        return;
    }
    if (signum == SIGINT) {
        if (g_attach_signal == 0)
            g_attach_signal = signum;
        else
            g_attach_signal_overflow = 1;
    }
}

static int install_one_handler(int signum, void (*handler)(int),
                               struct sigaction *old_action)
{
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    action.sa_handler = handler;
    if (sigemptyset(&action.sa_mask) != 0)
        return -1;
    action.sa_flags = 0;
    return sigaction(signum, &action, old_action);
}

static void restore_signals(attach_client_signals_t *signals)
{
    if (signals == NULL)
        return;
    if ((signals->installed_mask & (1U << 5)) != 0U)
        (void)sigaction(SIGPIPE, &signals->old_pipe, NULL);
    if ((signals->installed_mask & (1U << 4)) != 0U)
        (void)sigaction(SIGQUIT, &signals->old_quit, NULL);
    if ((signals->installed_mask & (1U << 3)) != 0U)
        (void)sigaction(SIGTERM, &signals->old_term, NULL);
    if ((signals->installed_mask & (1U << 2)) != 0U)
        (void)sigaction(SIGHUP, &signals->old_hup, NULL);
    if ((signals->installed_mask & (1U << 1)) != 0U)
        (void)sigaction(SIGWINCH, &signals->old_winch, NULL);
    if ((signals->installed_mask & 1U) != 0U)
        (void)sigaction(SIGINT, &signals->old_int, NULL);
    signals->installed_mask = 0U;
}

static int install_signals(attach_client_signals_t *signals)
{
    struct sigaction ignore_pipe;

    if (signals == NULL) {
        errno = EINVAL;
        return -1;
    }
    memset(signals, 0, sizeof(*signals));
    g_attach_signal = 0;
    g_attach_signal_overflow = 0;
    g_attach_resize = 0;
    g_attach_cancel_signal = 0;
    if (install_one_handler(SIGINT, attach_signal_handler,
                            &signals->old_int) != 0)
        return -1;
    signals->installed_mask |= 1U;
    if (install_one_handler(SIGWINCH, attach_signal_handler,
                            &signals->old_winch) != 0)
        goto fail;
    signals->installed_mask |= 1U << 1;
    if (install_one_handler(SIGHUP, attach_signal_handler,
                            &signals->old_hup) != 0)
        goto fail;
    signals->installed_mask |= 1U << 2;
    if (install_one_handler(SIGTERM, attach_signal_handler,
                            &signals->old_term) != 0)
        goto fail;
    signals->installed_mask |= 1U << 3;
    if (install_one_handler(SIGQUIT, attach_signal_handler,
                            &signals->old_quit) != 0)
        goto fail;
    signals->installed_mask |= 1U << 4;
    memset(&ignore_pipe, 0, sizeof(ignore_pipe));
    ignore_pipe.sa_handler = SIG_IGN;
    if (sigemptyset(&ignore_pipe.sa_mask) != 0 ||
        sigaction(SIGPIPE, &ignore_pipe, &signals->old_pipe) != 0)
        goto fail;
    signals->installed_mask |= 1U << 5;
    return 0;

fail:
    {
        int saved_errno = errno;

        restore_signals(signals);
        errno = saved_errno;
        return -1;
    }
}

static int set_nonblocking_cloexec(int fd, int *original_flags_out,
                                  int *original_descriptor_flags_out)
{
    int flags;
    int descriptor_flags;

    flags = fcntl(fd, F_GETFL);
    if (flags < 0)
        return -1;
    if (original_flags_out != NULL)
        *original_flags_out = flags;
    if ((flags & O_NONBLOCK) == 0 &&
        fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0)
        return -1;
    descriptor_flags = fcntl(fd, F_GETFD);
    if (descriptor_flags < 0)
        return -1;
    if (original_descriptor_flags_out != NULL)
        *original_descriptor_flags_out = descriptor_flags;
    if ((descriptor_flags & FD_CLOEXEC) == 0 &&
        fcntl(fd, F_SETFD, descriptor_flags | FD_CLOEXEC) != 0)
        return -1;
    return 0;
}

static int current_terminal_dimensions(int fd, uint16_t *rows_out,
                                       uint16_t *columns_out,
                                       uint16_t *xpixel_out,
                                       uint16_t *ypixel_out)
{
    struct winsize size;

    if (rows_out == NULL || columns_out == NULL || xpixel_out == NULL ||
        ypixel_out == NULL) {
        errno = EINVAL;
        return -1;
    }
    memset(&size, 0, sizeof(size));
    if (ioctl(fd, TIOCGWINSZ, &size) != 0 || size.ws_row == 0U ||
        size.ws_row > 1000U || size.ws_col == 0U || size.ws_col > 1000U)
        return -1;
    *rows_out = size.ws_row;
    *columns_out = size.ws_col;
    *xpixel_out = size.ws_xpixel;
    *ypixel_out = size.ws_ypixel;
    return 0;
}

static void initial_terminal_dimensions(int fd, uint16_t *rows_out,
                                        uint16_t *columns_out,
                                        uint16_t *xpixel_out,
                                        uint16_t *ypixel_out)
{
    if (current_terminal_dimensions(fd, rows_out, columns_out,
                                    xpixel_out, ypixel_out) == 0)
        return;
    *rows_out = UINT16_C(24);
    *columns_out = UINT16_C(80);
    *xpixel_out = 0U;
    *ypixel_out = 0U;
}

static int enter_raw_mode(int fd, attach_client_termios_t *saved)
{
    struct termios raw;

    if (saved == NULL) {
        errno = EINVAL;
        return -1;
    }
    memset(saved, 0, sizeof(*saved));
    if (!isatty(fd))
        return 0;
    if (tcgetattr(fd, &saved->value) != 0)
        return -1;
    raw = saved->value;
    cfmakeraw(&raw);
    if (tcsetattr(fd, TCSAFLUSH, &raw) != 0)
        return -1;
    saved->valid = 1;
    attach_panic_arm(fd, &saved->value);
    return 0;
}

static int restore_terminal(int fd, attach_client_termios_t *saved)
{
    if (saved == NULL || !saved->valid)
        return 0;
    saved->valid = 0;
    {
        int status = tcsetattr(fd, TCSAFLUSH, &saved->value);

        g_attach_panic_armed = 0;
        g_attach_panic_fd = -1;
        return status;
    }
}

static int parse_u16_range(const char *text, uint16_t minimum,
                           uint16_t maximum, uint16_t *value_out)
{
    uint32_t value = 0U;
    size_t i;

    if (text == NULL || text[0] == '\0' || value_out == NULL)
        return -1;
    for (i = 0U; text[i] != '\0'; i++) {
        uint8_t digit;

        if (text[i] < '0' || text[i] > '9')
            return -1;
        digit = (uint8_t)(text[i] - '0');
        if (value > ((uint32_t)maximum - digit) / 10U)
            return -1;
        value = value * 10U + digit;
    }
    if (value < (uint32_t)minimum || value > (uint32_t)maximum)
        return -1;
    *value_out = (uint16_t)value;
    return 0;
}

static int parse_bulk_options(int argc, char *const argv[],
                              attach_client_options_t *options)
{
    attach_local_record_t validation;
    int index = 3;
    const char *first;
    const char *second;

    options->wire_budget = ATTACH_LOCAL_BULK_WIRE_DEFAULT;
    options->stall_seconds = ATTACH_LOCAL_BULK_STALL_DEFAULT;
    if (index < argc && strcmp(argv[index], "--bulk-mtu") == 0) {
        if (index + 1 >= argc || strcmp(argv[index + 1], "--") == 0 ||
            parse_u16_range(argv[index + 1], ATTACH_LOCAL_BULK_WIRE_MIN,
                            ATTACH_LOCAL_BULK_WIRE_MAX,
                            &options->wire_budget) != 0)
            return -1;
        index += 2;
    }
    if (index < argc && strcmp(argv[index], "--bulk-stall-secs") == 0) {
        if (index + 1 >= argc || strcmp(argv[index + 1], "--") == 0 ||
            parse_u16_range(argv[index + 1], ATTACH_LOCAL_BULK_STALL_MIN,
                            ATTACH_LOCAL_BULK_STALL_MAX,
                            &options->stall_seconds) != 0)
            return -1;
        index += 2;
    }
    if (index < argc && strcmp(argv[index], "--force") == 0) {
        options->bulk_options |= ATTACH_LOCAL_BULK_OPTION_FORCE;
        index++;
    }
    if (index >= argc || strcmp(argv[index], "--") != 0 ||
        argc - index != 3)
        return -1;
    first = argv[index + 1];
    second = argv[index + 2];
    if (first == NULL || second == NULL)
        return -1;
    if (options->kind == ATTACH_CLIENT_BULK_PUSH_KIND) {
        options->local_path = first;
        options->remote_path = second;
    } else {
        options->remote_path = first;
        options->local_path = second;
    }
    options->local_path_length = strlen(options->local_path);
    options->remote_path_length = strlen(options->remote_path);
    if (options->local_path_length == 0U ||
        options->local_path_length > ATTACH_LOCAL_BULK_PATH_MAX ||
        options->remote_path_length == 0U ||
        options->remote_path_length >
            attach_local_bulk_request_path_limit(options->wire_budget))
        return -1;
    if (attach_local_bulk_open(
            options->kind, options->wire_budget, options->stall_seconds,
            options->bulk_options,
            (const uint8_t *)options->local_path,
            options->local_path_length,
            (const uint8_t *)options->remote_path,
            options->remote_path_length, &validation) != ATTACH_LOCAL_OK)
        return -1;
    return 0;
}

int attach_client_parse_options(int argc, char *const argv[],
                                attach_client_options_t *options_out)
{
    uint8_t encoded[ATTACH_LOCAL_MAX_PAYLOAD];
    size_t encoded_length = 0U;
    size_t argument_count;

    if (argv == NULL || options_out == NULL || argc < 3 ||
        strcmp(argv[0], "--socket") != 0 || argv[1] == NULL ||
        !attach_local_path_fits(argv[1])) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    memset(options_out, 0, sizeof(*options_out));
    options_out->socket_path = argv[1];
    if (argc == 3 && strcmp(argv[2], "terminal") == 0) {
        options_out->kind = ATTACH_CLIENT_TERMINAL_KIND;
        return ATTACH_LOCAL_OK;
    }
    if (strcmp(argv[2], "push") == 0 || strcmp(argv[2], "pull") == 0) {
        options_out->kind = strcmp(argv[2], "push") == 0
            ? ATTACH_CLIENT_BULK_PUSH_KIND : ATTACH_CLIENT_BULK_PULL_KIND;
        if (parse_bulk_options(argc, argv, options_out) != 0) {
            errno = EINVAL;
            return ATTACH_LOCAL_ERR_ARGUMENT;
        }
        return ATTACH_LOCAL_OK;
    }
    if (argc < 5 || strcmp(argv[2], "exec") != 0 ||
        strcmp(argv[3], "--") != 0) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    argument_count = (size_t)(argc - 4);
    if (argument_count == 0U ||
        argument_count > ATTACH_LOCAL_MAX_EXEC_ARGS ||
        attach_local_exec_encode(argument_count,
                                 (const char *const *)(argv + 4),
                                 encoded, &encoded_length) != ATTACH_LOCAL_OK) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    options_out->kind = ATTACH_CLIENT_EXEC_KIND;
    options_out->argument_count = argument_count;
    options_out->arguments = argv + 4;
    return ATTACH_LOCAL_OK;
}

static int client_socket_read(int fd, attach_local_parser_t *parser,
                              attach_local_record_t *record_out)
{
    uint8_t input[ATTACH_LOCAL_MAX_PAYLOAD];
    size_t needed;
    size_t consumed = 0U;
    ssize_t received;
    int status;

    if (!parser->header_ready)
        needed = ATTACH_LOCAL_HEADER_BYTES - parser->header_used;
    else
        needed = (size_t)parser->payload_length - parser->payload_used;
    if (needed == 0U) {
        errno = EPROTO;
        return ATTACH_LOCAL_ERR_PROTOCOL;
    }
    received = recv(fd, input, needed, 0);
    if (received < 0) {
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
            return ATTACH_LOCAL_WOULD_BLOCK;
        return ATTACH_LOCAL_ERR_IO;
    }
    if (received == 0) {
        if (parser->header_used != 0U || parser->payload_used != 0U) {
            errno = EPROTO;
            return ATTACH_LOCAL_ERR_PROTOCOL;
        }
        return ATTACH_LOCAL_CLOSED;
    }
    status = attach_local_parser_feed(parser, input, (size_t)received,
                                      &consumed, record_out);
    if (consumed != (size_t)received) {
        errno = EPROTO;
        return ATTACH_LOCAL_ERR_PROTOCOL;
    }
    return status;
}

static int outbound_pending(const attach_local_connection_t *connection)
{
    return connection->write_offset != connection->write_length;
}

static int queue_record(attach_local_connection_t *connection,
                        const attach_local_record_t *record)
{
    int status = attach_local_connection_queue(connection, record);

    return status == ATTACH_LOCAL_OK ? 0 : -1;
}

static int queue_signal(attach_local_connection_t *connection, int signum)
{
    attach_local_record_t record;

    if (signum <= 0 || signum > 63 ||
        attach_local_signal((uint8_t)signum, &record) != ATTACH_LOCAL_OK)
        return -1;
    return queue_record(connection, &record);
}

static int queue_resize(attach_local_connection_t *connection, int input_fd)
{
    attach_local_record_t record;
    uint16_t rows;
    uint16_t columns;
    uint16_t xpixel;
    uint16_t ypixel;

    if (current_terminal_dimensions(input_fd, &rows, &columns,
                                    &xpixel, &ypixel) != 0)
        return 0;
    if (attach_local_resize(rows, columns, xpixel, ypixel, &record) !=
        ATTACH_LOCAL_OK)
        return -1;
    return queue_record(connection, &record);
}

static int inbound_record(attach_local_record_t *record, int *accepted,
                          int *result_seen, int *exit_seen,
                          uint32_t *exit_code, int *close_seen,
                          uint32_t *close_code,
                          uint8_t output[ATTACH_LOCAL_MAX_PAYLOAD],
                          size_t *output_length, size_t *output_offset)
{
    uint32_t handle;
    uint32_t code;

    switch (record->type) {
    case ATTACH_LOCAL_RECORD_RESULT:
        if (*result_seen ||
            attach_local_result_decode(record, &handle, &code) !=
                ATTACH_LOCAL_OK)
            return -1;
        *result_seen = 1;
        if (code != 0U)
            return 1;
        if (handle == 0U)
            return -1;
        *accepted = 1;
        return 0;
    case ATTACH_LOCAL_RECORD_DATA:
        if (!*accepted || *exit_seen || *close_seen ||
            *output_length != *output_offset)
            return -1;
        memcpy(output, record->payload, (size_t)record->length);
        *output_length = (size_t)record->length;
        *output_offset = 0U;
        return 0;
    case ATTACH_LOCAL_RECORD_EXIT:
        if (!*accepted || *exit_seen || *close_seen ||
            *output_length != *output_offset ||
            attach_local_code_decode(record, ATTACH_LOCAL_RECORD_EXIT,
                                     &code) != ATTACH_LOCAL_OK)
            return -1;
        *exit_seen = 1;
        *exit_code = code;
        return 0;
    case ATTACH_LOCAL_RECORD_CLOSE:
        if (!*result_seen || *close_seen ||
            *output_length != *output_offset ||
            attach_local_code_decode(record, ATTACH_LOCAL_RECORD_CLOSE,
                                     &code) != ATTACH_LOCAL_OK)
            return -1;
        *close_seen = 1;
        *close_code = code;
        return 0;
    default:
        return -1;
    }
}

static int shell_status(uint32_t code)
{
    /* EXIT is a signed LE32 result.  Only the ordinary shell-status domain is
     * representable by main(3); negative and wider values remain loud. */
    if (code <= UINT32_C(255))
        return (int)code;
    return 1;
}

static const char *bulk_kind_name(uint8_t kind)
{
    return kind == ATTACH_CLIENT_BULK_PUSH_KIND ? "push" : "pull";
}

static int attach_client_run_bulk_connected(
    int socket_fd, const attach_local_record_t *open_record)
{
    attach_local_connection_t outbound;
    attach_local_parser_t inbound;
    attach_client_signals_t signals;
    uint32_t handle = 0U;
    uint32_t result_code = 0U;
    uint64_t transfer_id = 0U;
    int result_seen = 0;
    int accepted = 0;
    int local_close_sent = 0;
    int return_code = 1;
    int normal_finish = 0;
    int failure_reported = 0;

    memset(&outbound, 0, sizeof(outbound));
    memset(&inbound, 0, sizeof(inbound));
    memset(&signals, 0, sizeof(signals));
    if (socket_fd < 0 || open_record == NULL ||
        open_record->version != ATTACH_LOCAL_VERSION_V2 ||
        open_record->type != (uint8_t)ATTACH_LOCAL_RECORD_OPEN ||
        (open_record->kind != ATTACH_CLIENT_BULK_PUSH_KIND &&
         open_record->kind != ATTACH_CLIENT_BULK_PULL_KIND)) {
        errno = EINVAL;
        goto cleanup;
    }
    if (set_nonblocking_cloexec(socket_fd, NULL, NULL) != 0 ||
        install_signals(&signals) != 0)
        goto cleanup;
    outbound.fd = socket_fd;
    outbound.peer_uid = geteuid();
    outbound.active = 1;
    attach_local_parser_init(&outbound.parser, 0);
    attach_local_parser_init(&inbound, 0);
    if (queue_record(&outbound, open_record) != 0)
        goto cleanup;

    for (;;) {
        struct pollfd descriptor;
        int poll_result;
        int cancel_signal = g_attach_cancel_signal != 0
            ? (int)g_attach_cancel_signal : (int)g_attach_signal;

        if (cancel_signal != 0 && !result_seen) {
            return_code = cancel_signal <= 127 ? 128 + cancel_signal : 1;
            normal_finish = 1;
            break;
        }
        if (cancel_signal != 0 && accepted && !local_close_sent &&
            !outbound_pending(&outbound)) {
            attach_local_record_t close_record;

            if (attach_local_close_version(
                    ATTACH_LOCAL_VERSION_V2, ATTACH_CLIENT_CLOSE_PROTOCOL,
                    &close_record) != ATTACH_LOCAL_OK ||
                queue_record(&outbound, &close_record) != 0)
                goto cleanup;
            local_close_sent = 1;
            return_code = cancel_signal <= 127 ? 128 + cancel_signal : 1;
        }
        if (local_close_sent && !outbound_pending(&outbound)) {
            normal_finish = 1;
            break;
        }

        memset(&descriptor, 0, sizeof(descriptor));
        descriptor.fd = socket_fd;
        if (!local_close_sent)
            descriptor.events |= POLLIN;
        if (outbound_pending(&outbound))
            descriptor.events |= POLLOUT;
        poll_result = poll(&descriptor, 1U, -1);
        if (poll_result < 0) {
            if (errno == EINTR)
                continue;
            goto cleanup;
        }
        if ((descriptor.revents & (POLLERR | POLLNVAL)) != 0) {
            errno = EIO;
            goto cleanup;
        }
        if (outbound_pending(&outbound) &&
            (descriptor.revents & POLLOUT) != 0) {
            int status = attach_local_connection_flush(&outbound);

            if (status != ATTACH_LOCAL_OK &&
                status != ATTACH_LOCAL_WOULD_BLOCK)
                goto cleanup;
        }
        if (!local_close_sent &&
            (descriptor.revents & (POLLIN | POLLHUP)) != 0) {
            attach_local_record_t record;
            int status = client_socket_read(socket_fd, &inbound, &record);

            if (status == ATTACH_LOCAL_FRAME_READY) {
                if (record.version != ATTACH_LOCAL_VERSION_V2)
                    goto protocol_failure;
                if (record.type == ATTACH_LOCAL_RECORD_RESULT) {
                    if (result_seen ||
                        attach_local_bulk_result_decode(
                            &record, &handle, &result_code,
                            &transfer_id) != ATTACH_LOCAL_OK)
                        goto protocol_failure;
                    result_seen = 1;
                    if (result_code != 0U) {
                        fprintf(stderr,
                                "unmoor: attach refused "
                                "(handle=%" PRIu32 ", code=%" PRIu32
                                ", transfer_id=%" PRIu64 ")%s\n",
                                handle, result_code, transfer_id,
                                /* Name the confinement refusal so the
                                 * operator sees the remedy, not just a code. */
                                result_code ==
                                        ATTACH_LOCAL_BULK_RESULT_CONFINED
                                    ? " local path outside the terminal"
                                      " client's confinement roots"
                                    : "");
                        failure_reported = 1;
                        return_code = 1;
                        normal_finish = 1;
                        break;
                    }
                    accepted = 1;
                } else if (record.type == ATTACH_LOCAL_RECORD_CLOSE) {
                    uint32_t close_code = 0U;

                    if (!accepted ||
                        attach_local_code_decode(
                            &record, ATTACH_LOCAL_RECORD_CLOSE,
                            &close_code) != ATTACH_LOCAL_OK)
                        goto protocol_failure;
                    if (close_code ==
                        ATTACH_LOCAL_BULK_CLOSE_CONFINED) {
                        fprintf(stderr,
                                "unmoor: child transfer client confinement "
                                "required but unavailable; refusing; use "
                                "--confine=best-effort on the control session "
                                "to continue at your own security risk "
                                "(kind=%s transfer_id=%" PRIu64 ")\n",
                                bulk_kind_name(open_record->kind),
                                transfer_id);
                    } else {
                        fprintf(stderr,
                                "unmoor.bulk.result.v1 kind=%s transfer_id=%"
                                PRIu64 " code=%" PRIu32 "\n",
                                bulk_kind_name(open_record->kind),
                                transfer_id, close_code);
                    }
                    return_code = close_code == 0U ? 0 : 1;
                    normal_finish = 1;
                    break;
                } else {
                    goto protocol_failure;
                }
            } else if (status == ATTACH_LOCAL_CLOSED) {
                goto protocol_failure;
            } else if (status != ATTACH_LOCAL_OK &&
                       status != ATTACH_LOCAL_WOULD_BLOCK) {
                goto cleanup;
            }
        }
        continue;

protocol_failure:
        errno = EPROTO;
        goto cleanup;
    }

cleanup:
    {
        int saved_errno = errno;
        int cleanup_failed = 0;

        if (!normal_finish && !failure_reported) {
            if (saved_errno == 0)
                saved_errno = EPROTO;
            fprintf(stderr, "unmoor: local attach failed: %s\n",
                    strerror(saved_errno));
        }
        restore_signals(&signals);
        if (socket_fd >= 0 && close(socket_fd) != 0)
            cleanup_failed = 1;
        if (cleanup_failed) {
            if (normal_finish)
                fprintf(stderr, "unmoor: local attach cleanup failed\n");
            return_code = 1;
        }
        errno = saved_errno;
    }
    return return_code;
}

int attach_client_run_connected(int socket_fd, int input_fd, int output_fd,
                                const attach_local_record_t *open_record)
{
    attach_local_connection_t outbound;
    attach_local_parser_t inbound;
    attach_client_signals_t signals;
    attach_client_termios_t saved_terminal;
    uint8_t output[ATTACH_LOCAL_MAX_PAYLOAD];
    size_t output_length = 0U;
    size_t output_offset = 0U;
    int original_output_flags = -1;
    int original_output_descriptor_flags = -1;
    int result_seen = 0;
    int accepted = 0;
    int input_ended = 0;
    int exit_seen = 0;
    int close_seen = 0;
    int local_close_sent = 0;
    int local_cancel_status = 1;
    int raw_mode_attempted = 0;
    uint32_t exit_code = 0U;
    uint32_t close_code = 0U;
    int terminal_kind;
    int return_code = 1;
    int setup_complete = 0;
    int normal_finish = 0;
    int failure_reported = 0;

    memset(&outbound, 0, sizeof(outbound));
    memset(&inbound, 0, sizeof(inbound));
    memset(&signals, 0, sizeof(signals));
    memset(&saved_terminal, 0, sizeof(saved_terminal));
    if (open_record != NULL &&
        open_record->version == ATTACH_LOCAL_VERSION_V2 &&
        (open_record->kind == ATTACH_CLIENT_BULK_PUSH_KIND ||
         open_record->kind == ATTACH_CLIENT_BULK_PULL_KIND))
        return attach_client_run_bulk_connected(socket_fd, open_record);
    if (socket_fd < 0 || input_fd < 0 || output_fd < 0 ||
        open_record == NULL ||
        open_record->version != ATTACH_LOCAL_VERSION_V1 ||
        open_record->type != (uint8_t)ATTACH_LOCAL_RECORD_OPEN ||
        (open_record->kind != ATTACH_CLIENT_TERMINAL_KIND &&
         open_record->kind != ATTACH_CLIENT_EXEC_KIND)) {
        errno = EINVAL;
        goto cleanup;
    }
    terminal_kind = open_record->kind == ATTACH_CLIENT_TERMINAL_KIND;
    if (set_nonblocking_cloexec(socket_fd, NULL, NULL) != 0 ||
        set_nonblocking_cloexec(output_fd, &original_output_flags,
                                &original_output_descriptor_flags) != 0 ||
        install_signals(&signals) != 0)
        goto cleanup;
    outbound.fd = socket_fd;
    outbound.peer_uid = geteuid();
    outbound.active = 1;
    attach_local_parser_init(&outbound.parser, 0);
    attach_local_parser_init(&inbound, 0);
    if (queue_record(&outbound, open_record) != 0)
        goto cleanup;
    setup_complete = 1;

    for (;;) {
        struct pollfd poll_fds[3];
        nfds_t poll_count = 1U;
        int socket_index = 0;
        int input_index = -1;
        int output_index = -1;
        int poll_result;

        if (close_seen && output_offset == output_length) {
            if (exit_seen)
                return_code = shell_status(exit_code);
            else if (close_code == 0U)
                return_code = 0;
            else
                return_code = shell_status(close_code);
            normal_finish = 1;
            break;
        }
        if (local_close_sent && !outbound_pending(&outbound)) {
            return_code = local_cancel_status;
            normal_finish = 1;
            break;
        }
        if (!accepted && (g_attach_cancel_signal != 0 ||
                          g_attach_signal != 0 ||
                          g_attach_signal_overflow != 0)) {
            int signum = g_attach_cancel_signal != 0 ?
                         (int)g_attach_cancel_signal : (int)g_attach_signal;

            if (signum > 0 && signum <= 127)
                return_code = 128 + signum;
            normal_finish = 1;
            break;
        }

        if (accepted && terminal_kind && !raw_mode_attempted) {
            raw_mode_attempted = 1;
            if (enter_raw_mode(input_fd, &saved_terminal) != 0)
                goto cleanup;
        }

        if (!outbound_pending(&outbound) && accepted && !local_close_sent) {
            if (g_attach_cancel_signal != 0 ||
                g_attach_signal_overflow != 0) {
                attach_local_record_t record;

                if (attach_local_close(ATTACH_CLIENT_CLOSE_PROTOCOL, &record) !=
                        ATTACH_LOCAL_OK ||
                    queue_record(&outbound, &record) != 0)
                    goto cleanup;
                local_close_sent = 1;
                input_ended = 1;
                if (g_attach_cancel_signal > 0 &&
                    g_attach_cancel_signal <= 127)
                    local_cancel_status = 128 + (int)g_attach_cancel_signal;
            } else if (g_attach_signal != 0) {
                int signum = (int)g_attach_signal;

                g_attach_signal = 0;
                if (queue_signal(&outbound, signum) != 0)
                    goto cleanup;
            } else if (terminal_kind && g_attach_resize != 0) {
                g_attach_resize = 0;
                if (queue_resize(&outbound, input_fd) != 0)
                    goto cleanup;
            }
        }

        memset(poll_fds, 0, sizeof(poll_fds));
        poll_fds[socket_index].fd = socket_fd;
        if (output_offset == output_length && !close_seen)
            poll_fds[socket_index].events |= POLLIN;
        if (outbound_pending(&outbound))
            poll_fds[socket_index].events |= POLLOUT;

        if (accepted && !input_ended && !local_close_sent &&
            !outbound_pending(&outbound) && g_attach_signal == 0 &&
            g_attach_resize == 0 && g_attach_cancel_signal == 0) {
            input_index = (int)poll_count;
            poll_fds[poll_count].fd = input_fd;
            poll_fds[poll_count].events = POLLIN;
            poll_count++;
        }
        if (output_offset != output_length) {
            output_index = (int)poll_count;
            poll_fds[poll_count].fd = output_fd;
            poll_fds[poll_count].events = POLLOUT;
            poll_count++;
        }

        poll_result = poll(poll_fds, poll_count, -1);
        if (poll_result < 0) {
            if (errno == EINTR)
                continue;
            goto cleanup;
        }

        if (outbound_pending(&outbound) &&
            (poll_fds[socket_index].revents & POLLOUT) != 0) {
            int status = attach_local_connection_flush(&outbound);

            if (status != ATTACH_LOCAL_OK &&
                status != ATTACH_LOCAL_WOULD_BLOCK)
                goto cleanup;
        }
        if ((poll_fds[socket_index].revents & (POLLERR | POLLNVAL)) != 0) {
            errno = EIO;
            goto cleanup;
        }

        if (output_index >= 0 &&
            (poll_fds[output_index].revents &
             (POLLOUT | POLLNVAL)) != 0) {
            ssize_t written = write(output_fd, output + output_offset,
                                    output_length - output_offset);

            if (written > 0) {
                output_offset += (size_t)written;
                if (output_offset == output_length) {
                    output_offset = 0U;
                    output_length = 0U;
                }
            } else if (written == 0) {
                errno = EIO;
                goto cleanup;
            } else if (errno != EINTR && errno != EAGAIN &&
                       errno != EWOULDBLOCK) {
                goto cleanup;
            }
        }
        if (output_index >= 0 &&
            (poll_fds[output_index].revents & POLLERR) != 0) {
            errno = EIO;
            goto cleanup;
        }

        if (input_index >= 0 &&
            (poll_fds[input_index].revents &
             (POLLIN | POLLHUP | POLLNVAL)) != 0) {
            uint8_t input[ATTACH_LOCAL_MAX_PAYLOAD];
            ssize_t received = read(input_fd, input, sizeof(input));

            if (received > 0) {
                attach_local_record_t record;

                if (attach_local_data(input, (size_t)received, &record) !=
                        ATTACH_LOCAL_OK ||
                    queue_record(&outbound, &record) != 0)
                    goto cleanup;
            } else if (received == 0) {
                attach_local_record_t record;

                if (attach_local_eof(&record) != ATTACH_LOCAL_OK ||
                    queue_record(&outbound, &record) != 0)
                    goto cleanup;
                input_ended = 1;
            } else if (errno != EINTR && errno != EAGAIN &&
                       errno != EWOULDBLOCK) {
                goto cleanup;
            }
        }
        if (input_index >= 0 &&
            (poll_fds[input_index].revents & POLLERR) != 0) {
            errno = EIO;
            goto cleanup;
        }

        if ((poll_fds[socket_index].revents & (POLLIN | POLLHUP)) != 0 &&
            output_offset == output_length && !close_seen) {
            attach_local_record_t record;
            int status = client_socket_read(socket_fd, &inbound, &record);

            if (status == ATTACH_LOCAL_FRAME_READY) {
                int outcome = inbound_record(&record, &accepted, &result_seen,
                                             &exit_seen, &exit_code,
                                             &close_seen, &close_code,
                                             output, &output_length,
                                             &output_offset);

                if (outcome > 0) {
                    uint32_t refused_handle;
                    uint32_t refused_code;

                    if (attach_local_result_decode(&record, &refused_handle,
                                                   &refused_code) ==
                        ATTACH_LOCAL_OK) {
                        fprintf(stderr,
                                "unmoor: attach refused (handle=%u, code=%u)\n",
                                refused_handle, refused_code);
                    } else {
                        fprintf(stderr, "unmoor: attach refused\n");
                    }
                    failure_reported = 1;
                    return_code = 1;
                    break;
                }
                if (outcome < 0) {
                    errno = EPROTO;
                    goto cleanup;
                }
            } else if (status == ATTACH_LOCAL_CLOSED) {
                errno = EPROTO;
                goto cleanup;
            } else if (status != ATTACH_LOCAL_OK &&
                       status != ATTACH_LOCAL_WOULD_BLOCK) {
                goto cleanup;
            }
        }
    }

cleanup:
    {
        int cleanup_failed = 0;
        int saved_errno = errno;

        if (!normal_finish && !failure_reported) {
            if (saved_errno == 0)
                saved_errno = EPROTO;
            fprintf(stderr, "unmoor: local attach failed: %s\n",
                    strerror(saved_errno));
        }
        if (restore_terminal(input_fd, &saved_terminal) != 0)
            cleanup_failed = 1;
        restore_signals(&signals);
        if (original_output_flags >= 0 &&
            fcntl(output_fd, F_SETFL, original_output_flags) != 0)
            cleanup_failed = 1;
        if (original_output_descriptor_flags >= 0 &&
            fcntl(output_fd, F_SETFD,
                  original_output_descriptor_flags) != 0)
            cleanup_failed = 1;
        if (socket_fd >= 0 && close(socket_fd) != 0)
            cleanup_failed = 1;
        if (!setup_complete || cleanup_failed) {
            if (cleanup_failed && normal_finish)
                fprintf(stderr, "unmoor: local attach cleanup failed\n");
            return_code = 1;
        }
        errno = saved_errno;
    }
    return return_code;
}

int attach_client_command(int argc, char *argv[])
{
    attach_client_options_t options;
    attach_local_record_t open_record;
    uint16_t rows;
    uint16_t columns;
    uint16_t xpixel;
    uint16_t ypixel;
    int socket_fd = -1;
    int status;
    int debuggable = 0;
    confine_role_t confine_role;
    int runtime_status;

    for (int index = 0; index < argc; index++) {
        int move;

        if (strcmp(argv[index], "--") == 0)
            break;
        if (strcmp(argv[index], "--debuggable") != 0)
            continue;
        if (debuggable) {
            fprintf(stderr, "attach: --debuggable may appear once\n");
            return 1;
        }
        debuggable = 1;
        for (move = index; move + 1 < argc; move++)
            argv[move] = argv[move + 1];
        argc--;
        index--;
    }

    /* client-confinement: --confine is positional-transparent, exactly like --debuggable
     * above: strip it before the fixed `--socket PATH KIND` grammar runs. */
    for (int index = 0; index < argc; index++) {
        int consumed;
        int move;

        if (strcmp(argv[index], "--") == 0)
            break;
        if (strcmp(argv[index], "--confine") != 0 &&
            strncmp(argv[index], "--confine=", 10U) != 0 &&
            strcmp(argv[index], "--confine-root") != 0 &&
            strncmp(argv[index], "--confine-root=", 15U) != 0)
            continue;
        {
            int cursor = index;

            if (confine_parse_option("attach", argc, argv, &cursor) < 0)
                return 1;
            consumed = cursor - index + 1;
        }
        for (move = index; move + consumed < argc; move++)
            argv[move] = argv[move + consumed];
        argc -= consumed;
        index--;
    }

    status = attach_client_parse_options(argc, argv, &options);
    if (status != ATTACH_LOCAL_OK) {
        fprintf(stderr,
                "Usage: unmoor attach --socket PATH terminal\n"
                "       unmoor attach --socket PATH exec -- ARGV...\n"
                "       unmoor attach --socket PATH push [--bulk-mtu B] "
                "[--bulk-stall-secs S] [--force] -- LOCAL REMOTE\n"
                "       unmoor attach --socket PATH pull [--bulk-mtu B] "
                "[--bulk-stall-secs S] [--force] -- REMOTE LOCAL\n");
        return 1;
    }
    if (process_harden_command("attach", debuggable) != 0)
        return 1;
    confine_note_debuggable("attach", debuggable);
    if (options.kind == ATTACH_CLIENT_TERMINAL_KIND) {
        initial_terminal_dimensions(STDIN_FILENO, &rows, &columns,
                                    &xpixel, &ypixel);
        if (attach_local_terminal_open(rows, columns, &open_record) !=
                ATTACH_LOCAL_OK) {
            fprintf(stderr, "unmoor: cannot encode terminal attach: %s\n",
                    strerror(errno));
            return 1;
        }
    } else if (options.kind == ATTACH_CLIENT_EXEC_KIND) {
        if (attach_local_exec_open(
                options.argument_count,
                (const char *const *)options.arguments,
                &open_record) != ATTACH_LOCAL_OK) {
            fprintf(stderr, "unmoor: invalid exec argument vector: %s\n",
                    strerror(errno));
            return 1;
        }
    } else if (attach_local_bulk_open(
                   options.kind, options.wire_budget,
                   options.stall_seconds, options.bulk_options,
                   (const uint8_t *)options.local_path,
                   options.local_path_length,
                   (const uint8_t *)options.remote_path,
                   options.remote_path_length,
                   &open_record) != ATTACH_LOCAL_OK) {
        fprintf(stderr, "unmoor: invalid bulk attach request: %s\n",
                strerror(errno));
        return 1;
    }
    status = attach_local_connect(options.socket_path, &socket_fd);
    if (status != ATTACH_LOCAL_OK) {
        fprintf(stderr, "unmoor: cannot connect attach socket %s: %s\n",
                options.socket_path, strerror(errno));
        return 1;
    }
    /* Client confinement point: the attach socket is connected and the open
     * record is already encoded, so this client needs no filesystem at all
     * from here on. The ruleset is empty for both attach roles. A terminal
     * attach selects TRAP and supplies static-lifetime tty restoration;
     * non-terminal kinds retain KILL_PROCESS. */
    confine_role = options.kind == ATTACH_CLIENT_TERMINAL_KIND
                       ? CONFINE_ROLE_ATTACH_TERMINAL_CLIENT
                       : CONFINE_ROLE_ATTACH_CLIENT;
    if (options.kind == ATTACH_CLIENT_TERMINAL_KIND)
        attach_panic_prepare();
    if (confine_apply("attach", confine_role) != 0) {
        if (options.kind == ATTACH_CLIENT_TERMINAL_KIND)
            attach_panic_clear();
        (void)close(socket_fd);
        return 1;
    }
    runtime_status = attach_client_run_connected(socket_fd, STDIN_FILENO,
                                                 STDOUT_FILENO, &open_record);
    if (options.kind == ATTACH_CLIENT_TERMINAL_KIND)
        attach_panic_clear();
    return runtime_status;
}
