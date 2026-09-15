/*
 * attach_local.c — channel-session bounded same-uid local attach protocol
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#else
#define _GNU_SOURCE
#endif
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "attach_local.h"
#include "bulk.h"

#define ATTACH_LOCAL_DIRECTORY_MODE ((mode_t)0700)
#define ATTACH_LOCAL_SOCKET_MODE ((mode_t)0600)
#define ATTACH_LOCAL_COMPONENT_CAP 256U

/* Linux O_PATH references let the verified component walk, fstatat/fchdir
 * consumers and relative socket operations proceed without granting Landlock
 * READ_DIR. Darwin has no O_PATH and no Landlock, so retain the historical
 * readable directory descriptor there. */
#if defined(__linux__)
#define ATTACH_LOCAL_DIRECTORY_REFERENCE O_PATH
#else
#define ATTACH_LOCAL_DIRECTORY_REFERENCE O_RDONLY
#endif
#define ATTACH_LOCAL_DIRECTORY_REFERENCE_FLAGS \
    (ATTACH_LOCAL_DIRECTORY_REFERENCE | O_DIRECTORY | O_CLOEXEC)

_Static_assert(ATTACH_LOCAL_BULK_WIRE_MIN == BULK_WIRE_MIN,
               "local and bulk-transfer minimum wire budgets diverged");
_Static_assert(ATTACH_LOCAL_BULK_WIRE_MAX == BULK_WIRE_MAX,
               "local and bulk-transfer maximum wire budgets diverged");
_Static_assert(ATTACH_LOCAL_BULK_PATH_MAX == BULK_PATH_MAX,
               "local and bulk-transfer path bounds diverged");

static void put_u16_le(uint8_t out[2], uint16_t value)
{
    out[0] = (uint8_t)(value & UINT16_C(0xff));
    out[1] = (uint8_t)(value >> 8);
}

static uint16_t get_u16_le(const uint8_t in[2])
{
    return (uint16_t)((uint16_t)in[0] | ((uint16_t)in[1] << 8));
}

static void put_u32_le(uint8_t out[4], uint32_t value)
{
    out[0] = (uint8_t)(value & UINT32_C(0xff));
    out[1] = (uint8_t)((value >> 8) & UINT32_C(0xff));
    out[2] = (uint8_t)((value >> 16) & UINT32_C(0xff));
    out[3] = (uint8_t)(value >> 24);
}

static uint32_t get_u32_le(const uint8_t in[4])
{
    return (uint32_t)in[0] |
           ((uint32_t)in[1] << 8) |
           ((uint32_t)in[2] << 16) |
           ((uint32_t)in[3] << 24);
}

static void put_u64_le(uint8_t out[8], uint64_t value)
{
    unsigned int i;

    for (i = 0U; i < 8U; i++)
        out[i] = (uint8_t)(value >> (8U * i));
}

static uint64_t get_u64_le(const uint8_t in[8])
{
    uint64_t value = 0U;
    unsigned int i;

    for (i = 0U; i < 8U; i++)
        value |= (uint64_t)in[i] << (8U * i);
    return value;
}

static int record_type_valid(uint8_t type)
{
    return type >= (uint8_t)ATTACH_LOCAL_RECORD_OPEN &&
           type <= (uint8_t)ATTACH_LOCAL_RECORD_CLOSE;
}

static int local_handle_valid(uint32_t handle)
{
    return (handle & UINT32_C(0x0f)) != 0U && (handle >> 4) != 0U;
}

static int bulk_kind_valid(uint8_t kind)
{
    return kind == ATTACH_LOCAL_KIND_BULK_PUSH ||
           kind == ATTACH_LOCAL_KIND_BULK_PULL;
}

size_t attach_local_bulk_request_path_limit(uint16_t wire_budget)
{
    size_t available;

    if (wire_budget < ATTACH_LOCAL_BULK_WIRE_MIN ||
        wire_budget > ATTACH_LOCAL_BULK_WIRE_MAX ||
        wire_budget < ATTACH_LOCAL_BULK_REQUEST_BASE_BYTES)
        return 0U;
    available = (size_t)wire_budget -
                ATTACH_LOCAL_BULK_REQUEST_BASE_BYTES;
    return available < ATTACH_LOCAL_BULK_PATH_MAX
        ? available : ATTACH_LOCAL_BULK_PATH_MAX;
}

static int record_header_valid(uint8_t version, uint8_t type, uint8_t kind,
                               uint8_t flags)
{
    if (!record_type_valid(type) || flags != 0U)
        return 0;
    if (version == ATTACH_LOCAL_VERSION_V1) {
        if (type == (uint8_t)ATTACH_LOCAL_RECORD_OPEN)
            return kind == ATTACH_LOCAL_KIND_TERMINAL ||
                   kind == ATTACH_LOCAL_KIND_EXEC;
        return kind == 0U;
    }
    if (version == ATTACH_LOCAL_VERSION_V2) {
        if (type == (uint8_t)ATTACH_LOCAL_RECORD_OPEN)
            return bulk_kind_valid(kind);
        return kind == 0U &&
               (type == (uint8_t)ATTACH_LOCAL_RECORD_RESULT ||
                type == (uint8_t)ATTACH_LOCAL_RECORD_CLOSE);
    }
    return 0;
}

static int bulk_result_valid(uint32_t handle, uint32_t code,
                             uint64_t transfer_id)
{
    if (code > 4U && code != ATTACH_LOCAL_BULK_RESULT_CONFINED)
        return 0;
    if (code == 0U)
        return local_handle_valid(handle) && transfer_id != 0U;
    if (handle == 0U || transfer_id == 0U)
        return handle == 0U && transfer_id == 0U;
    return local_handle_valid(handle);
}

static int bulk_open_decode_payload(const attach_local_record_t *record,
                                    attach_local_bulk_open_t *open_out)
{
    attach_local_bulk_open_t decoded;
    size_t expected;
    size_t remote_limit;

    if (record == NULL || record->version != ATTACH_LOCAL_VERSION_V2 ||
        record->type != (uint8_t)ATTACH_LOCAL_RECORD_OPEN ||
        !bulk_kind_valid(record->kind) ||
        record->length < ATTACH_LOCAL_BULK_OPEN_PREFIX_BYTES + 2U)
        return 0;
    memset(&decoded, 0, sizeof(decoded));
    decoded.kind = record->kind;
    decoded.wire_budget = get_u16_le(record->payload);
    decoded.stall_seconds = get_u16_le(record->payload + 2U);
    decoded.options = record->payload[4];
    decoded.local_path_length = get_u16_le(record->payload + 8U);
    decoded.remote_path_length = get_u16_le(record->payload + 10U);
    remote_limit = attach_local_bulk_request_path_limit(decoded.wire_budget);
    expected = ATTACH_LOCAL_BULK_OPEN_PREFIX_BYTES +
               (size_t)decoded.local_path_length +
               (size_t)decoded.remote_path_length;
    if (decoded.stall_seconds < ATTACH_LOCAL_BULK_STALL_MIN ||
        decoded.stall_seconds > ATTACH_LOCAL_BULK_STALL_MAX ||
        (decoded.options & ~ATTACH_LOCAL_BULK_OPTION_FORCE) != 0U ||
        record->payload[5] != 0U || record->payload[6] != 0U ||
        record->payload[7] != 0U ||
        decoded.local_path_length == 0U ||
        decoded.local_path_length > ATTACH_LOCAL_BULK_PATH_MAX ||
        decoded.remote_path_length == 0U || remote_limit == 0U ||
        (size_t)decoded.remote_path_length > remote_limit ||
        expected != (size_t)record->length ||
        memchr(record->payload + ATTACH_LOCAL_BULK_OPEN_PREFIX_BYTES, '\0',
               (size_t)decoded.local_path_length) != NULL ||
        !bulk_remote_path_valid(
            record->payload + ATTACH_LOCAL_BULK_OPEN_PREFIX_BYTES +
                (size_t)decoded.local_path_length,
            (size_t)decoded.remote_path_length))
        return 0;
    if (open_out != NULL) {
        memcpy(decoded.local_path,
               record->payload + ATTACH_LOCAL_BULK_OPEN_PREFIX_BYTES,
               (size_t)decoded.local_path_length);
        memcpy(decoded.remote_path,
               record->payload + ATTACH_LOCAL_BULK_OPEN_PREFIX_BYTES +
                   (size_t)decoded.local_path_length,
               (size_t)decoded.remote_path_length);
        decoded.local_path[decoded.local_path_length] = '\0';
        decoded.remote_path[decoded.remote_path_length] = '\0';
        *open_out = decoded;
    }
    return 1;
}

static int record_payload_valid(const attach_local_record_t *record)
{
    if (record->version == ATTACH_LOCAL_VERSION_V2) {
        if (record->type == (uint8_t)ATTACH_LOCAL_RECORD_OPEN)
            return bulk_open_decode_payload(record, NULL);
        if (record->type == (uint8_t)ATTACH_LOCAL_RECORD_RESULT) {
            if (record->length != 16U)
                return 0;
            return bulk_result_valid(get_u32_le(record->payload),
                                     get_u32_le(record->payload + 4U),
                                     get_u64_le(record->payload + 8U));
        }
        return record->type == (uint8_t)ATTACH_LOCAL_RECORD_CLOSE &&
               record->length == 4U;
    }
    if (record->version != ATTACH_LOCAL_VERSION_V1)
        return 0;
    if (record->type == (uint8_t)ATTACH_LOCAL_RECORD_OPEN) {
        if (record->kind == ATTACH_LOCAL_KIND_TERMINAL) {
            uint16_t rows;
            uint16_t columns;

            if (record->length != 4U)
                return 0;
            rows = get_u16_le(record->payload);
            columns = get_u16_le(record->payload + 2U);
            return rows >= 1U && rows <= 1000U &&
                   columns >= 1U && columns <= 1000U;
        }
        if (record->kind == ATTACH_LOCAL_KIND_EXEC) {
            attach_local_exec_argv_t decoded;

            return record->length >= 2U &&
                   attach_local_exec_decode(record->payload,
                                            (size_t)record->length,
                                            &decoded) == ATTACH_LOCAL_OK;
        }
        return 0;
    }
    if (record->type == (uint8_t)ATTACH_LOCAL_RECORD_RESULT) {
        uint32_t handle;
        uint32_t code;

        if (record->length != 8U)
            return 0;
        handle = get_u32_le(record->payload);
        code = get_u32_le(record->payload + 4U);
        if (code > 4U)
            return 0;
        if (code == 0U)
            return local_handle_valid(handle);
        return handle == 0U || local_handle_valid(handle);
    }
    if (record->type == (uint8_t)ATTACH_LOCAL_RECORD_DATA)
        return record->length >= 1U &&
               record->length <= ATTACH_LOCAL_MAX_PAYLOAD;
    if (record->type == (uint8_t)ATTACH_LOCAL_RECORD_EOF)
        return record->length == 0U;
    if (record->type == (uint8_t)ATTACH_LOCAL_RECORD_RESIZE) {
        uint16_t rows;
        uint16_t columns;

        if (record->length != 8U)
            return 0;
        rows = get_u16_le(record->payload);
        columns = get_u16_le(record->payload + 2U);
        return rows >= 1U && rows <= 1000U &&
               columns >= 1U && columns <= 1000U;
    }
    if (record->type == (uint8_t)ATTACH_LOCAL_RECORD_SIGNAL)
        return record->length == 4U && record->payload[0] >= 1U &&
               record->payload[0] <= 63U && record->payload[1] == 0U &&
               record->payload[2] == 0U && record->payload[3] == 0U;
    if (record->type == (uint8_t)ATTACH_LOCAL_RECORD_EXIT ||
        record->type == (uint8_t)ATTACH_LOCAL_RECORD_CLOSE)
        return record->length == 4U;
    return 0;
}

static void parser_reset_frame(attach_local_parser_t *parser)
{
    memset(parser->header, 0, sizeof(parser->header));
    parser->header_used = 0U;
    parser->payload_length = 0U;
    parser->payload_used = 0U;
    parser->header_ready = 0;
}

static int parser_fail(attach_local_parser_t *parser)
{
    parser->poisoned = 1;
    errno = EPROTO;
    return ATTACH_LOCAL_ERR_PROTOCOL;
}

static int parser_finish(attach_local_parser_t *parser,
                         attach_local_record_t *record_out)
{
    record_out->version = parser->header[0];
    record_out->type = parser->header[1];
    record_out->kind = parser->header[2];
    record_out->length = parser->payload_length;
    if (parser->payload_length != 0U) {
        memcpy(record_out->payload, parser->payload,
               (size_t)parser->payload_length);
    }
    if (!record_payload_valid(record_out))
        return parser_fail(parser);
    if (parser->saw_first_record &&
        record_out->type == (uint8_t)ATTACH_LOCAL_RECORD_OPEN)
        return parser_fail(parser);
    parser->saw_first_record = 1;
    parser->first_record_deadline_ms = 0;
    parser_reset_frame(parser);
    return ATTACH_LOCAL_FRAME_READY;
}

int attach_local_record_encode(const attach_local_record_t *record,
                               uint8_t *wire, size_t wire_capacity,
                               size_t *wire_length_out)
{
    size_t wire_length;

    if (record == NULL || wire == NULL || wire_length_out == NULL ||
        !record_header_valid(record->version, record->type, record->kind, 0U) ||
        !record_payload_valid(record) ||
        record->length > ATTACH_LOCAL_MAX_PAYLOAD) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    wire_length = ATTACH_LOCAL_HEADER_BYTES + (size_t)record->length;
    if (wire_capacity < wire_length) {
        errno = EMSGSIZE;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    wire[0] = record->version;
    wire[1] = record->type;
    wire[2] = record->kind;
    wire[3] = 0U;
    put_u32_le(wire + 4U, record->length);
    if (record->length != 0U)
        memcpy(wire + ATTACH_LOCAL_HEADER_BYTES, record->payload,
               (size_t)record->length);
    *wire_length_out = wire_length;
    return ATTACH_LOCAL_OK;
}

void attach_local_parser_init(attach_local_parser_t *parser, int64_t now_ms)
{
    if (parser == NULL)
        return;
    memset(parser, 0, sizeof(*parser));
    if (now_ms > INT64_MAX - ATTACH_LOCAL_FIRST_RECORD_MS)
        parser->first_record_deadline_ms = INT64_MAX;
    else
        parser->first_record_deadline_ms =
            now_ms + ATTACH_LOCAL_FIRST_RECORD_MS;
}

int attach_local_parser_feed(attach_local_parser_t *parser,
                             const uint8_t *input, size_t input_length,
                             size_t *consumed_out,
                             attach_local_record_t *record_out)
{
    size_t consumed = 0U;

    if (parser == NULL || consumed_out == NULL || record_out == NULL ||
        (input == NULL && input_length != 0U)) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    *consumed_out = 0U;
    if (parser->poisoned)
        return parser_fail(parser);

    while (consumed < input_length) {
        if (!parser->header_ready) {
            size_t missing = ATTACH_LOCAL_HEADER_BYTES - parser->header_used;
            size_t take = input_length - consumed;

            if (take > missing)
                take = missing;
            memcpy(parser->header + parser->header_used, input + consumed,
                   take);
            parser->header_used += take;
            consumed += take;
            if (parser->header_used != ATTACH_LOCAL_HEADER_BYTES)
                continue;
            if (!record_header_valid(parser->header[0], parser->header[1],
                                     parser->header[2], parser->header[3])) {
                *consumed_out = consumed;
                return parser_fail(parser);
            }
            parser->payload_length = get_u32_le(parser->header + 4U);
            if (parser->payload_length > ATTACH_LOCAL_MAX_PAYLOAD) {
                *consumed_out = consumed;
                return parser_fail(parser);
            }
            parser->header_ready = 1;
            if (parser->payload_length == 0U) {
                *consumed_out = consumed;
                return parser_finish(parser, record_out);
            }
        }

        if (parser->header_ready) {
            size_t missing = (size_t)parser->payload_length -
                             parser->payload_used;
            size_t take = input_length - consumed;

            if (take > missing)
                take = missing;
            memcpy(parser->payload + parser->payload_used, input + consumed,
                   take);
            parser->payload_used += take;
            consumed += take;
            if (parser->payload_used == (size_t)parser->payload_length) {
                *consumed_out = consumed;
                return parser_finish(parser, record_out);
            }
        }
    }

    *consumed_out = consumed;
    return ATTACH_LOCAL_OK;
}

int attach_local_parser_check_deadline(const attach_local_parser_t *parser,
                                       int64_t now_ms)
{
    if (parser == NULL) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    if (!parser->saw_first_record &&
        now_ms >= parser->first_record_deadline_ms) {
        errno = ETIMEDOUT;
        return ATTACH_LOCAL_ERR_TIMEOUT;
    }
    return ATTACH_LOCAL_OK;
}

int attach_local_exec_encode_slices(const uint8_t *const arguments[],
                                    const uint16_t lengths[], size_t count,
                                    uint8_t out[ATTACH_LOCAL_MAX_PAYLOAD],
                                    size_t *length_out)
{
    size_t cursor = 2U;
    size_t i;

    if (arguments == NULL || lengths == NULL || out == NULL ||
        length_out == NULL || count == 0U ||
        count > ATTACH_LOCAL_MAX_EXEC_ARGS) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    for (i = 0U; i < count; i++) {
        size_t length = (size_t)lengths[i];

        if (arguments[i] == NULL || (i == 0U && length == 0U) ||
            (length != 0U && memchr(arguments[i], '\0', length) != NULL) ||
            cursor > ATTACH_LOCAL_MAX_PAYLOAD - 2U ||
            length > ATTACH_LOCAL_MAX_PAYLOAD - cursor - 2U) {
            errno = EINVAL;
            return ATTACH_LOCAL_ERR_ARGUMENT;
        }
        cursor += 2U + length;
    }

    put_u16_le(out, (uint16_t)count);
    cursor = 2U;
    for (i = 0U; i < count; i++) {
        size_t length = (size_t)lengths[i];

        put_u16_le(out + cursor, lengths[i]);
        cursor += 2U;
        if (length != 0U) {
            memcpy(out + cursor, arguments[i], length);
            cursor += length;
        }
    }
    *length_out = cursor;
    return ATTACH_LOCAL_OK;
}

int attach_local_exec_encode(size_t count, const char *const arguments[],
                             uint8_t out[ATTACH_LOCAL_MAX_PAYLOAD],
                             size_t *length_out)
{
    const uint8_t *slices[ATTACH_LOCAL_MAX_EXEC_ARGS];
    uint16_t lengths[ATTACH_LOCAL_MAX_EXEC_ARGS];
    size_t i;

    if (arguments == NULL || count == 0U ||
        count > ATTACH_LOCAL_MAX_EXEC_ARGS) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    for (i = 0U; i < count; i++) {
        size_t length;

        if (arguments[i] == NULL) {
            errno = EINVAL;
            return ATTACH_LOCAL_ERR_ARGUMENT;
        }
        length = strlen(arguments[i]);
        if (length > UINT16_MAX) {
            errno = EINVAL;
            return ATTACH_LOCAL_ERR_ARGUMENT;
        }
        slices[i] = (const uint8_t *)arguments[i];
        lengths[i] = (uint16_t)length;
    }
    return attach_local_exec_encode_slices(slices, lengths, count, out,
                                           length_out);
}

int attach_local_exec_decode(const uint8_t *payload, size_t payload_length,
                             attach_local_exec_argv_t *argv_out)
{
    size_t count;
    size_t cursor = 2U;
    size_t storage_cursor = 0U;
    size_t i;

    if (payload == NULL || argv_out == NULL || payload_length < 2U ||
        payload_length > ATTACH_LOCAL_MAX_PAYLOAD) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    memset(argv_out, 0, sizeof(*argv_out));
    count = (size_t)get_u16_le(payload);
    if (count == 0U || count > ATTACH_LOCAL_MAX_EXEC_ARGS) {
        errno = EPROTO;
        return ATTACH_LOCAL_ERR_PROTOCOL;
    }
    for (i = 0U; i < count; i++) {
        size_t length;

        if (cursor > payload_length - 2U) {
            errno = EPROTO;
            return ATTACH_LOCAL_ERR_PROTOCOL;
        }
        length = (size_t)get_u16_le(payload + cursor);
        cursor += 2U;
        if ((i == 0U && length == 0U) ||
            length > payload_length - cursor ||
            (length != 0U && memchr(payload + cursor, '\0', length) != NULL) ||
            storage_cursor > ATTACH_LOCAL_EXEC_STORAGE - 1U ||
            length > ATTACH_LOCAL_EXEC_STORAGE - storage_cursor - 1U) {
            errno = EPROTO;
            return ATTACH_LOCAL_ERR_PROTOCOL;
        }
        argv_out->offsets[i] = (uint16_t)storage_cursor;
        argv_out->lengths[i] = (uint16_t)length;
        if (length != 0U)
            memcpy(argv_out->storage + storage_cursor,
                   payload + cursor, length);
        argv_out->storage[storage_cursor + length] = '\0';
        storage_cursor += length + 1U;
        cursor += length;
    }
    if (cursor != payload_length) {
        errno = EPROTO;
        return ATTACH_LOCAL_ERR_PROTOCOL;
    }
    argv_out->count = count;
    argv_out->storage_used = storage_cursor;
    return ATTACH_LOCAL_OK;
}

int attach_local_exec_prefix_boundary(const uint8_t *bytes, size_t used,
                                      size_t *expected_out)
{
    size_t cursor = 2U;
    size_t count;
    size_t index;

    if (bytes == NULL || expected_out == NULL ||
        used > ATTACH_LOCAL_MAX_PAYLOAD) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    *expected_out = 0U;
    if (used < 2U)
        return ATTACH_LOCAL_OK;
    count = (size_t)get_u16_le(bytes);
    if (count == 0U || count > ATTACH_LOCAL_MAX_EXEC_ARGS) {
        errno = EPROTO;
        return ATTACH_LOCAL_ERR_PROTOCOL;
    }
    for (index = 0U; index < count; index++) {
        size_t available;
        size_t length;

        if (cursor > ATTACH_LOCAL_MAX_PAYLOAD - 2U) {
            errno = EPROTO;
            return ATTACH_LOCAL_ERR_PROTOCOL;
        }
        if (used < cursor + 2U)
            return ATTACH_LOCAL_OK;
        length = (size_t)get_u16_le(bytes + cursor);
        cursor += 2U;
        if ((index == 0U && length == 0U) ||
            length > ATTACH_LOCAL_MAX_PAYLOAD - cursor) {
            errno = EPROTO;
            return ATTACH_LOCAL_ERR_PROTOCOL;
        }
        available = used - cursor;
        if (available > length)
            available = length;
        if (available != 0U &&
            memchr(bytes + cursor, '\0', available) != NULL) {
            errno = EPROTO;
            return ATTACH_LOCAL_ERR_PROTOCOL;
        }
        if (used < cursor + length)
            return ATTACH_LOCAL_OK;
        cursor += length;
    }
    *expected_out = cursor;
    return ATTACH_LOCAL_FRAME_READY;
}

const char *attach_local_exec_argument(const attach_local_exec_argv_t *argv,
                                       size_t index)
{
    if (argv == NULL || index >= argv->count)
        return NULL;
    return argv->storage + argv->offsets[index];
}

int attach_local_terminal_open(uint16_t rows, uint16_t columns,
                               attach_local_record_t *record_out)
{
    if (record_out == NULL || rows == 0U || rows > 1000U ||
        columns == 0U || columns > 1000U) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    memset(record_out, 0, sizeof(*record_out));
    record_out->version = ATTACH_LOCAL_VERSION_V1;
    record_out->type = ATTACH_LOCAL_RECORD_OPEN;
    record_out->kind = ATTACH_LOCAL_KIND_TERMINAL;
    record_out->length = 4U;
    put_u16_le(record_out->payload, rows);
    put_u16_le(record_out->payload + 2U, columns);
    return ATTACH_LOCAL_OK;
}

int attach_local_exec_open(size_t count, const char *const arguments[],
                           attach_local_record_t *record_out)
{
    size_t length = 0U;
    int status;

    if (record_out == NULL) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    memset(record_out, 0, sizeof(*record_out));
    status = attach_local_exec_encode(count, arguments, record_out->payload,
                                      &length);
    if (status != ATTACH_LOCAL_OK)
        return status;
    record_out->version = ATTACH_LOCAL_VERSION_V1;
    record_out->type = ATTACH_LOCAL_RECORD_OPEN;
    record_out->kind = ATTACH_LOCAL_KIND_EXEC;
    record_out->length = (uint32_t)length;
    return ATTACH_LOCAL_OK;
}

int attach_local_bulk_open(uint8_t kind, uint16_t wire_budget,
                           uint16_t stall_seconds, uint8_t options,
                           const uint8_t *local_path,
                           size_t local_path_length,
                           const uint8_t *remote_path,
                           size_t remote_path_length,
                           attach_local_record_t *record_out)
{
    size_t remote_limit =
        attach_local_bulk_request_path_limit(wire_budget);
    size_t length;

    if (!bulk_kind_valid(kind) || record_out == NULL ||
        local_path == NULL || remote_path == NULL ||
        stall_seconds < ATTACH_LOCAL_BULK_STALL_MIN ||
        stall_seconds > ATTACH_LOCAL_BULK_STALL_MAX ||
        (options & ~ATTACH_LOCAL_BULK_OPTION_FORCE) != 0U ||
        local_path_length == 0U ||
        local_path_length > ATTACH_LOCAL_BULK_PATH_MAX ||
        remote_path_length == 0U || remote_limit == 0U ||
        remote_path_length > remote_limit ||
        memchr(local_path, '\0', local_path_length) != NULL ||
        !bulk_remote_path_valid(remote_path, remote_path_length)) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    length = ATTACH_LOCAL_BULK_OPEN_PREFIX_BYTES + local_path_length +
             remote_path_length;
    if (length > ATTACH_LOCAL_MAX_PAYLOAD || length > UINT32_MAX) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    memset(record_out, 0, sizeof(*record_out));
    record_out->version = ATTACH_LOCAL_VERSION_V2;
    record_out->type = ATTACH_LOCAL_RECORD_OPEN;
    record_out->kind = kind;
    record_out->length = (uint32_t)length;
    put_u16_le(record_out->payload, wire_budget);
    put_u16_le(record_out->payload + 2U, stall_seconds);
    record_out->payload[4] = options;
    put_u16_le(record_out->payload + 8U, (uint16_t)local_path_length);
    put_u16_le(record_out->payload + 10U, (uint16_t)remote_path_length);
    memcpy(record_out->payload + ATTACH_LOCAL_BULK_OPEN_PREFIX_BYTES,
           local_path, local_path_length);
    memcpy(record_out->payload + ATTACH_LOCAL_BULK_OPEN_PREFIX_BYTES +
               local_path_length,
           remote_path, remote_path_length);
    return ATTACH_LOCAL_OK;
}

int attach_local_bulk_open_decode(const attach_local_record_t *record,
                                  attach_local_bulk_open_t *open_out)
{
    if (open_out == NULL || !bulk_open_decode_payload(record, open_out)) {
        errno = EPROTO;
        return ATTACH_LOCAL_ERR_PROTOCOL;
    }
    return ATTACH_LOCAL_OK;
}

int attach_local_result(uint32_t handle, uint32_t code,
                        attach_local_record_t *record_out)
{
    if (record_out == NULL || code > 4U ||
        (code == 0U && !local_handle_valid(handle)) ||
        (code != 0U && handle != 0U && !local_handle_valid(handle))) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    memset(record_out, 0, sizeof(*record_out));
    record_out->version = ATTACH_LOCAL_VERSION_V1;
    record_out->type = ATTACH_LOCAL_RECORD_RESULT;
    record_out->length = 8U;
    put_u32_le(record_out->payload, handle);
    put_u32_le(record_out->payload + 4U, code);
    return ATTACH_LOCAL_OK;
}

int attach_local_result_decode(const attach_local_record_t *record,
                               uint32_t *handle_out, uint32_t *code_out)
{
    if (record == NULL || handle_out == NULL || code_out == NULL ||
        record->version != ATTACH_LOCAL_VERSION_V1 ||
        record->type != (uint8_t)ATTACH_LOCAL_RECORD_RESULT ||
        record->kind != 0U || !record_payload_valid(record)) {
        errno = EPROTO;
        return ATTACH_LOCAL_ERR_PROTOCOL;
    }
    *handle_out = get_u32_le(record->payload);
    *code_out = get_u32_le(record->payload + 4U);
    return ATTACH_LOCAL_OK;
}

int attach_local_bulk_result(uint32_t handle, uint32_t code,
                             uint64_t transfer_id,
                             attach_local_record_t *record_out)
{
    if (record_out == NULL ||
        !bulk_result_valid(handle, code, transfer_id)) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    memset(record_out, 0, sizeof(*record_out));
    record_out->version = ATTACH_LOCAL_VERSION_V2;
    record_out->type = ATTACH_LOCAL_RECORD_RESULT;
    record_out->length = 16U;
    put_u32_le(record_out->payload, handle);
    put_u32_le(record_out->payload + 4U, code);
    put_u64_le(record_out->payload + 8U, transfer_id);
    return ATTACH_LOCAL_OK;
}

int attach_local_bulk_result_decode(const attach_local_record_t *record,
                                    uint32_t *handle_out,
                                    uint32_t *code_out,
                                    uint64_t *transfer_id_out)
{
    if (record == NULL || handle_out == NULL || code_out == NULL ||
        transfer_id_out == NULL ||
        record->version != ATTACH_LOCAL_VERSION_V2 ||
        record->type != (uint8_t)ATTACH_LOCAL_RECORD_RESULT ||
        record->kind != 0U || !record_payload_valid(record)) {
        errno = EPROTO;
        return ATTACH_LOCAL_ERR_PROTOCOL;
    }
    *handle_out = get_u32_le(record->payload);
    *code_out = get_u32_le(record->payload + 4U);
    *transfer_id_out = get_u64_le(record->payload + 8U);
    return ATTACH_LOCAL_OK;
}

int attach_local_data(const uint8_t *data, size_t length,
                      attach_local_record_t *record_out)
{
    if (data == NULL || record_out == NULL || length == 0U ||
        length > ATTACH_LOCAL_MAX_PAYLOAD) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    memset(record_out, 0, sizeof(*record_out));
    record_out->version = ATTACH_LOCAL_VERSION_V1;
    record_out->type = ATTACH_LOCAL_RECORD_DATA;
    record_out->length = (uint32_t)length;
    memcpy(record_out->payload, data, length);
    return ATTACH_LOCAL_OK;
}

int attach_local_eof(attach_local_record_t *record_out)
{
    if (record_out == NULL) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    memset(record_out, 0, sizeof(*record_out));
    record_out->version = ATTACH_LOCAL_VERSION_V1;
    record_out->type = ATTACH_LOCAL_RECORD_EOF;
    return ATTACH_LOCAL_OK;
}

int attach_local_resize(uint16_t rows, uint16_t columns,
                        uint16_t xpixel, uint16_t ypixel,
                        attach_local_record_t *record_out)
{
    if (record_out == NULL || rows == 0U || rows > 1000U ||
        columns == 0U || columns > 1000U) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    memset(record_out, 0, sizeof(*record_out));
    record_out->version = ATTACH_LOCAL_VERSION_V1;
    record_out->type = ATTACH_LOCAL_RECORD_RESIZE;
    record_out->length = 8U;
    put_u16_le(record_out->payload, rows);
    put_u16_le(record_out->payload + 2U, columns);
    put_u16_le(record_out->payload + 4U, xpixel);
    put_u16_le(record_out->payload + 6U, ypixel);
    return ATTACH_LOCAL_OK;
}

int attach_local_resize_decode(const attach_local_record_t *record,
                               uint16_t *rows_out, uint16_t *columns_out,
                               uint16_t *xpixel_out, uint16_t *ypixel_out)
{
    if (record == NULL || rows_out == NULL || columns_out == NULL ||
        xpixel_out == NULL || ypixel_out == NULL ||
        record->type != (uint8_t)ATTACH_LOCAL_RECORD_RESIZE ||
        record->kind != 0U || !record_payload_valid(record)) {
        errno = EPROTO;
        return ATTACH_LOCAL_ERR_PROTOCOL;
    }
    *rows_out = get_u16_le(record->payload);
    *columns_out = get_u16_le(record->payload + 2U);
    *xpixel_out = get_u16_le(record->payload + 4U);
    *ypixel_out = get_u16_le(record->payload + 6U);
    return ATTACH_LOCAL_OK;
}

int attach_local_signal(uint8_t signum, attach_local_record_t *record_out)
{
    if (record_out == NULL || signum == 0U || signum > 63U) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    memset(record_out, 0, sizeof(*record_out));
    record_out->version = ATTACH_LOCAL_VERSION_V1;
    record_out->type = ATTACH_LOCAL_RECORD_SIGNAL;
    record_out->length = 4U;
    record_out->payload[0] = signum;
    return ATTACH_LOCAL_OK;
}

int attach_local_signal_decode(const attach_local_record_t *record,
                               uint8_t *signum_out)
{
    if (record == NULL || signum_out == NULL ||
        record->type != (uint8_t)ATTACH_LOCAL_RECORD_SIGNAL ||
        record->kind != 0U || !record_payload_valid(record)) {
        errno = EPROTO;
        return ATTACH_LOCAL_ERR_PROTOCOL;
    }
    *signum_out = record->payload[0];
    return ATTACH_LOCAL_OK;
}

static int code_record(uint8_t version, uint8_t type, uint32_t code,
                       attach_local_record_t *record_out)
{
    if (record_out == NULL ||
        !record_header_valid(version, type, 0U, 0U) ||
        (type != (uint8_t)ATTACH_LOCAL_RECORD_EXIT &&
         type != (uint8_t)ATTACH_LOCAL_RECORD_CLOSE)) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    memset(record_out, 0, sizeof(*record_out));
    record_out->version = version;
    record_out->type = type;
    record_out->length = 4U;
    put_u32_le(record_out->payload, code);
    return ATTACH_LOCAL_OK;
}

int attach_local_exit(uint32_t code, attach_local_record_t *record_out)
{
    return code_record(ATTACH_LOCAL_VERSION_V1, ATTACH_LOCAL_RECORD_EXIT,
                       code, record_out);
}

int attach_local_close(uint32_t code, attach_local_record_t *record_out)
{
    return attach_local_close_version(ATTACH_LOCAL_VERSION_V1, code,
                                      record_out);
}

int attach_local_close_version(uint8_t version, uint32_t code,
                               attach_local_record_t *record_out)
{
    return code_record(version, ATTACH_LOCAL_RECORD_CLOSE, code, record_out);
}

int attach_local_code_decode(const attach_local_record_t *record,
                             uint8_t expected_type, uint32_t *code_out)
{
    if (record == NULL || code_out == NULL ||
        (expected_type != (uint8_t)ATTACH_LOCAL_RECORD_EXIT &&
         expected_type != (uint8_t)ATTACH_LOCAL_RECORD_CLOSE) ||
        record->type != expected_type || record->kind != 0U ||
        !record_payload_valid(record)) {
        errno = EPROTO;
        return ATTACH_LOCAL_ERR_PROTOCOL;
    }
    *code_out = get_u32_le(record->payload);
    return ATTACH_LOCAL_OK;
}

static int component_valid(const char *name)
{
    size_t length;
    size_t i;

    if (name == NULL)
        return 0;
    length = strlen(name);
    if (length == 0U || length >= ATTACH_LOCAL_NAME_CAP ||
        (length == 1U && name[0] == '.') ||
        (length == 2U && name[0] == '.' && name[1] == '.'))
        return 0;
    for (i = 0U; i < length; i++) {
        unsigned char ch = (unsigned char)name[i];

        if (!((ch >= (unsigned char)'a' && ch <= (unsigned char)'z') ||
              (ch >= (unsigned char)'A' && ch <= (unsigned char)'Z') ||
              (ch >= (unsigned char)'0' && ch <= (unsigned char)'9') ||
              ch == (unsigned char)'-' || ch == (unsigned char)'_' ||
              ch == (unsigned char)'.'))
            return 0;
    }
    return 1;
}

static int copy_path(char *out, size_t out_capacity, const char *path)
{
    size_t length;

    if (out == NULL || path == NULL || out_capacity == 0U) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    length = strlen(path);
    while (length > 1U && path[length - 1U] == '/')
        length--;
    if (length == 0U || length >= out_capacity) {
        errno = ENAMETOOLONG;
        return ATTACH_LOCAL_ERR_UNSAFE;
    }
    memcpy(out, path, length);
    out[length] = '\0';
    return ATTACH_LOCAL_OK;
}

static int join_path(char *out, size_t out_capacity,
                     const char *parent, const char *child)
{
    size_t parent_length;
    size_t child_length;
    int need_slash;

    if (out == NULL || parent == NULL || child == NULL ||
        out_capacity == 0U) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    parent_length = strlen(parent);
    while (parent_length > 1U && parent[parent_length - 1U] == '/')
        parent_length--;
    child_length = strlen(child);
    need_slash = parent_length != 1U || parent[0] != '/';
    if (parent_length == 0U || child_length == 0U ||
        parent_length >= out_capacity ||
        child_length >= out_capacity - parent_length -
                            (size_t)need_slash) {
        errno = ENAMETOOLONG;
        return ATTACH_LOCAL_ERR_UNSAFE;
    }
    memcpy(out, parent, parent_length);
    if (need_slash)
        out[parent_length++] = '/';
    memcpy(out + parent_length, child, child_length);
    out[parent_length + child_length] = '\0';
    return ATTACH_LOCAL_OK;
}

int attach_local_path_fits(const char *path)
{
    return path != NULL && path[0] == '/' &&
           strlen(path) + 1U <= ATTACH_LOCAL_PATH_CAP;
}

int attach_local_peer_uid_matches(uid_t expected, uid_t actual)
{
    return expected == actual;
}

static int validate_directory_stat(const struct stat *st, uid_t uid,
                                   int exact_private_mode)
{
    if (!S_ISDIR(st->st_mode) || st->st_uid != uid)
        return 0;
    if (exact_private_mode &&
        (st->st_mode & (mode_t)07777) != ATTACH_LOCAL_DIRECTORY_MODE)
        return 0;
    return 1;
}

static int open_absolute_directory(const char *path, uid_t uid,
                                   int exact_private_mode, int *fd_out)
{
    const char *cursor;
    int fd = -1;
    struct stat st;

    if (path == NULL || path[0] != '/' || fd_out == NULL) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    *fd_out = -1;
    fd = open("/", ATTACH_LOCAL_DIRECTORY_REFERENCE_FLAGS | O_NOFOLLOW);
    if (fd < 0)
        return ATTACH_LOCAL_ERR_IO;

    cursor = path + 1;
    while (*cursor != '\0') {
        const char *end;
        size_t length;
        char component[ATTACH_LOCAL_COMPONENT_CAP];
        int next_fd;

        while (*cursor == '/')
            cursor++;
        if (*cursor == '\0')
            break;
        end = cursor;
        while (*end != '\0' && *end != '/')
            end++;
        length = (size_t)(end - cursor);
        if (length == 0U || length >= sizeof(component) ||
            (length == 1U && cursor[0] == '.') ||
            (length == 2U && cursor[0] == '.' && cursor[1] == '.')) {
            (void)close(fd);
            errno = EINVAL;
            return ATTACH_LOCAL_ERR_UNSAFE;
        }
        memcpy(component, cursor, length);
        component[length] = '\0';
        next_fd = openat(fd, component,
                         ATTACH_LOCAL_DIRECTORY_REFERENCE_FLAGS | O_NOFOLLOW);
        if (next_fd < 0) {
            int saved_errno = errno;

            (void)close(fd);
            errno = saved_errno;
            return saved_errno == ELOOP || saved_errno == ENOTDIR ?
                       ATTACH_LOCAL_ERR_UNSAFE : ATTACH_LOCAL_ERR_IO;
        }
        (void)close(fd);
        fd = next_fd;
        cursor = end;
    }

    if (fstat(fd, &st) != 0) {
        int saved_errno = errno;

        (void)close(fd);
        errno = saved_errno;
        return ATTACH_LOCAL_ERR_IO;
    }
    if (!validate_directory_stat(&st, uid, exact_private_mode)) {
        (void)close(fd);
        errno = EPERM;
        return ATTACH_LOCAL_ERR_UNSAFE;
    }
    *fd_out = fd;
    return ATTACH_LOCAL_OK;
}

static int open_private_child(int parent_fd, const char *name, uid_t uid,
                              int *created_out, int *fd_out)
{
    int created = 0;
    int fd;
    struct stat st;

    if (mkdirat(parent_fd, name, ATTACH_LOCAL_DIRECTORY_MODE) == 0) {
        created = 1;
    } else if (errno != EEXIST) {
        return ATTACH_LOCAL_ERR_IO;
    }
    fd = openat(parent_fd, name,
                O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        int saved_errno = errno;

        if (created)
            (void)unlinkat(parent_fd, name, AT_REMOVEDIR);
        errno = saved_errno;
        return saved_errno == ELOOP || saved_errno == ENOTDIR ?
                   ATTACH_LOCAL_ERR_UNSAFE : ATTACH_LOCAL_ERR_IO;
    }
    if (created && fchmod(fd, ATTACH_LOCAL_DIRECTORY_MODE) != 0) {
        int saved_errno = errno;

        (void)close(fd);
        (void)unlinkat(parent_fd, name, AT_REMOVEDIR);
        errno = saved_errno;
        return ATTACH_LOCAL_ERR_IO;
    }
    if (fstat(fd, &st) != 0) {
        int saved_errno = errno;

        (void)close(fd);
        if (created)
            (void)unlinkat(parent_fd, name, AT_REMOVEDIR);
        errno = saved_errno;
        return ATTACH_LOCAL_ERR_IO;
    }
    if (!validate_directory_stat(&st, uid, 1)) {
        (void)close(fd);
        if (created)
            (void)unlinkat(parent_fd, name, AT_REMOVEDIR);
        errno = EPERM;
        return ATTACH_LOCAL_ERR_UNSAFE;
    }
    *created_out = created;
    *fd_out = fd;
    return ATTACH_LOCAL_OK;
}

static int choose_runtime_base(const attach_local_listener_config_t *config,
                               attach_local_listener_t *listener)
{
    const char *candidates[2];
    attach_local_runtime_source_t sources[2];
    size_t i;

    candidates[0] = config->xdg_runtime_dir;
    candidates[1] = config->tmpdir;
    sources[0] = ATTACH_LOCAL_RUNTIME_XDG;
    sources[1] = ATTACH_LOCAL_RUNTIME_TMPDIR;
    for (i = 0U; i < 2U; i++) {
        int fd;

        if (candidates[i] == NULL || candidates[i][0] == '\0')
            continue;
        if (open_absolute_directory(candidates[i], config->uid, 1, &fd) ==
            ATTACH_LOCAL_OK) {
            if (copy_path(listener->base_path,
                          sizeof(listener->base_path), candidates[i]) !=
                ATTACH_LOCAL_OK) {
                (void)close(fd);
                return ATTACH_LOCAL_ERR_UNSAFE;
            }
            listener->base_fd = fd;
            listener->runtime_source = sources[i];
            return ATTACH_LOCAL_OK;
        }
    }

    if (config->home != NULL && config->home[0] != '\0') {
        char private_path[ATTACH_LOCAL_PATH_CAP];
        int home_fd = -1;
        int private_fd = -1;
        int run_fd = -1;
        int created_private = 0;
        int created_run = 0;
        int status;

        status = open_absolute_directory(config->home, config->uid, 0,
                                         &home_fd);
        if (status != ATTACH_LOCAL_OK)
            return status;
        status = open_private_child(home_fd, ".unmoor", config->uid,
                                    &created_private, &private_fd);
        if (status != ATTACH_LOCAL_OK)
            goto home_fail;
        status = open_private_child(private_fd, "run", config->uid,
                                    &created_run, &run_fd);
        if (status != ATTACH_LOCAL_OK)
            goto home_fail;
        status = join_path(private_path, sizeof(private_path), config->home,
                           ".unmoor");
        if (status != ATTACH_LOCAL_OK)
            goto home_fail;
        status = join_path(listener->base_path, sizeof(listener->base_path),
                           private_path, "run");
        if (status != ATTACH_LOCAL_OK)
            goto home_fail;
        (void)close(home_fd);
        (void)close(private_fd);
        listener->base_fd = run_fd;
        listener->runtime_source = ATTACH_LOCAL_RUNTIME_HOME;
        return ATTACH_LOCAL_OK;

home_fail:
        {
            int saved_errno = errno;

            if (run_fd >= 0)
                (void)close(run_fd);
            if (created_run && private_fd >= 0)
                (void)unlinkat(private_fd, "run", AT_REMOVEDIR);
            if (private_fd >= 0)
                (void)close(private_fd);
            if (home_fd >= 0 && created_private)
                (void)unlinkat(home_fd, ".unmoor", AT_REMOVEDIR);
            if (home_fd >= 0)
                (void)close(home_fd);
            errno = saved_errno;
            return status;
        }
    }

    errno = EPERM;
    return ATTACH_LOCAL_ERR_UNSAFE;
}

void attach_local_listener_config_from_environment(
    attach_local_listener_config_t *config,
    const char *session_name, const char *socket_name)
{
    if (config == NULL)
        return;
    memset(config, 0, sizeof(*config));
    config->xdg_runtime_dir = getenv("XDG_RUNTIME_DIR");
    config->tmpdir = getenv("TMPDIR");
    config->home = getenv("HOME");
    config->session_name = session_name;
    config->socket_name = socket_name;
    config->uid = geteuid();
}

static int set_fd_flags(int fd)
{
    int descriptor_flags;
    int status_flags;

    descriptor_flags = fcntl(fd, F_GETFD);
    if (descriptor_flags < 0 ||
        fcntl(fd, F_SETFD, descriptor_flags | FD_CLOEXEC) != 0)
        return ATTACH_LOCAL_ERR_IO;
    status_flags = fcntl(fd, F_GETFL);
    if (status_flags < 0 ||
        fcntl(fd, F_SETFL, status_flags | O_NONBLOCK) != 0)
        return ATTACH_LOCAL_ERR_IO;
    return ATTACH_LOCAL_OK;
}

static void set_no_sigpipe(int fd)
{
#ifdef SO_NOSIGPIPE
    int one = 1;

    (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#else
    (void)fd;
#endif
}

static int socket_path_stat(int directory_fd, const char *name,
                            struct stat *st)
{
    if (fstatat(directory_fd, name, st, AT_SYMLINK_NOFOLLOW) == 0)
        return ATTACH_LOCAL_OK;
    if (errno == ENOENT)
        return ATTACH_LOCAL_CLOSED;
    return ATTACH_LOCAL_ERR_IO;
}

static int same_object(const struct stat *left, const struct stat *right)
{
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino;
}

static int probe_existing_socket(const char *path)
{
    struct sockaddr_un address;
    int fd;
    int result;
    int saved_errno;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return ATTACH_LOCAL_ERR_IO;
    (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, path, strlen(path) + 1U);
    result = connect(fd, (const struct sockaddr *)&address, sizeof(address));
    saved_errno = errno;
    (void)close(fd);
    if (result == 0) {
        errno = EADDRINUSE;
        return ATTACH_LOCAL_ERR_BUSY;
    }
    errno = saved_errno;
    if (saved_errno == ECONNREFUSED)
        return ATTACH_LOCAL_CLOSED;
    if (saved_errno == ENOENT)
        return ATTACH_LOCAL_OK;
    return ATTACH_LOCAL_ERR_BUSY;
}

static int remove_safe_stale_socket(attach_local_listener_t *listener)
{
    struct stat before;
    struct stat after;
    int status;

    status = socket_path_stat(listener->directory_fd, listener->socket_name,
                              &before);
    if (status == ATTACH_LOCAL_CLOSED)
        return ATTACH_LOCAL_OK;
    if (status != ATTACH_LOCAL_OK)
        return status;
    if (!S_ISSOCK(before.st_mode) || before.st_uid != listener->uid ||
        (before.st_mode & (mode_t)07777) != ATTACH_LOCAL_SOCKET_MODE) {
        errno = EPERM;
        return ATTACH_LOCAL_ERR_UNSAFE;
    }
    status = probe_existing_socket(listener->socket_path);
    if (status == ATTACH_LOCAL_ERR_BUSY)
        return status;
    if (status != ATTACH_LOCAL_CLOSED && status != ATTACH_LOCAL_OK)
        return status;
    if (status == ATTACH_LOCAL_OK)
        return ATTACH_LOCAL_OK;
    if (socket_path_stat(listener->directory_fd, listener->socket_name,
                         &after) != ATTACH_LOCAL_OK ||
        !same_object(&before, &after) || !S_ISSOCK(after.st_mode) ||
        after.st_uid != listener->uid ||
        (after.st_mode & (mode_t)07777) != ATTACH_LOCAL_SOCKET_MODE) {
        errno = EPERM;
        return ATTACH_LOCAL_ERR_UNSAFE;
    }
    if (unlinkat(listener->directory_fd, listener->socket_name, 0) != 0)
        return ATTACH_LOCAL_ERR_IO;
    return ATTACH_LOCAL_OK;
}

/*
 * client-confinement: retain a path-only cwd descriptor across the Landlock boundary. It
 * can restore cwd with fchdir without carrying directory-listing authority.
 * A negative value keeps the historical on-demand behavior for unconfined
 * callers (also path-only on Linux).
 */
static int acquire_cwd_fd(int held_fd, int *owned_out)
{
    if (held_fd >= 0) {
        *owned_out = 0;
        return held_fd;
    }
    *owned_out = 1;
    return open(".", ATTACH_LOCAL_DIRECTORY_REFERENCE_FLAGS);
}

static void release_cwd_fd(int fd, int owned)
{
    if (owned && fd >= 0)
        (void)close(fd);
}

static int bind_relative_to_directory(int fd, int directory_fd,
                                      const char *socket_name,
                                      int saved_cwd_fd)
{
    struct sockaddr_un address;
    int cwd_fd;
    int cwd_owned = 0;
    int result;
    int operation_errno;

    cwd_fd = acquire_cwd_fd(saved_cwd_fd, &cwd_owned);
    if (cwd_fd < 0)
        return ATTACH_LOCAL_ERR_IO;
    if (fchdir(directory_fd) != 0) {
        int saved_errno = errno;

        release_cwd_fd(cwd_fd, cwd_owned);
        errno = saved_errno;
        return ATTACH_LOCAL_ERR_IO;
    }
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, socket_name, strlen(socket_name) + 1U);
    result = bind(fd, (const struct sockaddr *)&address, sizeof(address));
    operation_errno = errno;
    if (fchdir(cwd_fd) != 0) {
        int saved_errno = errno;

        release_cwd_fd(cwd_fd, cwd_owned);
        errno = saved_errno;
        return ATTACH_LOCAL_ERR_IO;
    }
    release_cwd_fd(cwd_fd, cwd_owned);
    errno = operation_errno;
    return result == 0 ? ATTACH_LOCAL_OK : ATTACH_LOCAL_ERR_IO;
}

static int connect_relative_to_directory(int fd, int directory_fd,
                                         const char *socket_name)
{
    struct sockaddr_un address;
    int cwd_fd;
    int result;
    int operation_errno;

    cwd_fd = open(".", ATTACH_LOCAL_DIRECTORY_REFERENCE_FLAGS);
    if (cwd_fd < 0)
        return ATTACH_LOCAL_ERR_IO;
    if (fchdir(directory_fd) != 0) {
        int saved_errno = errno;

        (void)close(cwd_fd);
        errno = saved_errno;
        return ATTACH_LOCAL_ERR_IO;
    }
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, socket_name, strlen(socket_name) + 1U);
    result = connect(fd, (const struct sockaddr *)&address, sizeof(address));
    operation_errno = errno;
    if (fchdir(cwd_fd) != 0) {
        int saved_errno = errno;

        (void)close(cwd_fd);
        errno = saved_errno;
        return ATTACH_LOCAL_ERR_IO;
    }
    (void)close(cwd_fd);
    errno = operation_errno;
    if (result == 0)
        return ATTACH_LOCAL_OK;
    if (operation_errno == EAGAIN || operation_errno == EWOULDBLOCK ||
        operation_errno == EINPROGRESS)
        return ATTACH_LOCAL_WOULD_BLOCK;
    return ATTACH_LOCAL_ERR_IO;
}

/*
 * Darwin does not permit fchmod/fchmodat on a bound socket inode.  Resolve
 * the final component relative to the already verified directory fd while
 * preserving the process cwd, just as bind_relative_to_directory does.
 */
static int chmod_relative_to_directory(int directory_fd,
                                       const char *socket_name, mode_t mode,
                                       int saved_cwd_fd)
{
    int cwd_fd;
    int cwd_owned = 0;
    int result;
    int operation_errno;

    cwd_fd = acquire_cwd_fd(saved_cwd_fd, &cwd_owned);
    if (cwd_fd < 0)
        return ATTACH_LOCAL_ERR_IO;
    if (fchdir(directory_fd) != 0) {
        int saved_errno = errno;

        release_cwd_fd(cwd_fd, cwd_owned);
        errno = saved_errno;
        return ATTACH_LOCAL_ERR_IO;
    }
    result = chmod(socket_name, mode);
    operation_errno = errno;
    if (fchdir(cwd_fd) != 0) {
        int saved_errno = errno;

        release_cwd_fd(cwd_fd, cwd_owned);
        errno = saved_errno;
        return ATTACH_LOCAL_ERR_IO;
    }
    release_cwd_fd(cwd_fd, cwd_owned);
    errno = operation_errno;
    return result == 0 ? ATTACH_LOCAL_OK : ATTACH_LOCAL_ERR_IO;
}

static int stat_owned_socket(attach_local_listener_t *listener)
{
    struct stat st;

    if (socket_path_stat(listener->directory_fd, listener->socket_name, &st) !=
        ATTACH_LOCAL_OK || !S_ISSOCK(st.st_mode) ||
        st.st_uid != listener->uid) {
        errno = EPERM;
        return ATTACH_LOCAL_ERR_UNSAFE;
    }
    listener->socket_device = st.st_dev;
    listener->socket_inode = st.st_ino;
    listener->socket_owned = 1;
    return ATTACH_LOCAL_OK;
}

static int cleanup_owned_socket(attach_local_listener_t *listener)
{
    struct stat st;
    int status;

    if (!listener->socket_owned)
        return ATTACH_LOCAL_OK;
    status = socket_path_stat(listener->directory_fd, listener->socket_name,
                              &st);
    if (status == ATTACH_LOCAL_CLOSED) {
        listener->socket_owned = 0;
        return ATTACH_LOCAL_OK;
    }
    if (status != ATTACH_LOCAL_OK || !S_ISSOCK(st.st_mode) ||
        st.st_uid != listener->uid ||
        st.st_dev != listener->socket_device ||
        st.st_ino != listener->socket_inode) {
        errno = EPERM;
        return ATTACH_LOCAL_ERR_UNSAFE;
    }
    if (unlinkat(listener->directory_fd, listener->socket_name, 0) != 0)
        return ATTACH_LOCAL_ERR_IO;
    listener->socket_owned = 0;
    return ATTACH_LOCAL_OK;
}

static void listener_initialize(attach_local_listener_t *listener)
{
    size_t i;

    memset(listener, 0, sizeof(*listener));
    listener->listen_fd = -1;
    listener->base_fd = -1;
    listener->directory_fd = -1;
    listener->cwd_fd = -1;
    for (i = 0U; i < ATTACH_LOCAL_MAX_CONNECTIONS; i++)
        listener->connections[i].fd = -1;
}

static int listener_bind_owned_socket(attach_local_listener_t *listener)
{
    struct stat socket_stat;
    int status;

    status = remove_safe_stale_socket(listener);
    if (status != ATTACH_LOCAL_OK)
        return status;
    listener->listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listener->listen_fd < 0)
        return ATTACH_LOCAL_ERR_IO;
    if (set_fd_flags(listener->listen_fd) != ATTACH_LOCAL_OK)
        return ATTACH_LOCAL_ERR_IO;
    set_no_sigpipe(listener->listen_fd);
    status = bind_relative_to_directory(listener->listen_fd,
                                        listener->directory_fd,
                                        listener->socket_name,
                                        listener->cwd_fd);
    if (status != ATTACH_LOCAL_OK)
        return status;
    status = stat_owned_socket(listener);
    if (status != ATTACH_LOCAL_OK)
        return status;
    if (chmod_relative_to_directory(listener->directory_fd,
                                    listener->socket_name,
                                    ATTACH_LOCAL_SOCKET_MODE,
                                    listener->cwd_fd) !=
        ATTACH_LOCAL_OK)
        return ATTACH_LOCAL_ERR_IO;
    if (socket_path_stat(listener->directory_fd, listener->socket_name,
                         &socket_stat) != ATTACH_LOCAL_OK ||
        !S_ISSOCK(socket_stat.st_mode) || socket_stat.st_uid != listener->uid ||
        (socket_stat.st_mode & (mode_t)07777) != ATTACH_LOCAL_SOCKET_MODE ||
        socket_stat.st_dev != listener->socket_device ||
        socket_stat.st_ino != listener->socket_inode) {
        errno = EPERM;
        return ATTACH_LOCAL_ERR_UNSAFE;
    }
    if (listen(listener->listen_fd, (int)ATTACH_LOCAL_MAX_CONNECTIONS) != 0)
        return ATTACH_LOCAL_ERR_IO;
    return ATTACH_LOCAL_OK;
}

int attach_local_listener_open(attach_local_listener_t *listener,
                               const attach_local_listener_config_t *config)
{
    struct stat directory_stat;
    int created = 0;
    int status;

    if (listener == NULL) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    listener_initialize(listener);
    if (config == NULL || !component_valid(config->session_name) ||
        !component_valid(config->socket_name) ||
        config->uid != geteuid()) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    listener->uid = config->uid;
    memcpy(listener->directory_name, config->session_name,
           strlen(config->session_name) + 1U);
    memcpy(listener->socket_name, config->socket_name,
           strlen(config->socket_name) + 1U);

    status = choose_runtime_base(config, listener);
    if (status != ATTACH_LOCAL_OK)
        goto fail;
    status = join_path(listener->directory_path,
                       sizeof(listener->directory_path), listener->base_path,
                       listener->directory_name);
    if (status != ATTACH_LOCAL_OK)
        goto fail;
    status = join_path(listener->socket_path, sizeof(listener->socket_path),
                       listener->directory_path, listener->socket_name);
    if (status != ATTACH_LOCAL_OK ||
        !attach_local_path_fits(listener->socket_path)) {
        errno = ENAMETOOLONG;
        status = ATTACH_LOCAL_ERR_UNSAFE;
        goto fail;
    }
    status = open_private_child(listener->base_fd, listener->directory_name,
                                listener->uid, &created,
                                &listener->directory_fd);
    if (status != ATTACH_LOCAL_OK)
        goto fail;
    listener->directory_created = created;
    if (fstat(listener->directory_fd, &directory_stat) != 0) {
        status = ATTACH_LOCAL_ERR_IO;
        goto fail;
    }
    listener->directory_device = directory_stat.st_dev;
    listener->directory_inode = directory_stat.st_ino;

    status = listener_bind_owned_socket(listener);
    if (status != ATTACH_LOCAL_OK)
        goto fail;
    return ATTACH_LOCAL_OK;

fail:
    {
        int saved_errno = errno;

        if (listener->listen_fd >= 0) {
            (void)close(listener->listen_fd);
            listener->listen_fd = -1;
        }
        if (listener->directory_fd >= 0)
            (void)cleanup_owned_socket(listener);
        if (listener->directory_fd >= 0) {
            (void)close(listener->directory_fd);
            listener->directory_fd = -1;
        }
        if (listener->directory_created && listener->base_fd >= 0)
            (void)unlinkat(listener->base_fd, listener->directory_name,
                           AT_REMOVEDIR);
        if (listener->base_fd >= 0) {
            (void)close(listener->base_fd);
            listener->base_fd = -1;
        }
        errno = saved_errno;
        return status;
    }
}

static int split_absolute_socket_path(const char *path,
                                      char parent_out[ATTACH_LOCAL_PATH_CAP],
                                      char name_out[ATTACH_LOCAL_NAME_CAP])
{
    const char *slash;
    size_t parent_length;

    if (!attach_local_path_fits(path) || parent_out == NULL ||
        name_out == NULL) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    slash = strrchr(path, '/');
    if (slash == NULL || slash[1] == '\0' || !component_valid(slash + 1)) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    parent_length = (size_t)(slash - path);
    if (parent_length == 0U)
        parent_length = 1U;
    if (parent_length >= ATTACH_LOCAL_PATH_CAP) {
        errno = ENAMETOOLONG;
        return ATTACH_LOCAL_ERR_UNSAFE;
    }
    memcpy(parent_out, path, parent_length);
    parent_out[parent_length] = '\0';
    memcpy(name_out, slash + 1, strlen(slash + 1) + 1U);
    return ATTACH_LOCAL_OK;
}

/*
 * client-confinement prepare step.  Resolve the runtime base, walk it, record its identity
 * and save a cwd descriptor — every path operation that a Landlock domain
 * would govern — while the process is still unconfined.  No socket is created
 * and no directory is made, so nothing an observer can see changes: the
 * socket still appears only when attach_local_listener_bind_prepared() runs
 * at the same point in the session as before.
 */
int attach_local_listener_prepare_path(attach_local_listener_t *listener,
                                       const char *absolute_path, uid_t uid)
{
    char parent_path[ATTACH_LOCAL_PATH_CAP];
    char socket_name[ATTACH_LOCAL_NAME_CAP];
    struct stat directory_stat;
    int status;

    if (listener == NULL) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    listener_initialize(listener);
    if (uid != geteuid()) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    status = split_absolute_socket_path(absolute_path, parent_path,
                                        socket_name);
    if (status != ATTACH_LOCAL_OK)
        return status;
    status = open_absolute_directory(parent_path, uid, 1,
                                     &listener->directory_fd);
    if (status != ATTACH_LOCAL_OK)
        return status;
    listener->uid = uid;
    listener->runtime_source = ATTACH_LOCAL_RUNTIME_NONE;
    memcpy(listener->base_path, parent_path, strlen(parent_path) + 1U);
    memcpy(listener->directory_path, parent_path, strlen(parent_path) + 1U);
    memcpy(listener->socket_path, absolute_path, strlen(absolute_path) + 1U);
    memcpy(listener->socket_name, socket_name, strlen(socket_name) + 1U);
    if (fstat(listener->directory_fd, &directory_stat) != 0) {
        int saved_errno = errno;

        (void)close(listener->directory_fd);
        listener->directory_fd = -1;
        errno = saved_errno;
        return ATTACH_LOCAL_ERR_IO;
    }
    listener->directory_device = directory_stat.st_dev;
    listener->directory_inode = directory_stat.st_ino;
    listener->cwd_fd = open(".", ATTACH_LOCAL_DIRECTORY_REFERENCE_FLAGS);
    if (listener->cwd_fd < 0) {
        int saved_errno = errno;

        (void)close(listener->directory_fd);
        listener->directory_fd = -1;
        errno = saved_errno;
        return ATTACH_LOCAL_ERR_IO;
    }
    listener->prepared = 1;
    return ATTACH_LOCAL_OK;
}

/* client-confinement bind step.  Uses only the descriptors the prepare step already holds:
 * MAKE_SOCK plus REMOVE_FILE on the one runtime directory is the whole
 * filesystem authority this needs. */
int attach_local_listener_bind_prepared(attach_local_listener_t *listener)
{
    int status;

    if (listener == NULL || !listener->prepared ||
        listener->directory_fd < 0 || listener->listen_fd >= 0) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    status = listener_bind_owned_socket(listener);
    if (status != ATTACH_LOCAL_OK)
        goto fail;
    return ATTACH_LOCAL_OK;

fail:
    {
        int saved_errno = errno;

        if (listener->listen_fd >= 0) {
            (void)close(listener->listen_fd);
            listener->listen_fd = -1;
        }
        if (listener->directory_fd >= 0)
            (void)cleanup_owned_socket(listener);
        if (listener->directory_fd >= 0) {
            (void)close(listener->directory_fd);
            listener->directory_fd = -1;
        }
        if (listener->cwd_fd >= 0) {
            (void)close(listener->cwd_fd);
            listener->cwd_fd = -1;
        }
        listener->prepared = 0;
        errno = saved_errno;
        return status;
    }
}

int attach_local_listener_open_path(attach_local_listener_t *listener,
                                    const char *absolute_path, uid_t uid)
{
    int status;

    status = attach_local_listener_prepare_path(listener, absolute_path, uid);
    if (status != ATTACH_LOCAL_OK)
        return status;
    return attach_local_listener_bind_prepared(listener);
}

static int peer_uid(int fd, uid_t *uid_out)
{
#ifdef __linux__
    struct ucred credential;
    socklen_t length = (socklen_t)sizeof(credential);

    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credential, &length) != 0 ||
        length != (socklen_t)sizeof(credential))
        return ATTACH_LOCAL_ERR_IO;
    *uid_out = credential.uid;
    return ATTACH_LOCAL_OK;
#elif defined(__APPLE__)
    uid_t effective_uid;
    gid_t effective_gid;

    if (getpeereid(fd, &effective_uid, &effective_gid) != 0)
        return ATTACH_LOCAL_ERR_IO;
    *uid_out = effective_uid;
    return ATTACH_LOCAL_OK;
#else
#error "channel-session local attach peer credentials require Linux or macOS"
#endif
}

int attach_local_listener_accept(attach_local_listener_t *listener,
                                 int64_t now_ms, size_t *index_out)
{
    size_t slot;
    int fd;
    uid_t uid;

    if (listener == NULL || index_out == NULL || listener->listen_fd < 0) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    *index_out = SIZE_MAX;
    fd = accept(listener->listen_fd, NULL, NULL);
    if (fd < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            return ATTACH_LOCAL_WOULD_BLOCK;
        return ATTACH_LOCAL_ERR_IO;
    }
    if (set_fd_flags(fd) != ATTACH_LOCAL_OK) {
        int saved_errno = errno;

        (void)close(fd);
        errno = saved_errno;
        return ATTACH_LOCAL_ERR_IO;
    }
    set_no_sigpipe(fd);
    if (peer_uid(fd, &uid) != ATTACH_LOCAL_OK) {
        int saved_errno = errno;

        (void)close(fd);
        errno = saved_errno;
        return ATTACH_LOCAL_ERR_IO;
    }
    if (!attach_local_peer_uid_matches(listener->uid, uid)) {
        (void)close(fd);
        errno = EPERM;
        return ATTACH_LOCAL_ERR_UID;
    }
    for (slot = 0U; slot < ATTACH_LOCAL_MAX_CONNECTIONS; slot++) {
        if (!listener->connections[slot].active)
            break;
    }
    if (slot == ATTACH_LOCAL_MAX_CONNECTIONS) {
        (void)close(fd);
        errno = ENOSPC;
        return ATTACH_LOCAL_ERR_CAPACITY;
    }
    memset(&listener->connections[slot], 0,
           sizeof(listener->connections[slot]));
    listener->connections[slot].fd = fd;
    listener->connections[slot].peer_uid = uid;
    listener->connections[slot].active = 1;
    attach_local_parser_init(&listener->connections[slot].parser, now_ms);
    *index_out = slot;
    return ATTACH_LOCAL_OK;
}

void attach_local_connection_close(attach_local_connection_t *connection)
{
    if (connection == NULL)
        return;
    if (connection->active && connection->fd >= 0)
        (void)close(connection->fd);
    memset(connection, 0, sizeof(*connection));
    connection->fd = -1;
}

int attach_local_connection_read(attach_local_connection_t *connection,
                                 int64_t now_ms,
                                 attach_local_record_t *record_out)
{
    uint8_t input[ATTACH_LOCAL_MAX_PAYLOAD];
    size_t needed;
    size_t consumed = 0U;
    ssize_t received;
    int was_first;
    int status;

    if (connection == NULL || record_out == NULL || !connection->active ||
        connection->fd < 0) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    status = attach_local_parser_check_deadline(&connection->parser, now_ms);
    if (status != ATTACH_LOCAL_OK)
        return status;
    if (!connection->parser.header_ready)
        needed = ATTACH_LOCAL_HEADER_BYTES - connection->parser.header_used;
    else
        needed = (size_t)connection->parser.payload_length -
                 connection->parser.payload_used;
    if (needed == 0U) {
        errno = EPROTO;
        return ATTACH_LOCAL_ERR_PROTOCOL;
    }
    received = recv(connection->fd, input, needed, 0);
    if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            return ATTACH_LOCAL_WOULD_BLOCK;
        if (errno != ECONNRESET)
            return ATTACH_LOCAL_ERR_IO;
        /* Linux resets an AF_UNIX stream whose peer closed with unread
         * data still queued on its side; macOS reports the same departure
         * as EOF. Both mean the peer is gone: classify the reset as EOF so
         * a retained partial record still fails the parser below. */
        received = 0;
    }
    if (received == 0) {
        if (connection->parser.header_used != 0U ||
            connection->parser.payload_used != 0U) {
            return parser_fail(&connection->parser);
        }
        return ATTACH_LOCAL_CLOSED;
    }
    was_first = !connection->parser.saw_first_record;
    status = attach_local_parser_feed(&connection->parser, input,
                                      (size_t)received, &consumed, record_out);
    if (consumed != (size_t)received)
        return parser_fail(&connection->parser);
    if (status == ATTACH_LOCAL_FRAME_READY && was_first &&
        record_out->type != (uint8_t)ATTACH_LOCAL_RECORD_OPEN)
        return parser_fail(&connection->parser);
    return status;
}

int attach_local_connection_queue(attach_local_connection_t *connection,
                                  const attach_local_record_t *record)
{
    size_t length = 0U;
    int status;

    if (connection == NULL || record == NULL || !connection->active ||
        connection->fd < 0) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    if (connection->write_offset != connection->write_length) {
        errno = EAGAIN;
        return ATTACH_LOCAL_WOULD_BLOCK;
    }
    status = attach_local_record_encode(record, connection->write_buffer,
                                        sizeof(connection->write_buffer),
                                        &length);
    if (status != ATTACH_LOCAL_OK)
        return status;
    connection->write_length = length;
    connection->write_offset = 0U;
    return ATTACH_LOCAL_OK;
}

int attach_local_connection_flush(attach_local_connection_t *connection)
{
    ssize_t sent;
    int flags = 0;

    if (connection == NULL || !connection->active || connection->fd < 0) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    if (connection->write_offset == connection->write_length)
        return ATTACH_LOCAL_OK;
#ifdef MSG_NOSIGNAL
    flags |= MSG_NOSIGNAL;
#endif
    sent = send(connection->fd,
                connection->write_buffer + connection->write_offset,
                connection->write_length - connection->write_offset, flags);
    if (sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            return ATTACH_LOCAL_WOULD_BLOCK;
        return ATTACH_LOCAL_ERR_IO;
    }
    if (sent == 0) {
        errno = EPIPE;
        return ATTACH_LOCAL_ERR_IO;
    }
    connection->write_offset += (size_t)sent;
    if (connection->write_offset != connection->write_length)
        return ATTACH_LOCAL_WOULD_BLOCK;
    connection->write_offset = 0U;
    connection->write_length = 0U;
    return ATTACH_LOCAL_OK;
}

static int directory_identity_matches(const attach_local_listener_t *listener)
{
    struct stat st;

    if (fstatat(listener->base_fd, listener->directory_name, &st,
                AT_SYMLINK_NOFOLLOW) != 0)
        return errno == ENOENT ? 0 : -1;
    return S_ISDIR(st.st_mode) && st.st_uid == listener->uid &&
           st.st_dev == listener->directory_device &&
           st.st_ino == listener->directory_inode;
}

int attach_local_listener_close(attach_local_listener_t *listener)
{
    int status = ATTACH_LOCAL_OK;
    int saved_errno = 0;
    size_t i;

    if (listener == NULL) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    for (i = 0U; i < ATTACH_LOCAL_MAX_CONNECTIONS; i++)
        attach_local_connection_close(&listener->connections[i]);
    if (listener->listen_fd >= 0) {
        if (close(listener->listen_fd) != 0) {
            status = ATTACH_LOCAL_ERR_IO;
            saved_errno = errno;
        }
        listener->listen_fd = -1;
    }
    if (listener->directory_fd >= 0 &&
        cleanup_owned_socket(listener) != ATTACH_LOCAL_OK &&
        status == ATTACH_LOCAL_OK) {
        status = ATTACH_LOCAL_ERR_UNSAFE;
        saved_errno = errno;
    }
    if (listener->directory_created && listener->base_fd >= 0) {
        int identity = directory_identity_matches(listener);

        if (identity != 1) {
            if (status == ATTACH_LOCAL_OK) {
                status = ATTACH_LOCAL_ERR_UNSAFE;
                saved_errno = identity < 0 ? errno : EPERM;
            }
        } else if (unlinkat(listener->base_fd, listener->directory_name,
                            AT_REMOVEDIR) != 0 && status == ATTACH_LOCAL_OK) {
            status = ATTACH_LOCAL_ERR_IO;
            saved_errno = errno;
        }
    }
    if (listener->directory_fd >= 0) {
        (void)close(listener->directory_fd);
        listener->directory_fd = -1;
    }
    if (listener->base_fd >= 0) {
        (void)close(listener->base_fd);
        listener->base_fd = -1;
    }
    if (listener->cwd_fd >= 0) {
        (void)close(listener->cwd_fd);
        listener->cwd_fd = -1;
    }
    if (status != ATTACH_LOCAL_OK)
        errno = saved_errno;
    return status;
}

int attach_local_connect(const char *path, int *fd_out)
{
    char parent_path[ATTACH_LOCAL_PATH_CAP];
    char socket_name[ATTACH_LOCAL_NAME_CAP];
    struct stat st;
    uid_t uid;
    int directory_fd = -1;
    int fd;
    int status;

    if (fd_out == NULL) {
        errno = EINVAL;
        return ATTACH_LOCAL_ERR_ARGUMENT;
    }
    *fd_out = -1;
    status = split_absolute_socket_path(path, parent_path, socket_name);
    if (status != ATTACH_LOCAL_OK)
        return status;
    status = open_absolute_directory(parent_path, geteuid(), 1,
                                     &directory_fd);
    if (status != ATTACH_LOCAL_OK)
        return status;
    status = socket_path_stat(directory_fd, socket_name, &st);
    if (status != ATTACH_LOCAL_OK || !S_ISSOCK(st.st_mode) ||
        st.st_uid != geteuid() ||
        (st.st_mode & (mode_t)07777) != ATTACH_LOCAL_SOCKET_MODE) {
        int saved_errno = status == ATTACH_LOCAL_OK ? EPERM : errno;

        (void)close(directory_fd);
        errno = saved_errno;
        return ATTACH_LOCAL_ERR_UNSAFE;
    }
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        int saved_errno = errno;

        (void)close(directory_fd);
        errno = saved_errno;
        return ATTACH_LOCAL_ERR_IO;
    }
    if (set_fd_flags(fd) != ATTACH_LOCAL_OK) {
        int saved_errno = errno;

        (void)close(fd);
        (void)close(directory_fd);
        errno = saved_errno;
        return ATTACH_LOCAL_ERR_IO;
    }
    set_no_sigpipe(fd);
    status = connect_relative_to_directory(fd, directory_fd, socket_name);
    (void)close(directory_fd);
    if (status != ATTACH_LOCAL_OK) {
        int saved_errno = errno;

        (void)close(fd);
        errno = saved_errno;
        return status;
    }
    status = peer_uid(fd, &uid);
    if (status != ATTACH_LOCAL_OK) {
        int saved_errno = errno;

        (void)close(fd);
        errno = saved_errno;
        return ATTACH_LOCAL_ERR_IO;
    }
    if (uid != geteuid()) {
        (void)close(fd);
        errno = EPERM;
        return ATTACH_LOCAL_ERR_UID;
    }
    *fd_out = fd;
    return ATTACH_LOCAL_OK;
}
