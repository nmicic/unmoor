/*
 * attach_local.h — channel-session bounded same-uid local attach protocol
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef UNMOOR_ATTACH_LOCAL_H
#define UNMOOR_ATTACH_LOCAL_H

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#define ATTACH_LOCAL_VERSION_V1 UINT8_C(1)
#define ATTACH_LOCAL_VERSION_V2 UINT8_C(2)
/* Source-compatible name for the local-protocol version this build speaks. */
#define ATTACH_LOCAL_VERSION ATTACH_LOCAL_VERSION_V1
#define ATTACH_LOCAL_HEADER_BYTES 8U
#define ATTACH_LOCAL_MAX_PAYLOAD 4096U
#define ATTACH_LOCAL_MAX_CONNECTIONS 15U
#define ATTACH_LOCAL_FIRST_RECORD_MS INT64_C(5000)
#define ATTACH_LOCAL_MAX_EXEC_ARGS 64U
#define ATTACH_LOCAL_EXEC_STORAGE \
    (ATTACH_LOCAL_MAX_PAYLOAD + ATTACH_LOCAL_MAX_EXEC_ARGS)
#define ATTACH_LOCAL_NAME_CAP 64U
#define ATTACH_LOCAL_PATH_CAP (sizeof(((struct sockaddr_un *)0)->sun_path))

#define ATTACH_LOCAL_KIND_TERMINAL UINT8_C(1)
#define ATTACH_LOCAL_KIND_EXEC UINT8_C(2)
#define ATTACH_LOCAL_KIND_BULK_PUSH UINT8_C(3)
#define ATTACH_LOCAL_KIND_BULK_PULL UINT8_C(4)

#define ATTACH_LOCAL_BULK_WIRE_MIN UINT16_C(768)
#define ATTACH_LOCAL_BULK_WIRE_DEFAULT UINT16_C(1200)
#define ATTACH_LOCAL_BULK_WIRE_MAX UINT16_C(8952)
#define ATTACH_LOCAL_BULK_STALL_MIN UINT16_C(1)
#define ATTACH_LOCAL_BULK_STALL_DEFAULT UINT16_C(30)
#define ATTACH_LOCAL_BULK_STALL_MAX UINT16_C(300)
#define ATTACH_LOCAL_BULK_PATH_MAX 1024U
#define ATTACH_LOCAL_BULK_OPEN_PREFIX_BYTES 12U
#define ATTACH_LOCAL_BULK_REQUEST_BASE_BYTES 48U
#define ATTACH_LOCAL_BULK_OPTION_FORCE UINT8_C(0x01)
/* Local-only v2 RESULT refusal emitted before a child handle or transfer id
 * exists. It names a control-client confinement refusal and never reaches the
 * UDP/session wire. Codes 5..7 and every other extension remain invalid. */
#define ATTACH_LOCAL_BULK_RESULT_CONFINED UINT32_C(8)
/* Local-only v2 CLOSE result.  It cannot collide with the bulk-transfer result-code
 * range and is never placed on the UDP/session wire. */
#define ATTACH_LOCAL_BULK_CLOSE_CONFINED UINT32_C(0x80000001)

/* Exact v1 local record type ids. */
typedef enum {
    ATTACH_LOCAL_RECORD_OPEN = 1,
    ATTACH_LOCAL_RECORD_RESULT = 2,
    ATTACH_LOCAL_RECORD_DATA = 3,
    ATTACH_LOCAL_RECORD_EOF = 4,
    ATTACH_LOCAL_RECORD_RESIZE = 5,
    ATTACH_LOCAL_RECORD_SIGNAL = 6,
    ATTACH_LOCAL_RECORD_EXIT = 7,
    ATTACH_LOCAL_RECORD_CLOSE = 8
} attach_local_record_type_t;

/*
 * Nonnegative values are ordinary progress.  Negative values are terminal
 * for the affected operation/connection.  Functions set errno when a useful
 * POSIX error exists, but callers must branch on this closed status set.
 */
typedef enum {
    ATTACH_LOCAL_OK = 0,
    ATTACH_LOCAL_FRAME_READY = 1,
    ATTACH_LOCAL_WOULD_BLOCK = 2,
    ATTACH_LOCAL_CLOSED = 3,
    ATTACH_LOCAL_ERR_ARGUMENT = -1,
    ATTACH_LOCAL_ERR_PROTOCOL = -2,
    ATTACH_LOCAL_ERR_IO = -3,
    ATTACH_LOCAL_ERR_UNSAFE = -4,
    ATTACH_LOCAL_ERR_CAPACITY = -5,
    ATTACH_LOCAL_ERR_TIMEOUT = -6,
    ATTACH_LOCAL_ERR_UID = -7,
    ATTACH_LOCAL_ERR_BUSY = -8
} attach_local_status_t;

typedef struct {
    uint8_t version;
    uint8_t type;
    uint8_t kind;
    uint32_t length;
    uint8_t payload[ATTACH_LOCAL_MAX_PAYLOAD];
} attach_local_record_t;

typedef struct {
    uint8_t header[ATTACH_LOCAL_HEADER_BYTES];
    size_t header_used;
    uint32_t payload_length;
    size_t payload_used;
    uint8_t payload[ATTACH_LOCAL_MAX_PAYLOAD];
    int header_ready;
    int saw_first_record;
    int poisoned;
    int64_t first_record_deadline_ms;
} attach_local_parser_t;

typedef struct {
    size_t count;
    size_t storage_used;
    uint16_t offsets[ATTACH_LOCAL_MAX_EXEC_ARGS];
    uint16_t lengths[ATTACH_LOCAL_MAX_EXEC_ARGS];
    char storage[ATTACH_LOCAL_EXEC_STORAGE];
} attach_local_exec_argv_t;

/*
 * Owned, decoded version-2 BULK_PUSH/BULK_PULL OPEN.  Lengths retain the exact
 * wire values; the private trailing NULs are for bounded filesystem APIs and
 * are never part of the local protocol.
 */
typedef struct {
    uint16_t wire_budget;
    uint16_t stall_seconds;
    uint16_t local_path_length;
    uint16_t remote_path_length;
    uint8_t options;
    uint8_t kind;
    uint8_t local_path[ATTACH_LOCAL_BULK_PATH_MAX + 1U];
    uint8_t remote_path[ATTACH_LOCAL_BULK_PATH_MAX + 1U];
} attach_local_bulk_open_t;

typedef enum {
    ATTACH_LOCAL_RUNTIME_NONE = 0,
    ATTACH_LOCAL_RUNTIME_XDG,
    ATTACH_LOCAL_RUNTIME_TMPDIR,
    ATTACH_LOCAL_RUNTIME_HOME
} attach_local_runtime_source_t;

typedef struct {
    const char *xdg_runtime_dir;
    const char *tmpdir;
    const char *home;
    const char *session_name;
    const char *socket_name;
    uid_t uid;
} attach_local_listener_config_t;

typedef struct {
    int fd;
    uid_t peer_uid;
    int active;
    attach_local_parser_t parser;
    uint8_t write_buffer[ATTACH_LOCAL_HEADER_BYTES +
                         ATTACH_LOCAL_MAX_PAYLOAD];
    size_t write_length;
    size_t write_offset;
} attach_local_connection_t;

typedef struct {
    int listen_fd;
    int base_fd;
    int directory_fd;
    int cwd_fd;    /* client-confinement: cwd saved before confinement; -1 when unused */
    int prepared;  /* client-confinement: prepare ran, bind has not */
    uid_t uid;
    attach_local_runtime_source_t runtime_source;
    int directory_created;
    int socket_owned;
    dev_t directory_device;
    ino_t directory_inode;
    dev_t socket_device;
    ino_t socket_inode;
    char base_path[ATTACH_LOCAL_PATH_CAP];
    char directory_path[ATTACH_LOCAL_PATH_CAP];
    char socket_path[ATTACH_LOCAL_PATH_CAP];
    char directory_name[ATTACH_LOCAL_NAME_CAP];
    char socket_name[ATTACH_LOCAL_NAME_CAP];
    attach_local_connection_t connections[ATTACH_LOCAL_MAX_CONNECTIONS];
} attach_local_listener_t;

/*
 * Local header, byte for byte:
 *   0 version=1|2, 1 type=1..8, 2 kind, 3 flags=0,
 *   4 length LE32<=4096.
 * Version 1 is the exact grammar below.  Version 2 admits only
 * BULK_PUSH/BULK_PULL OPEN, RESULT, and CLOSE; every non-OPEN has kind=0.
 * OPEN kind in v1 is TERMINAL=1 or EXEC=2.
 * A TERMINAL OPEN body is rows LE16 + columns LE16 (both 1..1000).  An EXEC
 * OPEN body is exactly the argv encoding below.  RESULT is handle LE32 plus
 * normalized code LE32. In v1 it is 0 accepted or 1..4 refused. In v2 it is
 * 0 accepted, 1..4 ordinarily refused, or exactly 8 for a pre-generation
 * local confinement refusal; code 8 requires zero handle and transfer id.
 * DATA is 1..4096 opaque bytes; EOF is empty; RESIZE is rows, columns,
 * xpixel, ypixel as four LE16 values (rows/columns 1..1000); SIGNAL is
 * signum 1..63 plus three zero bytes; EXIT and CLOSE are one unrestricted
 * LE32 code each.
 */
int attach_local_record_encode(const attach_local_record_t *record,
                               uint8_t *wire, size_t wire_capacity,
                               size_t *wire_length_out);
void attach_local_parser_init(attach_local_parser_t *parser, int64_t now_ms);
int attach_local_parser_feed(attach_local_parser_t *parser,
                             const uint8_t *input, size_t input_length,
                             size_t *consumed_out,
                             attach_local_record_t *record_out);
int attach_local_parser_check_deadline(const attach_local_parser_t *parser,
                                       int64_t now_ms);

/*
 * EXEC OPEN payload, byte for byte:
 *   argc LE16, then argc repetitions of arg_length LE16 + raw argument.
 * The complete payload is <=4096 bytes.  argc is 1..64, argv[0] is nonempty,
 * and later arguments may be empty; no argument may contain NUL.
 * Metacharacters have no special meaning.
 */
int attach_local_exec_encode_slices(const uint8_t *const arguments[],
                                    const uint16_t lengths[], size_t count,
                                    uint8_t out[ATTACH_LOCAL_MAX_PAYLOAD],
                                    size_t *length_out);
int attach_local_exec_encode(size_t count, const char *const arguments[],
                             uint8_t out[ATTACH_LOCAL_MAX_PAYLOAD],
                             size_t *length_out);
int attach_local_exec_decode(const uint8_t *payload, size_t payload_length,
                             attach_local_exec_argv_t *argv_out);
/*
 * Inspect an incrementally received EXEC argv preface.  Return
 * ATTACH_LOCAL_FRAME_READY once the complete preface is present and write its
 * exact boundary to expected_out; bytes after that boundary are child stdin.
 * Return ATTACH_LOCAL_OK while more bytes are needed, or a negative status as
 * soon as the bounded grammar is impossible.
 */
int attach_local_exec_prefix_boundary(const uint8_t *bytes, size_t used,
                                      size_t *expected_out);
const char *attach_local_exec_argument(const attach_local_exec_argv_t *argv,
                                       size_t index);
int attach_local_terminal_open(uint16_t rows, uint16_t columns,
                               attach_local_record_t *record_out);
int attach_local_exec_open(size_t count, const char *const arguments[],
                           attach_local_record_t *record_out);
size_t attach_local_bulk_request_path_limit(uint16_t wire_budget);
int attach_local_bulk_open(uint8_t kind, uint16_t wire_budget,
                           uint16_t stall_seconds, uint8_t options,
                           const uint8_t *local_path,
                           size_t local_path_length,
                           const uint8_t *remote_path,
                           size_t remote_path_length,
                           attach_local_record_t *record_out);
int attach_local_bulk_open_decode(const attach_local_record_t *record,
                                  attach_local_bulk_open_t *open_out);
int attach_local_result(uint32_t handle, uint32_t code,
                        attach_local_record_t *record_out);
int attach_local_result_decode(const attach_local_record_t *record,
                               uint32_t *handle_out, uint32_t *code_out);
int attach_local_bulk_result(uint32_t handle, uint32_t code,
                             uint64_t transfer_id,
                             attach_local_record_t *record_out);
int attach_local_bulk_result_decode(const attach_local_record_t *record,
                                    uint32_t *handle_out,
                                    uint32_t *code_out,
                                    uint64_t *transfer_id_out);
int attach_local_data(const uint8_t *data, size_t length,
                      attach_local_record_t *record_out);
int attach_local_eof(attach_local_record_t *record_out);
int attach_local_resize(uint16_t rows, uint16_t columns,
                        uint16_t xpixel, uint16_t ypixel,
                        attach_local_record_t *record_out);
int attach_local_resize_decode(const attach_local_record_t *record,
                               uint16_t *rows_out, uint16_t *columns_out,
                               uint16_t *xpixel_out, uint16_t *ypixel_out);
int attach_local_signal(uint8_t signum, attach_local_record_t *record_out);
int attach_local_signal_decode(const attach_local_record_t *record,
                               uint8_t *signum_out);
int attach_local_exit(uint32_t code, attach_local_record_t *record_out);
int attach_local_close(uint32_t code, attach_local_record_t *record_out);
int attach_local_close_version(uint8_t version, uint32_t code,
                               attach_local_record_t *record_out);
int attach_local_code_decode(const attach_local_record_t *record,
                             uint8_t expected_type, uint32_t *code_out);

void attach_local_listener_config_from_environment(
    attach_local_listener_config_t *config,
    const char *session_name, const char *socket_name);
int attach_local_path_fits(const char *path);
int attach_local_peer_uid_matches(uid_t expected, uid_t actual);
int attach_local_listener_open(attach_local_listener_t *listener,
                               const attach_local_listener_config_t *config);
/*
 * Explicit --attach-socket contract.  The absolute path's immediate parent
 * must already exist, be reached without symlinks, and be euid-owned 0700.
 * The parent is never removed by listener cleanup.
 */
/*
 * client-confinement split of attach_local_listener_open_path().  `prepare` performs every
 * path operation (base walk, identity capture, saved cwd) and creates
 * nothing; `bind_prepared` creates and binds the socket using only the held
 * descriptors, so it stays legal inside a Landlock domain whose only right on
 * that directory is MAKE_SOCK|REMOVE_FILE.  Calling open_path is exactly
 * prepare followed by bind_prepared.
 */
int attach_local_listener_prepare_path(attach_local_listener_t *listener,
                                       const char *absolute_path, uid_t uid);
int attach_local_listener_bind_prepared(attach_local_listener_t *listener);
int attach_local_listener_open_path(attach_local_listener_t *listener,
                                    const char *absolute_path, uid_t uid);
int attach_local_listener_accept(attach_local_listener_t *listener,
                                 int64_t now_ms, size_t *index_out);
int attach_local_listener_close(attach_local_listener_t *listener);
void attach_local_connection_close(attach_local_connection_t *connection);
int attach_local_connection_read(attach_local_connection_t *connection,
                                 int64_t now_ms,
                                 attach_local_record_t *record_out);
int attach_local_connection_queue(attach_local_connection_t *connection,
                                  const attach_local_record_t *record);
int attach_local_connection_flush(attach_local_connection_t *connection);

/* Client-side bounded, nonblocking, close-on-exec connect helper. */
int attach_local_connect(const char *path, int *fd_out);

#endif /* UNMOOR_ATTACH_LOCAL_H */
