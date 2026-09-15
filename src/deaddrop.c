/*
 * deaddrop.c — epoch-rekey public one-shot deaddrop records
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */

#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif
#ifdef __linux__
#define _GNU_SOURCE 1
#endif
#define _XOPEN_SOURCE 700 /* S_ISVTX is XSI, hidden under strict POSIX on glibc */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "deaddrop.h"
#include "fd_stat.h"

#define DD_MAGIC_LEN       8U
#define DD_HEADER_SIZE    36U
#define DD_NAME_CAP       64U

#define DD_OFF_VERSION     8U
#define DD_OFF_TYPE        9U
#define DD_OFF_RESERVED0  10U
#define DD_OFF_ID         12U
#define DD_OFF_PORT       28U
#define DD_OFF_TRANSPORT  30U
#define DD_OFF_RESERVED1  31U
#define DD_OFF_CAPS       32U

#define DD_TYPE_OFFER      1U
#define DD_TYPE_RESPONSE   2U

typedef enum dd_kind {
    DD_KIND_OFFER = 1,
    DD_KIND_RESPONSE = 2
} dd_kind_t;

static int public_kind_to_internal(deaddrop_public_kind_t kind,
                                   dd_kind_t *internal_out)
{
    if (internal_out == NULL)
        return -1;
    if (kind == DEADDROP_PUBLIC_OFFER) {
        *internal_out = DD_KIND_OFFER;
        return 0;
    }
    if (kind == DEADDROP_PUBLIC_RESPONSE) {
        *internal_out = DD_KIND_RESPONSE;
        return 0;
    }
    return -1;
}

static const uint8_t dd_magic[DD_MAGIC_LEN] = {
    'U', 'N', 'M', 'D', 'D', 'P', '2', '8'
};

static void put_u16_be(uint8_t out[2], uint16_t value)
{
    out[0] = (uint8_t)(value >> 8);
    out[1] = (uint8_t)(value & 0xffU);
}

static uint16_t get_u16_be(const uint8_t in[2])
{
    return (uint16_t)(((uint16_t)in[0] << 8) | (uint16_t)in[1]);
}

static void put_u32_be(uint8_t out[4], uint32_t value)
{
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)((value >> 16) & 0xffU);
    out[2] = (uint8_t)((value >> 8) & 0xffU);
    out[3] = (uint8_t)(value & 0xffU);
}

static uint32_t get_u32_be(const uint8_t in[4])
{
    return ((uint32_t)in[0] << 24) |
           ((uint32_t)in[1] << 16) |
           ((uint32_t)in[2] << 8) |
           (uint32_t)in[3];
}

int deaddrop_id_valid(const uint8_t id[DEADDROP_ID_LEN])
{
    uint8_t any = 0;
    size_t i;

    if (id == NULL)
        return 0;
    for (i = 0; i < DEADDROP_ID_LEN; i++)
        any |= id[i];
    return any != 0;
}

deaddrop_status_t deaddrop_id_from_hex(
    const char *text, uint8_t id_out[DEADDROP_ID_LEN])
{
    size_t i;

    if (text == NULL || id_out == NULL ||
        strlen(text) != DEADDROP_ID_HEX_LEN) {
        errno = EINVAL;
        return DEADDROP_ERR_ARGUMENT;
    }
    for (i = 0; i < DEADDROP_ID_LEN; i++) {
        unsigned int hi;
        unsigned int lo;
        char a = text[i * 2U];
        char b = text[i * 2U + 1U];

        if (a >= '0' && a <= '9')
            hi = (unsigned int)(a - '0');
        else if (a >= 'a' && a <= 'f')
            hi = (unsigned int)(a - 'a') + 10U;
        else {
            memset(id_out, 0, DEADDROP_ID_LEN);
            errno = EINVAL;
            return DEADDROP_ERR_FORMAT;
        }
        if (b >= '0' && b <= '9')
            lo = (unsigned int)(b - '0');
        else if (b >= 'a' && b <= 'f')
            lo = (unsigned int)(b - 'a') + 10U;
        else {
            memset(id_out, 0, DEADDROP_ID_LEN);
            errno = EINVAL;
            return DEADDROP_ERR_FORMAT;
        }
        id_out[i] = (uint8_t)((hi << 4) | lo);
    }
    if (!deaddrop_id_valid(id_out)) {
        memset(id_out, 0, DEADDROP_ID_LEN);
        errno = EINVAL;
        return DEADDROP_ERR_FORMAT;
    }
    return DEADDROP_OK;
}

deaddrop_status_t deaddrop_id_to_hex(
    const uint8_t id[DEADDROP_ID_LEN],
    char text_out[DEADDROP_ID_HEX_LEN + 1U])
{
    static const char hex[] = "0123456789abcdef";
    size_t i;

    if (!deaddrop_id_valid(id) || text_out == NULL) {
        errno = EINVAL;
        return DEADDROP_ERR_ARGUMENT;
    }
    for (i = 0; i < DEADDROP_ID_LEN; i++) {
        text_out[i * 2U] = hex[id[i] >> 4];
        text_out[i * 2U + 1U] = hex[id[i] & 0x0fU];
    }
    text_out[DEADDROP_ID_HEX_LEN] = '\0';
    return DEADDROP_OK;
}

static deaddrop_status_t validate_dirfd(int dirfd)
{
    struct stat st;

    if (dirfd < 0) {
        errno = EBADF;
        return DEADDROP_ERR_ARGUMENT;
    }
    if (unmoor_fd_stat(dirfd, &st) != 0)
        return DEADDROP_ERR_IO;
    if (!S_ISDIR(st.st_mode) || st.st_uid != geteuid() ||
        (st.st_mode & (mode_t)07777) != (mode_t)0700) {
        errno = EPERM;
        return DEADDROP_ERR_UNSAFE;
    }
    return DEADDROP_OK;
}

static int fsync_retry(int fd);
static int close_once(int fd);

deaddrop_status_t deaddrop_dir_open(const char *path, int *dirfd_out)
{
    int fd;
    deaddrop_status_t status;

    if (path == NULL || path[0] == '\0' || dirfd_out == NULL) {
        errno = EINVAL;
        return DEADDROP_ERR_ARGUMENT;
    }
    *dirfd_out = -1;
    fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ELOOP || errno == ENOTDIR)
            return DEADDROP_ERR_UNSAFE;
        return DEADDROP_ERR_IO;
    }
    status = validate_dirfd(fd);
    if (status != DEADDROP_OK) {
        int saved_errno = errno;
        (void)close(fd);
        errno = saved_errno;
        return status;
    }
    *dirfd_out = fd;
    return DEADDROP_OK;
}

static deaddrop_status_t attempt_name(
    const uint8_t id[DEADDROP_ID_LEN],
    char out[DEADDROP_ID_HEX_LEN + 1U])
{
    return deaddrop_id_to_hex(id, out);
}

deaddrop_status_t deaddrop_attempt_create(
    int parentfd, const uint8_t id[DEADDROP_ID_LEN], int *attemptfd_out)
{
    char name[DEADDROP_ID_HEX_LEN + 1U];
    deaddrop_status_t status;
    int fd = -1;
    int created = 0;
    int saved_errno;

    if (!attemptfd_out) {
        errno = EINVAL;
        return DEADDROP_ERR_ARGUMENT;
    }
    *attemptfd_out = -1;
    status = validate_dirfd(parentfd);
    if (status != DEADDROP_OK)
        return status;
    status = attempt_name(id, name);
    if (status != DEADDROP_OK)
        return status;
    if (mkdirat(parentfd, name, 0700) != 0)
        return errno == EEXIST ? DEADDROP_ERR_EXISTS : DEADDROP_ERR_IO;
    created = 1;
    fd = openat(parentfd, name,
                O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        status = (errno == ELOOP || errno == ENOTDIR) ?
                     DEADDROP_ERR_UNSAFE : DEADDROP_ERR_IO;
        goto fail;
    }
    if (fchmod(fd, 0700) != 0) {
        status = DEADDROP_ERR_IO;
        goto fail;
    }
    status = validate_dirfd(fd);
    if (status != DEADDROP_OK)
        goto fail;
    if (fsync_retry(fd) != 0 || fsync_retry(parentfd) != 0) {
        status = DEADDROP_ERR_IO;
        goto fail;
    }
    *attemptfd_out = fd;
    return DEADDROP_OK;

fail:
    saved_errno = errno;
    if (fd >= 0)
        (void)close_once(fd);
    if (created)
        (void)unlinkat(parentfd, name, AT_REMOVEDIR);
    (void)fsync_retry(parentfd);
    errno = saved_errno;
    return status;
}

deaddrop_status_t deaddrop_attempt_remove(
    int parentfd, const uint8_t id[DEADDROP_ID_LEN])
{
    char name[DEADDROP_ID_HEX_LEN + 1U];
    deaddrop_status_t status;

    status = validate_dirfd(parentfd);
    if (status != DEADDROP_OK)
        return status;
    status = attempt_name(id, name);
    if (status != DEADDROP_OK)
        return status;
    if (unlinkat(parentfd, name, AT_REMOVEDIR) != 0 && errno != ENOENT)
        return DEADDROP_ERR_IO;
    if (fsync_retry(parentfd) != 0)
        return DEADDROP_ERR_IO;
    return DEADDROP_OK;
}

static deaddrop_status_t encode_header(uint8_t *out, size_t out_len,
                                       uint8_t type,
                                       const uint8_t id[DEADDROP_ID_LEN],
                                       uint16_t port, uint32_t required_caps)
{
    if (out == NULL || out_len < DD_HEADER_SIZE ||
        !deaddrop_id_valid(id) || port == 0 ||
        (type != DD_TYPE_OFFER && type != DD_TYPE_RESPONSE)) {
        errno = EINVAL;
        return DEADDROP_ERR_ARGUMENT;
    }
    memset(out, 0, out_len);
    memcpy(out, dd_magic, DD_MAGIC_LEN);
    out[DD_OFF_VERSION] = DEADDROP_RECORD_VERSION;
    out[DD_OFF_TYPE] = type;
    memcpy(out + DD_OFF_ID, id, DEADDROP_ID_LEN);
    put_u16_be(out + DD_OFF_PORT, port);
    out[DD_OFF_TRANSPORT] = DEADDROP_TRANSPORT_UDP;
    put_u32_be(out + DD_OFF_CAPS, required_caps);
    return DEADDROP_OK;
}

static deaddrop_status_t decode_header(const uint8_t *in, size_t in_len,
                                       uint8_t expected_type,
                                       uint8_t id_out[DEADDROP_ID_LEN],
                                       uint16_t *port_out,
                                       uint32_t *required_caps_out)
{
    uint16_t port;

    if (in == NULL || in_len < DD_HEADER_SIZE || id_out == NULL ||
        port_out == NULL || required_caps_out == NULL) {
        errno = EINVAL;
        return DEADDROP_ERR_ARGUMENT;
    }
    if (memcmp(in, dd_magic, DD_MAGIC_LEN) != 0 ||
        in[DD_OFF_VERSION] != DEADDROP_RECORD_VERSION ||
        in[DD_OFF_TYPE] != expected_type ||
        in[DD_OFF_RESERVED0] != 0 || in[DD_OFF_RESERVED0 + 1U] != 0 ||
        in[DD_OFF_TRANSPORT] != DEADDROP_TRANSPORT_UDP ||
        in[DD_OFF_RESERVED1] != 0) {
        errno = EPROTO;
        return DEADDROP_ERR_FORMAT;
    }
    memcpy(id_out, in + DD_OFF_ID, DEADDROP_ID_LEN);
    port = get_u16_be(in + DD_OFF_PORT);
    if (!deaddrop_id_valid(id_out) || port == 0) {
        memset(id_out, 0, DEADDROP_ID_LEN);
        errno = EPROTO;
        return DEADDROP_ERR_FORMAT;
    }
    *port_out = port;
    *required_caps_out = get_u32_be(in + DD_OFF_CAPS);
    return DEADDROP_OK;
}

deaddrop_status_t deaddrop_offer_encode(
    const deaddrop_offer_t *offer,
    uint8_t out[DEADDROP_OFFER_RECORD_SIZE])
{
    deaddrop_status_t status;

    if (offer == NULL || out == NULL) {
        errno = EINVAL;
        return DEADDROP_ERR_ARGUMENT;
    }
    status = encode_header(out, DEADDROP_OFFER_RECORD_SIZE, DD_TYPE_OFFER,
                           offer->id, offer->port, offer->required_caps);
    if (status != DEADDROP_OK)
        return status;
    memcpy(out + DD_HEADER_SIZE, offer->server_public_key,
           DEADDROP_PUBLIC_KEY_LEN);
    memcpy(out + DD_HEADER_SIZE + DEADDROP_PUBLIC_KEY_LEN,
           offer->offer_fingerprint, DEADDROP_FINGERPRINT_LEN);
    return DEADDROP_OK;
}

deaddrop_status_t deaddrop_offer_decode(
    const uint8_t in[DEADDROP_OFFER_RECORD_SIZE],
    deaddrop_offer_t *offer_out)
{
    deaddrop_offer_t decoded;
    deaddrop_status_t status;

    if (in == NULL || offer_out == NULL) {
        errno = EINVAL;
        return DEADDROP_ERR_ARGUMENT;
    }
    memset(&decoded, 0, sizeof(decoded));
    status = decode_header(in, DEADDROP_OFFER_RECORD_SIZE, DD_TYPE_OFFER,
                           decoded.id, &decoded.port,
                           &decoded.required_caps);
    if (status != DEADDROP_OK) {
        memset(offer_out, 0, sizeof(*offer_out));
        return status;
    }
    memcpy(decoded.server_public_key, in + DD_HEADER_SIZE,
           DEADDROP_PUBLIC_KEY_LEN);
    memcpy(decoded.offer_fingerprint,
           in + DD_HEADER_SIZE + DEADDROP_PUBLIC_KEY_LEN,
           DEADDROP_FINGERPRINT_LEN);
    *offer_out = decoded;
    return DEADDROP_OK;
}

deaddrop_status_t deaddrop_response_encode(
    const deaddrop_response_t *response,
    uint8_t out[DEADDROP_RESPONSE_RECORD_SIZE])
{
    deaddrop_status_t status;
    size_t off;

    if (response == NULL || out == NULL) {
        errno = EINVAL;
        return DEADDROP_ERR_ARGUMENT;
    }
    status = encode_header(out, DEADDROP_RESPONSE_RECORD_SIZE,
                           DD_TYPE_RESPONSE, response->id, response->port,
                           response->required_caps);
    if (status != DEADDROP_OK)
        return status;
    off = DD_HEADER_SIZE;
    memcpy(out + off, response->server_public_key, DEADDROP_PUBLIC_KEY_LEN);
    off += DEADDROP_PUBLIC_KEY_LEN;
    memcpy(out + off, response->client_public_key, DEADDROP_PUBLIC_KEY_LEN);
    off += DEADDROP_PUBLIC_KEY_LEN;
    memcpy(out + off, response->offer_fingerprint,
           DEADDROP_FINGERPRINT_LEN);
    off += DEADDROP_FINGERPRINT_LEN;
    memcpy(out + off, response->transcript_fingerprint,
           DEADDROP_FINGERPRINT_LEN);
    return DEADDROP_OK;
}

deaddrop_status_t deaddrop_response_decode(
    const uint8_t in[DEADDROP_RESPONSE_RECORD_SIZE],
    deaddrop_response_t *response_out)
{
    deaddrop_response_t decoded;
    deaddrop_status_t status;
    size_t off;

    if (in == NULL || response_out == NULL) {
        errno = EINVAL;
        return DEADDROP_ERR_ARGUMENT;
    }
    memset(&decoded, 0, sizeof(decoded));
    status = decode_header(in, DEADDROP_RESPONSE_RECORD_SIZE,
                           DD_TYPE_RESPONSE, decoded.id, &decoded.port,
                           &decoded.required_caps);
    if (status != DEADDROP_OK) {
        memset(response_out, 0, sizeof(*response_out));
        return status;
    }
    off = DD_HEADER_SIZE;
    memcpy(decoded.server_public_key, in + off, DEADDROP_PUBLIC_KEY_LEN);
    off += DEADDROP_PUBLIC_KEY_LEN;
    memcpy(decoded.client_public_key, in + off, DEADDROP_PUBLIC_KEY_LEN);
    off += DEADDROP_PUBLIC_KEY_LEN;
    memcpy(decoded.offer_fingerprint, in + off, DEADDROP_FINGERPRINT_LEN);
    off += DEADDROP_FINGERPRINT_LEN;
    memcpy(decoded.transcript_fingerprint, in + off,
           DEADDROP_FINGERPRINT_LEN);
    *response_out = decoded;
    return DEADDROP_OK;
}

static const char *kind_suffix(dd_kind_t kind)
{
    if (kind == DD_KIND_OFFER)
        return ".offer";
    if (kind == DD_KIND_RESPONSE)
        return ".response";
    return NULL;
}

static deaddrop_status_t build_name(
    const uint8_t id[DEADDROP_ID_LEN], dd_kind_t kind,
    int used, int temp_index, char out[DD_NAME_CAP])
{
    char id_hex[DEADDROP_ID_HEX_LEN + 1U];
    const char *suffix;
    int n;
    deaddrop_status_t status;

    if (out == NULL || (used && temp_index >= 0)) {
        errno = EINVAL;
        return DEADDROP_ERR_ARGUMENT;
    }
    suffix = kind_suffix(kind);
    if (suffix == NULL) {
        errno = EINVAL;
        return DEADDROP_ERR_ARGUMENT;
    }
    status = deaddrop_id_to_hex(id, id_hex);
    if (status != DEADDROP_OK)
        return status;

    if (temp_index >= 0) {
        if ((unsigned int)temp_index >= DEADDROP_TEMP_ATTEMPTS) {
            errno = EINVAL;
            return DEADDROP_ERR_ARGUMENT;
        }
        n = snprintf(out, DD_NAME_CAP, "%s%s.tmp.%d", id_hex, suffix,
                     temp_index);
    } else if (used) {
        n = snprintf(out, DD_NAME_CAP, "%s%s.used", id_hex, suffix);
    } else {
        n = snprintf(out, DD_NAME_CAP, "%s%s", id_hex, suffix);
    }
    if (n < 0 || (size_t)n >= DD_NAME_CAP) {
        errno = ENAMETOOLONG;
        return DEADDROP_ERR_IO;
    }
    return DEADDROP_OK;
}

static int fsync_retry(int fd)
{
    int result;
    do {
        result = fsync(fd);
    } while (result != 0 && errno == EINTR);
    return result;
}

/* POSIX leaves a close(2) interrupted by a signal state-dependent.  Retrying
 * can close a descriptor reused by a signal handler or another thread. */
static int close_once(int fd)
{
    return close(fd);
}

static int write_all(int fd, const uint8_t *data, size_t len)
{
    size_t off = 0;

    while (off < len) {
        ssize_t n = write(fd, data + off, len - off);
        if (n > 0) {
            off += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        if (n == 0)
            errno = EIO;
        return -1;
    }
    return 0;
}

static deaddrop_status_t validate_new_file(int fd)
{
    struct stat st;

    if (unmoor_fd_stat(fd, &st) != 0)
        return DEADDROP_ERR_IO;
    if (!S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
        (st.st_mode & (mode_t)07777) != (mode_t)0600 || st.st_nlink != 1) {
        errno = EPERM;
        return DEADDROP_ERR_UNSAFE;
    }
    return DEADDROP_OK;
}

static deaddrop_status_t publish_record(
    int dirfd, const uint8_t id[DEADDROP_ID_LEN], dd_kind_t kind,
    const uint8_t *record, size_t record_size)
{
    char final_name[DD_NAME_CAP];
    char temp_name[DD_NAME_CAP];
    deaddrop_status_t status;
    int temp_fd = -1;
    unsigned int attempt;
    int saved_errno;
    int linked = 0;

    status = validate_dirfd(dirfd);
    if (status != DEADDROP_OK)
        return status;
    if (!deaddrop_id_valid(id) || record == NULL || record_size == 0) {
        errno = EINVAL;
        return DEADDROP_ERR_ARGUMENT;
    }
    status = build_name(id, kind, 0, -1, final_name);
    if (status != DEADDROP_OK)
        return status;

    for (attempt = 0; attempt < DEADDROP_TEMP_ATTEMPTS; attempt++) {
        status = build_name(id, kind, 0, (int)attempt, temp_name);
        if (status != DEADDROP_OK)
            return status;
        temp_fd = openat(dirfd, temp_name,
                         O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW |
                         O_CLOEXEC,
                         0600);
        if (temp_fd >= 0)
            break;
        if (errno != EEXIST)
            return DEADDROP_ERR_IO;
    }
    if (temp_fd < 0) {
        errno = EEXIST;
        return DEADDROP_ERR_TEMP_COLLISION;
    }

    if (fchmod(temp_fd, 0600) != 0) {
        status = DEADDROP_ERR_IO;
        goto fail;
    }
    status = validate_new_file(temp_fd);
    if (status != DEADDROP_OK)
        goto fail;
    if (write_all(temp_fd, record, record_size) != 0 ||
        fsync_retry(temp_fd) != 0) {
        status = DEADDROP_ERR_IO;
        goto fail;
    }
    if (close_once(temp_fd) != 0) {
        temp_fd = -1;
        status = DEADDROP_ERR_IO;
        goto fail;
    }
    temp_fd = -1;

    if (linkat(dirfd, temp_name, dirfd, final_name, 0) != 0) {
        status = (errno == EEXIST) ? DEADDROP_ERR_EXISTS : DEADDROP_ERR_IO;
        goto fail;
    }
    linked = 1;
    if (unlinkat(dirfd, temp_name, 0) != 0) {
        status = DEADDROP_ERR_IO;
        goto finish;
    }
    if (fsync_retry(dirfd) != 0)
        return DEADDROP_ERR_IO;
    return DEADDROP_OK;

fail:
    saved_errno = errno;
    if (temp_fd >= 0)
        (void)close_once(temp_fd);
    (void)unlinkat(dirfd, temp_name, 0);
    (void)fsync_retry(dirfd);
    errno = saved_errno;
    return status;

finish:
    saved_errno = errno;
    if (!linked)
        (void)unlinkat(dirfd, final_name, 0);
    (void)fsync_retry(dirfd);
    errno = saved_errno;
    return status;
}

deaddrop_status_t deaddrop_publish_offer(
    int dirfd, const deaddrop_offer_t *offer)
{
    uint8_t wire[DEADDROP_OFFER_RECORD_SIZE];
    deaddrop_status_t status;

    status = deaddrop_offer_encode(offer, wire);
    if (status != DEADDROP_OK)
        return status;
    return publish_record(dirfd, offer->id, DD_KIND_OFFER,
                          wire, sizeof(wire));
}

deaddrop_status_t deaddrop_publish_response(
    int dirfd, const deaddrop_response_t *response)
{
    uint8_t wire[DEADDROP_RESPONSE_RECORD_SIZE];
    deaddrop_status_t status;

    status = deaddrop_response_encode(response, wire);
    if (status != DEADDROP_OK)
        return status;
    return publish_record(dirfd, response->id, DD_KIND_RESPONSE,
                          wire, sizeof(wire));
}

static deaddrop_status_t record_present(
    int dirfd, const uint8_t id[DEADDROP_ID_LEN], dd_kind_t kind,
    size_t expected_size, int *present_out)
{
    char name[DD_NAME_CAP];
    char used_name[DD_NAME_CAP];
    struct stat st;
    deaddrop_status_t status;

    if (expected_size == 0 || expected_size > DEADDROP_PUBLIC_RECORD_MAX ||
        present_out == NULL) {
        errno = EINVAL;
        return DEADDROP_ERR_ARGUMENT;
    }
    *present_out = 0;
    status = validate_dirfd(dirfd);
    if (status != DEADDROP_OK)
        return status;
    status = build_name(id, kind, 1, -1, used_name);
    if (status != DEADDROP_OK)
        return status;
    if (fstatat(dirfd, used_name, &st, AT_SYMLINK_NOFOLLOW) == 0)
        return DEADDROP_ERR_REUSED;
    if (errno != ENOENT)
        return DEADDROP_ERR_IO;
    status = build_name(id, kind, 0, -1, name);
    if (status != DEADDROP_OK)
        return status;
    if (fstatat(dirfd, name, &st, AT_SYMLINK_NOFOLLOW) == 0) {
        if (!S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
            (st.st_mode & (mode_t)0177) != 0 ||
            (st.st_mode & (mode_t)(S_ISUID | S_ISGID | S_ISVTX)) != 0) {
            errno = EPERM;
            return DEADDROP_ERR_UNSAFE;
        }
        if (st.st_size < 0 ||
            (uintmax_t)st.st_size != (uintmax_t)expected_size) {
            errno = EPROTO;
            return DEADDROP_ERR_FORMAT;
        }
        *present_out = 1;
        return DEADDROP_OK;
    }
    if (errno == ENOENT)
        return DEADDROP_OK;
    return DEADDROP_ERR_IO;
}

deaddrop_status_t deaddrop_offer_present(
    int dirfd, const uint8_t id[DEADDROP_ID_LEN], int *present_out)
{
    return record_present(dirfd, id, DD_KIND_OFFER,
                          DEADDROP_OFFER_RECORD_SIZE, present_out);
}

deaddrop_status_t deaddrop_response_present(
    int dirfd, const uint8_t id[DEADDROP_ID_LEN], int *present_out)
{
    return record_present(dirfd, id, DD_KIND_RESPONSE,
                          DEADDROP_RESPONSE_RECORD_SIZE, present_out);
}

deaddrop_status_t deaddrop_public_publish(
    int dirfd, const uint8_t id[DEADDROP_ID_LEN],
    deaddrop_public_kind_t kind, const uint8_t *record, size_t record_size)
{
    dd_kind_t internal;

    if (public_kind_to_internal(kind, &internal) != 0 || record == NULL ||
        record_size == 0 || record_size > DEADDROP_PUBLIC_RECORD_MAX) {
        errno = EINVAL;
        return DEADDROP_ERR_ARGUMENT;
    }
    return publish_record(dirfd, id, internal, record, record_size);
}

deaddrop_status_t deaddrop_public_present(
    int dirfd, const uint8_t id[DEADDROP_ID_LEN],
    deaddrop_public_kind_t kind, size_t expected_size, int *present_out)
{
    dd_kind_t internal;

    if (public_kind_to_internal(kind, &internal) != 0 ||
        expected_size == 0 || expected_size > DEADDROP_PUBLIC_RECORD_MAX) {
        errno = EINVAL;
        return DEADDROP_ERR_ARGUMENT;
    }
    return record_present(dirfd, id, internal, expected_size, present_out);
}

static deaddrop_status_t create_tombstone(
    int dirfd, const uint8_t id[DEADDROP_ID_LEN], dd_kind_t kind,
    int *created_out)
{
    char name[DD_NAME_CAP];
    int fd;
    deaddrop_status_t status;

    *created_out = 0;
    status = build_name(id, kind, 1, -1, name);
    if (status != DEADDROP_OK)
        return status;
    fd = openat(dirfd, name,
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                0600);
    if (fd < 0) {
        if (errno == EEXIST)
            return DEADDROP_ERR_REUSED;
        return DEADDROP_ERR_IO;
    }
    *created_out = 1;
    if (fchmod(fd, 0600) != 0) {
        status = DEADDROP_ERR_IO;
    } else {
        status = validate_new_file(fd);
        if (status == DEADDROP_OK && fsync_retry(fd) != 0)
            status = DEADDROP_ERR_IO;
    }
    if (close_once(fd) != 0 && status == DEADDROP_OK)
        status = DEADDROP_ERR_IO;
    if (fsync_retry(dirfd) != 0 && status == DEADDROP_OK)
        status = DEADDROP_ERR_IO;
    return status;
}

static deaddrop_status_t read_claimed_record(
    int dirfd, const char *name, uint8_t *record, size_t record_size)
{
    int fd;
    struct stat st;
    size_t off = 0;
    uint8_t extra;
    deaddrop_status_t status = DEADDROP_OK;

    fd = openat(dirfd, name,
                O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT)
            return DEADDROP_ERR_NOT_FOUND;
        if (errno == ELOOP)
            return DEADDROP_ERR_UNSAFE;
        return DEADDROP_ERR_IO;
    }
    if (unmoor_fd_stat(fd, &st) != 0) {
        status = DEADDROP_ERR_IO;
        goto done;
    }
    if (!S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
        (st.st_mode & (mode_t)0177) != 0 ||
        (st.st_mode & (mode_t)(S_ISUID | S_ISGID | S_ISVTX)) != 0) {
        errno = EPERM;
        status = DEADDROP_ERR_UNSAFE;
        goto done;
    }
    if (st.st_size < 0 || (uintmax_t)st.st_size != (uintmax_t)record_size) {
        errno = EPROTO;
        status = DEADDROP_ERR_FORMAT;
        goto done;
    }
    while (off < record_size) {
        ssize_t n = read(fd, record + off, record_size - off);
        if (n > 0) {
            off += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        if (n == 0)
            errno = EPROTO;
        status = (n == 0) ? DEADDROP_ERR_FORMAT : DEADDROP_ERR_IO;
        goto done;
    }
    for (;;) {
        ssize_t n = read(fd, &extra, 1);
        if (n == 0)
            break;
        if (n < 0 && errno == EINTR)
            continue;
        if (n > 0) {
            errno = EPROTO;
            status = DEADDROP_ERR_FORMAT;
        } else {
            status = DEADDROP_ERR_IO;
        }
        break;
    }

done:
    if (close_once(fd) != 0 && status == DEADDROP_OK)
        status = DEADDROP_ERR_IO;
    return status;
}

static deaddrop_status_t remove_claimed_record(int dirfd, const char *name)
{
    if (unlinkat(dirfd, name, 0) != 0 && errno != ENOENT)
        return DEADDROP_ERR_IO;
    if (fsync_retry(dirfd) != 0)
        return DEADDROP_ERR_IO;
    return DEADDROP_OK;
}

static deaddrop_status_t claim_record(
    int dirfd, const uint8_t id[DEADDROP_ID_LEN], dd_kind_t kind,
    uint8_t *wire, size_t wire_size)
{
    char name[DD_NAME_CAP];
    deaddrop_status_t status;
    deaddrop_status_t remove_status;
    int created = 0;

    status = validate_dirfd(dirfd);
    if (status != DEADDROP_OK)
        return status;
    if (!deaddrop_id_valid(id) || wire == NULL || wire_size == 0) {
        errno = EINVAL;
        return DEADDROP_ERR_ARGUMENT;
    }
    status = build_name(id, kind, 0, -1, name);
    if (status != DEADDROP_OK)
        return status;

    status = create_tombstone(dirfd, id, kind, &created);
    if (status == DEADDROP_ERR_REUSED)
        return status;
    if (status == DEADDROP_OK)
        status = read_claimed_record(dirfd, name, wire, wire_size);

    if (created) {
        remove_status = remove_claimed_record(dirfd, name);
        if (status == DEADDROP_OK && remove_status != DEADDROP_OK)
            status = remove_status;
    }
    return status;
}

deaddrop_status_t deaddrop_public_claim(
    int dirfd, const uint8_t id[DEADDROP_ID_LEN],
    deaddrop_public_kind_t kind, uint8_t *record, size_t record_size)
{
    dd_kind_t internal;

    if (public_kind_to_internal(kind, &internal) != 0 || record == NULL ||
        record_size == 0 || record_size > DEADDROP_PUBLIC_RECORD_MAX) {
        errno = EINVAL;
        return DEADDROP_ERR_ARGUMENT;
    }
    return claim_record(dirfd, id, internal, record, record_size);
}

deaddrop_status_t deaddrop_claim_offer(
    int dirfd, const uint8_t id[DEADDROP_ID_LEN],
    deaddrop_offer_t *offer_out)
{
    uint8_t wire[DEADDROP_OFFER_RECORD_SIZE];
    deaddrop_offer_t decoded;
    deaddrop_status_t status;

    if (offer_out == NULL) {
        errno = EINVAL;
        return DEADDROP_ERR_ARGUMENT;
    }
    memset(offer_out, 0, sizeof(*offer_out));
    memset(wire, 0, sizeof(wire));
    status = claim_record(dirfd, id, DD_KIND_OFFER, wire, sizeof(wire));
    if (status != DEADDROP_OK)
        return status;
    status = deaddrop_offer_decode(wire, &decoded);
    if (status != DEADDROP_OK)
        return status;
    if (memcmp(decoded.id, id, DEADDROP_ID_LEN) != 0) {
        errno = EPROTO;
        return DEADDROP_ERR_FORMAT;
    }
    *offer_out = decoded;
    return DEADDROP_OK;
}

deaddrop_status_t deaddrop_claim_response(
    int dirfd, const uint8_t id[DEADDROP_ID_LEN],
    deaddrop_response_t *response_out)
{
    uint8_t wire[DEADDROP_RESPONSE_RECORD_SIZE];
    deaddrop_response_t decoded;
    deaddrop_status_t status;

    if (response_out == NULL) {
        errno = EINVAL;
        return DEADDROP_ERR_ARGUMENT;
    }
    memset(response_out, 0, sizeof(*response_out));
    memset(wire, 0, sizeof(wire));
    status = claim_record(dirfd, id, DD_KIND_RESPONSE, wire, sizeof(wire));
    if (status != DEADDROP_OK)
        return status;
    status = deaddrop_response_decode(wire, &decoded);
    if (status != DEADDROP_OK)
        return status;
    if (memcmp(decoded.id, id, DEADDROP_ID_LEN) != 0) {
        errno = EPROTO;
        return DEADDROP_ERR_FORMAT;
    }
    *response_out = decoded;
    return DEADDROP_OK;
}

deaddrop_status_t deaddrop_cleanup_id(
    int dirfd, const uint8_t id[DEADDROP_ID_LEN])
{
    dd_kind_t kinds[2] = { DD_KIND_OFFER, DD_KIND_RESPONSE };
    deaddrop_status_t status;
    deaddrop_status_t result = DEADDROP_OK;
    char name[DD_NAME_CAP];
    size_t k;
    unsigned int attempt;
    int changed = 0;

    status = validate_dirfd(dirfd);
    if (status != DEADDROP_OK)
        return status;
    if (!deaddrop_id_valid(id)) {
        errno = EINVAL;
        return DEADDROP_ERR_ARGUMENT;
    }

    for (k = 0; k < sizeof(kinds) / sizeof(kinds[0]); k++) {
        int used;
        for (used = 0; used <= 1; used++) {
            status = build_name(id, kinds[k], used, -1, name);
            if (status != DEADDROP_OK)
                return status;
            if (unlinkat(dirfd, name, 0) == 0) {
                changed = 1;
            } else if (errno != ENOENT && result == DEADDROP_OK) {
                result = DEADDROP_ERR_IO;
            }
        }
        for (attempt = 0; attempt < DEADDROP_TEMP_ATTEMPTS; attempt++) {
            status = build_name(id, kinds[k], 0, (int)attempt, name);
            if (status != DEADDROP_OK)
                return status;
            if (unlinkat(dirfd, name, 0) == 0) {
                changed = 1;
            } else if (errno != ENOENT && result == DEADDROP_OK) {
                result = DEADDROP_ERR_IO;
            }
        }
    }
    if (changed && fsync_retry(dirfd) != 0 && result == DEADDROP_OK)
        result = DEADDROP_ERR_IO;
    return result;
}

const char *deaddrop_status_string(deaddrop_status_t status)
{
    switch (status) {
    case DEADDROP_OK:
        return "ok";
    case DEADDROP_ERR_ARGUMENT:
        return "invalid argument";
    case DEADDROP_ERR_IO:
        return "I/O error";
    case DEADDROP_ERR_UNSAFE:
        return "unsafe file or directory";
    case DEADDROP_ERR_FORMAT:
        return "noncanonical record";
    case DEADDROP_ERR_EXISTS:
        return "record already exists";
    case DEADDROP_ERR_REUSED:
        return "drop already used";
    case DEADDROP_ERR_NOT_FOUND:
        return "record not found";
    case DEADDROP_ERR_TEMP_COLLISION:
        return "temporary-name collision limit";
    default:
        return "unknown deaddrop status";
    }
}
