/*
 * deaddrop.h — epoch-rekey public one-shot deaddrop records
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * This layer stores public bootstrap material only.  Private scalars, raw DH
 * output, bootstrap roots, traffic keys and confirmation keys have no type or
 * API representation here.
 */
#ifndef UNMOOR_DEADDROP_H
#define UNMOOR_DEADDROP_H

#define _POSIX_C_SOURCE 200809L

#include <stddef.h>
#include <stdint.h>

#define DEADDROP_ID_LEN                    16U
#define DEADDROP_ID_HEX_LEN                32U
#define DEADDROP_PUBLIC_KEY_LEN            32U
#define DEADDROP_FINGERPRINT_LEN           32U

#define DEADDROP_RECORD_VERSION             1U
#define DEADDROP_TRANSPORT_UDP               1U
#define DEADDROP_TEMP_ATTEMPTS               8U

/*
 * Canonical offer wire record (100 bytes):
 *
 *   0..7    magic "UNMDDP28"
 *   8       record version (1)
 *   9       type (offer = 1)
 *   10..11  reserved, zero
 *   12..27  16-byte drop id
 *   28..29  UDP port, unsigned big-endian, nonzero
 *   30      transport id (UDP = 1)
 *   31      reserved, zero
 *   32..35  required capability mask, unsigned big-endian
 *   36..67  server X25519 public key
 *   68..99  public offer fingerprint
 *
 * Canonical response wire record (164 bytes):
 *
 *   0..35   same canonical header and exchange fields, type response = 2
 *   36..67  server X25519 public key
 *   68..99  client X25519 public key
 *   100..131 exact public offer fingerprint
 *   132..163 public full-transcript fingerprint
 *
 * Encoding and decoding are byte-wise.  The C structures below are never
 * copied to or from disk.
 */
#define DEADDROP_OFFER_RECORD_SIZE         100U
#define DEADDROP_RESPONSE_RECORD_SIZE      164U

typedef enum deaddrop_status {
    DEADDROP_OK = 0,
    DEADDROP_ERR_ARGUMENT = -1,
    DEADDROP_ERR_IO = -2,
    DEADDROP_ERR_UNSAFE = -3,
    DEADDROP_ERR_FORMAT = -4,
    DEADDROP_ERR_EXISTS = -5,
    DEADDROP_ERR_REUSED = -6,
    DEADDROP_ERR_NOT_FOUND = -7,
    DEADDROP_ERR_TEMP_COLLISION = -8
} deaddrop_status_t;

typedef enum deaddrop_public_kind {
    DEADDROP_PUBLIC_OFFER = 1,
    DEADDROP_PUBLIC_RESPONSE = 2
} deaddrop_public_kind_t;

#define DEADDROP_PUBLIC_RECORD_MAX 4096U

typedef struct deaddrop_offer {
    uint8_t id[DEADDROP_ID_LEN];
    uint16_t port;
    uint32_t required_caps;
    uint8_t server_public_key[DEADDROP_PUBLIC_KEY_LEN];
    uint8_t offer_fingerprint[DEADDROP_FINGERPRINT_LEN];
} deaddrop_offer_t;

typedef struct deaddrop_response {
    uint8_t id[DEADDROP_ID_LEN];
    uint16_t port;
    uint32_t required_caps;
    uint8_t server_public_key[DEADDROP_PUBLIC_KEY_LEN];
    uint8_t client_public_key[DEADDROP_PUBLIC_KEY_LEN];
    uint8_t offer_fingerprint[DEADDROP_FINGERPRINT_LEN];
    uint8_t transcript_fingerprint[DEADDROP_FINGERPRINT_LEN];
} deaddrop_response_t;

/* A drop id is valid iff it is a nonzero 16-byte value. */
int deaddrop_id_valid(const uint8_t id[DEADDROP_ID_LEN]);

/* Strict lowercase fixed-width conversion.  Uppercase and extra text fail. */
deaddrop_status_t deaddrop_id_from_hex(
    const char *text, uint8_t id_out[DEADDROP_ID_LEN]);
deaddrop_status_t deaddrop_id_to_hex(
    const uint8_t id[DEADDROP_ID_LEN],
    char text_out[DEADDROP_ID_HEX_LEN + 1U]);

/*
 * Open an existing wrapper-owned directory.  The final path must name a real
 * directory (not a symlink), owned by the effective uid, with exact mode
 * 0700.  The returned descriptor has close-on-exec set and is caller-owned.
 */
deaddrop_status_t deaddrop_dir_open(const char *path, int *dirfd_out);

/* Create one fresh id-named mode-0700 attempt directory beneath an already
 * open, same-euid, exact-0700 parent.  The returned descriptor is
 * O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC, owner/mode verified, and caller-owned.
 * Creation is made durable by fsyncing both the child and parent directory. */
deaddrop_status_t deaddrop_attempt_create(
    int parentfd, const uint8_t id[DEADDROP_ID_LEN], int *attemptfd_out);

/* Remove only the exact empty id-named attempt directory and fsync its
 * parent. Missing is idempotent success; a symlink or nonempty directory is
 * never followed or recursively removed. */
deaddrop_status_t deaddrop_attempt_remove(
    int parentfd, const uint8_t id[DEADDROP_ID_LEN]);

/* Explicit canonical byte codecs, exposed for transcript construction/tests. */
deaddrop_status_t deaddrop_offer_encode(
    const deaddrop_offer_t *offer,
    uint8_t out[DEADDROP_OFFER_RECORD_SIZE]);
deaddrop_status_t deaddrop_offer_decode(
    const uint8_t in[DEADDROP_OFFER_RECORD_SIZE],
    deaddrop_offer_t *offer_out);
deaddrop_status_t deaddrop_response_encode(
    const deaddrop_response_t *response,
    uint8_t out[DEADDROP_RESPONSE_RECORD_SIZE]);
deaddrop_status_t deaddrop_response_decode(
    const uint8_t in[DEADDROP_RESPONSE_RECORD_SIZE],
    deaddrop_response_t *response_out);

/*
 * Publish uses only an id-derived basename.  It writes an id-derived bounded
 * temporary regular file at mode 0600, fsyncs it, links it to the final name
 * without replacement, unlinks the temporary name, then fsyncs the directory.
 */
deaddrop_status_t deaddrop_publish_offer(
    int dirfd, const deaddrop_offer_t *offer);
deaddrop_status_t deaddrop_publish_response(
    int dirfd, const deaddrop_response_t *response);

/*
 * Exact-name metadata probes for a waiter.  They neither open nor parse a
 * record and therefore do not claim it.  They use no-follow metadata to
 * require a same-euid regular file, mode no broader than 0600, and the exact
 * type-specific size.  An existing exact tombstone reports
 * DEADDROP_ERR_REUSED rather than absence.  The subsequent claim repeats the
 * metadata checks after winning its tombstone and remains the only path that
 * reads or parses.
 */
deaddrop_status_t deaddrop_offer_present(
    int dirfd, const uint8_t id[DEADDROP_ID_LEN], int *present_out);
deaddrop_status_t deaddrop_response_present(
    int dirfd, const uint8_t id[DEADDROP_ID_LEN], int *present_out);

/*
 * Claim first creates the corresponding empty .used tombstone with
 * O_CREAT|O_EXCL and makes that creation durable.  Only then is the record
 * opened and checked.  The record name is unlinked after the first claim,
 * whether decoding succeeds or fails.  An existing tombstone returns the
 * distinct DEADDROP_ERR_REUSED status without opening the record.
 */
deaddrop_status_t deaddrop_claim_offer(
    int dirfd, const uint8_t id[DEADDROP_ID_LEN],
    deaddrop_offer_t *offer_out);
deaddrop_status_t deaddrop_claim_response(
    int dirfd, const uint8_t id[DEADDROP_ID_LEN],
    deaddrop_response_t *response_out);

/* Version-neutral one-shot storage for strict public records. The caller
 * owns the exact codec and supplies a fixed expected size; these functions
 * never allocate from file contents. */
deaddrop_status_t deaddrop_public_publish(
    int dirfd, const uint8_t id[DEADDROP_ID_LEN],
    deaddrop_public_kind_t kind, const uint8_t *record, size_t record_size);
deaddrop_status_t deaddrop_public_present(
    int dirfd, const uint8_t id[DEADDROP_ID_LEN],
    deaddrop_public_kind_t kind, size_t expected_size, int *present_out);
deaddrop_status_t deaddrop_public_claim(
    int dirfd, const uint8_t id[DEADDROP_ID_LEN],
    deaddrop_public_kind_t kind, uint8_t *record, size_t record_size);

/*
 * Remove only the offer/response, their tombstones, and all bounded temporary
 * names derived from one validated id.  Missing names are ignored.  No
 * directory scan is performed and non-regular entries are never traversed.
 */
deaddrop_status_t deaddrop_cleanup_id(
    int dirfd, const uint8_t id[DEADDROP_ID_LEN]);

const char *deaddrop_status_string(deaddrop_status_t status);

#endif /* UNMOOR_DEADDROP_H */
