/*
 * sync_work_codec.h — fixed local STORE/PLAN records, not a wire protocol
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef UNMOOR_SYNC_WORK_CODEC_H
#define UNMOOR_SYNC_WORK_CODEC_H

#include "sync_repair_plan.h"
#include <stddef.h>
#include <stdint.h>

#define SYNC_WORK_VERSION       1U
#define SYNC_WORK_HEADER       24U
#define SYNC_WORK_UNIT      16384U
#define SYNC_WORK_STORE         1U
#define SYNC_WORK_STORED        2U
#define SYNC_WORK_PLAN          3U
#define SYNC_WORK_PLANNED       4U
#define SYNC_WORK_STORE_BYTES   (SYNC_WORK_HEADER + 8U + SYNC_WORK_UNIT)
#define SYNC_WORK_STORED_BYTES  (SYNC_WORK_HEADER + 1U)
#define SYNC_WORK_PLAN_BYTES    (SYNC_WORK_HEADER + 200U)
#define SYNC_WORK_PLANNED_BYTES (SYNC_WORK_HEADER + 11U)

/* Native values only; serialized fields are always encoded individually.
 * Neither a nonzero identity nor codec success proves issuance, freshness,
 * source acceptance, publication, send/delivery or any other authority. */
typedef struct {
    uint64_t incarnation;
    uint64_t operation;
    uint8_t type;
    uint8_t direction;
} sync_work_header_t;

/* Pure synchronous helpers. Return 0 on success, -1 on invalid input.
 * Encoders require sufficient capacity and leave output unchanged on error.
 * Decoders require exact input length and clear every supplied output on
 * error. All input/output objects are disjoint/non-aliasing caller storage.
 * Typed helpers reject a mismatched header.type. Header encode requires a
 * writable 24-byte buffer; header decode accepts exactly 24 bytes.
 * No returned borrowed pointer is an asynchronous lifetime agreement.
 */
size_t sync_work_frame_bytes(uint8_t type); /* 0 for an unknown type */
int sync_work_header_encode(uint8_t output[SYNC_WORK_HEADER],
                            const sync_work_header_t *header);
int sync_work_header_decode(sync_work_header_t *header,
                            const uint8_t *input, size_t length);

int sync_work_store_encode(uint8_t *output, size_t capacity,
                           const sync_work_header_t *header, uint64_t offset,
                           const uint8_t unit[SYNC_WORK_UNIT]);
/* unit borrows exactly U bytes from input until input is changed/released. */
int sync_work_store_decode(sync_work_header_t *header, uint64_t *offset,
                           const uint8_t **unit, const uint8_t *input,
                           size_t length);
/* STORED status is exactly 0 (accepted) or 1 (backing failure). */
int sync_work_stored_encode(uint8_t *output, size_t capacity,
                            const sync_work_header_t *header, uint8_t status);
int sync_work_stored_decode(sync_work_header_t *header, uint8_t *status,
                            const uint8_t *input, size_t length);

/* Encode zeros semantically unused bitmap bits/bytes without mutating view.
 * Decode rejects nonzero unused bits/bytes. Geometry uses the existing small
 * result guard, not a second repair search. cursor>=limit remains valid. */
int sync_work_plan_encode(uint8_t *output, size_t capacity,
                          const sync_work_header_t *header,
                          const sync_repair_view_t *view);
int sync_work_plan_decode(sync_work_header_t *header, sync_repair_view_t *view,
                          const uint8_t *input, size_t length);

/* NONE/EXHAUSTED require zero offset/length. RANGE requires length 1..210
 * and a nonwrapping end. Checks only that canonical syntactic shape. The
 * trusted caller separately checks the issued/current view with the existing
 * result guard before use. Codec success cannot authorize a chosen range. */
int sync_work_planned_encode(uint8_t *output, size_t capacity,
                             const sync_work_header_t *header,
                             const sync_repair_result_t *result);
int sync_work_planned_decode(sync_work_header_t *header,
                             sync_repair_result_t *result,
                             const uint8_t *input, size_t length);

#endif
