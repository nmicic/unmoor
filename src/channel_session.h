/*
 * channel_session.h — channel-session encrypted channel handles and lifecycle
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef UNMOOR_CHANNEL_SESSION_H
#define UNMOOR_CHANNEL_SESSION_H

#include <stddef.h>
#include <stdint.h>

#define CHANNEL_SESSION_SLOTS 16U
#define CHANNEL_SESSION_DATA_SLOTS 15U
#define CHANNEL_SESSION_HANDLE_BYTES 4U
#define CHANNEL_SESSION_GENERATION_MAX UINT32_C(0x0fffffff)

#define CHANNEL_SESSION_OPEN_BYTES 48U
#define CHANNEL_SESSION_RESULT_BYTES 12U
#define CHANNEL_SESSION_LABEL_MAX 32U
#define CHANNEL_SESSION_READY_BYTES 56U
#define CHANNEL_SESSION_FIRST_OPEN_MS INT64_C(31000)

#define CTRL_CHANNEL_OPEN      0x13U
#define CTRL_CHANNEL_ACCEPT    0x14U
#define CTRL_CHANNEL_REFUSE    0x15U
#define CTRL_CHANNEL_CLOSE     0x16U
#define CTRL_CHANNEL_CLOSE_ACK 0x17U

typedef enum {
    CHANNEL_KIND_TERMINAL = 1,
    CHANNEL_KIND_EXEC = 2,
    CHANNEL_KIND_BULK_PUSH = 3,
    CHANNEL_KIND_BULK_PULL = 4
} channel_session_kind_t;

typedef enum {
    CHANNEL_CODE_OK = 0,
    CHANNEL_CODE_POLICY = 1,
    CHANNEL_CODE_CAPACITY = 2,
    CHANNEL_CODE_KIND_UNSUPPORTED = 3,
    CHANNEL_CODE_RESOURCE = 4,
    CHANNEL_CODE_TIMEOUT = 5,
    CHANNEL_CODE_STALLED = 6,
    CHANNEL_CODE_PROTOCOL = 7,
    /* client-confinement: local-only. The confined terminal client refused a child-transfer operand
     * before forking because it lies outside the confinement roots. Never
     * placed on the wire; it is carried to the attach client so the refusal
     * is named instead of surfacing as an EACCES inside the child. */
    CHANNEL_CODE_CONFINED = 8
} channel_session_code_t;

typedef struct {
    uint8_t version;
    uint8_t kind;
    uint8_t flags;
    uint8_t label_length;
    uint32_t handle;
    uint32_t parameter0;
    uint32_t parameter1;
    uint8_t label[CHANNEL_SESSION_LABEL_MAX];
} channel_session_open_t;

typedef struct {
    uint8_t version;
    uint8_t kind;
    uint32_t handle;
    uint32_t code;
} channel_session_result_t;

typedef enum {
    CHANNEL_SLOT_FREE = 0,
    CHANNEL_SLOT_OPENING,
    CHANNEL_SLOT_ACTIVE,
    CHANNEL_SLOT_CLOSING,
    CHANNEL_SLOT_RETIRED
} channel_session_slot_state_t;

typedef struct {
    channel_session_slot_state_t state;
    uint32_t last_generation;
    uint32_t handle;
    channel_session_open_t open;
    uint8_t decision_type;
    uint32_t decision_code;
    uint32_t close_code;       /* immutable local CLOSE / matching ACK */
    uint32_t peer_close_code;  /* immutable peer CLOSE / our ACK */
    uint8_t local_close_started;
    uint8_t local_close_acked;
    uint8_t peer_close_seen;
} channel_session_slot_t;

typedef struct {
    channel_session_slot_t slots[CHANNEL_SESSION_SLOTS];
    uint16_t live_mask;
    uint16_t active_mask;
    uint8_t next_slot;
    uint8_t opening_slot;
    uint8_t last_close_started;
} channel_session_table_t;

typedef enum {
    CHANNEL_OBSERVE_ERROR = -1,
    CHANNEL_OBSERVE_NEW = 0,
    CHANNEL_OBSERVE_DUPLICATE = 1,
    CHANNEL_OBSERVE_STALE = 2,
    CHANNEL_OBSERVE_CONFLICT = 3
} channel_session_observe_t;

int channel_session_kind_valid(uint8_t kind);
int channel_session_handle_make(uint8_t slot, uint32_t generation,
                                uint32_t *handle_out);
int channel_session_handle_decode(uint32_t handle, uint8_t *slot_out,
                                  uint32_t *generation_out);

int channel_session_open_encode(
    const channel_session_open_t *open,
    uint8_t out[CHANNEL_SESSION_OPEN_BYTES]);
int channel_session_open_decode(
    const uint8_t *wire, size_t wire_length,
    channel_session_open_t *open_out);
int channel_session_result_encode(
    uint8_t type, const channel_session_result_t *result,
    uint8_t out[CHANNEL_SESSION_RESULT_BYTES]);
int channel_session_result_decode(
    uint8_t type, const uint8_t *wire, size_t wire_length,
    channel_session_result_t *result_out);

int channel_session_ready_encode(
    const uint8_t ready_prefix[8], int is_client,
    const channel_session_open_t *first_open,
    uint8_t out[CHANNEL_SESSION_READY_BYTES]);
int channel_session_ready_decode(
    const uint8_t *wire, size_t wire_length, int from_client,
    uint8_t ready_prefix_out[8], channel_session_open_t *first_open_out);

void channel_session_table_init(channel_session_table_t *table);
int channel_session_client_candidate_slot(
    const channel_session_table_t *table, uint8_t *slot_out);
int channel_session_client_candidate_slot_excluding(
    const channel_session_table_t *table, uint16_t unavailable_mask,
    uint8_t *slot_out);
int channel_session_client_begin_open_at(
    channel_session_table_t *table, const channel_session_open_t *descriptor,
    uint8_t slot, channel_session_open_t *open_out);
int channel_session_client_begin_open(
    channel_session_table_t *table, const channel_session_open_t *descriptor,
    channel_session_open_t *open_out);
channel_session_observe_t channel_session_observe_open(
    channel_session_table_t *table, const channel_session_open_t *open);
int channel_session_decide_open(channel_session_table_t *table,
                                uint32_t handle, int accepted,
                                uint32_t code);
channel_session_observe_t channel_session_observe_result(
    channel_session_table_t *table, uint8_t type,
    const channel_session_result_t *result);
/* Resolve one fully authenticated and reassembled data record.  NEW means
 * the ACTIVE instance may receive it.  DUPLICATE means the handle is current
 * but not ACTIVE and must be dropped before the application. */
channel_session_observe_t channel_session_resolve_data(
    const channel_session_table_t *table, uint32_t handle, uint8_t kind);
int channel_session_begin_close(channel_session_table_t *table,
                                uint32_t handle, uint32_t code);
channel_session_observe_t channel_session_observe_close(
    channel_session_table_t *table,
    const channel_session_result_t *close_record);
channel_session_observe_t channel_session_observe_close_ack(
    channel_session_table_t *table,
    const channel_session_result_t *ack_record);
unsigned int channel_session_live_count(const channel_session_table_t *table);

#endif /* UNMOOR_CHANNEL_SESSION_H */
