/*
 * event_log.h — bounded traffic-profile structured-event codec and sink
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef UNMOOR_EVENT_LOG_H
#define UNMOOR_EVENT_LOG_H

#include <stddef.h>
#include <stdint.h>

#define EVENT_LOG_SCHEMA_V1 "unmoor.event.v1"
#define EVENT_LOG_SCHEMA_V2 "unmoor.event.v2"
#define EVENT_LOG_LINE_MAX 2048U
#define EVENT_LOG_JSON_INTEGER_MAX UINT64_C(9007199254740991)
#define EVENT_LOG_V1_ORDINARY_ATTEMPT_MAX 254U
#define EVENT_LOG_V1_ATTEMPT_MAX 256U
#define EVENT_LOG_V2_ORDINARY_ATTEMPT_MAX 2046U
#define EVENT_LOG_V2_ATTEMPT_MAX 2048U
/* Source-compatible v1 names used by legacy callers and tests. */
#define EVENT_LOG_ORDINARY_ATTEMPT_MAX EVENT_LOG_V1_ORDINARY_ATTEMPT_MAX
#define EVENT_LOG_ATTEMPT_MAX EVENT_LOG_V1_ATTEMPT_MAX
#define EVENT_LOG_NO_LEG (-1)

typedef enum event_log_schema_version {
    EVENT_LOG_SCHEMA_VERSION_V1 = 1,
    EVENT_LOG_SCHEMA_VERSION_V2 = 2
} event_log_schema_version_t;

typedef enum event_log_format {
    EVENT_LOG_FORMAT_TEXT = 0,
    EVENT_LOG_FORMAT_JSON = 1
} event_log_format_t;

typedef enum event_log_event {
    EVENT_LOG_EVENT_OPEN = 0,
    EVENT_LOG_EVENT_VALIDATE,
    EVENT_LOG_EVENT_REROLL,
    EVENT_LOG_EVENT_ROAM,
    EVENT_LOG_EVENT_DEGRADE,
    EVENT_LOG_EVENT_CLOSE,
    EVENT_LOG_EVENT_REFUSE,
    EVENT_LOG_EVENT_STALLED,
    EVENT_LOG_EVENT_COUNT
} event_log_event_t;

typedef enum event_log_scope {
    EVENT_LOG_SCOPE_SESSION = 0,
    EVENT_LOG_SCOPE_LEG,
    EVENT_LOG_SCOPE_CHANNEL,
    EVENT_LOG_SCOPE_COUNT
} event_log_scope_t;

typedef enum event_log_channel_kind {
    EVENT_LOG_CHANNEL_KIND_NONE = 0,
    EVENT_LOG_CHANNEL_TERMINAL = 1,
    EVENT_LOG_CHANNEL_EXEC = 2,
    EVENT_LOG_CHANNEL_BULK_PUSH = 3,
    EVENT_LOG_CHANNEL_BULK_PULL = 4,
    EVENT_LOG_CHANNEL_KIND_COUNT
} event_log_channel_kind_t;

typedef enum event_log_role {
    EVENT_LOG_ROLE_CLIENT = 0,
    EVENT_LOG_ROLE_LISTENER,
    EVENT_LOG_ROLE_COUNT
} event_log_role_t;

typedef enum event_log_profile {
    EVENT_LOG_PROFILE_ENTERPRISE = 0,
    EVENT_LOG_PROFILE_LAB,
    EVENT_LOG_PROFILE_COUNT
} event_log_profile_t;

typedef enum event_log_session_state {
    EVENT_LOG_STATE_IDLE = 0,
    EVENT_LOG_STATE_CONNECTING,
    EVENT_LOG_STATE_KEY_DERIVING,
    EVENT_LOG_STATE_ESTABLISHED,
    EVENT_LOG_STATE_REKEYING,
    EVENT_LOG_STATE_CLOSING,
    EVENT_LOG_STATE_COUNT
} event_log_session_state_t;

typedef enum event_log_reason {
    EVENT_LOG_REASON_SESSION_ACTIVE = 0,
    EVENT_LOG_REASON_PATH_FIRST_ATTEMPT,
    EVENT_LOG_REASON_CHALLENGE_CONFIRMED,
    EVENT_LOG_REASON_SINGLE_LEG_REROLL,
    EVENT_LOG_REASON_WHOLE_SET_REROLL,
    EVENT_LOG_REASON_AUTHENTICATED_HWM,
    EVENT_LOG_REASON_SHARE_REDUCED,
    EVENT_LOG_REASON_REROLL_EXHAUSTED,
    EVENT_LOG_REASON_PEER_CLOSE,
    EVENT_LOG_REASON_LOCAL_CLOSE,
    EVENT_LOG_REASON_COMPLETED,
    EVENT_LOG_REASON_CAPABILITY_MISMATCH,
    EVENT_LOG_REASON_BUSY,
    EVENT_LOG_REASON_QUOTA,
    EVENT_LOG_REASON_NOT_INTERESTED,
    EVENT_LOG_REASON_PROTOCOL_ERROR,
    EVENT_LOG_REASON_IO_ERROR,
    EVENT_LOG_REASON_NO_PROGRESS,
    EVENT_LOG_REASON_NO_CONTACT,
    EVENT_LOG_REASON_PATH_REVALIDATION,
    EVENT_LOG_REASON_COUNT
} event_log_reason_t;

typedef enum event_log_address_family {
    EVENT_LOG_ADDRESS_UNAVAILABLE = 0,
    EVENT_LOG_ADDRESS_IPV4 = 4,
    EVENT_LOG_ADDRESS_IPV6 = 6
} event_log_address_family_t;

typedef struct event_log_endpoint {
    uint8_t family;
    uint8_t reserved;
    uint16_t port;       /* host byte order; zero only when unavailable */
    uint32_t scope_id;   /* numeric IPv6 scope; zero for IPv4 */
    uint8_t address[16]; /* network-order bytes; first four for IPv4 */
} event_log_endpoint_t;

typedef struct event_log_counter {
    uint64_t value;
    uint8_t available;
    uint8_t reserved[7];
} event_log_counter_t;

typedef struct event_log_record {
    event_log_schema_version_t schema_version;
    int64_t time_ms;
    event_log_event_t event;
    event_log_scope_t scope;
    event_log_role_t role;
    event_log_profile_t profile;
    event_log_session_state_t session_state;
    event_log_reason_t reason;
    int leg; /* EVENT_LOG_NO_LEG for session scope; otherwise 0..31 */
    uint64_t generation; /* ignored only for canonical session scope */
    event_log_endpoint_t local;
    event_log_endpoint_t remote;
    uint8_t path_count;
    uint8_t validated_count;
    uint8_t reserved[6];
    event_log_counter_t tx_datagrams;
    event_log_counter_t tx_failures;
    event_log_counter_t rx_datagrams;
    event_log_counter_t rx_drops;
    event_log_counter_t replay_drops;
    event_log_counter_t sent_bytes;
    event_log_counter_t acked_bytes;
    event_log_counter_t timeout_loss;
    event_log_counter_t rerolls;
    uint64_t event_drops;
    uint32_t channel_handle;
    event_log_channel_kind_t channel_kind;
    uint32_t channel_code;
} event_log_record_t;

/* Caller-owned fixed sink state. It retains no line or event payload. */
typedef struct event_log_sink {
    int fd;
    int saved_flags;
    size_t pipe_atomic_bound; /* zero for non-pipe/fifo sinks */
    uint64_t drops;
    uint16_t attempts;
    uint16_t ordinary_attempts;
    uint8_t terminal_attempted;
    uint8_t close_attempted;
    uint8_t armed;
    uint8_t flags_changed;
    event_log_schema_version_t schema_version;
} event_log_sink_t;

typedef enum event_log_emit_result {
    EVENT_LOG_EMIT_ERROR = -1,
    EVENT_LOG_EMIT_WRITTEN = 0,
    EVENT_LOG_EMIT_DROPPED = 1
} event_log_emit_result_t;

void event_log_record_init(event_log_record_t *record,
                           event_log_event_t event,
                           event_log_scope_t scope,
                           event_log_role_t role,
                           event_log_profile_t profile,
                           event_log_session_state_t state,
                           event_log_reason_t reason);
/* Upgrade one initialized record to the channel-session flat v2 event schema. */
void event_log_record_use_v2(event_log_record_t *record);
/* Set canonical channel scope. No string or peer-label input is accepted. */
int event_log_record_set_channel(event_log_record_t *record,
                                 uint32_t handle,
                                 event_log_channel_kind_t kind,
                                 uint32_t code);
event_log_counter_t event_log_counter_unavailable(void);
event_log_counter_t event_log_counter_observed(uint64_t value);
void event_log_endpoint_clear(event_log_endpoint_t *endpoint);
int event_log_endpoint_ipv4(event_log_endpoint_t *endpoint,
                            const uint8_t address[4], uint16_t port);
int event_log_endpoint_ipv6(event_log_endpoint_t *endpoint,
                            const uint8_t address[16], uint16_t port,
                            uint32_t scope_id);

/* Encode exactly one newline-terminated object. No input field is a string. */
int event_log_encode(const event_log_record_t *record, char *out,
                     size_t out_capacity, size_t *length_out);

void event_log_sink_init(event_log_sink_t *sink);
int event_log_sink_arm(event_log_sink_t *sink, int fd);
int event_log_sink_restore(event_log_sink_t *sink);
event_log_emit_result_t event_log_sink_emit(
    event_log_sink_t *sink, const event_log_record_t *record);
void event_log_sink_note_suppressed(event_log_sink_t *sink);
uint64_t event_log_sink_drop_count(const event_log_sink_t *sink);
unsigned int event_log_sink_attempt_count(const event_log_sink_t *sink);

#endif /* UNMOOR_EVENT_LOG_H */
