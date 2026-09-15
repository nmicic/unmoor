/*
 * event_log.c — bounded traffic-profile structured-event codec and sink
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#define _POSIX_C_SOURCE 200809L

#include "event_log.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct event_writer {
    char *bytes;
    size_t capacity;
    size_t length;
    int failed;
} event_writer_t;

static const char *const event_names[EVENT_LOG_EVENT_COUNT] = {
    "open", "validate", "reroll", "roam", "degrade", "close",
    "refuse", "stalled"
};
static const char *const scope_names[EVENT_LOG_SCOPE_COUNT] = {
    "session", "leg", "channel"
};
static const char *const channel_kind_names[EVENT_LOG_CHANNEL_KIND_COUNT] = {
    NULL, "terminal", "exec", "bulk_push", "bulk_pull"
};
static const char *const role_names[EVENT_LOG_ROLE_COUNT] = {
    "client", "listener"
};
static const char *const profile_names[EVENT_LOG_PROFILE_COUNT] = {
    "enterprise", "lab"
};
static const char *const state_names[EVENT_LOG_STATE_COUNT] = {
    "idle", "connecting", "key_deriving", "established", "rekeying",
    "closing"
};
static const char *const reason_names[EVENT_LOG_REASON_COUNT] = {
    "session_active", "path_first_attempt", "challenge_confirmed",
    "single_leg_reroll", "whole_set_reroll", "authenticated_hwm",
    "share_reduced", "reroll_exhausted", "peer_close", "local_close",
    "completed",
    "capability_mismatch", "busy", "quota", "not_interested",
    "protocol_error", "io_error", "no_progress", "no_contact",
    "path_revalidation"
};

static uint64_t json_integer(uint64_t value)
{
    return value > EVENT_LOG_JSON_INTEGER_MAX
        ? EVENT_LOG_JSON_INTEGER_MAX : value;
}

static void drops_increment(event_log_sink_t *sink)
{
    if (sink->drops < EVENT_LOG_JSON_INTEGER_MAX)
        sink->drops++;
}

static void writer_append(event_writer_t *writer, const char *format, ...)
#if defined(__GNUC__) || defined(__clang__)
    __attribute__((format(printf, 2, 3)))
#endif
    ;

static void writer_append(event_writer_t *writer, const char *format, ...)
{
    va_list arguments;
    int count;

    if (writer == NULL || writer->failed || writer->bytes == NULL ||
        writer->length >= writer->capacity)
        return;
    va_start(arguments, format);
    count = vsnprintf(writer->bytes + writer->length,
                      writer->capacity - writer->length,
                      format, arguments);
    va_end(arguments);
    if (count < 0 || (size_t)count >= writer->capacity - writer->length) {
        writer->failed = 1;
        return;
    }
    writer->length += (size_t)count;
}

static int address_bytes_zero(const uint8_t *bytes, size_t count)
{
    uint8_t value = 0U;
    size_t i;

    for (i = 0U; i < count; i++)
        value |= bytes[i];
    return value == 0U;
}

static int endpoint_valid(const event_log_endpoint_t *endpoint)
{
    static const uint8_t mapped_prefix[12] = {
        0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0xffU, 0xffU
    };

    if (endpoint == NULL || endpoint->reserved != 0U)
        return 0;
    if (endpoint->family == EVENT_LOG_ADDRESS_UNAVAILABLE)
        return endpoint->port == 0U && endpoint->scope_id == 0U &&
               address_bytes_zero(endpoint->address,
                                  sizeof(endpoint->address));
    if (endpoint->port == 0U)
        return 0;
    if (endpoint->family == EVENT_LOG_ADDRESS_IPV4)
        return endpoint->scope_id == 0U &&
               address_bytes_zero(endpoint->address + 4U, 12U);
    if (endpoint->family == EVENT_LOG_ADDRESS_IPV6)
        return memcmp(endpoint->address, mapped_prefix,
                      sizeof(mapped_prefix)) != 0;
    return 0;
}

static void writer_endpoint(event_writer_t *writer,
                            const event_log_endpoint_t *endpoint)
{
    char address[INET6_ADDRSTRLEN];
    int family;

    if (endpoint->family == EVENT_LOG_ADDRESS_UNAVAILABLE) {
        writer_append(writer, "null");
        return;
    }
    family = endpoint->family == EVENT_LOG_ADDRESS_IPV4 ? AF_INET : AF_INET6;
    if (inet_ntop(family, endpoint->address, address, sizeof(address)) == NULL) {
        writer->failed = 1;
        return;
    }
    if (family == AF_INET) {
        writer_append(writer, "\"%s:%u\"", address,
                      (unsigned int)endpoint->port);
    } else if (endpoint->scope_id != 0U) {
        writer_append(writer, "\"[%s%%%" PRIu32 "]:%u\"", address,
                      endpoint->scope_id, (unsigned int)endpoint->port);
    } else {
        writer_append(writer, "\"[%s]:%u\"", address,
                      (unsigned int)endpoint->port);
    }
}

static int counter_valid(const event_log_counter_t *counter)
{
    return counter != NULL && counter->available <= 1U &&
           address_bytes_zero(counter->reserved, sizeof(counter->reserved));
}

static int channel_handle_valid(uint32_t handle)
{
    return (handle & UINT32_C(0x0f)) != 0U &&
           (handle >> 4) != 0U;
}

static void writer_counter(event_writer_t *writer,
                           const event_log_counter_t *counter)
{
    if (!counter->available)
        writer_append(writer, "null");
    else
        writer_append(writer, "%" PRIu64, json_integer(counter->value));
}

static int record_valid(const event_log_record_t *record)
{
    const event_log_counter_t *counters[9];
    size_t i;

    if (record == NULL ||
        (record->schema_version != EVENT_LOG_SCHEMA_VERSION_V1 &&
         record->schema_version != EVENT_LOG_SCHEMA_VERSION_V2) ||
        record->time_ms < 0 ||
        record->event < 0 || record->event >= EVENT_LOG_EVENT_COUNT ||
        record->scope < 0 || record->scope >= EVENT_LOG_SCOPE_COUNT ||
        record->role < 0 || record->role >= EVENT_LOG_ROLE_COUNT ||
        record->profile < 0 || record->profile >= EVENT_LOG_PROFILE_COUNT ||
        record->session_state < 0 ||
        record->session_state >= EVENT_LOG_STATE_COUNT ||
        record->reason < 0 || record->reason >= EVENT_LOG_REASON_COUNT ||
        record->path_count == 0U || record->path_count > 32U ||
        record->validated_count > record->path_count ||
        !address_bytes_zero(record->reserved, sizeof(record->reserved)) ||
        !endpoint_valid(&record->local) || !endpoint_valid(&record->remote))
        return 0;
    if (((record->scope == EVENT_LOG_SCOPE_SESSION ||
          record->scope == EVENT_LOG_SCOPE_CHANNEL) &&
         (record->leg != EVENT_LOG_NO_LEG || record->generation != 0U)) ||
        (record->scope == EVENT_LOG_SCOPE_LEG &&
         (record->leg < 0 || record->leg > 31)))
        return 0;
    if (record->schema_version == EVENT_LOG_SCHEMA_VERSION_V1) {
        if (record->scope == EVENT_LOG_SCOPE_CHANNEL ||
            record->channel_handle != 0U ||
            record->channel_kind != EVENT_LOG_CHANNEL_KIND_NONE ||
            record->channel_code != 0U)
            return 0;
    } else if (record->scope == EVENT_LOG_SCOPE_CHANNEL) {
        if (!channel_handle_valid(record->channel_handle) ||
            record->channel_kind < EVENT_LOG_CHANNEL_TERMINAL ||
            record->channel_kind >= EVENT_LOG_CHANNEL_KIND_COUNT)
            return 0;
    } else if (record->channel_handle != 0U ||
               record->channel_kind != EVENT_LOG_CHANNEL_KIND_NONE ||
               record->channel_code != 0U) {
        return 0;
    }
    counters[0] = &record->tx_datagrams;
    counters[1] = &record->tx_failures;
    counters[2] = &record->rx_datagrams;
    counters[3] = &record->rx_drops;
    counters[4] = &record->replay_drops;
    counters[5] = &record->sent_bytes;
    counters[6] = &record->acked_bytes;
    counters[7] = &record->timeout_loss;
    counters[8] = &record->rerolls;
    for (i = 0U; i < sizeof(counters) / sizeof(counters[0]); i++)
        if (!counter_valid(counters[i]))
            return 0;
    return 1;
}

void event_log_record_init(event_log_record_t *record,
                           event_log_event_t event,
                           event_log_scope_t scope,
                           event_log_role_t role,
                           event_log_profile_t profile,
                           event_log_session_state_t state,
                           event_log_reason_t reason)
{
    if (record == NULL)
        return;
    memset(record, 0, sizeof(*record));
    record->schema_version = EVENT_LOG_SCHEMA_VERSION_V1;
    record->event = event;
    record->scope = scope;
    record->role = role;
    record->profile = profile;
    record->session_state = state;
    record->reason = reason;
    record->leg = EVENT_LOG_NO_LEG;
    record->path_count = 1U;
}

void event_log_record_use_v2(event_log_record_t *record)
{
    if (record != NULL)
        record->schema_version = EVENT_LOG_SCHEMA_VERSION_V2;
}

int event_log_record_set_channel(event_log_record_t *record,
                                 uint32_t handle,
                                 event_log_channel_kind_t kind,
                                 uint32_t code)
{
    if (record == NULL ||
        record->schema_version != EVENT_LOG_SCHEMA_VERSION_V2 ||
        !channel_handle_valid(handle) ||
        kind < EVENT_LOG_CHANNEL_TERMINAL ||
        kind >= EVENT_LOG_CHANNEL_KIND_COUNT)
        return -1;
    record->scope = EVENT_LOG_SCOPE_CHANNEL;
    record->leg = EVENT_LOG_NO_LEG;
    record->generation = 0U;
    record->channel_handle = handle;
    record->channel_kind = kind;
    record->channel_code = code;
    return 0;
}

event_log_counter_t event_log_counter_unavailable(void)
{
    event_log_counter_t counter;

    memset(&counter, 0, sizeof(counter));
    return counter;
}

event_log_counter_t event_log_counter_observed(uint64_t value)
{
    event_log_counter_t counter;

    memset(&counter, 0, sizeof(counter));
    counter.value = value;
    counter.available = 1U;
    return counter;
}

void event_log_endpoint_clear(event_log_endpoint_t *endpoint)
{
    if (endpoint != NULL)
        memset(endpoint, 0, sizeof(*endpoint));
}

int event_log_endpoint_ipv4(event_log_endpoint_t *endpoint,
                            const uint8_t address[4], uint16_t port)
{
    if (endpoint == NULL || address == NULL || port == 0U)
        return -1;
    memset(endpoint, 0, sizeof(*endpoint));
    endpoint->family = EVENT_LOG_ADDRESS_IPV4;
    endpoint->port = port;
    memcpy(endpoint->address, address, 4U);
    return 0;
}

int event_log_endpoint_ipv6(event_log_endpoint_t *endpoint,
                            const uint8_t address[16], uint16_t port,
                            uint32_t scope_id)
{
    event_log_endpoint_t candidate;

    if (endpoint == NULL || address == NULL || port == 0U)
        return -1;
    memset(&candidate, 0, sizeof(candidate));
    candidate.family = EVENT_LOG_ADDRESS_IPV6;
    candidate.port = port;
    candidate.scope_id = scope_id;
    memcpy(candidate.address, address, 16U);
    if (!endpoint_valid(&candidate))
        return -1;
    *endpoint = candidate;
    return 0;
}

int event_log_encode(const event_log_record_t *record, char *out,
                     size_t out_capacity, size_t *length_out)
{
    event_writer_t writer;

    if (length_out != NULL)
        *length_out = 0U;
    if (out == NULL || length_out == NULL || out_capacity == 0U ||
        out_capacity > EVENT_LOG_LINE_MAX || !record_valid(record))
        return -1;
    memset(&writer, 0, sizeof(writer));
    writer.bytes = out;
    writer.capacity = out_capacity;
    writer_append(&writer,
        "{\"schema\":\"%s\",\"time_ms\":%" PRIu64
        ",\"event\":\"%s\",\"scope\":\"%s\",\"role\":\"%s\""
        ",\"profile\":\"%s\",\"session_state\":\"%s\",\"leg\":",
        record->schema_version == EVENT_LOG_SCHEMA_VERSION_V1
            ? EVENT_LOG_SCHEMA_V1 : EVENT_LOG_SCHEMA_V2,
        json_integer((uint64_t)record->time_ms),
        event_names[record->event], scope_names[record->scope],
        role_names[record->role], profile_names[record->profile],
        state_names[record->session_state]);
    if (record->scope != EVENT_LOG_SCOPE_LEG)
        writer_append(&writer, "null");
    else
        writer_append(&writer, "%d", record->leg);
    writer_append(&writer, ",\"local\":");
    writer_endpoint(&writer, &record->local);
    writer_append(&writer, ",\"remote\":");
    writer_endpoint(&writer, &record->remote);
    writer_append(&writer, ",\"generation\":");
    if (record->scope != EVENT_LOG_SCOPE_LEG)
        writer_append(&writer, "null");
    else
        writer_append(&writer, "%" PRIu64,
                      json_integer(record->generation));
    writer_append(&writer,
        ",\"reason\":\"%s\",\"path_count\":%u,\"validated_count\":%u"
        ",\"tx_datagrams\":",
        reason_names[record->reason], (unsigned int)record->path_count,
        (unsigned int)record->validated_count);
    writer_counter(&writer, &record->tx_datagrams);
    writer_append(&writer, ",\"tx_failures\":");
    writer_counter(&writer, &record->tx_failures);
    writer_append(&writer, ",\"rx_datagrams\":");
    writer_counter(&writer, &record->rx_datagrams);
    writer_append(&writer, ",\"rx_drops\":");
    writer_counter(&writer, &record->rx_drops);
    writer_append(&writer, ",\"replay_drops\":");
    writer_counter(&writer, &record->replay_drops);
    writer_append(&writer, ",\"sent_bytes\":");
    writer_counter(&writer, &record->sent_bytes);
    writer_append(&writer, ",\"acked_bytes\":");
    writer_counter(&writer, &record->acked_bytes);
    writer_append(&writer, ",\"timeout_loss\":");
    writer_counter(&writer, &record->timeout_loss);
    writer_append(&writer, ",\"rerolls\":");
    writer_counter(&writer, &record->rerolls);
    writer_append(&writer, ",\"event_drops\":%" PRIu64,
                  json_integer(record->event_drops));
    if (record->schema_version == EVENT_LOG_SCHEMA_VERSION_V2) {
        writer_append(&writer, ",\"channel_handle\":");
        if (record->scope == EVENT_LOG_SCOPE_CHANNEL)
            writer_append(&writer, "%" PRIu32, record->channel_handle);
        else
            writer_append(&writer, "null");
        writer_append(&writer, ",\"channel_kind\":");
        if (record->scope == EVENT_LOG_SCOPE_CHANNEL)
            writer_append(&writer, "\"%s\"",
                          channel_kind_names[record->channel_kind]);
        else
            writer_append(&writer, "null");
        writer_append(&writer, ",\"channel_code\":");
        if (record->scope == EVENT_LOG_SCOPE_CHANNEL)
            writer_append(&writer, "%" PRIu32, record->channel_code);
        else
            writer_append(&writer, "null");
    }
    writer_append(&writer, "}\n");
    if (writer.failed || writer.length == 0U ||
        writer.length > EVENT_LOG_LINE_MAX ||
        writer.bytes[writer.length - 1U] != '\n') {
        if (out_capacity != 0U)
            out[0] = '\0';
        return -1;
    }
    *length_out = writer.length;
    return 0;
}

void event_log_sink_init(event_log_sink_t *sink)
{
    if (sink == NULL)
        return;
    memset(sink, 0, sizeof(*sink));
    sink->fd = -1;
}

int event_log_sink_arm(event_log_sink_t *sink, int fd)
{
    struct stat status;
    long atomic_bound = 0;
    int flags;

    if (sink == NULL || fd < 0 || sink->armed || sink->fd != -1)
        return -1;
    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fstat(fd, &status) != 0)
        return -1;
    if (S_ISFIFO(status.st_mode)) {
        errno = 0;
        atomic_bound = fpathconf(fd, _PC_PIPE_BUF);
        if (atomic_bound <= 0)
            return -1;
    }
    if ((flags & O_NONBLOCK) == 0 &&
        fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0)
        return -1;
    sink->fd = fd;
    sink->saved_flags = flags;
    sink->pipe_atomic_bound = atomic_bound > 0
        ? (size_t)atomic_bound : 0U;
    sink->flags_changed = (flags & O_NONBLOCK) == 0;
    sink->armed = 1U;
    return 0;
}

int event_log_sink_restore(event_log_sink_t *sink)
{
    if (sink == NULL || !sink->armed || sink->fd < 0)
        return -1;
    if (sink->flags_changed &&
        fcntl(sink->fd, F_SETFL, sink->saved_flags) != 0)
        return -1;
    sink->armed = 0U;
    sink->flags_changed = 0U;
    sink->fd = -1;
    sink->pipe_atomic_bound = 0U;
    return 0;
}

static int sink_claim_attempt(event_log_sink_t *sink,
                              const event_log_record_t *record)
{
    event_log_event_t event = record->event;
    event_log_schema_version_t schema_version = record->schema_version;
    unsigned int ordinary_max;
    unsigned int attempt_max;

    if (schema_version != EVENT_LOG_SCHEMA_VERSION_V1 &&
        schema_version != EVENT_LOG_SCHEMA_VERSION_V2)
        return 0;
    if (sink->schema_version == 0)
        sink->schema_version = schema_version;
    else if (sink->schema_version != schema_version)
        return 0;
    ordinary_max = schema_version == EVENT_LOG_SCHEMA_VERSION_V1
        ? EVENT_LOG_V1_ORDINARY_ATTEMPT_MAX
        : EVENT_LOG_V2_ORDINARY_ATTEMPT_MAX;
    attempt_max = schema_version == EVENT_LOG_SCHEMA_VERSION_V1
        ? EVENT_LOG_V1_ATTEMPT_MAX : EVENT_LOG_V2_ATTEMPT_MAX;
    /* V1 has no channel scope, so preserve its closed budget. Channel-session v2 adds
     * multiple channel CLOSE observations; those use the ordinary budget and
     * cannot consume the one attempt reserved for the final session CLOSE. */
    if (event == EVENT_LOG_EVENT_CLOSE &&
        (schema_version == EVENT_LOG_SCHEMA_VERSION_V1 ||
         record->scope == EVENT_LOG_SCOPE_SESSION)) {
        if (sink->close_attempted)
            return 0;
        sink->close_attempted = 1U;
    } else if (event == EVENT_LOG_EVENT_REFUSE ||
               event == EVENT_LOG_EVENT_STALLED) {
        if (sink->terminal_attempted)
            return 0;
        sink->terminal_attempted = 1U;
    } else {
        if ((unsigned int)sink->ordinary_attempts >= ordinary_max)
            return 0;
        sink->ordinary_attempts++;
    }
    if ((unsigned int)sink->attempts >= attempt_max)
        return 0;
    sink->attempts++;
    return 1;
}

event_log_emit_result_t event_log_sink_emit(
    event_log_sink_t *sink, const event_log_record_t *record)
{
    event_log_record_t observation;
    char line[EVENT_LOG_LINE_MAX];
    size_t length = 0U;
    ssize_t written;

    if (sink == NULL || record == NULL || !sink->armed || sink->fd < 0)
        return EVENT_LOG_EMIT_ERROR;
    if (record->event < 0 || record->event >= EVENT_LOG_EVENT_COUNT ||
        !sink_claim_attempt(sink, record)) {
        drops_increment(sink);
        return EVENT_LOG_EMIT_DROPPED;
    }
    observation = *record;
    observation.event_drops = sink->drops;
    if (event_log_encode(&observation, line, sizeof(line), &length) != 0 ||
        length > sizeof(line) ||
        (sink->pipe_atomic_bound != 0U &&
         length > sink->pipe_atomic_bound)) {
        drops_increment(sink);
        return EVENT_LOG_EMIT_DROPPED;
    }
    written = write(sink->fd, line, length);
    if (written < 0 || (size_t)written != length) {
        drops_increment(sink);
        return EVENT_LOG_EMIT_DROPPED;
    }
    return EVENT_LOG_EMIT_WRITTEN;
}

void event_log_sink_note_suppressed(event_log_sink_t *sink)
{
    if (sink != NULL)
        drops_increment(sink);
}

uint64_t event_log_sink_drop_count(const event_log_sink_t *sink)
{
    return sink != NULL ? sink->drops : 0U;
}

unsigned int event_log_sink_attempt_count(const event_log_sink_t *sink)
{
    return sink != NULL ? (unsigned int)sink->attempts : 0U;
}
