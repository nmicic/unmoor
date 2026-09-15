/*
 * deaddrop_runtime.h — epoch-rekey process and SSH bootstrap integration
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * This boundary deliberately accepts and emits only public bootstrap
 * records.  Bootstrap roots are created inside the endpoint C processes and
 * handed directly to the session runner; they never have a string form.
 */
#ifndef UNMOOR_DEADDROP_RUNTIME_H
#define UNMOOR_DEADDROP_RUNTIME_H

#include <stdint.h>

#include "deaddrop_exchange.h"
#include "event_log.h"
#include "pq_policy.h"
#include "traffic_profile.h"
#include "transport.h"

typedef int (*d28_endpoint_armed_fn)(void *arg);
struct d28_monitor_endpoint;

/* Public command policy only. It intentionally retains NONE/BARE/EXACT so
 * SSH propagation cannot turn an optional enterprise offer into a required
 * count. Each endpoint resolves this once for its application before I/O. */
typedef struct d28_endpoint_policy {
    traffic_profile_t traffic_profile;
    traffic_multipath_option_t multipath_option;
    uint8_t exact_paths; /* nonzero exactly for MULTIPATH_OPTION_EXACT */
    event_log_format_t log_format;
    uint8_t channelised; /* explicit channel-session terminal bundle; never inferred */
    uint8_t pq_hybrid;   /* exact pq-hybrid carrier selection; runtime-owned */
} d28_endpoint_policy_t;

/* The runner owns `transport` once called.  It must copy `root` into its
 * protected session allocation and wipe the caller buffer before it can
 * block.  A listener invokes `armed` after session_listen() succeeds and
 * before session_run(); a client receives NULL. */
typedef int (*d28_endpoint_runner_fn)(
    transport_t *transport,
    uint8_t root[32],
    const uint8_t pair_seed[4],
    int is_listener,
    d28_application_profile_t application_profile,
    void *runner_context,
    const d28_endpoint_policy_t *policy,
    struct d28_monitor_endpoint *monitor_endpoint,
    int64_t absolute_deadline_ms,
    d28_endpoint_armed_fn armed,
    void *armed_arg);

typedef struct d28_ssh_connect_config {
    d28_application_profile_t application_profile;
    void *runner_context;
    const char *udp_host;
    const char *remote_bind_host;
    const char *remote_command;
    int timeout_secs;
    int remote_foreground;
    /* Explicit first-slice request for the remote listener process boundary.
     * Omission preserves the historical public remote command. */
    uint8_t listener_monitor;
    pq_policy_t pq_policy;
    /* Internal child-transfer inheritance: selected by an authenticated control
     * session, never inferred from an attach request. */
    uint8_t pq_carrier_required;
    d28_endpoint_policy_t policy;
    uint8_t udp_port_layout;
    uint8_t udp_port_mask_explicit;
    uint16_t udp_port_mask;
    uint16_t bulk_wire_budget;
    int bulk_stall_secs;
    /* server-confinement: explicit policy for the remote one-shot bulk server. NULL keeps
     * the historical command byte-for-byte; otherwise this is one validated
     * off|best-effort|require word carried only as public argv. */
    const char *remote_confine_level;
    /* child-transfer: when non-NULL, carry the unchanged public epoch-rekey exchange through
     * one local channel-session EXEC attach instead of SSH. `local_command` is the
     * current unmoor executable; the remote command remains exact argv.
     * `local_confine_level` is the already-resolved parent policy for this
     * second local client process and never enters the remote command. */
    const char *attach_socket_path;
    const char *local_command;
    const char *local_confine_level;
    int ssh_argc;
    char **ssh_argv;
} d28_ssh_connect_config_t;

typedef struct d28_listener_config {
    d28_application_profile_t application_profile;
    void *runner_context;
    const char *udp_port;
    const char *udp_bind_host;
    const char *deaddrop_parent;
    const char *log_path;
    int timeout_secs;
    int foreground;
    int debuggable;
    uint8_t listener_monitor;
    /* Suppress successful parent-side bootstrap prose while an EXEC channel
     * merges stderr into the exact public-record stream. Failures stay loud. */
    int quiet_success;
    /* server-confinement: the one-shot bulk child has an explicit late path policy. The
     * parent prepares exact deaddrop cleanup scope before the fork. */
    uint8_t server_confine;
    /* Exact internal marker supplied by a positively probed SSH initiator or
     * an authenticated child-transfer parent. Absence preserves v1 byte-for-byte. */
    uint8_t pq_carrier_required;
    d28_endpoint_policy_t policy;
} d28_listener_config_t;

int d28_runtime_ssh_connect(const d28_ssh_connect_config_t *config,
                            d28_endpoint_runner_fn runner);

int d28_runtime_listen(const d28_listener_config_t *config,
                       d28_endpoint_runner_fn runner);

#endif /* UNMOOR_DEADDROP_RUNTIME_H */
