/*
 * traffic_profile.h — pure traffic-profile and flow-stagger policy
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef UNMOOR_TRAFFIC_PROFILE_H
#define UNMOOR_TRAFFIC_PROFILE_H

#include <stdint.h>

#define TRAFFIC_STAGGER_INTERVAL_MS INT64_C(5000)
#define TRAFFIC_STAGGER_NO_LEG UINT8_MAX

typedef enum {
    TRAFFIC_PROFILE_ENTERPRISE = 0,
    TRAFFIC_PROFILE_LAB = 1
} traffic_profile_t;

typedef enum {
    TRAFFIC_APPLICATION_TERMINAL = 0,
    TRAFFIC_APPLICATION_BULK = 1
} traffic_application_t;

typedef enum {
    TRAFFIC_MULTIPATH_OPTION_NONE = 0,
    TRAFFIC_MULTIPATH_OPTION_BARE = 1,
    TRAFFIC_MULTIPATH_OPTION_EXACT = 2
} traffic_multipath_option_t;

typedef enum {
    TRAFFIC_MULTIPATH_MODE_NONE = 0,
    TRAFFIC_MULTIPATH_MODE_OPTIONAL = 1,
    TRAFFIC_MULTIPATH_MODE_REQUIRED = 2
} traffic_multipath_mode_t;

typedef enum {
    TRAFFIC_ENDPOINT_CLIENT = 0,
    TRAFFIC_ENDPOINT_LISTENER = 1
} traffic_endpoint_t;

typedef struct {
    uint8_t configured_paths;
    uint8_t multipath_mode; /* traffic_multipath_mode_t */
} traffic_profile_result_t;

/* Exact, case-sensitive public profile spelling. The output is written only
 * on success. Invalid enum values have no name. */
int traffic_profile_parse(const char *text, traffic_profile_t *profile_out);
const char *traffic_profile_name(traffic_profile_t profile);

/* Resolve traffic-profile's local allocation and capability-negotiation offer/require intent. `is_udp` is
 * exactly zero or one. `exact_paths` must be zero unless option is EXACT.
 * Duplicate/conflicting CLI occurrences remain the caller's responsibility.
 * The output is written only on success. */
int traffic_profile_resolve(traffic_profile_t profile,
                            traffic_application_t application,
                            int is_udp,
                            traffic_multipath_option_t option,
                            uint8_t exact_paths,
                            traffic_profile_result_t *result_out);

/* Reapply an already validated option form to a different application.
 * Enterprise EXACT values are application-specific (terminal two, bulk four);
 * lab EXACT values remain literal. Outputs are written only on success. */
int traffic_profile_inherit_option(
    traffic_profile_t profile,
    traffic_application_t source_application,
    traffic_application_t target_application,
    int is_udp,
    traffic_multipath_option_t option,
    uint8_t source_exact_paths,
    uint8_t *target_exact_paths_out,
    traffic_profile_result_t *result_out);

/* Pure injected-clock admission state. Initialisation happens once at multipath
 * service activation, never on rekey. Enterprise clients admit only leg zero
 * immediately; lab endpoints and listeners admit every selected leg. */
typedef struct {
    uint32_t admitted_mask;
    uint32_t attempted_mask;
    int64_t next_admission_ms;
    int64_t last_observed_ms;
    uint8_t path_count;
    uint8_t admitted_count;
    uint8_t pending_leg;
    uint8_t staggered;
} traffic_stagger_t;

int traffic_stagger_init(traffic_stagger_t *stagger,
                         traffic_profile_t profile,
                         traffic_endpoint_t endpoint,
                         uint8_t selected_paths,
                         int64_t activation_ms);

/* Return one when `leg` may make a physical transport attempt, zero while it
 * remains gated, and -1 for invalid input. At a due boundary this call admits
 * exactly the next numeric alternate and records it as admitted-but-unopened. */
int traffic_stagger_allow_leg(traffic_stagger_t *stagger, uint8_t leg,
                              int64_t now_ms);

/* Notify the first actual transport-send call for an admitted leg, regardless
 * of syscall result. Return one for the first observation, zero for a repeat,
 * and -1 for malformed or not-admitted input. Only this edge can arm the next
 * enterprise alternate deadline. */
int traffic_stagger_note_physical_attempt(traffic_stagger_t *stagger,
                                          uint8_t leg,
                                          int64_t observed_now_ms);

/* Milliseconds until another alternate may be admitted: zero means due and
 * -1 means no timer is armed (including while an admitted leg is unopened). */
int64_t traffic_stagger_next_wait(const traffic_stagger_t *stagger,
                                  int64_t now_ms);

#endif /* UNMOOR_TRAFFIC_PROFILE_H */
