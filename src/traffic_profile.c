/*
 * traffic_profile.c — pure traffic-profile and flow-stagger policy
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */

#include "traffic_profile.h"

#include <limits.h>
#include <stddef.h>
#include <string.h>

static int profile_valid(traffic_profile_t profile)
{
    return profile == TRAFFIC_PROFILE_ENTERPRISE ||
           profile == TRAFFIC_PROFILE_LAB;
}

static int application_valid(traffic_application_t application)
{
    return application == TRAFFIC_APPLICATION_TERMINAL ||
           application == TRAFFIC_APPLICATION_BULK;
}

static int option_valid(traffic_multipath_option_t option)
{
    return option == TRAFFIC_MULTIPATH_OPTION_NONE ||
           option == TRAFFIC_MULTIPATH_OPTION_BARE ||
           option == TRAFFIC_MULTIPATH_OPTION_EXACT;
}

static int path_count_valid(uint8_t count)
{
    return count == 1U ||
           (count >= 2U && count <= 32U &&
            (count & (uint8_t)(count - 1U)) == 0U);
}

static uint32_t path_mask(uint8_t count)
{
    if (count == 32U)
        return UINT32_MAX;
    return (UINT32_C(1) << count) - UINT32_C(1);
}

static int deadline_after(int64_t now_ms, int64_t *deadline_out)
{
    if (now_ms < 0 || now_ms > INT64_MAX - TRAFFIC_STAGGER_INTERVAL_MS ||
        deadline_out == NULL)
        return -1;
    *deadline_out = now_ms + TRAFFIC_STAGGER_INTERVAL_MS;
    return 0;
}

int traffic_profile_parse(const char *text, traffic_profile_t *profile_out)
{
    traffic_profile_t parsed;

    if (text == NULL || profile_out == NULL)
        return -1;
    if (strcmp(text, "enterprise") == 0)
        parsed = TRAFFIC_PROFILE_ENTERPRISE;
    else if (strcmp(text, "lab") == 0)
        parsed = TRAFFIC_PROFILE_LAB;
    else
        return -1;
    *profile_out = parsed;
    return 0;
}

const char *traffic_profile_name(traffic_profile_t profile)
{
    if (profile == TRAFFIC_PROFILE_ENTERPRISE)
        return "enterprise";
    if (profile == TRAFFIC_PROFILE_LAB)
        return "lab";
    return NULL;
}

int traffic_profile_resolve(traffic_profile_t profile,
                            traffic_application_t application,
                            int is_udp,
                            traffic_multipath_option_t option,
                            uint8_t exact_paths,
                            traffic_profile_result_t *result_out)
{
    traffic_profile_result_t result;
    uint8_t profile_count;

    if (!profile_valid(profile) || !application_valid(application) ||
        (is_udp != 0 && is_udp != 1) || !option_valid(option) ||
        result_out == NULL)
        return -1;
    if ((option == TRAFFIC_MULTIPATH_OPTION_EXACT) !=
        (exact_paths != 0U))
        return -1;

    result.configured_paths = 1U;
    result.multipath_mode = (uint8_t)TRAFFIC_MULTIPATH_MODE_NONE;
    if (!is_udp) {
        if (option != TRAFFIC_MULTIPATH_OPTION_NONE)
            return -1;
        *result_out = result;
        return 0;
    }

    profile_count = application == TRAFFIC_APPLICATION_BULK ? 4U : 2U;
    if (profile == TRAFFIC_PROFILE_ENTERPRISE) {
        if (option == TRAFFIC_MULTIPATH_OPTION_EXACT &&
            exact_paths != profile_count)
            return -1;
        result.configured_paths = profile_count;
        result.multipath_mode = option == TRAFFIC_MULTIPATH_OPTION_NONE
            ? (uint8_t)TRAFFIC_MULTIPATH_MODE_OPTIONAL
            : (uint8_t)TRAFFIC_MULTIPATH_MODE_REQUIRED;
        *result_out = result;
        return 0;
    }

    if (option == TRAFFIC_MULTIPATH_OPTION_NONE) {
        *result_out = result;
        return 0;
    }
    if (option == TRAFFIC_MULTIPATH_OPTION_BARE) {
        result.configured_paths = 8U;
    } else {
        if (!path_count_valid(exact_paths) || exact_paths == 1U)
            return -1;
        result.configured_paths = exact_paths;
    }
    result.multipath_mode = (uint8_t)TRAFFIC_MULTIPATH_MODE_REQUIRED;
    *result_out = result;
    return 0;
}

int traffic_profile_inherit_option(
    traffic_profile_t profile,
    traffic_application_t source_application,
    traffic_application_t target_application,
    int is_udp,
    traffic_multipath_option_t option,
    uint8_t source_exact_paths,
    uint8_t *target_exact_paths_out,
    traffic_profile_result_t *result_out)
{
    traffic_profile_result_t source;
    traffic_profile_result_t target;
    traffic_profile_result_t target_default;
    uint8_t target_exact = source_exact_paths;

    if (target_exact_paths_out == NULL || result_out == NULL ||
        traffic_profile_resolve(profile, source_application, is_udp,
                                option, source_exact_paths, &source) != 0)
        return -1;
    if (profile == TRAFFIC_PROFILE_ENTERPRISE &&
        option == TRAFFIC_MULTIPATH_OPTION_EXACT) {
        if (traffic_profile_resolve(
                profile, target_application, is_udp,
                TRAFFIC_MULTIPATH_OPTION_NONE, 0U, &target_default) != 0)
            return -1;
        target_exact = target_default.configured_paths;
    }
    if (traffic_profile_resolve(profile, target_application, is_udp,
                                option, target_exact, &target) != 0)
        return -1;
    *target_exact_paths_out = target_exact;
    *result_out = target;
    return 0;
}

int traffic_stagger_init(traffic_stagger_t *stagger,
                         traffic_profile_t profile,
                         traffic_endpoint_t endpoint,
                         uint8_t selected_paths,
                         int64_t activation_ms)
{
    traffic_stagger_t next;

    if (stagger == NULL || !profile_valid(profile) ||
        (endpoint != TRAFFIC_ENDPOINT_CLIENT &&
         endpoint != TRAFFIC_ENDPOINT_LISTENER) ||
        !path_count_valid(selected_paths) || activation_ms < 0)
        return -1;

    memset(&next, 0, sizeof(next));
    next.path_count = selected_paths;
    next.pending_leg = TRAFFIC_STAGGER_NO_LEG;
    next.next_admission_ms = -1;
    next.last_observed_ms = activation_ms;
    next.staggered = (uint8_t)
        (profile == TRAFFIC_PROFILE_ENTERPRISE &&
         endpoint == TRAFFIC_ENDPOINT_CLIENT && selected_paths > 1U);
    if (!next.staggered) {
        next.admitted_mask = path_mask(selected_paths);
        next.admitted_count = selected_paths;
    } else {
        if (deadline_after(activation_ms, &next.next_admission_ms) != 0)
            return -1;
        next.admitted_mask = UINT32_C(1);
        next.admitted_count = 1U;
    }
    *stagger = next;
    return 0;
}

int traffic_stagger_allow_leg(traffic_stagger_t *stagger, uint8_t leg,
                              int64_t now_ms)
{
    uint32_t bit;

    if (stagger == NULL || !path_count_valid(stagger->path_count) ||
        leg >= stagger->path_count || now_ms < 0)
        return -1;
    if (now_ms < stagger->last_observed_ms)
        now_ms = stagger->last_observed_ms;
    else
        stagger->last_observed_ms = now_ms;
    bit = UINT32_C(1) << leg;
    if ((stagger->admitted_mask & bit) != 0U)
        return 1;
    if (!stagger->staggered || stagger->pending_leg != TRAFFIC_STAGGER_NO_LEG ||
        stagger->next_admission_ms < 0 ||
        now_ms < stagger->next_admission_ms ||
        leg != stagger->admitted_count)
        return 0;

    stagger->admitted_mask |= bit;
    stagger->pending_leg = leg;
    stagger->admitted_count = (uint8_t)(stagger->admitted_count + 1U);
    stagger->next_admission_ms = -1;
    return 1;
}

int traffic_stagger_note_physical_attempt(traffic_stagger_t *stagger,
                                          uint8_t leg,
                                          int64_t observed_now_ms)
{
    uint32_t bit;
    int64_t normalized_now;
    int64_t next_deadline = -1;

    if (stagger == NULL || !path_count_valid(stagger->path_count) ||
        leg >= stagger->path_count || observed_now_ms < 0)
        return -1;
    bit = UINT32_C(1) << leg;
    if ((stagger->admitted_mask & bit) == 0U)
        return -1;
    if ((stagger->attempted_mask & bit) != 0U)
        return 0;

    normalized_now = observed_now_ms < stagger->last_observed_ms
        ? stagger->last_observed_ms : observed_now_ms;
    if (stagger->staggered && leg == stagger->pending_leg &&
        stagger->admitted_count < stagger->path_count &&
        deadline_after(normalized_now, &next_deadline) != 0)
        return -1;

    stagger->last_observed_ms = normalized_now;
    stagger->attempted_mask |= bit;
    if (stagger->staggered && leg == stagger->pending_leg) {
        stagger->pending_leg = TRAFFIC_STAGGER_NO_LEG;
        stagger->next_admission_ms = next_deadline;
    }
    return 1;
}

int64_t traffic_stagger_next_wait(const traffic_stagger_t *stagger,
                                  int64_t now_ms)
{
    int64_t normalized_now;

    if (stagger == NULL || !path_count_valid(stagger->path_count) ||
        now_ms < 0 || !stagger->staggered ||
        stagger->pending_leg != TRAFFIC_STAGGER_NO_LEG ||
        stagger->next_admission_ms < 0)
        return -1;
    normalized_now = now_ms < stagger->last_observed_ms
        ? stagger->last_observed_ms : now_ms;
    if (normalized_now >= stagger->next_admission_ms)
        return 0;
    return stagger->next_admission_ms - normalized_now;
}
