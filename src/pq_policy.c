/*
 * pq_policy.c — pq-hybrid policy and exact SSH feature-probe classification
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#include "pq_policy.h"

#include <string.h>

int pq_policy_parse(const char *text, pq_policy_t *out)
{
    pq_policy_t parsed;

    if (!text || !out)
        return -1;
    if (strcmp(text, "off") == 0)
        parsed = PQ_POLICY_OFF;
    else if (strcmp(text, "prefer") == 0)
        parsed = PQ_POLICY_PREFER;
    else if (strcmp(text, "require") == 0)
        parsed = PQ_POLICY_REQUIRE;
    else
        return -1;
    *out = parsed;
    return 0;
}

const char *pq_policy_name(pq_policy_t policy)
{
    switch (policy) {
    case PQ_POLICY_OFF:
        return "off";
    case PQ_POLICY_PREFER:
        return "prefer";
    case PQ_POLICY_REQUIRE:
        return "require";
    default:
        return NULL;
    }
}

int pq_policy_valid(pq_policy_t policy)
{
    return pq_policy_name(policy) != NULL;
}

pq_probe_result_t pq_probe_classify(const uint8_t *stdout_bytes,
                                    size_t stdout_len,
                                    const uint8_t *stderr_bytes,
                                    size_t stderr_len,
                                    int exited, int exit_code)
{
    static const uint8_t supported[] = PQ_PROBE_SUPPORTED_TEXT;
    static const uint8_t legacy[] = PQ_PROBE_LEGACY_TEXT;

    if ((stdout_len != 0U && !stdout_bytes) ||
        (stderr_len != 0U && !stderr_bytes) || stderr_len != 0U ||
        exited != 1 || exit_code != 0)
        return PQ_PROBE_ERROR;
    if (stdout_len == sizeof(supported) - 1U &&
        memcmp(stdout_bytes, supported, sizeof(supported) - 1U) == 0)
        return PQ_PROBE_SUPPORTED;
    if (stdout_len == sizeof(legacy) - 1U &&
        memcmp(stdout_bytes, legacy, sizeof(legacy) - 1U) == 0)
        return PQ_PROBE_LEGACY;
    return PQ_PROBE_ERROR;
}
