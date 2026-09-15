/*
 * pq_policy.h — pq-hybrid policy and exact SSH feature-probe classification
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef UNMOOR_PQ_POLICY_H
#define UNMOOR_PQ_POLICY_H

#include <stddef.h>
#include <stdint.h>

#define PQ_HYBRID_SUITE_NAME \
    "pq-hybrid-x25519-mlkem1024-xchacha20-blake2b-v1"
#define PQ_PROBE_SUPPORTED_TEXT "UNMOOR PQ-HYBRID v1\n"
#define PQ_PROBE_LEGACY_TEXT "unmoor 0.1.0 (protocol v1)\n"
#define PQ_PREFER_FALLBACK_NOTICE \
    "unmoor: peer lacks " PQ_HYBRID_SUITE_NAME \
    "; continuing with v1 (--pq=prefer)\n"
#define PQ_REQUIRE_REFUSAL_NOTICE \
    "unmoor: PQ required but peer lacks " PQ_HYBRID_SUITE_NAME \
    " (default --pq=require; use --pq=prefer for one visible v1 fallback " \
    "or --pq=off for legacy)\n"

typedef enum pq_policy {
    PQ_POLICY_OFF = 0,
    PQ_POLICY_PREFER = 1,
    PQ_POLICY_REQUIRE = 2
} pq_policy_t;

typedef enum pq_probe_result {
    PQ_PROBE_ERROR = -1,
    PQ_PROBE_LEGACY = 0,
    PQ_PROBE_SUPPORTED = 1
} pq_probe_result_t;

int pq_policy_parse(const char *text, pq_policy_t *out);
const char *pq_policy_name(pq_policy_t policy);
int pq_policy_valid(pq_policy_t policy);

/* A probe is positive only for one exact stdout tuple and ordinary exit
 * zero. All other stdout/process shapes are errors. The probe's stderr is
 * not an input: the initiator leaves it inherited, so an sshd banner or any
 * OpenSSH diagnostic stays visible to the operator and never decides. */
pq_probe_result_t pq_probe_classify(const uint8_t *stdout_bytes,
                                    size_t stdout_len,
                                    int exited, int exit_code);

#endif /* UNMOOR_PQ_POLICY_H */
