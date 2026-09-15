/*
 * monitor_roles.h — listener-monitor native C/M kernel roles, unlinked preparation
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * Contract: the listener-monitor.  These helpers are not product admission
 * and must not be used as a generic sandbox wrapper.
 */
#ifndef UNMOOR_MONITOR_ROLES_H
#define UNMOOR_MONITOR_ROLES_H

#include <stdint.h>
#include <sys/types.h>

enum {
    MONITOR_ROLE_C_CHILDREN = 3,
    MONITOR_ROLE_C_ATTEMPT_FDS = 2
};

typedef struct monitor_custodian_role_config {
    int channel_fd;
    pid_t children[MONITOR_ROLE_C_CHILDREN];
    int attempt_fds[MONITOR_ROLE_C_ATTEMPT_FDS];
    uint8_t child_count;
    uint8_t attempt_count;
    uint8_t reserved[6];
} monitor_custodian_role_config_t;

#define MONITOR_CUSTODIAN_ROLE_CONFIG_EMPTY \
    { -1, { -1, -1, -1 }, { -1, -1 }, 0, 0, {0} }

/* Little-endian LP64 Linux x86_64/aarch64, non-instrumented builds only. */
int monitor_role_supported(void);

/* M: call after all fixed inherited descriptors exist and before any private
 * generation. c_channel_fd is the sole rights-capable local receive path. */
int monitor_role_install_m(int c_channel_fd);

/* C: call only after shell birth, OFFER/ACQUIRED and certain alias release,
 * immediately before COMMIT. The config is trusted constructor state, not an
 * IPC object. Failure after a valid call may have set NO_NEW_PRIVS. */
int monitor_role_install_c(const monitor_custodian_role_config_t *config);

#endif
