/*
 * process_hygiene.h — process-boundary hygiene shared by every exec site
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef UNMOOR_PROCESS_HYGIENE_H
#define UNMOOR_PROCESS_HYGIENE_H

#include <stddef.h>

/* The long-lived Unmoor process handles a closed stream as an I/O error. */
int process_ignore_sigpipe(void);

/* An exec child must not inherit Unmoor's signal policy or blocked mask. */
void process_reset_child_signals(void);

/* Close every descriptor at or above lowfd except the explicit allowlist. */
int process_close_from(int lowfd, const int keep[], size_t keep_count);

/* Resolve the running image once; bare_fallback reports PATH-sensitive argv. */
int process_resolve_self_path(const char *argv0, char *path,
                              size_t path_size, int *bare_fallback);

/* Disable process dumps/attach unless this invocation is explicitly opted out. */
int process_harden(int debuggable);

/* Apply the policy after CLI parsing and emit the command's sole diagnostic. */
int process_harden_command(const char *command, int debuggable);

#endif /* UNMOOR_PROCESS_HYGIENE_H */
