/*
 * monitor_child_pidfd.h — standalone exact-owned-child reference preparation
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef UNMOOR_MONITOR_CHILD_PIDFD_H
#define UNMOOR_MONITOR_CHILD_PIDFD_H

#include <sys/types.h>

/* Trusted, single-threaded caller only: its own positive fork result remains
 * unreaped from birth through acquisition. No handler or competing waiter
 * may reap/change that ownership; no tracing or reparenting is permitted.
 * Queries cannot prove this history.
 * Requires SIGCHLD=SIG_DFL and !SA_NOCLDWAIT without changing either, then
 * observes exact child status nonconsumingly before pidfd_open(child,0).
 * Success transfers one CLOEXEC descriptor. Failure creates no descriptor.
 * No fork, close, reap, signal, heap, retry or post-open failable operation.
 */
int monitor_child_pidfd_open(pid_t owned_child);

/* Borrow only the caller's stable pidfd. Exact process, signum1..63, NULL
 * info and flags0; no numeric-PID/group/proc fallback, close or retry. Result
 * is syscall acceptance/error, not evidence the target acted on the signal.
 */
int monitor_child_pidfd_signal(int borrowed_pidfd, int signum);

/* Errors: invalid scalar=EINVAL; unavailable platform/compile or ENOSYS=
 * ENOTSUP; SIGCHLD predicate=EPERM; malformed populated wait result=EPROTO;
 * all other native errors retained. Valid inputs on unsupported builds
 * refuse. Linux LP64 x86_64/aarch64 only; sanitizers remain usable here.
 * No caller currently uses these helpers in the product; they are neither
 * a kernel role nor constructor/custodian/runtime/FIN policy.
 */
#endif
