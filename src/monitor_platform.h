/*
 * monitor_platform.h — listener-monitor pre-birth native prerequisites, not a sandbox
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef UNMOOR_MONITOR_PLATFORM_H
#define UNMOOR_MONITOR_PLATFORM_H

#include <sys/types.h>

/* Internal trusted-startup calls: 0 success, -1 with errno on failure.
 * No caller may continue W/private startup after failure. No function forks,
 * waits, signals another PID, prints, or establishes a final kernel role.
 * No function is called by the ordinary product path in this preparation. */

/* Fresh single-threaded never-secret C only, before maps/work fds or W.
 * Replace stdin/out/err with non-CLOEXEC /dev/null, then close ALL fds >=3.
 * No keep-list, rlimit scan or fallback after unavailable/incomplete closure.
 * Failure may have closed/replaced fds; no atomic rollback is promised. */
int monitor_birth_fds(void);

/* Fresh exclusive connected AF_UNIX/SOCK_STREAM only. The caller retains
 * its exact unreaped child, or verifies its current parent; endpoints have
 * never been shared/transferred/forked/exec'd. PID supplied by owned process
 * creation, not a protocol/log field. This helper proves no such provenance.
 * fd<0, pid<=0 or uid==(uid_t)-1 is EINVAL, before any native query.
 * Wrong family/type is EINVAL; actual unconnected errors are retained.
 * Native size/shape error is EPROTO; identity mismatch is EPERM; unavailable
 * queries/platform are ENOTSUP; other syscall failures retain their errno. */
int monitor_peer_matches(int fd, pid_t expected_pid, uid_t expected_uid);

/* Fresh W/M before untrusted work/private generation. Linux installs
 * PDEATHSIG(SIGKILL), immediately checks getppid, and reads the signal back.
 * Parent must remain its single creator thread. Later seals must prevent
 * clearing, credential/exec changes and child/thread creation separately.
 * expected<=0 is EINVAL before mutation; changed parent is ESRCH; malformed
 * readback is EPROTO; non-Linux is ENOTSUP. Valid-input failure may have
 * installed the guard; exit rather than resume. No exact-reap/wipe claim. */
int monitor_parent_guard(pid_t expected_parent);

#endif
