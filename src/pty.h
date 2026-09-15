/*
 * pty.h — PTY spawn / resize / close
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef UNMOOR_PTY_H
#define UNMOOR_PTY_H

#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <sys/types.h>

/*
 * Spawn `shell` (or $SHELL → /bin/zsh → /bin/bash) in a fresh PTY.
 * Child inherits the parent environment plus TERM=xterm-256color.
 * On success: *master_fd_out = PTY master fd, *child_pid_out = shell pid.
 * Returns 0 on success, -1 on failure (errno is meaningful).
 */
int pty_spawn(const char *shell,
              uint16_t rows, uint16_t cols,
              int *master_fd_out, pid_t *child_pid_out);

/* TIOCSWINSZ on the master fd. Returns 0/-1. */
int pty_resize(int master_fd, uint16_t rows, uint16_t cols);

/*
 * Close the master fd and reap the child with SIGTERM-then-SIGKILL.
 * Blocks up to ~200ms for graceful exit, then SIGKILLs.
 * Returns the child's exit code (or -1 if it could not be reaped).
 */
int pty_close(int master_fd, pid_t child_pid);

#endif /* UNMOOR_PTY_H */
