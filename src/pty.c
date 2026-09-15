/*
 * pty.c — forkpty(3)-based PTY spawn / resize / close
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */

#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE   700
#define _DEFAULT_SOURCE 1
#define _GNU_SOURCE     1
#ifdef __APPLE__
/* macOS hides SIGWINCH/SIGTSTP/forkpty behind _DARWIN_C_SOURCE when
 * _POSIX_C_SOURCE is defined. */
#define _DARWIN_C_SOURCE 1
#endif

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include "pty.h"
#include "process_hygiene.h"

/* NOTE: do NOT #include <pty.h> — with -Isrc the search would resolve to
 * our own src/pty.h. Declare forkpty(3) manually here; linked from -lutil. */
extern int forkpty(int *amaster, char *name,
                   const struct termios *termp, const struct winsize *winp);

/* -------------------------------------------------------------------------
 * pty_spawn
 * ---------------------------------------------------------------------- */

int pty_spawn(const char *shell,
              uint16_t rows, uint16_t cols,
              int *master_fd_out, pid_t *child_pid_out)
{
    if (!master_fd_out || !child_pid_out) {
        errno = EINVAL;
        return -1;
    }

    /* Determine shell: arg → $SHELL → /bin/zsh → /bin/bash */
    const char *shell_path = shell;
    if (!shell_path || !shell_path[0]) shell_path = getenv("SHELL");
    if (!shell_path || !shell_path[0]) {
        if (access("/bin/zsh", X_OK) == 0)       shell_path = "/bin/zsh";
        else if (access("/bin/bash", X_OK) == 0) shell_path = "/bin/bash";
        else                                     shell_path = "/bin/sh";
    }

    struct winsize ws;
    memset(&ws, 0, sizeof(ws));
    ws.ws_row = rows ? rows : 24;
    ws.ws_col = cols ? cols : 80;

    int master = -1;
    pid_t pid = forkpty(&master, NULL, NULL, &ws);
    if (pid < 0) {
        int cause = errno;
        fprintf(stderr, "pty_spawn: forkpty: %s\n", strerror(cause));
        errno = cause;
        return -1;
    }

    if (pid == 0) {
        /* Child */
        /* forkpty inherited the parent's handlers and blocked mask. */
        process_reset_child_signals();

        if (process_close_from(STDERR_FILENO + 1, NULL, 0U) != 0)
            _exit(127);

        setenv("TERM", "xterm-256color", 1);
        /* advertise that this shell runs inside an unmoor PTY session, so
         * PS1 / prompt scripts can detect unmoor context without inspecting
         * PPID. Not security-sensitive: this only sets a benign flag, and
         * any code that runs inside the session can already see PPID. */
        setenv("UNMOOR_SESSION", "1", 1);
        /* Start a fresh login-ish shell */
        execl(shell_path, shell_path, (char *)NULL);
        /* If exec fails, die with a message on the slave fd */
        fprintf(stderr, "pty_spawn: execl(%s): %s\n", shell_path, strerror(errno));
        _exit(127);
    }

    /* Parent: set master non-blocking so session poll loop doesn't stall. */
    int flags = fcntl(master, F_GETFL, 0);
    if (flags >= 0) {
        (void)fcntl(master, F_SETFL, flags | O_NONBLOCK);
    }
    /* FD_CLOEXEC on PTY master so future forks don't leak it. */
    (void)fcntl(master, F_SETFD, FD_CLOEXEC);

    *master_fd_out = master;
    *child_pid_out = pid;
    return 0;
}

/* -------------------------------------------------------------------------
 * pty_resize
 * ---------------------------------------------------------------------- */

int pty_resize(int master_fd, uint16_t rows, uint16_t cols)
{
    struct winsize ws;
    memset(&ws, 0, sizeof(ws));
    ws.ws_row = rows;
    ws.ws_col = cols;
    if (ioctl(master_fd, TIOCSWINSZ, &ws) != 0) {
        fprintf(stderr, "pty_resize: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * pty_close
 * ---------------------------------------------------------------------- */

int pty_close(int master_fd, pid_t child_pid)
{
    int exit_code = -1;

    if (master_fd >= 0) close(master_fd);

    if (child_pid <= 0) return exit_code;

    int status = 0;
    /* After close(master) the kernel delivers SIGHUP to the session
     * leader; poll waitpid up to 500ms before resorting to SIGTERM. */
    for (int i = 0; i < 50; i++) {
        pid_t r = waitpid(child_pid, &status, WNOHANG);
        if (r == child_pid) {
            if (WIFEXITED(status))        exit_code = WEXITSTATUS(status);
            else if (WIFSIGNALED(status)) exit_code = 128 + WTERMSIG(status);
            return exit_code;
        }
        if (r < 0 && errno != EINTR) return exit_code;
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 10 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }

    /* Natural SIGHUP didn't land — nudge with SIGTERM, wait another 200ms. */
    kill(child_pid, SIGTERM);
    for (int i = 0; i < 20; i++) {
        pid_t r = waitpid(child_pid, &status, WNOHANG);
        if (r == child_pid) {
            if (WIFEXITED(status))        exit_code = WEXITSTATUS(status);
            else if (WIFSIGNALED(status)) exit_code = 128 + WTERMSIG(status);
            return exit_code;
        }
        if (r < 0 && errno != EINTR) return exit_code;
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 10 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }

    /* Force-kill */
    kill(child_pid, SIGKILL);
    if (waitpid(child_pid, &status, 0) == child_pid) {
        if (WIFEXITED(status))        exit_code = WEXITSTATUS(status);
        else if (WIFSIGNALED(status)) exit_code = 128 + WTERMSIG(status);
    }
    return exit_code;
}
