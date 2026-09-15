/*
 * main.c — unmoor subcommand dispatch
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * Subcommands:
 *   unmoor keygen
 *   unmoor listen  --transport udp [--port N] [--loop]
 *   unmoor listen  --bootstrap                       (one-shot, over ssh)
 *   unmoor listen  --deaddrop-bootstrap              (public DH over ssh)
 *   unmoor connect --transport udp --host H --port N
 *   unmoor ssh-connect --udp-host H -- [ssh args] TARGET
 *   unmoor push LOCAL [user@]HOST:REMOTE_PATH
 *   unmoor pull [user@]HOST:REMOTE_PATH LOCAL
 *   unmoor push/pull --bootstrap-exec-socket PATH ... (child-transfer internal)
 *   unmoor attach --socket PATH terminal
 *   unmoor attach --socket PATH exec -- ARGV...
 *   unmoor listen/connect --transport unix --socket PATH
 *   unmoor listen/connect --exec "cmd args"          (stdio transport)
 *
 * Key material is never read from disk. Both sides take the 32-byte PSK
 * from UNMOOR_KEY (64 hex chars), which is scrubbed out of the environment
 * as soon as it is parsed; `--bootstrap` generates an ephemeral one and
 * prints it once on stdout for an ssh channel to carry (mosh's model).
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1
#ifdef __APPLE__
/* macOS hides cfmakeraw + SIGWINCH behind _DARWIN_C_SOURCE when
 * _POSIX_C_SOURCE is defined. */
#define _DARWIN_C_SOURCE 1
#endif

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

#include "attach_client.h"
#include "channel.h"
#include "channel_bulk.h"
#include "channel_delivery.h"
#include "channel_pty.h"
#include "child_transfer.h"
#include "crypto.h"
#include "deaddrop_runtime.h"
#include "frame.h"
#include "confine.h"
#include "monitor_endpoint.h"
#include "process_hygiene.h"
#include "rss.h"
#include "rss_command.h"
#include "session.h"
#include "traffic_profile.h"
#include "transport.h"

/* -------------------------------------------------------------------------
 * Client raw-mode + signal forwarding
 * ---------------------------------------------------------------------- */

static struct termios g_saved_termios;
static int            g_termios_saved = 0;

/* the sync engine flushes display bytes to stdout nonblocking so a
 * stalled terminal (^S, a slow hop) can never freeze the event loop. stdout
 * usually shares its open file description with the invoking shell's tty, so
 * normal cleanup restores the original flags or fails loudly. Installed
 * fatal/fault handlers make a best-effort attempt; fcntl is async-signal-safe,
 * so wipe_keys_now may call it from a handler. */
static int g_stdout_flags_saved = 0;
static int g_stdout_saved_flags = 0;
/* Resolved running image used by child-transfer's local no-shell attach carrier. It is
 * public process metadata, never key material or a later PATH lookup. */
static char g_program_path_storage[4096];
static const char *g_program_path = "unmoor";

/* sync-status title output has a descriptor distinct from stdout/stderr and every
 * channel sink. Failure to open or write /dev/tty disables titles only. */
static int g_status_tty_fd = -1;
static int g_status_title_pushed = 0;

static int standard_streams_share_terminal(void)
{
    struct stat display;
    struct stat diagnostics;

    if (!isatty(STDOUT_FILENO) || !isatty(STDERR_FILENO) ||
        fstat(STDOUT_FILENO, &display) != 0 ||
        fstat(STDERR_FILENO, &diagnostics) != 0)
        return 0;
    return display.st_dev == diagnostics.st_dev &&
           display.st_ino == diagnostics.st_ino &&
           display.st_rdev == diagnostics.st_rdev;
}

static void status_tty_write(const char *bytes, size_t len)
{
    while (g_status_tty_fd >= 0 && len > 0) {
        ssize_t n = write(g_status_tty_fd, bytes, len);
        if (n > 0) {
            bytes += (size_t)n;
            len -= (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        break;
    }
}

static void status_title_open(void)
{
    int fd;

    if (g_status_tty_fd >= 0)
        return;
    fd = open("/dev/tty", O_WRONLY | O_NONBLOCK | O_CLOEXEC | O_NOCTTY);
    /* A closed standard descriptor is otherwise the lowest free number, so
     * open(2) may return 0, 1, or 2 and silently turn the UI path into stdin,
     * stdout, or stderr. Preserve the claimed descriptor separation even in
     * that process shape; inability to duplicate disables titles only. */
    if (fd >= 0 && fd <= STDERR_FILENO) {
        int moved = fcntl(fd, F_DUPFD_CLOEXEC, STDERR_FILENO + 1);
        (void)close(fd);
        fd = moved;
    }
    g_status_tty_fd = fd;
    g_status_title_pushed = 0;
}

static void status_title_close(void)
{
    static const char pop[] = "\033[23;0t";
    if (g_status_tty_fd < 0)
        return;
    if (g_status_title_pushed)
        status_tty_write(pop, sizeof(pop) - 1U);
    (void)close(g_status_tty_fd);
    g_status_tty_fd = -1;
    g_status_title_pushed = 0;
}

static void client_status_ui(session_t *s, const sync_status_view_t *view)
{
    static const char push[] = "\033[22;0t";
    char title[160];
    char osc[192];
    int n;

    (void)s;
    if (g_status_tty_fd < 0 ||
        sync_status_format_title(view, title, sizeof(title)) != 0)
        return;
    if (!g_status_title_pushed) {
        /* Publish cleanup state before the first byte: a fatal signal may
         * interrupt write(2), and an extra best-effort POP is safer than an
         * emitted PUSH that cleanup no longer knows it must undo. */
        g_status_title_pushed = 1;
        status_tty_write(push, sizeof(push) - 1U);
    }
    n = snprintf(osc, sizeof(osc), "\033]0;%s\007", title);
    if (n > 0 && (size_t)n < sizeof(osc))
        status_tty_write(osc, (size_t)n);
}

static int get_file_flags(int fd)
{
    int flags;
    do {
        flags = fcntl(fd, F_GETFL, 0);
    } while (flags < 0 && errno == EINTR);
    return flags;
}

static int set_file_flags(int fd, int flags)
{
    int rc;
    do {
        rc = fcntl(fd, F_SETFL, flags);
    } while (rc < 0 && errno == EINTR);
    return rc;
}

/* Reserve the process-standard descriptor numbers before any transport can
 * allocate sockets.  A caller is allowed to close stdin/stdout/stderr; without
 * this guard the first multipath UDP leg can become fd 0 and alias the client-input
 * poll entry.  Deaddrop endpoints have the same boundary in their process
 * runtime because they open the transport outside cmd_session(). */
static int ensure_standard_fds(void)
{
    int target;

    for (target = STDIN_FILENO; target <= STDERR_FILENO; target++) {
        int fd;

        if (fcntl(target, F_GETFD, 0) >= 0)
            continue;
        if (errno != EBADF)
            return -1;
        fd = open("/dev/null", O_RDWR | O_CLOEXEC);
        if (fd < 0)
            return -1;
        if (fd != target) {
            if (dup2(fd, target) < 0) {
                (void)close(fd);
                return -1;
            }
            (void)close(fd);
        }
    }
    return 0;
}

static int save_stdout_flags(void)
{
    int flags;

    if (g_stdout_flags_saved)
        return 0;
    flags = get_file_flags(STDOUT_FILENO);
    if (flags < 0)
        return -1;
    g_stdout_saved_flags = flags;
    g_stdout_flags_saved = 1;
    return 0;
}

static int restore_stdout_flags(void)
{
    if (!g_stdout_flags_saved)
        return 0;
    if (set_file_flags(STDOUT_FILENO, g_stdout_saved_flags) != 0)
        return -1;
    g_stdout_flags_saved = 0;
    return 0;
}

static void restore_termios_only(void)
{
    if (g_termios_saved) {
        tcsetattr(STDIN_FILENO, TCSANOW, &g_saved_termios);
        g_termios_saved = 0;
    }
}

static void restore_termios_atexit(void)
{
    status_title_close();
    (void)restore_stdout_flags();
    restore_termios_only();
}

static uint8_t * volatile g_wipe_psk = NULL;
static session_t * volatile g_active_session = NULL;

static void wipe_keys_now(void)
{
    if (g_wipe_psk)
        crypto_memzero(g_wipe_psk, 32);
    if (g_active_session)
        session_wipe_key_material(g_active_session);
    status_title_close();
    (void)restore_stdout_flags();
    restore_termios_only();
}

static void fatal_signal_handler(int sig)
{
    wipe_keys_now();
    _exit(128 + sig);
}

static void fault_signal_handler(int sig)
{
    wipe_keys_now();
    struct sigaction sa_dfl;
    memset(&sa_dfl, 0, sizeof sa_dfl);
    sa_dfl.sa_handler = SIG_DFL;
    sigaction(sig, &sa_dfl, NULL);
    raise(sig);
}

static int enter_raw_mode(void)
{
    if (!isatty(STDIN_FILENO)) {
        /* stdin not a tty (pipe/heredoc in tests) — nothing to do. */
        return 0;
    }
    if (tcgetattr(STDIN_FILENO, &g_saved_termios) != 0) {
        fprintf(stderr, "tcgetattr(stdin): %s\n", strerror(errno));
        return -1;
    }
    g_termios_saved = 1;
    atexit(restore_termios_atexit);

    struct termios raw = g_saved_termios;
    cfmakeraw(&raw);
    if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) != 0) {
        fprintf(stderr, "tcsetattr(stdin raw): %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

static volatile sig_atomic_t g_pending_sigint    = 0;
static volatile sig_atomic_t g_pending_sigwinch  = 0;
static volatile sig_atomic_t g_pending_diagnostic = 0;
static volatile sig_atomic_t g_loop_should_exit  = 0;
static volatile sig_atomic_t g_d28_exit_signal   = 0;
static volatile sig_atomic_t g_d28_services_ready = 0;

/* Session currently inside session_run on the loop-mode listener path, so
 * SIGTERM/SIGHUP can break out of an in-flight session rather than only the
 * gap between sessions. NULL when no session is active. */
static session_t *g_loop_active_session = NULL;

static void handle_sigint(int sig)  { (void)sig; g_pending_sigint = 1; }
static void handle_sigwinch(int sig){ (void)sig; g_pending_sigwinch = 1; }
static void handle_diagnostic(int sig)
{
    (void)sig;
    g_pending_diagnostic = 1;
}

/* --loop: break the re-listen loop on SIGTERM/SIGHUP without _exit'ing, so
 * we still wipe the PSK and munlock. should_exit is a plain int, but the
 * write is a single store and session_run reads it every loop tick. */
static void handle_loop_exit(int sig)
{
    (void)sig;
    g_loop_should_exit = 1;
    if (g_loop_active_session) g_loop_active_session->should_exit = 1;
}

/* epoch-rekey owns an SSH child until the outer runtime unwinds.  Unlike the legacy
 * one-process client path, HUP/TERM/QUIT must not _exit here: record the
 * requested status, stop only the exact active session, and let the caller
 * wipe secrets and reap its exact SSH child. */
static void handle_d28_exit(int sig)
{
    if (g_d28_exit_signal == 0)
        g_d28_exit_signal = sig;
    g_loop_should_exit = 1;
    if (g_active_session)
        g_active_session->should_exit = 1;
}

/* Before the mandatory epoch-one barrier, SIGINT belongs to the bootstrap
 * process owner and must unwind the exact SSH/listener tree with status 130.
 * Only a post-barrier client may translate it into a terminal PTY signal. */
static void handle_d28_sigint(int sig)
{
    if (g_d28_services_ready) {
        g_pending_sigint = 1;
        return;
    }
    handle_d28_exit(sig);
}

/* Lifecycle hook: sync DATA may overtake PTY_OPEN_ACK, so arm the
 * process-owned display sink after sync negotiation but before any channel
 * opens. The original flags were captured before stdin could mutate a shared
 * open-file description. */
static int client_on_session_established(session_t *s)
{
    int flags;

    if (!sync_active(s))
        return 0;
    if (!g_stdout_flags_saved) {
        fprintf(stderr,
                "unmoor: stdout flags were not saved before sync setup\n");
        return -1;
    }
    flags = get_file_flags(STDOUT_FILENO);
    if (flags < 0 ||
        set_file_flags(STDOUT_FILENO, flags | O_NONBLOCK) != 0) {
        fprintf(stderr, "unmoor: cannot arm nonblocking sync stdout: %s\n",
                strerror(errno));
        return -1;
    }
    fprintf(stderr,
            "unmoor: sync stdout armed nonblocking before channel open\n");
    return 0;
}

static int d28_client_on_session_established(session_t *s)
{
    if (client_on_session_established(s) != 0)
        return -1;
    /* session_activate_services invokes this only after the mandatory epoch-rekey
     * barrier; a pending PTY SIGINT is not consumed until its next tick. */
    g_d28_services_ready = 1;
    return 0;
}

static int d28_bulk_on_session_established(session_t *s)
{
    (void)s;
    /* This hook runs only after the mandatory epoch-one barrier and
     * exact bulk-transfer activation.  It exposes no terminal sink or UI state. */
    g_d28_services_ready = 1;
    return 0;
}

/* Hook called by channel_pty.c when the client receives PTY_OPEN_ACK. */
static void client_on_pty_ack(session_t *s)
{
    if (g_termios_saved) {
        s->raw_mode_active = 1;
        return; /* already raw */
    }
    if (enter_raw_mode() == 0) {
        s->raw_mode_active = g_termios_saved ? 1 : 0;
        if (s->raw_mode_active)
            fprintf(stderr, "unmoor: entered raw mode\n");
    }
}

/* channel-session embeds the first TERMINAL descriptor in READY, before the legacy PTY
 * open hook gets a chance to sample the tty. Keep the same 24x80 fallback and
 * accept only a complete, nonzero kernel sample. */
static void terminal_dimensions(uint16_t *rows_out, uint16_t *columns_out)
{
    struct winsize ws;

    *rows_out = 24U;
    *columns_out = 80U;
    if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0 &&
        ws.ws_row != 0U && ws.ws_col != 0U) {
        *rows_out = ws.ws_row;
        *columns_out = ws.ws_col;
    }
}

/* Session tick: pump pending SIGINT / SIGWINCH to the server. */
static void client_session_tick(session_t *s)
{
    if (g_pending_sigint) {
        /* Clear the signal-safe handoff before copying it into session-owned
         * bounded state. A concurrent signal sets it again for the next
         * tick; scheduler admission failure cannot erase the copied event. */
        g_pending_sigint = 0;
        channel_pty_client_queue_signal(s, 2 /* SIGINT */);
    }
    if (g_pending_sigwinch) {
        g_pending_sigwinch = 0;
        struct winsize ws;
        if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0)
            channel_pty_client_queue_resize(s, ws.ws_row, ws.ws_col);
    }
    (void)channel_pty_client_flush_control(s);
}

/* Signal handlers only latch sig_atomic_t. The ordinary event loop owns all
 * inspection, formatting and nonblocking output. */
static void process_session_tick(session_t *s)
{
    static uint64_t snapshot_id = 0U;

    if (s->is_client_pty)
        client_session_tick(s);
    if (g_pending_diagnostic) {
        g_pending_diagnostic = 0;
        if (snapshot_id != UINT64_MAX)
            snapshot_id++;
        (void)session_diagnostic_snapshot(
            s, STDERR_FILENO, snapshot_id == 0U ? UINT64_MAX : snapshot_id,
            -1);
    }
}

static int install_diagnostic_handler(void)
{
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    action.sa_handler = handle_diagnostic;
    sigemptyset(&action.sa_mask);
    return sigaction(SIGUSR1, &action, NULL);
}

/* -------------------------------------------------------------------------
 * Transport registry lookup
 * ---------------------------------------------------------------------- */

const transport_ops_t *transport_find(const char *name)
{
    if (!name) return NULL;
    if (strcmp(name, "udp")   == 0) return &transport_udp;
    if (strcmp(name, "unix")  == 0) return &transport_unix;
    if (strcmp(name, "stdio") == 0) return &transport_stdio;
    return NULL;
}

/* -------------------------------------------------------------------------
 * keygen — print a fresh 32-byte PSK as 64 hex chars on stdout
 * ---------------------------------------------------------------------- */

static int cmd_keygen(int argc, char *argv[])
{
    int debuggable = 0;
    uint8_t key[32];
    char    hex[65];

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--debuggable") == 0) {
            if (debuggable) {
                fprintf(stderr, "keygen: --debuggable may appear once\n");
                return 1;
            }
            debuggable = 1;
        }
    }
    if (process_harden_command("keygen", debuggable) != 0)
        return 1;

    crypto_mlock(key, sizeof key);
    crypto_mark_dontdump(key, sizeof key);

    if (crypto_random_bytes(key, sizeof key) != 0) {
        fprintf(stderr, "keygen: crypto_random_bytes failed\n");
        crypto_munlock(key, sizeof key);
        crypto_memzero(key, sizeof key);
        return 1;
    }
    for (int i = 0; i < 32; i++)
        snprintf(hex + 2 * i, 3, "%02x", key[i]);
    printf("%s\n", hex);
    fflush(stdout);

    crypto_memzero(hex, sizeof hex);
    crypto_munlock(key, sizeof key);
    crypto_memzero(key, sizeof key);
    return 0;
}

/* child-transfer aggregate lifetime lease. This is an internal exact-argv EXEC
 * target, not an operator command: it emits one fixed private-stream readiness
 * byte and owns no transfer metadata. EOF is the sole release signal. */
static int cmd_child_transfer_lease(int argc, char *argv[])
{
    static const uint8_t ready = UINT8_C(0x4c);
    uint8_t buffer[512];
    ssize_t written;

    (void)argv;
    if (argc != 0) {
        fprintf(stderr,
                "unmoor: internal child-transfer lease takes no arguments\n");
        return 1;
    }
    if (process_harden_command("unmoor", 0) != 0)
        return 1;
    do {
        written = write(STDOUT_FILENO, &ready, sizeof(ready));
    } while (written < 0 && errno == EINTR);
    if (written != (ssize_t)sizeof(ready))
        return 1;
    for (;;) {
        ssize_t received = read(STDIN_FILENO, buffer, sizeof(buffer));

        if (received > 0)
            continue;
        if (received == 0) {
            crypto_memzero(buffer, sizeof(buffer));
            return 0;
        }
        if (errno == EINTR)
            continue;
        crypto_memzero(buffer, sizeof(buffer));
        return 1;
    }
}

/* -------------------------------------------------------------------------
 * listen/connect: take the key, open the transport, run the session
 * ---------------------------------------------------------------------- */

/* Decode 64 hex chars into 32 bytes. Returns 0 on success. */
static int hex32_decode(const char *hex, uint8_t out[32])
{
    if (strlen(hex) != 64) return -1;
    for (int i = 0; i < 32; i++) {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

static int parse_positive_int(const char *text, int maximum, int *value_out)
{
    char *end = NULL;
    long value;

    if (!text || text[0] == '\0' || !value_out)
        return -1;
    errno = 0;
    value = strtol(text, &end, 10);
    if (errno != 0 || !end || *end != '\0' || value <= 0 ||
        value > maximum)
        return -1;
    *value_out = (int)value;
    return 0;
}

typedef enum endpoint_policy_error {
    ENDPOINT_POLICY_ERROR_NONE = 0,
    ENDPOINT_POLICY_ERROR_PROFILE,
    ENDPOINT_POLICY_ERROR_LOG_FORMAT,
    ENDPOINT_POLICY_ERROR_MULTIPATH
} endpoint_policy_error_t;

typedef struct endpoint_cli_policy {
    traffic_profile_t profile;
    uint8_t exact_paths;
    uint8_t profile_seen;
    uint8_t log_format_seen;
    uint8_t log_json;
    uint8_t multipath_seen;
    uint8_t multipath_bare_seen;
    uint8_t multipath_exact_seen;
    endpoint_policy_error_t error;
} endpoint_cli_policy_t;

typedef struct child_port_policy {
    uint16_t mask;
    uint8_t layout;
    uint8_t layout_seen;
    uint8_t mask_seen;
} child_port_policy_t;

typedef struct server_confine_policy {
    confine_level_t level;
    uint8_t seen;
} server_confine_policy_t;

/* Local runner context for the terminal epoch-rekey client.  This pointer never
 * enters d28_endpoint_policy_t, whose fields are serialized into the remote
 * listener command. */
typedef struct terminal_runner_context {
    const char *attach_socket_path;
    session_child_transfer_config_t child_transfer;
    uint8_t child_transfer_enabled;
} terminal_runner_context_t;

/* child-transfer's internal child status is process-local public metadata.  Keeping it
 * beside the legacy bulk-transfer config lets the top-level command report bootstrap
 * failures as well as an endpoint result without adding wire state. */
typedef struct bulk_runner_context {
    bulk_engine_config_t engine;
    bulk_result_code_t final_code;
    uint32_t child_local_result;
    int child_result_fd;
    uint8_t child_kind;
} bulk_runner_context_t;

static int parse_server_confine_option(const char *command, int argc,
                                       char *argv[], int *index,
                                       server_confine_policy_t *policy)
{
    static const char prefix[] = "--server-confine=";
    const char *argument;
    const char *value = NULL;
    confine_level_t level;

    if (argv == NULL || index == NULL || policy == NULL ||
        *index < 0 || *index >= argc)
        return 0;
    argument = argv[*index];
    if (strcmp(argument, "--server-confine") == 0) {
        if (*index + 1 >= argc) {
            fprintf(stderr,
                    "%s: --server-confine needs off|best-effort|require\n",
                    command);
            return -1;
        }
        value = argv[++*index];
    } else if (strncmp(argument, prefix, sizeof(prefix) - 1U) == 0) {
        value = argument + sizeof(prefix) - 1U;
    }
    if (value == NULL)
        return 0;
    if (confine_level_parse(value, &level) != 0) {
        fprintf(stderr,
                "%s: --server-confine must be off, best-effort or require\n",
                command);
        return -1;
    }
    if (policy->seen && policy->level != level) {
        fprintf(stderr,
                "%s: --server-confine may not be repeated with a different level\n",
                command);
        return -1;
    }
    policy->level = level;
    policy->seen = 1U;
    return 1;
}

static void server_confine_best_effort_notice(
    const char *command, const server_confine_policy_t *policy)
{
    if (policy != NULL && policy->seen &&
        policy->level == CONFINE_LEVEL_BEST_EFFORT)
        fprintf(stderr,
                "%s: --server-confine=best-effort permits a remote bulk "
                "server without Landlock/seccomp enforcement; use "
                "--server-confine=require to refuse instead\n",
                command);
}

static int bulk_server_confine_path(void *opaque,
                                    bulk_operation_t operation,
                                    const uint8_t *path,
                                    size_t path_length)
{
    char owned[BULK_PATH_MAX + 1U];

    (void)opaque;
    if (path == NULL || path_length == 0U || path_length > BULK_PATH_MAX ||
        (operation != BULK_OPERATION_PUT &&
         operation != BULK_OPERATION_GET))
        return BULK_RC_ARGUMENT;
    memcpy(owned, path, path_length);
    owned[path_length] = '\0';
    if (operation == BULK_OPERATION_GET) {
        if (confine_scope_set_read_file("bulk-server", owned) != 0)
            return BULK_RC_IO;
    } else if (confine_scope_set_write_dir("bulk-server", owned) != 0) {
        return BULK_RC_IO;
    }
    int result = confine_apply("bulk-server", CONFINE_ROLE_BULK_SERVER);
    return result == 0 ? BULK_RC_OK : BULK_RC_IO;
}

static int parse_exact_path_count(const char *value, uint8_t *count_out)
{
    unsigned int count;

    if (!value || !count_out)
        return -1;
    if (strcmp(value, "2") == 0)
        count = 2U;
    else if (strcmp(value, "4") == 0)
        count = 4U;
    else if (strcmp(value, "8") == 0)
        count = 8U;
    else if (strcmp(value, "16") == 0)
        count = 16U;
    else if (strcmp(value, "32") == 0)
        count = 32U;
    else
        return -1;
    *count_out = (uint8_t)count;
    return 0;
}

/* Parse only traffic-profile endpoint-policy options. The caller keeps parsing command-
 * specific options. Profile and multipath duplicates are retained until the
 * application/transport are known so option order cannot change resolution. */
static int parse_endpoint_policy_option(int argc, char *argv[], int *index,
                                        endpoint_cli_policy_t *policy)
{
    static const char profile_prefix[] = "--profile=";
    static const char log_prefix[] = "--log-format=";
    static const char multipath_prefix[] = "--multipath=";
    const char *argument;
    const char *value;
    traffic_profile_t profile;
    uint8_t count;
    int json;

    if (!argv || !index || !policy || *index < 0 || *index >= argc)
        return -1;
    argument = argv[*index];
    if (strcmp(argument, "--profile") == 0) {
        if (*index + 1 >= argc)
            return -1;
        value = argv[++*index];
    } else if (strncmp(argument, profile_prefix,
                       sizeof(profile_prefix) - 1U) == 0) {
        value = argument + sizeof(profile_prefix) - 1U;
    } else {
        value = NULL;
    }
    if (value != NULL) {
        if (traffic_profile_parse(value, &profile) != 0 ||
            (policy->profile_seen && policy->profile != profile)) {
            policy->error = ENDPOINT_POLICY_ERROR_PROFILE;
            return -1;
        }
        policy->profile = profile;
        policy->profile_seen = 1U;
        return 1;
    }
    if (strncmp(argument, "--profile", 9U) == 0) {
        policy->error = ENDPOINT_POLICY_ERROR_PROFILE;
        return -1;
    }

    if (strcmp(argument, "--log-format") == 0) {
        if (*index + 1 >= argc)
            return -1;
        value = argv[++*index];
    } else if (strncmp(argument, log_prefix, sizeof(log_prefix) - 1U) == 0) {
        value = argument + sizeof(log_prefix) - 1U;
    } else {
        value = NULL;
    }
    if (value != NULL) {
        if (strcmp(value, "text") == 0)
            json = 0;
        else if (strcmp(value, "json") == 0)
            json = 1;
        else {
            policy->error = ENDPOINT_POLICY_ERROR_LOG_FORMAT;
            return -1;
        }
        if (policy->log_format_seen && policy->log_json != (uint8_t)json) {
            policy->error = ENDPOINT_POLICY_ERROR_LOG_FORMAT;
            return -1;
        }
        policy->log_json = (uint8_t)json;
        policy->log_format_seen = 1U;
        return 1;
    }
    if (strncmp(argument, "--log-format", 12U) == 0) {
        policy->error = ENDPOINT_POLICY_ERROR_LOG_FORMAT;
        return -1;
    }

    if (strcmp(argument, "--multipath") == 0) {
        policy->multipath_seen = 1U;
        policy->multipath_bare_seen = 1U;
        return 1;
    }
    if (strncmp(argument, multipath_prefix,
                sizeof(multipath_prefix) - 1U) == 0) {
        value = argument + sizeof(multipath_prefix) - 1U;
        if (parse_exact_path_count(value, &count) != 0 ||
            (policy->multipath_exact_seen && policy->exact_paths != count)) {
            policy->error = ENDPOINT_POLICY_ERROR_MULTIPATH;
            return -1;
        }
        policy->multipath_seen = 1U;
        policy->multipath_exact_seen = 1U;
        policy->exact_paths = count;
        return 1;
    }
    if (strncmp(argument, "--multipath", 11U) == 0) {
        policy->error = ENDPOINT_POLICY_ERROR_MULTIPATH;
        return -1;
    }
    return 0;
}

static int parse_pq_policy_option(const char *command, int argc, char *argv[],
                                  int *index, pq_policy_t *policy,
                                  uint8_t *seen)
{
    static const char prefix[] = "--pq=";
    const char *argument;
    const char *value = NULL;
    pq_policy_t parsed;

    if (!command || !argv || !index || !policy || !seen ||
        *index < 0 || *index >= argc)
        return -1;
    argument = argv[*index];
    if (strcmp(argument, "--pq") == 0) {
        if (*index + 1 >= argc) {
            fprintf(stderr, "%s: --pq needs off|prefer|require\n", command);
            return -1;
        }
        value = argv[++*index];
    } else if (strncmp(argument, prefix, sizeof(prefix) - 1U) == 0) {
        value = argument + sizeof(prefix) - 1U;
    } else if (strncmp(argument, "--pq", 4U) == 0) {
        fprintf(stderr, "%s: --pq needs off|prefer|require\n", command);
        return -1;
    } else {
        return 0;
    }
    if (pq_policy_parse(value, &parsed) != 0) {
        fprintf(stderr, "%s: --pq must be off, prefer or require\n", command);
        return -1;
    }
    if (*seen != 0U && *policy != parsed) {
        fprintf(stderr,
                "%s: --pq may not be repeated with a different policy\n",
                command);
        return -1;
    }
    *policy = parsed;
    *seen = 1U;
    return 1;
}

static void print_endpoint_policy_parse_error(
    const char *command, const endpoint_cli_policy_t *policy)
{
    if (policy && policy->error == ENDPOINT_POLICY_ERROR_MULTIPATH) {
        fprintf(stderr,
                "%s: --multipath requires one exact count: 2,4,8,16,32\n",
                command);
        return;
    }
    fprintf(stderr,
            "%s: invalid/conflicting --profile, --log-format, or --multipath option\n",
            command);
}

static void print_endpoint_policy_resolution_error(
    const char *command, const endpoint_cli_policy_t *policy, int is_udp)
{
    if (policy && policy->multipath_seen && !is_udp) {
        fprintf(stderr, "%s: --multipath requires --transport udp\n",
                command);
        return;
    }
    fprintf(stderr, "%s: endpoint traffic profile is invalid\n", command);
}

static int resolve_endpoint_policy(const endpoint_cli_policy_t *policy,
                                   traffic_application_t application,
                                   int is_udp,
                                   traffic_profile_result_t *result_out)
{
    traffic_profile_result_t resolved;
    traffic_profile_result_t alternate;
    traffic_multipath_option_t option = TRAFFIC_MULTIPATH_OPTION_NONE;
    uint8_t exact = 0U;

    if (!policy || !result_out)
        return -1;
    if (policy->multipath_exact_seen) {
        option = TRAFFIC_MULTIPATH_OPTION_EXACT;
        exact = policy->exact_paths;
    } else if (policy->multipath_bare_seen) {
        option = TRAFFIC_MULTIPATH_OPTION_BARE;
    }
    if (traffic_profile_resolve(policy->profile, application, is_udp,
                                option, exact, &resolved) != 0)
        return -1;
    if (policy->multipath_bare_seen && policy->multipath_exact_seen) {
        if (traffic_profile_resolve(policy->profile, application, is_udp,
                                    TRAFFIC_MULTIPATH_OPTION_BARE, 0U,
                                    &alternate) != 0 ||
            alternate.configured_paths != resolved.configured_paths ||
            alternate.multipath_mode != resolved.multipath_mode)
            return -1;
    }
    *result_out = resolved;
    return 0;
}

static void export_endpoint_policy(const endpoint_cli_policy_t *parsed,
                                   d28_endpoint_policy_t *policy_out)
{
    memset(policy_out, 0, sizeof(*policy_out));
    policy_out->traffic_profile = parsed->profile;
    policy_out->log_format = parsed->log_json
        ? EVENT_LOG_FORMAT_JSON : EVENT_LOG_FORMAT_TEXT;
    if (parsed->multipath_exact_seen) {
        policy_out->multipath_option = TRAFFIC_MULTIPATH_OPTION_EXACT;
        policy_out->exact_paths = parsed->exact_paths;
    } else if (parsed->multipath_bare_seen) {
        policy_out->multipath_option = TRAFFIC_MULTIPATH_OPTION_BARE;
    } else {
        policy_out->multipath_option = TRAFFIC_MULTIPATH_OPTION_NONE;
    }
}

static int parse_port_layout_value(const char *text, uint8_t *layout_out)
{
    if (!text || !layout_out)
        return -1;
    if (strcmp(text, "block") == 0)
        *layout_out = TRANSPORT_UDP_PORT_LAYOUT_BLOCK;
    else if (strcmp(text, "cube") == 0)
        *layout_out = TRANSPORT_UDP_PORT_LAYOUT_CUBE;
    else if (strcmp(text, "random") == 0)
        *layout_out = TRANSPORT_UDP_PORT_LAYOUT_RANDOM;
    else
        return -1;
    return 0;
}

static int parse_port_mask_value(const char *text, uint16_t *mask_out)
{
    uint32_t value = 0U;
    size_t digits;
    size_t i;

    if (!text || !mask_out || text[0] != '0' || text[1] != 'x')
        return -1;
    digits = strlen(text + 2);
    if (digits == 0U || digits > 4U)
        return -1;
    for (i = 0U; i < digits; i++) {
        unsigned int nibble;
        unsigned char c = (unsigned char)text[i + 2U];

        if (c >= (unsigned char)'0' && c <= (unsigned char)'9')
            nibble = (unsigned int)(c - (unsigned char)'0');
        else if (c >= (unsigned char)'a' && c <= (unsigned char)'f')
            nibble = (unsigned int)(c - (unsigned char)'a') + 10U;
        else if (c >= (unsigned char)'A' && c <= (unsigned char)'F')
            nibble = (unsigned int)(c - (unsigned char)'A') + 10U;
        else
            return -1;
        value = (value << 4) | nibble;
    }
    if (value == 0U || value > UINT32_C(0x3fff))
        return -1;
    *mask_out = (uint16_t)value;
    return 0;
}

static unsigned int port_mask_popcount(uint16_t mask)
{
    unsigned int count = 0U;

    while (mask != 0U) {
        mask = (uint16_t)(mask & (uint16_t)(mask - 1U));
        count++;
    }
    return count;
}

static unsigned int path_count_log2(unsigned int path_count)
{
    unsigned int result = 0U;

    while (path_count > 1U) {
        path_count >>= 1;
        result++;
    }
    return result;
}

/* child-transfer launch policy belongs to the control-session client, not to the
 * attach-v2 request.  These existing bulk-transfer spellings therefore select only
 * the future child session's source-port layout when --attach-socket is
 * present; they never alter the control session's own UDP path pool. */
static int parse_child_port_policy_option(int argc, char *argv[], int *index,
                                          child_port_policy_t *policy)
{
    static const char layout_prefix[] = "--port-layout=";
    static const char mask_prefix[] = "--port-mask=";
    const char *argument;
    const char *value = NULL;
    uint16_t mask;
    uint8_t layout;

    if (!argv || !index || !policy || *index < 0 || *index >= argc)
        return -1;
    argument = argv[*index];
    if (strcmp(argument, "--port-layout") == 0) {
        if (*index + 1 >= argc)
            return -1;
        value = argv[++*index];
    } else if (strncmp(argument, layout_prefix,
                       sizeof(layout_prefix) - 1U) == 0) {
        value = argument + sizeof(layout_prefix) - 1U;
    }
    if (value != NULL) {
        if (parse_port_layout_value(value, &layout) != 0 ||
            (policy->layout_seen && policy->layout != layout))
            return -1;
        policy->layout = layout;
        policy->layout_seen = 1U;
        return 1;
    }
    if (strncmp(argument, "--port-layout", 13U) == 0)
        return -1;

    if (strcmp(argument, "--port-mask") == 0) {
        if (*index + 1 >= argc)
            return -1;
        value = argv[++*index];
    } else if (strncmp(argument, mask_prefix,
                       sizeof(mask_prefix) - 1U) == 0) {
        value = argument + sizeof(mask_prefix) - 1U;
    }
    if (value != NULL) {
        if (parse_port_mask_value(value, &mask) != 0 ||
            (policy->mask_seen && policy->mask != mask))
            return -1;
        policy->mask = mask;
        policy->mask_seen = 1U;
        return 1;
    }
    if (strncmp(argument, "--port-mask", 11U) == 0)
        return -1;
    return 0;
}

static int child_port_policy_validate(const char *command,
                                      const child_port_policy_t *policy,
                                      int attach_enabled)
{
    if (!policy)
        return -1;
    if ((policy->layout_seen || policy->mask_seen) && !attach_enabled) {
        fprintf(stderr,
                "%s: --port-layout/--port-mask require --attach-socket\n",
                command);
        return -1;
    }
    if (policy->mask_seen &&
        policy->layout != TRANSPORT_UDP_PORT_LAYOUT_CUBE) {
        fprintf(stderr,
                "%s: --port-mask requires --port-layout=cube\n",
                command);
        return -1;
    }
    return 0;
}

static void bulk_status_report(session_t *session)
{
    bulk_engine_path_snapshot_t paths;
    path_leg_metrics_t metrics[MULTIPATH_PATHS_MAX];
    const bulk_engine_stats_t *stats;
    transport_stats_t transport_stats;
    uint8_t path_count;
    uint8_t metric_count = 0U;
    int metrics_ready;
    unsigned int leg;

    if (!session || !session->bulk_activated || !session->bulk)
        return;
    stats = bulk_engine_stats(session->bulk);
    path_count = bulk_engine_path_count(session->bulk);
    if (!stats || path_count == 0U ||
        bulk_engine_path_snapshot(session->bulk, &paths) != BULK_RC_OK) {
        fprintf(stderr, "unmoor: bulk status unavailable\n");
        return;
    }
    memset(metrics, 0, sizeof(metrics));
    metrics_ready = session_path_metrics_snapshot(
        session, metrics, MULTIPATH_PATHS_MAX, &metric_count) == 0 &&
        metric_count == path_count;
    for (leg = 0U; leg < path_count; leg++) {
        const bulk_engine_leg_stats_t *item = &stats->leg[leg];
        path_leg_metrics_t operator_metrics;
        char metric_text[192];

        memset(&operator_metrics, 0, sizeof(operator_metrics));
        if (metrics_ready)
            operator_metrics = metrics[leg];
        /* bulk-transfer remains the counter authority even if teardown could retain
         * no RTT snapshot. The printed loss ratio is therefore always exact. */
        operator_metrics.loss_timeouts = item->timeout_loss;
        operator_metrics.loss_attempts = item->sent_chunks;
        if (operator_metrics.delivered_interval_ms == 0U)
            operator_metrics.delivered_interval_ms =
                (uint64_t)SYNC_STATUS_HEARTBEAT_MS;
        if (path_leg_format_metrics(&operator_metrics, metric_text,
                                    sizeof(metric_text)) != 0)
            (void)snprintf(metric_text, sizeof(metric_text),
                           "rtt-ms=unknown loss=%llu/%llu "
                           "delivered=0/%lldms keepalive-tx=0",
                           (unsigned long long)item->timeout_loss,
                           (unsigned long long)item->sent_chunks,
                           (long long)SYNC_STATUS_HEARTBEAT_MS);

        fprintf(stderr,
                "unmoor: bulk status leg=%u sent=%llu acked=%llu "
                "timeout-loss=%llu sent-bytes=%llu acked-bytes=%llu "
                "retransmits=%llu share-reductions=%llu "
                "share-recoveries=%llu mtu-failures=%llu "
                "reroll-requests=%llu reroll-attempts=%llu "
                "rerolls=%llu reroll-exhaustions=%llu share-shift=%u %s\n",
                leg,
                (unsigned long long)item->sent_chunks,
                (unsigned long long)item->acked_chunks,
                (unsigned long long)item->timeout_loss,
                (unsigned long long)item->sent_bytes,
                (unsigned long long)item->acked_bytes,
                (unsigned long long)item->retransmits,
                (unsigned long long)item->share_reductions,
                (unsigned long long)item->share_recoveries,
                (unsigned long long)item->mtu_failures,
                (unsigned long long)item->reroll_requests,
                (unsigned long long)item->reroll_attempts,
                (unsigned long long)item->rerolls,
                (unsigned long long)item->reroll_exhaustions,
                (unsigned int)paths.share_shift[leg], metric_text);
    }
    memset(&transport_stats, 0, sizeof(transport_stats));
    if (session->transport && session->transport->ops &&
        session->transport->ops->stats &&
        session->transport->ops->stats(session->transport,
                                       &transport_stats) == 0) {
        /* Every successful UDP tx/rx counter increment follows exactly one
         * sendto/recvfrom syscall, so a measurement can read the real packet
         * cost off these counters instead of inferring it from file geometry. */
        fprintf(stderr,
                "unmoor: bulk io transport=%u tx-datagrams=%u "
                "tx-failed=%u rx-datagrams=%u rx-dropped=%u\n",
                (unsigned int)transport_stats.transport_id,
                (unsigned int)transport_stats.tx_ok,
                (unsigned int)transport_stats.tx_fail,
                (unsigned int)transport_stats.rx_ok,
                (unsigned int)transport_stats.rx_drop);
    } else {
        fprintf(stderr, "unmoor: bulk io unavailable\n");
    }
}

/* epoch-rekey endpoint handoff.  The runtime owns process/SSH/deaddrop mechanics;
 * this function owns the normal production session/channel lifecycle. */
static int run_d28_endpoint(transport_t *transport,
                            uint8_t root[32],
                            const uint8_t pair_seed[4],
                            int is_listener,
                            d28_application_profile_t application_profile,
                            void *runner_context,
                            const d28_endpoint_policy_t *policy,
                            struct d28_monitor_endpoint *monitor_endpoint,
                            int64_t absolute_deadline_ms,
                            d28_endpoint_armed_fn armed,
                            void *armed_arg)
{
    session_t *s = NULL;
    const bulk_engine_config_t *bulk_config = NULL;
    sigset_t blocked;
    sigset_t previous;
    int signals_blocked = 0;
    int exit_code = 1;
    int ret = -1;
    int bulk_profile =
        application_profile == D28_APPLICATION_PROFILE_BULK_D33;
    bulk_runner_context_t *bulk_context = bulk_profile
        ? (bulk_runner_context_t *)runner_context : NULL;
    const terminal_runner_context_t *terminal_context = bulk_profile
        ? NULL : (const terminal_runner_context_t *)runner_context;
    session_child_transfer_config_t inherited_child_config;
    traffic_application_t traffic_application = bulk_profile
        ? TRAFFIC_APPLICATION_BULK : TRAFFIC_APPLICATION_TERMINAL;
    traffic_profile_result_t resolved;

    if (!transport || !root || !pair_seed ||
        (application_profile != D28_APPLICATION_PROFILE_TERMINAL &&
         !bulk_profile) || !policy ||
        (monitor_endpoint != NULL &&
         (!is_listener || bulk_profile || policy->channelised != 0U)) ||
        (policy->log_format != EVENT_LOG_FORMAT_TEXT &&
         policy->log_format != EVENT_LOG_FORMAT_JSON) ||
        traffic_profile_resolve(policy->traffic_profile,
                                traffic_application, 1,
                                policy->multipath_option,
                                policy->exact_paths, &resolved) != 0)
        goto cleanup;
    memset(&inherited_child_config, 0, sizeof(inherited_child_config));
    if (bulk_profile) {
        if (!bulk_context)
            goto cleanup;
        bulk_config = &bulk_context->engine;
        if (
            (bulk_config->endpoint == BULK_ENGINE_ENDPOINT_SERVER) !=
                (is_listener != 0))
            goto cleanup;
    }
    g_d28_exit_signal = 0;
    g_d28_services_ready = 0;
    g_pending_sigint = 0;
    g_pending_diagnostic = 0;
    g_loop_should_exit = 0;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGINT);
    sigaddset(&blocked, SIGHUP);
    sigaddset(&blocked, SIGTERM);
    sigaddset(&blocked, SIGQUIT);
    if (sigprocmask(SIG_BLOCK, &blocked, &previous) != 0) {
        fprintf(stderr, "unmoor: could not protect bootstrap root handoff\n");
        goto cleanup;
    }
    signals_blocked = 1;
    s = session_create(transport, root, pair_seed);
    if (!s) {
        fprintf(stderr, "unmoor: public-bootstrap session allocation failed\n");
        goto cleanup;
    }
    g_active_session = s;
    /* The monitored endpoint must bind before session_listen() prepares
     * delivery capabilities, because that preparation observes the bound
     * source.  The constructor has already restricted this handoff to the
     * listener role; publish that role now, then let session_listen() freeze
     * and initialize the ordinary listener state below. */
    if (monitor_endpoint != NULL)
        s->is_server = 1;
    if (monitor_endpoint != NULL &&
        d28_monitor_endpoint_bind_session(monitor_endpoint, s) != 0) {
        fprintf(stderr,
                "unmoor: could not bind the fixed monitored endpoint: %s\n",
                strerror(errno));
        goto cleanup;
    }
    if (!is_listener && !bulk_profile)
        session_set_shared_raw_display_tty(
            s, standard_streams_share_terminal());
    /* session_create copied the root into protected session storage.  The
     * bootstrap buffer is retired while asynchronous termination is blocked,
     * before logging, I/O, or restoration of the caller's signal mask. */
    crypto_memzero(root, 32);

    if (session_set_traffic_profile(s, policy->traffic_profile) != 0 ||
        (policy->log_format == EVENT_LOG_FORMAT_JSON &&
         session_enable_json_events(s, STDERR_FILENO) != 0)) {
        fprintf(stderr,
                "unmoor: could not initialize traffic-profile endpoint policy\n");
        goto cleanup;
    }

    if (policy->channelised != 0U) {
        uint16_t rows;
        uint16_t columns;

        terminal_dimensions(&rows, &columns);
        if (bulk_profile || session_enable_channelised_terminal(
                s, rows, columns, "") != 0) {
            fprintf(stderr,
                    "unmoor: could not require the channel-session terminal bundle\n");
            goto cleanup;
        }
    }
    if (!is_listener && terminal_context &&
        terminal_context->attach_socket_path &&
        session_enable_attach_socket(
            s, terminal_context->attach_socket_path) != 0) {
        fprintf(stderr,
                "unmoor: could not initialize the local channel-session attach socket\n");
        goto cleanup;
    }
    if (!is_listener && terminal_context &&
        terminal_context->child_transfer_enabled) {
        inherited_child_config = terminal_context->child_transfer;
        inherited_child_config.pq_carrier_required = policy->pq_hybrid;
        if (session_enable_child_transfers(
                s, &inherited_child_config) != 0) {
        fprintf(stderr,
                "unmoor: could not initialize child-transfer launch policy\n");
        goto cleanup;
        }
    }

    if (bulk_profile && session_enable_bulk(s, bulk_config) != 0) {
        fprintf(stderr,
                "unmoor: could not initialize the bulk-transfer endpoint\n");
        goto cleanup;
    }
    if (resolved.multipath_mode != TRAFFIC_MULTIPATH_MODE_NONE &&
        ((resolved.multipath_mode == TRAFFIC_MULTIPATH_MODE_REQUIRED
              ? session_enable_multipath_paths(s,
                                               resolved.configured_paths)
              : session_offer_multipath_paths(s,
                                              resolved.configured_paths)) !=
         0)) {
        fprintf(stderr,
                "unmoor: could not configure multipath on the public-bootstrap endpoint\n");
        goto cleanup;
    }

    {
        struct sigaction fault;
        memset(&fault, 0, sizeof(fault));
        fault.sa_handler = fault_signal_handler;
        fault.sa_flags = (int)SA_RESETHAND;
        sigemptyset(&fault.sa_mask);
        (void)sigaction(SIGSEGV, &fault, NULL);
        (void)sigaction(SIGBUS, &fault, NULL);
        (void)sigaction(SIGFPE, &fault, NULL);
    }

    channel_register(s, &channel_control_ops);
    if (bulk_profile)
        channel_register(s, &channel_bulk_ops);
    else {
        channel_register(s, &channel_pty_ops);
        channel_register(s, &channel_delivery_ops);
    }
    session_run_tick = process_session_tick;
    session_on_established = NULL;
    session_status_ui = NULL;
    channel_pty_on_client_ack = NULL;

    if (bulk_profile) {
        struct sigaction action;

        g_loop_should_exit = 0;
        if (is_listener)
            g_loop_active_session = s;
        memset(&action, 0, sizeof(action));
        action.sa_handler = handle_d28_exit;
        sigemptyset(&action.sa_mask);
        (void)sigaction(SIGINT, &action, NULL);
        (void)sigaction(SIGHUP, &action, NULL);
        (void)sigaction(SIGTERM, &action, NULL);
        (void)sigaction(SIGQUIT, &action, NULL);
        session_on_established = d28_bulk_on_session_established;
    } else if (!is_listener) {
        struct sigaction action;
        int flags;

        if (save_stdout_flags() != 0) {
            fprintf(stderr, "unmoor: cannot read stdout flags: %s\n",
                    strerror(errno));
            goto cleanup;
        }
        status_title_open();
        session_status_ui = client_status_ui;
        memset(&action, 0, sizeof(action));
        action.sa_handler = handle_d28_sigint;
        sigemptyset(&action.sa_mask);
        (void)sigaction(SIGINT, &action, NULL);
        action.sa_handler = handle_sigwinch;
        (void)sigaction(SIGWINCH, &action, NULL);
        action.sa_handler = handle_d28_exit;
        action.sa_flags = 0;
        (void)sigaction(SIGHUP, &action, NULL);
        (void)sigaction(SIGTERM, &action, NULL);
        (void)sigaction(SIGQUIT, &action, NULL);

        flags = fcntl(STDIN_FILENO, F_GETFL, 0);
        if (flags >= 0)
            (void)fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);
        s->is_client_pty = 1;
        channel_pty_on_client_ack = client_on_pty_ack;
        session_on_established = d28_client_on_session_established;
    } else {
        struct sigaction action;
        g_loop_should_exit = 0;
        g_loop_active_session = s;
        memset(&action, 0, sizeof(action));
        action.sa_handler = handle_d28_exit;
        sigemptyset(&action.sa_mask);
        (void)sigaction(SIGINT, &action, NULL);
        (void)sigaction(SIGHUP, &action, NULL);
        (void)sigaction(SIGTERM, &action, NULL);
        (void)sigaction(SIGQUIT, &action, NULL);
    }

    if (install_diagnostic_handler() != 0) {
        fprintf(stderr,
                "unmoor: could not install SIGUSR1 diagnostic handler: %s\n",
                strerror(errno));
        goto cleanup;
    }

    if (sigprocmask(SIG_SETMASK, &previous, NULL) != 0) {
        fprintf(stderr, "unmoor: could not restore bootstrap signal mask\n");
        goto cleanup;
    }
    signals_blocked = 0;
    if (g_loop_should_exit)
        goto cleanup;
    /* Client confinement point.  A listener is never confined (its data path is
     * chosen by the peer after this point), so this covers the epoch-rekey terminal
     * client, standalone push/pull and the child-transfer children. */
    if (!is_listener) {
        if (session_prepare_attach_socket(s) != 0) {
            fprintf(stderr,
                    "unmoor: could not prepare the local channel-session attach socket: %s\n",
                    strerror(errno));
            goto cleanup;
        }
        int confine_result =
            confine_apply(bulk_profile ? "bulk" : "unmoor",
                          bulk_profile ? CONFINE_ROLE_BULK_CLIENT
                                       : CONFINE_ROLE_TERMINAL_CLIENT);

        if (confine_result != 0) {
            if (bulk_profile && bulk_context)
                bulk_context->child_local_result =
                    child_transfer_confinement_result(
                        confine_result, bulk_context->child_result_fd);
            goto cleanup;
        }
    }
    if (session_enable_epoch_rekey(s, pair_seed, 1, 1) != 0) {
        fprintf(stderr, "unmoor: could not require epoch rekey\n");
        goto cleanup;
    }
    if (policy->pq_hybrid != 0U && session_enable_pq_hybrid(s) != 0) {
        fprintf(stderr, "unmoor: could not require PQ hybrid crypto\n");
        goto cleanup;
    }
    session_set_liveness_unbound(s, 1);
    session_set_bootstrap_deadline_ms(s, absolute_deadline_ms);

    ret = is_listener ? session_listen(s) : session_connect(s);
    if (ret == 0 && is_listener && armed && armed(armed_arg) != 0) {
        fprintf(stderr,
                "unmoor: could not confirm the armed public-bootstrap listener\n");
        ret = -1;
    }
    if (ret == 0) {
        ret = session_run(s);
        if (is_listener)
            g_loop_active_session = NULL;
    }
    if (bulk_profile) {
        bulk_result_code_t bulk_code = BULK_CODE_PROTOCOL;
        bulk_engine_result_t bulk_result =
            session_bulk_result(s, &bulk_code);

        bulk_status_report(s);
        exit_code = ret == 0 &&
                    bulk_result == BULK_ENGINE_RESULT_SUCCESS ? 0 : 1;
        bulk_context->final_code =
            bulk_result == BULK_ENGINE_RESULT_SUCCESS
                ? BULK_CODE_NONE
                : (bulk_code == BULK_CODE_NONE
                       ? BULK_CODE_PROTOCOL : bulk_code);
        if (exit_code != 0)
            fprintf(stderr,
                    "unmoor: bulk endpoint exited nonzero (result=%d code=%u)\n",
                    (int)bulk_result, (unsigned int)bulk_code);
    } else if (!is_listener && s->pty_eof_seen)
        exit_code = s->client_exit_code;
    else if (!is_listener && s->client_exit_code != 0)
        exit_code = s->client_exit_code;
    else
        exit_code = ret == 0 ? 0 : 1;

cleanup:
    if (signals_blocked)
        (void)sigprocmask(SIG_SETMASK, &previous, NULL);
    crypto_memzero(root, 32);
    g_loop_active_session = NULL;
    g_active_session = NULL;
    session_run_tick = NULL;
    session_on_established = NULL;
    session_status_ui = NULL;
    if (s)
        session_destroy(s);
    if (transport)
        transport->ops->close(transport);
    if (!is_listener && !bulk_profile) {
        status_title_close();
        if (restore_stdout_flags() != 0) {
            fprintf(stderr,
                    "unmoor: cannot restore original stdout flags: %s\n",
                    strerror(errno));
            exit_code = 1;
        }
        restore_termios_only();
    }
    if (g_d28_exit_signal != 0)
        exit_code = 128 + (int)g_d28_exit_signal;
    if (bulk_profile && bulk_context && exit_code != 0 &&
        bulk_context->final_code == BULK_CODE_NONE)
        bulk_context->final_code = g_d28_exit_signal != 0
            ? BULK_CODE_CANCELLED : BULK_CODE_PROTOCOL;
    g_d28_services_ready = 0;
    return exit_code;
}

static int cmd_deaddrop_listener(int argc, char *argv[])
{
    d28_listener_config_t config;
    endpoint_cli_policy_t policy;
    traffic_profile_result_t resolved;
    const char *log_path = getenv("UNMOOR_DEADDROP_LOG");
    int channelised = 0;
    int debuggable = 0;
    int listener_monitor = 0;
    int pq_carrier_seen = 0;

    memset(&config, 0, sizeof(config));
    memset(&policy, 0, sizeof(policy));
    config.udp_port = "0";
    config.timeout_secs = 60;
    config.log_path = log_path && log_path[0] != '\0' ? log_path : NULL;
    for (int i = 0; i < argc; i++) {
        int parsed_policy = parse_endpoint_policy_option(
            argc, argv, &i, &policy);

        if (parsed_policy < 0) {
            print_endpoint_policy_parse_error("listen", &policy);
            return 1;
        }
        if (parsed_policy > 0)
            continue;
        if (strcmp(argv[i], "--channelised") == 0) {
            channelised = 1;
        } else if (strcmp(argv[i], "--listener-monitor") == 0) {
            if (listener_monitor) {
                fprintf(stderr,
                        "listen: --listener-monitor may appear once\n");
                return 1;
            }
            listener_monitor = 1;
        } else if (strcmp(argv[i], "--debuggable") == 0) {
            if (debuggable) {
                fprintf(stderr, "listen: --debuggable may appear once\n");
                return 1;
            }
            debuggable = 1;
        } else if (strcmp(argv[i], "--deaddrop-bootstrap") == 0) {
            continue;
        } else if (strcmp(argv[i], "--pq-carrier=require") == 0) {
            if (pq_carrier_seen) {
                fprintf(stderr,
                        "listen: --pq-carrier=require may appear once\n");
                return 1;
            }
            pq_carrier_seen = 1;
            config.pq_carrier_required = 1U;
        } else if (strcmp(argv[i], "--deaddrop-parent") == 0 &&
                   i + 1 < argc) {
            config.deaddrop_parent = argv[++i];
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            config.udp_port = argv[++i];
        } else if (strcmp(argv[i], "--bind-host") == 0 && i + 1 < argc) {
            config.udp_bind_host = argv[++i];
        } else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) {
            if (parse_positive_int(argv[++i], 3600,
                                   &config.timeout_secs) != 0) {
                fprintf(stderr,
                        "listen: --timeout must be 1..3600 seconds\n");
                return 1;
            }
        } else if (strcmp(argv[i], "--bootstrap-foreground") == 0) {
            config.foreground = 1;
        } else if (strcmp(argv[i], "--log") == 0 && i + 1 < argc) {
            config.log_path = argv[++i];
        } else {
            fprintf(stderr,
                    "listen: option '%s' is incompatible with "
                    "--deaddrop-bootstrap\n", argv[i]);
            return 1;
        }
    }
    if (listener_monitor && channelised) {
        fprintf(stderr,
                "listen: --listener-monitor requires classic terminal mode\n");
        return 1;
    }
    if (listener_monitor && debuggable) {
        fprintf(stderr,
                "listen: --listener-monitor is incompatible with --debuggable\n");
        return 1;
    }
    if (resolve_endpoint_policy(&policy, TRAFFIC_APPLICATION_TERMINAL,
                                1, &resolved) != 0) {
        print_endpoint_policy_resolution_error("listen", &policy, 1);
        return 1;
    }
    export_endpoint_policy(&policy, &config.policy);
    config.policy.channelised = (uint8_t)channelised;
    config.debuggable = debuggable;
    config.listener_monitor = (uint8_t)listener_monitor;
    if (process_harden_command("listen", debuggable) != 0)
        return 1;
    return d28_runtime_listen(&config, run_d28_endpoint);
}

static int cmd_ssh_connect(int argc, char *argv[])
{
    d28_ssh_connect_config_t config;
    terminal_runner_context_t runner_context;
    endpoint_cli_policy_t policy;
    child_port_policy_t child_ports;
    server_confine_policy_t server_confine;
    traffic_profile_result_t resolved;
    const char *attach_socket_path = NULL;
    int separator = -1;
    int channelised = 0;
    int debuggable = 0;
    int listener_monitor = 0;
    uint8_t pq_policy_seen = 0U;

    memset(&config, 0, sizeof(config));
    memset(&runner_context, 0, sizeof(runner_context));
    memset(&policy, 0, sizeof(policy));
    memset(&child_ports, 0, sizeof(child_ports));
    memset(&server_confine, 0, sizeof(server_confine));
    config.remote_command = "unmoor";
    config.timeout_secs = 60;
    config.pq_policy = PQ_POLICY_REQUIRE;
    for (int i = 0; i < argc; i++) {
        int parsed_policy;

        if (strcmp(argv[i], "--") == 0) {
            separator = i;
            break;
        }
        parsed_policy = parse_endpoint_policy_option(argc, argv, &i,
                                                     &policy);
        if (parsed_policy < 0) {
            print_endpoint_policy_parse_error("ssh-connect", &policy);
            return 1;
        }
        if (parsed_policy > 0)
            continue;
        parsed_policy = parse_pq_policy_option(
            "ssh-connect", argc, argv, &i, &config.pq_policy,
            &pq_policy_seen);
        if (parsed_policy < 0)
            return 1;
        if (parsed_policy > 0)
            continue;
        parsed_policy = parse_child_port_policy_option(
            argc, argv, &i, &child_ports);
        if (parsed_policy < 0) {
            fprintf(stderr,
                    "ssh-connect: invalid/conflicting --port-layout or --port-mask option\n");
            return 1;
        }
        if (parsed_policy > 0)
            continue;
        parsed_policy = parse_server_confine_option(
            "ssh-connect", argc, argv, &i, &server_confine);
        if (parsed_policy < 0)
            return 1;
        if (parsed_policy > 0)
            continue;
        parsed_policy = confine_parse_option("ssh-connect", argc, argv, &i);
        if (parsed_policy < 0)
            return 1;
        if (parsed_policy > 0)
            continue;
        if (strcmp(argv[i], "--channelised") == 0) {
            channelised = 1;
        } else if (strcmp(argv[i], "--listener-monitor") == 0) {
            if (listener_monitor) {
                fprintf(stderr,
                        "ssh-connect: --listener-monitor may appear once\n");
                return 1;
            }
            listener_monitor = 1;
        } else if (strcmp(argv[i], "--debuggable") == 0) {
            if (debuggable) {
                fprintf(stderr,
                        "ssh-connect: --debuggable may appear once\n");
                return 1;
            }
            debuggable = 1;
        } else if (strcmp(argv[i], "--attach-socket") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr,
                        "ssh-connect: --attach-socket requires PATH\n");
                return 1;
            }
            attach_socket_path = argv[++i];
        } else if (strcmp(argv[i], "--udp-host") == 0 && i + 1 < argc) {
            config.udp_host = argv[++i];
        } else if (strcmp(argv[i], "--remote-bind-host") == 0 &&
                   i + 1 < argc) {
            config.remote_bind_host = argv[++i];
        } else if (strcmp(argv[i], "--remote") == 0 && i + 1 < argc) {
            config.remote_command = argv[++i];
        } else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) {
            if (parse_positive_int(argv[++i], 3600,
                                   &config.timeout_secs) != 0) {
                fprintf(stderr,
                        "ssh-connect: --timeout must be 1..3600 seconds\n");
                return 1;
            }
        } else if (strcmp(argv[i], "--remote-foreground") == 0) {
            config.remote_foreground = 1;
        } else {
            fprintf(stderr, "ssh-connect: unknown option '%s'\n", argv[i]);
            return 1;
        }
    }
    if (listener_monitor && channelised) {
        fprintf(stderr,
                "ssh-connect: --listener-monitor requires classic terminal mode\n");
        return 1;
    }
    if (attach_socket_path && !channelised) {
        fprintf(stderr,
                "ssh-connect: --attach-socket requires --channelised\n");
        return 1;
    }
    if (server_confine.seen && !attach_socket_path) {
        fprintf(stderr,
                "ssh-connect: --server-confine requires --channelised and --attach-socket\n");
        return 1;
    }
    if (attach_socket_path && !attach_local_path_fits(attach_socket_path)) {
        fprintf(stderr,
                "ssh-connect: --attach-socket PATH must be absolute and fit sun_path\n");
        return 1;
    }
    if (child_port_policy_validate("ssh-connect", &child_ports,
                                   attach_socket_path != NULL) != 0)
        return 1;
    if (separator < 0 || separator + 1 >= argc || !config.udp_host) {
        fprintf(stderr,
                "ssh-connect: require --udp-host HOST and -- "
                "[ssh-options...] TARGET\n");
        return 1;
    }
    if (resolve_endpoint_policy(&policy, TRAFFIC_APPLICATION_TERMINAL,
                                1, &resolved) != 0) {
        print_endpoint_policy_resolution_error("ssh-connect", &policy, 1);
        return 1;
    }
    export_endpoint_policy(&policy, &config.policy);
    config.policy.channelised = (uint8_t)channelised;
    config.listener_monitor = (uint8_t)listener_monitor;
    server_confine_best_effort_notice("ssh-connect", &server_confine);
    if (process_harden_command("ssh-connect", debuggable) != 0)
        return 1;
    confine_note_debuggable("ssh-connect", debuggable);
    confine_set_panic_hook(restore_termios_only);
    confine_scope_set_program_path(g_program_path);
    if (attach_socket_path != NULL)
        confine_scope_set_attach_socket_dir(attach_socket_path);
    if (attach_socket_path) {
        runner_context.attach_socket_path = attach_socket_path;
        runner_context.child_transfer.program_path = g_program_path;
        runner_context.child_transfer.udp_host = config.udp_host;
        runner_context.child_transfer.remote_command =
            config.remote_command;
        runner_context.child_transfer.remote_bind_host =
            config.remote_bind_host;
        runner_context.child_transfer.traffic_profile =
            config.policy.traffic_profile;
        runner_context.child_transfer.multipath_option =
            config.policy.multipath_option;
        runner_context.child_transfer.log_format = config.policy.log_format;
        runner_context.child_transfer.timeout_seconds = config.timeout_secs;
        runner_context.child_transfer.exact_paths = config.policy.exact_paths;
        runner_context.child_transfer.port_layout = child_ports.layout;
        runner_context.child_transfer.port_mask = child_ports.mask;
        runner_context.child_transfer.port_mask_explicit =
            child_ports.mask_seen;
        /* client-confinement: the transfer child re-enters this binary as a bulk client and
         * confines itself; it inherits the parent's effective level (already
         * lowered if --debuggable was given) as an explicit argv word. */
        runner_context.child_transfer.confine_level =
            confine_level_name(confine_level());
        if (server_confine.seen)
            runner_context.child_transfer.server_confine_level =
                confine_level_name(server_confine.level);
        runner_context.child_transfer_enabled = 1U;
        config.runner_context = &runner_context;
    }
    config.ssh_argc = argc - separator - 1;
    config.ssh_argv = argv + separator + 1;
    return d28_runtime_ssh_connect(&config, run_d28_endpoint);
}

#define BULK_CLI_AUTHORITY_MAX 2048U

typedef struct bulk_cli_target {
    char ssh_authority[BULK_CLI_AUTHORITY_MAX];
    char udp_host[BULK_CLI_AUTHORITY_MAX];
    const uint8_t *remote_path;
    size_t remote_path_length;
} bulk_cli_target_t;

static int copy_cli_component(char *out, size_t out_size,
                              const char *begin, size_t length)
{
    if (!out || out_size == 0U || !begin || length == 0U ||
        length >= out_size)
        return -1;
    memcpy(out, begin, length);
    out[length] = '\0';
    return 0;
}

/* Split only the local argv representation. REMOTE_PATH remains opaque bytes
 * after the delimiter and is never appended to the SSH remote command. */
static int parse_bulk_target(const char *text, bulk_cli_target_t *target)
{
    const char *delimiter;
    const char *host_begin;
    const char *authority_end;
    const char *open;
    const char *close;
    const char *at;
    size_t authority_length;
    size_t host_length;
    size_t path_length;

    if (!text || !target || text[0] == '\0' || text[0] == '-')
        return -1;
    memset(target, 0, sizeof(*target));
    open = strchr(text, '[');
    if (open) {
        close = strchr(open + 1, ']');
        if (!close || close == open + 1 || close[1] != ':' ||
            strchr(close + 1, ']') != NULL ||
            strchr(open + 1, '[') != NULL)
            return -1;
        /* Before '[' only an optional nonempty user@ prefix is legal. */
        if (open != text &&
            (open[-1] != '@' || open == text + 1 ||
             memchr(text, ':', (size_t)(open - text)) != NULL))
            return -1;
        delimiter = close + 1;
        authority_end = close + 1;
        host_begin = open + 1;
        host_length = (size_t)(close - host_begin);
    } else {
        delimiter = strchr(text, ':');
        if (!delimiter || delimiter == text ||
            strrchr(text, ':') != delimiter)
            return -1; /* ambiguous unbracketed IPv6 is forbidden */
        authority_end = delimiter;
        at = NULL;
        for (const char *p = text; p < delimiter; p++) {
            if (*p == '@')
                at = p;
        }
        host_begin = at ? at + 1 : text;
        host_length = (size_t)(delimiter - host_begin);
        if (host_length == 0U)
            return -1;
    }
    authority_length = (size_t)(authority_end - text);
    path_length = strlen(delimiter + 1);
    if (path_length == 0U || path_length > BULK_PATH_MAX ||
        copy_cli_component(target->ssh_authority,
                           sizeof(target->ssh_authority),
                           text, authority_length) != 0 ||
        copy_cli_component(target->udp_host, sizeof(target->udp_host),
                           host_begin, host_length) != 0)
        return -1;
    target->remote_path = (const uint8_t *)(delimiter + 1);
    target->remote_path_length = path_length;
    return 0;
}

static int parse_bulk_wire_budget(const char *text, uint16_t *budget_out)
{
    int value;

    if (!budget_out || parse_positive_int(text, BULK_WIRE_MAX, &value) != 0 ||
        !bulk_wire_budget_valid((uint16_t)value))
        return -1;
    *budget_out = (uint16_t)value;
    return 0;
}

static int random_nonzero_transfer_id(uint64_t *transfer_id)
{
    unsigned int attempt;

    if (!transfer_id)
        return -1;
    for (attempt = 0U; attempt < 4U; attempt++) {
        if (crypto_random_bytes((uint8_t *)transfer_id,
                                sizeof(*transfer_id)) != 0)
            return -1;
        if (*transfer_id != 0U)
            return 0;
    }
    *transfer_id = 0U;
    return -1;
}

static int parse_nonzero_u64(const char *text, uint64_t *value_out)
{
    char *end = NULL;
    unsigned long long value;
    const char *cursor;

    if (!text || !value_out || text[0] == '\0')
        return -1;
    for (cursor = text; *cursor != '\0'; cursor++)
        if (*cursor < '0' || *cursor > '9')
            return -1;
    errno = 0;
    value = strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value == 0U)
        return -1;
    *value_out = (uint64_t)value;
    return 0;
}

static int cmd_bulk_server(int argc, char *argv[])
{
    d28_listener_config_t config;
    bulk_runner_context_t runner_context;
    bulk_engine_config_t *bulk = &runner_context.engine;
    endpoint_cli_policy_t policy;
    traffic_profile_result_t resolved;
    const char *log_path = getenv("UNMOOR_DEADDROP_LOG");
    const char *pace_bps = NULL;
    int stall_secs = (int)(BULK_ENGINE_STALL_DEFAULT_MS / INT64_C(1000));
    int debuggable = 0;
    int pq_carrier_seen = 0;
    int preflight_result = 0;
    int exec_carrier = 0;

    confine_server_reset();
    memset(&config, 0, sizeof(config));
    memset(&runner_context, 0, sizeof(runner_context));
    memset(&policy, 0, sizeof(policy));
    config.application_profile = D28_APPLICATION_PROFILE_BULK_D33;
    config.runner_context = &runner_context;
    config.udp_port = "0";
    config.timeout_secs = 60;
    config.log_path = log_path && log_path[0] != '\0' ? log_path : NULL;
    runner_context.final_code = BULK_CODE_PROTOCOL;
    runner_context.child_result_fd = -1;
    bulk->endpoint = BULK_ENGINE_ENDPOINT_SERVER;
    bulk->wire_budget = BULK_WIRE_DEFAULT;
    for (int i = 0; i < argc; i++) {
        int parsed_policy = parse_endpoint_policy_option(
            argc, argv, &i, &policy);

        if (parsed_policy < 0) {
            print_endpoint_policy_parse_error("bulk-server", &policy);
            return 1;
        }
        if (parsed_policy > 0)
            continue;
        parsed_policy = confine_parse_level_option(
            "bulk-server", argc, argv, &i);
        if (parsed_policy < 0)
            return 1;
        if (parsed_policy > 0)
            continue;
        if (strcmp(argv[i], "--deaddrop-parent") == 0 && i + 1 < argc) {
            config.deaddrop_parent = argv[++i];
        } else if (strcmp(argv[i], "--debuggable") == 0) {
            if (debuggable) {
                fprintf(stderr,
                        "bulk-server: --debuggable may appear once\n");
                return 1;
            }
            debuggable = 1;
        } else if (strcmp(argv[i], "--pq-carrier=require") == 0) {
            if (pq_carrier_seen) {
                fprintf(stderr,
                        "bulk-server: --pq-carrier=require may appear once\n");
                return 1;
            }
            pq_carrier_seen = 1;
            config.pq_carrier_required = 1U;
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            config.udp_port = argv[++i];
        } else if (strcmp(argv[i], "--bind-host") == 0 && i + 1 < argc) {
            config.udp_bind_host = argv[++i];
        } else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) {
            if (parse_positive_int(argv[++i], 3600,
                                   &config.timeout_secs) != 0) {
                fprintf(stderr,
                        "bulk-server: --timeout must be 1..3600 seconds\n");
                return 1;
            }
        } else if (strcmp(argv[i], "--bulk-mtu") == 0 && i + 1 < argc) {
            if (parse_bulk_wire_budget(argv[++i], &bulk->wire_budget) != 0) {
                fprintf(stderr,
                        "bulk-server: --bulk-mtu must be 768..8952 bytes\n");
                return 1;
            }
        } else if (strcmp(argv[i], "--bulk-stall-secs") == 0 &&
                   i + 1 < argc) {
            if (parse_positive_int(argv[++i], 300, &stall_secs) != 0) {
                fprintf(stderr,
                        "bulk-server: --bulk-stall-secs must be 1..300\n");
                return 1;
            }
        } else if (strcmp(argv[i], "--bootstrap-foreground") == 0) {
            config.foreground = 1;
        } else if (strcmp(argv[i], "--bootstrap-quiet") == 0) {
            config.quiet_success = 1;
        } else if (strcmp(argv[i], "--bootstrap-exec-carrier") == 0) {
            /* Internal child-transfer carrier routing, not an enforcement selector.
             * Its initiator owns the best-effort advisory. Never infer this
             * from fd identity: a user's ordinary terminal also merges fd 1/2. */
            if (exec_carrier)
                return 1;
            exec_carrier = 1;
        } else if (strcmp(argv[i], "--pace-bps") == 0 && i + 1 < argc) {
            char *end = NULL;
            const char *p;

            pace_bps = argv[++i];
            for (p = pace_bps; *p != '\0'; p++) {
                if (*p < '0' || *p > '9')
                    break;
            }
            errno = 0;
            (void)strtoll(pace_bps, &end, 10);
            if (pace_bps[0] == '\0' || *p != '\0' || errno != 0 ||
                end == pace_bps || *end != '\0') {
                fprintf(stderr,
                        "bulk-server: --pace-bps must be decimal bytes/s\n");
                return 1;
            }
        } else if (strcmp(argv[i], "--log") == 0 && i + 1 < argc) {
            config.log_path = argv[++i];
        } else {
            fprintf(stderr, "bulk-server: unknown option '%s'\n", argv[i]);
            return 1;
        }
    }
    if (resolve_endpoint_policy(&policy, TRAFFIC_APPLICATION_BULK,
                                1, &resolved) != 0) {
        print_endpoint_policy_resolution_error("bulk-server", &policy, 1);
        return 1;
    }
    export_endpoint_policy(&policy, &config.policy);
    config.debuggable = debuggable;
    confine_note_debuggable("bulk-server", debuggable);
    if (confine_level() != CONFINE_LEVEL_OFF) {
        preflight_result = confine_preflight(
            "bulk-server", CONFINE_ROLE_BULK_SERVER);
        if (preflight_result < 0)
            return 1;
        if (preflight_result > 0 &&
            !exec_carrier &&
            confine_server_preflight_notice("bulk-server") < 0)
            return 1;
        config.server_confine = 1U;
        bulk->path_policy = bulk_server_confine_path;
    }
    bulk->stall_ms = (int64_t)stall_secs * INT64_C(1000);
    if (pace_bps && setenv("UNMOOR_PACE_BPS", pace_bps, 1) != 0) {
        fprintf(stderr, "bulk-server: could not apply --pace-bps: %s\n",
                strerror(errno));
        return 1;
    }
    if (process_harden_command("bulk-server", debuggable) != 0)
        return 1;
    return d28_runtime_listen(&config, run_d28_endpoint);
}

static int cmd_bulk_transfer(int argc, char *argv[],
                             bulk_operation_t operation)
{
    d28_ssh_connect_config_t config;
    bulk_runner_context_t runner_context;
    bulk_engine_config_t *bulk = &runner_context.engine;
    bulk_cli_target_t target;
    endpoint_cli_policy_t policy;
    server_confine_policy_t server_confine;
    traffic_profile_result_t resolved;
    const char *positionals[2] = { NULL, NULL };
    char *ssh_arguments[1];
    size_t positional_count = 0U;
    uint16_t wire_budget = BULK_WIRE_DEFAULT;
    int stall_secs = (int)(BULK_ENGINE_STALL_DEFAULT_MS / INT64_C(1000));
    int options = 1;
    int port_layout_seen = 0;
    int port_mask_seen = 0;
    const char *bootstrap_exec_socket = NULL;
    uint64_t child_transfer_id = 0U;
    int child_result_fd_seen = 0;
    int child_transfer_id_seen = 0;
    int debuggable = 0;
    uint8_t pq_policy_seen = 0U;

    memset(&config, 0, sizeof(config));
    memset(&runner_context, 0, sizeof(runner_context));
    memset(&target, 0, sizeof(target));
    memset(&policy, 0, sizeof(policy));
    memset(&server_confine, 0, sizeof(server_confine));
    config.application_profile = D28_APPLICATION_PROFILE_BULK_D33;
    config.runner_context = &runner_context;
    config.remote_command = "unmoor";
    config.timeout_secs = 60;
    config.pq_policy = PQ_POLICY_REQUIRE;
    runner_context.final_code = BULK_CODE_PROTOCOL;
    runner_context.child_result_fd = -1;
    for (int i = 0; i < argc; i++) {
        int parsed_policy = 0;

        if (options && strcmp(argv[i], "--") == 0) {
            options = 0;
            continue;
        }
        /* pq-hybrid's private child-transfer carrier marker is not the operator-facing
         * --pq policy namespace.  Consume it before the closed public
         * parser sees the shared prefix. */
        if (options && strcmp(argv[i], "--pq-carrier=require") == 0) {
            if (config.pq_carrier_required != 0U) {
                fprintf(stderr,
                        "bulk: --pq-carrier=require may appear once\n");
                return 1;
            }
            config.pq_carrier_required = 1U;
            continue;
        }
        if (options)
            parsed_policy = parse_endpoint_policy_option(
                argc, argv, &i, &policy);
        if (parsed_policy < 0) {
            print_endpoint_policy_parse_error("bulk", &policy);
            return 1;
        }
        if (parsed_policy > 0)
            continue;
        if (options) {
            parsed_policy = parse_pq_policy_option(
                "bulk", argc, argv, &i, &config.pq_policy,
                &pq_policy_seen);
            if (parsed_policy < 0)
                return 1;
            if (parsed_policy > 0)
                continue;
        }
        if (options) {
            parsed_policy = parse_server_confine_option(
                "bulk", argc, argv, &i, &server_confine);
            if (parsed_policy < 0)
                return 1;
            if (parsed_policy > 0)
                continue;
        }
        if (options) {
            parsed_policy = confine_parse_option("bulk", argc, argv, &i);
            if (parsed_policy < 0)
                return 1;
            if (parsed_policy > 0)
                continue;
        }
        if (options && strcmp(argv[i], "--udp-host") == 0 &&
                   i + 1 < argc) {
            config.udp_host = argv[++i];
        } else if (options &&
                   strcmp(argv[i], "--remote-bind-host") == 0 &&
                   i + 1 < argc) {
            config.remote_bind_host = argv[++i];
        } else if (options && strcmp(argv[i], "--remote") == 0 &&
                   i + 1 < argc) {
            config.remote_command = argv[++i];
        } else if (options && strcmp(argv[i], "--timeout") == 0 &&
                   i + 1 < argc) {
            if (parse_positive_int(argv[++i], 3600,
                                   &config.timeout_secs) != 0) {
                fprintf(stderr,
                        "bulk: --timeout must be 1..3600 seconds\n");
                return 1;
            }
        } else if (options && strcmp(argv[i], "--remote-foreground") == 0) {
            config.remote_foreground = 1;
        } else if (options &&
                   strcmp(argv[i], "--bootstrap-exec-socket") == 0 &&
                   i + 1 < argc) {
            if (bootstrap_exec_socket != NULL) {
                fprintf(stderr,
                        "bulk: --bootstrap-exec-socket may appear once\n");
                return 1;
            }
            bootstrap_exec_socket = argv[++i];
        } else if (options &&
                   strcmp(argv[i], "--child-result-fd") == 0 &&
                   i + 1 < argc) {
            if (child_result_fd_seen ||
                strcmp(argv[++i], "3") != 0) {
                fprintf(stderr,
                        "bulk: --child-result-fd must appear once with value 3\n");
                return 1;
            }
            child_result_fd_seen = 1;
        } else if (options &&
                   strcmp(argv[i], "--child-transfer-id") == 0 &&
                   i + 1 < argc) {
            if (child_transfer_id_seen ||
                parse_nonzero_u64(argv[++i], &child_transfer_id) != 0) {
                fprintf(stderr,
                        "bulk: --child-transfer-id must be one nonzero decimal u64\n");
                return 1;
            }
            child_transfer_id_seen = 1;
        } else if (options && strcmp(argv[i], "--port-layout") == 0 &&
                   i + 1 < argc) {
            uint8_t layout;

            if (parse_port_layout_value(argv[++i], &layout) != 0 ||
                (port_layout_seen && config.udp_port_layout != layout)) {
                fprintf(stderr,
                        "bulk: --port-layout must be one of block,cube,random\n");
                return 1;
            }
            config.udp_port_layout = layout;
            port_layout_seen = 1;
        } else if (options &&
                   strncmp(argv[i], "--port-layout=", 14U) == 0) {
            uint8_t layout;

            if (parse_port_layout_value(argv[i] + 14U, &layout) != 0 ||
                (port_layout_seen && config.udp_port_layout != layout)) {
                fprintf(stderr,
                        "bulk: --port-layout must be one of block,cube,random\n");
                return 1;
            }
            config.udp_port_layout = layout;
            port_layout_seen = 1;
        } else if (options && strcmp(argv[i], "--port-mask") == 0 &&
                   i + 1 < argc) {
            uint16_t mask;

            if (parse_port_mask_value(argv[++i], &mask) != 0 ||
                (port_mask_seen && config.udp_port_mask != mask)) {
                fprintf(stderr,
                        "bulk: --port-mask must be 0x0001..0x3fff\n");
                return 1;
            }
            config.udp_port_mask = mask;
            config.udp_port_mask_explicit = 1U;
            port_mask_seen = 1;
        } else if (options &&
                   strncmp(argv[i], "--port-mask=", 12U) == 0) {
            uint16_t mask;

            if (parse_port_mask_value(argv[i] + 12U, &mask) != 0 ||
                (port_mask_seen && config.udp_port_mask != mask)) {
                fprintf(stderr,
                        "bulk: --port-mask must be 0x0001..0x3fff\n");
                return 1;
            }
            config.udp_port_mask = mask;
            config.udp_port_mask_explicit = 1U;
            port_mask_seen = 1;
        } else if (options && strcmp(argv[i], "--bulk-mtu") == 0 &&
                   i + 1 < argc) {
            if (parse_bulk_wire_budget(argv[++i], &wire_budget) != 0) {
                fprintf(stderr,
                        "bulk: --bulk-mtu must be 768..8952 bytes\n");
                return 1;
            }
        } else if (options && strcmp(argv[i], "--bulk-stall-secs") == 0 &&
                   i + 1 < argc) {
            if (parse_positive_int(argv[++i], 300, &stall_secs) != 0) {
                fprintf(stderr,
                        "bulk: --bulk-stall-secs must be 1..300\n");
                return 1;
            }
        } else if (options && strcmp(argv[i], "--force") == 0) {
            bulk->force = 1U;
        } else if (options && strcmp(argv[i], "--debuggable") == 0) {
            if (debuggable) {
                fprintf(stderr, "bulk: --debuggable may appear once\n");
                return 1;
            }
            debuggable = 1;
        } else if (options && argv[i][0] == '-') {
            fprintf(stderr, "bulk: unknown option '%s'\n", argv[i]);
            return 1;
        } else if (positional_count < 2U) {
            positionals[positional_count++] = argv[i];
        } else {
            fprintf(stderr, "bulk: expected exactly two path operands\n");
            return 1;
        }
    }
    if (resolve_endpoint_policy(&policy, TRAFFIC_APPLICATION_BULK,
                                1, &resolved) != 0) {
        print_endpoint_policy_resolution_error("bulk", &policy, 1);
        return 1;
    }
    if (child_result_fd_seen != child_transfer_id_seen ||
        (child_result_fd_seen && !bootstrap_exec_socket) ||
        (config.pq_carrier_required != 0U && !bootstrap_exec_socket)) {
        fprintf(stderr,
                "bulk: child-transfer status/PQ inheritance requires an attach bootstrap\n");
        return 1;
    }
    if (child_result_fd_seen &&
        child_transfer_result_fd_arm(CHILD_TRANSFER_RESULT_FD) != 0) {
        fprintf(stderr, "bulk: could not arm child-transfer result fd: %s\n",
                strerror(errno));
        return 1;
    }
    export_endpoint_policy(&policy, &config.policy);
    if (server_confine.seen)
        config.remote_confine_level =
            confine_level_name(server_confine.level);
    if ((port_layout_seen || port_mask_seen) &&
        !policy.multipath_seen) {
        fprintf(stderr,
                "bulk: source-port layout options require --multipath\n");
        return 1;
    }
    if (port_mask_seen &&
        config.udp_port_layout != TRANSPORT_UDP_PORT_LAYOUT_CUBE) {
        fprintf(stderr,
                "bulk: --port-mask requires --port-layout=cube\n");
        return 1;
    }
    if (config.udp_port_layout == TRANSPORT_UDP_PORT_LAYOUT_CUBE &&
        port_mask_seen &&
        port_mask_popcount(config.udp_port_mask) !=
            path_count_log2(resolved.configured_paths)) {
        fprintf(stderr,
                "bulk: --port-mask popcount must equal log2(multipath paths)\n");
        return 1;
    }
    if (positional_count != 2U) {
        fprintf(stderr,
                operation == BULK_OPERATION_PUT
                    ? "usage: unmoor push [options] LOCAL [user@]HOST:REMOTE_PATH\n"
                    : "usage: unmoor pull [options] [user@]HOST:REMOTE_PATH LOCAL\n");
        return 1;
    }
    {
        const char *remote_operand = operation == BULK_OPERATION_PUT
            ? positionals[1] : positionals[0];

        if (bootstrap_exec_socket) {
            size_t remote_length = strlen(remote_operand);

            if (!attach_local_path_fits(bootstrap_exec_socket) ||
                !config.udp_host || config.udp_host[0] == '\0' ||
                config.remote_foreground || remote_length == 0U ||
                remote_length > BULK_PATH_MAX) {
                fprintf(stderr,
                        "bulk: attach bootstrap requires an absolute fitting socket, --udp-host, a plain remote path, and no --remote-foreground\n");
                return 1;
            }
            target.remote_path = (const uint8_t *)remote_operand;
            target.remote_path_length = remote_length;
        } else if (parse_bulk_target(remote_operand, &target) != 0) {
            fprintf(stderr,
                    operation == BULK_OPERATION_PUT
                        ? "usage: unmoor push [options] LOCAL [user@]HOST:REMOTE_PATH\n"
                        : "usage: unmoor pull [options] [user@]HOST:REMOTE_PATH LOCAL\n");
            return 1;
        }
    }
    if (target.remote_path_length > bulk_request_path_limit(wire_budget)) {
        fprintf(stderr,
                "bulk: remote path does not fit the selected wire budget\n");
        return 1;
    }
    bulk->endpoint = BULK_ENGINE_ENDPOINT_CLIENT;
    bulk->operation = operation;
    bulk->wire_budget = wire_budget;
    bulk->stall_ms = (int64_t)stall_secs * INT64_C(1000);
    bulk->local_path = (const uint8_t *)(operation == BULK_OPERATION_PUT
                           ? positionals[0] : positionals[1]);
    bulk->local_path_length = strlen((const char *)bulk->local_path);
    bulk->remote_path = target.remote_path;
    bulk->remote_path_length = target.remote_path_length;
    if (bulk->local_path_length == 0U ||
        bulk->local_path_length > BULK_PATH_MAX) {
        fprintf(stderr,
                "bulk: local path must be 1..1024 bytes\n");
        return 1;
    }
    if (process_harden_command(
            operation == BULK_OPERATION_PUT ? "push" : "pull",
            debuggable) != 0)
        return 1;
    {
        const char *bulk_command =
            operation == BULK_OPERATION_PUT ? "push" : "pull";

        confine_note_debuggable(bulk_command, debuggable);
        server_confine_best_effort_notice(bulk_command, &server_confine);
        confine_scope_set_program_path(g_program_path);
        /* client-confinement: exactly one local operand is in scope — the source file for
         * push, the destination's parent directory for pull (bulk.c:1555
         * opens that directory and bulk.c:1570 creates the O_RDWR temp file
         * inside it). */
        if (confine_level() != CONFINE_LEVEL_OFF) {
            if (operation == BULK_OPERATION_PUT) {
                if (confine_scope_set_read_file(
                        bulk_command,
                        (const char *)bulk->local_path) != 0)
                    return 1;
            } else if (confine_scope_set_write_dir(
                           bulk_command,
                           (const char *)bulk->local_path) != 0) {
                return 1;
            }
        }
    }
    if (child_transfer_id_seen)
        bulk->transfer_id = child_transfer_id;
    else if (random_nonzero_transfer_id(&bulk->transfer_id) != 0) {
        fprintf(stderr,
                "bulk: transfer id generation failed\n");
        return 1;
    }
    if (!config.udp_host)
        config.udp_host = target.udp_host;
    config.bulk_wire_budget = wire_budget;
    config.bulk_stall_secs = stall_secs;
    if (bootstrap_exec_socket) {
        config.attach_socket_path = bootstrap_exec_socket;
        config.local_command = g_program_path;
        /* The carrier is a second local client process.  It must inherit the
         * already-resolved policy instead of re-reading the product default. */
        config.local_confine_level = confine_level_name(confine_level());
    } else {
        ssh_arguments[0] = target.ssh_authority;
        config.ssh_argc = 1;
        config.ssh_argv = ssh_arguments;
    }
    if (child_result_fd_seen) {
        int result;
        uint32_t result_code;

        runner_context.child_result_fd = CHILD_TRANSFER_RESULT_FD;
        runner_context.child_kind = operation == BULK_OPERATION_PUT
            ? CHILD_TRANSFER_KIND_PUSH : CHILD_TRANSFER_KIND_PULL;
        result = d28_runtime_ssh_connect(&config, run_d28_endpoint);
        result_code = runner_context.child_local_result != 0U
            ? runner_context.child_local_result
            : (uint32_t)runner_context.final_code;
        if (result != 0 && result_code == (uint32_t)BULK_CODE_NONE)
            result_code = (uint32_t)BULK_CODE_PROTOCOL;
        if (child_transfer_result_write(
                runner_context.child_result_fd, runner_context.child_kind,
                bulk->transfer_id, result_code) != 0)
            result = 1;
        (void)close(runner_context.child_result_fd);
        runner_context.child_result_fd = -1;
        return result;
    }
    return d28_runtime_ssh_connect(&config, run_d28_endpoint);
}

static int cmd_session(int argc, char *argv[], int is_listen)
{
    const char *transport_name = NULL;
    const char *socket_path = NULL;
    const char *attach_socket_path = NULL;
    const char *exec_str = NULL;
    const char *udp_host = NULL;
    const char *udp_port = NULL;
    int loop_mode = 0;
    int bootstrap_mode = 0;   /* mosh-style: ephemeral key, one-shot */
    int channelised = 0;
    endpoint_cli_policy_t policy;
    child_port_policy_t child_ports;
    server_confine_policy_t server_confine;
    traffic_profile_result_t resolved;
    unsigned int multipath_paths = 0U;
    int multipath_required = 0;
    int debuggable = 0;

    session_status_ui = NULL;
    memset(&policy, 0, sizeof(policy));
    memset(&child_ports, 0, sizeof(child_ports));
    memset(&server_confine, 0, sizeof(server_confine));

    for (int i = 0; i < argc; i++) {
        int parsed_policy = parse_endpoint_policy_option(
            argc, argv, &i, &policy);

        if (parsed_policy < 0) {
            print_endpoint_policy_parse_error("session", &policy);
            return 1;
        }
        if (parsed_policy > 0)
            continue;
        parsed_policy = parse_child_port_policy_option(
            argc, argv, &i, &child_ports);
        if (parsed_policy < 0) {
            fprintf(stderr,
                    "session: invalid/conflicting --port-layout or --port-mask option\n");
            return 1;
        }
        if (parsed_policy > 0)
            continue;
        if (!is_listen) {
            parsed_policy = parse_server_confine_option(
                "session", argc, argv, &i, &server_confine);
            if (parsed_policy < 0)
                return 1;
            if (parsed_policy > 0)
                continue;
        }
        if (!is_listen) {
            /* client-confinement: confinement is a client control; a listener never
             * confines itself, so `listen` keeps rejecting these. */
            parsed_policy = confine_parse_option("session", argc, argv, &i);
            if (parsed_policy < 0)
                return 1;
            if (parsed_policy > 0)
                continue;
        }
        if (strcmp(argv[i], "--transport") == 0 && i + 1 < argc) {
            transport_name = argv[++i];
        } else if (strcmp(argv[i], "--socket") == 0 && i + 1 < argc) {
            socket_path = argv[++i];
        } else if (strcmp(argv[i], "--exec") == 0 && i + 1 < argc) {
            exec_str = argv[++i];
        } else if (strcmp(argv[i], "--host") == 0 && i + 1 < argc) {
            udp_host = argv[++i];
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            udp_port = argv[++i];
        } else if (strcmp(argv[i], "--loop") == 0) {
            loop_mode = 1;
        } else if (strcmp(argv[i], "--bootstrap") == 0) {
            bootstrap_mode = 1;
        } else if (strcmp(argv[i], "--channelised") == 0) {
            channelised = 1;
        } else if (strcmp(argv[i], "--debuggable") == 0) {
            if (debuggable) {
                fprintf(stderr, "session: --debuggable may appear once\n");
                return 1;
            }
            debuggable = 1;
        } else if (strcmp(argv[i], "--attach-socket") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr,
                        "session: --attach-socket requires PATH\n");
                return 1;
            }
            attach_socket_path = argv[++i];
        } else {
            fprintf(stderr, "session: unknown option '%s'\n", argv[i]);
            return 1;
        }
    }

    if (attach_socket_path && is_listen) {
        fprintf(stderr,
                "session: --attach-socket is only valid for connect and ssh-connect\n");
        return 1;
    }
    if (attach_socket_path && !channelised) {
        fprintf(stderr,
                "session: --attach-socket requires --channelised\n");
        return 1;
    }
    if (server_confine.seen && !attach_socket_path) {
        fprintf(stderr,
                "session: --server-confine requires --channelised and --attach-socket\n");
        return 1;
    }
    if (attach_socket_path && !attach_local_path_fits(attach_socket_path)) {
        fprintf(stderr,
                "session: --attach-socket PATH must be absolute and fit sun_path\n");
        return 1;
    }
    if (child_port_policy_validate("session", &child_ports,
                                   attach_socket_path != NULL) != 0)
        return 1;

    if (loop_mode && !is_listen) {
        fprintf(stderr, "session: --loop is only valid for 'listen'\n");
        return 1;
    }

    /* --bootstrap: one-shot listener launched over ssh by a key-carrying
     * bootstrap helper. Ephemeral in-memory key, udp transport, ephemeral
     * port by default. */
    if (bootstrap_mode) {
        if (!is_listen) {
            fprintf(stderr, "session: --bootstrap is only valid for 'listen'"
                            " (the client uses UNMOOR_KEY)\n");
            return 1;
        }
        if (loop_mode) {
            fprintf(stderr, "session: --bootstrap excludes --loop\n");
            return 1;
        }
        transport_name = "udp";
        if (!udp_port) udp_port = "0";
    }

    /* Infer transport from flags if not set */
    if (!transport_name) {
        if (exec_str)         transport_name = "stdio";
        else if (socket_path) transport_name = "unix";
        else if (udp_port)    transport_name = "udp";
        else {
            fprintf(stderr, "session: no transport specified"
                            " (use --transport, --port or --exec)\n");
            return 1;
        }
    }
    if (resolve_endpoint_policy(
            &policy, TRAFFIC_APPLICATION_TERMINAL,
            strcmp(transport_name, "udp") == 0, &resolved) != 0) {
        print_endpoint_policy_resolution_error(
            "session", &policy, strcmp(transport_name, "udp") == 0);
        return 1;
    }
    if (resolved.multipath_mode != TRAFFIC_MULTIPATH_MODE_NONE)
        multipath_paths = resolved.configured_paths;
    multipath_required =
        resolved.multipath_mode == TRAFFIC_MULTIPATH_MODE_REQUIRED;

    if (!is_listen)
        server_confine_best_effort_notice("session", &server_confine);
    if (process_harden_command(is_listen ? "listen" : "connect",
                               debuggable) != 0)
        return 1;
    if (!is_listen) {
        confine_note_debuggable("connect", debuggable);
        confine_set_panic_hook(restore_termios_only);
        confine_scope_set_program_path(g_program_path);
        if (attach_socket_path != NULL)
            confine_scope_set_attach_socket_dir(attach_socket_path);
    }

    if (ensure_standard_fds() != 0) {
        fprintf(stderr,
                "session: cannot reserve standard descriptors before transport open: %s\n",
                strerror(errno));
        return 1;
    }

    uint8_t psk[32]     = {0};
    uint8_t pair_id[4]  = {0};
    crypto_mlock(psk, 32);
    crypto_mark_dontdump(psk, 32);
    g_wipe_psk = psk;

    char *env_key = getenv("UNMOOR_KEY");
    if (bootstrap_mode) {
        /* Ephemeral key, never touches disk. Printed once on stdout for
         * the ssh channel to carry (mosh-server's model). */
        if (crypto_random_bytes(psk, 32) != 0 ||
            crypto_derive_pair_id(psk, pair_id) != 0) {
            fprintf(stderr, "session: bootstrap key generation failed\n");
            crypto_munlock(psk, 32);
            crypto_memzero(psk, 32);
            g_wipe_psk = NULL;
            return 1;
        }
    } else if (env_key) {
        /* UNMOOR_KEY=<64 hex> — key delivered out of band (a key-carrying
         * ssh bootstrap, or `unmoor keygen` piped to both sides). Scrubbed
         * from our own environment immediately; pair_id is derived from the
         * PSK so both ends agree without any on-disk state. */
        int krc = hex32_decode(env_key, psk);
        crypto_memzero(env_key, strlen(env_key)); /* scrub environ copy */
        unsetenv("UNMOOR_KEY");
        if (krc != 0) {
            fprintf(stderr, "session: UNMOOR_KEY must be 64 hex chars\n");
            crypto_munlock(psk, 32);
            crypto_memzero(psk, 32);
            g_wipe_psk = NULL;
            return 1;
        }
        if (crypto_derive_pair_id(psk, pair_id) != 0) {
            fprintf(stderr, "session: pair_id derivation failed\n");
            crypto_munlock(psk, 32);
            crypto_memzero(psk, 32);
            g_wipe_psk = NULL;
            return 1;
        }
    } else {
        fprintf(stderr,
            "session: no key. Set UNMOOR_KEY=<64 hex> (see `unmoor keygen`)\n"
            "         or use `listen --bootstrap` over ssh.\n");
        crypto_munlock(psk, 32);
        crypto_memzero(psk, 32);
        g_wipe_psk = NULL;
        return 1;
    }

    const transport_ops_t *ops = transport_find(transport_name);
    if (!ops) {
        fprintf(stderr, "session: unknown transport '%s'"
                        " (udp, unix, stdio)\n", transport_name);
        crypto_munlock(psk, 32);
        crypto_memzero(psk, 32);
        g_wipe_psk = NULL;
        return 1;
    }

    transport_config_t cfg;
    uint16_t bound_port = 0;
    memset(&cfg, 0, sizeof(cfg));
    cfg.transport = transport_name;
    cfg.path      = socket_path;
    cfg.listen    = is_listen;
    cfg.exec      = exec_str;
    cfg.udp_host  = udp_host;
    cfg.udp_port  = udp_port;
    cfg.udp_multipath_paths = (uint8_t)multipath_paths;
    if (bootstrap_mode) cfg.udp_bound_port_out = &bound_port;
    memcpy(cfg.pair_id, pair_id, 4);

    /* Install signal handlers ONCE, before the loop. The client forwards
     * SIGINT/SIGWINCH to the remote PTY; a loop-mode listener takes a
     * non-fatal SIGTERM/SIGHUP so it can break the loop and still wipe. */
    {
        /* Install fault cleanup before any client F_SETFL below. Otherwise a
         * fault in that narrow window can leave a shared caller tty mutated. */
        struct sigaction flt;
        memset(&flt, 0, sizeof(flt));
        flt.sa_handler = fault_signal_handler;
        flt.sa_flags   = (int)SA_RESETHAND;
        sigemptyset(&flt.sa_mask);
        sigaction(SIGSEGV, &flt, NULL);
        sigaction(SIGBUS,  &flt, NULL);
        sigaction(SIGFPE,  &flt, NULL);
    }

    g_pending_diagnostic = 0;
    if (install_diagnostic_handler() != 0) {
        fprintf(stderr,
                "session: could not install SIGUSR1 diagnostic handler: %s\n",
                strerror(errno));
        crypto_munlock(psk, 32);
        crypto_memzero(psk, 32);
        g_wipe_psk = NULL;
        return 1;
    }

    if (!is_listen) {
        /* F_SETFL acts on the open-file description. stdin and stdout
         * may be duped from one tty, so capture stdout's original flags before
         * making stdin nonblocking; saving on PTY_OPEN_ACK is already late. */
        if (save_stdout_flags() != 0) {
            fprintf(stderr, "unmoor: cannot read stdout flags: %s\n",
                    strerror(errno));
            crypto_munlock(psk, 32);
            crypto_memzero(psk, 32);
            g_wipe_psk = NULL;
            return 1;
        }
        status_title_open();
        session_status_ui = client_status_ui;

        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = handle_sigint;
        sigaction(SIGINT, &sa, NULL);
        sa.sa_handler = handle_sigwinch;
        sigaction(SIGWINCH, &sa, NULL);

        /* SIGHUP/SIGTERM/SIGQUIT → restore termios then _exit(128+sig).
         * SA_RESETHAND so a second signal takes the default action if we
         * hang in the handler for any reason. */
        struct sigaction fsa;
        memset(&fsa, 0, sizeof(fsa));
        fsa.sa_handler = fatal_signal_handler;
        fsa.sa_flags   = (int)SA_RESETHAND;
        sigemptyset(&fsa.sa_mask);
        sigaction(SIGHUP,  &fsa, NULL);
        sigaction(SIGTERM, &fsa, NULL);
        sigaction(SIGQUIT, &fsa, NULL);

        /* Non-blocking stdin so pump_stdin drains without stalling. */
        int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
        if (flags >= 0) fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);
    } else if (loop_mode) {
        struct sigaction lsa;
        memset(&lsa, 0, sizeof(lsa));
        lsa.sa_handler = handle_loop_exit;
        sigemptyset(&lsa.sa_mask);
        sigaction(SIGTERM, &lsa, NULL);
        sigaction(SIGHUP,  &lsa, NULL);
        sigaction(SIGINT,  &lsa, NULL);
        sigaction(SIGQUIT, &lsa, NULL);
    } else {
        struct sigaction lsa;
        memset(&lsa, 0, sizeof(lsa));
        lsa.sa_handler = fatal_signal_handler;
        lsa.sa_flags   = (int)SA_RESETHAND;
        sigemptyset(&lsa.sa_mask);
        sigaction(SIGTERM, &lsa, NULL);
        sigaction(SIGHUP,  &lsa, NULL);
        sigaction(SIGQUIT, &lsa, NULL);
    }

    int exit_code = 0;
    int ret;

    /* The do/while wraps one session lifecycle. Without --loop it runs
     * exactly once; with it, the listener re-opens the transport and
     * re-listens after each session ends. The PSK stays mlock'd on the
     * stack across iterations and is wiped exactly once after the loop. */
    do {
        transport_t *transport = NULL;
        if (ops->open(&cfg, &transport) != 0) {
            fprintf(stderr, "session: transport open failed\n");
            exit_code = 1;
            break;
        }

        session_t *s = session_create(transport, psk, pair_id);
        if (!s) {
            fprintf(stderr, "session: session_create failed\n");
            ops->close(transport);
            exit_code = 1;
            break;
        }
        g_active_session = s;
        if (!is_listen)
            session_set_shared_raw_display_tty(
                s, standard_streams_share_terminal());

        if (session_set_traffic_profile(s, policy.profile) != 0) {
            fprintf(stderr, "session: could not set traffic profile\n");
            session_destroy(s);
            ops->close(transport);
            exit_code = 1;
            break;
        }

        if (channelised) {
            uint16_t rows;
            uint16_t columns;

            terminal_dimensions(&rows, &columns);
            if (session_enable_channelised_terminal(
                    s, rows, columns, "") != 0) {
                fprintf(stderr,
                        "session: could not require the channel-session terminal bundle\n");
                session_destroy(s);
                ops->close(transport);
                exit_code = 1;
                break;
            }
        }
        if (attach_socket_path &&
            session_enable_attach_socket(s, attach_socket_path) != 0) {
            fprintf(stderr,
                    "session: could not initialize the local channel-session attach socket\n");
            session_destroy(s);
            ops->close(transport);
            exit_code = 1;
            break;
        }
        if (attach_socket_path && strcmp(transport_name, "udp") == 0 &&
            udp_host != NULL) {
            session_child_transfer_config_t child_config;

            memset(&child_config, 0, sizeof(child_config));
            child_config.program_path = g_program_path;
            child_config.udp_host = udp_host;
            child_config.remote_command = "unmoor";
            child_config.traffic_profile = policy.profile;
            child_config.multipath_option =
                policy.multipath_bare_seen
                    ? TRAFFIC_MULTIPATH_OPTION_BARE
                    : (policy.multipath_exact_seen
                           ? TRAFFIC_MULTIPATH_OPTION_EXACT
                           : TRAFFIC_MULTIPATH_OPTION_NONE);
            child_config.log_format = policy.log_json
                ? EVENT_LOG_FORMAT_JSON : EVENT_LOG_FORMAT_TEXT;
            child_config.timeout_seconds = 60;
            child_config.exact_paths = policy.exact_paths;
            child_config.port_layout = child_ports.layout;
            child_config.port_mask = child_ports.mask;
            child_config.port_mask_explicit = child_ports.mask_seen;
            /* client-confinement: propagate the effective confinement level to child-transfer
             * children. --debuggable is deliberately not propagated (it is
             * documented as not reaching exec children); it has already
             * lowered this level to "off", so the child stays coherent. */
            child_config.confine_level = confine_level_name(confine_level());
            if (server_confine.seen)
                child_config.server_confine_level =
                    confine_level_name(server_confine.level);
            if (session_enable_child_transfers(s, &child_config) != 0) {
                fprintf(stderr,
                        "session: could not initialize child-transfer launch policy\n");
                session_destroy(s);
                ops->close(transport);
                exit_code = 1;
                break;
            }
        }

        /* udp defaults to the mosh-style liveness hold — the session
         * survives outages and address changes; the peer is re-located by
         * its next authenticated frame. */
        if (strcmp(transport_name, "udp") == 0)
            session_set_liveness_unbound(s, 1);

        /* terminal state sync opt-out: UNMOOR_SYNC=0 stops offering pty-sync-v1 so the
         * session negotiates the legacy lossy PTY path. It is an escape hatch
         * for comparing against that path. Any other value — including unset —
         * keeps the default mask. Offered, never required: a legacy peer
         * still connects. */
        const char *sync_env = getenv("UNMOOR_SYNC");
        if (sync_env && strcmp(sync_env, "0") == 0) {
            if (session_set_capabilities(s,
                    UNMOOR_CAP_DEFAULT_SUPPORTED &
                        ~(UNMOOR_CAP_PTY_SYNC_V1 |
                          UNMOOR_CAP_STATUS_HEARTBEAT_V1 |
                          UNMOOR_CAP_LATEST_BLOCK_D31_V1 |
                          UNMOOR_CAP_RELIABLE_DGRAM_D31_V1),
                    UNMOOR_CAP_DEFAULT_REQUIRED) != 0)
                fprintf(stderr, "session: UNMOOR_SYNC=0 not applied\n");
            else
                fprintf(stderr, "session: UNMOOR_SYNC=0 — legacy PTY path\n");
        }

        /* traffic-profile enterprise defaults are supported-only offers. Explicit
         * requests and every lab request retain exact fail-closed multipath. */
        if (multipath_paths != 0U &&
            (multipath_required
                 ? session_enable_multipath_paths(s, multipath_paths)
                 : session_offer_multipath_paths(s, multipath_paths)) != 0) {
            fprintf(stderr,
                    "session: could not configure multipath-v1\n");
            session_destroy(s);
            ops->close(transport);
            exit_code = 1;
            break;
        }

        if (bootstrap_mode) {
            const char *blog = getenv("UNMOOR_BOOTSTRAP_LOG");

            /* Validate and install an explicitly requested log before the
             * secret announce or daemon fork.  O_NOFOLLOW protects the final
             * path component.  A rejected path must fail this foreground
             * command loudly; otherwise the detached child retains the SSH
             * stderr channel and bootstrap can wait until listener expiry. */
            if (blog) {
                int lfd = open(blog, O_WRONLY | O_CREAT | O_APPEND |
                                     O_NOFOLLOW | O_CLOEXEC, 0600);
                if (lfd < 0) {
                    fprintf(stderr,
                            "session: bootstrap log open failed: %s\n",
                            strerror(errno));
                    session_destroy(s);
                    ops->close(transport);
                    exit_code = 1;
                    break;
                }
                if (dup2(lfd, STDERR_FILENO) < 0) {
                    int saved_errno = errno;
                    (void)close(lfd);
                    errno = saved_errno;
                    fprintf(stderr,
                            "session: bootstrap log redirect failed: %s\n",
                            strerror(errno));
                    session_destroy(s);
                    ops->close(transport);
                    exit_code = 1;
                    break;
                }
                if (lfd > STDERR_FILENO)
                    (void)close(lfd);
                /* dup2() clears close-on-exec on the destination.  Mark the
                 * actual process log descriptor, not the now-closed source.
                 * forkpty() independently remaps 0/1/2 to its slave. */
                if (fcntl(STDERR_FILENO, F_SETFD, FD_CLOEXEC) < 0) {
                    fprintf(stderr,
                            "session: bootstrap log close-on-exec failed: %s\n",
                            strerror(errno));
                    session_destroy(s);
                    ops->close(transport);
                    exit_code = 1;
                    break;
                }
            }

            /* Announce on stdout — the ONE line the ssh channel carries
             * back to the bootstrap helper. Everything else this process
             * ever prints goes to stderr. */
            char hex[65];
            for (int i = 0; i < 32; i++)
                snprintf(hex + 2 * i, 3, "%02x", psk[i]);
            printf("UNMOOR CONNECT v1 %u %s\n", (unsigned)bound_port, hex);
            fflush(stdout);
            crypto_memzero(hex, sizeof(hex));

            /* Detach so ssh gets EOF and returns; the listener must not
             * die with the ssh TCP session (SIGHUP) or roaming would be
             * pointless. mosh-server does exactly this. */
            pid_t pid = fork();
            if (pid < 0) {
                fprintf(stderr, "session: bootstrap fork failed: %s\n",
                        strerror(errno));
                session_destroy(s);
                ops->close(transport);
                exit_code = 1;
                break;
            }
            if (pid > 0) _exit(0);  /* parent: release the ssh channel */
            if (process_harden(debuggable) != 0) {
                fprintf(stderr,
                        "session: detached process hardening failed: %s\n",
                        strerror(errno));
                session_destroy(s);
                ops->close(transport);
                crypto_munlock(psk, 32);
                crypto_memzero(psk, 32);
                g_wipe_psk = NULL;
                _exit(1);
            }
            setsid();
            int devnull = open("/dev/null", O_RDWR);
            if (devnull >= 0) {
                dup2(devnull, STDIN_FILENO);
                dup2(devnull, STDOUT_FILENO);
                if (!blog) dup2(devnull, STDERR_FILENO);
                if (devnull > 2) close(devnull);
            }

            int bsecs = 60;
            const char *bt = getenv("UNMOOR_BOOTSTRAP_TIMEOUT_SECS");
            if (bt) {
                int v = atoi(bt);
                if (v > 0) bsecs = v;
            }
            session_set_bootstrap_timeout(s, bsecs);
            fprintf(stderr, "session: bootstrap: detached (pid %ld), "
                            "accept window %ds\n", (long)getpid(), bsecs);
        }

        if (policy.log_json &&
            session_enable_json_events(s, STDERR_FILENO) != 0) {
            fprintf(stderr,
                    "session: could not arm nonblocking JSON event sink\n");
            session_destroy(s);
            ops->close(transport);
            exit_code = 1;
            break;
        }

        channel_register(s, &channel_control_ops);
        channel_register(s, &channel_pty_ops);
        channel_register(s, &channel_delivery_ops);
        session_run_tick = process_session_tick;

        /* Client-side PTY auto-open + raw mode + signal forwarding */
        if (!is_listen) {
            s->is_client_pty = 1;
            channel_pty_on_client_ack = client_on_pty_ack;
            session_on_established = client_on_session_established;
        }

        /* Client confinement point: the transport is open, the attach socket
         * has done its path work, every descriptor this client needs is
         * held, and no wire byte has been read yet. */
        if (!is_listen) {
            if (session_prepare_attach_socket(s) != 0) {
                fprintf(stderr,
                        "session: could not prepare the local channel-session attach socket: %s\n",
                        strerror(errno));
                session_destroy(s);
                ops->close(transport);
                exit_code = 1;
                break;
            }
            if (confine_apply("connect",
                              CONFINE_ROLE_TERMINAL_CLIENT) != 0) {
                session_destroy(s);
                ops->close(transport);
                exit_code = 1;
                break;
            }
        }

        ret = is_listen ? session_listen(s) : session_connect(s);
        if (ret == 0) {
            if (loop_mode) g_loop_active_session = s;
            ret = session_run(s);
            if (loop_mode) g_loop_active_session = NULL;
        }

        /* If the remote shell exited cleanly (PTY_EOF received), return its
         * exit code regardless of what session_run returned. */
        if (!is_listen && s->pty_eof_seen) {
            exit_code = s->client_exit_code;
        } else if (!is_listen && s->client_exit_code != 0) {
            exit_code = s->client_exit_code;
        } else {
            exit_code = (ret == 0) ? 0 : 1;
        }

        g_active_session = NULL;
        session_destroy(s);
        ops->close(transport);

        if (loop_mode && !g_loop_should_exit) {
            fprintf(stderr, "unmoor: session ended, re-listening...\n");
            sleep(1);
        }
    } while (loop_mode && !g_loop_should_exit);

    crypto_munlock(psk, 32);
    crypto_memzero(psk, 32);
    g_wipe_psk = NULL;

    session_status_ui = NULL;
    session_run_tick = NULL;
    status_title_close();

    if (restore_stdout_flags() != 0) {
        fprintf(stderr, "unmoor: cannot restore original stdout flags: %s\n",
                strerror(errno));
        exit_code = 1;
    }
    restore_termios_only();
    return exit_code;
}

/* -------------------------------------------------------------------------
 * usage / main
 * ---------------------------------------------------------------------- */

static void usage(const char *prog)
{
    fprintf(stderr,
"unmoor — authenticated state transport for unreliable, changing networks\n"
"\n"
"Usage: %s <subcommand> [options]\n"
"\n"
"Subcommands:\n"
"  keygen                       print a fresh 64-hex-char session key\n"
"  listen  [options]            accept a session\n"
"  connect [options]            start a session\n"
"  ssh-connect [options] -- ... authenticate a public-DH bootstrap over ssh\n"
"  push [options] LOCAL TARGET:PATH  verified single-file upload\n"
"  pull [options] TARGET:PATH LOCAL  verified single-file download\n"
"  attach --socket PATH terminal     attach a local tty to this session\n"
"  attach --socket PATH exec -- ARGV...  run exact argv; no shell\n"
"  rss-plan [options]             predict RSS queue coverage; no NIC writes\n"
"  version                      print version and exit\n"
"\n"
"Transport options:\n"
"  --transport udp|unix|stdio   default inferred from the flags below\n"
"  --host HOST                  udp: peer host (connect) or exact native\n"
"                               bind family/address (listen)\n"
"  --port PORT                  udp: port (0 = ephemeral, listen only)\n"
"                               omitted listen host requires native IPv4 +\n"
"                               V6ONLY IPv6 on one shared port\n"
"  --profile enterprise|lab     traffic defaults (default: enterprise)\n"
"                               enterprise: terminal 2, bulk 4 optional paths\n"
"                               lab: one path unless multipath is requested\n"
"  --multipath[=2|4|8|16|32]    udp: require a validated path pool; bare uses\n"
"                               the profile count (enterprise 2/4, lab 8)\n"
"  --log-format text|json       diagnostics (default: text); json emits bounded\n"
"                               unmoor.event.v1 normally, unmoor.event.v2 when\n"
"                               --channelised is selected; always on stderr\n"
"  --socket PATH                unix: socket path\n"
"  --exec \"cmd args\"            stdio: run cmd and speak over its pipes\n"
"\n"
"Process option (all subcommands):\n"
"  --debuggable                 allow cores and same-user process attach;\n"
"                               prints one warning; not propagated to execs\n"
"  SIGUSR1                      request one bounded, read-only session/path\n"
"                               snapshot on stderr (64 per session maximum)\n"
"\n"
"Client confinement options (connect, ssh-connect, push, pull, attach):\n"
"  --confine off|best-effort|require\n"
"                               narrow this client's own future after the last\n"
"                               fork/exec: no_new_privs, a Landlock path\n"
"                               allow-list and a seccomp syscall allow-list\n"
#if defined(__linux__)
"                               (Linux only). This Linux build defaults to\n"
"                               require and refuses if a mechanism is missing;\n"
"                               explicit best-effort continues with a warning.\n"
#else
"                               (Linux only). This non-Linux build defaults to\n"
"                               warned best-effort; Linux builds default to\n"
"                               require and refuse a missing mechanism.\n"
#endif
"                               --debuggable implies off\n"
"                               unless --confine was given explicitly. Never\n"
"                               applied to a listener\n"
"  --confine-root PATH          add one read/write data root for the terminal\n"
"                               client (repeatable, at most 8). The working\n"
"                               directory is always a root; a background\n"
"                               transfer operand outside every root is\n"
"                               refused by name before the child is forked\n"
"\n"
"One-shot bulk-server confinement (push/pull and attached transfers):\n"
"  --server-confine off|best-effort|require\n"
"                               explicitly narrow the remote one-shot server\n"
"                               after its authenticated path is known and\n"
"                               before that file is opened. Omission keeps\n"
"                               existing unconfined server behavior. Linux\n"
"                               require refuses if Landlock or seccomp is\n"
"                               unavailable; non-Linux cannot enforce it.\n"
"                               On connect/ssh-connect this option requires\n"
"                               --channelised plus --attach-socket and applies\n"
"                               only to later push/pull attachments.\n"
"\n"
"Session options:\n"
"  --channelised                require multi-channel terminal support; no\n"
"                               downgrade\n"
"  --attach-socket PATH         connect/ssh-connect: local attach socket\n"
"  --bootstrap                  listen: one-shot, ephemeral key on stdout,\n"
"                               then detach (for a key-carrying ssh\n"
"                               bootstrap)\n"
"  --deaddrop-bootstrap         listen: one-shot public X25519 exchange;\n"
"  --listener-monitor          ssh-connect/listen: experimental Linux-only\n"
"                               isolated listener process boundary; explicit\n"
"                               request fails if unavailable, never falls back\n"
"  --deaddrop-parent DIR        public one-shot record parent (mode 0700)\n"
"  --bind-host HOST             bind the deaddrop UDP listener to HOST\n"
"  --bootstrap-foreground       wait for the owned listener child\n"
"  --timeout SECS               one absolute bootstrap window (1..3600)\n"
"  --loop                       listen: re-listen after each session ends\n"
"\n"
"ssh-connect options:\n"
"  --pq off|prefer|require      post-quantum bootstrap/rekey policy\n"
"                               (default: require)\n"
"  --udp-host HOST              required UDP destination (may differ from ssh)\n"
"  --remote-bind-host HOST      explicit remote UDP listener bind address\n"
"  --remote CMD                 remote unmoor executable (default: unmoor)\n"
"  --remote-foreground          lifecycle-test mode: keep ssh as owner\n"
"  --timeout SECS               public exchange through epoch-1 deadline\n"
"  -- [ssh-options...] TARGET   exact ssh option/destination boundary\n"
"\n"
"Bulk push/pull options:\n"
"  --pq off|prefer|require      post-quantum bootstrap/rekey policy\n"
"                               (default: require)\n"
"  --bulk-mtu BYTES             complete UDP payload budget (768..8952)\n"
"  --bulk-stall-secs SECS       no-progress deadline (1..300; default 30)\n"
"                               use 240 for roaming/ECMP until measured\n"
"  --port-layout block|cube|random  client source-port layout\n"
"  --port-mask 0xNNNN           cube mask; popcount = log2(path count)\n"
"  --force                      atomically replace an existing destination\n"
"  --udp-host/--remote/--remote-bind-host/--timeout/--profile/\n"
"  --multipath/--log-format as above\n"
"\n"
"Environment:\n"
"  UNMOOR_KEY                   64 hex chars; required unless --bootstrap.\n"
"                               Scrubbed from the environment once parsed.\n"
"  UNMOOR_PACE_BPS              token-bucket read pacer, bytes/sec (0 = off)\n"
"  UNMOOR_SYNC                  0 = legacy lossy PTY path (default: state\n"
"                               sync — lossless display)\n"
"  UNMOOR_SYNC_BACKLOG_BYTES    sync retransmit backlog per side\n"
"                               (default 256M; bounds disconnect survival)\n"
"  UNMOOR_SYNC_PENDING_BYTES    sync receive reorder buffer (default 4M)\n"
"  UNMOOR_SYNC_LINGER_MS        server wait for the final ack after the\n"
"                               shell exits (default 10000)\n"
"  UNMOOR_BOOTSTRAP_LOG         --bootstrap: stderr log path after detach\n"
"  UNMOOR_BOOTSTRAP_TIMEOUT_SECS  --bootstrap: accept window (default 60)\n",
        prog);
}

int main(int argc, char *argv[])
{
    int bare_path_fallback = 0;

    /* Force stderr unbuffered as a defense against forkpty(3) stdio buffer
     * inheritance: with stderr on a pipe, bytes pending in the parent's
     * stderr FILE* buffer were inherited by the forkpty child and dumped
     * onto the PTY slave during shell setup, corrupting the first frames
     * the server sent back. POSIX / C11 §7.21.3 say stderr "is not fully
     * buffered" but mandate no specific mode, so pin it. */
    setvbuf(stderr, NULL, _IONBF, 0);

    /* A closed stream is an ordinary transport failure, never process-wide
     * signal authority. Every later exec boundary restores SIG_DFL. */
    if (process_ignore_sigpipe() != 0) {
        fprintf(stderr, "unmoor: cannot ignore SIGPIPE: %s\n",
                strerror(errno));
        return 1;
    }

    if (process_resolve_self_path(
            argc > 0 ? argv[0] : NULL, g_program_path_storage,
            sizeof(g_program_path_storage), &bare_path_fallback) != 0) {
        fprintf(stderr, "unmoor: cannot resolve executable path: %s\n",
                strerror(errno));
        return 1;
    }
    g_program_path = g_program_path_storage;
    if (bare_path_fallback)
        fprintf(stderr,
                "unmoor: executable path unavailable; using PATH-sensitive argv[0] '%s'\n",
                g_program_path);

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    const char *subcmd = argv[1];
    int sub_argc = argc - 2;
    char **sub_argv = argv + 2;

    if (strcmp(subcmd, "keygen") == 0) {
        return cmd_keygen(sub_argc, sub_argv);
    } else if (strcmp(subcmd, "listen") == 0) {
        /* The mode marker is positional so an unrelated legacy option value
         * named "--deaddrop-bootstrap" cannot silently select a new parser. */
        if (sub_argc > 0 &&
            strcmp(sub_argv[0], "--deaddrop-bootstrap") == 0)
            return cmd_deaddrop_listener(sub_argc, sub_argv);
        if (sub_argc > 0 &&
            strcmp(sub_argv[0], "--listener-monitor") == 0) {
            fprintf(stderr,
                    "listen: --listener-monitor requires --deaddrop-bootstrap\n");
            return 1;
        }
        return cmd_session(sub_argc, sub_argv, 1);
    } else if (strcmp(subcmd, "connect") == 0) {
        return cmd_session(sub_argc, sub_argv, 0);
    } else if (strcmp(subcmd, "ssh-connect") == 0) {
        return cmd_ssh_connect(sub_argc, sub_argv);
    } else if (strcmp(subcmd, "push") == 0) {
        return cmd_bulk_transfer(sub_argc, sub_argv, BULK_OPERATION_PUT);
    } else if (strcmp(subcmd, "pull") == 0) {
        return cmd_bulk_transfer(sub_argc, sub_argv, BULK_OPERATION_GET);
    } else if (strcmp(subcmd, "attach") == 0) {
        return attach_client_command(sub_argc, sub_argv);
    } else if (strcmp(subcmd, "rss-plan") == 0) {
        return rss_plan_command(sub_argc, sub_argv);
    } else if (strcmp(subcmd, "--bulk-server") == 0) {
        return cmd_bulk_server(sub_argc, sub_argv);
    } else if (strcmp(subcmd, "--child-transfer-lease") == 0) {
        return cmd_child_transfer_lease(sub_argc, sub_argv);
    } else if (strcmp(subcmd, "version") == 0) {
        int debuggable = 0;

        if (sub_argc == 1 && strcmp(sub_argv[0], "--pq-probe") == 0) {
            if (process_harden_command("version", 0) != 0)
                return 1;
            if (fwrite(PQ_PROBE_SUPPORTED_TEXT, 1,
                       sizeof(PQ_PROBE_SUPPORTED_TEXT) - 1U, stdout) !=
                    sizeof(PQ_PROBE_SUPPORTED_TEXT) - 1U ||
                fflush(stdout) != 0)
                return 1;
            return 0;
        }

        for (int i = 0; i < sub_argc; i++) {
            if (strcmp(sub_argv[i], "--debuggable") == 0 && !debuggable) {
                debuggable = 1;
            } else {
                fprintf(stderr, "version: unknown option '%s'\n", sub_argv[i]);
                return 1;
            }
        }
        if (process_harden_command("version", debuggable) != 0)
            return 1;
        printf("unmoor %s (protocol v%d)\n", UNMOOR_VERSION, UNMOOR_PROTO_VERSION);
        return 0;
    } else if (strcmp(subcmd, "--help") == 0 || strcmp(subcmd, "-h") == 0) {
        int debuggable = 0;

        for (int i = 0; i < sub_argc; i++)
            if (strcmp(sub_argv[i], "--debuggable") == 0)
                debuggable = 1;
        if (process_harden_command("help", debuggable) != 0)
            return 1;
        usage(argv[0]);
        return 0;
    }

    fprintf(stderr, "Unknown subcommand: %s\n", subcmd);
    usage(argv[0]);
    return 1;
}
