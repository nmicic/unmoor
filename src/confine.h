/*
 * confine.h — client self-confinement (Landlock + seccomp-bpf)
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * After an authenticated peer's bytes have passed AEAD they reach this
 * program's own parsers.  A parser defect is therefore reachable by the peer,
 * so each client role narrows its own future before the first wire byte is
 * read: PR_SET_NO_NEW_PRIVS, a Landlock filesystem allow-list built from the
 * paths the role actually needs, and a seccomp-bpf syscall allow-list.  This
 * confines unmoor's own process; it never touches anything outside it.
 *
 * Linux only.  Everywhere else every entry point reports "unsupported";
 * `best-effort` emits one warning and continues, while `require` refuses.
 *
 * Nothing here is applied to a listener.  This is client-confinement scope;
 * the terminal listener deliberately runs with the full authority of the
 * SSH user it logged in as, and SECURITY.md says so.
 */
#ifndef UNMOOR_CONFINE_H
#define UNMOOR_CONFINE_H

#include <stddef.h>

typedef enum {
    CONFINE_LEVEL_OFF = 0,
    CONFINE_LEVEL_BEST_EFFORT = 1,
    CONFINE_LEVEL_REQUIRE = 2
} confine_level_t;

typedef enum {
    /* `connect`/`ssh-connect` terminal client.  May still fork/exec the child-transfer
     * child transfers, so it keeps EXECUTE on its own image and the loader. */
    CONFINE_ROLE_TERMINAL_CLIENT = 0,
    /* `push`/`pull`, standalone or as a child transfer.  One source file or one
     * destination directory, plus the result fd; never execs. */
    CONFINE_ROLE_BULK_CLIENT = 1,
    /* `attach`.  Operands are already open; the ruleset is empty. */
    CONFINE_ROLE_ATTACH_CLIENT = 2,
    /* `attach ... terminal`: same empty/narrow policy as ATTACH_CLIENT, but
     * its denied-syscall disposition must restore the borrowed tty. */
    CONFINE_ROLE_ATTACH_TERMINAL_CLIENT = 3,
    /* server-confinement one-shot server after REQUEST. Existing descriptors only: exact
     * file/deaddrop cleanup, no new socket, process creation or reaping. */
    CONFINE_ROLE_BULK_SERVER = 4
} confine_role_t;

#define CONFINE_MAX_ROOTS 8U

/* One decoded --confine word.  Returns 0 on success. */
int confine_level_parse(const char *text, confine_level_t *level_out);
const char *confine_level_name(confine_level_t level);

/* Reset the process-wide plan.  Call once per command before parsing. */
void confine_reset(void);
/* server-confinement's first server increment is deliberately default-neutral. */
void confine_server_reset(void);

/*
 * Option parsing, shaped like parse_endpoint_policy_option():
 *   1  consumed (*index may have advanced)
 *   0  not one of ours
 *  -1  malformed; one named diagnostic already printed for `command`
 * Accepts `--confine LEVEL`, `--confine=LEVEL`, `--confine-root PATH` and
 * `--confine-root=PATH`.
 */
int confine_parse_option(const char *command, int argc, char *argv[],
                         int *index);
/* Level-only form used by the private bulk-server command. Roots are not
 * consumed because server-confinement derives one exact path from authenticated REQUEST. */
int confine_parse_level_option(const char *command, int argc, char *argv[],
                               int *index);

/* --debuggable implies --confine off unless --confine was given explicitly.
 * Prints one notice when it actually lowers the level. */
void confine_note_debuggable(const char *command, int debuggable);

confine_level_t confine_level(void);
int confine_level_explicit(void);

/* Scope, filled in once the role's operands are known.  Each returns 0 on
 * success and -1 after printing one named diagnostic. */
int confine_scope_add_root(const char *command, const char *path);
int confine_scope_set_read_file(const char *command, const char *path);
int confine_scope_set_write_dir(const char *command, const char *path);
int confine_scope_set_cleanup_dirs(const char *command,
                                   const char *parent_path,
                                   const char *attempt_path);
void confine_scope_set_program_path(const char *path);
void confine_scope_set_attach_socket_dir(const char *path);

/*
 * Containment check used before a child-transfer fork so the refusal is
 * named in the confined parent instead of dying silently in the child
 * (whose stderr is /dev/null).  Returns 1 when `path` is inside a configured
 * root, and also when no Landlock domain is installed or no roots are
 * configured, because there is then nothing for the kernel to enforce.
 */
int confine_path_within_roots(const char *path);

/*
 * Install the role's confinement in this process.  Returns 0 when the caller
 * may continue and -1 when the command must fail.  A server whose real
 * preflight succeeded also fails closed if the late exact-path install no
 * longer succeeds; best-effort continuation is decided by preflight only.
 */
int confine_apply(const char *command, confine_role_t role);
/* Probe real mechanism installation before epoch-rekey creates private bootstrap
 * material. Returns 0 when enforcement is available, 1 when explicit
 * best-effort may continue without it, and -1 when the command must refuse.
 * The probe runs in a disposable child and does not consume the late domain. */
int confine_preflight(const char *command, confine_role_t role);
/* Emit the deferred best-effort reduction notice at most once. */
int confine_server_preflight_notice(const char *command);

/*
 * Emergency restore run from the SIGSYS handler before the terminal client
 * dies on a denied syscall, so the operator's tty is not left raw.  Must be
 * async-signal-safe.
 */
void confine_set_panic_hook(void (*hook)(void));

/* Introspection for confinement test builds and the lab profile harness. */
int confine_supported(void);      /* 1 when built with the Linux mechanisms */
int confine_landlock_abi(void);   /* ABI level, 0 = absent, -1 = unsupported */
int confine_seccomp_arch_supported(void);

/*
 * Test seams.  Declared always, defined only under -DUNMOOR_CONFINE_TEST=1 so
 * the production binary carries no confine_test_ symbol (`make hygiene`).
 */
#if defined(UNMOOR_CONFINE_TEST)
confine_level_t confine_test_platform_default(void);
confine_level_t confine_test_default_for_linux(int linux_platform);
void confine_test_set_landlock_abi(int abi);
#define CONFINE_TEST_PREFLIGHT_FAIL_LANDLOCK 1
#define CONFINE_TEST_PREFLIGHT_FAIL_SECCOMP 2
void confine_test_set_preflight_failure(int stage);
unsigned long long confine_test_handled_fs(int abi);
unsigned long long confine_test_file_rights(int abi);
size_t confine_test_rule_count(confine_role_t role);
void confine_test_set_rule_limit(size_t limit);
int confine_test_apply_landlock(const char *command, confine_role_t role);
int confine_test_apply_seccomp(confine_role_t role);
int confine_test_syscall_allowed(confine_role_t role, int number);
size_t confine_test_syscall_count(confine_role_t role);
void confine_test_set_installed(int landlock_installed,
                                int seccomp_installed);
#endif

#endif /* UNMOOR_CONFINE_H */
