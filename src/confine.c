/*
 * confine.c — client self-confinement (Landlock + seccomp-bpf)
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * Raw syscalls only: no libseccomp, no libcap, so the static build stays
 * dependency-free.  Everything installed here narrows only this process and
 * its future children; nested Landlock domains intersect, so a child can
 * narrow further but never widen.
 */
#define _GNU_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif

#include "confine.h"
#include "fd_stat.h"

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#if defined(__linux__)
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include "confine_tables.h"
#endif

#ifndef CONFINE_PATH_MAX
#define CONFINE_PATH_MAX 4096
#endif
#define CONFINE_MAX_RULES 32U

/* ------------------------------------------------------------------ *
 * Process-wide plan.  One command, one plan; filled during option
 * parsing and operand resolution, consumed once by confine_apply().
 * ------------------------------------------------------------------ */

typedef struct {
    char path[CONFINE_PATH_MAX];
    unsigned long long access;
    int optional; /* an absent path is skipped, not an error */
    int required_regular_file; /* server GET must never grant a subtree */
} confine_rule_t;

static struct {
    confine_level_t level;
    int level_explicit;
    int debuggable_lowered;
    size_t root_count;
    char roots[CONFINE_MAX_ROOTS][CONFINE_PATH_MAX];
    char read_file[CONFINE_PATH_MAX];
    char write_dir[CONFINE_PATH_MAX];
    char program_path[CONFINE_PATH_MAX];
    char attach_socket_dir[CONFINE_PATH_MAX];
    char cleanup_parent[CONFINE_PATH_MAX];
    char cleanup_attempt[CONFINE_PATH_MAX];
    int have_read_file;
    int have_write_dir;
    int have_cleanup_dirs;
    int server_preflight_complete;
    int server_preflight_degraded;
    int server_preflight_notice_emitted;
    char server_preflight_reason[160];
    int applied;
    int landlock_installed;
    int seccomp_installed;
} g_plan;

static int g_plan_initialized;
static void (*g_panic_hook)(void);
#if defined(UNMOOR_CONFINE_TEST)
static size_t g_test_rule_limit = CONFINE_MAX_RULES;
static int g_test_landlock_abi = -1;
static int g_test_preflight_failure;
#endif

static confine_level_t confine_default_for_linux(int linux_platform)
{
    return linux_platform ? CONFINE_LEVEL_REQUIRE
                          : CONFINE_LEVEL_BEST_EFFORT;
}

static confine_level_t confine_platform_default(void)
{
#if defined(__linux__)
    return confine_default_for_linux(1);
#else
    return confine_default_for_linux(0);
#endif
}

static void confine_plan_init(void)
{
    if (g_plan_initialized)
        return;
    memset(&g_plan, 0, sizeof(g_plan));
    g_plan.level = confine_platform_default();
    g_plan_initialized = 1;
}

static void confine_reset_with_level(confine_level_t level)
{
    g_plan_initialized = 0;
#if defined(UNMOOR_CONFINE_TEST)
    g_test_rule_limit = CONFINE_MAX_RULES;
    g_test_landlock_abi = -1;
    g_test_preflight_failure = 0;
#endif
    memset(&g_plan, 0, sizeof(g_plan));
    g_plan.level = level;
    g_plan_initialized = 1;
}

void confine_reset(void)
{
    confine_reset_with_level(confine_platform_default());
}

void confine_server_reset(void)
{
    confine_reset_with_level(CONFINE_LEVEL_OFF);
}

void confine_set_panic_hook(void (*hook)(void))
{
    g_panic_hook = hook;
}

int confine_level_parse(const char *text, confine_level_t *level_out)
{
    if (text == NULL || level_out == NULL)
        return -1;
    if (strcmp(text, "off") == 0)
        *level_out = CONFINE_LEVEL_OFF;
    else if (strcmp(text, "best-effort") == 0)
        *level_out = CONFINE_LEVEL_BEST_EFFORT;
    else if (strcmp(text, "require") == 0)
        *level_out = CONFINE_LEVEL_REQUIRE;
    else
        return -1;
    return 0;
}

const char *confine_level_name(confine_level_t level)
{
    switch (level) {
    case CONFINE_LEVEL_OFF:
        return "off";
    case CONFINE_LEVEL_BEST_EFFORT:
        return "best-effort";
    case CONFINE_LEVEL_REQUIRE:
        return "require";
    default:
        return NULL;
    }
}

confine_level_t confine_level(void)
{
    confine_plan_init();
    return g_plan.level;
}

int confine_level_explicit(void)
{
    confine_plan_init();
    return g_plan.level_explicit;
}

#if defined(UNMOOR_CONFINE_TEST)
confine_level_t confine_test_platform_default(void)
{
    return confine_platform_default();
}

confine_level_t confine_test_default_for_linux(int linux_platform)
{
    return confine_default_for_linux(linux_platform != 0);
}

void confine_test_set_landlock_abi(int abi)
{
    g_test_landlock_abi = abi;
}
#endif

/* ------------------------------------------------------------------ *
 * Option parsing
 * ------------------------------------------------------------------ */

int confine_parse_level_option(const char *command, int argc, char *argv[],
                               int *index)
{
    static const char level_prefix[] = "--confine=";
    const char *argument;
    const char *value = NULL;
    confine_level_t level;

    confine_plan_init();
    if (argv == NULL || index == NULL || *index < 0 || *index >= argc)
        return 0;
    argument = argv[*index];
    if (strcmp(argument, "--confine") == 0) {
        if (*index + 1 >= argc) {
            fprintf(stderr, "%s: --confine needs off|best-effort|require\n",
                    command);
            return -1;
        }
        value = argv[++*index];
    } else if (strncmp(argument, level_prefix,
                       sizeof(level_prefix) - 1U) == 0) {
        value = argument + sizeof(level_prefix) - 1U;
    }
    if (value != NULL) {
        if (confine_level_parse(value, &level) != 0) {
            fprintf(stderr, "%s: --confine must be off, best-effort or require\n",
                    command);
            return -1;
        }
        if (g_plan.level_explicit && g_plan.level != level) {
            fprintf(stderr, "%s: --confine may not be repeated with a different level\n",
                    command);
            return -1;
        }
        g_plan.level = level;
        g_plan.level_explicit = 1;
        return 1;
    }
    return 0;
}

int confine_parse_option(const char *command, int argc, char *argv[],
                         int *index)
{
    static const char root_prefix[] = "--confine-root=";
    const char *argument;
    const char *value = NULL;
    int parsed;

    parsed = confine_parse_level_option(command, argc, argv, index);
    if (parsed != 0)
        return parsed;
    if (argv == NULL || index == NULL || *index < 0 || *index >= argc)
        return 0;
    argument = argv[*index];

    if (strcmp(argument, "--confine-root") == 0) {
        if (*index + 1 >= argc) {
            fprintf(stderr, "%s: --confine-root needs a path\n", command);
            return -1;
        }
        value = argv[++*index];
    } else if (strncmp(argument, root_prefix,
                       sizeof(root_prefix) - 1U) == 0) {
        value = argument + sizeof(root_prefix) - 1U;
    }
    if (value != NULL)
        return confine_scope_add_root(command, value) == 0 ? 1 : -1;
    return 0;
}

void confine_note_debuggable(const char *command, int debuggable)
{
    confine_plan_init();
    if (!debuggable || g_plan.level_explicit ||
        g_plan.level == CONFINE_LEVEL_OFF)
        return;
    g_plan.level = CONFINE_LEVEL_OFF;
    g_plan.debuggable_lowered = 1;
    fprintf(stderr, "%s: client confinement disabled (--debuggable)\n",
            command);
}

/* ------------------------------------------------------------------ *
 * Scope
 * ------------------------------------------------------------------ */

/* Resolve `path` to an absolute, symlink-free directory or file name.  When
 * `want_parent` is set the last component may be absent and only its parent
 * has to exist; the resolved parent is returned. */
static int confine_resolve(const char *path, int want_parent,
                           char out[CONFINE_PATH_MAX])
{
    char scratch[CONFINE_PATH_MAX];
    char resolved[PATH_MAX];
    const char *target = path;
    size_t length;

    if (path == NULL || path[0] == '\0')
        return -1;
    if (want_parent) {
        const char *slash = strrchr(path, '/');

        if (slash == NULL) {
            target = ".";
        } else {
            size_t parent_length = (size_t)(slash - path);

            if (parent_length == 0U)
                parent_length = 1U;
            if (parent_length >= sizeof(scratch))
                return -1;
            memcpy(scratch, path, parent_length);
            scratch[parent_length] = '\0';
            target = scratch;
        }
    }
    if (realpath(target, resolved) == NULL)
        return -1;
    length = strlen(resolved);
    if (length == 0U || length >= CONFINE_PATH_MAX)
        return -1;
    memcpy(out, resolved, length + 1U);
    return 0;
}

static int confine_prefix_within(const char *root, const char *candidate);

int confine_scope_add_root(const char *command, const char *path)
{
    char resolved[CONFINE_PATH_MAX];
    size_t i;

    confine_plan_init();
    if (confine_resolve(path, 0, resolved) != 0) {
        fprintf(stderr, "%s: --confine-root '%s' does not resolve: %s\n",
                command, path != NULL ? path : "(null)", strerror(errno));
        return -1;
    }
    for (i = 0U; i < g_plan.root_count; i++) {
        if (strcmp(g_plan.roots[i], resolved) == 0)
            return 0;
    }
    if (g_plan.root_count >= CONFINE_MAX_ROOTS) {
        fprintf(stderr, "%s: at most %u --confine-root paths\n", command,
                (unsigned int)CONFINE_MAX_ROOTS);
        return -1;
    }
    memcpy(g_plan.roots[g_plan.root_count], resolved, strlen(resolved) + 1U);
    g_plan.root_count++;
    return 0;
}

int confine_scope_set_read_file(const char *command, const char *path)
{
    char resolved[CONFINE_PATH_MAX];

    confine_plan_init();
    if (confine_resolve(path, 0, resolved) != 0) {
        fprintf(stderr, "%s: cannot resolve source '%s': %s\n", command,
                path != NULL ? path : "(null)", strerror(errno));
        return -1;
    }
    memcpy(g_plan.read_file, resolved, strlen(resolved) + 1U);
    g_plan.have_read_file = 1;
    return 0;
}

int confine_scope_set_write_dir(const char *command, const char *path)
{
    char resolved[CONFINE_PATH_MAX];

    confine_plan_init();
    if (confine_resolve(path, 1, resolved) != 0) {
        fprintf(stderr, "%s: cannot resolve the parent of '%s': %s\n", command,
                path != NULL ? path : "(null)", strerror(errno));
        return -1;
    }
    memcpy(g_plan.write_dir, resolved, strlen(resolved) + 1U);
    g_plan.have_write_dir = 1;
    return 0;
}

int confine_scope_set_cleanup_dirs(const char *command,
                                   const char *parent_path,
                                   const char *attempt_path)
{
    char parent[CONFINE_PATH_MAX];
    char attempt[CONFINE_PATH_MAX];

    confine_plan_init();
    if (confine_resolve(parent_path, 0, parent) != 0 ||
        confine_resolve(attempt_path, 0, attempt) != 0 ||
        !confine_prefix_within(parent, attempt) ||
        strcmp(parent, attempt) == 0) {
        fprintf(stderr,
                "%s: cannot resolve the one-shot deaddrop cleanup scope\n",
                command);
        return -1;
    }
    memcpy(g_plan.cleanup_parent, parent, strlen(parent) + 1U);
    memcpy(g_plan.cleanup_attempt, attempt, strlen(attempt) + 1U);
    g_plan.have_cleanup_dirs = 1;
    return 0;
}

void confine_scope_set_program_path(const char *path)
{
    char resolved[CONFINE_PATH_MAX];

    confine_plan_init();
    if (path == NULL || confine_resolve(path, 0, resolved) != 0)
        return;
    memcpy(g_plan.program_path, resolved, strlen(resolved) + 1U);
}

void confine_scope_set_attach_socket_dir(const char *path)
{
    char resolved[CONFINE_PATH_MAX];

    confine_plan_init();
    if (path == NULL || confine_resolve(path, 1, resolved) != 0)
        return;
    memcpy(g_plan.attach_socket_dir, resolved, strlen(resolved) + 1U);
}

static int confine_prefix_within(const char *root, const char *candidate)
{
    size_t length = strlen(root);

    if (length == 1U && root[0] == '/')
        return 1;
    if (strncmp(root, candidate, length) != 0)
        return 0;
    return candidate[length] == '\0' || candidate[length] == '/';
}

int confine_path_within_roots(const char *path)
{
    char resolved[CONFINE_PATH_MAX];
    size_t i;

    confine_plan_init();
    if (!g_plan.landlock_installed)
        return 1;
    if (g_plan.root_count == 0U)
        return 1;
    if (confine_resolve(path, 0, resolved) != 0 &&
        confine_resolve(path, 1, resolved) != 0)
        return 0;
    for (i = 0U; i < g_plan.root_count; i++) {
        if (confine_prefix_within(g_plan.roots[i], resolved))
            return 1;
    }
    return 0;
}

static int confine_server_mark_preflight_degraded(const char *reason)
{
    int count;

    if (reason == NULL || reason[0] == '\0')
        return -1;
    count = snprintf(g_plan.server_preflight_reason,
                     sizeof(g_plan.server_preflight_reason), "%s", reason);
    if (count <= 0 ||
        (size_t)count >= sizeof(g_plan.server_preflight_reason))
        return -1;
    g_plan.server_preflight_complete = 1;
    g_plan.server_preflight_degraded = 1;
    return 1;
}

int confine_server_preflight_notice(const char *command)
{
    confine_plan_init();
    if (command == NULL || command[0] == '\0')
        return -1;
    if (!g_plan.server_preflight_complete ||
        !g_plan.server_preflight_degraded ||
        g_plan.server_preflight_notice_emitted)
        return 0;
    fprintf(stderr,
            "%s: server confinement reduced before bootstrap: %s; "
            "continuing with --server-confine=best-effort\n",
            command, g_plan.server_preflight_reason);
    g_plan.server_preflight_notice_emitted = 1;
    return 1;
}

/* ------------------------------------------------------------------ *
 * Non-Linux: every mechanism is absent.
 * ------------------------------------------------------------------ */

#if !defined(__linux__)

int confine_supported(void)
{
    return 0;
}

int confine_landlock_abi(void)
{
    return -1;
}

int confine_seccomp_arch_supported(void)
{
    return 0;
}

int confine_preflight(const char *command, confine_role_t role)
{
    confine_plan_init();
    if (role != CONFINE_ROLE_BULK_SERVER)
        return -1;
    if (g_plan.level == CONFINE_LEVEL_OFF)
        return 0;
    if (g_plan.level == CONFINE_LEVEL_REQUIRE) {
        fprintf(stderr,
                "%s: --server-confine require needs Linux Landlock and "
                "seccomp; refusing; use --server-confine=best-effort to "
                "continue at your own security risk\n",
                command);
        return -1;
    }
    return confine_server_mark_preflight_degraded(
        "Landlock/seccomp unavailable (platform is not Linux)");
}

int confine_apply(const char *command, confine_role_t role)
{
    const int server = role == CONFINE_ROLE_BULK_SERVER;
    confine_plan_init();
    if (g_plan.applied)
        return 0;
    g_plan.applied = 1;
    g_plan.landlock_installed = 0;
    g_plan.seccomp_installed = 0;
    if (g_plan.level == CONFINE_LEVEL_OFF)
        return 0;
    if (server && g_plan.server_preflight_complete &&
        g_plan.server_preflight_degraded)
        return 0;
    if (server && !g_plan.server_preflight_complete) {
        fprintf(stderr,
                "%s: server confinement preflight was not completed; "
                "refusing\n",
                command);
        return -1;
    }
    if (g_plan.level == CONFINE_LEVEL_REQUIRE) {
        fprintf(stderr,
                "%s: --%sconfine require needs Linux Landlock and seccomp; "
                "refusing; use --%sconfine=best-effort to continue at your "
                "own security risk\n",
                command, server ? "server-" : "",
                server ? "server-" : "");
        return -1;
    }
    fprintf(stderr,
            "%s: client confinement reduced: Landlock/seccomp unavailable "
            "(platform is not Linux; continuing with "
            "--confine=best-effort)\n",
            command);
    return 0;
}

#if defined(UNMOOR_CONFINE_TEST)

unsigned long long confine_test_handled_fs(int abi)
{
    (void)abi;
    return 0ULL;
}

unsigned long long confine_test_file_rights(int abi)
{
    (void)abi;
    return 0ULL;
}

size_t confine_test_rule_count(confine_role_t role)
{
    (void)role;
    return 0U;
}

void confine_test_set_rule_limit(size_t limit)
{
    g_test_rule_limit = limit <= CONFINE_MAX_RULES ? limit
                                                    : CONFINE_MAX_RULES;
}

void confine_test_set_preflight_failure(int stage)
{
    (void)stage;
}

int confine_test_apply_landlock(const char *command, confine_role_t role)
{
    (void)command;
    (void)role;
    return -1;
}

int confine_test_apply_seccomp(confine_role_t role)
{
    (void)role;
    return -1;
}

int confine_test_syscall_allowed(confine_role_t role, int number)
{
    (void)role;
    (void)number;
    return -1;
}

size_t confine_test_syscall_count(confine_role_t role)
{
    (void)role;
    return 0U;
}

void confine_test_set_installed(int landlock_installed,
                                int seccomp_installed)
{
    confine_plan_init();
    g_plan.landlock_installed = landlock_installed != 0;
    g_plan.seccomp_installed = seccomp_installed != 0;
}

#endif /* UNMOOR_CONFINE_TEST */

#else /* __linux__ */

/* ------------------------------------------------------------------ *
 * Landlock: own ABI declarations so the build never needs kernel headers.
 * ------------------------------------------------------------------ */

#define CONFINE_LL_EXECUTE (1ULL << 0)
#define CONFINE_LL_WRITE_FILE (1ULL << 1)
#define CONFINE_LL_READ_FILE (1ULL << 2)
#define CONFINE_LL_READ_DIR (1ULL << 3)
#define CONFINE_LL_REMOVE_DIR (1ULL << 4)
#define CONFINE_LL_REMOVE_FILE (1ULL << 5)
#define CONFINE_LL_MAKE_CHAR (1ULL << 6)
#define CONFINE_LL_MAKE_DIR (1ULL << 7)
#define CONFINE_LL_MAKE_REG (1ULL << 8)
#define CONFINE_LL_MAKE_SOCK (1ULL << 9)
#define CONFINE_LL_MAKE_FIFO (1ULL << 10)
#define CONFINE_LL_MAKE_BLOCK (1ULL << 11)
#define CONFINE_LL_MAKE_SYM (1ULL << 12)
#define CONFINE_LL_REFER (1ULL << 13)
#define CONFINE_LL_TRUNCATE (1ULL << 14)
#define CONFINE_LL_IOCTL_DEV (1ULL << 15)

#define CONFINE_LL_NET_BIND_TCP (1ULL << 0)
#define CONFINE_LL_NET_CONNECT_TCP (1ULL << 1)

#define CONFINE_LL_CREATE_RULESET_VERSION (1U << 0)
#define CONFINE_LL_RULE_PATH_BENEATH 1

struct confine_ruleset_attr {
    uint64_t handled_access_fs;
    uint64_t handled_access_net;
};

struct confine_path_beneath_attr {
    uint64_t allowed_access;
    int32_t parent_fd;
} __attribute__((packed));

static long confine_landlock_create_ruleset(
    const struct confine_ruleset_attr *attr, size_t size, uint32_t flags)
{
#ifdef __NR_landlock_create_ruleset
    return syscall(__NR_landlock_create_ruleset, attr, size, flags);
#else
    (void)attr;
    (void)size;
    (void)flags;
    errno = ENOSYS;
    return -1;
#endif
}

static long confine_landlock_add_rule(int ruleset_fd, int rule_type,
                                      const void *rule_attr, uint32_t flags)
{
#ifdef __NR_landlock_add_rule
    return syscall(__NR_landlock_add_rule, ruleset_fd, rule_type, rule_attr,
                   flags);
#else
    (void)ruleset_fd;
    (void)rule_type;
    (void)rule_attr;
    (void)flags;
    errno = ENOSYS;
    return -1;
#endif
}

static long confine_landlock_restrict_self(int ruleset_fd, uint32_t flags)
{
#ifdef __NR_landlock_restrict_self
    return syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
#else
    (void)ruleset_fd;
    (void)flags;
    errno = ENOSYS;
    return -1;
#endif
}

int confine_supported(void)
{
    return 1;
}

int confine_landlock_abi(void)
{
#if defined(UNMOOR_CONFINE_TEST)
    if (g_test_landlock_abi >= 0)
        return g_test_landlock_abi;
#endif
    long abi = confine_landlock_create_ruleset(
        NULL, 0, CONFINE_LL_CREATE_RULESET_VERSION);

    if (abi < 0)
        return 0;
    return (int)abi;
}

/* Every filesystem right the running kernel knows about.  An access right
 * that is not in the handled mask is silently ALLOWED, so this must grow
 * with the ABI or the domain quietly stops covering new operations. */
static uint64_t confine_handled_fs(int abi)
{
    uint64_t handled = CONFINE_LL_EXECUTE | CONFINE_LL_WRITE_FILE |
                       CONFINE_LL_READ_FILE | CONFINE_LL_READ_DIR |
                       CONFINE_LL_REMOVE_DIR | CONFINE_LL_REMOVE_FILE |
                       CONFINE_LL_MAKE_CHAR | CONFINE_LL_MAKE_DIR |
                       CONFINE_LL_MAKE_REG | CONFINE_LL_MAKE_SOCK |
                       CONFINE_LL_MAKE_FIFO | CONFINE_LL_MAKE_BLOCK |
                       CONFINE_LL_MAKE_SYM;

    if (abi >= 2)
        handled |= CONFINE_LL_REFER;
    if (abi >= 3)
        handled |= CONFINE_LL_TRUNCATE;
    if (abi >= 5)
        handled |= CONFINE_LL_IOCTL_DEV;
    return handled;
}

/* Rights that only make sense on a non-directory. */
static uint64_t confine_file_rights(int abi)
{
    uint64_t rights = CONFINE_LL_EXECUTE | CONFINE_LL_WRITE_FILE |
                      CONFINE_LL_READ_FILE;

    if (abi >= 3)
        rights |= CONFINE_LL_TRUNCATE;
    if (abi >= 5)
        rights |= CONFINE_LL_IOCTL_DEV;
    return rights;
}

/*  1 installed, 0 optional and absent, -1 error (errno set). */
static int confine_add_path(int ruleset_fd, const confine_rule_t *rule,
                            int abi)
{
    struct confine_path_beneath_attr attr;
    struct stat st;
    uint64_t access = rule->access & confine_handled_fs(abi);
    int fd;

    /* O_PATH deliberately follows symlinks: the rule must land on the real
     * object, and the walk happens before the domain exists. */
    fd = open(rule->path, O_PATH | O_CLOEXEC);
    if (fd < 0) {
        if (rule->optional && (errno == ENOENT || errno == ENOTDIR ||
                               errno == EACCES))
            return 0;
        return -1;
    }
    if (fstat(fd, &st) != 0) {
        int saved = errno;

        (void)close(fd);
        errno = saved;
        return -1;
    }
    /* Validate the same referenced object passed to Landlock, not an earlier
     * pathname lookup: a directory READ_FILE rule would cover descendants. */
    if (rule->required_regular_file && !S_ISREG(st.st_mode)) {
        (void)close(fd);
        errno = EINVAL;
        return -1;
    }
    if (!S_ISDIR(st.st_mode))
        access &= confine_file_rights(abi);
    if (access == 0ULL) {
        (void)close(fd);
        if (rule->optional)
            return 0;
        errno = EINVAL;
        return -1;
    }
    memset(&attr, 0, sizeof(attr));
    attr.allowed_access = access;
    attr.parent_fd = fd;
    if (confine_landlock_add_rule(ruleset_fd, CONFINE_LL_RULE_PATH_BENEATH,
                                  &attr, 0) != 0) {
        int saved = errno;

        (void)close(fd);
        errno = saved;
        return -1;
    }
    (void)close(fd);
    return 1;
}

/* ------------------------------------------------------------------ *
 * ELF interpreter of our own image, so EXECUTE can be granted on exactly
 * the loader instead of on every shared object directory.
 * ------------------------------------------------------------------ */

static int confine_read_interpreter(const char *program,
                                    char out[CONFINE_PATH_MAX])
{
    unsigned char header[64];
    unsigned char entry[64];
    unsigned long long phoff;
    unsigned int phentsize;
    unsigned int phnum;
    unsigned int i;
    int is64;
    int fd;
    ssize_t got;

    if (program == NULL || program[0] == '\0')
        return -1;
    fd = open(program, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    got = pread(fd, header, sizeof(header), 0);
    if (got != (ssize_t)sizeof(header) || memcmp(header, "\177ELF", 4) != 0) {
        (void)close(fd);
        return -1;
    }
    is64 = header[4] == 2;
    if (!is64 && header[4] != 1) {
        (void)close(fd);
        return -1;
    }
    /* Little-endian only; unmoor's Linux targets are all LE. */
    if (header[5] != 1) {
        (void)close(fd);
        return -1;
    }
    if (is64) {
        memcpy(&phoff, header + 32, 8);
        phentsize = (unsigned int)header[54] | ((unsigned int)header[55] << 8);
        phnum = (unsigned int)header[56] | ((unsigned int)header[57] << 8);
    } else {
        uint32_t off32;

        memcpy(&off32, header + 28, 4);
        phoff = off32;
        phentsize = (unsigned int)header[42] | ((unsigned int)header[43] << 8);
        phnum = (unsigned int)header[44] | ((unsigned int)header[45] << 8);
    }
    if (phentsize == 0U || phentsize > sizeof(entry) || phnum == 0U ||
        phnum > 128U) {
        (void)close(fd);
        return -1;
    }
    for (i = 0U; i < phnum; i++) {
        uint32_t type;
        unsigned long long offset;
        unsigned long long size;

        got = pread(fd, entry, phentsize,
                    (off_t)(phoff + (unsigned long long)i * phentsize));
        if (got != (ssize_t)phentsize)
            break;
        memcpy(&type, entry, 4);
        if (type != 3U) /* PT_INTERP */
            continue;
        if (is64) {
            memcpy(&offset, entry + 8, 8);
            memcpy(&size, entry + 32, 8);
        } else {
            uint32_t off32;
            uint32_t size32;

            memcpy(&off32, entry + 4, 4);
            memcpy(&size32, entry + 16, 4);
            offset = off32;
            size = size32;
        }
        if (size == 0ULL || size >= CONFINE_PATH_MAX)
            break;
        got = pread(fd, out, (size_t)size, (off_t)offset);
        (void)close(fd);
        if (got != (ssize_t)size)
            return -1;
        out[size - 1ULL] = '\0';
        return out[0] == '/' ? 0 : -1;
    }
    (void)close(fd);
    return -1;
}

/* ------------------------------------------------------------------ *
 * Rule set per role
 * ------------------------------------------------------------------ */

static int confine_rule_append(confine_rule_t *rules, size_t *count,
                               const char *path, unsigned long long access,
                               int optional)
{
    size_t length;

    if (path == NULL || path[0] == '\0')
        return 0;
    length = strlen(path);
    if (length >= CONFINE_PATH_MAX ||
#if defined(UNMOOR_CONFINE_TEST)
        *count >= g_test_rule_limit)
#else
        *count >= CONFINE_MAX_RULES)
#endif
        return -1;
    memcpy(rules[*count].path, path, length + 1U);
    rules[*count].access = access;
    rules[*count].optional = optional;
    rules[*count].required_regular_file = 0;
    (*count)++;
    return 0;
}

#define CONFINE_DATA_DIR_RIGHTS                                            \
    (CONFINE_LL_READ_FILE | CONFINE_LL_WRITE_FILE | CONFINE_LL_READ_DIR |  \
     CONFINE_LL_MAKE_REG | CONFINE_LL_MAKE_DIR | CONFINE_LL_MAKE_SOCK |    \
     CONFINE_LL_MAKE_FIFO | CONFINE_LL_MAKE_SYM | CONFINE_LL_REMOVE_FILE | \
     CONFINE_LL_REMOVE_DIR | CONFINE_LL_REFER | CONFINE_LL_TRUNCATE |      \
     CONFINE_LL_IOCTL_DEV)

#define CONFINE_SINK_DIR_RIGHTS                                           \
    (CONFINE_LL_READ_DIR | CONFINE_LL_READ_FILE | CONFINE_LL_WRITE_FILE | \
     CONFINE_LL_MAKE_REG | CONFINE_LL_REMOVE_FILE | CONFINE_LL_REFER |    \
     CONFINE_LL_TRUNCATE)

static int confine_role_is_attach(confine_role_t role)
{
    return role == CONFINE_ROLE_ATTACH_CLIENT ||
           role == CONFINE_ROLE_ATTACH_TERMINAL_CLIENT;
}

static int confine_role_is_server(confine_role_t role)
{
    return role == CONFINE_ROLE_BULK_SERVER;
}

static int confine_role_traps(confine_role_t role)
{
    return role == CONFINE_ROLE_TERMINAL_CLIENT ||
           role == CONFINE_ROLE_ATTACH_TERMINAL_CLIENT;
}

static size_t confine_rule_limit(void)
{
#if defined(UNMOOR_CONFINE_TEST)
    return g_test_rule_limit;
#else
    return CONFINE_MAX_RULES;
#endif
}

static int confine_build_rules(confine_role_t role, confine_rule_t *rules,
                               size_t *count_out)
{
    size_t count = 0U;
    size_t i;

    if (count_out == NULL)
        return -1;
    if (confine_role_is_attach(role)) {
        *count_out = 0U; /* deny-all: the operands are already open */
        return 0;
    }

    if (confine_role_is_server(role)) {
        if (g_plan.have_read_file) {
            if (confine_rule_append(rules, &count, g_plan.read_file,
                                    CONFINE_LL_READ_FILE, 0) != 0)
                return -1;
            rules[count - 1U].required_regular_file = 1;
        }
        if (g_plan.have_write_dir &&
            confine_rule_append(rules, &count, g_plan.write_dir,
                                CONFINE_SINK_DIR_RIGHTS, 0) != 0)
            return -1;
        if (g_plan.have_cleanup_dirs &&
            (confine_rule_append(rules, &count, g_plan.cleanup_attempt,
                                 CONFINE_LL_READ_DIR |
                                     CONFINE_LL_REMOVE_FILE,
                                 0) != 0 ||
             confine_rule_append(rules, &count, g_plan.cleanup_parent,
                                 CONFINE_LL_REMOVE_DIR, 0) != 0))
            return -1;
        *count_out = count;
        return 0;
    }

    if (role == CONFINE_ROLE_TERMINAL_CLIENT) {
        char interpreter[CONFINE_PATH_MAX];

        for (i = 0U; i < g_plan.root_count; i++) {
            if (confine_rule_append(rules, &count, g_plan.roots[i],
                                    CONFINE_DATA_DIR_RIGHTS, 0) != 0)
                return -1;
        }
        if (confine_rule_append(rules, &count, g_plan.program_path,
                                CONFINE_LL_EXECUTE | CONFINE_LL_READ_FILE,
                                0) != 0)
            return -1;
        if (confine_read_interpreter(g_plan.program_path, interpreter) == 0) {
            if (confine_rule_append(rules, &count, interpreter,
                                    CONFINE_LL_EXECUTE | CONFINE_LL_READ_FILE,
                                    1) != 0)
                return -1;
        }
        if (confine_rule_append(rules, &count, "/lib",
                                CONFINE_LL_READ_FILE | CONFINE_LL_READ_DIR,
                                1) != 0 ||
            confine_rule_append(rules, &count, "/lib64",
                                CONFINE_LL_READ_FILE | CONFINE_LL_READ_DIR,
                                1) != 0 ||
            confine_rule_append(rules, &count, "/usr/lib",
                                CONFINE_LL_READ_FILE | CONFINE_LL_READ_DIR,
                                1) != 0 ||
            confine_rule_append(rules, &count, "/usr/lib64",
                                CONFINE_LL_READ_FILE | CONFINE_LL_READ_DIR,
                                1) != 0 ||
            confine_rule_append(rules, &count, "/etc/ld.so.cache",
                                CONFINE_LL_READ_FILE, 1) != 0 ||
            confine_rule_append(rules, &count, "/etc/ld.so.preload",
                                CONFINE_LL_READ_FILE, 1) != 0)
            return -1;
        /* child_transfer_spawn() opens /dev/null O_RDWR for the child's
         * stdio before it execs (src/child_transfer.c:631). */
        if (confine_rule_append(rules, &count, "/dev/null",
                                CONFINE_LL_READ_FILE | CONFINE_LL_WRITE_FILE,
                                1) != 0)
            return -1;
        if (g_plan.attach_socket_dir[0] != '\0') {
            if (confine_rule_append(rules, &count, g_plan.attach_socket_dir,
                                    CONFINE_LL_MAKE_SOCK |
                                        CONFINE_LL_REMOVE_FILE,
                                    0) != 0)
                return -1;
        }
        *count_out = count;
        return 0;
    }

    /* CONFINE_ROLE_BULK_CLIENT */
    for (i = 0U; i < g_plan.root_count; i++) {
        if (confine_rule_append(rules, &count, g_plan.roots[i],
                                CONFINE_DATA_DIR_RIGHTS, 0) != 0)
            return -1;
    }
    if (g_plan.have_read_file &&
        confine_rule_append(rules, &count, g_plan.read_file,
                            CONFINE_LL_READ_FILE, 0) != 0)
        return -1;
    if (g_plan.have_write_dir &&
        confine_rule_append(rules, &count, g_plan.write_dir,
                            CONFINE_SINK_DIR_RIGHTS, 0) != 0)
        return -1;
    *count_out = count;
    return 0;
}

static int confine_apply_landlock(const char *command, confine_role_t role,
                                  int abi, char *reason, size_t reason_size)
{
    confine_rule_t rules[CONFINE_MAX_RULES];
    struct confine_ruleset_attr attr;
    size_t rule_count;
    size_t i;
    size_t attr_size;
    int ruleset_fd;

    (void)command;
    memset(rules, 0, sizeof(rules));
    if (confine_build_rules(role, rules, &rule_count) != 0) {
        snprintf(reason, reason_size,
                 "rule plan exceeds %zu entr%s", confine_rule_limit(),
                 confine_rule_limit() == 1U ? "y" : "ies");
        return -1;
    }

    memset(&attr, 0, sizeof(attr));
    attr.handled_access_fs = confine_handled_fs(abi);
    if (abi >= 4) {
        /* unmoor speaks UDP only.  Handling the TCP rights with no rule
         * denies every TCP bind and connect from this domain onwards. */
        attr.handled_access_net =
            CONFINE_LL_NET_BIND_TCP | CONFINE_LL_NET_CONNECT_TCP;
        attr_size = sizeof(attr);
    } else {
        attr_size = offsetof(struct confine_ruleset_attr, handled_access_net);
    }

    ruleset_fd = (int)confine_landlock_create_ruleset(&attr, attr_size, 0);
    if (ruleset_fd < 0) {
        snprintf(reason, reason_size, "landlock_create_ruleset: %s",
                 strerror(errno));
        return -1;
    }
    for (i = 0U; i < rule_count; i++) {
        if (confine_add_path(ruleset_fd, &rules[i], abi) < 0) {
            snprintf(reason, reason_size, "landlock rule '%.80s': %.40s",
                     rules[i].path, strerror(errno));
            (void)close(ruleset_fd);
            return -1;
        }
    }
    if (confine_landlock_restrict_self(ruleset_fd, 0) != 0) {
        snprintf(reason, reason_size, "landlock_restrict_self: %s",
                 strerror(errno));
        (void)close(ruleset_fd);
        return -1;
    }
    (void)close(ruleset_fd);
    return 0;
}

/* ------------------------------------------------------------------ *
 * seccomp-bpf
 * ------------------------------------------------------------------ */

#if defined(__x86_64__)
#define CONFINE_AUDIT_ARCH AUDIT_ARCH_X86_64
#define CONFINE_X32_BIT 0x40000000U
#elif defined(__aarch64__)
#define CONFINE_AUDIT_ARCH AUDIT_ARCH_AARCH64
#elif defined(__i386__)
#define CONFINE_AUDIT_ARCH AUDIT_ARCH_I386
#endif

int confine_seccomp_arch_supported(void)
{
#ifdef CONFINE_AUDIT_ARCH
    return 1;
#else
    return 0;
#endif
}

#ifdef CONFINE_AUDIT_ARCH

#define CONFINE_MAX_FILTER 512U

/* The SIGSYS report is assembled by hand: the handler runs after the filter
 * refused a call, and only async-signal-safe work is allowed there. */
static size_t sigsys_append(char *buffer, size_t capacity, size_t length,
                            const char *text)
{
    while (*text != '\0' && length + 1U < capacity)
        buffer[length++] = *text++;
    return length;
}

static size_t sigsys_append_number(char *buffer, size_t capacity,
                                   size_t length, long number)
{
    char digits[24];
    size_t count = 0U;
    unsigned long magnitude;

    if (number < 0) {
        length = sigsys_append(buffer, capacity, length, "-");
        magnitude = (unsigned long)(-(number + 1)) + 1UL;
    } else {
        magnitude = (unsigned long)number;
    }
    do {
        digits[count++] = (char)('0' + (int)(magnitude % 10UL));
        magnitude /= 10UL;
    } while (magnitude != 0UL && count < sizeof(digits));
    while (count > 0U && length + 1U < capacity)
        buffer[length++] = digits[--count];
    return length;
}

static void confine_sigsys_handler(int signal_number, siginfo_t *info,
                                   void *context)
{
    char message[96];
    size_t length = 0U;
    ssize_t written;

    (void)signal_number;
    (void)context;
    if (g_panic_hook != NULL)
        g_panic_hook();
    length = sigsys_append(message, sizeof(message), length,
                           "\r\nunmoor: confine: syscall ");
    length = sigsys_append_number(message, sizeof(message), length,
                                  info != NULL ? (long)info->si_syscall
                                               : -1L);
    length = sigsys_append(message, sizeof(message), length,
                           " denied\r\n");
    written = write(STDERR_FILENO, message, length);
    (void)written;
    _exit(128 + SIGSYS);
}

static int confine_install_sigsys_handler(void)
{
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    action.sa_sigaction = confine_sigsys_handler;
    /* SIGSYS stays blocked while the handler runs. Should the handler's own
     * write be refused by the filter, the kernel falls back to the default
     * action and the process dies instead of re-entering the handler. */
    action.sa_flags = SA_SIGINFO;
    sigemptyset(&action.sa_mask);
    return sigaction(SIGSYS, &action, NULL);
}

static int confine_filter_append(struct sock_filter *filter, size_t *count,
                                 struct sock_filter entry)
{
    if (*count >= CONFINE_MAX_FILTER)
        return -1;
    filter[*count] = entry;
    (*count)++;
    return 0;
}

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define CONFINE_ARGS_OFFSET \
    ((uint32_t)offsetof(struct seccomp_data, args))
#define CONFINE_ARG_LO(index) \
    (CONFINE_ARGS_OFFSET + (uint32_t)(index) * 8U)
#define CONFINE_ARG_HI(index) \
    (CONFINE_ARGS_OFFSET + (uint32_t)(index) * 8U + 4U)
#elif defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define CONFINE_ARGS_OFFSET \
    ((uint32_t)offsetof(struct seccomp_data, args))
#define CONFINE_ARG_LO(index) \
    (CONFINE_ARGS_OFFSET + (uint32_t)(index) * 8U + 4U)
#define CONFINE_ARG_HI(index) \
    (CONFINE_ARGS_OFFSET + (uint32_t)(index) * 8U)
#else
#error "confine seccomp argument filtering needs a known byte order"
#endif

#define CONFINE_FILTER_STMT(code, value) \
    ((struct sock_filter)BPF_STMT((code), (value)))
#define CONFINE_FILTER_JUMP(code, value, yes, no) \
    ((struct sock_filter)BPF_JUMP((code), (value), (yes), (no)))

#ifdef __NR_prctl

static int confine_filter_exact_u64(struct sock_filter *filter, size_t *count,
                                    size_t argument, uint64_t value,
                                    uint32_t default_action)
{
    uint32_t low = (uint32_t)(value & UINT64_C(0xffffffff));
    uint32_t high = (uint32_t)(value >> 32);

    if (confine_filter_append(
            filter, count,
            CONFINE_FILTER_STMT(BPF_LD | BPF_W | BPF_ABS,
                                CONFINE_ARG_LO(argument))) != 0 ||
        confine_filter_append(
            filter, count,
            CONFINE_FILTER_JUMP(BPF_JMP | BPF_JEQ | BPF_K, low, 1, 0)) != 0 ||
        confine_filter_append(filter, count,
                              CONFINE_FILTER_STMT(BPF_RET | BPF_K,
                                                  default_action)) != 0 ||
        confine_filter_append(
            filter, count,
            CONFINE_FILTER_STMT(BPF_LD | BPF_W | BPF_ABS,
                                CONFINE_ARG_HI(argument))) != 0 ||
        confine_filter_append(
            filter, count,
            CONFINE_FILTER_JUMP(BPF_JMP | BPF_JEQ | BPF_K, high, 1, 0)) != 0 ||
        confine_filter_append(filter, count,
                              CONFINE_FILTER_STMT(BPF_RET | BPF_K,
                                                  default_action)) != 0)
        return -1;
    return 0;
}

static int confine_filter_nonzero_u64(struct sock_filter *filter,
                                      size_t *count, size_t argument,
                                      uint32_t default_action)
{
    /* A non-zero low word skips the high-word check and failure return. If
     * the low word is zero, a non-zero high word skips only that return. */
    if (confine_filter_append(
            filter, count,
            CONFINE_FILTER_STMT(BPF_LD | BPF_W | BPF_ABS,
                                CONFINE_ARG_LO(argument))) != 0 ||
        confine_filter_append(
            filter, count,
            CONFINE_FILTER_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0U, 0, 3)) != 0 ||
        confine_filter_append(
            filter, count,
            CONFINE_FILTER_STMT(BPF_LD | BPF_W | BPF_ABS,
                                CONFINE_ARG_HI(argument))) != 0 ||
        confine_filter_append(
            filter, count,
            CONFINE_FILTER_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0U, 0, 1)) != 0 ||
        confine_filter_append(filter, count,
                              CONFINE_FILTER_STMT(BPF_RET | BPF_K,
                                                  default_action)) != 0)
        return -1;
    return 0;
}

static int confine_build_prctl_tuple(struct sock_filter *tuple,
                                     size_t *tuple_count, int option,
                                     uint32_t default_action)
{
    /* The option low word was selected by the caller; reject a noncanonical
     * high word before inspecting its four semantic arguments. */
    if (confine_filter_append(
            tuple, tuple_count,
            CONFINE_FILTER_STMT(BPF_LD | BPF_W | BPF_ABS,
                                CONFINE_ARG_HI(0))) != 0 ||
        confine_filter_append(
            tuple, tuple_count,
            CONFINE_FILTER_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0U, 1, 0)) != 0 ||
        confine_filter_append(tuple, tuple_count,
                              CONFINE_FILTER_STMT(BPF_RET | BPF_K,
                                                  default_action)) != 0)
        return -1;

    if (option == PR_SET_DUMPABLE) {
        if (confine_filter_exact_u64(tuple, tuple_count, 1U, 0U,
                                     default_action) != 0 ||
            confine_filter_exact_u64(tuple, tuple_count, 2U, 0U,
                                     default_action) != 0 ||
            confine_filter_exact_u64(tuple, tuple_count, 3U, 0U,
                                     default_action) != 0 ||
            confine_filter_exact_u64(tuple, tuple_count, 4U, 0U,
                                     default_action) != 0)
            return -1;
    } else if (option == PR_SET_NO_NEW_PRIVS) {
        if (confine_filter_exact_u64(tuple, tuple_count, 1U, 1U,
                                     default_action) != 0 ||
            confine_filter_exact_u64(tuple, tuple_count, 2U, 0U,
                                     default_action) != 0 ||
            confine_filter_exact_u64(tuple, tuple_count, 3U, 0U,
                                     default_action) != 0 ||
            confine_filter_exact_u64(tuple, tuple_count, 4U, 0U,
                                     default_action) != 0)
            return -1;
    } else if (option == PR_SET_SECCOMP) {
        if (confine_filter_exact_u64(tuple, tuple_count, 1U,
                                     (uint64_t)SECCOMP_MODE_FILTER,
                                     default_action) != 0 ||
            confine_filter_nonzero_u64(tuple, tuple_count, 2U,
                                       default_action) != 0 ||
            confine_filter_exact_u64(tuple, tuple_count, 3U, 0U,
                                     default_action) != 0 ||
            confine_filter_exact_u64(tuple, tuple_count, 4U, 0U,
                                     default_action) != 0)
            return -1;
    } else {
        return -1;
    }
    return confine_filter_append(tuple, tuple_count,
                                 CONFINE_FILTER_STMT(BPF_RET | BPF_K,
                                                     SECCOMP_RET_ALLOW));
}

static int confine_filter_prctl_option(struct sock_filter *filter,
                                       size_t *count, int option,
                                       uint32_t default_action)
{
    struct sock_filter tuple[64];
    size_t tuple_count = 0U;
    size_t i;

    if (confine_build_prctl_tuple(tuple, &tuple_count, option,
                                  default_action) != 0 ||
        tuple_count > UINT8_MAX)
        return -1;
    if (confine_filter_append(
            filter, count,
            CONFINE_FILTER_STMT(BPF_LD | BPF_W | BPF_ABS,
                                CONFINE_ARG_LO(0))) != 0 ||
        confine_filter_append(
            filter, count,
            CONFINE_FILTER_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                (uint32_t)option, 0,
                                (uint8_t)tuple_count)) != 0)
        return -1;
    for (i = 0U; i < tuple_count; i++) {
        if (confine_filter_append(filter, count, tuple[i]) != 0)
            return -1;
    }
    return 0;
}

static int confine_filter_prctl(struct sock_filter *filter, size_t *count,
                                uint32_t default_action)
{
    size_t branch_index = *count;
    size_t policy_start;
    size_t policy_count;

    if (confine_filter_append(
            filter, count,
            CONFINE_FILTER_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                (uint32_t)__NR_prctl, 0, 0)) != 0)
        return -1;
    policy_start = *count;
    if (confine_filter_prctl_option(filter, count, PR_SET_DUMPABLE,
                                    default_action) != 0 ||
        confine_filter_prctl_option(filter, count, PR_SET_NO_NEW_PRIVS,
                                    default_action) != 0 ||
        confine_filter_prctl_option(filter, count, PR_SET_SECCOMP,
                                    default_action) != 0 ||
        confine_filter_append(filter, count,
                              CONFINE_FILTER_STMT(BPF_RET | BPF_K,
                                                  default_action)) != 0)
        return -1;
    policy_count = *count - policy_start;
    if (policy_count > UINT8_MAX)
        return -1;
    filter[branch_index].jf = (uint8_t)policy_count;
    return 0;
}

#endif /* __NR_prctl */

#if defined(__NR_fcntl) || defined(__NR_fcntl64)

static int confine_build_server_fcntl_tuple(
    struct sock_filter *tuple, size_t *tuple_count, int command,
    uint32_t default_action)
{
    if (confine_filter_exact_u64(tuple, tuple_count, 1U,
                                 (uint64_t)(unsigned int)command,
                                 default_action) != 0)
        return -1;
    if (command == F_SETFD) {
        /* musl redundantly sets CLOEXEC after open(O_CLOEXEC). Only setting
         * this descriptor-local bit is permitted: no clearing, duplication,
         * shared status mutation or truncated high-word argument aliases. */
        if (confine_filter_append(
                tuple, tuple_count,
                CONFINE_FILTER_STMT(BPF_LD | BPF_W | BPF_ABS,
                                    CONFINE_ARG_HI(0))) != 0 ||
            confine_filter_append(
                tuple, tuple_count,
                CONFINE_FILTER_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                    0U, 1, 0)) != 0 ||
            confine_filter_append(tuple, tuple_count,
                                  CONFINE_FILTER_STMT(BPF_RET | BPF_K,
                                                      default_action)) != 0 ||
            confine_filter_exact_u64(tuple, tuple_count, 2U,
                                     (uint64_t)FD_CLOEXEC,
                                     default_action) != 0)
            return -1;
    } else if (confine_filter_exact_u64(tuple, tuple_count, 0U,
                                        (uint64_t)STDERR_FILENO,
                                        default_action) != 0) {
        return -1;
    }
    if (command == F_SETFL) {
        /* The bounded SIGUSR1/event writer only toggles O_NONBLOCK on fd 2.
         * In particular, O_ASYNC is excluded so an inherited descriptor can
         * never become a second signal-delivery route. */
        if (confine_filter_append(
                tuple, tuple_count,
                CONFINE_FILTER_STMT(BPF_LD | BPF_W | BPF_ABS,
                                    CONFINE_ARG_LO(2))) != 0 ||
            confine_filter_append(
                tuple, tuple_count,
                CONFINE_FILTER_JUMP(BPF_JMP | BPF_JSET | BPF_K,
                                    (uint32_t)O_ASYNC, 0, 1)) != 0 ||
            confine_filter_append(tuple, tuple_count,
                                  CONFINE_FILTER_STMT(BPF_RET | BPF_K,
                                                      default_action)) != 0 ||
            confine_filter_append(
                tuple, tuple_count,
                CONFINE_FILTER_STMT(BPF_LD | BPF_W | BPF_ABS,
                                    CONFINE_ARG_HI(2))) != 0 ||
            confine_filter_append(
                tuple, tuple_count,
                CONFINE_FILTER_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                    0U, 1, 0)) != 0 ||
            confine_filter_append(tuple, tuple_count,
                                  CONFINE_FILTER_STMT(BPF_RET | BPF_K,
                                                      default_action)) != 0)
            return -1;
    }
    return confine_filter_append(tuple, tuple_count,
                                 CONFINE_FILTER_STMT(BPF_RET | BPF_K,
                                                     SECCOMP_RET_ALLOW));
}

static int confine_filter_server_fcntl_option(
    struct sock_filter *filter, size_t *count, int command,
    uint32_t default_action)
{
    struct sock_filter tuple[48];
    size_t tuple_count = 0U;
    size_t i;

    if (confine_build_server_fcntl_tuple(
            tuple, &tuple_count, command, default_action) != 0 ||
        tuple_count > UINT8_MAX)
        return -1;
    if (confine_filter_append(
            filter, count,
            CONFINE_FILTER_STMT(BPF_LD | BPF_W | BPF_ABS,
                                CONFINE_ARG_LO(1))) != 0 ||
        confine_filter_append(
            filter, count,
            CONFINE_FILTER_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                (uint32_t)command, 0,
                                (uint8_t)tuple_count)) != 0)
        return -1;
    for (i = 0U; i < tuple_count; i++)
        if (confine_filter_append(filter, count, tuple[i]) != 0)
            return -1;
    return 0;
}

static int confine_filter_server_fcntl(
    struct sock_filter *filter, size_t *count, int syscall_number,
    uint32_t default_action)
{
    size_t branch_index = *count;
    size_t policy_start;
    size_t policy_count;

    if (confine_filter_append(
            filter, count,
            CONFINE_FILTER_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                (uint32_t)syscall_number, 0, 0)) != 0)
        return -1;
    policy_start = *count;
    if (confine_filter_server_fcntl_option(
            filter, count, F_GETFL, default_action) != 0 ||
        confine_filter_server_fcntl_option(
            filter, count, F_SETFL, default_action) != 0 ||
        confine_filter_server_fcntl_option(
            filter, count, F_SETFD, default_action) != 0 ||
        confine_filter_append(filter, count,
                              CONFINE_FILTER_STMT(BPF_RET | BPF_K,
                                                  default_action)) != 0)
        return -1;
    policy_count = *count - policy_start;
    if (policy_count > UINT8_MAX)
        return -1;
    filter[branch_index].jf = (uint8_t)policy_count;
    return 0;
}

#endif /* __NR_fcntl || __NR_fcntl64 */

/* The one-shot server reuses the already-open-fd/memory/time base, adds its
 * own narrow namespace table, and removes base operations that Landlock
 * cannot scope to its selected GET/PUT and deaddrop objects.  Keep this deny
 * set explicit: allowing one of these on an older Landlock ABI would turn a
 * path policy into ambient same-UID mutation, and signalling is outside the
 * server-confinement role on every ABI. */
static int confine_server_syscall_forbidden(int number)
{
#ifdef __NR_tgkill
    if (number == __NR_tgkill)
        return 1;
#endif
#ifdef __NR_tkill
    if (number == __NR_tkill)
        return 1;
#endif
#ifdef __NR_kill
    if (number == __NR_kill)
        return 1;
#endif
#ifdef __NR_rt_sigqueueinfo
    if (number == __NR_rt_sigqueueinfo)
        return 1;
#endif
#ifdef __NR_rt_tgsigqueueinfo
    if (number == __NR_rt_tgsigqueueinfo)
        return 1;
#endif
#ifdef __NR_pidfd_send_signal
    if (number == __NR_pidfd_send_signal)
        return 1;
#endif
#ifdef __NR_chmod
    if (number == __NR_chmod)
        return 1;
#endif
#ifdef __NR_fchmod
    if (number == __NR_fchmod)
        return 1;
#endif
#ifdef __NR_fchmodat
    if (number == __NR_fchmodat)
        return 1;
#endif
#ifdef __NR_fchmodat2
    if (number == __NR_fchmodat2)
        return 1;
#endif
#ifdef __NR_chown
    if (number == __NR_chown)
        return 1;
#endif
#ifdef __NR_lchown
    if (number == __NR_lchown)
        return 1;
#endif
#ifdef __NR_fchown
    if (number == __NR_fchown)
        return 1;
#endif
#ifdef __NR_fchownat
    if (number == __NR_fchownat)
        return 1;
#endif
#ifdef __NR_truncate
    if (number == __NR_truncate)
        return 1;
#endif
#ifdef __NR_truncate64
    if (number == __NR_truncate64)
        return 1;
#endif
#ifdef __NR_ftruncate
    if (number == __NR_ftruncate)
        return 1;
#endif
#ifdef __NR_ftruncate64
    if (number == __NR_ftruncate64)
        return 1;
#endif
#ifdef __NR_fallocate
    if (number == __NR_fallocate)
        return 1;
#endif
#ifdef __NR_utime
    if (number == __NR_utime)
        return 1;
#endif
#ifdef __NR_utimes
    if (number == __NR_utimes)
        return 1;
#endif
#ifdef __NR_futimesat
    if (number == __NR_futimesat)
        return 1;
#endif
#ifdef __NR_utimensat
    if (number == __NR_utimensat)
        return 1;
#endif
#ifdef __NR_utimensat_time64
    if (number == __NR_utimensat_time64)
        return 1;
#endif
#ifdef __NR_ioctl
    if (number == __NR_ioctl)
        return 1;
#endif
#ifdef __NR_prlimit64
    if (number == __NR_prlimit64)
        return 1;
#endif
#ifdef __NR_newfstatat
    if (number == __NR_newfstatat)
        return 1;
#endif
#ifdef __NR_fstatat64
    if (number == __NR_fstatat64)
        return 1;
#endif
#ifdef __NR_statx
    if (number == __NR_statx)
        return 1;
#endif
#ifdef __NR_fstatfs
    if (number == __NR_fstatfs)
        return 1;
#endif
#ifdef __NR_fstatfs64
    if (number == __NR_fstatfs64)
        return 1;
#endif
    return 0;
}

static int confine_collect_syscalls(confine_role_t role, int *numbers,
                                    size_t capacity, size_t *count_out)
{
    const int *groups[5];
    size_t sizes[5];
    size_t group_count = 0U;
    size_t count = 0U;
    size_t g;

    /* Every table ends in a 0 sentinel that keeps it non-empty on a port
     * where every entry is #ifdef'd out.  The sentinel must never reach the
     * filter: syscall 0 is read() on x86_64 but io_setup() on aarch64. */
#define CONFINE_ADD_GROUP(table)                                    \
    do {                                                            \
        groups[group_count] = (table);                              \
        sizes[group_count++] = sizeof(table) / sizeof(int) - 1U;    \
    } while (0)

    CONFINE_ADD_GROUP(confine_group_base);
    if (confine_role_is_server(role)) {
        CONFINE_ADD_GROUP(confine_group_server_files);
    } else if (!confine_role_is_attach(role)) {
        CONFINE_ADD_GROUP(confine_group_net);
        CONFINE_ADD_GROUP(confine_group_files);
        CONFINE_ADD_GROUP(confine_group_reap);
    }
    if (role == CONFINE_ROLE_TERMINAL_CLIENT)
        CONFINE_ADD_GROUP(confine_group_exec);
#undef CONFINE_ADD_GROUP
    for (g = 0U; g < group_count; g++) {
        size_t i;

        for (i = 0U; i < sizes[g]; i++) {
            size_t j;
            int already = 0;

            if (confine_role_is_server(role) &&
                confine_server_syscall_forbidden(groups[g][i]))
                continue;
            for (j = 0U; j < count; j++) {
                if (numbers[j] == groups[g][i]) {
                    already = 1;
                    break;
                }
            }
            if (already)
                continue;
            if (count >= capacity)
                return -1;
            numbers[count++] = groups[g][i];
        }
    }
    *count_out = count;
    return 0;
}

static int confine_apply_seccomp(confine_role_t role, char *reason,
                                 size_t reason_size)
{
    struct sock_filter filter[CONFINE_MAX_FILTER];
    struct sock_fprog program;
    int numbers[CONFINE_MAX_FILTER];
    size_t syscall_count = 0U;
    size_t count = 0U;
    size_t i;
    uint32_t default_action = confine_role_traps(role)
                                  ? (uint32_t)SECCOMP_RET_TRAP
                                  : (uint32_t)SECCOMP_RET_KILL_PROCESS;

    if (confine_collect_syscalls(role, numbers, CONFINE_MAX_FILTER,
                                 &syscall_count) != 0) {
        snprintf(reason, reason_size, "seccomp table overflow");
        return -1;
    }
    /* An allow-list that misses one loader syscall turns into an
     * unexplainable SIGSEGV under SECCOMP_RET_ERRNO, so this filter never
     * uses ERRNO: the terminal client traps (catchable, tty restored) and
     * every other role dies loudly. */
    if (confine_role_traps(role) &&
        confine_install_sigsys_handler() != 0) {
        snprintf(reason, reason_size, "SIGSYS handler: %s", strerror(errno));
        return -1;
    }

#define CONFINE_EMIT(entry)                                        \
    do {                                                           \
        struct sock_filter emitted = entry;                        \
        if (confine_filter_append(filter, &count, emitted) != 0) { \
            snprintf(reason, reason_size, "seccomp filter overflow"); \
            return -1;                                             \
        }                                                          \
    } while (0)

    /* arch */
    CONFINE_EMIT(BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                          (uint32_t)offsetof(struct seccomp_data, arch)));
    CONFINE_EMIT(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                          (uint32_t)CONFINE_AUDIT_ARCH, 1, 0));
    CONFINE_EMIT(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    /* syscall number */
    CONFINE_EMIT(BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                          (uint32_t)offsetof(struct seccomp_data, nr)));
#ifdef CONFINE_X32_BIT
    /* x32 shares the x86_64 audit arch but renumbers; refuse it outright. */
    CONFINE_EMIT(BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, CONFINE_X32_BIT, 0, 1));
    CONFINE_EMIT(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
#endif
    for (i = 0U; i < syscall_count; i++) {
#ifdef __NR_prctl
        if (numbers[i] == __NR_prctl) {
            if (confine_filter_prctl(filter, &count, default_action) != 0) {
                snprintf(reason, reason_size, "seccomp prctl filter overflow");
                return -1;
            }
            continue;
        }
#endif
#if defined(__NR_fcntl) || defined(__NR_fcntl64)
        if (confine_role_is_server(role) &&
#ifdef __NR_fcntl
            (numbers[i] == __NR_fcntl
#ifdef __NR_fcntl64
             || numbers[i] == __NR_fcntl64
#endif
            )) {
#else
            numbers[i] == __NR_fcntl64) {
#endif
            if (confine_filter_server_fcntl(
                    filter, &count, numbers[i], default_action) != 0) {
                snprintf(reason, reason_size,
                         "seccomp server fcntl filter overflow");
                return -1;
            }
            continue;
        }
#endif
        CONFINE_EMIT(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                              (uint32_t)numbers[i], 0, 1));
        CONFINE_EMIT(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    }
    CONFINE_EMIT(BPF_STMT(BPF_RET | BPF_K, default_action));
#undef CONFINE_EMIT

    memset(&program, 0, sizeof(program));
    program.len = (unsigned short)count;
    program.filter = filter;
    if (prctl(PR_SET_SECCOMP, (long)SECCOMP_MODE_FILTER, &program,
              0L, 0L) != 0) {
        snprintf(reason, reason_size, "PR_SET_SECCOMP: %s", strerror(errno));
        return -1;
    }
    return 0;
}

#else /* !CONFINE_AUDIT_ARCH */

static int confine_apply_seccomp(confine_role_t role, char *reason,
                                 size_t reason_size)
{
    (void)role;
    snprintf(reason, reason_size, "no seccomp syscall table for this arch");
    return -1;
}

#endif /* CONFINE_AUDIT_ARCH */

enum {
    CONFINE_PREFLIGHT_PROBE_OK = 0,
    CONFINE_PREFLIGHT_PROBE_LANDLOCK = 21,
    CONFINE_PREFLIGHT_PROBE_SECCOMP = 22
};

static int confine_probe_landlock_install(int abi)
{
    struct confine_ruleset_attr attr;
    confine_rule_t root_rule;
    size_t attr_size;
    int ruleset_fd;
    int result = -1;

    memset(&attr, 0, sizeof(attr));
    attr.handled_access_fs = confine_handled_fs(abi);
    if (abi >= 4) {
        attr.handled_access_net =
            CONFINE_LL_NET_BIND_TCP | CONFINE_LL_NET_CONNECT_TCP;
        attr_size = sizeof(attr);
    } else {
        attr_size = offsetof(struct confine_ruleset_attr,
                             handled_access_net);
    }
    ruleset_fd = (int)confine_landlock_create_ruleset(
        &attr, attr_size, 0);
    if (ruleset_fd < 0)
        return -1;
    memset(&root_rule, 0, sizeof(root_rule));
    memcpy(root_rule.path, "/", 2U);
    root_rule.access = confine_handled_fs(abi);
    if (confine_add_path(ruleset_fd, &root_rule, abi) == 1 &&
        confine_landlock_restrict_self(ruleset_fd, 0) == 0)
        result = 0;
    {
        int saved_errno = errno;

        (void)close(ruleset_fd);
        errno = saved_errno;
    }
    return result;
}

/* Prove real Landlock rule installation and the exact server seccomp filter
 * in a disposable child.  Installing either policy in the command process
 * would consume the one-way narrowing before REQUEST supplies its path. */
static int confine_probe_mechanisms(int abi, char *reason,
                                    size_t reason_size)
{
    pid_t pid;
    pid_t waited;
    int status = 0;

    pid = fork();
    if (pid < 0) {
        snprintf(reason, reason_size, "probe fork: %s", strerror(errno));
        return -1;
    }
    if (pid == 0) {
#if defined(UNMOOR_CONFINE_TEST)
        if (g_test_preflight_failure == CONFINE_PREFLIGHT_PROBE_LANDLOCK)
            _exit(CONFINE_PREFLIGHT_PROBE_LANDLOCK);
#endif
        if (confine_probe_landlock_install(abi) != 0)
            _exit(CONFINE_PREFLIGHT_PROBE_LANDLOCK);
#if defined(UNMOOR_CONFINE_TEST)
        if (g_test_preflight_failure == CONFINE_PREFLIGHT_PROBE_SECCOMP)
            _exit(CONFINE_PREFLIGHT_PROBE_SECCOMP);
#endif
        if (confine_apply_seccomp(CONFINE_ROLE_BULK_SERVER,
                                  reason, reason_size) != 0)
            _exit(CONFINE_PREFLIGHT_PROBE_SECCOMP);
        _exit(CONFINE_PREFLIGHT_PROBE_OK);
    }
    do {
        waited = waitpid(pid, &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited != pid) {
        snprintf(reason, reason_size, "probe wait: %s", strerror(errno));
        return -1;
    }
    if (WIFEXITED(status) &&
        WEXITSTATUS(status) == CONFINE_PREFLIGHT_PROBE_OK)
        return 0;
    if (WIFEXITED(status) &&
        WEXITSTATUS(status) == CONFINE_PREFLIGHT_PROBE_LANDLOCK) {
        snprintf(reason, reason_size, "Landlock install probe failed");
    } else if (WIFEXITED(status) &&
               WEXITSTATUS(status) == CONFINE_PREFLIGHT_PROBE_SECCOMP) {
        snprintf(reason, reason_size, "seccomp install probe failed");
    } else if (WIFSIGNALED(status)) {
        snprintf(reason, reason_size, "install probe died by signal %d",
                 WTERMSIG(status));
    } else {
        snprintf(reason, reason_size, "install probe returned no verdict");
    }
    return -1;
}

/* ------------------------------------------------------------------ *
 * Entry point
 * ------------------------------------------------------------------ */

#if defined(UNMOOR_SANITIZER)
#define CONFINE_SANITIZER_BUILD 1
#else
#define CONFINE_SANITIZER_BUILD 0
#endif

static int confine_degrade(const char *command, confine_role_t role,
                           const char *what, const char *reason)
{
    const int server = confine_role_is_server(role);

    if (g_plan.level == CONFINE_LEVEL_REQUIRE) {
        fprintf(stderr,
                "%s: %s confinement required but unavailable: %s (%s); "
                "refusing; use --%sconfine=best-effort to continue at your "
                "own security risk\n",
                command, server ? "server" : "client", what, reason,
                server ? "server-" : "");
        return -1;
    }
    fprintf(stderr, "%s: %s confinement reduced: %s (%s)\n", command,
            server ? "server" : "client", what, reason);
    return 0;
}

/*
 * Client confinement: the terminal client's writable data scope is the
 * current working directory plus every explicit --confine-root.
 * Child-transfer operands are resolved against this same set before the
 * fork.  When a Landlock domain was actually installed, a path outside it
 * is refused by name instead of dying inside the child; best-effort
 * degradation preserves functionality because no absent filesystem domain
 * is imitated here.
 */
static int confine_add_cwd_root(const char *command)
{
    char cwd[CONFINE_PATH_MAX];
    const char *home;
    size_t i;

    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        fprintf(stderr, "%s: cannot read the working directory: %s\n", command,
                strerror(errno));
        return -1;
    }
    for (i = 0U; i < g_plan.root_count; i++) {
        if (strcmp(g_plan.roots[i], cwd) == 0)
            return 0;
    }
    if (confine_scope_add_root(command, cwd) != 0)
        return -1;
    home = getenv("HOME");
    if (home != NULL && home[0] == '/' && strcmp(home, cwd) == 0)
        fprintf(stderr,
                "%s: client confinement data root is $HOME (the working "
                "directory); use --confine-root for a narrower scope\n",
                command);
    return 0;
}

int confine_preflight(const char *command, confine_role_t role)
{
    char reason[160];
    int abi;

    confine_plan_init();
    if (!confine_role_is_server(role))
        return -1;
    if (g_plan.level == CONFINE_LEVEL_OFF)
        return 0;
    if (g_plan.server_preflight_complete)
        return g_plan.server_preflight_degraded ? 1 : 0;
    if (CONFINE_SANITIZER_BUILD) {
        if (g_plan.level == CONFINE_LEVEL_BEST_EFFORT)
            return confine_server_mark_preflight_degraded(
                "Landlock/seccomp disabled by sanitizer build");
        fprintf(stderr,
                "%s: --server-confine require is not available in a "
                "sanitizer build; refusing; use "
                "--server-confine=best-effort to continue at your own "
                "security risk\n",
                command);
        return -1;
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L) != 0) {
        snprintf(reason, sizeof(reason), "%s", strerror(errno));
        if (g_plan.level == CONFINE_LEVEL_REQUIRE)
            return confine_degrade(command, role, "PR_SET_NO_NEW_PRIVS",
                                   reason);
        return confine_server_mark_preflight_degraded(reason);
    }
    abi = confine_landlock_abi();
    if (abi < 3) {
        static const char unavailable[] =
            "Landlock ABI 3 or newer required for file truncation mediation";

        if (g_plan.level == CONFINE_LEVEL_REQUIRE)
            return confine_degrade(command, role, "Landlock",
                                   unavailable);
        return confine_server_mark_preflight_degraded(unavailable);
    }
    if (!confine_seccomp_arch_supported() || !UNMOOR_FD_STAT_DIRECT) {
        static const char unsupported[] =
            "server confinement requires native LP64 x86_64 or aarch64";

        if (g_plan.level == CONFINE_LEVEL_REQUIRE)
            return confine_degrade(command, role, "server architecture",
                                   unsupported);
        return confine_server_mark_preflight_degraded(unsupported);
    }
    if (confine_probe_mechanisms(abi, reason, sizeof(reason)) != 0) {
        if (g_plan.level == CONFINE_LEVEL_REQUIRE)
            return confine_degrade(command, role, "install preflight",
                                   reason);
        return confine_server_mark_preflight_degraded(reason);
    }
    g_plan.server_preflight_complete = 1;
    return 0;
}

int confine_apply(const char *command, confine_role_t role)
{
    char reason[160];
    const int server = confine_role_is_server(role);
    int abi;

    confine_plan_init();
    if (g_plan.applied)
        return 0;
    g_plan.applied = 1;
    g_plan.landlock_installed = 0;
    g_plan.seccomp_installed = 0;
    if (g_plan.level == CONFINE_LEVEL_OFF)
        return 0;
    if (server && g_plan.server_preflight_complete &&
        g_plan.server_preflight_degraded)
        return 0;
    if (server && !g_plan.server_preflight_complete) {
        fprintf(stderr,
                "%s: server confinement preflight was not completed; "
                "refusing\n",
                command);
        return -1;
    }
    if (role == CONFINE_ROLE_TERMINAL_CLIENT &&
        confine_add_cwd_root(command) != 0) {
        if (g_plan.level == CONFINE_LEVEL_REQUIRE)
            return -1;
        fprintf(stderr,
                "%s: confine: the working directory could not be added to "
                "the filesystem policy; continuing without confinement "
                "under --confine=best-effort\n",
                command);
        return 0;
    }

    /* LeakSanitizer needs ptrace, tgkill, process_vm_readv and
     * /proc/self/maps at exit; confinement and a sanitizer build cannot both
     * be honest, so the sanitizer build refuses rather than pretends.  This
     * is a compile-time constant tested with an ordinary `if` so that every
     * helper below stays referenced and the sanitizer build has no
     * unused-function or unused-variable warning of its own. */
    if (CONFINE_SANITIZER_BUILD) {
        if (g_plan.level == CONFINE_LEVEL_REQUIRE) {
            fprintf(stderr,
                    "%s: --%sconfine require is not available in a sanitizer "
                    "build; refusing; use --%sconfine=best-effort to continue "
                    "at your own security risk\n",
                    command,
                    server ? "server-" : "",
                    server ? "server-" : "");
            return -1;
        }
        fprintf(stderr,
                "%s: %s confinement disabled (sanitizer build)\n",
                command,
                server ? "server" : "client");
        return 0;
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L) != 0) {
        snprintf(reason, sizeof(reason), "%s", strerror(errno));
        if (server) {
            fprintf(stderr,
                    "%s: server confinement changed after preflight: "
                    "PR_SET_NO_NEW_PRIVS (%s); refusing\n",
                    command, reason);
            return -1;
        }
        return confine_degrade(command, role, "PR_SET_NO_NEW_PRIVS", reason);
    }
    abi = confine_landlock_abi();
    if (abi < 1 || (server && abi < 3)) {
        if (server) {
            fprintf(stderr,
                    "%s: server confinement changed after preflight: "
                    "Landlock unavailable; refusing\n",
                    command);
            return -1;
        }
        if (confine_degrade(command, role, "Landlock unavailable",
                            "landlock_create_ruleset(VERSION) failed") != 0)
            return -1;
    } else if (confine_apply_landlock(command, role, abi, reason,
                                      sizeof(reason)) != 0) {
        if (server) {
            fprintf(stderr,
                    "%s: server confinement path install failed after "
                    "preflight: %s; refusing\n",
                    command, reason);
            return -1;
        }
        if (confine_degrade(command, role, "Landlock", reason) != 0)
            return -1;
    } else {
        g_plan.landlock_installed = 1;
    }
    if (confine_apply_seccomp(role, reason, sizeof(reason)) != 0) {
        if (server) {
            fprintf(stderr,
                    "%s: server confinement syscall install failed after "
                    "preflight: %s; refusing\n",
                    command, reason);
            return -1;
        }
        if (confine_degrade(command, role, "seccomp", reason) != 0)
            return -1;
    } else {
        g_plan.seccomp_installed = 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ *
 * Test seams.  Compiled only into a confinement test build with
 * -DUNMOOR_CONFINE_TEST=1; `make hygiene` asserts the production binary
 * exports no confine_test_ symbol.
 * ------------------------------------------------------------------ */

#if defined(UNMOOR_CONFINE_TEST)

unsigned long long confine_test_handled_fs(int abi)
{
    return (unsigned long long)confine_handled_fs(abi);
}

unsigned long long confine_test_file_rights(int abi)
{
    return (unsigned long long)confine_file_rights(abi);
}

size_t confine_test_rule_count(confine_role_t role)
{
    confine_rule_t rules[CONFINE_MAX_RULES];
    size_t count = 0U;

    confine_plan_init();
    memset(rules, 0, sizeof(rules));
    if (confine_build_rules(role, rules, &count) != 0)
        return SIZE_MAX;
    return count;
}

void confine_test_set_rule_limit(size_t limit)
{
    g_test_rule_limit = limit <= CONFINE_MAX_RULES ? limit
                                                    : CONFINE_MAX_RULES;
}

void confine_test_set_preflight_failure(int stage)
{
    if (stage == CONFINE_TEST_PREFLIGHT_FAIL_LANDLOCK)
        g_test_preflight_failure = CONFINE_PREFLIGHT_PROBE_LANDLOCK;
    else if (stage == CONFINE_TEST_PREFLIGHT_FAIL_SECCOMP)
        g_test_preflight_failure = CONFINE_PREFLIGHT_PROBE_SECCOMP;
    else
        g_test_preflight_failure = CONFINE_PREFLIGHT_PROBE_OK;
}

int confine_test_apply_landlock(const char *command, confine_role_t role)
{
    char reason[160];
    int abi = confine_landlock_abi();

    confine_plan_init();
    if (abi <= 0)
        return -1;
    if (prctl(PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L) != 0)
        return -1;
    if (confine_apply_landlock(command, role, abi, reason,
                               sizeof(reason)) != 0) {
        fprintf(stderr, "confine_test: landlock: %s\n", reason);
        return -1;
    }
    return 0;
}

int confine_test_apply_seccomp(confine_role_t role)
{
    char reason[160];

    confine_plan_init();
    if (prctl(PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L) != 0)
        return -1;
    if (confine_apply_seccomp(role, reason, sizeof(reason)) != 0) {
        fprintf(stderr, "confine_test: seccomp: %s\n", reason);
        return -1;
    }
    return 0;
}

int confine_test_syscall_allowed(confine_role_t role, int number)
{
#ifdef CONFINE_AUDIT_ARCH
    int numbers[CONFINE_MAX_FILTER];
    size_t count = 0U;
    size_t i;

    if (confine_collect_syscalls(role, numbers, CONFINE_MAX_FILTER,
                                 &count) != 0)
        return -1;
    for (i = 0U; i < count; i++) {
        if (numbers[i] == number)
            return 1;
    }
    return 0;
#else
    (void)role;
    (void)number;
    return -1;
#endif
}

size_t confine_test_syscall_count(confine_role_t role)
{
#ifdef CONFINE_AUDIT_ARCH
    int numbers[CONFINE_MAX_FILTER];
    size_t count = 0U;

    if (confine_collect_syscalls(role, numbers, CONFINE_MAX_FILTER,
                                 &count) != 0)
        return 0U;
    return count;
#else
    (void)role;
    return 0U;
#endif
}

void confine_test_set_installed(int landlock_installed,
                                int seccomp_installed)
{
    confine_plan_init();
    g_plan.landlock_installed = landlock_installed != 0;
    g_plan.seccomp_installed = seccomp_installed != 0;
}

#endif /* UNMOOR_CONFINE_TEST */

#endif /* __linux__ */
