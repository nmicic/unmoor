/*
 * monitor_worker.c — composed, fixed-channel listener-monitor STORE/PLAN worker
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "monitor_worker.h"
#include "monitor_worker_native.h"
#include "monitor_platform.h"
#include "sync_work_carriage.h"
#include <errno.h>
#include <stdint.h>
#include <unistd.h>

#define WORKER_UNMASKABLE ((UINT64_C(1) << 8) | (UINT64_C(1) << 18))
#define WORKER_BLOCKED (~WORKER_UNMASKABLE)

_Static_assert(sizeof(monitor_worker_birth_t) == 24, "worker birth budget");
_Static_assert(sizeof(sync_work_carriage_t) == 17056, "worker carriage budget");
_Static_assert(sizeof(sync_work_io_t) == 24 && sizeof(sync_work_callbacks_t) == 24,
               "worker adapter budget");

int monitor_worker_supported(void) { return WORKER_NATIVE_SUPPORTED; }

#if WORKER_NATIVE_SUPPORTED
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>

_Static_assert(sizeof(struct pollfd) == 8 && sizeof(struct rlimit) == 16 &&
               sizeof(struct sock_fprog) == 16 && sizeof(struct sock_filter) == 8,
               "worker native setup budget");
_Static_assert(sizeof(sync_source_map_layout_t) == 40 &&
               sizeof(sync_source_map_t) == 48 && sizeof(sync_repair_view_t) == 200,
               "worker mapping and decode budgets");

/* Pre-seal only. The post-seal boundary never reads or writes libc errno. */
static int worker_status(long result)
{
    if (result == 0) return 0;
    errno = result < 0 && result >= -4095 ? (int)-result : EPROTO;
    return -1;
}

static long worker_mask(const uint64_t *set, uint64_t *get)
{
    return worker_native_call(SYS_rt_sigprocmask, SIG_SETMASK,
        (unsigned long)set, (unsigned long)get, 8, 0, 0);
}
#endif

int monitor_worker_block_for_fork(uint64_t *saved)
{
    if (saved == NULL) { errno = EINVAL; return -1; }
#if WORKER_NATIVE_SUPPORTED
    uint64_t mask = WORKER_BLOCKED;
    if (worker_status(worker_mask(&mask, saved)) != 0 ||
        worker_status(worker_mask(NULL, &mask)) != 0) return -1;
    if (mask != WORKER_BLOCKED) { errno = EPROTO; return -1; }
    return 0;
#else
    errno = ENOTSUP;
    return -1;
#endif
}

int monitor_worker_restore_after_fork(uint64_t saved)
{
    if (saved & WORKER_UNMASKABLE) { errno = EINVAL; return -1; }
#if WORKER_NATIVE_SUPPORTED
    uint64_t mask = 0;
    if (worker_status(worker_mask(&saved, NULL)) != 0 ||
        worker_status(worker_mask(NULL, &mask)) != 0) return -1;
    if (mask != saved) { errno = EPROTO; return -1; }
    return 0;
#else
    (void)saved;
    errno = ENOTSUP;
    return -1;
#endif
}

#if WORKER_NATIVE_SUPPORTED
static int worker_normalize_signals(void)
{
    /* Two actions and ONE reused mask word:72 bytes, not an inherited
     * action backup table. Every catchable kernel signal, including32/33. */
    worker_kernel_action_t wanted = {0}, observed = {0};
    uint64_t mask = 0;
    if (worker_status(worker_mask(NULL, &mask)) != 0) return -1;
    if (mask != WORKER_BLOCKED) { errno = EPROTO; return -1; }
    for (unsigned sig = 1; sig <= 64; ++sig) {
        if (sig == SIGKILL || sig == SIGSTOP) continue;
        wanted.handler = sig == SIGPIPE ? SIG_IGN : SIG_DFL;
        if (worker_status(worker_native_call(SYS_rt_sigaction, sig,
                (unsigned long)&wanted, 0, 8, 0, 0)) != 0 ||
            worker_status(worker_native_call(SYS_rt_sigaction, sig,
                0, (unsigned long)&observed, 8, 0, 0)) != 0) return -1;
        if (observed.handler != wanted.handler || observed.flags != 0 ||
            observed.restorer != NULL || observed.mask != 0) {
            errno = EPROTO; return -1;
        }
    }
    mask = 0;
    if (worker_status(worker_mask(&mask, NULL)) != 0 ||
        worker_status(worker_mask(NULL, &mask)) != 0) return -1;
    if (mask != 0) { errno = EPROTO; return -1; }
    return 0;
}

static int worker_process_policy(void)
{
    struct rlimit core = {0};
    if (worker_status(worker_native_call(SYS_prlimit64, 0, RLIMIT_CORE,
            0, (unsigned long)&core, 0, 0)) != 0) return -1;
    rlim_t hard = core.rlim_max;
    core.rlim_cur = 0;
    if (worker_status(worker_native_call(SYS_prlimit64, 0, RLIMIT_CORE,
            (unsigned long)&core, 0, 0, 0)) != 0 ||
        worker_status(worker_native_call(SYS_prlimit64, 0, RLIMIT_CORE,
            0, (unsigned long)&core, 0, 0)) != 0) return -1;
    if (core.rlim_cur != 0 || core.rlim_max != hard) {
        errno = EPROTO; return -1;
    }
    if (worker_status(worker_native_call(SYS_prctl, PR_SET_DUMPABLE,
            0, 0, 0, 0, 0)) != 0) return -1;
    return worker_status(worker_native_call(SYS_prctl, PR_GET_DUMPABLE,
                                             0, 0, 0, 0, 0));
}

#if defined(__x86_64__)
#define WORKER_AUDIT_ARCH AUDIT_ARCH_X86_64
#else
#define WORKER_AUDIT_ARCH AUDIT_ARCH_AARCH64
#endif
#define WORKER_LD(offset) BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (uint32_t)(offset))
#define WORKER_KILL BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS)
#define WORKER_ALLOW BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
/* Each equality check is3 instructions: false fails here, true skips KILL. */
#define WORKER_EQ(offset, value) WORKER_LD(offset), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, value, 1, 0), WORKER_KILL
#define WORKER_LO(arg) offsetof(struct seccomp_data, args[arg])
#define WORKER_HI(arg) (WORKER_LO(arg) + 4)

/* Little-endian native halves. No mutable builder, user-selected descriptor,
 * alternate syscall ABI or implied pointer-content validation. Absolute
 * instruction indices are independently interpreted in the fault fixture. */
enum { WORKER_BPF_IO = 11, WORKER_BPF_POLL = 26, WORKER_BPF_EXIT = 51,
       WORKER_BPF_EXIT_ALLOW = 59, WORKER_BPF_COUNT = 60 };
static const struct sock_filter worker_filter[] = {
    /* 0..5: exact ABI and explicit x32-bit rejection. */
    WORKER_EQ(offsetof(struct seccomp_data, arch), WORKER_AUDIT_ARCH),
    WORKER_LD(offsetof(struct seccomp_data, nr)),
    BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, UINT32_C(0x40000000), 0, 1),
    WORKER_KILL,
    /* 6..10: dispatch; nothing else has an allow path. */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_read, WORKER_BPF_IO - 7, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_write, WORKER_BPF_IO - 8, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_ppoll, WORKER_BPF_POLL - 9, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_exit_group, WORKER_BPF_EXIT - 10, 0),
    WORKER_KILL,
    /* 11..25: fd3, nonempty bounded I/O (both high words zero). */
    WORKER_EQ(WORKER_HI(0), 0),
    WORKER_EQ(WORKER_LO(0), MONITOR_WORKER_FD),
    WORKER_EQ(WORKER_HI(2), 0),
    WORKER_LD(WORKER_LO(2)),
    BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 1, 1, 0), WORKER_KILL,
    BPF_JUMP(BPF_JMP | BPF_JGT | BPF_K, SYNC_WORK_STEP_BYTES, 0, 1), WORKER_KILL,
    WORKER_ALLOW,
    /* 26..50: one pollfd, NULL timeout/mask, kernel mask size8. */
    WORKER_EQ(WORKER_HI(1), 0), WORKER_EQ(WORKER_LO(1), 1),
    WORKER_EQ(WORKER_HI(2), 0), WORKER_EQ(WORKER_LO(2), 0),
    WORKER_EQ(WORKER_HI(3), 0), WORKER_EQ(WORKER_LO(3), 0),
    WORKER_EQ(WORKER_HI(4), 0), WORKER_EQ(WORKER_LO(4), 8),
    WORKER_ALLOW,
    /* 51..59: internal nonzero failure disposition only. */
    WORKER_EQ(WORKER_HI(0), 0), WORKER_LD(WORKER_LO(0)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, MONITOR_WORKER_EXIT_SETUP,
        WORKER_BPF_EXIT_ALLOW - 56, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, MONITOR_WORKER_EXIT_WAIT,
        WORKER_BPF_EXIT_ALLOW - 57, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, MONITOR_WORKER_EXIT_WORK,
        WORKER_BPF_EXIT_ALLOW - 58, 0),
    WORKER_KILL, WORKER_ALLOW
};
_Static_assert(sizeof(worker_filter) / sizeof(worker_filter[0]) == WORKER_BPF_COUNT &&
               WORKER_BPF_COUNT <= 64, "worker fixed BPF budget and offsets");

static int worker_seal(void)
{
    struct sock_fprog program = {
        (unsigned short)WORKER_BPF_COUNT, (struct sock_filter *)worker_filter
    };
    if (worker_status(worker_native_call(SYS_prctl, PR_SET_NO_NEW_PRIVS,
            1, 0, 0, 0, 0)) != 0) return -1;
    long nnp = worker_native_call(SYS_prctl, PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0, 0);
    if (nnp != 1) return worker_status(nnp < 0 ? nnp : -EPROTO);
    /* On success no libc errno access or further setup syscall follows. */
    long result = worker_native_call(SYS_prctl, PR_SET_SECCOMP,
        SECCOMP_MODE_FILTER, (unsigned long)&program, 0, 0, 0);
    if (result != 0) return worker_status(result);
    return 0;
}

static ptrdiff_t worker_io_result(long result, size_t offered)
{
    if (result >= 0) return (unsigned long)result <= offered ?
        (ptrdiff_t)result : SYNC_WORK_IO_ERROR;
    if (result == -EINTR) return SYNC_WORK_IO_INTR;
    if (result == -EAGAIN || result == -EWOULDBLOCK) return SYNC_WORK_IO_AGAIN;
    return SYNC_WORK_IO_ERROR;
}
static ptrdiff_t worker_read(void *context, uint8_t *out, size_t offered)
{
    (void)context;
    return worker_io_result(worker_native_call(SYS_read, MONITOR_WORKER_FD,
        (unsigned long)out, (unsigned long)offered, 0, 0, 0), offered);
}
static ptrdiff_t worker_write(void *context, const uint8_t *in, size_t offered)
{
    (void)context;
    return worker_io_result(worker_native_call(SYS_write, MONITOR_WORKER_FD,
        (unsigned long)in, (unsigned long)offered, 0, 0, 0), offered);
}
static int worker_store(void *context, const sync_work_header_t *header,
                         uint64_t offset, const uint8_t unit[SYNC_WORK_UNIT])
{
    return sync_source_map_store_unit(context, offset, unit, header->operation) ==
        SYNC_SOURCE_MAP_OK ? 0 : 1;
}
static int worker_plan(void *context, const sync_repair_view_t *view,
                        sync_repair_result_t *result)
{
    (void)context;
    return sync_repair_plan_choose(view, result);
}

/* One raw wait; no timeout, temporary signal mask or writable-idle spin.
 * Only actual subsequent reads distinguish HUP/ERR from queued data/EOF. */
static int worker_wait(short events)
{
    struct pollfd one = { MONITOR_WORKER_FD, events, 0 };
    long result = worker_native_call(SYS_ppoll, (unsigned long)&one, 1, 0, 0, 8, 0);
    if (result == -EINTR) return 1;
    if (result != 1 || (one.revents & POLLNVAL) != 0 ||
        (one.revents & (events | POLLHUP | POLLERR)) == 0) return -1;
    return 0;
}

static _Noreturn void worker_terminate(sync_work_carriage_t *carriage, int code)
{
    if (carriage != NULL) (void)sync_work_retire(carriage);
    (void)worker_native_call(SYS_exit_group, (unsigned long)code, 0, 0, 0, 0, 0);
    __builtin_trap(); /* A broken raw exit must not return to a epoch-rekey caller. */
}
#endif

_Noreturn void monitor_worker_enter(sync_source_map_t *map,
                                    const monitor_worker_birth_t *birth)
{
#if WORKER_NATIVE_SUPPORTED
    /* Constructor custody is a prerequisite, not inferred from this manifest.
     * Guard is deliberately before substantial map/signal/owner setup. */
    if (birth == NULL || birth->expected_c_pid <= 0 ||
        monitor_parent_guard((pid_t)birth->expected_c_pid) != 0)
        worker_terminate(NULL, MONITOR_WORKER_EXIT_SETUP);
    if (map == NULL || birth->incarnation == 0 || birth->direction > 1 ||
        birth->reserved[0] != 0 || birth->reserved[1] != 0 ||
        birth->reserved[2] != 0 || !sync_source_map_supported() ||
        map->state != SYNC_SOURCE_MAP_CREATED || map->failure != 0)
        worker_terminate(NULL, MONITOR_WORKER_EXIT_SETUP);
    sync_source_map_layout_t layout = {0};
    if (sync_source_map_geometry(birth->quota, map->page_length, &layout) != 0 ||
        layout.nrecords != map->nrecords || layout.payload_length != map->payload_length ||
        layout.page_length != map->page_length)
        worker_terminate(NULL, MONITOR_WORKER_EXIT_SETUP);

    long flags = worker_native_call(SYS_fcntl, MONITOR_WORKER_FD, F_GETFL, 0, 0, 0, 0);
    if (flags < 0 || (flags & O_ACCMODE) != O_RDWR || (flags & O_NONBLOCK) == 0 ||
        worker_native_call(SYS_fcntl, MONITOR_WORKER_FD, F_GETFD, 0, 0, 0, 0) != FD_CLOEXEC)
        worker_terminate(NULL, MONITOR_WORKER_EXIT_SETUP);
    /* No retry, including EINTR: ownership is terminal on uncertain close. */
    if (worker_native_call(SYS_close, MONITOR_WORKER_OTHER_FD, 0, 0, 0, 0, 0) != 0 ||
        worker_native_call(SYS_fcntl, MONITOR_WORKER_OTHER_FD, F_GETFD, 0, 0, 0, 0) != -EBADF)
        worker_terminate(NULL, MONITOR_WORKER_EXIT_SETUP);
    if (worker_normalize_signals() != 0 || worker_process_policy() != 0 ||
        sync_source_map_enter_worker(map) != SYNC_SOURCE_MAP_OK)
        worker_terminate(NULL, MONITOR_WORKER_EXIT_SETUP);

    sync_work_carriage_t carriage = {0};
    const sync_work_io_t io = { NULL, worker_read, worker_write };
    const sync_work_callbacks_t callbacks = { map, worker_store, worker_plan };
    if (sync_work_carriage_init(&carriage, SYNC_WORK_WORKER,
            birth->incarnation, birth->direction) != SYNC_WORK_OK || worker_seal() != 0)
        worker_terminate(&carriage, MONITOR_WORKER_EXIT_SETUP);

    static const uint8_t ready = MONITOR_WORKER_READY;
    for (;;) {
        ptrdiff_t count = worker_write(NULL, &ready, 1);
        if (count == 1) break;
        if (count != SYNC_WORK_IO_AGAIN && count != SYNC_WORK_IO_INTR)
            worker_terminate(&carriage, MONITOR_WORKER_EXIT_WORK);
        if (worker_wait(POLLOUT) < 0)
            worker_terminate(&carriage, MONITOR_WORKER_EXIT_WAIT);
    }
    for (;;) {
        unsigned interest = sync_work_interests(&carriage);
        if (interest == 0) worker_terminate(&carriage, MONITOR_WORKER_EXIT_WORK);
        if ((interest & SYNC_WORK_LOCAL) == 0) {
            short events = POLLIN;
            if ((interest & SYNC_WORK_WRITE) != 0) events |= POLLOUT;
            int waiting = worker_wait(events);
            if (waiting < 0) worker_terminate(&carriage, MONITOR_WORKER_EXIT_WAIT);
            if (waiting > 0) continue;
        }
        if (sync_work_step(&carriage, &io, &callbacks) != SYNC_WORK_OK)
            worker_terminate(&carriage, MONITOR_WORKER_EXIT_WORK);
    }
#else
    (void)map;
    (void)birth;
    _exit(MONITOR_WORKER_EXIT_SETUP);
#endif
}
