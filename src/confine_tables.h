/*
 * confine_tables.h — client-confinement seccomp allow-list groups
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * Each group is a set of syscall numbers, guarded so that a port whose kernel
 * ABI lacks an entry simply omits it.  The trailing 0 is a deliberate no-op
 * sentinel: __NR_read is 0 on x86_64, so the duplicate is harmless, and it
 * keeps every array non-empty even on a hypothetical port that defines none
 * of the names.
 *
 * client-confinement rule: an allow-list one syscall short of the truth is fatal, so the
 * groups are deliberately generous about syscalls that cannot widen the
 * process's authority (Landlock is the filesystem authority, not seccomp) and
 * strict about the ones that can: ptrace, mount, chroot, set*uid, bpf,
 * kexec, module loading, keyctl and process_vm_* appear in no group at all.
 * clone and execve live only in confine_group_exec, which the terminal
 * client alone receives; what they can start is bounded by Landlock execute
 * rights on the binary's own image and the loader paths plus no_new_privs,
 * not by seccomp.
 */
#ifndef UNMOOR_CONFINE_TABLES_H
#define UNMOOR_CONFINE_TABLES_H

#if defined(__linux__)

#include <sys/syscall.h>

/* Every role: signals, exit, memory, time, poll, already-open fd io. */
static const int confine_group_base[] = {
#ifdef __NR_read
    __NR_read,
#endif
#ifdef __NR_write
    __NR_write,
#endif
#ifdef __NR_readv
    __NR_readv,
#endif
#ifdef __NR_writev
    __NR_writev,
#endif
#ifdef __NR_pread64
    __NR_pread64,
#endif
#ifdef __NR_pwrite64
    __NR_pwrite64,
#endif
#ifdef __NR_open
    __NR_open,
#endif
#ifdef __NR_openat
    __NR_openat,
#endif
#ifdef __NR_openat2
    __NR_openat2,
#endif
#ifdef __NR_close
    __NR_close,
#endif
#ifdef __NR_close_range
    __NR_close_range,
#endif
#ifdef __NR_fcntl
    __NR_fcntl,
#endif
#ifdef __NR_fcntl64
    __NR_fcntl64,
#endif
#ifdef __NR_ioctl
    __NR_ioctl,
#endif
#ifdef __NR_lseek
    __NR_lseek,
#endif
#ifdef __NR__llseek
    __NR__llseek,
#endif
#ifdef __NR_poll
    __NR_poll,
#endif
#ifdef __NR_ppoll
    __NR_ppoll,
#endif
#ifdef __NR_ppoll_time64
    __NR_ppoll_time64,
#endif
#ifdef __NR_pselect6
    __NR_pselect6,
#endif
#ifdef __NR_pselect6_time64
    __NR_pselect6_time64,
#endif
#ifdef __NR_select
    __NR_select,
#endif
#ifdef __NR__newselect
    __NR__newselect,
#endif
#ifdef __NR_epoll_create1
    __NR_epoll_create1,
#endif
#ifdef __NR_epoll_ctl
    __NR_epoll_ctl,
#endif
#ifdef __NR_epoll_wait
    __NR_epoll_wait,
#endif
#ifdef __NR_epoll_pwait
    __NR_epoll_pwait,
#endif
#ifdef __NR_epoll_pwait2
    __NR_epoll_pwait2,
#endif
#ifdef __NR_fstat
    __NR_fstat,
#endif
#ifdef __NR_fstat64
    __NR_fstat64,
#endif
#ifdef __NR_newfstatat
    __NR_newfstatat,
#endif
#ifdef __NR_fstatat64
    __NR_fstatat64,
#endif
#ifdef __NR_statx
    __NR_statx,
#endif
#ifdef __NR_fstatfs
    __NR_fstatfs,
#endif
#ifdef __NR_fstatfs64
    __NR_fstatfs64,
#endif
#ifdef __NR_rt_sigreturn
    __NR_rt_sigreturn,
#endif
#ifdef __NR_rt_sigaction
    __NR_rt_sigaction,
#endif
#ifdef __NR_rt_sigprocmask
    __NR_rt_sigprocmask,
#endif
#ifdef __NR_rt_sigtimedwait
    __NR_rt_sigtimedwait,
#endif
#ifdef __NR_rt_sigtimedwait_time64
    __NR_rt_sigtimedwait_time64,
#endif
#ifdef __NR_rt_sigsuspend
    __NR_rt_sigsuspend,
#endif
#ifdef __NR_rt_sigpending
    __NR_rt_sigpending,
#endif
#ifdef __NR_sigaltstack
    __NR_sigaltstack,
#endif
#ifdef __NR_restart_syscall
    __NR_restart_syscall,
#endif
#ifdef __NR_exit
    __NR_exit,
#endif
#ifdef __NR_exit_group
    __NR_exit_group,
#endif
#ifdef __NR_brk
    __NR_brk,
#endif
#ifdef __NR_mmap
    __NR_mmap,
#endif
#ifdef __NR_mmap2
    __NR_mmap2,
#endif
#ifdef __NR_munmap
    __NR_munmap,
#endif
#ifdef __NR_mremap
    __NR_mremap,
#endif
#ifdef __NR_mprotect
    __NR_mprotect,
#endif
#ifdef __NR_madvise
    __NR_madvise,
#endif
#ifdef __NR_mlock
    __NR_mlock,
#endif
#ifdef __NR_mlock2
    __NR_mlock2,
#endif
#ifdef __NR_munlock
    __NR_munlock,
#endif
#ifdef __NR_mlockall
    __NR_mlockall,
#endif
#ifdef __NR_munlockall
    __NR_munlockall,
#endif
#ifdef __NR_futex
    __NR_futex,
#endif
#ifdef __NR_futex_time64
    __NR_futex_time64,
#endif
#ifdef __NR_futex_waitv
    __NR_futex_waitv,
#endif
#ifdef __NR_set_robust_list
    __NR_set_robust_list,
#endif
#ifdef __NR_get_robust_list
    __NR_get_robust_list,
#endif
#ifdef __NR_rseq
    __NR_rseq,
#endif
#ifdef __NR_set_tid_address
    __NR_set_tid_address,
#endif
#ifdef __NR_clock_gettime
    __NR_clock_gettime,
#endif
#ifdef __NR_clock_gettime64
    __NR_clock_gettime64,
#endif
#ifdef __NR_clock_getres
    __NR_clock_getres,
#endif
#ifdef __NR_clock_getres_time64
    __NR_clock_getres_time64,
#endif
#ifdef __NR_clock_nanosleep
    __NR_clock_nanosleep,
#endif
#ifdef __NR_clock_nanosleep_time64
    __NR_clock_nanosleep_time64,
#endif
#ifdef __NR_nanosleep
    __NR_nanosleep,
#endif
#ifdef __NR_gettimeofday
    __NR_gettimeofday,
#endif
#ifdef __NR_times
    __NR_times,
#endif
#ifdef __NR_getpid
    __NR_getpid,
#endif
#ifdef __NR_gettid
    __NR_gettid,
#endif
#ifdef __NR_getuid
    __NR_getuid,
#endif
#ifdef __NR_geteuid
    __NR_geteuid,
#endif
#ifdef __NR_getgid
    __NR_getgid,
#endif
#ifdef __NR_getegid
    __NR_getegid,
#endif
#ifdef __NR_getppid
    __NR_getppid,
#endif
#ifdef __NR_getpgrp
    __NR_getpgrp,
#endif
#ifdef __NR_getpgid
    __NR_getpgid,
#endif
#ifdef __NR_getsid
    __NR_getsid,
#endif
#ifdef __NR_getrandom
    __NR_getrandom,
#endif
#ifdef __NR_sched_yield
    __NR_sched_yield,
#endif
#ifdef __NR_sched_getaffinity
    __NR_sched_getaffinity,
#endif
#ifdef __NR_getrusage
    __NR_getrusage,
#endif
#ifdef __NR_prlimit64
    __NR_prlimit64,
#endif
#ifdef __NR_getrlimit
    __NR_getrlimit,
#endif
#ifdef __NR_ugetrlimit
    __NR_ugetrlimit,
#endif
#ifdef __NR_uname
    __NR_uname,
#endif
#ifdef __NR_sysinfo
    __NR_sysinfo,
#endif
#ifdef __NR_membarrier
    __NR_membarrier,
#endif
#ifdef __NR_arch_prctl
    __NR_arch_prctl,
#endif
#ifdef __NR_tgkill
    __NR_tgkill,
#endif
#ifdef __NR_dup
    __NR_dup,
#endif
#ifdef __NR_dup2
    __NR_dup2,
#endif
#ifdef __NR_dup3
    __NR_dup3,
#endif
#ifdef __NR_recvfrom
    __NR_recvfrom,
#endif
#ifdef __NR_recvmsg
    __NR_recvmsg,
#endif
#ifdef __NR_recvmmsg
    __NR_recvmmsg,
#endif
#ifdef __NR_recvmmsg_time64
    __NR_recvmmsg_time64,
#endif
#ifdef __NR_sendto
    __NR_sendto,
#endif
#ifdef __NR_sendmsg
    __NR_sendmsg,
#endif
#ifdef __NR_sendmmsg
    __NR_sendmmsg,
#endif
#ifdef __NR_getsockopt
    __NR_getsockopt,
#endif
#ifdef __NR_setsockopt
    __NR_setsockopt,
#endif
#ifdef __NR_shutdown
    __NR_shutdown,
#endif
#ifdef __NR_getsockname
    __NR_getsockname,
#endif
    0 /* sentinel keeps the array non-empty on any port */
};

/* Terminal and bulk clients: multipath path sockets and roaming-freshest-path roaming. */
static const int confine_group_net[] = {
#ifdef __NR_socket
    __NR_socket,
#endif
#ifdef __NR_socketpair
    __NR_socketpair,
#endif
#ifdef __NR_bind
    __NR_bind,
#endif
#ifdef __NR_connect
    __NR_connect,
#endif
#ifdef __NR_listen
    __NR_listen,
#endif
#ifdef __NR_accept
    __NR_accept,
#endif
#ifdef __NR_accept4
    __NR_accept4,
#endif
#ifdef __NR_getpeername
    __NR_getpeername,
#endif
    0 /* sentinel keeps the array non-empty on any port */
};

/* Terminal and bulk clients: Landlock-scoped path operations. */
static const int confine_group_files[] = {
#ifdef __NR_getcwd
    __NR_getcwd,
#endif
#ifdef __NR_chdir
    __NR_chdir,
#endif
#ifdef __NR_fchdir
    __NR_fchdir,
#endif
#ifdef __NR_getdents
    __NR_getdents,
#endif
#ifdef __NR_getdents64
    __NR_getdents64,
#endif
#ifdef __NR_readlink
    __NR_readlink,
#endif
#ifdef __NR_readlinkat
    __NR_readlinkat,
#endif
#ifdef __NR_access
    __NR_access,
#endif
#ifdef __NR_faccessat
    __NR_faccessat,
#endif
#ifdef __NR_faccessat2
    __NR_faccessat2,
#endif
#ifdef __NR_stat
    __NR_stat,
#endif
#ifdef __NR_stat64
    __NR_stat64,
#endif
#ifdef __NR_lstat
    __NR_lstat,
#endif
#ifdef __NR_lstat64
    __NR_lstat64,
#endif
#ifdef __NR_statfs
    __NR_statfs,
#endif
#ifdef __NR_statfs64
    __NR_statfs64,
#endif
#ifdef __NR_unlink
    __NR_unlink,
#endif
#ifdef __NR_unlinkat
    __NR_unlinkat,
#endif
#ifdef __NR_rename
    __NR_rename,
#endif
#ifdef __NR_renameat
    __NR_renameat,
#endif
#ifdef __NR_renameat2
    __NR_renameat2,
#endif
#ifdef __NR_mkdir
    __NR_mkdir,
#endif
#ifdef __NR_mkdirat
    __NR_mkdirat,
#endif
#ifdef __NR_rmdir
    __NR_rmdir,
#endif
#ifdef __NR_link
    __NR_link,
#endif
#ifdef __NR_linkat
    __NR_linkat,
#endif
#ifdef __NR_symlink
    __NR_symlink,
#endif
#ifdef __NR_symlinkat
    __NR_symlinkat,
#endif
#ifdef __NR_chmod
    __NR_chmod,
#endif
#ifdef __NR_fchmod
    __NR_fchmod,
#endif
#ifdef __NR_fchmodat
    __NR_fchmodat,
#endif
#ifdef __NR_fchmodat2
    __NR_fchmodat2,
#endif
#ifdef __NR_truncate
    __NR_truncate,
#endif
#ifdef __NR_ftruncate
    __NR_ftruncate,
#endif
#ifdef __NR_ftruncate64
    __NR_ftruncate64,
#endif
#ifdef __NR_fsync
    __NR_fsync,
#endif
#ifdef __NR_fdatasync
    __NR_fdatasync,
#endif
#ifdef __NR_fallocate
    __NR_fallocate,
#endif
#ifdef __NR_umask
    __NR_umask,
#endif
#ifdef __NR_utimensat
    __NR_utimensat,
#endif
#ifdef __NR_utimensat_time64
    __NR_utimensat_time64,
#endif
    0 /* sentinel keeps the array non-empty on any port */
};

/* server-confinement one-shot bulk server: only the extra operations exercised after the
 * authenticated path hook.  Path opening and fd-stat/read/write live in the
 * base group; Landlock scopes the namespace operations to the selected PUT
 * directory and one-shot deaddrop cleanup directories. */
static const int confine_group_server_files[] = {
#ifdef __NR_unlinkat
    __NR_unlinkat,
#endif
#ifdef __NR_renameat
    __NR_renameat,
#endif
#ifdef __NR_linkat
    __NR_linkat,
#endif
#ifdef __NR_fsync
    __NR_fsync,
#endif
#ifdef __NR_fdatasync
    __NR_fdatasync,
#endif
#ifdef __NR_umask
    __NR_umask,
#endif
    0 /* sentinel keeps the array non-empty on any port */
};

/*
 * Reaping and signalling a process this role created BEFORE it confined
 * itself.  The public-bootstrap client forks the SSH carrier and tears it
 * down at shutdown (SIGTERM, then SIGKILL, then waitpid, in
 * src/deaddrop_runtime.c).  The bulk client cannot create a new process once
 * confined; the terminal client can, through confine_group_exec below, and
 * Landlock bounds what that process can be.  kill(2) is the one entry here
 * that reaches beyond this process tree (any process of the same uid);
 * seccomp cannot bound its target usefully, so a confined role can signal
 * any process of its own user, not only the children it already had.
 */
static const int confine_group_reap[] = {
#ifdef __NR_wait4
    __NR_wait4,
#endif
#ifdef __NR_waitid
    __NR_waitid,
#endif
#ifdef __NR_waitpid
    __NR_waitpid,
#endif
#ifdef __NR_kill
    __NR_kill,
#endif
    0 /* sentinel keeps the array non-empty on any port */
};

static const int confine_group_exec[] = {
#ifdef __NR_clone
    __NR_clone,
#endif
#ifdef __NR_clone3
    __NR_clone3,
#endif
#ifdef __NR_fork
    __NR_fork,
#endif
#ifdef __NR_vfork
    __NR_vfork,
#endif
#ifdef __NR_execve
    __NR_execve,
#endif
#ifdef __NR_execveat
    __NR_execveat,
#endif
#ifdef __NR_pipe
    __NR_pipe,
#endif
#ifdef __NR_pipe2
    __NR_pipe2,
#endif
#ifdef __NR_setsid
    __NR_setsid,
#endif
#ifdef __NR_setpgid
    __NR_setpgid,
#endif
#ifdef __NR_prctl
    __NR_prctl,
#endif
#ifdef __NR_landlock_create_ruleset
    __NR_landlock_create_ruleset,
#endif
#ifdef __NR_landlock_add_rule
    __NR_landlock_add_rule,
#endif
#ifdef __NR_landlock_restrict_self
    __NR_landlock_restrict_self,
#endif
    0 /* sentinel keeps the array non-empty on any port */
};

#endif /* __linux__ */

#endif /* UNMOOR_CONFINE_TABLES_H */
