/*
 * fd_stat.h — existing-descriptor metadata without pathname syscalls
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef UNMOOR_FD_STAT_H
#define UNMOOR_FD_STAT_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/syscall.h>
#endif

/* Some glibc versions implement fstat through newfstatat. The late server
 * deliberately cannot make pathname metadata calls. Use the native LP64
 * fd-only syscall and convert an explicit kernel layout, not an unchecked
 * libc struct. Callers on Linux enable _GNU_SOURCE before any header.
 * Layout references: Linux arch/x86/include/uapi/asm/stat.h and
 * include/uapi/asm-generic/stat.h. Other platforms retain libc fstat and
 * cannot install the server-confinement role unless separately supported. */
#if defined(__linux__) && defined(__LP64__) && defined(SYS_fstat) && \
    (defined(__x86_64__) || defined(__aarch64__))
#define UNMOOR_FD_STAT_DIRECT 1
typedef struct unmoor_kernel_fd_stat {
    uint64_t device;
    uint64_t inode;
#if defined(__x86_64__)
    uint64_t links;
    uint32_t mode;
    uint32_t uid;
    uint32_t gid;
    uint32_t pad0;
#else
    uint32_t mode;
    uint32_t links;
    uint32_t uid;
    uint32_t gid;
#endif
    uint64_t rdevice;
#if defined(__aarch64__)
    uint64_t pad1;
#endif
    int64_t size;
#if defined(__x86_64__)
    int64_t block_size;
#else
    int32_t block_size;
    int32_t pad2;
#endif
    int64_t blocks;
    int64_t access_seconds;
    uint64_t access_nanos;
    int64_t modify_seconds;
    uint64_t modify_nanos;
    int64_t change_seconds;
    uint64_t change_nanos;
#if defined(__x86_64__)
    int64_t unused[3];
#else
    uint32_t unused[2];
#endif
} unmoor_kernel_fd_stat_t;

_Static_assert(offsetof(unmoor_kernel_fd_stat_t, size) == 48U &&
               offsetof(unmoor_kernel_fd_stat_t, blocks) == 64U &&
               offsetof(unmoor_kernel_fd_stat_t, access_seconds) == 72U &&
               offsetof(unmoor_kernel_fd_stat_t, change_nanos) == 112U,
               "native fd-stat kernel offsets changed");
#if defined(__x86_64__)
_Static_assert(sizeof(unmoor_kernel_fd_stat_t) == 144U &&
               offsetof(unmoor_kernel_fd_stat_t, mode) == 24U &&
               offsetof(unmoor_kernel_fd_stat_t, rdevice) == 40U,
               "x86_64 fd-stat kernel layout changed");
#else
_Static_assert(sizeof(unmoor_kernel_fd_stat_t) == 128U &&
               offsetof(unmoor_kernel_fd_stat_t, mode) == 16U &&
               offsetof(unmoor_kernel_fd_stat_t, rdevice) == 32U,
               "aarch64 fd-stat kernel layout changed");
#endif
_Static_assert(sizeof(((struct stat *)0)->st_size) >= 8U &&
               sizeof(((struct stat *)0)->st_ino) >= 8U &&
               sizeof(((struct stat *)0)->st_atim.tv_sec) >= 8U,
               "fd-stat requires native 64-bit file and time fields");
#else
#define UNMOOR_FD_STAT_DIRECT 0
#endif

static inline int unmoor_fd_stat(int fd, struct stat *out)
{
#if UNMOOR_FD_STAT_DIRECT
    unmoor_kernel_fd_stat_t raw;

    if (syscall(SYS_fstat, fd, &raw) != 0)
        return -1;
    memset(out, 0, sizeof(*out));
    out->st_dev = raw.device;
    out->st_ino = raw.inode;
    out->st_nlink = raw.links;
    out->st_mode = raw.mode;
    out->st_uid = raw.uid;
    out->st_gid = raw.gid;
    out->st_rdev = raw.rdevice;
    out->st_size = raw.size;
    out->st_blksize = raw.block_size;
    out->st_blocks = raw.blocks;
    out->st_atim.tv_sec = raw.access_seconds;
    out->st_atim.tv_nsec = (long)raw.access_nanos;
    out->st_mtim.tv_sec = raw.modify_seconds;
    out->st_mtim.tv_nsec = (long)raw.modify_nanos;
    out->st_ctim.tv_sec = raw.change_seconds;
    out->st_ctim.tv_nsec = (long)raw.change_nanos;
    return 0;
#else
    return fstat(fd, out);
#endif
}

#endif
