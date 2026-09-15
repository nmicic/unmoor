/*
 * monitor_worker_native.h — private, fixed Linux raw-call boundary for W
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef UNMOOR_MONITOR_WORKER_NATIVE_H
#define UNMOOR_MONITOR_WORKER_NATIVE_H

#include <stddef.h>
#include <stdint.h>

#ifndef __has_feature
#define __has_feature(x) 0
#endif

#if defined(__linux__) && defined(__LP64__) && \
    (defined(__x86_64__) || defined(__aarch64__)) && \
    (defined(__GNUC__) || defined(__clang__)) && \
    defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ && \
    !defined(UNMOOR_SANITIZER) && !defined(__SANITIZE_ADDRESS__) && \
    !defined(__SANITIZE_THREAD__) && !__has_feature(address_sanitizer) && \
    !__has_feature(undefined_behavior_sanitizer) && \
    !__has_feature(thread_sanitizer) && !__has_feature(memory_sanitizer)
#define WORKER_NATIVE_SUPPORTED 1
#else
#define WORKER_NATIVE_SUPPORTED 0
#endif

#if WORKER_NATIVE_SUPPORTED
#include <signal.h>
#include <sys/syscall.h>

/* Kernel UAPI action, not libc's sigaction/sigset_t. Native layout and
 * signal numbers are independently gated on both supported architectures. */
typedef struct {
    void (*handler)(int);
    unsigned long flags;
    void (*restorer)(void);
    uint64_t mask;
} worker_kernel_action_t;

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8 &&
               sizeof(worker_kernel_action_t) == 32 &&
               offsetof(worker_kernel_action_t, flags) == 8 &&
               offsetof(worker_kernel_action_t, restorer) == 16 &&
               offsetof(worker_kernel_action_t, mask) == 24,
               "fixed native kernel signal ABI");
_Static_assert(SIGKILL == 9 && SIGSTOP == 19 && SIGPIPE == 13,
               "fixed native signal numbers");

/* No libc syscall(), errno/TLS/cancellation, allocation or hidden retry.
 * All six arguments are explicit full-width native values. Kernel errors
 * stay negative; the pre-seal caller alone may translate them to errno. */
static inline long worker_native_call(long nr, unsigned long a0,
                                      unsigned long a1, unsigned long a2,
                                      unsigned long a3, unsigned long a4,
                                      unsigned long a5)
{
#if defined(__x86_64__)
    register unsigned long r10 __asm__("r10") = a3;
    register unsigned long r8 __asm__("r8") = a4;
    register unsigned long r9 __asm__("r9") = a5;
    long result;
    __asm__ volatile ("syscall"
                      : "=a" (result)
                      : "a" (nr), "D" (a0), "S" (a1), "d" (a2),
                        "r" (r10), "r" (r8), "r" (r9)
                      : "rcx", "r11", "cc", "memory");
    return result;
#else
    register long x0 __asm__("x0") = (long)a0;
    register unsigned long x1 __asm__("x1") = a1;
    register unsigned long x2 __asm__("x2") = a2;
    register unsigned long x3 __asm__("x3") = a3;
    register unsigned long x4 __asm__("x4") = a4;
    register unsigned long x5 __asm__("x5") = a5;
    register long x8 __asm__("x8") = nr;
    __asm__ volatile ("svc #0"
                      : "+r" (x0)
                      : "r" (x1), "r" (x2), "r" (x3), "r" (x4),
                        "r" (x5), "r" (x8)
                      : "cc", "memory");
    return x0;
#endif
}
#endif
#endif
