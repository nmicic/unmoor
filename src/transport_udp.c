/*
 * transport_udp.c — UDP datagram transport with mosh-style peer roaming
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * UDP roaming. One datagram carries exactly one Unmoor frame — UDP is
 * already message-framed, so there is no length prefix (unlike unix/stdio).
 *
 * Roaming model (the mosh rule): the socket is never connect()ed. recv
 * accepts datagrams from ANY source address — AEAD is the only gate on who
 * the peer is — and records the source of the most recent datagram as the
 * *candidate* peer address. The session layer calls peer_confirm() only
 * after a frame passed AEAD and advanced the replay high-water mark; that
 * promotes candidate → confirmed, and all sends go to the confirmed
 * address. So when the peer's IP or NAT binding changes mid-session, its
 * next authenticated frame re-points the return path, and the session
 * never notices at any layer above this file.
 *
 * The client learns the server address from getaddrinfo at open and
 * confirms it immediately (it must send the first HELLO somewhere); the
 * listener starts with no peer and learns it from the first confirmed
 * frame. Leaving the socket unconnected also means ICMP errors during an
 * outage are not surfaced as send/recv failures — the session just keeps
 * trying, which is exactly the mosh behavior we want with liveness unbound.
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <limits.h>

#include "transport.h"
#include "frame.h" /* FRAME_MAX_LEN */
#include "rss.h"

/* Not exposed under strict _POSIX_C_SOURCE on Darwin. */
#ifndef NI_MAXHOST
#define NI_MAXHOST 1025
#endif
#ifndef NI_MAXSERV
#define NI_MAXSERV 32
#endif

/* -------------------------------------------------------------------------
 * Internal state
 * ---------------------------------------------------------------------- */

typedef struct {
    transport_t             base;       /* must be first */
    int                     fd[MULTIPATH_PATHS_MAX];
    int                     shadow_fd[MULTIPATH_PATHS_MAX];
    uint8_t                 fd_count;
    uint8_t                 path_limit; /* 0 ordinary, else exact multipath N */
    uint8_t                 peer_leg;
    uint8_t                 rx_cursor;
    uint8_t                 port_layout;
    uint8_t                 port_mask_explicit;
    uint16_t                port_mask;
    uint16_t                shadow_port_mask;
    uint8_t                 reroll_fail_after_bind_count;
    uint64_t                shadow_cookie;
    uint32_t                shadow_mask;
    int                     is_listener;
    struct sockaddr_storage peer;       /* confirmed return address */
    socklen_t               peer_len;
    int                     have_peer;
    struct sockaddr_storage cand;       /* source of most recent datagram */
    socklen_t               cand_len;
    uint8_t                 cand_leg;
    int                     have_cand;
    transport_stats_t       stats;
} transport_udp_t;

static int set_nonblocking_cloexec(int fd)
{
    int flags;

    if (fcntl(fd, F_SETFD, FD_CLOEXEC) != 0)
        return -1;
    flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0)
        return -1;
    return 0;
}

static int token_from_sockaddr(uint8_t leg, const struct sockaddr *sa,
                               socklen_t len, multipath_token_t *out)
{
    if (!sa || !out)
        return -1;
    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *v4 = (const struct sockaddr_in *)sa;
        if (len < (socklen_t)sizeof(*v4))
            return -1;
        return multipath_token_init(
            out, leg, 4U, ntohs(v4->sin_port), 0U,
            (const uint8_t *)&v4->sin_addr, sizeof(v4->sin_addr));
    }
    if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)sa;
        if (len < (socklen_t)sizeof(*v6))
            return -1;
        return multipath_token_init(
            out, leg, 6U, ntohs(v6->sin6_port), v6->sin6_scope_id,
            (const uint8_t *)&v6->sin6_addr, sizeof(v6->sin6_addr));
    }
    return -1;
}

static int preauth_source_from_sockaddr(const struct sockaddr *sa,
                                        socklen_t len,
                                        preauth_source_t *out)
{
    if (!sa || !out)
        return -1;
    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *v4 = (const struct sockaddr_in *)sa;
        if (len < (socklen_t)sizeof(*v4))
            return -1;
        return preauth_source_init(
            out, 4U, (const uint8_t *)&v4->sin_addr,
            sizeof(v4->sin_addr), 0U);
    }
    if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)sa;
        if (len < (socklen_t)sizeof(*v6))
            return -1;
        return preauth_source_init(
            out, 6U, (const uint8_t *)&v6->sin6_addr,
            sizeof(v6->sin6_addr), v6->sin6_scope_id);
    }
    return -1;
}

static int canonical_token_from_sockaddr(
    uint8_t leg, const struct sockaddr *sa, socklen_t len,
    const preauth_source_t *source, multipath_token_t *out)
{
    if (token_from_sockaddr(leg, sa, len, out) == 0)
        return 0;
    /* An ordinary dual-stack OS may report an IPv4-mapped AF_INET6 source.
     * source-prefilter folds it into the native IPv4 budget. Multipath rejects mapped tokens,
     * so synthesize the equivalent canonical v4 token without changing the
     * raw sockaddr retained for legacy roaming-freshest-path. Native V4+V6ONLY multipath sockets
     * never need this branch. */
    if (sa && sa->sa_family == AF_INET6 && source && source->family == 4U &&
        len >= (socklen_t)sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)sa;
        return multipath_token_init(out, leg, 4U, ntohs(v6->sin6_port),
                                    0U, source->address, 4U);
    }
    return -1;
}

static int sockaddr_from_token(const multipath_token_t *token,
                               struct sockaddr_storage *out,
                               socklen_t *len_out)
{
    if (!multipath_token_valid(token) || !out || !len_out)
        return -1;
    memset(out, 0, sizeof(*out));
    if (token->family == 4U) {
        struct sockaddr_in *v4 = (struct sockaddr_in *)out;
#if defined(__APPLE__)
        v4->sin_len = (uint8_t)sizeof(*v4);
#endif
        v4->sin_family = AF_INET;
        v4->sin_port = htons(token->port);
        memcpy(&v4->sin_addr, token->address, sizeof(v4->sin_addr));
        *len_out = (socklen_t)sizeof(*v4);
    } else {
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)out;
#if defined(__APPLE__)
        v6->sin6_len = (uint8_t)sizeof(*v6);
#endif
        v6->sin6_family = AF_INET6;
        v6->sin6_port = htons(token->port);
        v6->sin6_scope_id = token->scope;
        memcpy(&v6->sin6_addr, token->address, sizeof(v6->sin6_addr));
        *len_out = (socklen_t)sizeof(*v6);
    }
    return 0;
}

static void addr_str(const struct sockaddr *sa, socklen_t len,
                     char *out, size_t out_sz)
{
    char host[NI_MAXHOST], serv[NI_MAXSERV];
    if (getnameinfo(sa, len, host, sizeof(host), serv, sizeof(serv),
                    NI_NUMERICHOST | NI_NUMERICSERV) == 0)
        snprintf(out, out_sz, "%s:%s", host, serv);
    else
        snprintf(out, out_sz, "<unknown>");
}

static void close_fds(transport_udp_t *t)
{
    unsigned int i;

    if (!t)
        return;
    for (i = 0; i < MULTIPATH_PATHS_MAX; i++) {
        if (t->fd[i] >= 0) {
            close(t->fd[i]);
            t->fd[i] = -1;
        }
        if (t->shadow_fd[i] >= 0) {
            close(t->shadow_fd[i]);
            t->shadow_fd[i] = -1;
        }
    }
    t->fd_count = 0;
    t->shadow_mask = 0U;
}

static int wildcard_address(int family, uint16_t port,
                            struct sockaddr_storage *address,
                            socklen_t *length)
{
    if (!address || !length)
        return -1;
    memset(address, 0, sizeof(*address));
    if (family == AF_INET) {
        struct sockaddr_in *v4 = (struct sockaddr_in *)address;
        v4->sin_family = AF_INET;
        v4->sin_port = htons(port);
        v4->sin_addr.s_addr = htonl(INADDR_ANY);
        *length = (socklen_t)sizeof(*v4);
        return 0;
    }
    if (family == AF_INET6) {
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)address;
        v6->sin6_family = AF_INET6;
        v6->sin6_port = htons(port);
        v6->sin6_addr = in6addr_any;
        *length = (socklen_t)sizeof(*v6);
        return 0;
    }
    return -1;
}

static uint16_t sockaddr_port(const struct sockaddr_storage *address)
{
    if (!address)
        return 0U;
    if (address->ss_family == AF_INET)
        return ntohs(((const struct sockaddr_in *)address)->sin_port);
    if (address->ss_family == AF_INET6)
        return ntohs(((const struct sockaddr_in6 *)address)->sin6_port);
    return 0U;
}

static uint16_t addrinfo_port(const struct addrinfo *address)
{
    if (!address || !address->ai_addr)
        return 0U;
    if (address->ai_family == AF_INET)
        return ntohs(((const struct sockaddr_in *)address->ai_addr)->sin_port);
    if (address->ai_family == AF_INET6)
        return ntohs(
            ((const struct sockaddr_in6 *)address->ai_addr)->sin6_port);
    return 0U;
}

static int listener_socket_open(int family)
{
    int fd;
    int one = 1;

    if (family != AF_INET && family != AF_INET6) {
        errno = EAFNOSUPPORT;
        return -1;
    }
    fd = socket(family, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;
    /* No SO_REUSEADDR: UDP has no TIME_WAIT to work around, and the option
     * would let another local process co-bind the listener port and take
     * every inbound datagram. A busy port must fail with EADDRINUSE. */
    if (set_nonblocking_cloexec(fd) != 0 ||
        (family == AF_INET6 &&
         setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY,
                    &one, sizeof(one)) != 0)) {
        int saved = errno;

        (void)close(fd);
        errno = saved;
        return -1;
    }
    return fd;
}

static int listener_bind_wildcard(int fd, int family, uint16_t port)
{
    struct sockaddr_storage wildcard;
    socklen_t length = 0;

    return wildcard_address(family, port, &wildcard, &length) == 0 &&
           bind(fd, (struct sockaddr *)&wildcard, length) == 0 ? 0 : -1;
}

static int listener_bound_port(int fd, int expected_family,
                               uint16_t *port_out)
{
    struct sockaddr_storage bound;
    socklen_t length = (socklen_t)sizeof(bound);
    uint16_t port;

    if (!port_out) {
        errno = EINVAL;
        return -1;
    }
    memset(&bound, 0, sizeof(bound));
    if (getsockname(fd, (struct sockaddr *)&bound, &length) != 0)
        return -1;
    if (bound.ss_family != expected_family) {
        errno = EAFNOSUPPORT;
        return -1;
    }
    port = sockaddr_port(&bound);
    if (port == 0U) {
        errno = EADDRNOTAVAIL;
        return -1;
    }
    *port_out = port;
    return 0;
}

/* One public service port backed by two family-native sockets. IPv4 is
 * always physical local leg zero and V6ONLY IPv6 is leg one. Port-zero may
 * collide only in the second family; close the partial pair and retry within
 * the existing fixed 64-attempt UDP allocation ceiling. */
static int bind_native_dual_listener(transport_udp_t *t,
                                     uint16_t requested_port,
                                     uint16_t *bound_port_out)
{
    const unsigned int attempts = requested_port == 0U
        ? TRANSPORT_UDP_D32_BIND_ATTEMPTS : 1U;
    unsigned int attempt;

    if (!t || !bound_port_out) {
        errno = EINVAL;
        return -1;
    }
    *bound_port_out = 0U;
    for (attempt = 0U; attempt < attempts; attempt++) {
        uint16_t v4_port = 0U;
        uint16_t v6_port = 0U;
        int saved;

        t->fd[0] = listener_socket_open(AF_INET);
        if (t->fd[0] < 0)
            return -1;
        t->fd[1] = listener_socket_open(AF_INET6);
        if (t->fd[1] < 0) {
            saved = errno;
            close_fds(t);
            errno = saved;
            return -1;
        }
        if (listener_bind_wildcard(t->fd[0], AF_INET,
                                   requested_port) != 0 ||
            listener_bound_port(t->fd[0], AF_INET, &v4_port) != 0) {
            saved = errno;
            close_fds(t);
            errno = saved;
            if (requested_port == 0U && saved == EADDRINUSE)
                continue;
            return -1;
        }
        if (listener_bind_wildcard(t->fd[1], AF_INET6, v4_port) != 0 ||
            listener_bound_port(t->fd[1], AF_INET6, &v6_port) != 0) {
            saved = errno;
            close_fds(t);
            errno = saved;
            if (requested_port == 0U && saved == EADDRINUSE)
                continue;
            return -1;
        }
        if (v6_port != v4_port) {
            close_fds(t);
            errno = EADDRNOTAVAIL;
            return -1;
        }
        t->fd_count = 2U;
        *bound_port_out = v4_port;
        return 0;
    }
    errno = EADDRINUSE;
    return -1;
}

int transport_udp_d32_port_block_candidate(uint16_t ephemeral_port,
                                           uint8_t path_count,
                                           unsigned int attempt,
                                           uint16_t *base_port_out)
{
    return d33_cube_base_candidate(
        ephemeral_port, path_count, d33_cube_default_mask(path_count),
        attempt, base_port_out);
}

static void close_fd_array(int fds[MULTIPATH_PATHS_MAX])
{
    unsigned int leg;

    for (leg = 0U; leg < MULTIPATH_PATHS_MAX; leg++) {
        if (fds[leg] >= 0) {
            (void)close(fds[leg]);
            fds[leg] = -1;
        }
    }
}

/* Bind one all-or-none low-14-bit cube into an otherwise empty fd array.
 * The old active array may remain live while this binds a shadow set; any
 * overlap then fails in the kernel and advances to the next candidate. */
static int bind_cube_fd_array(int fds[MULTIPATH_PATHS_MAX], int family,
                              uint8_t path_count, uint16_t candidate_hint,
                              uint16_t port_mask,
                              uint8_t fail_after_bind_count,
                              uint16_t *base_port_out)
{
    struct sockaddr_storage wildcard;
    struct sockaddr_storage chosen;
    socklen_t wildcard_len = 0;
    socklen_t chosen_len = (socklen_t)sizeof(chosen);
    unsigned int attempt;
    uint16_t candidate;
    int probe = -1;

    if (!fds || !base_port_out ||
        !d33_cube_mask_valid(path_count, port_mask))
        return -1;
    *base_port_out = 0U;
    if (wildcard_address(family, 0U, &wildcard, &wildcard_len) != 0)
        return -1;
    if (candidate_hint != 0U) {
        candidate = candidate_hint;
    } else {
        probe = socket(family, SOCK_DGRAM, 0);
        if (probe < 0 || set_nonblocking_cloexec(probe) != 0 ||
            bind(probe, (struct sockaddr *)&wildcard, wildcard_len) != 0 ||
            getsockname(probe, (struct sockaddr *)&chosen, &chosen_len) != 0) {
            if (probe >= 0)
                (void)close(probe);
            return -1;
        }
        candidate = sockaddr_port(&chosen);
        (void)close(probe);
    }
    for (attempt = 0U; attempt < TRANSPORT_UDP_D32_BIND_ATTEMPTS; attempt++) {
        uint16_t base_port = 0U;
        unsigned int leg;

        if (d33_cube_base_candidate(candidate, path_count, port_mask,
                                    attempt, &base_port) != 0)
            return -1;
        for (leg = 0U; leg < path_count; leg++) {
            socklen_t bind_len = 0;
            uint16_t port = 0U;

            if (fail_after_bind_count != 0U &&
                leg >= fail_after_bind_count)
                break;
            if (d33_cube_port(base_port, path_count, port_mask,
                              (uint8_t)leg, &port) != 0 ||
                wildcard_address(family, port, &wildcard, &bind_len) != 0)
                break;
            fds[leg] = socket(family, SOCK_DGRAM, 0);
            if (fds[leg] < 0 || set_nonblocking_cloexec(fds[leg]) != 0 ||
                bind(fds[leg], (struct sockaddr *)&wildcard, bind_len) != 0)
                break;
        }
        /* The deterministic seam counts completed shadow binds.  Failing at
         * exactly N must still discard the complete shadow set; otherwise
         * the most important transaction boundary is untestable. */
        if (leg == path_count && fail_after_bind_count != 0U &&
            fail_after_bind_count == path_count) {
            close_fd_array(fds);
            continue;
        }
        if (leg == path_count) {
            *base_port_out = base_port;
            return 0;
        }
        close_fd_array(fds);
    }
    return -1;
}

/* The kernel supplies an ephemeral candidate; multipath rounds it down to an
 * N-aligned block and binds the entire adjacent block without SO_REUSE*.
 * Races/collisions close the partial block and retry atomically. */
static int bind_adjacent_client_fds(transport_udp_t *t, int family,
                                    uint8_t path_count,
                                    uint16_t candidate_hint,
                                    uint16_t *base_port_out)
{
    if (!t || !base_port_out || !multipath_path_count_valid(path_count))
        return -1;
    if (bind_cube_fd_array(t->fd, family, path_count, candidate_hint,
                           d33_cube_default_mask(path_count), 0U,
                           base_port_out) != 0)
        return -1;
    t->fd_count = path_count;
    return 0;
}

static int bind_cube_client_fds(transport_udp_t *t, int family,
                                uint8_t path_count,
                                uint16_t candidate_hint,
                                uint16_t port_mask,
                                uint16_t *base_port_out)
{
    if (!t || !base_port_out ||
        bind_cube_fd_array(t->fd, family, path_count, candidate_hint,
                           port_mask, 0U, base_port_out) != 0)
        return -1;
    t->fd_count = path_count;
    return 0;
}

/* Random layout deliberately asks the kernel for one ephemeral source port
 * per leg. There is no retry/search policy: every socket binds port zero
 * once, and a duplicate observed port fails the all-or-nothing allocation. */
static int bind_random_client_fds(transport_udp_t *t, int family,
                                  uint8_t path_count)
{
    struct sockaddr_storage wildcard;
    socklen_t wildcard_len = 0;
    unsigned int leg;

    if (!t || !multipath_path_count_valid(path_count) ||
        wildcard_address(family, 0U, &wildcard, &wildcard_len) != 0)
        return -1;
    for (leg = 0U; leg < path_count; leg++) {
        struct sockaddr_storage chosen;
        socklen_t chosen_len = (socklen_t)sizeof(chosen);
        uint16_t port;
        unsigned int earlier;

        t->fd[leg] = socket(family, SOCK_DGRAM, 0);
        if (t->fd[leg] < 0 || set_nonblocking_cloexec(t->fd[leg]) != 0 ||
            bind(t->fd[leg], (struct sockaddr *)&wildcard,
                 wildcard_len) != 0 ||
            getsockname(t->fd[leg], (struct sockaddr *)&chosen,
                        &chosen_len) != 0)
            break;
        t->fd_count = (uint8_t)(leg + 1U);
        port = sockaddr_port(&chosen);
        if (port == 0U)
            break;
        for (earlier = 0U; earlier < leg; earlier++) {
            struct sockaddr_storage previous;
            socklen_t previous_len = (socklen_t)sizeof(previous);

            if (getsockname(t->fd[earlier],
                            (struct sockaddr *)&previous,
                            &previous_len) != 0 ||
                sockaddr_port(&previous) == port)
                break;
        }
        if (earlier != leg)
            break;
    }
    if (leg == path_count)
        return 0;
    close_fds(t);
    return -1;
}

static int local_ports(const transport_udp_t *t,
                       uint16_t ports[MULTIPATH_PATHS_MAX])
{
    unsigned int leg;

    if (!t || !ports || t->fd_count == 0U)
        return -1;
    memset(ports, 0, sizeof(uint16_t) * MULTIPATH_PATHS_MAX);
    for (leg = 0U; leg < t->fd_count; leg++) {
        struct sockaddr_storage address;
        socklen_t length = (socklen_t)sizeof(address);

        if (t->fd[leg] < 0 ||
            getsockname(t->fd[leg], (struct sockaddr *)&address,
                        &length) != 0 ||
            (ports[leg] = sockaddr_port(&address)) == 0U)
            return -1;
    }
    return (int)t->fd_count;
}

static void log_random_ports(const transport_udp_t *t)
{
    uint16_t ports[MULTIPATH_PATHS_MAX];
    unsigned int leg;

    if (local_ports(t, ports) != (int)t->fd_count)
        return;
    fprintf(stderr,
            "transport_udp: bulk-transfer random local source ports count=%u ports=",
            (unsigned int)t->fd_count);
    for (leg = 0U; leg < t->fd_count; leg++)
        fprintf(stderr, "%s%u", leg == 0U ? "" : ",",
                (unsigned int)ports[leg]);
    fputc('\n', stderr);
}

static void log_cube_ports(const transport_udp_t *t, uint16_t base_port)
{
    uint16_t ports[MULTIPATH_PATHS_MAX];
    unsigned int leg;

    if (local_ports(t, ports) != (int)t->fd_count)
        return;
    fprintf(stderr,
            "transport_udp: bulk-transfer cube local source ports base=%u count=%u port-mask=0x%04x ports=",
            (unsigned int)base_port, (unsigned int)t->fd_count,
            (unsigned int)t->port_mask);
    for (leg = 0U; leg < t->fd_count; leg++)
        fprintf(stderr, "%s%u", leg == 0U ? "" : ",",
                (unsigned int)ports[leg]);
    fputc('\n', stderr);
}

/* -------------------------------------------------------------------------
 * open
 * ---------------------------------------------------------------------- */

static int udp_open(const transport_config_t *cfg, transport_t **out)
{
    unsigned int i;

    if (out)
        *out = NULL;
    if (cfg && cfg->udp_bound_port_out)
        *cfg->udp_bound_port_out = 0U;
    if (!cfg || !out || !cfg->udp_port) {
        fprintf(stderr,
                "transport_udp: invalid open arguments or missing --port\n");
        return -1;
    }
    if (!cfg->listen && !cfg->udp_host) {
        fprintf(stderr, "transport_udp: connect mode requires --host\n");
        return -1;
    }
    if (cfg->udp_multipath_paths != 0U &&
        !multipath_path_count_valid(cfg->udp_multipath_paths)) {
        fprintf(stderr,
                "transport_udp: multipath paths must be 2,4,8,16,32\n");
        return -1;
    }
    if (cfg->udp_port_layout > TRANSPORT_UDP_PORT_LAYOUT_RANDOM ||
        cfg->udp_port_mask_explicit > 1U ||
        (cfg->udp_multipath_paths == 0U &&
         (cfg->udp_port_layout != TRANSPORT_UDP_PORT_LAYOUT_BLOCK ||
          cfg->udp_port_mask != 0U ||
          cfg->udp_port_mask_explicit != 0U)) ||
        (cfg->listen &&
         (cfg->udp_port_layout != TRANSPORT_UDP_PORT_LAYOUT_BLOCK ||
          cfg->udp_port_mask != 0U ||
          cfg->udp_port_mask_explicit != 0U)) ||
        (cfg->udp_port_layout == TRANSPORT_UDP_PORT_LAYOUT_RANDOM &&
         (cfg->udp_port_mask != 0U ||
          cfg->udp_port_mask_explicit != 0U)) ||
        (cfg->udp_port_layout == TRANSPORT_UDP_PORT_LAYOUT_BLOCK &&
         (cfg->udp_port_mask != 0U ||
          cfg->udp_port_mask_explicit != 0U)) ||
        (cfg->udp_port_layout == TRANSPORT_UDP_PORT_LAYOUT_CUBE &&
         ((cfg->udp_port_mask_explicit != 0U &&
           !d33_cube_mask_valid(cfg->udp_multipath_paths,
                                cfg->udp_port_mask)) ||
          (cfg->udp_port_mask_explicit == 0U &&
           cfg->udp_port_mask != 0U)))) {
        fprintf(stderr,
                "transport_udp: invalid bulk-transfer source-port layout configuration\n");
        return -1;
    }

    transport_udp_t *t = calloc(1, sizeof(*t));
    if (!t) {
        fprintf(stderr, "transport_udp: calloc failed\n");
        return -1;
    }
    t->base.ops = &transport_udp;
    for (i = 0U; i < MULTIPATH_PATHS_MAX; i++) {
        t->fd[i] = -1;
        t->shadow_fd[i] = -1;
    }
    t->is_listener = cfg->listen;
    t->path_limit = cfg->udp_multipath_paths;
    t->port_layout = cfg->udp_port_layout;
    t->port_mask = cfg->udp_port_mask;
    t->port_mask_explicit = cfg->udp_port_mask_explicit;
    t->reroll_fail_after_bind_count =
        cfg->udp_reroll_fail_after_bind_count;

    struct addrinfo hints, *res = NULL, *selected = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    if (cfg->listen) hints.ai_flags = AI_PASSIVE;

    int rc = getaddrinfo(cfg->udp_host, cfg->udp_port, &hints, &res);
    if (rc != 0 || !res) {
        fprintf(stderr, "transport_udp: getaddrinfo(%s:%s): %s\n",
                cfg->udp_host ? cfg->udp_host : "*", cfg->udp_port,
                gai_strerror(rc));
        free(t);
        return -1;
    }
    selected = res;

    if (cfg->listen && !cfg->udp_host) {
        uint16_t requested_port = addrinfo_port(selected);
        uint16_t bound_port = 0U;

        if (bind_native_dual_listener(t, requested_port,
                                      &bound_port) != 0) {
            fprintf(stderr,
                    "transport_udp: cannot bind native IPv4+V6ONLY-IPv6 listener on one port: %s\n",
                    strerror(errno));
            close_fds(t);
            freeaddrinfo(res);
            free(t);
            return -1;
        }
        if (cfg->udp_bound_port_out)
            *cfg->udp_bound_port_out = bound_port;
        if (!cfg->quiet_open_success) {
            fprintf(stderr,
                    "transport_udp: listening on udp port %u families=ipv4,ipv6\n",
                    (unsigned int)bound_port);
        }
    } else if (cfg->listen || t->path_limit == 0U) {
        t->fd[0] = socket(selected->ai_family, SOCK_DGRAM, 0);
        if (t->fd[0] < 0) {
            fprintf(stderr, "transport_udp: socket: %s\n", strerror(errno));
            freeaddrinfo(res);
            free(t);
            return -1;
        }
        t->fd_count = 1U;
        if (set_nonblocking_cloexec(t->fd[0]) != 0) {
            fprintf(stderr,
                    "transport_udp: cannot arm nonblocking socket: %s\n",
                    strerror(errno));
            close_fds(t);
            freeaddrinfo(res);
            free(t);
            return -1;
        }
    } else if (t->port_layout == TRANSPORT_UDP_PORT_LAYOUT_BLOCK) {
        uint16_t base_port = 0U;

        t->port_mask = d33_cube_default_mask(t->path_limit);
        if (bind_adjacent_client_fds(
                t, selected->ai_family, t->path_limit,
                cfg->udp_multipath_candidate_hint, &base_port) != 0) {
            fprintf(stderr,
                    "transport_udp: cannot bind an aligned adjacent multipath source-port block for %u paths\n",
                    (unsigned int)t->path_limit);
            close_fds(t);
            freeaddrinfo(res);
            free(t);
            return -1;
        }
        fprintf(stderr,
                "transport_udp: multipath local source ports base=%u count=%u mask=0x%08x\n",
                (unsigned int)base_port,
                (unsigned int)t->path_limit,
                multipath_low_mask(t->path_limit));
    } else if (t->port_layout == TRANSPORT_UDP_PORT_LAYOUT_RANDOM) {
        if (bind_random_client_fds(
                t, selected->ai_family, t->path_limit) != 0) {
            fprintf(stderr,
                    "transport_udp: cannot bind distinct kernel-selected bulk-transfer random source ports for %u paths\n",
                    (unsigned int)t->path_limit);
            close_fds(t);
            freeaddrinfo(res);
            free(t);
            return -1;
        }
        log_random_ports(t);
    } else {
        uint16_t base_port = 0U;

        if (t->port_mask == 0U)
            t->port_mask = d33_cube_default_mask(t->path_limit);
        if (bind_cube_client_fds(
                t, selected->ai_family, t->path_limit,
                cfg->udp_multipath_candidate_hint, t->port_mask,
                &base_port) != 0) {
            fprintf(stderr,
                    "transport_udp: cannot bind an all-or-none bulk-transfer source-port cube for %u paths mask=0x%04x\n",
                    (unsigned int)t->path_limit,
                    (unsigned int)t->port_mask);
            close_fds(t);
            freeaddrinfo(res);
            free(t);
            return -1;
        }
        log_cube_ports(t, base_port);
    }

    if (cfg->listen && cfg->udp_host) {
        int one = 1;

        /* Exclusive bind only; see listener_socket_open. */
        if (selected->ai_family == AF_INET6 &&
            setsockopt(t->fd[0], IPPROTO_IPV6, IPV6_V6ONLY,
                       &one, sizeof(one)) != 0) {
            fprintf(stderr,
                    "transport_udp: cannot configure native listener socket: %s\n",
                    strerror(errno));
            close_fds(t);
            freeaddrinfo(res);
            free(t);
            return -1;
        }
        if (bind(t->fd[0], selected->ai_addr,
                 selected->ai_addrlen) != 0) {
            fprintf(stderr, "transport_udp: bind(%s): %s\n",
                    cfg->udp_port, strerror(errno));
            close_fds(t);
            freeaddrinfo(res);
            free(t);
            return -1;
        }
        struct sockaddr_storage bound;
        socklen_t blen = sizeof(bound);
        uint16_t bport = 0;
        if (getsockname(t->fd[0], (struct sockaddr *)&bound, &blen) == 0) {
            if (bound.ss_family == AF_INET)
                bport = ntohs(((struct sockaddr_in *)&bound)->sin_port);
            else if (bound.ss_family == AF_INET6)
                bport = ntohs(((struct sockaddr_in6 *)&bound)->sin6_port);
        }
        if (bport == 0U) {
            fprintf(stderr,
                    "transport_udp: listener bound without a native service port\n");
            close_fds(t);
            freeaddrinfo(res);
            free(t);
            return -1;
        }
        if (cfg->udp_bound_port_out)
            *cfg->udp_bound_port_out = bport;
        if (!cfg->quiet_open_success) {
            fprintf(stderr,
                    "transport_udp: listening on udp port %u family=%s\n",
                    (unsigned)bport,
                    selected->ai_family == AF_INET6 ? "ipv6" : "ipv4");
        }
        /* No peer yet — learned from the first frame that passes AEAD. */
    } else if (!cfg->listen) {
        /* Client sockets remain unconnected. Ordinary roaming-freshest-path lets the kernel
         * choose an ephemeral source; multipath has already bound its adjacent
         * wildcard source-port block, so a local IP change still needs no
         * address-specific reconfiguration. */
        if (t->path_limit != 0U) {
            multipath_token_t initial;
            if (token_from_sockaddr(0U, selected->ai_addr,
                                    (socklen_t)selected->ai_addrlen,
                                    &initial) != 0 ||
                sockaddr_from_token(&initial, &t->peer,
                                    &t->peer_len) != 0) {
                fprintf(stderr,
                        "transport_udp: multipath peer is not canonical IPv4/IPv6\n");
                close_fds(t);
                freeaddrinfo(res);
                free(t);
                return -1;
            }
        } else {
            /* Preserve the original roaming-freshest-path address domain byte-for-byte when
             * multipath is not requested (including mapped/legacy sockaddr forms
             * and platform flowinfo). */
            memcpy(&t->peer, selected->ai_addr, selected->ai_addrlen);
            t->peer_len = (socklen_t)selected->ai_addrlen;
        }
        t->have_peer = 1;
        t->peer_leg = 0U;
        char s[NI_MAXHOST + NI_MAXSERV + 2];
        addr_str((struct sockaddr *)&t->peer, t->peer_len, s, sizeof(s));
        if (t->path_limit != 0U)
            fprintf(stderr,
                    "transport_udp: peer %s with %u local legs\n", s,
                    (unsigned int)t->path_limit);
        else
            fprintf(stderr, "transport_udp: peer %s\n", s);
    }

    freeaddrinfo(res);
    *out = &t->base;
    return 0;
}

/* -------------------------------------------------------------------------
 * send: one datagram per frame, to the confirmed peer address
 * ---------------------------------------------------------------------- */

static int udp_send(transport_t *base, const uint8_t *data, size_t len)
{
    transport_udp_t *t = (transport_udp_t *)base;
    if (!t->have_peer) {
        /* Listener before the first confirmed frame — nothing to send to.
         * errno must not look like a hangup to session_run. */
        t->stats.tx_fail++;
        errno = 0;
        return -1;
    }
    ssize_t n = sendto(t->fd[t->peer_leg], data, len, 0,
                       (struct sockaddr *)&t->peer, t->peer_len);
    if (n < 0 || (size_t)n != len) {
        /* Transient network errors (ENETUNREACH during a roam, etc.) are
         * expected mid-outage; report failure but never as a hangup. */
        t->stats.tx_fail++;
        errno = 0;
        return -1;
    }
    t->stats.tx_ok++;
    t->stats.tx_bytes += (uint64_t)len;
    return 0;
}

/* send-scheduler: one nonblocking datagram attempt. UDP is atomic: there is no partial
 * state, and EAGAIN leaves the session's one encoded frame untouched. */
static int udp_send_step(transport_t *base, const uint8_t *data, size_t len)
{
    transport_udp_t *t = (transport_udp_t *)base;
    if (!t->have_peer) {
        t->stats.tx_fail++;
        errno = 0;
        return TRANSPORT_SEND_FAILED;
    }
    ssize_t n = sendto(t->fd[t->peer_leg], data, len, 0,
                       (struct sockaddr *)&t->peer, t->peer_len);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        t->stats.tx_would_block++;
        errno = 0;
        return TRANSPORT_SEND_WOULD_BLOCK;
    }
    if (n < 0 && errno == EMSGSIZE) {
        t->stats.tx_fail++;
        t->stats.tx_too_large++;
        errno = 0;
        return TRANSPORT_SEND_TOO_LARGE;
    }
    if (n < 0 || (size_t)n != len) {
        t->stats.tx_fail++;
        errno = 0;
        return TRANSPORT_SEND_FAILED;
    }
    t->stats.tx_ok++;
    t->stats.tx_bytes += (uint64_t)len;
    return TRANSPORT_SEND_COMPLETE;
}

static int udp_send_step_to(transport_t *base,
                            const multipath_token_t *path,
                            const uint8_t *data, size_t len)
{
    transport_udp_t *t = (transport_udp_t *)base;
    struct sockaddr_storage peer;
    socklen_t peer_len;
    ssize_t n;

    if (!multipath_token_valid(path) || path->local_leg >= t->fd_count ||
        t->fd[path->local_leg] < 0 ||
        sockaddr_from_token(path, &peer, &peer_len) != 0) {
        t->stats.tx_fail++;
        errno = 0;
        return TRANSPORT_SEND_FAILED;
    }
    n = sendto(t->fd[path->local_leg], data, len, 0,
               (struct sockaddr *)&peer, peer_len);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        t->stats.tx_would_block++;
        errno = 0;
        return TRANSPORT_SEND_WOULD_BLOCK;
    }
    if (n < 0 && errno == EMSGSIZE) {
        t->stats.tx_fail++;
        t->stats.tx_too_large++;
        errno = 0;
        return TRANSPORT_SEND_TOO_LARGE;
    }
    if (n < 0 || (size_t)n != len) {
        if (n >= 0)
            fprintf(stderr,
                    "transport_udp: FATAL: multipath atomic datagram was short (%zd/%zu)\n",
                    n, len);
        t->stats.tx_fail++;
        errno = 0;
        return TRANSPORT_SEND_FAILED;
    }
    t->stats.tx_ok++;
    t->stats.tx_bytes += (uint64_t)len;
    return TRANSPORT_SEND_COMPLETE;
}

static int udp_send_cancel_untouched(transport_t *base)
{
    (void)base;
    /* sendto() is atomic. WOULD_BLOCK enqueued no datagram and retains no
     * transport-owned continuation state. */
    return 0;
}

/* -------------------------------------------------------------------------
 * recv: one datagram = one frame; source becomes the candidate peer
 * ---------------------------------------------------------------------- */

static int udp_recv_datagram(transport_udp_t *t, uint8_t *buf, size_t max,
                             int timeout_ms, uint8_t *selected_out,
                             struct sockaddr_storage *source_out,
                             socklen_t *source_length_out)
{
    struct pollfd pfds[MULTIPATH_PATHS_MAX];
    unsigned int offset;
    int selected = -1;
    socklen_t source_length = (socklen_t)sizeof(*source_out);
    ssize_t length;

    if (!t || !buf || max == 0U || !selected_out || !source_out ||
        !source_length_out || t->fd_count == 0U ||
        t->fd_count > MULTIPATH_PATHS_MAX) {
        errno = 0;
        return -1;
    }
    memset(source_out, 0, sizeof(*source_out));
    for (offset = 0U; offset < t->fd_count; offset++) {
        if (t->fd[offset] < 0) {
            errno = 0;
            return -1;
        }
        pfds[offset].fd = t->fd[offset];
        pfds[offset].events = POLLIN;
        pfds[offset].revents = 0;
    }
    for (;;) {
        int result = poll(pfds, t->fd_count, timeout_ms);

        if (result < 0 && errno == EINTR)
            continue;
        if (result <= 0) {
            errno = 0;
            return -1;
        }
        break;
    }
    for (offset = 0U; offset < t->fd_count; offset++) {
        unsigned int candidate =
            ((unsigned int)t->rx_cursor + offset) % t->fd_count;

        if ((pfds[candidate].revents &
             (POLLIN | POLLERR | POLLHUP)) != 0) {
            selected = (int)candidate;
            break;
        }
    }
    if (selected < 0) {
        errno = 0;
        return -1;
    }
    t->rx_cursor = (uint8_t)
        (((unsigned int)selected + 1U) % t->fd_count);
    length = recvfrom(t->fd[(size_t)selected], buf, max, 0,
                      (struct sockaddr *)source_out, &source_length);
    if (length < 0) {
        errno = 0; /* datagrams have no stream hangup */
        return -1;
    }
    /* Keep one spare byte so an exact-fit datagram cannot be mistaken for a
     * complete bulk-transfer frame after portable recvfrom() truncation. */
    if ((size_t)length >= max) {
        t->stats.rx_drop++;
        errno = 0;
        return -1;
    }
    *selected_out = (uint8_t)selected;
    *source_length_out = source_length;
    return (int)length;
}

static int udp_recv_from(transport_t *base, uint8_t *buf, size_t max,
                         int timeout_ms, multipath_token_t *path_out)
{
    transport_udp_t *t = (transport_udp_t *)base;
    struct sockaddr_storage source;
    socklen_t source_length = 0;
    uint8_t selected = 0U;
    int length;

    if (!path_out) {
        errno = 0;
        return -1;
    }
    memset(path_out, 0, sizeof(*path_out));
    length = udp_recv_datagram(t, buf, max, timeout_ms, &selected,
                               &source, &source_length);
    if (length < 0)
        return -1;
    if (token_from_sockaddr(selected, (struct sockaddr *)&source,
                            source_length, path_out) != 0) {
        t->stats.rx_drop++;
        t->have_cand = 0;
        errno = 0;
        return -1;
    }
    /* multipath engine and transport compare the same canonical identity. This
     * also keeps mapped IPv4 out of the retained family-6 identity. */
    if (sockaddr_from_token(path_out, &t->cand, &t->cand_len) != 0) {
        t->stats.rx_drop++;
        t->have_cand = 0;
        errno = 0;
        return -1;
    }
    t->cand_leg = selected;
    t->have_cand = 1;
    t->stats.rx_ok++;
    t->stats.rx_bytes += (uint64_t)length;
    return length;
}

static int udp_recv(transport_t *base, uint8_t *buf, size_t max,
                    int timeout_ms)
{
    transport_udp_t *t = (transport_udp_t *)base;
    struct sockaddr_storage source;
    socklen_t source_length = 0;
    uint8_t selected = 0U;
    int length = udp_recv_datagram(t, buf, max, timeout_ms, &selected,
                                   &source, &source_length);

    if (length < 0)
        return -1;
    /* Exact pre-D32 roaming-freshest-path behavior: ordinary mode keeps the platform's raw
     * family-native sockaddr and defers authority to AEAD/replay/HWM. */
    memcpy(&t->cand, &source, sizeof(source));
    t->cand_len = source_length;
    t->cand_leg = selected;
    t->have_cand = 1;
    t->stats.rx_ok++;
    t->stats.rx_bytes += (uint64_t)length;
    return length;
}

static int udp_recv_source(transport_t *base, uint8_t *buf, size_t max,
                           int timeout_ms, multipath_token_t *path_out,
                           preauth_source_t *source_out)
{
    transport_udp_t *t = (transport_udp_t *)base;
    struct sockaddr_storage source;
    socklen_t source_length = 0;
    uint8_t selected = 0U;
    int length;

    if (!path_out || !source_out) {
        errno = 0;
        return -1;
    }
    memset(path_out, 0, sizeof(*path_out));
    memset(source_out, 0, sizeof(*source_out));
    length = udp_recv_datagram(t, buf, max, timeout_ms, &selected,
                               &source, &source_length);
    if (length < 0)
        return -1;
    if (preauth_source_from_sockaddr((struct sockaddr *)&source,
                                     source_length, source_out) != 0 ||
        canonical_token_from_sockaddr(selected,
                                      (struct sockaddr *)&source,
                                      source_length, source_out,
                                      path_out) != 0) {
        t->stats.rx_drop++;
        t->have_cand = 0;
        memset(path_out, 0, sizeof(*path_out));
        memset(source_out, 0, sizeof(*source_out));
        errno = 0;
        return -1;
    }
    /* Preserve the exact platform-native candidate. Ordinary roaming-freshest-path confirms
     * this value; multipath confirms path_out instead. */
    memcpy(&t->cand, &source, sizeof(source));
    t->cand_len = source_length;
    t->cand_leg = selected;
    t->have_cand = 1;
    t->stats.rx_ok++;
    t->stats.rx_bytes += (uint64_t)length;
    return length;
}

/* -------------------------------------------------------------------------
 * peer_confirm: promote candidate → confirmed (called by the session layer
 * only after AEAD pass + replay HWM advance — see transport.h)
 * ---------------------------------------------------------------------- */

static int udp_peer_confirm(transport_t *base)
{
    transport_udp_t *t = (transport_udp_t *)base;
    int had_peer;
    if (!t->have_cand) return 0;

    had_peer = t->have_peer;
    int changed = !t->have_peer || t->cand_leg != t->peer_leg ||
                  t->cand_len != t->peer_len ||
                  memcmp(&t->cand, &t->peer, t->cand_len) != 0;
    if (!changed) return 0;

    memcpy(&t->peer, &t->cand, sizeof(t->cand));
    t->peer_len  = t->cand_len;
    t->peer_leg = t->cand_leg;
    t->have_peer = 1;
    char s[NI_MAXHOST + NI_MAXSERV + 2];
    addr_str((struct sockaddr *)&t->peer, t->peer_len, s, sizeof(s));
    fprintf(stderr, "transport_udp: peer roamed to %s\n", s);
    return had_peer ? 1 : 0;
}

static int udp_peer_confirm_from(transport_t *base,
                                 const multipath_token_t *path)
{
    transport_udp_t *t = (transport_udp_t *)base;
    struct sockaddr_storage peer;
    socklen_t peer_len;
    int had_peer;
    int changed;

    if (!multipath_token_valid(path) || path->local_leg >= t->fd_count ||
        sockaddr_from_token(path, &peer, &peer_len) != 0)
        return -1;
    had_peer = t->have_peer;
    changed = !t->have_peer || path->local_leg != t->peer_leg ||
              peer_len != t->peer_len ||
              memcmp(&peer, &t->peer, peer_len) != 0;
    if (!changed)
        return 0;
    t->peer = peer;
    t->peer_len = peer_len;
    t->peer_leg = path->local_leg;
    t->have_peer = 1;
    /* Session-level multipath state publishes bounded mask transitions.  Logging
     * every physical leg adoption here makes clean N=32 validation capable of
     * filling a caller's stderr pipe and blocking the sole event loop. */
    return had_peer ? 1 : 0;
}

/* -------------------------------------------------------------------------
 * close / stats / get_fd
 * ---------------------------------------------------------------------- */

static void udp_close(transport_t *base)
{
    transport_udp_t *t = (transport_udp_t *)base;
    close_fds(t);
    free(t);
}

static int udp_stats(transport_t *base, transport_stats_t *out)
{
    transport_udp_t *t = (transport_udp_t *)base;
    *out = t->stats;
    out->rssi_last = INT16_MIN;
    out->snr_last  = INT8_MIN;
    out->transport_id = 3;
    return 0;
}

static int udp_get_fd(transport_t *base)
{
    transport_udp_t *t = (transport_udp_t *)base;
    return t->fd[0];
}

static int udp_get_send_fd(transport_t *base)
{
    transport_udp_t *t = (transport_udp_t *)base;
    if (!t->have_peer || t->peer_leg >= t->fd_count)
        return -1;
    return t->fd[t->peer_leg];
}

static int udp_get_recv_fds(transport_t *base,
                            int fds[MULTIPATH_PATHS_MAX])
{
    transport_udp_t *t = (transport_udp_t *)base;
    unsigned int i;

    if (!fds)
        return -1;
    for (i = 0; i < t->fd_count; i++)
        fds[i] = t->fd[i];
    return (int)t->fd_count;
}

static int udp_get_path_send_fd(transport_t *base,
                                const multipath_token_t *path)
{
    transport_udp_t *t = (transport_udp_t *)base;
    if (!multipath_token_valid(path) || path->local_leg >= t->fd_count)
        return -1;
    return t->fd[path->local_leg];
}

static int udp_configured_local_ports(
    transport_t *base, uint16_t ports[MULTIPATH_PATHS_MAX])
{
    return local_ports((const transport_udp_t *)base, ports);
}

static int udp_configured_local_families(
    transport_t *base, uint8_t families[MULTIPATH_PATHS_MAX])
{
    transport_udp_t *t = (transport_udp_t *)base;
    unsigned int leg;

    if (!t || !families || t->fd_count == 0U)
        return -1;
    memset(families, 0, sizeof(uint8_t) * MULTIPATH_PATHS_MAX);
    for (leg = 0U; leg < t->fd_count; leg++) {
        struct sockaddr_storage address;
        socklen_t length = (socklen_t)sizeof(address);

        memset(&address, 0, sizeof(address));
        if (t->fd[leg] < 0 ||
            getsockname(t->fd[leg], (struct sockaddr *)&address,
                        &length) != 0)
            return -1;
        if (address.ss_family == AF_INET)
            families[leg] = 4U;
        else if (address.ss_family == AF_INET6)
            families[leg] = 6U;
        else
            return -1;
    }
    return (int)t->fd_count;
}

static int udp_configured_port_layout(transport_t *base)
{
    const transport_udp_t *t = (const transport_udp_t *)base;

    if (!t || t->is_listener || t->path_limit == 0U)
        return -1;
    return (int)t->port_layout;
}

static void shadow_abort_all(transport_udp_t *t)
{
    unsigned int leg;

    if (!t)
        return;
    for (leg = 0U; leg < MULTIPATH_PATHS_MAX; leg++) {
        if (t->shadow_fd[leg] >= 0) {
            (void)close(t->shadow_fd[leg]);
            t->shadow_fd[leg] = -1;
        }
    }
    t->shadow_mask = 0U;
    t->shadow_port_mask = 0U;
}

static int udp_path_reroll_prepare(
    transport_t *base, uint32_t local_leg_mask,
    transport_path_reroll_t *reroll_out)
{
    transport_udp_t *t = (transport_udp_t *)base;
    struct sockaddr_storage old_address;
    struct sockaddr_storage wildcard;
    struct sockaddr_storage chosen;
    socklen_t old_length = (socklen_t)sizeof(old_address);
    socklen_t wildcard_length = 0;
    socklen_t chosen_length = (socklen_t)sizeof(chosen);
    uint16_t ports[MULTIPATH_PATHS_MAX];
    uint16_t new_port;
    uint8_t leg = 0U;
    unsigned int i;

    if (!t || !reroll_out || t->is_listener || t->path_limit == 0U ||
        t->shadow_mask != 0U || t->shadow_cookie == UINT64_MAX ||
        local_leg_mask == 0U ||
        (local_leg_mask & ~multipath_low_mask(t->path_limit)) != 0U ||
        local_ports(t, ports) != (int)t->fd_count)
        return -1;
    if (t->port_layout == TRANSPORT_UDP_PORT_LAYOUT_RANDOM &&
        (local_leg_mask & (local_leg_mask - UINT32_C(1))) != 0U)
        return -1;
    if (t->port_layout != TRANSPORT_UDP_PORT_LAYOUT_RANDOM &&
        local_leg_mask != multipath_low_mask(t->path_limit))
        return -1;
    if (getsockname(t->fd[0], (struct sockaddr *)&old_address,
                    &old_length) != 0)
        return -1;

    memset(reroll_out, 0, sizeof(*reroll_out));
    reroll_out->old_port_mask = t->port_mask;
    reroll_out->new_port_mask = t->port_mask;

    if (t->port_layout != TRANSPORT_UDP_PORT_LAYOUT_RANDOM) {
        uint16_t base_port = 0U;

        if (t->port_layout == TRANSPORT_UDP_PORT_LAYOUT_CUBE &&
            !t->port_mask_explicit &&
            d33_cube_next_mask(t->path_limit, t->port_mask,
                               &reroll_out->new_port_mask) != 0)
            return -1;
        if (bind_cube_fd_array(
                t->shadow_fd, old_address.ss_family, t->path_limit, 0U,
                reroll_out->new_port_mask,
                t->reroll_fail_after_bind_count, &base_port) != 0) {
            shadow_abort_all(t);
            return -1;
        }
        t->shadow_port_mask = reroll_out->new_port_mask;
        reroll_out->cookie = ++t->shadow_cookie;
        reroll_out->local_leg_mask = local_leg_mask;
        for (i = 0U; i < t->fd_count; i++) {
            struct sockaddr_storage shadow_address;
            socklen_t shadow_length =
                (socklen_t)sizeof(shadow_address);

            reroll_out->old_port[i] = ports[i];
            if (getsockname(t->shadow_fd[i],
                            (struct sockaddr *)&shadow_address,
                            &shadow_length) != 0 ||
                (reroll_out->new_port[i] =
                    sockaddr_port(&shadow_address)) == 0U) {
                shadow_abort_all(t);
                memset(reroll_out, 0, sizeof(*reroll_out));
                return -1;
            }
        }
        t->shadow_mask = local_leg_mask;
        return 0;
    }

    while ((local_leg_mask & (UINT32_C(1) << leg)) == 0U)
        leg++;
    if (leg >= t->fd_count ||
        getsockname(t->fd[leg], (struct sockaddr *)&old_address,
                    &old_length) != 0 ||
        wildcard_address(old_address.ss_family, 0U, &wildcard,
                         &wildcard_length) != 0)
        return -1;
    t->shadow_fd[leg] = socket(old_address.ss_family, SOCK_DGRAM, 0);
    if (t->shadow_fd[leg] < 0 ||
        set_nonblocking_cloexec(t->shadow_fd[leg]) != 0 ||
        bind(t->shadow_fd[leg], (struct sockaddr *)&wildcard,
             wildcard_length) != 0 ||
        getsockname(t->shadow_fd[leg], (struct sockaddr *)&chosen,
                    &chosen_length) != 0) {
        shadow_abort_all(t);
        return -1;
    }
    new_port = sockaddr_port(&chosen);
    if (new_port == 0U) {
        shadow_abort_all(t);
        return -1;
    }
    for (i = 0U; i < t->fd_count; i++) {
        if (ports[i] == new_port) {
            shadow_abort_all(t);
            return -1;
        }
    }
    reroll_out->cookie = ++t->shadow_cookie;
    reroll_out->local_leg_mask = local_leg_mask;
    for (i = 0U; i < t->fd_count; i++) {
        reroll_out->old_port[i] = ports[i];
        reroll_out->new_port[i] = ports[i];
    }
    reroll_out->new_port[leg] = new_port;
    t->shadow_mask = local_leg_mask;
    t->shadow_port_mask = t->port_mask;
    return 0;
}

static int udp_path_reroll_ready(
    transport_t *base, const transport_path_reroll_t *reroll)
{
    const transport_udp_t *t = (const transport_udp_t *)base;
    uint16_t ports[MULTIPATH_PATHS_MAX];
    unsigned int leg;

    if (!t || !reroll || reroll->cookie == 0U ||
        reroll->cookie != t->shadow_cookie ||
        reroll->local_leg_mask == 0U ||
        reroll->local_leg_mask != t->shadow_mask ||
        reroll->old_port_mask != t->port_mask ||
        reroll->new_port_mask != t->shadow_port_mask ||
        local_ports(t, ports) != (int)t->fd_count)
        return 0;
    for (leg = 0U; leg < t->fd_count; leg++) {
        struct sockaddr_storage shadow_address;
        socklen_t shadow_length = (socklen_t)sizeof(shadow_address);
        uint32_t bit = UINT32_C(1) << leg;

        if (ports[leg] != reroll->old_port[leg])
            return 0;
        if ((reroll->local_leg_mask & bit) == 0U) {
            if (t->shadow_fd[leg] >= 0 ||
                reroll->new_port[leg] != ports[leg])
                return 0;
            continue;
        }
        if (t->shadow_fd[leg] < 0 ||
            getsockname(t->shadow_fd[leg],
                        (struct sockaddr *)&shadow_address,
                        &shadow_length) != 0 ||
            sockaddr_port(&shadow_address) != reroll->new_port[leg] ||
            reroll->new_port[leg] == reroll->old_port[leg])
            return 0;
    }
    return 1;
}

static void udp_path_reroll_commit(
    transport_t *base, const transport_path_reroll_t *reroll)
{
    transport_udp_t *t = (transport_udp_t *)base;
    unsigned int leg;

    if (!t || !reroll) {
        fprintf(stderr,
                "transport_udp: bulk-transfer reroll commit rejected invalid arguments\n");
        return;
    }
    if (reroll->cookie == 0U ||
        reroll->cookie != t->shadow_cookie ||
        reroll->local_leg_mask == 0U ||
        reroll->local_leg_mask != t->shadow_mask) {
        fprintf(stderr,
                "transport_udp: bulk-transfer reroll commit rejected cookie=%llu expected=%llu mask=0x%08x expected=0x%08x\n",
                (unsigned long long)reroll->cookie,
                (unsigned long long)t->shadow_cookie,
                (unsigned int)reroll->local_leg_mask,
                (unsigned int)t->shadow_mask);
        return;
    }

    /* The session calls ready immediately before its transactional multipath
     * mutation. No callback or event-loop turn intervenes; this is therefore
     * an infallible array swap whose only syscall is best-effort old-fd
     * cleanup. */
    for (leg = 0U; leg < t->fd_count; leg++) {
        uint32_t bit = UINT32_C(1) << leg;
        int old_fd;

        if ((reroll->local_leg_mask & bit) == 0U)
            continue;
        old_fd = t->fd[leg];
        t->fd[leg] = t->shadow_fd[leg];
        t->shadow_fd[leg] = -1;
        (void)close(old_fd);
    }
    t->port_mask = reroll->new_port_mask;
    t->shadow_mask = 0U;
    t->shadow_port_mask = 0U;
}

static void udp_path_reroll_abort(
    transport_t *base, const transport_path_reroll_t *reroll)
{
    transport_udp_t *t = (transport_udp_t *)base;

    if (!t || !reroll || reroll->cookie == 0U ||
        reroll->cookie != t->shadow_cookie ||
        reroll->local_leg_mask != t->shadow_mask)
        return;
    shadow_abort_all(t);
}

static int udp_configured_paths(
    transport_t *base,
    multipath_token_t paths[MULTIPATH_PATHS_MAX])
{
    transport_udp_t *t = (transport_udp_t *)base;
    int count = 0;
    unsigned int offset;

    if (!paths)
        return -1;
    memset(paths, 0, sizeof(multipath_token_t) * MULTIPATH_PATHS_MAX);
    if (!t->have_peer)
        return 0;
    if (t->path_limit != 0U && !t->is_listener) {
        if (t->fd_count != t->path_limit)
            return -1;
        for (offset = 0U; offset < t->fd_count; offset++) {
            uint8_t leg = (uint8_t)
                (((unsigned int)t->peer_leg + offset) &
                 (t->path_limit - 1U));

            if (token_from_sockaddr(leg,
                                    (struct sockaddr *)&t->peer,
                                    t->peer_len,
                                    &paths[count]) != 0)
                return -1;
            count++;
        }
    } else {
        if (token_from_sockaddr(t->peer_leg,
                                (struct sockaddr *)&t->peer, t->peer_len,
                                &paths[count]) != 0)
            return -1;
        count++;
    }
    return count;
}

static int udp_configured_path_limit(transport_t *base)
{
    transport_udp_t *t = (transport_udp_t *)base;

    return (int)t->path_limit;
}

static int udp_quiesce_unselected_paths(transport_t *base)
{
    transport_udp_t *t = (transport_udp_t *)base;
    unsigned int leg;

    if (!t || t->shadow_mask != 0U)
        return -1;
    if (t->path_limit == 0U)
        return 0;
    if (!t->is_listener) {
        if (t->fd_count != t->path_limit || t->fd_count < 2U ||
            t->fd[0] < 0)
            return -1;
        for (leg = 1U; leg < t->fd_count; leg++) {
            if (t->fd[leg] < 0)
                return -1;
            (void)close(t->fd[leg]);
            t->fd[leg] = -1;
        }
        t->fd_count = 1U;
        t->peer_leg = 0U;
        t->rx_cursor = 0U;
        /* A datagram received on a now-retired leg must not retain a
         * candidate that ordinary roaming-freshest-path could later confirm. */
        t->have_cand = 0;
        t->cand_leg = 0U;
        memset(&t->cand, 0, sizeof(t->cand));
        t->cand_len = 0;
    }
    t->path_limit = 0U;
    t->port_layout = TRANSPORT_UDP_PORT_LAYOUT_BLOCK;
    t->port_mask_explicit = 0U;
    t->port_mask = 0U;
    return 0;
}

const transport_ops_t transport_udp = {
    .name  = "udp",
    .poll_hup_err_is_readable = 1U,
    .open  = udp_open,
    .send  = udp_send,
    .send_step = udp_send_step,
    .send_cancel_untouched = udp_send_cancel_untouched,
    .recv  = udp_recv,
    .close = udp_close,
    .stats = udp_stats,
    .get_fd = udp_get_fd,
    .get_send_fd = udp_get_send_fd,
    .peer_confirm = udp_peer_confirm,
    .recv_source = udp_recv_source,
    .recv_from = udp_recv_from,
    .send_step_to = udp_send_step_to,
    .peer_confirm_from = udp_peer_confirm_from,
    .configured_paths = udp_configured_paths,
    .configured_path_limit = udp_configured_path_limit,
    .quiesce_unselected_paths = udp_quiesce_unselected_paths,
    .get_recv_fds = udp_get_recv_fds,
    .get_path_send_fd = udp_get_path_send_fd,
    .configured_local_ports = udp_configured_local_ports,
    .configured_local_families = udp_configured_local_families,
    .configured_port_layout = udp_configured_port_layout,
    .path_reroll_prepare = udp_path_reroll_prepare,
    .path_reroll_ready = udp_path_reroll_ready,
    .path_reroll_commit = udp_path_reroll_commit,
    .path_reroll_abort = udp_path_reroll_abort,
};
