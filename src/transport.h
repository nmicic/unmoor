/*
 * transport.h — transport abstraction interface
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * Defines transport_ops_t, transport_t, transport_config_t, transport_stats_t
 * exactly as specified.
 */
#ifndef UNMOOR_TRANSPORT_H
#define UNMOOR_TRANSPORT_H

#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stddef.h>
#include <limits.h>

#include "multipath.h"
#include "preauth_budget.h"
#include "transport_tx.h"

/* multipath client legs are selected only from the IANA dynamic/private range.
 * The range is divisible by every supported count and the search bound is
 * fixed before any peer traffic. */
#define TRANSPORT_UDP_D32_PORT_MIN 49152U
#define TRANSPORT_UDP_D32_PORT_MAX 65535U
#define TRANSPORT_UDP_D32_BIND_ATTEMPTS 64U

typedef enum {
    TRANSPORT_UDP_PORT_LAYOUT_BLOCK = 0,
    TRANSPORT_UDP_PORT_LAYOUT_CUBE = 1,
    TRANSPORT_UDP_PORT_LAYOUT_RANDOM = 2
} transport_udp_port_layout_t;

/* One fixed transport-owned shadow allocation. `local_leg_mask` is the
 * physical fd-index domain, never a multipath table-slot or semantic bitmap. */
typedef struct transport_path_reroll {
    uint64_t cookie;
    uint32_t local_leg_mask;
    uint16_t old_port_mask;
    uint16_t new_port_mask;
    uint16_t old_port[MULTIPATH_PATHS_MAX];
    uint16_t new_port[MULTIPATH_PATHS_MAX];
} transport_path_reroll_t;

/* -------------------------------------------------------------------------
 * Configuration
 * ---------------------------------------------------------------------- */

typedef struct transport_config {
    const char *transport;      /* "udp", "unix", "stdio" */
    /* unix transport */
    const char *path;           /* UNIX domain socket path */
    int         listen;         /* 1 = listen mode, 0 = connect mode */
    /* udp transport */
    const char *udp_host;       /* connect: server host; listen: bind addr (NULL = any) */
    const char *udp_port;       /* port / service string for getaddrinfo() */
    uint8_t     udp_multipath_paths; /* multipath: 0 or exact 2/4/8/16/32 */
    uint8_t     udp_port_layout; /* transport_udp_port_layout_t; zero=block */
    uint8_t     udp_port_mask_explicit; /* bulk-transfer cube only */
    uint16_t    udp_port_mask; /* bulk-transfer cube low-14-bit mask */
    /* Internal deterministic allocator seam used only by the native
     * regression harness.  Zero preserves the production kernel-selected
     * starting candidate; there is deliberately no CLI for this field. */
    uint16_t    udp_multipath_candidate_hint;
    /* Internal deterministic all-set shadow-allocation failure seam.  Zero
     * is disabled; N fails after N successful shadow binds on every
     * candidate.  There is deliberately no CLI for this field. */
    uint8_t     udp_reroll_fail_after_bind_count;
    uint16_t   *udp_bound_port_out; /* listen: if set, receives the actual
                                     * bound port (for --port 0 bootstrap) */
    /* Internal child-transfer bootstrap seam: suppress only transport-open success
     * prose while EXEC merges stderr into the exact public-record stream.
     * Errors are never suppressed. */
    uint8_t     quiet_open_success;
    /* stdio transport */
    const char *exec;           /* argv[] for execvp() fork (NULL = use fd 0/1) */
    uint8_t     pair_id[4];     /* zero = unset */
} transport_config_t;

/* -------------------------------------------------------------------------
 * Stats
 * ---------------------------------------------------------------------- */

typedef struct transport_stats {
    uint32_t  tx_ok;
    uint32_t  tx_fail;
    uint32_t  rx_ok;
    uint32_t  rx_drop;
    /* Datagram accounting for packet-capture reconciliation.  A would-block is
     * not a failure: the frame is retained and reattempted, so it is counted
     * apart from tx_fail rather than folded into it.  Byte counts are frame
     * bytes, which on UDP is the complete datagram payload and therefore
     * excludes the IP/UDP headers a capture also sees - a reconciliation has
     * to add those itself rather than find them silently included here.  The
     * stream transports count the same frame bytes and so exclude their own
     * 2-byte length prefix, which has no UDP counterpart. */
    uint32_t  tx_would_block;
    uint32_t  tx_too_large;    /* EMSGSIZE; a diagnostic, never authority */
    uint64_t  tx_bytes;        /* bytes of completed frames only */
    uint64_t  rx_bytes;        /* bytes of accepted frames only */
    int16_t   rssi_last;       /* dBm, INT16_MIN if unknown */
    int8_t    snr_last;        /* tenths of dB, INT8_MIN if unknown */
    uint8_t   transport_id;   /* 0=unix, 2=stdio, 3=udp */
} transport_stats_t;

/* -------------------------------------------------------------------------
 * Opaque transport handle
 * ---------------------------------------------------------------------- */

typedef struct transport transport_t;

/* -------------------------------------------------------------------------
 * Operations interface
 * ---------------------------------------------------------------------- */

typedef struct transport_ops {
    const char *name;
    /* Datagram sockets have no stream hangup boundary. POLLERR/POLLHUP is
     * receive readiness for the transport to drain or clear; only POLLNVAL
     * transfers ownership back to the session. Stream transports leave this
     * zero so their historical close-on-hup behavior is unchanged. */
    uint8_t poll_hup_err_is_readable;
    int  (*open)  (const transport_config_t *cfg, transport_t **out);
    int  (*send)  (transport_t *t, const uint8_t *data, size_t len);
    /* send-scheduler nonblocking one-frame step. Product transports implement this;
     * deterministic capture transports may omit it and complete through the
     * synchronous `send` fallback in the session arbiter. */
    int  (*send_step)(transport_t *t, const uint8_t *data, size_t len);
    /* Cancel the retained send_step frame only when that transport emitted
     * zero bytes. Product transports implement this send-scheduler terminal-boundary
     * operation; a partial stream frame must return -1. */
    int  (*send_cancel_untouched)(transport_t *t);
    int  (*recv)  (transport_t *t, uint8_t *buf, size_t max, int timeout_ms);
    void (*close) (transport_t *t);
    int  (*stats) (transport_t *t, transport_stats_t *out);
    /* Optional: return underlying pollable fd or -1 if not supported.
     * When present, session_run can poll this fd in the same poll() set as
     * the PTY master / stdin. */
    int  (*get_fd)(transport_t *t);
    /* Optional output fd for POLLOUT while send_step retains a frame.
     * May equal get_fd (UDP/UNIX/socketpair stdio). */
    int  (*get_send_fd)(transport_t *t);
    /* Optional : the session layer calls this after a
     * received frame passed AEAD *and* advanced the replay high-water mark
     * (or completed a pre-session hello). Roaming transports adopt the
     * source address of that frame as the peer's return address — the mosh
     * rule: the peer is wherever the freshest authenticated traffic comes
     * from, not a fixed L3/L4 endpoint. A stale-but-valid in-window frame
     * never triggers this, so a replayed capture cannot redirect the
     * return path. NULL for non-roaming transports. */
    /* Returns 1 only when a previously confirmed peer changed, 0 for first
     * adoption/unchanged/no candidate, and -1 on an internal error. */
    int  (*peer_confirm)(transport_t *t);

    /* source-aware datagram receive. Product UDP provides this in both
     * ordinary and multipath modes. `source_out` excludes the attacker-controlled
     * port/local leg; `path_out` retains the full canonical multipath identity.
     * The transport separately retains the platform-native raw sockaddr for
     * legacy peer_confirm(), so using this seam cannot canonicalize away
     * pre-multipath roaming-freshest-path behavior. NULL for stream transports. */
    int  (*recv_source)(transport_t *t, uint8_t *buf, size_t max,
                        int timeout_ms, multipath_token_t *path_out,
                        preauth_source_t *source_out);

    /* multipath UDP endpoint-path seam. Implementations either provide the
     * path-authority operations as a complete set or none of them;
     * session_enable_multipath rejects partial and non-UDP transports before
     * HELLO. get_recv_fds is transport-owned polling metadata and may also
     * enumerate ordinary-profile sockets. Receive metadata is immutable for
     * that datagram. One send_step_to call is exactly one visible syscall. */
    int  (*recv_from)(transport_t *t, uint8_t *buf, size_t max,
                      int timeout_ms, multipath_token_t *path_out);
    int  (*send_step_to)(transport_t *t,
                         const multipath_token_t *path,
                         const uint8_t *data, size_t len);
    int  (*peer_confirm_from)(transport_t *t,
                              const multipath_token_t *path);
    int  (*configured_paths)(transport_t *t,
                             multipath_token_t paths[MULTIPATH_PATHS_MAX]);
    int  (*configured_path_limit)(transport_t *t);
    /* traffic-profile optional multipath fallback. Before service activation, retire every
     * client fd except fd 0 and make all retired receive tokens unusable.
     * A listener retains its native IPv4+V6ONLY-IPv6 socket pair because
     * that pair is one ordinary roaming-freshest-path receive resource, not a client path
     * pool. In both roles the multipath configured limit becomes zero. */
    int  (*quiesce_unselected_paths)(transport_t *t);
    int  (*get_recv_fds)(transport_t *t,
                         int fds[MULTIPATH_PATHS_MAX]);
    int  (*get_path_send_fd)(transport_t *t,
                             const multipath_token_t *path);
    /* bulk-transfer local source-port observation/reconfiguration. These are local
     * transport-incarnation operations only; they grant no multipath authority.
     * prepare keeps old fds live, commit swaps exactly the retained cookie,
     * and abort closes only shadow fds. */
    int  (*configured_local_ports)(transport_t *t,
                                   uint16_t ports[MULTIPATH_PATHS_MAX]);
    /* Physical-fd domain parallel to configured_local_ports. Values are
     * zero (unknown), 4, or 6 and are observation only. */
    int  (*configured_local_families)(
        transport_t *t, uint8_t families[MULTIPATH_PATHS_MAX]);
    int  (*configured_port_layout)(transport_t *t);
    int  (*path_reroll_prepare)(transport_t *t, uint32_t local_leg_mask,
                                transport_path_reroll_t *reroll_out);
    int  (*path_reroll_ready)(transport_t *t,
                              const transport_path_reroll_t *reroll);
    /* After ready succeeds and with no intervening transport operation,
     * commit is an infallible fd-array swap; close errors are diagnostic and
     * never roll multipath state back. */
    void (*path_reroll_commit)(transport_t *t,
                               const transport_path_reroll_t *reroll);
    void (*path_reroll_abort)(transport_t *t,
                              const transport_path_reroll_t *reroll);
} transport_ops_t;

/* -------------------------------------------------------------------------
 * Transport implementations (defined in transport_*.c)
 * ---------------------------------------------------------------------- */

extern const transport_ops_t transport_unix;
extern const transport_ops_t transport_stdio;
extern const transport_ops_t transport_udp;

/* Pure multipath UDP source-port allocator seam.  The runtime probes one kernel
 * ephemeral port, then attempts at most 64 distinct aligned adjacent blocks;
 * an exhausted search tried all 64.  Exposed so the default harness can pin
 * the candidate sequence without depending on host allocator races. */
int transport_udp_d32_port_block_candidate(uint16_t ephemeral_port,
                                           uint8_t path_count,
                                           unsigned int attempt,
                                           uint16_t *base_port_out);

/* -------------------------------------------------------------------------
 * Helper: get transport_ops_t by name string
 * Returns NULL if not found.
 * ---------------------------------------------------------------------- */
const transport_ops_t *transport_find(const char *name);

/* -------------------------------------------------------------------------
 * transport_t base struct — each implementation embeds this at offset 0
 * ---------------------------------------------------------------------- */

struct transport {
    const transport_ops_t *ops;
};

#endif /* UNMOOR_TRANSPORT_H */
