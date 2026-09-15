/*
 * sync.h — terminal state sync
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * Reliable, exactly-once, in-order delivery of the PTY byte streams over a
 * lossy datagram transport. Each direction is one append-only stream:
 *
 *   sender    keeps a byte backlog from `base` (chain-verified at the peer,
 *             prunable below) to `tip` (stream length); new frames carry
 *             absolute 64-bit offsets (PTY_SYNC_DATA).
 *   receiver  holds out-of-order bytes in a pending ring, advances a
 *             contiguous `frontier`, displays only [0, delivered), and
 *             reports frontier + a 64-byte-block presence bitmap + a running
 *             BLAKE2b-256 stream chain in PTY_SYNC_ACK frames.
 *
 * Loss is repaired lowest-missing-first from the bitmap; a chain match at
 * the reported frontier authorizes the sender to prune its backlog. The
 * read gate binds on the local backlog quota only; peer credit
 * (delivered + pending ring) bounds transmission out of that backlog, never
 * local reads, so a long disconnect is absorbed up to the quota.
 *
 * Types 0x09/0x0A are carried on the PTY channel and are negotiated via
 * UNMOOR_CAP_PTY_SYNC_V1; when selected, PTY_DATA/PTY_EOF are forbidden on
 * the session and vice versa.
 */
#ifndef UNMOOR_SYNC_H
#define UNMOOR_SYNC_H

#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#include "crypto.h"
#include "sync_backlog.h"

struct session;

/* -------------------------------------------------------------------------
 * Wire constants (defaults)
 * ---------------------------------------------------------------------- */

#define SYNC_GRID              64U     /* bitmap block size, bytes */
#define SYNC_DATA_OVERHEAD     12U     /* ver+flags+reserved2+offset8 */
#define SYNC_DATA_PAYLOAD_MAX  210U    /* 222-byte plaintext budget - 12 */
#define SYNC_ACK_OVERHEAD      52U     /* ver+flags+bits2+frontier8+credit8+chain32 */
#define SYNC_ACK_BITMAP_MAX    170U    /* bitmap bytes: 52 + 170 = 222 */
#define SYNC_ACK_BITS_MAX      1360U   /* 170 * 8 */
#define SYNC_INITIAL_CREDIT    65536U  /* assumed before the first ack */
#define SYNC_ACK_DELAY_MS      25
#define SYNC_ACK_FRAMES        4U
#define SYNC_ACK_REPEAT_MS     100
#define SYNC_RTO_MIN_MS        200
#define SYNC_RTO_MAX_MS        5000
#define SYNC_LINGER_MS         10000   /* default; UNMOOR_SYNC_LINGER_MS */
#define SYNC_TX_CHUNK          SYNC_BACKLOG_CHUNK_SIZE

#define SYNC_BACKLOG_DEFAULT   (256ULL * 1024 * 1024)
#define SYNC_BACKLOG_MIN       (256ULL * 1024)
#define SYNC_BACKLOG_MAX       (4ULL * 1024 * 1024 * 1024)
#define SYNC_PENDING_DEFAULT   (4ULL * 1024 * 1024)
#define SYNC_PENDING_MIN       (64ULL * 1024)
#define SYNC_PENDING_MAX       (1ULL * 1024 * 1024 * 1024)

/* channel-session exact-stream instances deliberately use much smaller admitted
 * windows than the legacy singleton.  The session charges these values at
 * OPEN time even though TX chunks remain lazily allocated. */
#define SYNC_D36_BACKLOG_DEFAULT   (16ULL * 1024 * 1024)
#define SYNC_D36_BACKLOG_MAX       (64ULL * 1024 * 1024)
#define SYNC_D36_PENDING_DEFAULT   (1ULL * 1024 * 1024)
#define SYNC_D36_PENDING_MAX       (4ULL * 1024 * 1024)
#define SYNC_D36_BACKLOG_AGGREGATE (256ULL * 1024 * 1024)
#define SYNC_D36_PENDING_AGGREGATE (64ULL * 1024 * 1024)

/* PTY_SYNC_DATA flags */
#define SYNC_DATA_FIN          0x01U

/* PTY_SYNC_ACK flags */
#define SYNC_ACK_CREDIT        0x01U   /* credit_limit grew since last ack */
#define SYNC_ACK_SINK_BLOCKED  0x02U   /* local sink is write-blocked */
#define SYNC_ACK_FIN_SEEN      0x04U

/* send-scheduler fixed producer order inside the session RECOVERY lane. */
#define SYNC_RECOVERY_RR_REPAIR 0U
#define SYNC_RECOVERY_RR_PROBE  1U
#define SYNC_RECOVERY_RR_FIN    2U
#define SYNC_RECOVERY_RR_COUNT  3U

/* Retained RECOVERY-lane operation identity. */
#define SYNC_RECOVERY_NONE   0U
#define SYNC_RECOVERY_REPAIR 1U
#define SYNC_RECOVERY_PROBE  2U

/* -------------------------------------------------------------------------
 * Per-direction state, embedded in struct session
 * ---------------------------------------------------------------------- */

/* Outgoing stream (this side reads a source and transmits). */
typedef struct {
    int      active;

    uint64_t base;          /* chain-verified peer frontier; prune floor */
    uint64_t tip;           /* stream length appended so far */
    uint64_t sent;          /* everything below this was sent at least once */
    uint64_t peer_credit;   /* absolute transmit limit (monotonic max) */
    uint64_t quota;         /* backlog byte quota, chunk-rounded */

    /* Lazy byte storage only. The extra slot protects both [base, tip) and
     * the acknowledged base-1 persist byte from collision at full quota. */
    sync_backlog_t backlog;

    crypto_sync_chain_t chain;  /* absorbed exactly to base */

    /* Bitmap repair pass: cursor walks the peer map
     * lowest-first across acks; a full pass restarts at the frontier
     * (covering the unaligned tail) at most once per rto_ms. */
    uint64_t repair_cursor;
    int64_t  repair_pass_ms;
    uint8_t  repair_bitmap[SYNC_ACK_BITMAP_MAX];
    uint32_t repair_bits;
    uint64_t repair_frontier;
    uint64_t repair_generation;
    uint8_t  repair_attempts_left; /* max four terminal attempts per peer ACK */
    int      repair_plan_valid;

    /* send-scheduler has one NEW and one RECOVERY logical record outstanding. Their
     * offsets advance only from an actual terminal transport result. */
    int      new_send_pending;
    uint64_t new_pending_end;
    int      recovery_send_pending;
    uint8_t  recovery_pending_kind;
    uint8_t  recovery_cursor; /* repair -> probe -> FIN, skipping idle peers */
    uint64_t recovery_pending_generation;
    uint64_t recovery_pending_end;

    /* FIN */
    int      fin_pending;
    int      fin_acked;
    uint64_t fin_offset;
    int      have_code;
    int32_t  code;
    uint32_t fin_generation; /* changes when the local exit code changes */
    uint32_t fin_completed_generation;
    int      fin_seen_observed; /* first FIN_SEEN ack counted as linger progress */
    int      fin_send_pending;
    uint32_t fin_pending_generation; /* immutable retained FIN owner */
    int      fin_first_attempted;
    int64_t  fin_retry_ms;

    /* Timers. rto progress = frontier advance or credit growth;
     * linger progress additionally counts the first FIN_SEEN and any
     * SINK_BLOCKED ack (peer alive but deliberately blocked). */
    int64_t  now_cache;     /* clock injected by sync_tick (test-deterministic) */
    int64_t  last_progress_ms;
    int64_t  last_linger_progress_ms;
    int64_t  rto_ms;
    int64_t  next_probe_ms;
    int      was_outstanding;
    int64_t  linger_ms;
    int      close_started;

    unsigned gate_state;    /* bit0 quota gate, bit1 credit gate (log edges) */
    unsigned log_once;      /* bit0 malformed ack */
} sync_tx_t;

/* Incoming stream (this side receives and writes a sink). */
typedef struct {
    int      active;

    uint64_t delivered;     /* written to the sink */
    uint64_t frontier;      /* contiguous prefix received (chain-absorbed) */
    uint64_t highest;       /* max stored offset+len (bitmap extent) */

    uint8_t  *ring;         /* pending bytes, offset % ring_size */
    size_t   ring_size;     /* multiple of SYNC_GRID */
    uint8_t  *blockmap;     /* per-block received-prefix length, 0..64 */
    size_t   nblocks;       /* ring_size/64 + 1 (delivered may be unaligned) */
    uint64_t cleared_below; /* first block index not yet zeroed after flush */

    crypto_sync_chain_t chain;  /* absorbed exactly to frontier */

    /* FIN */
    int      fin_seen;
    uint64_t fin_offset;
    int      have_code;
    int32_t  exit_code;
    int      fin_delivered;

    /* Ack pacing */
    int      ack_due;
    int64_t  ack_first_pending_ms;  /* 0 = nothing pending */
    uint32_t frames_since_ack;
    int64_t  next_repeat_ms;        /* 100ms repeats while holes persist */
    int64_t  ack_retry_ms;          /* failed send retry floor; avoids spin */
    int      sink_blocked;
    uint64_t last_advertised_credit;
    uint64_t ack_generation;
    uint64_t ack_pending_generation;
    uint64_t ack_pending_credit;
    int      ack_send_pending;
    int      exit_after_ack_attempt;
    uint64_t exit_ack_generation;

    unsigned log_once;      /* bit0 malformed data, bit1 credit overrun */
} sync_rx_t;

typedef ssize_t (*sync_instance_read_fn)(void *context, uint8_t *buffer,
                                         size_t capacity);
typedef ssize_t (*sync_instance_write_fn)(void *context,
                                          const uint8_t *buffer,
                                          size_t length);

/* Descriptor/callback ownership is explicit per channel-session stream.  A NULL
 * callback uses read(2)/write(2) on the corresponding fd.  Descriptors are
 * borrowed: the channel runtime, not the sync engine, closes them. */
typedef struct {
    uint32_t handle;
    uint8_t slot;
    uint8_t kind;
    uint8_t configured;
    uint8_t admitted;
    uint8_t source_eof;
    int source_fd;
    int sink_fd;
    sync_instance_read_fn read_source;
    sync_instance_write_fn write_sink;
    void *source_context;
    void *sink_context;
} sync_instance_binding_t;

/* -------------------------------------------------------------------------
 * API (all no-ops when the capability was not negotiated)
 * ---------------------------------------------------------------------- */

/* Call at ESTABLISHED, before channel open. Parses UNMOOR_SYNC_BACKLOG_BYTES,
 * UNMOOR_SYNC_PENDING_BYTES, UNMOOR_SYNC_LINGER_MS. Prints the one-line
 * legacy-fallback notice when PTY_SYNC_V1 was not selected. Returns 0 on
 * success (including inactive fallback), -1 on allocation failure. */
int  sync_init(struct session *s);

/* Idempotent. Client side: attempts a bounded blocking drain of undelivered
 * display bytes, and flags run_failed if the stream ended before full
 * delivery. Wipes and frees all buffers. */
void sync_free(struct session *s);

int  sync_active(const struct session *s);

/* Backlog room in bytes — the read gate. Quota only; peer credit never
 * gates local reads. */
size_t sync_tx_room(const struct session *s);

/* accepted classic server source end makes room/read-limit zero;
 * already-owned output still sends. Client and channel-session APIs are unchanged. */
/* Maximum safe size for one local source read. This is the smaller of the
 * remaining backlog quota and one PTY_SYNC_DATA payload. Under the initial
 * open credit window that preserves read-pacer's sixteen-read/sixteen-frame startup
 * bound. A later credit boundary may split/release backlog; pacing that send
 * path is deliberately left to future work. */
size_t sync_tx_read_limit(const struct session *s);

/* Append source bytes at tip and transmit what credit allows.
 * len must be <= sync_tx_room(). Returns 0, or -1 on fatal error. A positive
 * classic server append after end fails before storage; empty is a no-op. */
int  sync_tx_append(struct session *s, const uint8_t *data, size_t len);

/* Mark end of stream at tip. Server: after reaping the child, with the exit
 * code (single coded FIN). Client: on stdin EOF, codeless.
 * Retransmits ride the probe timer until the peer acks FIN_SEEN at the FIN
 * offset. Idempotent; a later call may add the code. */
void sync_tx_fin(struct session *s, int have_code, int32_t code);

/* Frame handlers (bodies of PTY_SYNC_DATA / PTY_SYNC_ACK). */
int  sync_prevalidate_data(const struct session *s,
                           const uint8_t *body, size_t len);
int  sync_prevalidate_ack(const struct session *s,
                          const uint8_t *body, size_t len);
void sync_handle_data(struct session *s, const uint8_t *body, size_t len);
void sync_handle_ack(struct session *s, const uint8_t *body, size_t len);

/* send-scheduler selection-time absolute ACK snapshot. The logical due bit may wait
 * behind another lane or wire debt; bytes and completion metadata are frozen
 * only when the arbiter actually selects this record. */
int sync_ack_snapshot(struct session *s, uint8_t *body, size_t body_cap,
                      size_t *body_len, uint64_t *generation,
                      uint64_t *credit);

/* Drive timers: ack cadence/repeats, RTO probes (including the persist
 * probe against a closed credit window), FIN retransmit, server linger.
 * now_ms is the injected clock; also cached for the frame handlers. */
void sync_tick(struct session *s, int64_t now_ms);

/* send-scheduler terminal transport callback. Only COMPLETE/FAILED reaches this seam;
 * WOULD_BLOCK and partial progress leave the exact producer state retained. */
void sync_send_result(struct session *s, int done, int completed,
                      int64_t now_ms, uint64_t arg0, uint64_t arg1);

/* Authenticated AEAD+replay+HWM-confirmed path transition. It always creates
 * fresh TX recovery opportunities without changing delivery state. The
 * caller requests an absolute RX reassertion for legacy/non-ACK transitions;
 * a multipath PTY_SYNC_ACK-triggered selector change passes false so unchanged
 * reciprocal feedback cannot self-excite. */
void sync_path_changed(struct session *s, int64_t now_ms,
                       int reassert_rx_feedback);

/* Milliseconds until the next timer needs sync_tick, or -1 for none. */
int64_t sync_next_deadline(struct session *s, int64_t now_ms);

/* Undelivered contiguous bytes are pending for the sink. */
int  sync_rx_pending(const struct session *s);

/* Nonblocking sink flush: server → pty master, client → stdout. Sets
 * sink_blocked on EAGAIN; run_failed + close on hard write errors; performs
 * the client fin-completion (exit code, "\r\n", should_exit). */
void sync_rx_deliver(struct session *s);

/* channel-session per-instance surface.  Slot 1 is the legacy storage and every legacy
 * function above is an exact wrapper around slot 1.  Slots 2..15 use the
 * fixed session-owned arrays; peer input cannot allocate an instance. */
int sync_reserve_instance(struct session *s, uint8_t slot, uint8_t kind);
int sync_bind_reserved_instance(
    struct session *s, uint8_t slot, uint32_t handle, uint8_t kind,
    int source_fd, int sink_fd, sync_instance_read_fn read_source,
    void *source_context, sync_instance_write_fn write_sink,
    void *sink_context);
int sync_init_instance(struct session *s, uint8_t slot, uint32_t handle,
                       uint8_t kind, int source_fd, int sink_fd,
                       sync_instance_read_fn read_source,
                       void *source_context,
                       sync_instance_write_fn write_sink,
                       void *sink_context);
int sync_free_instance(struct session *s, uint8_t slot);
int sync_active_instance(const struct session *s, uint8_t slot);
size_t sync_tx_room_instance(const struct session *s, uint8_t slot);
size_t sync_tx_read_limit_instance(const struct session *s, uint8_t slot);
int sync_tx_append_instance(struct session *s, uint8_t slot,
                            const uint8_t *data, size_t len);
void sync_tx_fin_instance(struct session *s, uint8_t slot,
                          int have_code, int32_t code);
int sync_prevalidate_data_instance(const struct session *s, uint8_t slot,
                                   const uint8_t *body, size_t len);
int sync_prevalidate_ack_instance(const struct session *s, uint8_t slot,
                                  const uint8_t *body, size_t len);
void sync_handle_data_instance(struct session *s, uint8_t slot,
                               const uint8_t *body, size_t len);
void sync_handle_ack_instance(struct session *s, uint8_t slot,
                              const uint8_t *body, size_t len);
int sync_ack_snapshot_instance(struct session *s, uint8_t slot,
                               uint8_t *body, size_t body_cap,
                               size_t *body_len, uint64_t *generation,
                               uint64_t *credit);
void sync_tick_instance(struct session *s, uint8_t slot, int64_t now_ms);
void sync_send_result_instance(struct session *s, uint8_t slot, int done,
                               int completed, int64_t now_ms,
                               uint64_t arg0, uint64_t arg1);
int sync_send_result_owned_instance(struct session *s, uint8_t slot,
                                    int done, int completed,
                                    int64_t now_ms, uint64_t arg0,
                                    uint64_t arg1,
                                    uint64_t operation_generation);
void sync_path_changed_instance(struct session *s, uint8_t slot,
                                int64_t now_ms,
                                int reassert_rx_feedback);
int64_t sync_next_deadline_instance(struct session *s, uint8_t slot,
                                    int64_t now_ms);
int sync_rx_pending_instance(const struct session *s, uint8_t slot);
void sync_rx_deliver_instance(struct session *s, uint8_t slot);
/* Pure channel-session hard-sink taxonomy shared by delivery and focused tests. */
uint32_t sync_channel_sink_error_code(int sink_errno);
int sync_instance_set_io(struct session *s, uint8_t slot, uint32_t handle,
                         int source_fd, int sink_fd,
                         sync_instance_read_fn read_source,
                         void *source_context,
                         sync_instance_write_fn write_sink,
                         void *sink_context);
/* Clear borrowed descriptors/callbacks before their owner closes or reuses
 * them.  The complete handle is required so a delayed retirement cannot
 * detach a newer occupant of the same four-bit slot. */
int sync_instance_detach_io(struct session *s, uint8_t slot,
                            uint32_t handle);
int sync_instance_source_fd(const struct session *s, uint8_t slot);
int sync_instance_sink_fd(const struct session *s, uint8_t slot);
ssize_t sync_instance_read_source(struct session *s, uint8_t slot,
                                  uint8_t *buffer, size_t capacity);
const sync_tx_t *sync_tx_state_instance(const struct session *s,
                                        uint8_t slot);
const sync_rx_t *sync_rx_state_instance(const struct session *s,
                                        uint8_t slot);
int sync_aggregate_snapshot(const struct session *s,
                            uint64_t *tx_tip_out,
                            uint64_t *rx_delivered_out,
                            uint64_t *rx_highest_out,
                            int *sink_blocked_out);

#endif /* UNMOOR_SYNC_H */
