/*
 * session.h — session state machine
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * States: SESSION_IDLE → SESSION_CONNECTING → SESSION_KEY_DERIVING
 *         → [SESSION_REKEYING] → SESSION_ESTABLISHED
 *         → SESSION_CLOSING → SESSION_IDLE
 */
#ifndef UNMOOR_SESSION_H
#define UNMOOR_SESSION_H

#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stddef.h>

#include <sys/types.h>

#include "transport.h"
#include "channel.h"
#include "channel_session.h"
#include "attach_manager.h"
#include "channel_process.h"
#include "child_transfer.h"
#include "negotiation.h"
#include "rekey.h"
#include "reasm.h"
#include "sync.h"
#include "sync_status.h"
#include "client_escape.h"
#include "send_scheduler.h"
#include "delivery.h"
#include "bulk_engine.h"
#include "event_log.h"
#include "traffic_profile.h"
#include "pq_crypto.h"
#include "pq_rekey.h"

/* Peer-driven diagnostics are observational and must not become an unbounded
 * blocking output queue. */
#define SESSION_MULTIPATH_PRIMARY_LOG_LIMIT 8U
#define SESSION_REPLAY_LOG_LIMIT 8U
#define SESSION_MULTIPATH_MISMATCH_LOG_LIMIT 8U
#define SESSION_CHILD_TRANSFER_TEXT_MAX 2048U
#define SESSION_DIAGNOSTIC_SNAPSHOT_LIMIT 64U

/* Public, non-secret launch policy copied into the client control session.
 * Attach-v2 paths remain request-owned; no key, port, or transfer identity is
 * accepted here. */
typedef struct {
    const char *program_path;
    const char *udp_host;
    const char *remote_command;
    const char *remote_bind_host; /* optional */
    traffic_profile_t traffic_profile;
    traffic_multipath_option_t multipath_option;
    event_log_format_t log_format;
    uint16_t port_mask;
    int timeout_seconds;
    uint8_t exact_paths;
    uint8_t port_layout; /* transport_udp_port_layout_t */
    uint8_t port_mask_explicit;
    /* pq-hybrid: exact authenticated control-session selection.  This is not an
     * attach-request input; the epoch-rekey runner fills it from its selected public
     * bootstrap profile before the child launch policy is frozen. */
    uint8_t pq_carrier_required;
    /* Client confinement level word handed to child-transfer children as
     * "--confine <level>". NULL leaves the child's own default. */
    const char *confine_level;
    /* server-confinement: explicit remote bulk-server policy. NULL keeps child argv and
     * remote behavior unchanged. */
    const char *server_confine_level;
} session_child_transfer_config_t;

/* -------------------------------------------------------------------------
 * Session state enum
 * ---------------------------------------------------------------------- */

typedef enum {
    SESSION_IDLE         = 0,
    SESSION_CONNECTING   = 1,  /* client only: waiting for CTRL_HELLO_ACK */
    SESSION_KEY_DERIVING = 2,  /* both: CTRL_READY sent, waiting for peer's */
    SESSION_ESTABLISHED  = 3,
    SESSION_REKEYING     = 4,
    SESSION_CLOSING      = 5,
} session_state_t;

/* -------------------------------------------------------------------------
 * Replay window
 * ---------------------------------------------------------------------- */

#define REPLAY_WINDOW 256

typedef struct {
    uint32_t hwm;
    int      initialized;
    uint8_t  bitmap[REPLAY_WINDOW];
} replay_window_t;

/* -------------------------------------------------------------------------
 * send-scheduler bounded logical send state
 * ---------------------------------------------------------------------- */

#define SESSION_TX_SLOT_COUNT 20U

typedef enum {
    SESSION_TX_EPOCH_CURRENT = 0,
    SESSION_TX_EPOCH_PENDING = 1,
    SESSION_TX_EPOCH_HELLO_KEY = 2,
    SESSION_TX_HELLO = 3,
    SESSION_TX_HELLO_ACK_NEW = 4,
    SESSION_TX_RAW_FRAME = 5
} session_tx_epoch_t;

/* Selection-time sequence policy. NORMAL records stop before the epoch-rekey
 * reserve (or the legacy close-before-wrap boundary). EPOCH_CONTROL is
 * limited only by the no-wrap rule and is reserved for authenticated rekey,
 * error, and bounded close traffic. NONE owns no new sequence (raw frame). */
typedef enum {
    SESSION_TX_SEQ_NORMAL = 0,
    SESSION_TX_SEQ_EPOCH_CONTROL = 1,
    SESSION_TX_SEQ_NONE = 2
} session_tx_sequence_class_t;

typedef enum {
    SESSION_TX_DONE_NONE = 0,
    SESSION_TX_DONE_HELLO,
    SESSION_TX_DONE_HELLO_ACK,
    SESSION_TX_DONE_READY_INITIAL,
    SESSION_TX_DONE_READY_RETRY,
    SESSION_TX_DONE_READY_ACK,
    SESSION_TX_DONE_PTY_OPEN,
    SESSION_TX_DONE_STATUS_PERIODIC,
    SESSION_TX_DONE_REKEY_RETRY,
    SESSION_TX_DONE_REKEY_FINAL_ACK,
    SESSION_TX_DONE_SYNC_ACK,
    SESSION_TX_DONE_SYNC_NEW,
    SESSION_TX_DONE_SYNC_REPAIR,
    SESSION_TX_DONE_SYNC_PROBE,
    SESSION_TX_DONE_SYNC_FIN,
    SESSION_TX_DONE_LEGACY_EOF,
    SESSION_TX_DONE_ABORT,
    SESSION_TX_DONE_PATH_CHALLENGE,
    SESSION_TX_DONE_PATH_RESPONSE,
    SESSION_TX_DONE_CHANNEL_CONTROL
} session_tx_done_t;

typedef enum {
    SESSION_TX_PATH_PRIMARY = 0,
    SESSION_TX_PATH_CRITICAL = 1,
    SESSION_TX_PATH_TARGET = 2
} session_tx_path_policy_t;

#define SESSION_TX_MODE_ESTABLISHED 0x01U
#define SESSION_TX_MODE_REKEY       0x02U
#define SESSION_TX_MODE_PRE_SERVICE 0x04U
#define SESSION_TX_MODE_ABORT       0x08U

/* A slot owns one single-frame logical record, never ciphertext. Raw records
 * are limited to the two pre-session frames whose exact encoded bytes are
 * themselves protocol state (HELLO and cached HELLO_ACK). */
typedef struct {
    uint8_t  valid;
    uint8_t  inflight;
    uint8_t  lane;
    uint8_t  epoch_source;
    uint8_t  mode_mask;
    uint8_t  chan_byte;
    uint8_t  type;
    uint8_t  done;
    uint8_t  sequence_class;
    uint8_t  producer_id;
    uint8_t  path_policy;
    uint8_t  path_reserved;
    uint16_t length;
    uint32_t coalesce_key;
    uint32_t stream_handle;
    uint64_t ticket;
    uint64_t order;
    uint64_t operation_generation;
    uint64_t arg0;
    uint64_t arg1;
    multipath_handle_t path_target;
    multipath_token_t path_token;
    uint8_t  bytes[FRAME_MAX_LEN];
} session_tx_intent_t;

/* The sole generic bulk staging object permitted by send-scheduler. It holds one
 * admitted fragmentation message as plaintext; one fragment is encoded only after the
 * scheduler grants NEW. */
typedef struct {
    uint8_t  valid;
    uint8_t  inflight;
    uint8_t  chan_id;
    uint8_t  type;
    uint8_t  hash_ready;
    uint8_t  started;
    uint16_t count;
    uint16_t index;
    uint16_t stride;
    uint16_t total_length;
    uint32_t message_id;
    uint32_t started_epoch;
    uint64_t ticket;
    uint64_t order;
    uint8_t  hash[FRAGMENT_HASH_LEN];
    uint8_t  bytes[REASM_MAX_BUFFER];
} session_tx_message_t;

/* delivery-class is a logical producer beside the fixed intent table and the one fragmentation
 * staging object. It materializes exactly one canonical plaintext record only
 * after send-scheduler grants its lane; this token then stays immutable through
 * EAGAIN/partial transport progress and owns the terminal callback. */
typedef enum {
    SESSION_DELIVERY_ATTEMPT_NONE = 0,
    SESSION_DELIVERY_ATTEMPT_LATEST_HEAD,
    SESSION_DELIVERY_ATTEMPT_LATEST_BLOCK,
    SESSION_DELIVERY_ATTEMPT_LATEST_STATUS,
    SESSION_DELIVERY_ATTEMPT_RELIABLE_DATA,
    SESSION_DELIVERY_ATTEMPT_RELIABLE_STATUS
} session_delivery_attempt_kind_t;

typedef struct {
    uint8_t valid;
    uint8_t kind;
    uint8_t lane;
    uint8_t owner_slot;
    uint8_t chan_byte;
    uint8_t type;
    uint16_t owner_id;
    uint16_t block_index;
    uint64_t generation;
    uint16_t length;
    uint8_t bytes[DELIVERY_LATEST_BLOCK_WIRE_MAX];
} session_delivery_attempt_t;

typedef struct {
    uint8_t high_streak;
    uint8_t high_cursor;
    uint8_t low_cursor;
} session_delivery_service_t;

/* epoch-rekey's five exact control flights remain their own wire grammar, but use
 * the same bounded exact-owner lifecycle as delivery-class reliable datagrams.  The
 * logical descriptor contains no plaintext: the phase-specific record is
 * materialized only after send-scheduler grants INTERACTIVE. */
typedef struct {
    uint8_t valid;
    uint8_t semantic_retired;
    uint8_t type;
    uint8_t pending_epoch;
    uint32_t attempt_epoch;
    uint64_t ticket;
    uint64_t order;
    delivery_retry_owner_t retry;
} session_rekey_flight_t;

/* One fixed pq-hybrid sender generation. Public share bytes remain resident until
 * the epoch candidate has been confirmed because they are transcript input;
 * retired only suppresses further wire attempts. */
typedef struct {
    uint8_t active;
    uint8_t retired;
    uint8_t kind;
    uint8_t count;
    uint8_t cursor;
    uint8_t inflight;
    uint8_t inflight_index;
    uint8_t reserved;
    uint16_t stride;
    uint32_t from_epoch;
    uint32_t peer_bitmap;
    uint32_t cycle_remaining;
    int64_t next_send_ms;
    uint64_t order;
    uint8_t rekey_id[PQ_REKEY_ID_LEN];
    uint8_t bytes[PQ_REKEY_SHARE_LEN];
} session_pq_rekey_tx_t;

typedef struct {
    uint8_t configured;
    uint8_t priority;
    uint8_t reason_mask;
    uint16_t object_id;
    delivery_latest_install_fn install;
    void *install_arg;
} session_delivery_latest_config_t;

typedef void (*session_delivery_reliable_result_fn)(
    void *arg, uint16_t flow_id, uint64_t message_id,
    const uint8_t content_hash[DELIVERY_HASH_BYTES],
    delivery_result_t result);

typedef struct {
    uint8_t configured;
    uint8_t priority;
    uint8_t reason_mask;
    uint8_t result_notified;
    uint16_t flow_id;
    delivery_reliable_deliver_fn deliver;
    void *deliver_arg;
    session_delivery_reliable_result_fn result;
    void *result_arg;
    uint64_t notified_message_id;
    uint8_t notified_hash[DELIVERY_HASH_BYTES];
    delivery_result_t notified_result;
} session_delivery_reliable_config_t;

typedef enum {
    SESSION_DELIVERY_SEND = 0x01,
    SESSION_DELIVERY_RECEIVE = 0x02,
    SESSION_DELIVERY_BOTH = 0x03
} session_delivery_direction_t;

/* channel-session keeps retry/deadline policy beside the fixed lifecycle table. No
 * network record can allocate one of these entries. */
typedef struct {
    uint8_t open_armed;
    uint8_t open_retry_index;
    uint8_t decision_pending;
    uint8_t close_armed;
    uint8_t close_retry_index;
    uint8_t close_ack_pending;
    uint8_t peer_close_hold;
    /* At least one exact peer CLOSE_ACK reached the transport handoff
     * boundary.  A last-channel receiver retains its tombstone for the
     * peer's whole retry horizon, then distinguishes a clean handoff from
     * a local inability to send any acknowledgement. */
    uint8_t peer_close_ack_completed;
    int64_t open_started_ms;
    int64_t open_next_ms;
    int64_t open_deadline_ms;
    int64_t close_started_ms;
    int64_t close_next_ms;
    int64_t close_deadline_ms;
    int64_t response_next_ms;
    int64_t peer_close_deadline_ms;
} session_channel_runtime_t;

/* Application ownership is fixed per encrypted handle.  Local DATA
 * and control are retained only when their owning send-scheduler producer cannot yet
 * admit them; remote output advances terminal-state-sync delivery only after the complete
 * framed attach DATA record is physically written. */
typedef struct {
    struct session *session;
    attach_manager_owner_t attach_owner;
    uint32_t handle;
    uint32_t terminal_code;
    uint64_t output_cookie;
    size_t pending_input_length;
    size_t output_length;
    size_t exec_preface_used;
    size_t exec_preface_expected;
    uint8_t kind;
    uint8_t active;
    uint8_t attach_bound;
    uint8_t pending_input;
    uint8_t output_waiting;
    uint8_t output_delivered;
    uint8_t receive_complete;
    uint8_t exit_queued;
    uint8_t close_queued;
    uint8_t cleanup_pending;
    uint8_t process_fin_sent;
    uint8_t process_input_closed;
    uint8_t process_output_eof;
    uint8_t exec_spawned;
    uint8_t child_lease;
    uint8_t child_lease_ready;
    uint8_t child_lease_fin_sent;
    uint8_t signal_pending;
    uint8_t signal_admitted;
    uint8_t pending_signal;
    uint8_t resize_pending;
    uint8_t resize_admitted;
    uint16_t pending_rows;
    uint16_t pending_columns;
    uint16_t pending_xpixel;
    uint16_t pending_ypixel;
    uint8_t pending_input_bytes[ATTACH_LOCAL_MAX_PAYLOAD];
    uint8_t exec_preface[ATTACH_LOCAL_MAX_PAYLOAD];
} session_channel_application_t;

/* Optional monotonic clock source used at the physical-send boundary. The
 * product event loop installs its real CLOCK_MONOTONIC source; deterministic
 * composition tests may inject one so traffic-profile measures transport attempts, not
 * an earlier scheduler sample. */
typedef int64_t (*session_clock_now_fn)(void *context);

/* -------------------------------------------------------------------------
 * Session struct (opaque to callers via forward decl in channel.h)
 * ---------------------------------------------------------------------- */

struct session {
    /* Transport */
    transport_t *transport;

    /* Identity */
    uint8_t psk[32];           /* mlock'd */
    uint8_t pair_id[4];

    /* Keys */
    uint8_t hello_key[32];     /* derived from PSK, mlock'd */
    uint8_t session_key[32];   /* derived on handshake, mlock'd */

    /* Nonces */
    uint8_t nonce_a[16];       /* our nonce (client) or stored peer nonce (server) */
    uint8_t nonce_b[16];       /* peer nonce */

    /* State */
    session_state_t state;
    int is_server;             /* 1 = listening side */

    /* Authenticated capability negotiation (capability-negotiation). supported/required are
     * local policy configured before connect/listen; selected is immutable
     * after a successful handshake. Legacy peers select PTY_V1 only. */
    uint32_t supported_caps;
    uint32_t required_caps;
    /* Per-handshake effective offer. Policy in supported_caps is immutable
     * across reuse; fixed-format optional caps may be withheld here when the
     * configured plaintext MTU cannot carry their largest record. */
    uint32_t offered_caps;
    uint32_t selected_caps;
    int      configuration_frozen;
    int      negotiation_neg1;
    int      peer_legacy;
    uint8_t  transcript_hello[NEGOTIATION_PLAIN_LEN];
    uint8_t  transcript_ack[NEGOTIATION_PLAIN_LEN];
    uint8_t  stored_hello_plain[NEGOTIATION_PLAIN_LEN];
    int      stored_hello_plain_valid;
    int      run_failed;       /* terminal handshake/protocol error */

    /* Sequence counters */
    uint32_t tx_seq;           /* our outgoing SEQ */
    uint32_t rx_hwm;           /* used only for replay window */

    /* Replay window (incoming from peer) */
    replay_window_t replay;
    uint64_t replay_drop_count; /* saturating, full live session */
    /* source-prefilter: fixed allocation-free source table and lifetime counters. This
     * survives traffic-epoch and IDLE transitions; only destroy erases it. */
    preauth_budget_t preauth_budget;

    /* epoch-rekey established-epoch state. The original pair_id/session_key/tx_seq/
     * replay fields above are the current epoch so legacy tests and paths stay
     * unchanged. Pending state is initialized once, used to authenticate the
     * last three rekey flights, and moved intact at adoption. */
    int      epoch_rekey_enabled;
    int      pq_hybrid_enabled;
    int      bootstrap_rekey_required;
    int      ephemeral_bootstrap_root;
    int      services_started;
    uint8_t  pair_seed[4];
    uint32_t epoch;
    uint8_t  session_context[32];
    uint8_t  epoch_transcript_digest[32];
    uint8_t  epoch_fingerprint[32];
    int      completed_rekey_valid;
    uint8_t  completed_rekey_id[REKEY_ID_LEN];

    int      pending_epoch_valid;
    uint32_t pending_epoch;
    uint8_t  pending_pair_id[4];
    uint8_t  pending_key[32];
    uint32_t pending_tx_seq;
    replay_window_t pending_replay;
    uint8_t  pending_transcript_digest[32];
    uint8_t  pending_epoch_fingerprint[32];

    rekey_phase_t rekey_phase;
    int      rekey_request_pending;
    int      rekey_deferred; /* started fragmentation object drains before local rekey */
    int      rekey_adoption_deferred; /* validated flight waits for delivery-class terminal */
    int64_t  rekey_next_send_ms;
    session_rekey_flight_t rekey_flight;
    uint8_t  rekey_id[REKEY_ID_LEN];
    uint8_t  rekey_private[32];
    uint8_t  rekey_client_public[32];
    uint8_t  rekey_server_public[32];
    session_pq_rekey_tx_t pq_rekey_tx;
    pq_rekey_rx_t pq_rekey_rx;
    uint8_t  pq_mlkem_private[PQ_MLKEM_PRIVATE_LEN];
    uint8_t  pq_base_received;
    uint8_t  pq_rx_bitmap_retired;
    uint8_t  pq_work_cursor;
    uint8_t  pq_active_work;
    uint8_t  pq_rekey_metrics_active;
    uint32_t pq_share_tx_seen_bitmap;
    uint64_t pq_share_tx_attempts;
    uint64_t pq_share_tx_retransmits;
    int64_t  pq_rekey_started_ms;

    /* CTRL_HELLO retransmit state (client) */
    int     hello_tx_count;    /* number of CTRL_HELLO sent (max 5) */
    int64_t hello_next_send_ms; /* monotonic ms when next CTRL_HELLO is due */
    int64_t hello_backoff_ms;   /* current backoff interval */

    /* Stored CTRL_HELLO_ACK for idempotent re-send (server in KEY_DERIVING).
     * body now carries a 24-byte cleartext hello_nonce
     * prefix in addition to the 32-byte plaintext + 16-byte tag. */
    uint8_t stored_hello_ack[12 + 24 + 32 + 16]; /* hdr + nonce + ct + tag */
    size_t  stored_hello_ack_len;

    /* Key derivation state tracking */
    int     sent_ready;        /* 1 = sent CTRL_READY */
    int     recv_ready;        /* 1 = received peer CTRL_READY */
    int     ready_ack_pending; /* peer NEED_ACK held until our initial READY */
    int     ready_tx_count;    /* NEG1 NEED_ACK frames, each with fresh SEQ */
    int64_t ready_next_send_ms;
    int64_t key_deriving_deadline_ms; /* 10s timeout */

    /* Explicit flag: session_key has been derived (replaces has_key heuristic) */
    int     have_session_key;

    /* Stashed frame buffered in CONNECTING (e.g., early CTRL_READY) to be
     * decrypted after handle_hello_ack derives session_key. */
    int      stashed_valid;
    uint8_t  stashed_chan_byte;
    uint8_t  stashed_type;
    uint32_t stashed_seq;
    uint8_t  stashed_ct[UNMOOR_TERMINAL_PLAINTEXT_MAX + FRAME_TAG_LEN];
    size_t   stashed_ct_len;
    uint8_t  stashed_ad[10];
    multipath_token_t stashed_path;
    int      stashed_path_valid;
    preauth_source_t stashed_source;
    int      stashed_source_valid;
    int      stashed_source_required;

    /* Keepalive / liveness */
    int64_t last_authenticated_ms; /* monotonic ms of last successfully decrypted frame */
    int64_t next_keepalive_ms;
    /* int64_t, not int. The compare sites in session.c and the setter in
     * session_set_transport_mode all do timer arithmetic against int64_t
     * monotonic ms; a narrower type would risk truncation once a slow
     * transport wants multi-second periods and keepalive scaling on top. */
    int64_t keepalive_period_ms;   /* 2000 */
    int64_t liveness_timeout_ms;   /* 8000 — 4 × the keepalive period */
    /* UDP roaming: mosh-style hold. When set, liveness exhaustion logs
     * staleness ("no contact for Ns") instead of closing the session, so an
     * ESTABLISHED session survives suspend/wake and network changes; the
     * next authenticated frame resumes it. Default for the udp transport. */
    int     liveness_unbound;
    int64_t next_liveness_warn_ms;
    /* One legacy hold diagnostic per no-contact edge.  Authenticated contact
     * clears it; the unbounded roaming-freshest-path lifetime itself is unchanged. */
    uint8_t liveness_hold_announced;
    /* A client whose stderr is the same terminal device as the raw peer
     * display must not paint automatic status/liveness prose over the
     * authenticated stream. Redirected diagnostics and explicit queries
     * remain visible. */
    uint8_t shared_raw_display_tty;

    /* SSH bootstrap (mosh-style): if nonzero and the session has not
     * reached ESTABLISHED by this monotonic deadline, session_run gives
     * up — a one-shot bootstrap listener must not wait forever with an
     * ephemeral key in memory (mosh-server's 60s rule). */
    int64_t bootstrap_deadline_ms;

    /* Producer-overrun mitigation: UNMOOR_PACE_BPS token bucket. It gates
     * PTY-master/stdin READS (not sends), so backpressure lands in the
     * kernel PTY buffer and the event loop keeps polling inbound control.
     * Credits are milli-bytes: one B/s earns one milli-byte per ms without
     * truncating low rates. Every nonempty read costs one full effective MTU,
     * so a full high-rate bucket emits at most 16 datagrams even when PTY
     * reads are tiny. The rate is a ceiling, not a throughput promise. */
    int64_t pace_bps;             /* payload-equivalent B/s; 0 = disabled */
    int64_t pace_credit_milli;    /* may carry less than one-MTU debt */
    int64_t pace_burst_milli;     /* min(rate/4, 16 MTUs), floor 1 byte */
    int64_t pace_last_refill_ms;

    /* send-scheduler wire arbiter. The fixed slots hold bounded logical state; exactly
     * one encoded frame may be retained while a nonblocking transport makes
     * progress. `wire_active_slot == -2` identifies the fragmentation message stage. */
    send_scheduler_t wire_scheduler;
    session_tx_intent_t wire_intents[SESSION_TX_SLOT_COUNT];
    session_tx_message_t wire_message;
    uint8_t  wire_frame[FRAME_MAX_LEN];
    size_t   wire_frame_len;
    uint8_t  wire_frame_bulk;
    int      wire_active_slot;
    int      wire_in_run_loop;
    int      wire_driving;
    uint8_t  wire_producer_cursor[SEND_LANE_COUNT];
    int      wire_chaos_applied;
    int      wire_transport_broken;
    int      wire_protocol_failure;
    uint64_t wire_next_ticket;
    uint64_t wire_next_order;
    uint64_t wire_failed_ticket;

    /* multipath session-scoped validated endpoint-path pool and the fixed physical
     * plan (primary plus at most one alternate) for the one immutable frame. */
    int multipath_requested;
    int multipath_required;
    int multipath_active;
    traffic_profile_t traffic_profile;
    traffic_stagger_t multipath_stagger;
    uint8_t multipath_stagger_initialized;
    session_clock_now_fn physical_clock_now;
    void *physical_clock_context;
    event_log_sink_t event_sink;
    uint8_t event_log_enabled;
    uint8_t event_session_opened;
    uint8_t event_session_closed;
    uint8_t event_close_reason_set;
    event_log_reason_t event_close_reason;
    uint32_t event_path_open_mask;
    uint8_t multipath_path_count;
    uint8_t multipath_challenge_cursor;
    uint8_t multipath_response_cursor;
    uint8_t multipath_keepalive_initialized;
    int64_t multipath_keepalive_anchor_ms;
    uint64_t multipath_keepalive_phase_serial;
    uint32_t multipath_validation_log_mask;
    uint64_t multipath_mismatch_count;
    /* Explicit local SIGUSR1 observations only. The event loop owns emission;
     * this lifetime count bounds even a same-user signal loop. */
    uint8_t diagnostic_snapshot_count;
    uint8_t diagnostic_snapshot_reserved[7];
    multipath_t multipath;
    /* Composed leg seam. This mirrors existing layer-owned facts only;
     * it grants no multipath authority and carries no semantic delivery bitmap. */
    path_leg_t path_leg[MULTIPATH_PATHS_MAX];
    uint8_t path_leg_count;
    uint8_t path_leg_reserved[7];
    /* Last operator-only view survives enter_idle so a finite bulk-transfer command
     * can print its final path status after transport authority is erased. */
    path_leg_metrics_t path_leg_final_metrics[MULTIPATH_PATHS_MAX];
    uint8_t path_leg_final_count;
    uint8_t path_leg_final_reserved[7];
    multipath_plan_t wire_path_plan;
    uint8_t wire_path_plan_active;
    uint8_t wire_path_ordinal;
    uint8_t wire_path_need_replica_begin;
    uint8_t wire_path_reserved;
    uint32_t wire_path_blocked_mask;
    uint32_t wire_path_terminal_mask;
    uint32_t wire_path_success_mask;

    /* Bulk-transfer application profile.  The small engine owner is allocated
     * only by session_enable_bulk(); its fixed bitmap/window/frame arenas are
     * allocated later, after exact epoch-rekey/bulk-transfer negotiation succeeds.  Ordinary
     * terminal sessions therefore retain their existing allocation shape and
     * FRAME_MAX_LEN wire buffer. */
    int bulk_enabled;
    int bulk_activated;
    /* A final authenticated bootstrap barrier may complete while its prior
     * COMMIT is retained after UDP WOULD_BLOCK.  Activation owns a scheduler
     * reset and therefore waits until that immutable frame drains. */
    int bulk_activation_deferred;
    bulk_engine_t *bulk;
    bulk_engine_config_t bulk_config;
    uint8_t *bulk_prebarrier_receive;
    size_t bulk_prebarrier_receive_capacity;
    /* A received bulk record may complete the bootstrap epoch and activate
     * the engine while dispatch still borrows the pre-barrier arena. Retire
     * that arena only after every current frame dispatch has returned. */
    unsigned int frame_dispatch_depth;
    uint8_t bulk_tx_type;
    uint8_t bulk_tx_lane;
    uint16_t bulk_tx_reserved;
    size_t bulk_tx_plaintext_len;
    uint8_t bulk_reroll_cursor;
    uint8_t bulk_set_revalidation_active;
    uint8_t bulk_set_revalidation_layout;
    uint8_t bulk_set_revalidation_trigger;
    uint16_t bulk_set_old_port_mask;
    uint16_t bulk_set_new_port_mask;
    uint64_t bulk_set_generation[BULK_LEGS_MAX];
    /* Bounded operator/harness observations of sender-local bulk-transfer path state.
     * The signature deliberately excludes byte counters so an active transfer
     * cannot turn stderr into a per-ACK stream.  Each actual ladder/reroll
     * transition still records the counters that existed at that edge. */
    uint32_t bulk_path_log_signature[BULK_LEGS_MAX];
    uint32_t bulk_path_log_seen_mask;
    uint32_t bulk_path_active_seen_mask;
    uint16_t bulk_path_log_count;
    uint8_t bulk_path_log_suppressed;
    uint8_t bulk_path_log_reserved[3];

    /* delivery-class bounded non-terminal delivery state. All object/flow tables are
     * fixed; peer input cannot allocate. The context and state span a epoch-rekey
     * traffic epoch and are cleared only with the full live session. */
    int delivery_initialized;
    uint8_t delivery_context[DELIVERY_CONTEXT_BYTES];
    delivery_latest_sender_t delivery_latest_tx;
    delivery_latest_receiver_t delivery_latest_rx;
    delivery_reliable_sender_t delivery_reliable_tx;
    delivery_reliable_receiver_t delivery_reliable_rx;
    session_delivery_service_t delivery_lane_service[SEND_LANE_COUNT];
    int64_t delivery_head_next_ms[DELIVERY_LATEST_OBJECTS];
    int64_t delivery_latest_status_next_ms[DELIVERY_LATEST_OBJECTS];
    int64_t delivery_reliable_status_next_ms[DELIVERY_RELIABLE_FLOWS];
    uint8_t delivery_latest_status_dirty;
    uint8_t delivery_reliable_status_dirty;
    uint8_t delivery_callback_fatal;
    session_delivery_attempt_t wire_delivery;
    uint8_t d29_latest_periodic_pending;
    uint64_t d29_latest_periodic_revision;
    session_delivery_latest_config_t
        delivery_latest_tx_config[DELIVERY_LATEST_OBJECTS];
    session_delivery_latest_config_t
        delivery_latest_rx_config[DELIVERY_LATEST_OBJECTS];
    session_delivery_reliable_config_t
        delivery_reliable_tx_config[DELIVERY_RELIABLE_FLOWS];
    session_delivery_reliable_config_t
        delivery_reliable_rx_config[DELIVERY_RELIABLE_FLOWS];

    /* Bounded terminal CTRL_ERROR/CTRL_CLOSE state. Each bit identifies one
     * authenticated key epoch: current, pending, or pre-session hello key. */
    int     close_tx_count;
    int64_t close_next_send_ms;
    int     close_peer_seen;
    int     close_attempts_target;
    uint8_t close_epoch_mask;
    uint8_t terminal_abort_attempted_mask;

    /* ERR_SESSION rate limiting (3 in 10s → close) */
    int     err_session_count;
    int64_t err_session_window_start_ms;

    /* Channel registry */
    const channel_ops_t *channels[CHANNEL_MAX];

    /* channel-session runtime instances are distinct from the static outer-class
     * registry above. Stage 1 uses one TERMINAL occupant; later stages use
     * the same fixed table for up to fifteen concurrent data channels. */
    int channelised_requested;
    channel_session_table_t channel_table;
    session_channel_runtime_t channel_runtime[CHANNEL_SESSION_SLOTS];
    channel_session_open_t channel_first_template;
    channel_session_open_t channel_first_open;
    uint32_t terminal_channel_handle;
    uint8_t channel_first_open_valid;
    uint8_t channel_control_inflight;
    uint8_t channel_control_type;
    uint8_t channel_control_slot;
    uint8_t channel_control_cursor;
    uint32_t channel_control_handle;
    attach_manager_t attach_manager;
    channel_process_table_t channel_processes;
    child_transfer_table_t child_transfers;
    child_transfer_launch_policy_t child_transfer_policy;
    attach_manager_event_t child_transfer_pending_event;
    session_channel_application_t
        channel_application[CHANNEL_SESSION_SLOTS];
    char attach_socket_path[ATTACH_LOCAL_PATH_CAP];
    uint8_t attach_socket_configured;
    uint8_t attach_socket_prepared;
    uint8_t attach_socket_open;
    uint8_t channel_source_cursor;
    uint8_t child_transfer_configured;
    uint8_t child_transfer_remote_bind_configured;
    uint8_t child_transfer_manager_failed;
    uint8_t child_transfer_pending;
    uint8_t child_transfer_lease_slot;
    uint32_t child_transfer_lease_handle;
    char child_transfer_program[SESSION_CHILD_TRANSFER_TEXT_MAX];
    char child_transfer_udp_host[SESSION_CHILD_TRANSFER_TEXT_MAX];
    char child_transfer_remote_command[SESSION_CHILD_TRANSFER_TEXT_MAX];
    char child_transfer_remote_bind_host[SESSION_CHILD_TRANSFER_TEXT_MAX];

    /* ---- PTY ---- */
    /* Server-side PTY state */
    int     pty_master_fd;       /* -1 if not open */
    pid_t   pty_child_pid;       /* 0 if not spawned */

    /* Client-side PTY session flags */
    int     is_client_pty;       /* 1 = client has spawned a PTY session mode */
    int     raw_mode_active;     /* 1 if stdin is in raw mode (client) */
    int     pty_open_ack_seen;   /* client received PTY_OPEN_ACK */
    int     pty_open_err_seen;   /* client received PTY_OPEN_ERR — stop retrying */
    int     stdin_closed;        /* client stdin reached EOF — stop polling it */

    /* send-scheduler source ownership for local terminal control. SIGINT is one exact
     * pending event; resize is latest-state-wins. They survive a full
     * INTERACTIVE lane until admission succeeds. */
    uint8_t  pty_signal_pending;
    uint8_t  pty_pending_signal;
    uint8_t  pty_resize_pending;
    /* server-classic output ended; association-owned, not TX state.
     * Uses the byte before the aligned dimensions; only enter_idle resets. */
    uint8_t  pty_source_ended;
    uint16_t pty_pending_rows;
    uint16_t pty_pending_cols;

    /* PTY_OPEN retransmit state (client; a lost PTY_OPEN/PTY_OPEN_ACK
     * used to strand the session shell-less).
     * Armed by channel_pty_client_send_open, driven from session_run on
     * the CTRL_HELLO schedule: 5 sends, 1s/2s/4s/8s backoff, 16s final
     * wait, then session_close. */
    int      pty_open_tx_count;
    int64_t  pty_open_next_send_ms;
    int64_t  pty_open_backoff_ms;
    uint16_t pty_open_rows;
    uint16_t pty_open_cols;

    /* Plaintext budget for a single frame. Multi-fragment records deduct the
     * authenticated descriptor and whole-message hash from this budget. */
    uint16_t current_mtu;

    /* server-side write backlog for PTY master when write() returns
     * EAGAIN. Flushed via POLLOUT in session_run. */
    uint8_t pty_master_backlog[4096];
    size_t  pty_master_backlog_len;

    /* Exit code returned by the client when PTY_EOF arrives */
    int     client_exit_code;
    int     should_exit;         /* set by client PTY handlers to break session_run */
    int     pty_eof_seen;        /* PTY_EOF was received on client */

    /* Fixed global pool of authenticated whole-message assemblies. */
    reasm_t reasm;


    /* Bitmask of misdirected PTY subtypes already logged once for
     * this session. Bit (1 << type) is set after the first quiet-drop log so
     * a flooding peer doesn't fill stderr. Cleared on session_create. */
    uint16_t pty_quiet_log_mask;

    /* terminal state sync. Active only when PTY_SYNC_V1 was
     * negotiated; initialized at ESTABLISHED, freed on enter_idle/destroy. */
    /* One-shot listener-monitor external cleanup owner; never reset by sync_free. */
    struct sync_monitor_binding *sync_monitor;
    /* listener-monitor fixed server-classic backend. NULL is the exact ordinary path;
     * ownership remains external and session_destroy only detaches it. */
    struct monitor_session_backend *monitor_backend;
    sync_tx_t sync_tx;
    sync_rx_t sync_rx;
    sync_tx_t sync_tx_instances[CHANNEL_SESSION_SLOTS];
    sync_rx_t sync_rx_instances[CHANNEL_SESSION_SLOTS];
    sync_instance_binding_t sync_binding[CHANNEL_SESSION_SLOTS];
    uint64_t sync_admitted_tx;
    uint64_t sync_admitted_rx;
    uint64_t sync_retired_tx_tip;
    uint64_t sync_retired_rx_delivered;
    uint64_t sync_retired_rx_highest;
    uint64_t sync_d36_tx_quota;
    uint64_t sync_d36_rx_quota;
    uint8_t sync_d36_quotas_parsed;
    uint8_t sync_lane_cursor[SEND_LANE_COUNT];

    /* sync-status observational status. It carries no delivery authority and is
     * active only when STATUS_HEARTBEAT_V1 is negotiated with PTY_SYNC_V1. */
    sync_status_tracker_t sync_status;
    client_escape_t       client_escape;

};

/* -------------------------------------------------------------------------
 * Session API
 * ---------------------------------------------------------------------- */

/*
 * Create a new session.
 * PSK is copied into mlock'd memory; caller should wipe original after call.
 * Returns NULL on failure.
 */
session_t *session_create(transport_t *t,
                          const uint8_t psk[32],
                          const uint8_t pair_id[4]);

/*
 * Destroy session and free all resources. Wipes key material.
 */
void session_destroy(session_t *s);
/* Actual application mode, including the ESTABLISHED server WAIT_INIT
 * rekey barrier. Does not grant source, path or send authority by itself. */
int session_application_send_eligible(const session_t *s);

/*
 * Client: initiate connection (send CTRL_HELLO). State → CONNECTING.
 * Returns 0 on success, -1 on failure.
 */
int session_connect(session_t *s);

/*
 * Server: wait for connection (enter listen loop). State stays IDLE until
 * first CTRL_HELLO arrives, then transitions to KEY_DERIVING.
 * Typically just sets is_server=1; actual handling in session_run().
 * Returns 0.
 */
int session_listen(session_t *s);

/* Configure the immutable capability policy before connect/listen. Unknown
 * optional bits are allowed and intersect away; required must be a subset of
 * supported. The exact ordinary default is UNMOOR_CAP_DEFAULT_SUPPORTED,
 * including optional terminal-state-sync/sync-status/delivery-class services; only PTY_V1 is required. */
int session_set_capabilities(session_t *s, uint32_t supported,
                             uint32_t required);
uint32_t session_selected_capabilities(const session_t *s);
int session_peer_is_legacy(const session_t *s);

/* channel-session is explicit and required. Stage 1 enables exactly one terminal kind;
 * commands without this call preserve their legacy offer and wire bytes. */
int session_enable_channelised_terminal(session_t *s, uint16_t rows,
                                        uint16_t columns,
                                        const char *label);
/* Client-only local attach listener. Configuration is accepted before
 * connect and opened only after channel-session negotiation succeeds. */
int session_enable_attach_socket(session_t *s, const char *absolute_path);
/* client-confinement: run the attach socket's path work before confinement; the bind point
 * inside the session is unchanged. Returns 0 on success or when there is
 * nothing to prepare. */
int session_prepare_attach_socket(session_t *s);
/* child-transfer local launcher authority. Requires an already configured client attach
 * socket and copies every public string before connect freezes configuration. */
int session_enable_child_transfers(
    session_t *s, const session_child_transfer_config_t *config);
int session_channelised_active(const session_t *s);
/* Trusted classic source boundary, shared by OPEN and sync admission.
 * channel-session's slot-1 anchor and client stdin are deliberately excluded. */
static inline int session_classic_pty_source_ended(const session_t *s)
{
    return s && s->is_server && !session_channelised_active(s) &&
           s->pty_source_ended;
}
static inline void session_classic_pty_source_end(session_t *s)
{
    if (s && s->is_server && !session_channelised_active(s))
        s->pty_source_ended = 1U;
}
int session_stream_owner_active(const session_t *s, uint32_t handle);
uint32_t session_terminal_channel_handle(const session_t *s);
void session_channel_tick(session_t *s, int64_t now_ms);
int64_t session_channel_next_deadline(const session_t *s, int64_t now_ms);
int session_channel_terminal_complete(session_t *s, uint32_t code);
/* terminal-state-sync per-instance lifecycle callbacks.  The sync engine invokes these only
 * after its exact FIN/linger rules; channel-session maps them to one channel rather than
 * the outer session. */
void session_channel_stream_receive_complete(session_t *s, uint8_t slot,
                                             int have_code, int32_t code);
void session_channel_stream_send_complete(session_t *s, uint8_t slot,
                                          uint32_t code);
void session_channel_stream_io_failed(session_t *s, uint8_t slot,
                                      uint32_t code);

/* traffic-profile local traffic policy. The public profile name is SSH/CLI
 * configuration, never wire authority; exact multipath masks remain capability-negotiation-owned. */
int session_set_traffic_profile(session_t *s, traffic_profile_t profile);
/* traffic-profile bounded structured event sink. Must be enabled before connect/listen;
 * it makes only the supplied descriptor nonblocking and restores its prior
 * flags at destruction. Text mode simply never calls this API. */
int session_enable_json_events(session_t *s, int fd);

/* Explicit UDP-only multipath request. It requires the exact capability and a
 * complete path-aware transport seam before connect/listen freezes config. */
int session_enable_multipath_paths(session_t *s, unsigned int path_count);
int session_enable_multipath(session_t *s); /* default eight-path shorthand */
/* traffic-profile enterprise supported-only offer. The exact count is advertised but
 * not required; an unselected result retires the unused client descriptors
 * before service activation and continues on ordinary roaming-freshest-path fd 0. */
int session_offer_multipath_paths(session_t *s, unsigned int path_count);
int session_multipath_snapshot(const session_t *s,
                               multipath_snapshot_t *snapshot_out);
/* Read-only composed view. Refreshes transport/multipath/bulk-transfer observations
 * and copies exactly path_leg_count entries; it grants no path authority. */
int session_path_legs_snapshot(session_t *s,
                               path_leg_t legs[MULTIPATH_PATHS_MAX],
                               size_t leg_capacity,
                               uint8_t *leg_count_out);
int session_path_metrics_snapshot(
    session_t *s, path_leg_metrics_t metrics[MULTIPATH_PATHS_MAX],
    size_t metric_capacity, uint8_t *leg_count_out);
/* Operator-requested, observation-only process snapshot. The caller invokes
 * this from the ordinary event loop, never from a signal handler. Output is
 * fixed-size, nonblocking, and excludes keys, transcript and application
 * bytes. `snapshot_id` lets two endpoints correlate an explicit request. */
int session_diagnostic_snapshot(session_t *s, int fd,
                                uint64_t snapshot_id, int64_t now_ms);
int session_multipath_primary_log_due(uint64_t primary_changes);
int session_replay_log_due(uint64_t replay_drops);
int session_multipath_mismatch_log_due(uint64_t mismatches);
uint32_t session_multipath_validation_log_bit(unsigned int validated_count);
void session_multipath_tick(session_t *s, int64_t now_ms);
int64_t session_multipath_next_deadline(const session_t *s, int64_t now_ms);

/* Dedicated UDP-only bulk-transfer application profile.  Generic capability mutation
 * cannot advertise bulk-transfer; this API binds one client request or one passive
 * server endpoint before connect/listen.  Path bytes are copied by the bulk
 * engine at activation and never enter the SSH command boundary. */
int session_enable_bulk(session_t *s,
                        const bulk_engine_config_t *config);
int session_bulk_prevalidate(const session_t *s, uint8_t type,
                             const uint8_t *plaintext,
                             size_t plaintext_len);
int session_bulk_receive(session_t *s, uint8_t type,
                         const uint8_t *plaintext,
                         size_t plaintext_len);
bulk_engine_result_t session_bulk_result(const session_t *s,
                                         bulk_result_code_t *code_out);
int session_bulk_cancel(session_t *s);
/* Consume at most one bulk-transfer physical source-port reroll in one event-loop
 * turn. Public only for the deterministic production-session harness. */
int session_bulk_reroll_tick(session_t *s, int64_t now_ms);

/* delivery-class channel-2 receive boundary. The built-in delivery channel calls this
 * only after AEAD, replay, capability, and canonical single-frame checks. */
int session_delivery_prevalidate_latest(
    const session_t *s, uint8_t type, const uint8_t *plaintext,
    size_t plaintext_len, uint16_t *object_id_out);
int session_delivery_receive_latest(session_t *s, uint8_t type,
                                    const uint8_t *plaintext,
                                    size_t plaintext_len);

/* Static delivery-class application configuration and bounded admission. Object id 1
 * is reserved for sync-status and cannot be configured by an application. */
int session_delivery_configure_latest(
    session_t *s, unsigned int slot, session_delivery_direction_t directions,
    uint16_t object_id,
    delivery_priority_t priority, delivery_latest_install_fn install,
    void *install_arg);
int session_delivery_publish_latest(session_t *s, uint16_t object_id,
                                    const uint8_t *bytes, size_t length);
int session_delivery_set_latest_reason(session_t *s, uint16_t object_id,
                                       delivery_reason_t reason, int enabled);
int session_delivery_configure_reliable(
    session_t *s, unsigned int slot, session_delivery_direction_t directions,
    uint16_t flow_id,
    delivery_priority_t priority, delivery_reliable_deliver_fn deliver,
    void *deliver_arg, session_delivery_reliable_result_fn result,
    void *result_arg);
int session_delivery_send_reliable(session_t *s, uint16_t flow_id,
                                   const uint8_t *bytes, size_t length,
                                   uint64_t *message_id_out);
int session_delivery_set_reliable_reason(session_t *s, uint16_t flow_id,
                                         delivery_reason_t reason,
                                         int enabled);
void session_delivery_tick(session_t *s, int64_t now_ms);
int64_t session_delivery_next_deadline(const session_t *s, int64_t now_ms);

/* Enable the epoch-rekey engine before connect/listen. `pair_seed` is the
 * epoch-zero pair id derived by the public bootstrap. This makes the exact
 * epoch-rekey and PTY-sync capabilities required and runs a mandatory fresh-DH
 * barrier before services when bootstrap_required is nonzero. */
int session_enable_epoch_rekey(session_t *s, const uint8_t pair_seed[4],
                               int bootstrap_required,
                               int ephemeral_bootstrap_root);

/* Bind the pq-hybrid fixed-share engine to an already initialized epoch-rekey session.
 * The capability is required because the public v2 carrier was selected
 * before HELLO; generic capability mutation cannot advertise this bit. */
int session_enable_pq_hybrid(session_t *s);

/* Request a later client-led rekey. Primarily an explicit/test seam until a
 * rotation cadence is decided. Server calls emit repeated REQUEST state. */
int session_request_epoch_rekey(session_t *s);

/* Deterministic engine seams used by the production event loop and the
 * default fake-wire harness. They process the same product frames/state; no
 * test-only protocol implementation exists. */
void session_epoch_rekey_tick(session_t *s, int64_t now_ms);
/* Injected-clock READY timer used by the event loop and deterministic
 * bootstrap harness. It performs only due READY send/reassertion work. */
void session_ready_tick(session_t *s, int64_t now_ms);
void session_process_datagram(session_t *s, const uint8_t *frame,
                              size_t frame_len);
void session_process_datagram_at(session_t *s, const uint8_t *frame,
                                 size_t frame_len, int64_t now_ms);
void session_process_datagram_from(session_t *s, const uint8_t *frame,
                                   size_t frame_len,
                                   const multipath_token_t *ingress);
/* Deterministic receive-clock seams. The source identity is derived from the
 * canonical ingress token while its port/local leg are deliberately
 * excluded. `now_ms` governs pre-authentication accounting and authenticated
 * lifecycle deadlines; it never supplies protocol data. */
void session_process_datagram_from_at(session_t *s, const uint8_t *frame,
                                      size_t frame_len,
                                      const multipath_token_t *ingress,
                                      int64_t now_ms);

/* Complete the existing CONNECTING stash boundary after key derivation.
 * Public only so deterministic composition tests can pin authority ordering;
 * normal product code invokes it from the authenticated READY transition. */
void session_replay_stashed_frame(session_t *s);
void session_replay_stashed_frame_at(session_t *s, int64_t now_ms);

/* sync-status injected-clock status seam. A query prints only to local stderr and
 * asks for one fresh absolute snapshot; it never enters the PTY stream. */
int  session_status_active(const session_t *s);
void session_status_tick(session_t *s, int64_t now_ms);
void session_status_query(session_t *s);
int64_t session_status_next_deadline(const session_t *s, int64_t now_ms);

/* Fixed-offset key wipe used by signal cleanup. It deliberately does not
 * traverse or reset protocol-owned dynamic state. */
void session_wipe_key_material(session_t *s);

/* Idempotent full reset used by normal destruction and controlled cleanup. */
void session_wipe_secrets(session_t *s);

/* Internal read-pacer operations are exposed here so the deterministic unit
 * harness can inject time. A zero-length/EAGAIN read consumes no credit. */
void session_pacer_refill(session_t *s, int64_t now_ms);
void session_pacer_charge_read(session_t *s, size_t read_len);
int session_pacer_source_blocked(const session_t *s);

/* Internal typed send used by bounded channel producers. Public only for the
 * deterministic production-engine harnesses; callers must retain logical
 * state when it reports busy/failure. */
int session_send_lane(session_t *s, send_lane_t lane,
                      uint8_t chan_byte, uint8_t type,
                      const uint8_t *plaintext, size_t plaintext_len);

/* Admission plus an exact terminal transport-result owner. WOULD_BLOCK and
 * partial progress retain the immutable attempt and issue no callback;
 * COMPLETE/FAILED route `done` and the two bounded metadata words back to
 * the producer. This is an internal protocol-engine seam, not an application
 * delivery acknowledgement. */
int session_send_lane_tracked(session_t *s, send_lane_t lane,
                              uint8_t chan_byte, uint8_t type,
                              const uint8_t *plaintext,
                              size_t plaintext_len,
                              session_tx_done_t done,
                              uint64_t arg0, uint64_t arg1);
/* channel-session variant: `stream_slot` selects the exact stream owner and therefore
 * the encrypted handle prefix and completion callback.  Slot 1 is exactly
 * the legacy wrapper above. */
int session_send_lane_tracked_instance(session_t *s, uint8_t stream_slot,
                                       send_lane_t lane,
                                       uint8_t chan_byte, uint8_t type,
                                       const uint8_t *plaintext,
                                       size_t plaintext_len,
                                       session_tx_done_t done,
                                       uint64_t arg0, uint64_t arg1);

/* One injected-clock send-scheduler event-loop turn: retry at most the retained frame.
 * Normal session_run calls this itself. */
void session_send_scheduler_turn(session_t *s, int64_t now_ms);
int  session_send_scheduler_pending(session_t *s);
int  session_set_physical_clock(session_t *s, session_clock_now_fn now_fn,
                                void *context);
/* Re-initialise the wire scheduler (rate, MTU, clock) and re-apply the
 * service-start fact so a post-service REKEY stays paced (send-scheduler F1).  Every
 * scheduler re-init on a session goes through this seam, tests included;
 * never call send_scheduler_init() on s->wire_scheduler directly. */
int  session_wire_scheduler_reset(session_t *s, int64_t rate_bps,
                                  uint16_t effective_mtu, int64_t now_ms);

/*
 * Main event loop. Runs until session closes or error.
 * Uses poll() on transport fd + clock_gettime() for timer math.
 * Returns 0 on clean close, -1 on error.
 */
int session_run(session_t *s);

/*
 * Initiate graceful close. Sends CTRL_CLOSE and enters CLOSING state.
 */
void session_close(session_t *s);

/* Apply the raw client's line-start ~. command. This closes the whole
 * association even under channel-session; it is never translated into terminal FIN. */
void session_local_disconnect(session_t *s);

/* Injected-clock terminal-boundary step used by session_run and deterministic
 * composition gates. Returns 1 after the bounded close entered IDLE. */
int session_close_tick(session_t *s, int64_t now_ms);

/* Exact transport-ownership boundary shared by poll termination, bounded
 * close expiry, and the deterministic composition gate. It releases the
 * active logical owner exactly once and accounts every unresolved multipath copy. */
void session_transport_closed(session_t *s);

/* Send one authenticated terminal error per valid epoch and enter the
 * bounded close path. This is the channel-dispatch fail-closed seam. */
void session_protocol_error_close(session_t *s, uint16_t code);

/*
 * Admit one plaintext payload on the given channel. In session_run, success
 * means the bounded logical record was accepted; encryption and transport
 * completion happen in later scheduler turns. Deterministic callers outside
 * session_run drive one synchronous fake-wire turn for compatibility. The
 * low nibble must be exactly FF=1/MF=0.
 * Returns 0 on admission, -1 on refusal/failure.
 */
int session_send(session_t *s, uint8_t chan_byte, uint8_t type,
                 const uint8_t *plaintext, size_t plaintext_len);

/*
 * Authenticated whole-message send.
 * A message that exceeds `current_mtu` receives one identity, canonical
 * fragment geometry, and a repeated encrypted BLAKE2b-256 commitment. Each
 * multi-fragment datagram carries at most `current_mtu - 48` message bytes.
 * Messages are bounded to 4096 bytes and 32 fragments; channel 0 is rejected.
 *
 * chan_id: 1..15 (placed in the high nibble of the CHAN byte).
 * Returns 0 when the one bounded logical message is admitted. Product
 * session_run advances one fragment per scheduler grant; deterministic
 * callers outside the run loop drive their synchronous fake transport to
 * completion. A second message while the slot is occupied fails loudly.
 */
int session_send_data(session_t *s, uint8_t chan_id, uint8_t type,
                      const uint8_t *plaintext, size_t plaintext_len);

/*
 * UDP roaming: enable/disable the mosh-style liveness hold (see the
 * liveness_unbound field). Call after session_create, before session_run.
 */
void session_set_liveness_unbound(session_t *s, int unbound);

/* Mark whether stderr and the peer-display stdout resolve to the same
 * terminal device. Automatic prose is suppressed only while raw mode is
 * active; structured events and the distinct /dev/tty title sink are not. */
void session_set_shared_raw_display_tty(session_t *s, int shared);

/* Arm the bootstrap accept window: if the session is not ESTABLISHED
 * within `secs`, session_run returns -1 (mosh-server's 60s rule).
 * 0 disarms. */
void session_set_bootstrap_timeout(session_t *s, int secs);

/* Absolute CLOCK_MONOTONIC deadline used when a public pre-session exchange
 * has already consumed part of the one finite bootstrap window. A
 * nonpositive value disarms it. */
void session_set_bootstrap_deadline_ms(session_t *s, int64_t deadline_ms);

/*
 * Optional hook invoked by session_run() once per iteration. Used by the
 * client to pump pending SIGINT / SIGWINCH flags into PTY_SIGNAL / PTY_RESIZE
 * frames. NULL by default.
 */
typedef void (*session_tick_fn)(session_t *s);
extern session_tick_fn session_run_tick;

/* Optional process-integration hook invoked exactly once after negotiated
 * session services (currently terminal sync) initialize successfully and
 * before any channel on_open callback can emit or receive channel traffic.
 * A nonzero result is a loud establishment failure. */
typedef int (*session_established_fn)(session_t *s);
extern session_established_fn session_on_established;

/* Process-owned presentation hook. The session supplies bounded generated
 * state; main.c may render it on a separately opened /dev/tty only. */
typedef void (*session_status_ui_fn)(session_t *s,
                                     const sync_status_view_t *view);
extern session_status_ui_fn session_status_ui;

#endif /* UNMOOR_SESSION_H */
