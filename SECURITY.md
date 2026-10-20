<!-- Copyright (c) 2026 Nenad Micic -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.2.0 (protocol v2) | current — fixes land on `main` |
| anything earlier | no |

There is one line of development and no back-porting. This experimental
protocol carries no compatibility promise yet: endpoints with different wire
versions refuse each other and the older endpoint must be upgraded.

## Status of this code

Unmoor is version 0.2.0. It has been specified, implemented, reviewed and
tested inside this project — including a two-machine gate that runs complete
sessions across a routed, impaired network path, reported in `SOURCE.md` — and
**it has had no external security audit**. The cryptographic construction is
built from vendored implementations: X25519 combined with ML-KEM-1024,
XChaCha20-Poly1305 for record protection, BLAKE2b for derivation. The protocol
around it is this project's own, and no one outside the project has reviewed
it yet. That is the state a first public release is in, and it is the reason
this file exists.

The recommended bootstrap connects machines you already have SSH access to.
Unmoor is not a public service endpoint and should not be deployed as one.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Use GitHub's private vulnerability reporting on this repository (Security →
Report a vulnerability). That opens a private advisory visible only to the
maintainer. If you cannot use it, mail the address on the commits in this
repository's history and put `unmoor security` in the subject.

What helps, roughly in order of usefulness: the commit you tested, the exact
command lines for both endpoints, whether the peers were on one host or two,
and any captured frames or `--log-format json` output. A proof of concept is
welcome but not required — a clear description of the flaw is worth more than
a script.

This is a personal project, not a funded one. Expect an acknowledgement within
a week. There is no bounty, and there is no embargo clock I can promise to
beat; tell me what disclosure timeline you intend and I will work to it or say
plainly that I cannot.

## Known limitations

These are properties of the current design, not open findings, and you should
assume an attacker knows them. Where one needs a privileged position to reach,
that is said, because a limitation only matters next to what the same position
already buys.

- **The listener is not confined.** Client-side confinement (`no_new_privs`,
  Landlock, seccomp on Linux) protects the client. The terminal listener runs
  as the ordinary SSH user it logged in as, with that user's full authority.
  Do not run it as a user you are not willing to hand to whoever can complete
  the bootstrap.
- **A session does not recover a return path that goes stale under it.** If a
  client's source address changes while it is suspended and the old return
  flows stop delivering, input still reaches the far end but output does not
  come back, and the client does not open a replacement source port to repair
  it. It reports `STALLED` and shows nothing undelivered as delivered; start a
  fresh session. This is measured, not inferred — it is one of the two-machine
  scenarios in `SOURCE.md`.
- **The manual pre-shared-key listener has no forward secrecy at all.** This
  is stronger than "not post-quantum forward secret". That path runs no
  Diffie-Hellman: the session key is `BLAKE2b(PSK; hellos, selected caps)`
  (`src/crypto.c`, `crypto_derive_negotiated_session_key`), and epoch rekey is
  enabled only on the public-bootstrap path (`session_enable_epoch_rekey` has
  exactly one caller, in `src/main.c`). Both hello values are on the wire, so
  anyone who records the traffic and later obtains the PSK can recompute the
  session key and decrypt the whole session retroactively. Relatedly,
  `UNMOOR_KEY` carries a symmetric key through the environment, and
  `listen --bootstrap` prints a freshly generated one on stdout for a caller
  to relay; both are documented, and neither is the recommended path. Without
  rekey that path also has a hard stop: its 32-bit sequence space is never
  renewed, and a session that nearly exhausts it refuses to send rather than
  reuse a nonce (`sequence space exhausted` in `src/session.c`). The PSK modes
  exist for testing. Use `bin/client.sh`.
- **A targeted flood can silence a peer, and one source address is enough.**
  Every datagram that fails AEAD is charged to its source address
  (`src/preauth_budget.h`): eight failures within two seconds put that
  address into a two-second penalty during which its datagrams are dropped
  before any further AEAD work, genuine ones included. The budget is keyed on
  the address alone, never the port, so traffic spoofed to carry the live
  peer's address penalises the live peer. An attacker who can observe the
  flow to learn its destination port and clear four-byte pair identifier
  therefore needs no deliverable addresses of their own: roughly four bad
  datagrams per second with the peer's address as the source keep that peer
  silent for as long as they continue. The table has 64 address slots, and
  while every slot is busy, datagrams from addresses it does not hold, an
  established session's included, are dropped too. The client runs the same
  budget. Stop the traffic and the penalty drains within about four seconds;
  restart through SSH and the new session has a fresh port and pair identity.
  The `SIGUSR1` snapshot reports the budget's counters. This can interrupt
  availability but cannot read, forge or weaken traffic.
- **The return path follows whichever authenticated datagram arrives first.**
  A listener adopts a new return address when an authenticated datagram
  advances the replay high-water mark (`src/session.c`, the `peer_confirm`
  call guarded by `hwm`). An attacker on the path needs no key to exploit
  this: copying a fresh datagram verbatim and racing the copy ahead of the
  original satisfies both conditions, because the ciphertext is genuine and
  the sequence number is new. The return path then points at the attacker,
  and the genuine original is discarded as a replay. What the rule does
  prevent is redirection by an *old* captured packet. Someone holding that
  position can already drop the flow outright; what this adds is that they can
  also point the return path at themselves, and that doing so hands them
  ciphertext they cannot read. Treat on-path adversaries as able to steer the
  return path, not as able to read it.
- **Server-side confinement is scoped by the remote peer, and starts late.**
  `--server-confine` narrows the one-shot remote bulk server, but the
  narrowing is applied from the bulk engine's request-path hook
  (`bulk_server_confine_path` in `src/main.c`, reached via
  `apply_request_path_policy` in `src/bulk_engine.c`) — that is, only after
  the peer's REQUEST record has been received and parsed, and with a Landlock
  scope derived from the path the peer asked for. The process is unconfined
  while it parses that record. The peer in question has already completed an
  authenticated bootstrap, so this narrows what an authorised peer can reach
  rather than keeping an unauthorised one out.
- **The seccomp allow-lists filter almost no syscall arguments, and the
  confined client keeps more than "sandboxed" suggests.** Argument filters
  exist for exactly two calls: `prctl` is admitted for three fixed requests,
  and the one-shot bulk server's `fcntl` for a fixed set of commands
  (`src/confine.c`). Everything else on a role's list may be issued with any
  argument on any descriptor the process already holds: `ioctl` with any
  request code (on kernels that still permit `TIOCSTI`, that means typing
  into a controlling terminal), and `kill`, `tgkill` and `prlimit64` against
  any process of the same user, not only children. The terminal client keeps
  `clone` and `execve` for its child transfers; what they can start is
  bounded by Landlock execute rights on the binary's own image and the loader
  paths plus `no_new_privs`, not by seccomp. Several filesystem operations
  are outside Landlock on the ABI levels a client accepts: `chmod`, `umask`
  and `utimensat` always, `truncate` below ABI 3 and TCP sockets below ABI 4,
  while UDP and Unix sockets are never restricted. The allow-lists are
  deliberately generous about syscalls that cannot widen authority and strict
  about the ones that can — `ptrace`, `mount`, `chroot`, `set*uid`, `bpf`,
  `kexec`, module loading, `keyctl` and `process_vm_*` appear in no group —
  but read "confined" as "narrowed", not "sandboxed".
- **Another user on the same host can deny a start, not join a session.** The
  UDP listener binds its port exclusively, so a second process cannot share
  the socket and take datagrams; a port that is already taken is a loud
  failure. The `--listener-monitor` rendezvous between the monitor and its
  listener child is an abstract Unix socket under a random name. Abstract
  sockets carry no permissions, and once the monitor has bound the name it
  is visible to every user in the network namespace through
  `/proc/net/unix`; a local user who connects before the child does is
  rejected by the peer identity check, and the start then fails with a
  message and does not retry. A Unix-socket transport accepts connections
  only from the same user, and the listener's `--log` file must be a regular
  file that user owns.
- **Backlog is bounded per sender, not globally.** Classic terminal state sync
  holds up to 256 MiB of transmit history and 4 MiB of receive-pending data per
  endpoint by default. Channelised exact streams default to 16 MiB/1 MiB per
  stream with 256 MiB/64 MiB aggregate caps. These sit on top of kernel and
  application buffers; a host running many sessions can allocate a multiple
  of the per-session bounds.
- **Established terminal sessions do not expire on absent contact.** `STALLED`
  is an observation, not proof that the peer is dead. A listener can remain
  alive until an operator or normal session teardown closes it.
- **`--pq=prefer` and `--pq=off` are real reductions.** Both exist, both must
  be typed explicitly, and both are visible in the logs. On the recommended
  SSH bootstrap, `prefer` currently behaves exactly like `require`: the
  one-shot exchange has no legacy fallback, so a peer without the hybrid
  suite is refused either way, and only `off` selects the legacy profile.
  `--confine=off` and `--confine=best-effort` are the same kind of deliberate
  reduction on the client side.
- **Terminal output is not sanitised, and neither is the SSH carrier's
  stderr.** Bytes the far end writes to the terminal reach your terminal
  emulator as they are; the client filters only its own escape key on the
  way in (`src/client_escape.c`). A hostile or compromised server can drive
  any sequence your emulator honours, exactly as it can over plain `ssh`, so
  the emulator's own protections are part of the trust base. Separately, the
  `ssh` child inherits the client's stderr during the bootstrap and, under
  `--remote-foreground`, for the whole session, so that OpenSSH banners and
  diagnostics stay visible. That stream is unfiltered, and it is shared with
  `--log-format json` records; a consumer of those records must not assume
  it is the only writer of that descriptor.
- **Key memory is pinned only where the platform allows it.** The session
  asks the kernel to keep its key material out of swap (`crypto_mlock` in
  `src/crypto.c`); when that fails, for example under a low memory-lock
  limit, a warning is printed and the session continues.
- **No resume, no recursion, no metadata promise** for file transfer. A
  destination appears only after the whole transfer verifies, but an
  interrupted transfer starts again from the beginning.
- **This repository ships a focused test set.** `make check` and `make smoke`
  are fast checks that prove a build works and a real post-quantum session
  runs. The full regression suite and the two-machine impairment gate live in
  the development tree; `SOURCE.md` reports that gate run against this source.
  The smoke passes no `--confine` option unless asked, so on Linux it runs
  under the default `require` policy; `--confine best-effort` is an explicit
  opt-in for older kernels. It does not exercise attached transfers, bulk
  transfer or `--listener-monitor`.

## What is out of scope

Availability against a peer that has already completed an authenticated
bootstrap: that peer is, by construction, someone you let in over SSH.

Availability against an attacker who can already block traffic between the
two endpoints. Protocol-specific unauthenticated resource exhaustion,
boundedness and resource-accounting defects are still useful reports.

Attacks requiring the local user's privileges on either endpoint, and
weaknesses in OpenSSH, your shell, or your kernel reached through Unmoor but
not caused by it; report those upstream, though I would still like to know.

Copyright (c) 2026 Nenad Micic.
