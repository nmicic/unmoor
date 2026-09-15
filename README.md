<!-- Copyright (c) 2026 Nenad Micic -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Unmoor

Unmoor carries an authenticated UDP session over networks that move underneath
it. The session is identified by a cryptographic pair identity rather than by
an address tuple, so an address or path change does not by itself destroy the
session. A live session resumes when a usable bidirectional UDP path exists
again. A remote terminal is the first thing carried over that session;
verified single-file push and pull is the second.

Unmoor is a child project of [URTB (USB/Radio Terminal
Bridge)](https://github.com/nmicic/URTB). URTB carries a terminal across USB
and radio links; Unmoor is the network version of that work, built for
authenticated UDP sessions across changing addresses, NAT mappings and paths.

`unmoor 0.1.0 (protocol v1)`. C11, macOS and Linux. Every library it links is
vendored here, so the build pulls nothing from the network; running it the
recommended way also uses the Bash and OpenSSH client already on your machine,
because the bootstrap starts the far side over SSH.

## Status: experimental

Unmoor is version 0.1.0. Protocol v1 will change without a compatibility
promise until this section says otherwise. The PQ handshake, the confinement
defaults and the roaming rule have been specified, implemented, reviewed and
tested inside this project — including a two-machine gate that runs whole
sessions across a routed, impaired network path, reported in
[`SOURCE.md`](SOURCE.md) — and none of it has had an external security audit.

The recommended bootstrap connects machines you already have SSH access to.
Unmoor is not a public service endpoint and should not be deployed as one.

[`SECURITY.md`](SECURITY.md) states what is supported, how to report a
vulnerability privately, and the limitations you should assume an attacker
already knows about.

## Why Unmoor exists

Unmoor is for the awkward space between a normal SSH connection and a VPN: you
want one terminal to remain the same session while the client's address, NAT
mapping or usable path changes, without installing a privileged network
service. Its useful property is the combination of these behaviours:

- **The session, not an address tuple, is the identity.** A listener adopts a
  candidate return address only after a fresh authenticated packet advances
  the replay window, so an old captured packet cannot redirect it. What an
  attacker already on the path can still do with a fresh one is stated in
  [`SECURITY.md`](SECURITY.md).
- **SSH authenticates the introduction; it does not carry a traffic key.** SSH
  carries public exchange records and fingerprints. The endpoint processes
  generate private X25519 and ML-KEM-1024 material and derive traffic keys
  locally. A fresh authenticated UDP rekey finishes before terminal or file
  traffic is admitted.
- **Terminal bytes are repaired, not merely sent as best-effort datagrams.**
  Absolute offsets, a pending bitmap and a running hash let the receiver repair
  loss and reordering and let the sender prune confirmed history. The client
  exposes `SYNC`, `OUT-OF-SYNC` and `STALLED` instead of silently pretending a
  gap was delivered.
- **Several authenticated UDP legs may share one session.** A leg count is
  always a power of two from 2 to 32, but the default `enterprise` profile
  fixes it at 2 for a terminal and 4 for a transfer and refuses any other
  explicit count; `--profile lab` is what lets you name one yourself. This can
  exercise different RSS or ECMP choices, but several source ports are not
  proof that the network supplied several physical paths.
- **Complete files are verified before installation.** Push and pull scan and
  verify the complete regular file, then install it atomically; an incomplete
  destination is not presented as success.
- **Security reductions are explicit.** Hybrid post-quantum exchange is
  required by default. Linux clients also require `no_new_privs`, Landlock and
  seccomp support by default; a requested reduction is named and visible.

In the normal path, the two connections have deliberately different jobs:

```text
client  -- SSH: authenticate + carry public records -->  server
client  <==== encrypted authenticated UDP session ====>  listener
```

Unmoor is not a VPN, a relay or NAT hole-puncher, a terminal emulator or
multiplexer, a recursive filesystem synchronizer, or a hardened multi-user
daemon. SSH reachability alone is insufficient: the client must also be able
to reach the UDP port selected by the remote listener.

## How this was built

Unmoor is an end-to-end AI-assisted project. The specification, the C
implementation, the test harnesses, the reviews that found defects in them and
the prose in these files were all produced by me working with AI coding
agents, over a long sequence of directed sessions with human decisions at
every material step. Nothing here was pasted in unread, and the design
decisions, the refusals to ship, and the responsibility for the result are
mine.

That is worth stating plainly because it is the provenance of the code, and
because it should inform how you read it: the reasoning behind a given line is
real and usually written down, and the review it has had is this project's own
rather than an external audit's.

## Build

```sh
make -j2        # ./unmoor
make check      # unit tests, shell syntax, production-symbol hygiene
make smoke      # real PQ bootstrap over loopback UDP with a live PTY
```

To build `./unmoor`: a C11 compiler and GNU Make. `make check` additionally
uses `nm`, `strings` and `bash`, `make smoke` needs Python 3, and `make bundle`
needs Git and a clean checkout. Nothing in the build fetches anything from the
network.

To use it against a real peer, the initiating machine also needs Bash and an
OpenSSH client. The SSH bootstrap helper supports the Bash 3.2 shipped with
macOS; the short `bin/*.sh` launchers themselves are POSIX shell. The binary
links nothing but libc (and `libutil` on Linux, for the PTY).

Build as your ordinary user; Unmoor needs no root, no capabilities and no
kernel module.

`.github/workflows/ci.yml` is configured to run those three commands on Linux
with GCC and with Clang and on macOS with Clang, and then repeat them from a
`make bundle` archive unpacked into an empty directory. Manually recorded
verification is in `SOURCE.md`.

## Use

The recommended path needs no additional Unmoor key provisioning. Your normal
SSH credentials authenticate a public-record exchange; the terminal that
follows runs over UDP:

```sh
UNMOOR_PACE_BPS=400000 bin/client.sh --remote ./unmoor/unmoor user@server
```

`--remote` is the path to the `unmoor` executable **on the server**, which you
built there from this same source. The wrapper uses your normal SSH keys,
agent and host-key checking and starts a one-shot listener on the far side.
Only public records and fingerprints cross SSH. On this path no private or
derived Unmoor key enters a shell variable, argv, a forwarded environment
variable, a file or a log. The manual pre-shared-key modes that exist for
tests are deliberately not like this; [`HOWTO.md`](HOWTO.md) says how they
differ.

Leave the session with Enter then `~.`. `Ctrl-] s` prints local sync status.

Single files move over the same bootstrap, with no interactive session first:

```sh
bin/unmoor.sh push --remote ./unmoor/unmoor local.txt user@server:remote.txt
bin/unmoor.sh pull --remote ./unmoor/unmoor user@server:remote.txt back.txt
```

## Data exactness and limits

“Exact” here means **byte-exact after Unmoor has admitted a byte from the local
PTY or stdin**. It does not mean reconstruction of a terminal emulator's
screen, and it cannot restore bytes that an application or terminal driver
discarded before Unmoor read them. Local escape sequences such as `~.` are
also deliberately consumed unless escaped.

| Data class | Default retained state | At the limit | Completion rule |
| --- | --- | --- | --- |
| Classic terminal stream | 256 MiB transmit backlog; 4 MiB receive-pending window per endpoint | stop reading and apply backpressure; do not evict admitted bytes | missing final confirmation is failure, not silent success |
| Channelised exact stream | 16 MiB transmit and 1 MiB receive-pending per stream; 256 MiB/64 MiB aggregate caps | stop that source until confirmed history can be pruned | same byte-exact stream rule |
| One-file push/pull | fixed chunk bitmap; complete source and destination scans | bounded transfer fails rather than installing a partial destination | whole-file root must verify before atomic installation |

Loss and reordering may delay convergence, but they do not authorize Unmoor to
drop already admitted exact-stream bytes. A full backlog can therefore block
the producing command while the receiver catches up.

[`HOWTO.md`](HOWTO.md) covers everything else: network prerequisites,
multipath, IPv6, attached terminals and transfers, diagnostics,
troubleshooting, limits, every public command and option, and the manual
pre-shared-key listener that exists for tests.

## Defaults that refuse

Two defaults will stop you rather than quietly degrade, which is intentional:

- **Post-quantum is required.** Bootstrap and every rekey combine fresh
  X25519 with ML-KEM-1024. A peer that cannot do that is refused by name.
  `--pq=prefer` permits one visible fallback; `--pq=off` disables PQ. Both are
  explicit choices you have to type.
- **Linux clients confine themselves.** Before accepting peer-controlled
  session work, a client applies `no_new_privs`, a Landlock path allow-list and
  a role-specific seccomp syscall allow-list. A channelised terminal retains
  only the supervised process operations required for attached transfers. If
  the kernel cannot supply the requested controls, the client refuses and
  names `--confine=best-effort` as the reduction you may accept on purpose.
  macOS has neither mechanism, so it warns and runs best-effort.

The terminal listener itself is **not** confined. Run it as the ordinary SSH
user it logs in as. Client confinement protects the client.

## What is in here

```
src/              the implementation: frames, crypto, session, channels,
                  terminal state sync, bulk transfer, transports
src/vendor/       Monocypher 4.0.3 and mlkem-native, their upstream sources
                  unmodified, plus the licenses, provenance notes and the
                  one ML-KEM build-config header this project adds
bin/              thin wrappers: build, the `unmoor.sh` entry point, client,
                  listener, source bundle
tools/            the SSH bootstrap helper and two standalone test programs
tests/            hygiene check and the end-to-end loopback smoke
```

## License

Apache-2.0 — see [`LICENSE`](LICENSE). Every non-vendor authored file in
`src/`, `bin/`, `tools/` and `tests/` carries an SPDX identifier and the
copyright line.

Vendored code keeps its own terms, and `LICENSE` names both. Monocypher 4.0.3
is BSD-2-Clause OR CC0-1.0; the complete text of both licences is in
[`src/vendor/monocypher-LICENCE.md`](src/vendor/monocypher-LICENCE.md), copied
byte-for-byte from the upstream tarball. mlkem-native is Apache-2.0 OR ISC OR
MIT and ships its own `LICENSE` and `RELICENSE.md` in place. The upstream
sources of both are unmodified; what this project adds beside them is the
ML-KEM build-config header
`unmoor_mlkem_config.h`, the vendoring notes, and
[`src/vendor/mlkem-native/UNMOOR_PROVENANCE.md`](src/vendor/mlkem-native/UNMOOR_PROVENANCE.md),
which records exactly which upstream files were taken and which were left out.

[`SOURCE.md`](SOURCE.md) records where this published tree came from and the
exact respects in which it differs from the tree it was published from.

Copyright (c) 2026 Nenad Micic.
