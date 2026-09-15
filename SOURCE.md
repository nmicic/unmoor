<!-- Copyright (c) 2026 Nenad Micic -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Provenance

This repository is the published form of a private development tree. It is
the code, the tests that guard it, and the instructions for running it —
nothing else. The Git history starts here: no upstream history, no reviews,
no reports, no planning documents, no lab assets, no deployment
configuration and no credentials were imported.

That is a statement about what was copied, not a guarantee about what can be
inferred. Code carries the shape of the decisions behind it, and a careful
reader will reconstruct some of that reasoning from the comments, which is
fine — that is what the comments are for. What is not here is the material
itself: every tracked file was scanned before publication for credentials,
key material, host names, addresses, internal URLs and internal document
references, and what that scan found was removed or reworded.

This tree was cut from `unmoor 0.1.0 (protocol v1)` on 2026-09-15.

## What is in the tree

| Path | Contents |
| --- | --- |
| `src/*.c`, `src/*.h` | 132 files — the whole implementation |
| `src/vendor/` | 39 files — Monocypher 4.0.3 and mlkem-native, upstream sources unmodified, plus four files this project adds beside them: a build-config header, two vendoring notes and a license copy |
| `tools/` | the SSH bootstrap helper, and two standalone test programs |
| `bin/` | five short wrappers around `make` and the binary |
| `tests/` | the hygiene check, the loopback smoke, and its fixtures |
| `Makefile` | the whole build |
| `.github/` | one workflow: the same build and checks on Linux and macOS |

Every file outside `src/vendor/` carries `Copyright (c) 2026 Nenad Micic` and
`SPDX-License-Identifier: Apache-2.0` — the two exceptions being `LICENSE`
itself and `.gitignore`. The vendored trees keep their own license files in
place, and every upstream source file in them is byte-identical to what the
development tree builds against.

## How this differs from the tree it came from

Three kinds of change were applied on the way out. All three were measured
against the development tree rather than asserted; the method is in the next
section.

### 1. Comments

Internal work-tracking identifiers were replaced by the names of the things
they referred to, and citations of documents that do not ship were removed. A
comment that opened with an issue number and a colon now opens with the
sentence itself; one that cited a section of an internal specification now
names the layout it was pointing at; one that referred to a phase of the
development plan now describes the behaviour that phase produced. References
to helper programs, to commits and to review findings that this repository
does not carry were reworded to describe the thing rather than name something
a reader cannot open. Vocabulary inherited from a predecessor project — a
radio link, a firmware peer, a serial transport — was replaced with what the
code actually does now.

The technical content was kept in every case. What went away was the
bookkeeping, not the reasoning, and no comment was deleted to avoid saying
something inconvenient.

### 2. Text a person can read at runtime

These changes are visible in output but change no behaviour: the `--bootstrap`
help text and the usage block of `tools/unmoor-deaddrop-ssh`, two `fprintf`
diagnostics in `src/session.c`, one `_Static_assert` message, the two
`$(error)` messages and the `check` banner in the `Makefile`, and the
docstring of `tests/smoke.py`. Each dropped a pointer to something a reader of
this repository cannot open, or named an internal work item where the sentence
reads better naming the thing.

### 3. The code itself

Six source files differ in code, not only in comments. All six are listed here
in full.

**One temporary-file prefix, in `src/bulk.c`.** The temporary file a pull
writes before it installs carried an internal work-item number in its name.
It is now `.unmoor-bulk-`. The file exists on disk for the length of a
transfer and a user sees it, which is the reason to rename it; nothing reads
the name off the wire.

The four BLAKE2b domain-separation constants a few hundred lines above it were
deliberately left exactly as they are. Those strings feed the transfer hash
tree whose root travels in the MANIFEST, ACK and STATUS records: changing them
would make a build from this tree and a build from the development tree compute
different roots for the same file, so the two would negotiate protocol v1
successfully and then fail every transfer. No change in this repository is
wire-visible.

**One abstract-socket name, in `src/monitor_startup.c`.** The startup
rendezvous socket was named after an internal work item; it is now
`unmoor.startup.` — the same 15 bytes the code already copies. Two peers must
agree on it; both ends of any pair built from this tree do.

**Two internal command-line flags, in `src/child_transfer.c` and
`src/main.c`.** `--d42-child-result-fd` and `--d42-transfer-id` are now
`--child-result-fd` and `--child-transfer-id`. They are passed by the parent
process to a child it just spawned from the same binary, so the emitter and
the parser move together; they are not part of the documented CLI.

**Four dead conditional hooks removed from `src/main.c`.** Each was an
`#if defined(UNMOOR_BULK_REKEY_RUNTIME_TEST)` block calling a function that
does not exist in this tree. The macro was never defined here and defining it
would not have linked. Removing them took nothing out of the product; leaving
them in would have advertised a fixture that is not here.

**One behavioural fix, in `src/session.c`.** When choosing a leg for a bulk
send, the code took `bulk_paths.primary_leg` and shifted `1u` left by it
before testing the eligibility mask. `primary_leg` can be
`BULK_ENGINE_NO_LEG`, which is `UINT8_MAX`, and a shift by 255 is undefined
behaviour. The value is now range-checked against `path_limit` first; an
out-of-range leg was never eligible either way, so the intended outcome is
unchanged and only the undefined path is gone. This is the one place where
the published code is not merely a renaming of the development tree's, and it
is a fix rather than a divergence. It is named here for a specific reason: it
does not exist in the development tree, so none of that tree's own recorded
regression evidence covers it. What covers it is the two-machine gate reported
under "Verification run" below, run against this repository's source. That run
is new; no older result speaks for this line.

**Symbol names in `tools/frame_test.c`.** A test helper and its two return
codes were named after a firmware peer that no longer exists in this design;
they are now `pair_id_prefilter`, `PREFILTER_ACCEPT` and `PREFILTER_REJECT`.
This file is a standalone test program, not part of `./unmoor`.

**`tests/hygiene.sh` was generalized.** It used to grep the built binary for a
hardcoded list of known development symbol names. That list was itself a
disclosure — a reader could read off it what modules the private tree has —
and it could only ever catch what someone remembered to add. It now matches
*classes* of name (`test_`, `_test_`, `chaos`, `fixture`, `mock`, `harness`)
and classes of fixture string.

It is a different check, not a superset of the old one. Matching classes
catches scaffolding nobody remembered to enumerate, which a fixed list can
never do; in exchange, a name that matches no class is no longer named
individually. Two entries on the old list were exactly that, and both had
outlived it — neither name exists in this tree or in the development tree's
source, only in a stale object file left behind by an old build. What was
checked about the replacement: it does
not flag the genuine product function `bulk_bitmap_test` (a function that
tests a bit, not a test), it passes on `./unmoor` with zero matches on every
platform reported below, and it correctly fails when pointed at a test binary.

### What was deliberately left alone

Internal numbering survives in three places, on purpose:

- **C symbol names** — `d33_*`, `D21`, `D28` and similar appear in function,
  macro and field names throughout `src/`. Renaming them would have been a
  large mechanical change to code that is otherwise identical to a tested
  tree, for no reader benefit, and the risk is not zero.
- **Capability-bit macro names** — `UNMOOR_CAP_FRAGMENT_D21_V1`,
  `UNMOOR_CAP_BULK_FILE_D33_V1` and the rest. These are the names of wire
  features; renaming the macro without renaming the bit would make the code
  harder to follow, not easier.
- **Test-case labels in `tools/frame_test.c`** (`8-21
  d28_without_sync_dependency_rejected` and friends), printed by `make test`.
  They are named after those capability macros, so renaming the labels alone
  would create a mismatch with the code they test. No product user sees them.

What none of these leak is anything a reader could not already infer from the
code around them: they are names for features that are fully present here.
The operator-facing surface — flags, help text, diagnostics, file names,
socket names — is what was cleaned, because that is what a user reads.

## How that was verified

Each of the 134 non-vendor C source files here was compared with its
counterpart in the development tree under two normalizations: every comment
replaced by a single space, using a scanner that respects string and character
literals so a `/*` inside a string is not mistaken for a comment, and then
trailing whitespace stripped from each line.

Both normalizations matter, and the second is not cosmetic bookkeeping. Where
the scrub deleted a comment that sat at the end of a line of code, it took the
spaces in front of it too. Without the second normalization the comparison
reports files differing that differ in nothing but invisible bytes.

With both applied, **128 of the 134 files are identical to the development
tree**, and the six that differ are `src/bulk.c`, `src/child_transfer.c`,
`src/main.c`, `src/monitor_startup.c`, `src/session.c` and
`tools/frame_test.c` — differing in exactly the places listed above and
nowhere else. The diff was read line by line, not summarized by a count.

`src/vendor/` was compared directly. Every upstream source file is identical.
One file was added on the way out: `src/vendor/monocypher-LICENCE.md`, because
the vendoring note beside it referred to a license file that the development
tree did not actually carry. It is the complete, byte-identical `LICENCE.md`
from the pinned Monocypher 4.0.3 upstream archive, not a reconstructed extract
from one source-file header.

All 150 non-vendor source, script, documentation and build files — everything
except `LICENSE` and `.gitignore` — were checked for the copyright line and
the SPDX identifier; none were missing.

### What was written for this repository rather than copied

`README.md`, `HOWTO.md`, `SECURITY.md` and this file were written for a reader
who has only this tree. The development tree has files with three of those
names; they are internal documents, and none of their prose was carried over.
Checked rather than assumed: across the three, the only lines that appear
verbatim in both are the copyright comment, three Markdown headings and the
code-fence markers.

The `Makefile` (120 lines, against 1377 in the development tree), `.gitignore`,
the CI workflow, the five `bin/` wrappers, `tests/hygiene.sh`, `tests/smoke.py`
and its two fixtures were likewise written for this tree. `make bundle` and
the CI job that unpacks its output into an empty directory exist so that a
broken export fails a build here rather than being discovered by whoever
downloads it.

## Verification run

Everything below was run against the source in this repository, at the commit
being published — not against the development tree, and not against an earlier
draft of this one. Where a run used two machines, both built from the same
`make bundle` archive of this tree, and the run is reported with the digest
they agreed on.

### macOS — Darwin arm64, Apple clang 21.0.0 — 2026-09-15

- `make` from clean: zero warnings at `-Wall -Wextra -Wsign-compare -Wformat=2`.
- `make test`: 136 checks pass — 117 frame, reassembly and negotiation checks,
  and `pq_crypto_test: 19 PASS, 0 FAIL`.
- `make hygiene`: production symbol and fixture hygiene passes with zero
  matches, using the generalized patterns described above.
- `make shell-syntax`: passes.
- `make smoke`: passes — client launcher, real post-quantum public bootstrap,
  loopback UDP session, exact remote PTY output, clean owned shutdown. No host
  was contacted.

### Two hosts, real network — 2026-09-15

Two Ubuntu 24.04 machines, x86-64, GCC 13.3.0, kernels 6.8.0-124 and
6.8.0-136, at different places on the public internet. Each unpacked the same
bundle and built it.

- `make` from clean: zero warnings, on both. The binary links PIE with full
  RELRO and `BIND_NOW`, a non-executable stack, stack-clash protection and CET.
- Both builds produced the *identical* binary,
  `b0af1b81c41f4a5e712f08b51a1e293dc04727721ac0c5e22ef2d33be8289dff`.
- `make check`: passes on both — frame checks, the ML-KEM tests, symbol
  hygiene, shell syntax. `make smoke` passes on both and reports that digest.
- One machine then opened a session against the other over the documented
  `bin/client.sh` path: real OpenSSH carrier, real UDP across the public
  internet, remote PTY, no fixtures. Six checks, none failed — the public
  bootstrap verified once, both endpoints completed post-quantum epoch 1, a
  terminal command round-tripped byte-exactly, and the foreground listener was
  reaped with status 0.

That digest is the SHA-256 of the binary the run just built, which `make smoke`
re-checks afterwards to prove the binary did not change underneath the session.
Two machines agreeing on it is a real data point — same source, same compiler
version, same flags, same build path. It is not a reproducible-build claim, so
**a digest that differs from someone else's is not evidence of anything
wrong**: `-g` records the compilation directory, so the same bundle built at a
different path differs, and on macOS the Mach-O debug map additionally stores
each object file's path and modification time (`nm -pa ./unmoor | grep OSO`),
with a further 49 bytes moving per build in the `LC_UUID` field and the ad-hoc
code signature over it. Nothing in the source embeds a date, a git revision or
a build identifier.

### Impaired paths — two machines across a routed hop — 2026-09-15

The two-machine matrix over a routed, impaired path is this project's mandatory
public-release gate. What follows is that gate run with the source in this
repository as the product under test.

Two Ubuntu 24.04 KVM guests (Linux 6.8.0-138, GCC 13.3.0) sit on separate
bridges — `10.77.9.2/24` and `10.77.10.2/24`, `fd00:77:9::2` and
`fd00:77:10::2` — and share no link. Every datagram between them crosses a
routed network namespace on a third host (Linux 6.8.0-124), and that is where
the impairment is applied, per direction, with `tc` from iproute2-6.1.0.
Management SSH runs on a separate interface, so black-holing the test path
cannot also take away the ability to observe it.

Both guests were synced from this repository's source and gated before
anything ran: identical evidence-input stamp
`69f5054938c7dd1cef8925a79acf3818a52116124dc5bbc3ae05f567e92b1153`, identical
built binary
`423a1a73297e74e910e0e298182800132076727a9f226d8cb71336a80f3dfa00`, and zero
test or fixture symbols in either. The sessions are the documented
`bin/client.sh` path: real OpenSSH carrier, real UDP, real remote PTY.

| Impairment applied at the router | Checks |
| --- | --- |
| clean IPv4 — `delay 1ms` both directions | 46 |
| clean IPv6 — `delay 1ms` both directions | 52 |
| asymmetric delay — A→B `delay 120ms`, B→A `delay 20ms` | 48 |
| shallow reorder — B→A `delay 100ms reorder 100% gap 5` | 81 |
| deep reorder — B→A `delay 2500ms reorder 100% gap 300` | 81 |
| NAT rebind — the router's SNAT port moved under the live session | 117 |
| PMTU black hole — a 200-byte-MTU hop that discards silently | 267 |
| stale return mapping — client source moved, return flows dropped | 30 |
| bulk transfer — a bounded 100%-corruption interval, then asymmetric delay | 31 |
| monitored listener — a bounded 100%-loss blackout, then `gap 5` reorder | 28 |

781 checks, no failures, and one recorded characterization — in the
stale-return-mapping row, described below. Five rows are worth reading in
detail: three for what the session holds together under, and two for what it
does when the network does not come back.

**Deep reorder.** Before the session runs, a calibration probe measures what
the path actually does rather than what it was asked to do: 1200 datagrams
sent, 1200 received, none lost, none duplicated, 1196 reorder events, and a
maximum late displacement of 804 — a datagram arriving 804 positions after the
one it was sent behind. `REPLAY_WINDOW` is 256 (`src/session.h`), so the path
demonstrably moved packets further out of order than the window can absorb,
and the router's own qdisc counters confirm it carried all 1203 datagrams and
dropped none. The terminal session then ran over that same path and printed
4500 numbered lines. 4500 arrived. None was duplicated, none was missing, and
there were zero inversions — over a transport that, by the kernel's own
accounting, reordered 4234 packets on the production leg.

**NAT rebind.** The router's SNAT mapping for the live session is moved from
one port to another underneath it. Afterwards both ends are still the same
processes with the same start times, the same UDP socket inodes and the same
local ports; the listener recorded exactly two authenticated return-path
adoptions across the whole run — the initial one, and the rebound tuple once —
and each endpoint entered the established state exactly once. The session
survived the rebind rather than re-establishing across it.

**PMTU black hole.** This row characterizes a failure, not a success. A hop
with a 200-byte MTU that discards oversized datagrams without sending ICMP
will break the session, and it does. What the scenario pins is *how*: the
listener exits non-zero and names its undelivered byte count, the client exits
non-zero and names the incomplete remote output, the END barrier is never
falsely delivered, no authentication or replay diagnostic is produced, and
every process and UDP socket on both sides is gone afterwards. Unmoor fails
loudly on a dark path; it does not truncate silently and claim success.

**Stale return mapping.** This is the recorded characterization, and it is the
one in `SECURITY.md` under stale return-path mappings. The client is stopped,
its effective IPv6 source is moved from `fd00:77:9::2` to `fd00:77:9::10`, both
return ports are black-holed at the router, and the client is resumed. Input
still executes at the far end — the router counted 68 and 63 authenticated
datagrams arriving from the changed source — while 1406 return datagrams were
discarded. The client reports `STALLED`, truthfully, and no black-holed output
is ever shown as delivered. What it does **not** do is open a replacement
source port and recover: that is the pinned characterization, `current terminal
opened no replacement source port`, and it is a documented limitation rather
than a bug that slipped through. A freshly started session over the new source
works, and both ends exit 0.

**Bulk transfer under corruption.** In the middle of a live 4 MiB push, the
router is switched to `netem corrupt 100%` in both directions for a bounded
interval — every packet crossing it gets a bit flipped. 596 A→B and 310 B→A
datagrams went through while that was true. The push stayed active, the
endpoint processes did not change, and **the destination file stayed absent
for the whole corrupted interval**: no partial file is ever visible. After the
corruption was released the push exited 0 and installed byte-exact data,
verified by SHA-256 against the source. A pull under asymmetric directional
delay likewise installed byte-exact data, and both transfers ran across four
legs from both endpoints with no fatal protocol path on either.

**Total-loss blackout.** Where the PMTU row is a path that never recovers,
this one is a path that does. The router drops everything for a finite
interval in the middle of a live terminal session — five authenticated client
datagrams were dropped during it — and the terminal command that was lost is
executed after the blackout ends rather than being lost with it. The link is
then switched to deterministic `gap 5` reordering and a 32 KiB payload is sent
through it: all 32768 bytes arrived, and a byte-for-byte scan of the received
buffer found nothing but the expected value. Ctrl-C returned control to the
remote shell, and both the client and its driver exited 0 with no fatal
diagnostic on either side.

### Random loss — 100 sessions across the same routed hop — 2026-09-15

The same two guests, same binary, same source stamp. Each row applies uniform
random loss in both directions at the router and runs 20 full sessions,
bootstrap through post-quantum epoch-1 rekey to clean close.

| Loss, both directions | PQ | Completed | Fatal | Timeout | Median rekey | p95 rekey |
| --- | --- | --- | --- | --- | --- | --- |
| 1% | require | 20/20 | 0 | 0 | 2 ms | 502 ms |
| 2% | require | 20/20 | 0 | 0 | 1 ms | 2 ms |
| 5% | require | 20/20 | 0 | 0 | 2 ms | 502 ms |
| 10% | require | 19/20 | 0 | 0 | 1 ms | 1502 ms |
| 5% | off | 20/20 | 0 | 0 | — | — |

No attempt in any row ended in a protocol-fatal close or a timeout. The single
non-completion, at 10% loss, is counted as a failure because the harness
counted it as one: that session completed its rekey, opened its PTY, printed
its marker and closed with status 0, but a diagnostic line was interleaved
into the marker line in the capture, so the row's exact-line oracle did not
match it.

The rekey columns are the epoch-1 post-quantum rekey, which is why the
`--pq=off` row has none to report. The 502 ms and 1502 ms tails are not
computation — `PQ_REKEY_RETRY_MS` is 500 (`src/pq_rekey.h`), so those are one
and three retransmission timers firing while a lost rekey fragment waits. The
median stays at 1–2 ms at every loss level. Across the 1% row the endpoints
retransmitted 368 fragments in total, and across the 10% row, 352.

### Scope

The lab harness that drives the two-machine rows is not in this repository —
it is several thousand lines of automation for building guests, placing qdiscs
and reading kernel counters, and it is not part of the product. What is here
is the source both guests built and the binary they ran. The single-host
checks (`make check`, `make smoke`) reproduce from this tree directly.

Not exercised by these runs: static-musl linking, and IPv6 roaming across real
interface changes. `tests/smoke.py` passes `--confine best-effort` and never
`--confine=require`, which is the Linux default. There has been no external
security audit.

`.github/workflows/ci.yml` is configured to run the build, `make check` and
`make smoke` on Linux with GCC and with Clang and on macOS with Clang, and then
repeat all three from the `make bundle` archive unpacked into an empty
directory. Everything reported above was run by hand.

Copyright (c) 2026 Nenad Micic.
