<!-- Copyright (c) 2026 Nenad Micic -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Operating Unmoor

Everything here assumes an ordinary user account on both machines. Unmoor
never needs root, never installs a service, and never edits your SSH
configuration, firewall, routing or NAT. If a UDP path does not exist between
the two hosts, Unmoor will tell you so; opening it is your network's business,
not this program's.

Contents:

1. [Build it on both machines](#1-build-it-on-both-machines)
2. [Start a session](#2-start-a-session)
3. [Naming the two destinations](#3-naming-the-two-destinations)
4. [Paths](#4-paths)
5. [Moving one file](#5-moving-one-file)
6. [Several things over one session](#6-several-things-over-one-session)
7. [Security defaults, and reducing them on purpose](#7-security-defaults-and-reducing-them-on-purpose)
8. [The manual pre-shared-key listener](#8-the-manual-pre-shared-key-listener)
9. [Checks, diagnostics and limits](#9-checks-diagnostics-and-limits)
10. [Troubleshooting](#10-troubleshooting)
11. [Command and option reference](#11-command-and-option-reference)

## 1. Build it on both machines

To build you need a C11 compiler, GNU Make, and — only for `make smoke` —
Python 3. On Linux you also need the usual libc development headers. There is
nothing to download: every library Unmoor links is vendored in `src/vendor/`.

To actually run a session you also need Bash and an OpenSSH client on the
machine you start from. `tools/unmoor-deaddrop-ssh` supports the Bash 3.2
shipped with macOS; the short `bin/*.sh` launchers are POSIX shell. `ssh` is
the carrier that authenticates the bootstrap. The server side needs an SSH
daemon you can log in to and a copy of `unmoor` you built there. The binary
itself links only libc, plus `libutil` on Linux for the PTY.

```sh
make -j2
make check
bin/unmoor.sh version
bin/unmoor.sh --help
```

Objects land in `.build/<system>-<architecture>/`. Run `make clean` before
changing compiler or flags. **Do not copy a built binary between machines** —
not macOS to Linux, not arm64 to x86_64. Copy the source and build it there.

To carry the source to the server, make an archive from a clean checkout:

```sh
archive=$(make -s bundle)         # captures the exact archive pathname
scp "$archive" user@server:unmoor-source.tar.gz
ssh user@server 'mkdir unmoor-new && tar -xzf unmoor-source.tar.gz \
    -C unmoor-new --strip-components=1 && cd unmoor-new && make -j2 && make check'
```

The archive holds committed source and scripts only — no `.git`, no binaries,
no logs, no keys — and builds without Git present. Extract it somewhere that
does not already contain an `unmoor/` directory; do not unpack it over
somebody else's checkout.

On Linux, `make unmoor-static` optionally produces a self-contained binary
using `musl-gcc` with static-PIE support. There is no fixed-address fallback:
if your musl toolchain cannot do static-PIE, the build fails rather than
producing something weaker.

## 2. Start a session

```sh
UNMOOR_PACE_BPS=400000 bin/client.sh --remote ./unmoor/unmoor user@server
```

That is the whole normal workflow. `bin/client.sh` uses your existing SSH
keys, agent and host-key checking to authenticate a public-record exchange,
and starts a one-shot listener on an ephemeral UDP port on the far side. From
there the terminal runs over UDP. An address or path change does not destroy
the cryptographic session, but recovery still requires a later usable
bidirectional UDP path. Unmoor does not open a firewall, punch a NAT or relay
traffic.

`--remote` is the **path to the server's `unmoor` executable**, not a shell
command. The example above assumes you extracted the bundle into the remote
user's home directory. Give an absolute path if it lives elsewhere. Do not put
shell syntax, quoting tricks or `~` into that value.

Locally, `bin/client.sh` always runs the `unmoor` next to this checkout, never
one that happens to be on your `PATH`. Add `--local PATH` when you deliberately
want to test a different local binary.

`UNMOOR_PACE_BPS` is a read pacer in bytes per second. It limits how fast
Unmoor reads from the local source, so a burst never exceeds what the
bottleneck queue can absorb. Set it to something near your real uplink. Zero
turns it off.

The client must be able to send UDP to the ephemeral port printed by the
remote listener, and replies must be able to return. SSH reachability by
itself is not enough. On a cloud host, permit the selected UDP port in both the
host firewall and the provider firewall. The recommended bootstrap currently
chooses that port dynamically; use the diagnostics in section 10 to
distinguish an SSH/bootstrap failure from a blocked UDP path.

Once you are in:

| Keys | Effect |
| --- | --- |
| Enter, then `~.` | disconnect locally |
| Enter, then `~~` | send one literal tilde at line start |
| `Ctrl-] s` | print local sync status |
| `Ctrl-] Ctrl-]` | send one literal `Ctrl-]` |
| Ctrl+C | goes to the remote terminal, as you would expect |

SSH carries only public exchange records and fingerprints. On this path,
private scalars and every derived key stay inside the two C processes: never
in a shell variable, never in argv, never in a file, never in a log. The
manual pre-shared-key modes are different by construction — `UNMOOR_KEY`
carries a symmetric key through the environment, and `listen --bootstrap`
prints a freshly generated one on stdout for a caller to relay. Neither is the
recommended path; both are described in
[§8, the manual pre-shared-key listener](#8-the-manual-pre-shared-key-listener).

The default public bootstrap combines fresh X25519 and ML-KEM-1024 material.
Before any terminal or file channel opens, the endpoints complete and confirm
a fresh authenticated rekey over UDP. Later rekeys use fresh material and wipe
retired keys, but this version does not yet promise routine time- or byte-based
rotation; automatic rotation is reserved for the sequence-exhaustion boundary.

## 3. Naming the two destinations

An SSH destination and a UDP destination are two different things, and they
are allowed to differ. When your SSH alias is not a name DNS can resolve, say
where the UDP flow should go:

```sh
bin/client.sh --remote ./unmoor/unmoor --udp-host server.example.net my-alias
```

For IPv6, give `--udp-host` a real reachable IPv6 address and, if you want the
remote listener bound explicitly to IPv6, add `--remote-bind-host ::`. With no
explicit bind host the listener opens native IPv4 and `IPV6_V6ONLY` IPv6 on
the same port, and fails loudly if either family is unavailable — it will not
half-start. An IPv4-only host can select `--remote-bind-host 0.0.0.0`.

Clients resolve and use one native family. Unmoor does not race A against AAAA
records.

## 4. Paths

A session can use several authenticated UDP paths at once. The `enterprise`
profile is the default and offers two optional terminal paths and four for
bulk transfer; `lab` uses a single path unless you ask for more.

```sh
# Pin a test to exactly one path:
bin/client.sh --profile lab --remote ./unmoor/unmoor user@server

# Or ask for an exact count (2, 4, 8, 16 or 32):
bin/client.sh --profile lab --multipath=4 --remote ./unmoor/unmoor user@server
```

Both peers must agree on the count; there is no downgrade. These are separate
authenticated source-port legs — they are not a promise that your network,
your NIC or your provider will actually route them differently.

Roaming is a property of the UDP transport, not of multipath. The listener
adopts the source address of any frame that both passes authentication and
advances the replay high-water mark. A replayed capture is in-window but
never advances that mark, so it cannot redirect your return traffic.

## 5. Moving one file

Push and pull use the same public bootstrap and need no interactive session
first:

```sh
UNMOOR_PACE_BPS=400000 bin/unmoor.sh push --remote ./unmoor/unmoor \
    sample.txt user@server:received.txt
UNMOOR_PACE_BPS=400000 bin/unmoor.sh pull --remote ./unmoor/unmoor \
    user@server:received.txt returned.txt
cmp sample.txt returned.txt
```

Remote paths are relative to the remote user's working directory. A
destination becomes visible only after the whole transfer has been verified,
and an existing destination is refused unless you pass `--force`. There is no
directory recursion, no durable resume across restarts, and no promise to
reproduce file metadata.

Useful knobs: `--bulk-stall-secs 240` raises the no-progress deadline from its
30-second default, which is what you want on a roaming or ECMP path;
`--port-layout block|cube|random` selects how client source ports are laid
out; `--bulk-mtu BYTES` sets the UDP payload budget.

## 6. Several things over one session

One session can carry a terminal and supervised transfers at the same time.
Open it with a local control socket in a directory only you can read:

```sh
umask 077
mkdir -p private/attach
chmod 700 private/attach
bin/client.sh --channelised \
    --attach-socket "$PWD/private/attach/control.sock" \
    --remote ./unmoor/unmoor user@server
```

Then, from other local terminals in this checkout:

```sh
bin/unmoor.sh attach --socket "$PWD/private/attach/control.sock" terminal
bin/unmoor.sh attach --socket "$PWD/private/attach/control.sock" \
    push -- sample.txt received.txt
bin/unmoor.sh attach --socket "$PWD/private/attach/control.sock" \
    pull -- received.txt returned.txt
bin/unmoor.sh attach --socket "$PWD/private/attach/control.sock" \
    exec -- /usr/bin/uptime
```

The socket's parent directory must be owned by you and mode 0700. Note that
`mkdir -p` does not change the mode of a directory that already exists —
check it. One push and one pull may be in flight at once, each in its own
transfer session. `exec` runs an exact argv with no shell between you and it.

On Linux, local file operands must sit inside the controlling client's working
directory or inside a `--confine-root` you chose when opening the session.
That is the confinement working as intended, not a bug.

## 7. Security defaults, and reducing them on purpose

Two defaults refuse rather than degrade. Both reductions exist, both are one
explicit flag, and neither happens behind your back.

**Post-quantum.** `--pq=require` is the default for the bootstrap and for
every rekey: fresh X25519 combined with ML-KEM-1024. A peer that cannot do
that is identified and refused before an exchange is attempted. `--pq=prefer`
permits exactly one visible fallback to such a peer. `--pq=off` asks for the
legacy profile. Once both sides have selected the hybrid suite, a session
cannot fall back mid-flight.

This is a bounded protocol property that has been tested inside this project,
not an external audit. Sessions using a pre-shared key, explicit `off`, or an
actual `prefer` fallback are not post-quantum, whatever the default says.

**Client confinement.** Before accepting peer-controlled session work, a
Linux client narrows itself with `no_new_privs`, a Landlock path allow-list and
a role-specific seccomp syscall allow-list. A channelised terminal retains the
supervised process operations required to launch attached transfers. If the
kernel cannot supply the requested mechanisms the client refuses and names
`--confine=best-effort` as the reduction you may accept deliberately; that
prints a warning, and no wrapper in this repository ever chooses it for you.
macOS has neither mechanism, so it defaults to a warned best-effort.
`--confine=require` on macOS makes it refuse instead; `--confine=off` disables
the control silently.

**What is not confined.** The terminal listener. Run it as the ordinary SSH
user it logs in as, and do not treat it as a hardened multi-user service.
Client confinement protects the client, not the server. One-shot bulk servers
can separately be asked for `--server-confine=require` on a supporting Linux
host; that policy applies after the authenticated file request, not to the
listener that was waiting before it.

Do not write a key to a file, a repository, your shell history, a test
fixture, or a log. Do not enable cores or process debugging to get past a
refusal — `--debuggable` exists, prints a warning, and is not propagated to
anything Unmoor execs.

## 8. The manual pre-shared-key listener

`bin/listener.sh` is a thin front end to `unmoor listen`, kept for existing
manually provisioned tests. Both endpoints must already hold the same
ephemeral `UNMOOR_KEY` in memory:

```sh
# Listener machine:
bin/listener.sh --transport udp --host 0.0.0.0 --port 9000 --profile lab
# Client machine:
bin/unmoor.sh connect --transport udp --host server.example.net \
    --port 9000 --profile lab
```

Neither command creates or exchanges a key. This is **not** the recommended
path: a pre-shared key is not post-quantum forward secret, and making the
example work by pasting a key somewhere is exactly the mistake section 2
exists to avoid. `unmoor` does scrub `UNMOOR_KEY` from its own environment the
moment it has parsed it, but that does not make the key's journey to both
machines safe.

Besides UDP there are two other transports, both useful mainly for testing:
`--transport unix` speaks over a socket path, and `--transport stdio` speaks
over any pipe, including a command's own pipes via `--exec`. Roaming is a UDP
property; the other two do not have it.

## 9. Checks, diagnostics and limits

`make check` runs the frame, reassembly, negotiation and ML-KEM unit tests,
a shell-syntax pass, and a hygiene check that asserts the production binary
exports no test-only symbols. `make smoke` additionally runs a real
post-quantum bootstrap, a UDP session and a finite remote PTY over loopback
using a local SSH fixture — it contacts no server and needs no SSH key. Its
client side is a pipe, so it is a liveness test, not a loss or roaming matrix.

On a Linux kernel without the confinement mechanisms, the smoke deliberately
fails at the same refusal a real client would hit. Run
`python3 tests/smoke.py --confine best-effort` only if you have decided to
accept that reduction.

Inside a real session, finite commands like `ps -ef`, `w`, or `top` then `q`
are the useful first tests. For throughput, prefer something that does not
spray terminal control bytes:

```sh
head -c 65535 /dev/urandom | openssl base64
printf '\nPASS\n'
```

An endless `cat /dev/zero` followed by Ctrl+C exercises backpressure and
interrupt responsiveness; start with short runs.

### Byte-exactness boundary

For a terminal stream, “exact” begins when Unmoor admits a byte from the local
PTY or stdin. Every admitted byte is retained until acknowledged and delivered
once, in order. This is not a promise to recreate a terminal emulator's screen,
and it cannot restore bytes that an application or terminal driver discarded
before Unmoor read them. The local `~.` and status-query escape sequences are
also deliberately consumed unless escaped.

| Mode | Transmit backlog | Receive-pending window | Behaviour at the limit |
| --- | ---: | ---: | --- |
| Classic terminal | 256 MiB per endpoint | 4 MiB per endpoint | source reads pause; admitted old bytes are not evicted |
| Channelised exact stream | 16 MiB per stream, 256 MiB aggregate | 1 MiB per stream, 64 MiB aggregate | only the blocked source pauses until confirmed history can be pruned |

These are Unmoor's own defaults, on top of application, PTY and kernel buffers;
they are not host-wide memory limits. `UNMOOR_SYNC_BACKLOG_BYTES` and
`UNMOOR_SYNC_PENDING_BYTES` change the endpoint you launch; do not assume an
environment variable crosses SSH to the other endpoint. At 400000 B/s,
draining a full classic 256 MiB backlog takes at least about eleven minutes.
An out-of-order record that cannot yet fit the pending window is repaired from
the sender's retained history; it is not declared delivered.

Final stream shutdown waits for the complete frontier for a bounded linger.
If final delivery cannot be confirmed, Unmoor reports failure rather than
claiming silent success. One-file push/pull has a separate exactness rule: the
receiver verifies the complete file root and only then atomically installs the
destination. It does not expose an incomplete destination as success.

Keep diagnostics off the terminal by redirecting stderr before launch:

```sh
umask 077
mkdir -p logs
bin/client.sh --remote ./unmoor/unmoor user@server 2>logs/session.log
```

Watch that file from a second terminal, especially when setup fails — errors
go there too. `--log-format json` *adds* a bounded structured event stream; it
does not replace the human-readable diagnostics, so the two are interleaved on
the same stderr and a parser has to skip the non-JSON lines. `Ctrl-] s`
queries the live session. `SIGUSR1` sent to the **exact PID
of the client you started** requests one bounded read-only snapshot on stderr,
at most 64 per session. Never use `killall`, `pkill`, or a name-matched PID
list: other sessions may be live on the same machine.

`unmoor rss-plan` predicts how a receive-side scaling key would distribute a
given path layout across queues. It is an offline calculator: it writes
nothing to any NIC and contacts nothing.

Two things worth knowing about what the status output means. `STALLED` says
authenticated contact is currently absent — it does not say the peer is dead.
Established terminal sessions currently have no automatic no-contact expiry;
a stalled listener can remain alive until it is closed by an operator or by
normal session teardown. Stale return-path mappings after a long standby
remain a known limitation, described in [`SECURITY.md`](SECURITY.md).

Finally: `make check` and `make smoke` are the checks that run from this tree
on a single host. Multi-host roaming, impaired paths and loss matrices are
covered by the two-machine gate reported in [`SOURCE.md`](SOURCE.md), which
needs a lab rather than one machine.

## 10. Troubleshooting

Keep client diagnostics in a separate file while diagnosing a session:

```sh
umask 077
mkdir -p logs
bin/client.sh --remote ./unmoor/unmoor user@server 2>logs/session.log
```

The first successful session should print a verified public-bootstrap
fingerprint, complete the authenticated epoch-1 rekey, enter `ESTABLISHED`,
receive `PTY_OPEN_ACK`, and present a remote prompt. Run `hostname`, then
`printf 'UNMOOR_OK\n'`, and leave with Enter then `~.`.

| Symptom | Likely boundary | What to check |
| --- | --- | --- |
| SSH fails before a bootstrap fingerprint | SSH destination, authentication, or remote executable | Run ordinary `ssh user@server`; verify the exact `--remote` path and that it was built for the remote OS/CPU. |
| Listener starts, then the client becomes `STALLED` | UDP cannot travel in one or both directions | Check host and provider firewalls, NAT policy, the printed UDP port, `--udp-host`, and address family. Unmoor does not create a route or relay. |
| SSH alias works but UDP name resolution does not | SSH and UDP destinations differ | Supply `--udp-host` with the address reachable by UDP. |
| IPv4-only or IPv6-only host refuses during listener setup | The default listener requires both native families | Select `--remote-bind-host 0.0.0.0` or `--remote-bind-host ::` deliberately. |
| `PQ required but peer lacks...` | Peers do not share the required hybrid suite | Install the same current source on both ends. Only if you accept the reduction, use `--pq=prefer` or `--pq=off`. |
| Linux client refuses confinement | Landlock or seccomp is unavailable/incomplete | Use a supporting kernel, or explicitly accept `--confine=best-effort`. Do not add the flag merely to suppress a message. |
| Attach socket is refused | Parent ownership/mode or socket path is wrong | Use an absolute path; make the parent owned by you and mode 0700. |
| A command stops producing output while backlog is high | Exact-stream backpressure | Query with `Ctrl-] s`; wait for the confirmed frontier to catch up or interrupt the remote producer. Do not interpret slow draining as dropped admitted data. |
| Session remains `STALLED` after a long outage | No authenticated return traffic reaches the client | The session does not expire automatically. Exit locally with Enter then `~.` and inspect both endpoint logs. |
| File destination already exists | Atomic install refuses replacement | Verify the target, then repeat with `--force` only when replacement is intended. |

### Manually terminate one known detached listener

On a Linux server where you know this user has exactly one detached Unmoor
listener, the following is safer than a `ps | grep | kill` pipeline. `PPID 1`
is normal for a detached listener and does **not** prove that it is stale; this
procedure is an explicit operator decision to terminate the one candidate.

```sh
set -eu

candidates=$(
    ps -u "$(id -u)" -o pid=,ppid=,comm= |
    awk '$2 == 1 && ($3 == "unmoor" || $3 ~ /^unmoor-/) { print $1 }'
)

# Intentional word splitting: candidates contains decimal PIDs only.
set -- $candidates
if [ "$#" -ne 1 ]; then
    echo "refusing: expected exactly one detached Unmoor process; found $#" >&2
    ps -u "$(id -u)" -o user=,pid=,ppid=,etime=,stat=,comm= >&2
    exit 1
fi

pid=$1
ps -p "$pid" -o user=,pid=,ppid=,etime=,stat=,args=
printf 'Type the PID above to send TERM: '
IFS= read -r answer
[ "$answer" = "$pid" ] || { echo 'cancelled' >&2; exit 1; }

# Re-check the Linux process identity immediately before signalling it.
uid=$(awk '$1 == "Uid:" { print $2 }' "/proc/$pid/status")
ppid=$(awk '$1 == "PPid:" { print $2 }' "/proc/$pid/status")
exe=$(readlink "/proc/$pid/exe")
name=${exe##*/}
[ "$uid" = "$(id -u)" ] && [ "$ppid" = 1 ] || {
    echo 'refusing: process ownership or parent changed' >&2
    exit 1
}
case $name in
    unmoor|unmoor-*) ;;
    *) echo 'refusing: executable is no longer Unmoor' >&2; exit 1 ;;
esac
if ! tr '\0' '\n' <"/proc/$pid/cmdline" |
    awk '$0 == "listen" { listen = 1 }
         $0 == "--deaddrop-bootstrap" { bootstrap = 1 }
         END { exit !(listen && bootstrap) }'
then
    echo 'refusing: process is not a public-bootstrap listener' >&2
    exit 1
fi

kill -TERM -- "$pid"
echo "TERM sent to PID $pid; re-run the listing to verify that it exited"
```

Do not replace the exact-count check with “take the first match”, do not run
this as root, and do not add an automatic `KILL`. If more than one session may
exist, inspect and terminate an exact PID individually.

## 11. Command and option reference

This section documents the public command surface without requiring a build.
`unmoor --help` prints the current combined runtime summary. This experimental
version does not yet provide a separate successful `--help` page for every
subcommand.

### Commands

```text
unmoor keygen [--debuggable]
unmoor listen [transport and session options]
unmoor listen --deaddrop-bootstrap [public-listener options]
unmoor connect [transport and session options]
unmoor ssh-connect [options] -- [ssh-options...] TARGET
unmoor push [options] LOCAL TARGET:PATH
unmoor pull [options] TARGET:PATH LOCAL
unmoor attach [confinement options] --socket PATH terminal
unmoor attach [confinement options] --socket PATH exec -- ARGV...
unmoor attach [confinement options] --socket PATH push [bulk options] -- LOCAL REMOTE
unmoor attach [confinement options] --socket PATH pull [bulk options] -- REMOTE LOCAL
unmoor rss-plan --rss-key HEX --queues N --paths N [options]
unmoor version
```

- `keygen` prints a fresh 32-byte manual-session key as 64 hexadecimal
  characters. It is for the pre-shared-key path in section 8, not the
  recommended public bootstrap.
- `listen` and `connect` are the direct transport endpoints. UDP roams; Unix
  sockets and stdio are test-oriented and do not.
- `ssh-connect` is the binary-level form of `bin/client.sh`. SSH options and
  the final destination begin only after `--`.
- `push` and `pull` move one regular file through their own public bootstrap.
- `attach` opens work through a live channelised control session. `exec` sends
  an exact argv and never inserts a shell. Attached push and pull use separate
  supervised transfer sessions.
- `rss-plan` is an offline IPv4 Toeplitz/RSS model. It observes and changes no
  NIC configuration.

### Transport and session options

| Option | Meaning and default |
| --- | --- |
| `--transport udp|unix|stdio` | Direct `listen`/`connect` transport; otherwise inferred from host, socket, or exec options. |
| `--host HOST`, `--port PORT` | UDP peer or listener bind. Listener port 0 is ephemeral. An omitted bind host requires native IPv4 and `IPV6_V6ONLY` IPv6 on one shared port. |
| `--socket PATH` | Unix transport path, or the local channelised attach socket where the command syntax says so. |
| `--exec "command arguments"` | Stdio transport child. This transport-oriented form is separate from no-shell channelised `attach ... exec -- ARGV...`. |
| `--profile enterprise|lab` | `enterprise` is default. It offers optional terminal-two/bulk-four paths; `lab` stays single-path unless multipath is requested. |
| `--multipath[=N]` | Require an authenticated pool. N is a power of two from 2 to 32, but under the default `enterprise` profile the only accepted N is the profile count itself (2 for a terminal, 4 for a transfer) — any other value is refused. Use `--profile lab` to choose N yourself. Bare form always takes the profile count: enterprise 2/4 by data class, lab 8. |
| `--log-format text|json` | `json` *adds* structured records to stderr alongside the ordinary text diagnostics; it does not replace them. JSON records are bounded and may be dropped if the diagnostic sink remains blocked; data-plane progress is not blocked for logging. |
| `--channelised` | Require multi-channel terminal support with no downgrade. |
| `--attach-socket PATH` | Create the local same-user channelised control socket. Requires `--channelised`. |
| `--bootstrap` | Direct listener: print a newly generated symmetric key and detach. This key-carrying legacy bootstrap is not the recommended public-record exchange. |
| `--loop` | Direct listener: start another association after one ends. It is not used by the recommended one-shot public bootstrap. |
| `--debuggable` | Permit core dumps and same-user debugger attachment; prints a warning and is not propagated to executed children. Unless confinement was explicitly selected, it also selects confinement off. |

### Public SSH bootstrap options

These apply to `ssh-connect`; most also apply to `push` and `pull`. The
recommended `bin/client.sh` accepts the corresponding bootstrap-helper forms.

| Option | Meaning and default |
| --- | --- |
| `--pq off|prefer|require` | Hybrid policy; default `require`. `prefer` permits one visible legacy fallback; `off` explicitly selects legacy. |
| `--udp-host HOST` | UDP destination when it differs from the SSH destination's host part. |
| `--remote-bind-host HOST` | Exact address family/address for the remote UDP listener. |
| `--remote PATH` | Remote `unmoor` executable; default `unmoor`. It is an executable path, not a shell fragment. |
| `--timeout SECS` | One absolute public-bootstrap-through-epoch-1 deadline, 1–3600 seconds; default 60. It is not an established-session lifetime. |
| `--remote-foreground` | Keep SSH as the owned foreground lifecycle carrier; primarily useful for tests and supervised invocation. |
| `-- [ssh-options...] TARGET` | Exact boundary before OpenSSH options such as `-J jump-host` and the final destination. |
| `--deaddrop-bootstrap` | Remote listener mode for the one-shot public exchange; normally constructed by the wrapper rather than typed directly. |
| `--deaddrop-parent DIR` | Mode-0700 parent for one-shot public exchange records. |
| `--bind-host HOST` | Direct deaddrop-listener bind address. The wrapper-facing spelling is `--remote-bind-host`. |
| `--bootstrap-foreground` | Remote listener waits for its owned listener child; normally managed by the wrapper. |
| `--listener-monitor` | Experimental Linux x86-64/aarch64 classic-terminal isolation boundary. An explicit unsupported request fails; it never silently falls back. |

For `bin/client.sh`, `--local PATH` deliberately selects another local binary;
the normal default is the `unmoor` beside the checkout. The helper accepts the
public-bootstrap, profile, logging, PQ, multipath, channelised, attach,
confinement, server-confinement and port-layout options printed by
`tools/unmoor-deaddrop-ssh --help`. It does **not** currently expose
`--listener-monitor` or `--debuggable`; use the binary's direct `ssh-connect`
form for those. Unrecognized helper arguments are interpreted as SSH options,
which is why spelling and the final destination boundary matter.

### Client and one-shot server confinement

| Option | Meaning |
| --- | --- |
| `--confine off|best-effort|require` | Confinement for this client. Linux defaults to `require`; non-Linux defaults to a warned `best-effort`. |
| `--confine-root PATH` | Add a local read/write data root, repeatable at most eight times. The terminal client's starting working directory is always a root. |
| `--server-confine off|best-effort|require` | Explicit confinement for a one-shot remote bulk server after its authenticated path is known. Omission keeps that server unconfined. For later attached transfers it requires the channelised control-session options. |

The ordinary terminal listener is not covered by these client or one-shot
bulk controls.

### Bulk and source-port options

| Option | Meaning and bounds |
| --- | --- |
| `--bulk-mtu BYTES` | Complete UDP payload budget, 768–8952; default 1200. |
| `--bulk-stall-secs SECS` | No-progress deadline, 1–300; default 30. A value such as 240 may be more suitable for deliberately roaming or heterogeneous paths. |
| `--port-layout block|cube|random` | Layout of client source ports. NAT may rewrite the result. |
| `--port-mask 0xNNNN` | Cube layout only; range `0x0001..0x3fff`, with popcount equal to `log2(path-count)`. On `connect`, layout/mask configure future attached transfer children, not the terminal legs. |
| `--force` | Atomically replace an existing destination after complete verification. |

Only one regular file is transferred. There is no recursion, restart-resume,
or metadata-preservation contract. The chunk bitmap contains at most `2^24`
entries. The MTU-selected chunk size therefore bounds files to 8–128 GiB;
the default 1200-byte budget uses 1024-byte chunks and permits at most 16 GiB.
The sender scans the source before sending and the receiver scans the completed
temporary file before installation. A nonzero pacer must be at least twice the
wire budget (2400 B/s at the default MTU).

### RSS planner options

| Option | Meaning |
| --- | --- |
| `--rss-key HEX` | Toeplitz key, 16–64 bytes. |
| `--queues N` | Power-of-two queue count, 1–1024. |
| `--paths N` | 2, 4, 8, 16, or 32 modeled source ports. |
| `--reta N` | Cyclic redirection-table size; default 512, maximum 4096, power of two and at least the queue count. |
| `--direction c2s|s2c|both` | Tuple direction to model. |
| `--port-mask 0xNNNN --base-port P` | Generate cube ports from a base. |
| `--ports P0,P1,...` | Model an explicit port list instead. |
| `--src-ip A --dst-ip B --server-port P` | IPv4 tuple to model. The planner does not read a live NIC's key or RETA. |

### Environment variables

| Variable | Scope and default |
| --- | --- |
| `UNMOOR_KEY` | Exactly 64 hex characters for direct pre-shared-key listen/connect. It is scrubbed after parsing and rejected by the recommended public bootstrap. |
| `UNMOOR_PACE_BPS` | Token-bucket source-read pace in bytes/second; 0 or unset disables it. The wrapper forwards a valid value to the remote listener. |
| `UNMOOR_SYNC` | Direct classic sessions only: `0` permits the legacy lossy PTY path. The recommended public bootstrap rejects that reduction. |
| `UNMOOR_SYNC_BACKLOG_BYTES` | Transmit history. Classic default/min/max: 256 MiB/256 KiB/4 GiB. Channelised per-stream default/max: 16 MiB/64 MiB. |
| `UNMOOR_SYNC_PENDING_BYTES` | Receive reorder storage. Classic default/min/max: 4 MiB/64 KiB/1 GiB. Channelised per-stream default/max: 1 MiB/4 MiB. |
| `UNMOOR_SYNC_LINGER_MS` | Final exact-stream acknowledgement wait; default 10000 ms. |
| `UNMOOR_BOOTSTRAP_LOG` | Direct legacy `listen --bootstrap` stderr log after detach. |
| `UNMOOR_BOOTSTRAP_TIMEOUT_SECS` | Direct legacy `listen --bootstrap` first-client accept window; default 60 seconds. It is not the public bootstrap `--timeout` or an established-session lifetime. |
