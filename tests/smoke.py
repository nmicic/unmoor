#!/usr/bin/env python3
# Copyright (c) 2026 Nenad Micic
# SPDX-License-Identifier: Apache-2.0
"""One clean local production/PQ/UDP/PTY smoke. A single end-to-end path,
not a regression suite."""

import argparse
import hashlib
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time


class SmokeError(Exception):
    pass


class Cancelled(Exception):
    def __init__(self, signum):
        self.signum = signum


def require(condition, message):
    if not condition:
        raise SmokeError(message)


def group_exists(pgid):
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False


def cleanup_group(process):
    # Authority comes only from our Popen(start_new_session=True), independent
    # of whether its direct leader has already exited. No log-derived PIDs.
    for sig in (signal.SIGTERM, signal.SIGKILL):
        process.poll()
        if not group_exists(process.pid):
            return
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            return
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            process.poll()
            if not group_exists(process.pid):
                return
            time.sleep(0.05)
    require(not group_exists(process.pid), "owned process group did not disappear")


def read_result(process, result):
    # The caller owns the buffers so failures/cancellation preserve every byte
    # already read, not just output from a successfully completed process.
    deadline = time.monotonic() + 40
    with selectors.DefaultSelector() as selector:
        for label, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, label)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            require(remaining > 0, "smoke exceeded its 40-second bound")
            for key, _ in selector.select(min(remaining, 0.2)):
                data = os.read(key.fd, 8192)
                if data:
                    result[key.data].extend(data)
                    require(len(result[key.data]) <= 65536, "unexpected excessive output")
                else:
                    selector.unregister(key.fileobj)
        process.wait(timeout=max(0.1, deadline - time.monotonic()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confine", choices=("best-effort",),
                        help="explicit caller-selected continuation on an older Linux kernel")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    binary = root / "unmoor"
    launcher = root / "bin/client.sh"
    wrapper = root / "tools/unmoor-deaddrop-ssh"
    for path in (binary, launcher, wrapper, root / "tests/fixtures/ssh", root / "tests/fixtures/finite-shell"):
        require(path.is_file() and os.access(path, os.X_OK), f"missing executable: {path}; run make first")
    before = hashlib.sha256(binary.read_bytes()).hexdigest()
    work = Path(tempfile.mkdtemp(prefix="unmoor-smoke-")).resolve()
    (work / "deaddrop").mkdir(mode=0o700)
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(("UNMOOR_", "DYLD_"))
                   and key not in {"BASH_ENV", "ENV", "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP",
                                   "PYTHONINSPECT", "LD_PRELOAD", "LD_LIBRARY_PATH", "MINIMAL_SMOKE_DIR"}}
    # Preserve HOME. Only the fixture's explicit listener parent is used.
    environment.update(MINIMAL_SMOKE_DIR=str(work), UNMOOR_PACE_BPS="400000",
                       PATH=os.pathsep.join((str(root / "tests/fixtures"), str(Path(sys.executable).resolve().parent), os.defpath)))
    command = [str(launcher), "--remote", str(binary),
               "--udp-host", "127.0.0.1", "--remote-bind-host", "127.0.0.1",
               "--remote-foreground", "--timeout", "20"]
    if args.confine:
        command += ["--confine", args.confine]
    command.append("minimal-smoke.invalid")
    process = None
    result = {"stdout": bytearray(), "stderr": bytearray()}
    success = False
    handlers = {}

    def cancelled(signum, _frame):
        raise Cancelled(signum)

    for sig in (signal.SIGINT, signal.SIGTERM):
        handlers[sig] = signal.signal(sig, cancelled)
    try:
        process = subprocess.Popen(command, cwd=root, env=environment, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        read_result(process, result)
        require(process.returncode == 0, f"production wrapper exited {process.returncode}; native defaults were not weakened")
        # The real PTY may translate LF to CRLF. The unchanged sync client
        # adds one CRLF after its successful FIN ACK (src/sync.c). Check both
        # the marker and that exact close framing; discard no other output.
        require(result["stdout"].replace(b"\r\n", b"\n") == b"UNMOOR_MINIMAL_PTY_OK\n\n", "PTY marker/close framing was not exact")
        diagnostic = result["stderr"]
        require(diagnostic.count(b"verified public bootstrap ") == 1, "missing real public bootstrap confirmation")
        for role in (b"client", b"listener"):
            require(b"pq-hybrid rekey metrics role=" + role + b" epoch=1 " in diagnostic,
                    "missing real PQ epoch completion from both endpoints")
        require(b"channel_pty: shell exited (code=0)" in diagnostic,
                "finite PTY child did not report successful exit")
        require(re.search(rb"(?m)^unmoor: foreground listener child pid [1-9][0-9]* reaped status 0$", diagnostic),
                "foreground listener did not report successful reap")
        require((work / "ssh.calls").read_text().splitlines() == ["pq-probe", "listen"], "unexpected carrier invocations")
        require(not list((work / "deaddrop").iterdir()), "product left one-shot deaddrop state")
        require(not group_exists(process.pid), "foreground process group remained after successful close")
        require(hashlib.sha256(binary.read_bytes()).hexdigest() == before, "binary changed during smoke")
        success = True
    finally:
        for sig in handlers:
            signal.signal(sig, signal.SIG_IGN)
        try:
            try:
                if process is not None:
                    cleanup_group(process)
                    for stream in (process.stdin, process.stdout, process.stderr):
                        stream.close()
            except (SmokeError, OSError):
                success = False
                raise
            finally:
                if success:
                    shutil.rmtree(work)
                else:
                    (work / "diagnostics.txt").write_bytes(result["stderr"])
                    (work / "pty-output.txt").write_bytes(result["stdout"])
                    print(f"smoke: failed evidence retained at {work}", file=sys.stderr)
        finally:
            for sig, handler in handlers.items():
                signal.signal(sig, handler)
    print(f"smoke: PASS — client launcher, real PQ/public bootstrap, loopback UDP, exact PTY marker, clean close; sha256={before}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Cancelled as exc:
        raise SystemExit(128 + exc.signum)
    except (SmokeError, OSError, subprocess.TimeoutExpired) as exc:
        print(f"smoke: FAIL — {exc}", file=sys.stderr)
        raise SystemExit(1)
