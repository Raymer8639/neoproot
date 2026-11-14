#!/usr/bin/env python3
"""Measure launch-to-guest-marker and launch-to-exit, emitting JSON Lines.

Commands are JSON argv arrays, never shell-evaluated. Put {marker} in the guest
command's printf argument; only an exact stdout line counts (CRLF accepted).
Python 3.8+, POSIX host; no third-party dependencies.
"""

import argparse
import json
import math
import os
import selectors
import signal
import subprocess
import time
import uuid


class MarkerLines:
    """Bounded exact-line matcher; reject marker text embedded in boot logs."""

    def __init__(self, marker):
        self.marker = marker.encode("utf-8")
        self.pending = bytearray()
        self.overflow = False

    def feed(self, data):
        found = False
        for part_index, part in enumerate(data.split(b"\n")):
            if part_index:
                if not self.overflow and bytes(self.pending) in (self.marker, self.marker + b"\r"):
                    found = True
                self.pending.clear()
                self.overflow = False
            if not self.overflow:
                self.pending.extend(part)
                if len(self.pending) > len(self.marker) + 1:
                    self.pending.clear()
                    self.overflow = True
        return found


def clean_environment():
    env = os.environ.copy()
    removed = []
    for key in list(env):
        if key in ("LD_PRELOAD", "LD_AUDIT") or key.startswith("NEOPROOT_STATSHIM_"):
            removed.append(key)
            del env[key]
    return env, sorted(removed)


def kill_group(proc):
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def measure(backend, command, marker, timeout, sample):
    argv = [arg.replace("{marker}", marker) for arg in command]
    env, removed = clean_environment()
    record = dict(backend=backend, sample=sample, argv=argv, marker=marker,
                  clock="time.monotonic_ns", marker_stream="stdout",
                  first_output_ms=None, total_ms=None, elapsed_ms=None, returncode=None,
                  signal=None, timed_out=False, error=None,
                  stdout_bytes=0, stderr_bytes=0, removed_env=removed)
    matcher = MarkerLines(marker)
    proc = None
    start = time.monotonic_ns()
    deadline = start + int(timeout * 1_000_000_000)
    try:
        with selectors.DefaultSelector() as selector:
            proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    env=env, start_new_session=True)
            for name, pipe in (("stdout", proc.stdout), ("stderr", proc.stderr)):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, name)
            while True:
                if proc.poll() is not None and record["total_ms"] is None:
                    record["total_ms"] = (time.monotonic_ns() - start) / 1_000_000
                if not selector.get_map() and proc.returncode is not None:
                    break
                remaining = (deadline - time.monotonic_ns()) / 1_000_000_000
                if remaining <= 0:
                    record["timed_out"] = True
                    kill_group(proc)
                    break
                for key, _ in selector.select(min(remaining, 0.05)):
                    data = os.read(key.fileobj.fileno(), 65536)
                    observed = time.monotonic_ns()
                    if not data:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    record[key.data + "_bytes"] += len(data)
                    if key.data == "stdout" and matcher.feed(data):
                        if record["first_output_ms"] is None:
                            record["first_output_ms"] = (observed - start) / 1_000_000
    except OSError as exc:
        record["error"] = str(exc)
    finally:
        if proc is not None:
            # Kill this sample's group even if the launcher already exited.
            # Descendants may keep pipes open or close them and linger.
            kill_group(proc)
            proc.wait()
            record["returncode"] = proc.returncode
            if proc.returncode < 0:
                record["signal"] = -proc.returncode
            if record["total_ms"] is None:
                record["total_ms"] = (time.monotonic_ns() - start) / 1_000_000
            for pipe in (proc.stdout, proc.stderr):
                pipe.close()
        record["elapsed_ms"] = (time.monotonic_ns() - start) / 1_000_000
    return record


def command_json(value):
    try:
        command = json.loads(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("command must be a JSON argv array") from exc
    if (not isinstance(command, list) or not command or
            any(not isinstance(arg, str) or "\0" in arg for arg in command) or
            not command[0] or not any("{marker}" in arg for arg in command)):
        raise argparse.ArgumentTypeError("expected nonempty JSON argv with a {marker} placeholder")
    return command


def positive_seconds(value):
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected finite positive seconds") from exc
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("expected finite positive seconds")
    return number


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fast-command", required=True, type=command_json)
    parser.add_argument("--um-command", required=True, type=command_json)
    parser.add_argument("--runs", type=int, default=5, help="samples per backend (default: 5)")
    parser.add_argument("--timeout", type=positive_seconds, default=30.0,
                        help="per-sample timeout in seconds (default: 30)")
    args = parser.parse_args()
    if args.runs <= 0:
        parser.error("--runs must be positive")
    failed = False
    # Alternate order to reduce systematic order bias; there is no hidden warmup.
    for sample in range(1, args.runs + 1):
        commands = [("fast", args.fast_command), ("um", args.um_command)]
        if sample % 2 == 0:
            commands.reverse()
        for backend, command in commands:
            marker = "NEOPROOT_BENCH_" + uuid.uuid4().hex
            record = measure(backend, command, marker, args.timeout, sample)
            print(json.dumps(record, ensure_ascii=True), flush=True)
            failed |= (record["timed_out"] or record["error"] is not None or
                       record["returncode"] != 0 or record["first_output_ms"] is None)
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
