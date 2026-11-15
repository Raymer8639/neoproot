#!/usr/bin/env python3
"""Short old/new regression experiment runner. POSIX Python 3.8+, no deps.

A "lane" is one Neoproot build. Each lane gets a JSON argv template; the
runner substitutes {workload}, {iterations}, {marker} and {data_dir} and
executes the argv directly (never through a shell). Both lanes run the same
guest probe, in the same sanitized environment, alternating ABBA/BAAB so that
drift and thermal effects hit both builds equally.

Output is JSON Lines on stdout: one row per sample, one summary per workload,
then one gate row. Nothing here knows about a specific device: every threshold
is a configurable ratio, never a wall-clock constant.

Exit codes: 0 report-only finished, or gate passed; 1 a sample failed
validation/timeout (always fatal); 3 gate inconclusive; 130 interrupted.
"""
import argparse
import hashlib
import json
import math
import os
import selectors
import signal
import statistics
import subprocess
import time
import uuid

# Default operation counts. They are deliberately small ("short gate") and can
# be overridden per workload with --iterations WORKLOAD=N.
WORKLOADS = {"startup": 1, "stat-absolute": 2000, "stat-relative": 2000,
             "l2s": 32, "fork-exec": 8}
for _category in ("connected", "translated"):
    for _method in ("sendto", "sendmsg", "sendmmsg"):
        WORKLOADS["unix-" + _category + "-" + _method] = 256

PLACEHOLDERS = ("{workload}", "{iterations}", "{marker}", "{data_dir}")
LANES = ("old", "new")
STDOUT_LIMIT = 1024 * 1024


class MarkerLines:
    """Exact complete-line matcher, robust to splits and to CRLF.

    A marker is only accepted as a whole line; text embedded in a boot log or
    in a launcher banner therefore never counts.
    """

    def __init__(self, marker):
        self.marker = marker.encode("utf-8")
        self.buffer = bytearray()

    def feed(self, data):
        found = False
        self.buffer.extend(data)
        while True:
            index = self.buffer.find(b"\n")
            if index < 0:
                break
            line = bytes(self.buffer[:index])
            del self.buffer[:index + 1]
            if line.endswith(b"\r"):
                line = line[:-1]
            if line == self.marker:
                found = True
        if len(self.buffer) > 4096:  # runaway line without a newline
            self.buffer.clear()
        return found


def emit(row):
    print(json.dumps(row, sort_keys=True, allow_nan=False), flush=True)


def positive_number(value):
    try:
        result = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected finite positive number") from exc
    if not math.isfinite(result) or result <= 0:
        raise argparse.ArgumentTypeError("expected finite positive number")
    return result


def nonnegative_number(value):
    try:
        result = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected finite non-negative number") from exc
    if not math.isfinite(result) or result < 0:
        raise argparse.ArgumentTypeError("expected finite non-negative number")
    return result


def command_json(text):
    try:
        argv = json.loads(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected JSON argv array") from exc
    if (not isinstance(argv, list) or not argv or not isinstance(argv[0], str) or not argv[0] or
            any(not isinstance(a, str) or "\0" in a for a in argv)):
        raise argparse.ArgumentTypeError("expected nonempty string argv without NUL")
    for token in PLACEHOLDERS:
        if not any(token in argument for argument in argv):
            raise argparse.ArgumentTypeError("command template is missing placeholder " + token)
    return argv


def environment(settings, base=None):
    """One sanitized snapshot, shared byte for byte by every lane and sample.

    LD_*, NEOPROOT_* and PROOT_* are dropped because they silently change what
    is being measured (a stat shim, a loader override, a different backend).
    Anything the experiment really needs is added back explicitly with --env,
    so it is visible in the experiment row.
    """
    source = os.environ if base is None else base
    env = {k: v for k, v in source.items()
           if not k.startswith(("LD_", "NEOPROOT_", "PROOT_"))}
    removed = sorted(set(source) - set(env))
    restored = []
    for setting in settings:
        key, separator, value = setting.partition("=")
        if (not separator or not key or "\0" in setting or "\0" in key or
                "=" in key or not key.strip()):
            raise ValueError("--env requires KEY=VALUE")
        if key in removed:
            restored.append(key)
        env[key] = value
    digest = hashlib.sha256(json.dumps(env, sort_keys=True).encode()).hexdigest()
    return env, removed, sorted(restored), digest


def expand(command, values):
    argv = []
    for argument in command:
        for key, value in values.items():
            argument = argument.replace("{" + key + "}", str(value))
        argv.append(argument)
    return argv


def kill_group(proc):
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def validate(stdout, marker, workload, iterations, returncode):
    """Return (probe_result, error). error is None only for a usable sample."""
    lines = stdout.split(b"\n")
    # A trailing fragment without LF is not a complete protocol line.
    lines = [line[:-1] if line.endswith(b"\r") else line for line in lines[:-1]]
    target = marker.encode("utf-8")
    if lines.count(target) != 1:
        return None, "expected exactly one complete marker line"
    candidates = []
    for line in lines[lines.index(target) + 1:]:
        try:
            item = json.loads(line)
        except (ValueError, UnicodeError):
            continue
        if isinstance(item, dict) and item.get("marker") == marker:
            candidates.append(item)
    if len(candidates) != 1:
        return None, "expected exactly one probe result for the marker"
    result = candidates[0]
    if (result.get("protocol") != 1 or result.get("workload") != workload or
            result.get("status") not in ("ok", "unsupported", "error")):
        return result, "probe protocol/workload/status mismatch"
    for key in ("operations", "checksum", "duration_ns", "errno"):
        if type(result.get(key)) is not int or result[key] < 0:
            return result, "invalid " + key
    if not isinstance(result.get("stage"), str) or not result["stage"]:
        return result, "invalid stage"
    if result["status"] == "unsupported":
        if (returncode != 77 or not workload.startswith("unix-") or
                result["stage"] != "destination-send" or result["errno"] == 0 or
                result["operations"] > iterations):
            return result, "invalid unsupported result"
        return result, None
    if result["status"] == "error":
        return result, "probe reported an error at stage " + result["stage"]
    if returncode != 0:
        return result, "probe exited nonzero for an ok result"
    unit = (64 if workload.startswith("unix-") else
            17 if workload.startswith("stat-") or workload == "l2s" else 1)
    if (result["operations"] != iterations or result["checksum"] != iterations * unit or
            result["errno"] != 0 or result["stage"] != "complete" or
            (workload != "startup" and result["duration_ns"] <= 0)):
        return result, "operation/checksum/result validation failed"
    return result, None


def measure(argv, env, marker, workload, iterations, timeout):
    """Run one sample in its own session; kill the whole group afterwards."""
    row = dict(type="sample", argv=argv, marker=marker, workload=workload,
               iterations=iterations, status="error", returncode=None, signal=None,
               timed_out=False, error=None, first_output_ms=None, launch_exit_ms=None,
               elapsed_ms=None, stdout_bytes=0, stderr_bytes=0, probe=None)
    start = time.monotonic_ns()
    deadline = start + int(timeout * 1e9)
    proc = None
    output = bytearray()
    stderr_tail = bytearray()
    matcher = MarkerLines(marker)
    try:
        with selectors.DefaultSelector() as selector:
            proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, env=env, start_new_session=True)
            for name, pipe in (("stdout", proc.stdout), ("stderr", proc.stderr)):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, name)
            while True:
                if proc.poll() is not None and row["launch_exit_ms"] is None:
                    row["launch_exit_ms"] = (time.monotonic_ns() - start) / 1e6
                if not selector.get_map() and proc.returncode is not None:
                    break
                remaining = (deadline - time.monotonic_ns()) / 1e9
                if remaining <= 0:
                    row["timed_out"] = True
                    row["error"] = "sample timeout"
                    break
                for key, _ in selector.select(min(remaining, 0.01)):
                    try:
                        data = os.read(key.fileobj.fileno(), 65536)
                    except BlockingIOError:
                        continue
                    observed = time.monotonic_ns()
                    if not data:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    row[key.data + "_bytes"] += len(data)
                    if key.data == "stderr":
                        stderr_tail.extend(data)
                        del stderr_tail[:-4096]
                        continue
                    if len(output) + len(data) > STDOUT_LIMIT:
                        row["error"] = "stdout exceeds 1 MiB protocol limit"
                        raise ValueError(row["error"])
                    output.extend(data)
                    if row["first_output_ms"] is None and matcher.feed(data):
                        row["first_output_ms"] = (observed - start) / 1e6
    except (OSError, ValueError) as exc:
        row["error"] = str(exc)
    finally:
        if proc is not None:
            # Kill the whole session even when the launcher itself exited:
            # a guest process could still hold the pipes open.
            kill_group(proc)
            proc.wait()
            row["returncode"] = proc.returncode
            if proc.returncode < 0:
                row["signal"] = -proc.returncode
            if row["launch_exit_ms"] is None:
                row["launch_exit_ms"] = (time.monotonic_ns() - start) / 1e6
            for pipe in (proc.stdout, proc.stderr):
                try:
                    pipe.close()
                except OSError:
                    pass
        row["elapsed_ms"] = (time.monotonic_ns() - start) / 1e6
    row["stderr_tail"] = stderr_tail.decode("utf-8", "replace")
    if row["error"] is None:
        result, error = validate(bytes(output), marker, workload, iterations, row["returncode"])
        row["probe"], row["error"] = result, error
        if error is None:
            row["status"] = result["status"]
    return row


def robust(values):
    if not values:
        return dict(count=0, median=None, mad=None, relative_mad=None)
    median = statistics.median(values)
    mad = statistics.median(abs(value - median) for value in values)
    return dict(count=len(values), median=median, mad=mad,
                relative_mad=mad / median if median > 0 else None)


def sample_value(row, workload):
    """startup: launcher-to-marker wall time here; others: guest loop time."""
    if workload == "startup":
        return row["first_output_ms"]
    return row["probe"]["duration_ns"] / 1e6


def summarize(rows, workload, blocks, min_blocks, min_samples,
              min_ratio, max_ratio, max_noise):
    metric = "first_output_ms" if workload == "startup" else "guest_duration_ms"
    lanes = {}
    for lane in LANES + ("native",):
        values = [sample_value(r, workload) for r in rows if r["lane"] == lane and r["status"] == "ok"]
        lanes[lane] = robust(values)

    pairs = []
    for block in range(blocks):
        subset = [r for r in rows if r["block"] == block and r["lane"] in LANES]
        old = [sample_value(r, workload) for r in subset if r["lane"] == "old" and r["status"] == "ok"]
        new = [sample_value(r, workload) for r in subset if r["lane"] == "new" and r["status"] == "ok"]
        if len(old) == len(new) == 2 and all(value > 0 for value in old + new):
            pairs.append(dict(block=block,
                              ratio=math.sqrt(new[0] * new[1] / (old[0] * old[1])),
                              old=old, new=new))
    ratios = robust([pair["ratio"] for pair in pairs])

    state, reason = "inconclusive", "insufficient paired samples"
    low = high = None
    errors = [r for r in rows if r["status"] == "error"]
    unsupported = [r for r in rows if r["status"] == "unsupported"]
    old_ok = lanes["old"]["count"]
    new_ok = lanes["new"]["count"]
    if errors:
        state, reason = "fail", "sample error/timeout/validation failure"
    elif unsupported:
        reason = "unsupported capability; a failed operation has no speed ratio"
    elif old_ok < min_samples or new_ok < min_samples:
        reason = "only %d/%d complete samples per lane, need %d" % (old_ok, new_ok, min_samples)
    elif len(pairs) < min_blocks:
        reason = "only %d paired blocks, need %d" % (len(pairs), min_blocks)
    else:
        # Descriptive band only: 3 scaled MADs of the paired ratios, divided by
        # sqrt(blocks) like a standard error, with a 1% floor so a lucky run of
        # identical blocks cannot claim sub-percent precision. Not a CI.
        spread = max(3 * 1.4826 * ratios["mad"] / math.sqrt(len(pairs)),
                     0.01 * ratios["median"])
        low, high = ratios["median"] - spread, ratios["median"] + spread
        noise = {"ratio": ratios["relative_mad"], "old": lanes["old"]["relative_mad"],
                 "new": lanes["new"]["relative_mad"]}
        noisy = [name for name, value in noise.items()
                 if value is None or value > max_noise]
        if noisy:
            reason = "excessive relative MAD for " + ", ".join(noisy)
        elif low > max_ratio:
            state, reason = "fail", "paired slowdown band starts above --max-ratio"
        elif high < min_ratio:
            state, reason = "fail", "paired speedup band ends below --min-ratio"
        elif high <= max_ratio:
            state, reason = "pass", "paired ratio band within the configured window"
        else:
            reason = "paired ratio band crosses --max-ratio"
    return dict(type="summary", workload=workload, metric=metric, lanes=lanes,
                paired_blocks=[dict(block=p["block"], ratio=p["ratio"]) for p in pairs],
                paired_ratio=ratios, ratio_band=[low, high],
                min_ratio=min_ratio, max_ratio=max_ratio,
                max_relative_mad=max_noise, min_blocks=min_blocks,
                min_samples=min_samples, status=state, reason=reason,
                unsupported=[dict(lane=r["lane"], block=r["block"], probe=r["probe"])
                             for r in unsupported])


def build_schedule(block, workloads, native):
    """ABBA on even blocks, BAAB on odd ones: order bias hits both lanes."""
    order = ("old", "new", "new", "old") if block % 2 == 0 else ("new", "old", "old", "new")
    schedule = []
    for workload in workloads:
        lanes = list(order)
        if native is not None and workload.startswith("unix-"):
            lanes.append("native")
        schedule.append((workload, lanes))
    return schedule


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--old-command", type=command_json,
                        help="JSON argv template for the baseline build")
    parser.add_argument("--new-command", type=command_json,
                        help="JSON argv template for the candidate build")
    parser.add_argument("--native-command", type=command_json,
                        help="optional untraced socket baseline, never part of the ratio")
    parser.add_argument("--old-bin", help="baseline binary (shorthand, needs --rootfs)")
    parser.add_argument("--new-bin", help="candidate binary (shorthand, needs --rootfs)")
    parser.add_argument("--rootfs", help="guest rootfs for the binary shorthand")
    parser.add_argument("--probe", required=True, help="absolute probe path inside the guest")
    parser.add_argument("--data-dir", required=True,
                        help="existing writable absolute directory inside the guest")
    parser.add_argument("--samples", type=int, default=8,
                        help="complete samples per lane per workload, multiple of 4 (default: 8)")
    parser.add_argument("--min-samples", type=int, default=8,
                        help="complete samples per lane required to decide (default: 8)")
    parser.add_argument("--min-blocks", type=int, default=4,
                        help="paired ABBA/BAAB blocks required to decide, even, "
                             "2..--samples/2 (default: 4)")
    parser.add_argument("--min-ratio", type=nonnegative_number, default=0.0,
                        help="lower sanity bound for new/old, 0 disables (default: 0)")
    parser.add_argument("--max-ratio", type=positive_number, default=1.25,
                        help="regression ceiling for new/old (default: 1.25)")
    parser.add_argument("--max-relative-mad", type=positive_number, default=0.35,
                        help="noise ceiling per lane, exceeded means inconclusive (default: 0.35)")
    parser.add_argument("--timeout", type=positive_number, default=8.0,
                        help="per-sample seconds (default: 8)")
    parser.add_argument("--budget", type=positive_number, default=300.0,
                        help="whole experiment seconds (default: 300)")
    parser.add_argument("--workloads", default=",".join(WORKLOADS))
    parser.add_argument("--iterations", action="append", default=[], metavar="WORKLOAD=N")
    parser.add_argument("--env", action="append", default=[], metavar="KEY=VALUE",
                        help="explicit setting added to the sanitized environment")
    parser.add_argument("--label", default="", help="device/rootfs/shim/version context, no secrets")
    parser.add_argument("--gate", action="store_true",
                        help="exit 3 on inconclusive, 1 on regression")
    args = parser.parse_args()

    if args.samples < 4 or args.samples % 4:
        parser.error("--samples must be a multiple of 4: an ABBA and a BAAB block "
                     "must appear equally often or the ratio carries order bias")
    if args.samples > 200:
        parser.error("--samples must be <= 200")
    if args.min_samples < 4 or args.min_samples > args.samples:
        parser.error("--min-samples must be 4..--samples")
    if args.min_blocks < 2 or args.min_blocks > args.samples // 2 or args.min_blocks % 2:
        parser.error("--min-blocks must be even and 2..--samples/2")
    if args.min_ratio and args.min_ratio >= args.max_ratio:
        parser.error("--min-ratio must be below --max-ratio")
    if not args.probe.startswith("/") or not args.data_dir.startswith("/"):
        parser.error("--probe and --data-dir must be absolute guest paths")

    counts = dict(WORKLOADS)
    workloads = args.workloads.split(",")
    if len(set(workloads)) != len(workloads) or any(w not in counts for w in workloads):
        parser.error("unknown or duplicate workload")
    for override in args.iterations:
        key, separator, value = override.partition("=")
        if not separator or key not in counts or not value.isdecimal() or not 1 <= int(value) <= 10000000:
            parser.error("--iterations requires known WORKLOAD=N (1..10000000)")
        counts[key] = int(value)

    commands = {}
    for lane in LANES:
        command = getattr(args, lane + "_command")
        binary = getattr(args, lane + "_bin")
        if command is not None and binary is not None:
            parser.error("choose a command template or a binary for " + lane)
        if command is None:
            if not binary or not args.rootfs:
                parser.error("provide both command templates, or binaries plus --rootfs")
            command = [binary, "--backend=fast", "--link2symlink", "-r", args.rootfs,
                       "-w", "/", "{probe}", "{workload}", "{iterations}", "{marker}", "{data_dir}"]
        commands[lane] = command

    try:
        env, removed, restored, digest = environment(args.env)
    except ValueError as exc:
        parser.error(str(exc))

    blocks = args.samples // 2
    emit(dict(type="experiment", protocol=1, clock="time.monotonic_ns", label=args.label,
              commands=commands, native_command=args.native_command, counts=counts,
              workloads=workloads, blocks=blocks, samples=args.samples,
              min_samples=args.min_samples, min_blocks=args.min_blocks,
              min_ratio=args.min_ratio, max_ratio=args.max_ratio,
              max_relative_mad=args.max_relative_mad, timeout=args.timeout,
              budget=args.budget, removed_env=removed, restored_env=restored,
              env_sha256=digest, env_overrides=list(args.env),
              note="no hidden warmup; the native lane is untraced and excluded from ratios"))

    started = time.monotonic()
    rows = {workload: [] for workload in workloads}
    budget_exhausted = False
    try:
        for block in range(blocks):
            for workload, lanes in build_schedule(block, workloads, args.native_command):
                for position, lane in enumerate(lanes):
                    remaining = args.budget - (time.monotonic() - started)
                    # Never start a sample the budget cannot host in full: a
                    # truncated sample is a timeout, and a timeout is an error,
                    # not a "the run was too short" result.
                    if remaining < args.timeout:
                        budget_exhausted = True
                        break
                    marker = "SHORT_" + uuid.uuid4().hex
                    command = args.native_command if lane == "native" else commands[lane]
                    argv = expand(command, dict(probe=args.probe, workload=workload,
                                                iterations=counts[workload], marker=marker,
                                                data_dir=args.data_dir))
                    row = measure(argv, env, marker, workload, counts[workload],
                                  min(args.timeout, remaining))
                    row.update(lane=lane, block=block, position=position,
                               order="ABBA" if block % 2 == 0 else "BAAB",
                               env_sha256=digest,
                               socket_category="native" if lane == "native" else
                               "translated" if "translated" in workload else
                               "connected" if "connected" in workload else None)
                    emit(row)
                    rows[workload].append(row)
                if budget_exhausted:
                    break
            if budget_exhausted:
                break
    except KeyboardInterrupt:
        emit(dict(type="interrupted", status="error"))
        return 130

    summaries = [summarize(rows[workload], workload, blocks, args.min_blocks,
                           args.min_samples, args.min_ratio, args.max_ratio,
                           args.max_relative_mad)
                 for workload in workloads]
    for summary in summaries:
        emit(summary)
    statuses = [summary["status"] for summary in summaries]
    status = ("fail" if "fail" in statuses else
              "inconclusive" if budget_exhausted or "inconclusive" in statuses else "pass")
    emit(dict(type="gate", status=status, budget_exhausted=budget_exhausted,
              elapsed_s=time.monotonic() - started, enforced=args.gate,
              workloads=len(workloads), samples_per_lane=args.samples))
    # A broken sample is fatal even in report-only mode: it is never "fast".
    if any(row["status"] == "error" for workload_rows in rows.values() for row in workload_rows):
        return 1
    if not args.gate:
        return 0
    return 1 if status == "fail" else 3 if status == "inconclusive" else 0


if __name__ == "__main__":
    raise SystemExit(main())
