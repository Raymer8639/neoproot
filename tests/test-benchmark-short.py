#!/usr/bin/env python3
"""Host-only tests for tools/benchmark-short.py.

No Neoproot, no device, no root: a tiny fake probe speaks protocol v1 on
stdout, so every runner path (marker uniqueness, JSON uniqueness, CRLF,
chunked writes, timeouts, exit codes, statistics, argument and environment
validation) is exercised on the host.
"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUNNER = os.path.join(ROOT, "tools", "benchmark-short.py")


def load_runner():
    spec = importlib.util.spec_from_file_location("benchmark_short", RUNNER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bs = load_runner()

FAKE_PROBE = textwrap.dedent(r'''
    import json, os, subprocess, sys, time

    workload, iterations, marker, data_dir = sys.argv[1:5]
    mode = sys.argv[5] if len(sys.argv) > 5 else "ok"
    iterations = int(iterations)
    unit = 64 if workload.startswith("unix-") else 17 if workload.startswith("stat-") or workload == "l2s" else 1
    out = sys.stdout

    def emit(status="ok", operations=None, checksum=None, duration_ns=1000000, errno=0, stage="complete"):
        payload = dict(protocol=1, marker=marker, workload=workload, status=status,
                       operations=iterations if operations is None else operations,
                       checksum=iterations * unit if checksum is None else checksum,
                       duration_ns=duration_ns, errno=errno, stage=stage)
        out.write(json.dumps(payload) + "\n")
        out.flush()

    def header():
        out.write(marker + "\n")
        out.flush()

    duration = int(mode.split(":", 1)[1]) if ":" in mode else 1000000
    if mode.startswith("ok"):
        header()
        emit(duration_ns=duration)
        sys.exit(0)
    if mode == "dup_marker":
        out.write(marker + "\n" + marker + "\n")
        out.flush()
        emit()
        sys.exit(0)
    if mode == "dup_json":
        header()
        emit()
        emit()
        sys.exit(0)
    if mode == "no_json":
        header()
        sys.exit(0)
    if mode == "no_marker":
        emit()
        sys.exit(0)
    if mode == "json_first":
        emit()
        header()
        sys.exit(0)
    if mode == "crlf":
        out.write(marker + "\r\n")
        out.flush()
        out.write(json.dumps(dict(protocol=1, marker=marker, workload=workload, status="ok",
                                  operations=iterations, checksum=iterations * unit,
                                  duration_ns=duration, errno=0,
                                  stage="complete")) + "\r\n")
        out.flush()
        sys.exit(0)
    if mode == "chunked":
        out.write(marker[:4])
        out.flush()
        time.sleep(0.15)
        out.write(marker[4:] + "\n")
        out.flush()
        time.sleep(0.15)
        emit(duration_ns=duration)
        sys.exit(0)
    if mode == "partial":
        out.write(marker + "\n" + '{"protocol":1,"marker":"' + marker + '"')
        out.flush()
        sys.exit(0)
    if mode == "unsupported":
        header()
        emit(status="unsupported", operations=0, checksum=0, errno=30, stage="destination-send")
        sys.exit(77)
    if mode == "unsupported_wrong_exit":
        header()
        emit(status="unsupported", operations=0, checksum=0, errno=30, stage="destination-send")
        sys.exit(1)
    if mode == "error":
        header()
        emit(status="error", operations=0, checksum=0, errno=2, stage="stat")
        sys.exit(1)
    if mode == "error_exit_zero":
        header()
        emit(status="error", operations=0, checksum=0, errno=2, stage="stat")
        sys.exit(0)
    if mode == "badcount":
        header()
        emit(operations=iterations - 1)
        sys.exit(0)
    if mode == "badchecksum":
        header()
        emit(checksum=iterations * unit + 1)
        sys.exit(0)
    if mode == "slow":
        beat = sys.argv[6]
        child = subprocess.Popen([sys.executable, "-c",
            "import sys,time\n"
            "beat = sys.argv[1]\n"
            "while True:\n"
            "    open(beat,'a').write('x')\n"
            "    time.sleep(0.02)\n", beat])
        open(sys.argv[7], "w").write(str(child.pid))
        header()
        time.sleep(60)
        sys.exit(0)
    sys.stderr.write("unknown fake mode " + mode + "\n")
    sys.exit(9)
''')


def sample_row(lane, block, milliseconds, status="ok", workload="stat-absolute"):
    return dict(type="sample", lane=lane, block=block, status=status,
                first_output_ms=milliseconds,
                probe=dict(duration_ns=int(milliseconds * 1000000)))


class Probe(object):
    """A fake probe written to a temporary directory."""

    def __init__(self, directory):
        self.path = os.path.join(directory, "fake_probe.py")
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write(FAKE_PROBE)
        self.directory = directory

    def command(self, mode="ok", workload="stat-absolute", extra=()):
        argv = [sys.executable, self.path, "{workload}", "{iterations}",
                "{marker}", "{data_dir}", mode]
        argv.extend(extra)
        return argv


class ValidationTests(unittest.TestCase):
    marker = "SHORT_" + "a" * 32

    def body(self, **overrides):
        payload = dict(protocol=1, marker=self.marker, workload="stat-absolute",
                       status="ok", operations=10, checksum=170, duration_ns=5000,
                       errno=0, stage="complete")
        payload.update(overrides)
        return (self.marker + "\n" + json.dumps(payload) + "\n").encode()

    def validate(self, stdout, returncode=0, iterations=10, workload="stat-absolute"):
        return bs.validate(stdout, self.marker, workload, iterations, returncode)

    def test_ok(self):
        result, error = self.validate(self.body())
        self.assertIsNone(error)
        self.assertEqual(result["operations"], 10)

    def test_crlf_is_accepted(self):
        stdout = self.body().replace(b"\n", b"\r\n")
        result, error = self.validate(stdout)
        self.assertIsNone(error, error)

    def test_trailing_partial_line_is_not_a_result(self):
        # The JSON never got its newline: the sample must not be usable.
        stdout = self.body()
        _, error = self.validate(stdout[:stdout.rindex(b"\n")])
        self.assertEqual(error, "expected exactly one probe result for the marker")

    def test_missing_marker(self):
        stdout = self.body().split(b"\n", 1)[1]
        _, error = self.validate(stdout)
        self.assertIn("marker", error)

    def test_duplicate_marker(self):
        stdout = self.marker.encode() + b"\n" + self.body()
        _, error = self.validate(stdout)
        self.assertIn("marker", error)

    def test_marker_embedded_in_text_is_not_a_marker(self):
        # A launcher banner that merely contains the marker text must not count.
        stdout = b"log " + self.marker.encode() + b"\n" + self.body().split(b"\n", 1)[1]
        _, error = self.validate(stdout)
        self.assertEqual(error, "expected exactly one complete marker line")

    def test_missing_json(self):
        _, error = self.validate((self.marker + "\n").encode())
        self.assertIn("result", error)

    def test_duplicate_json(self):
        stdout = self.body() + json.dumps(json.loads(self.body().split(b"\n")[1])).encode() + b"\n"
        _, error = self.validate(stdout)
        self.assertIn("result", error)

    def test_json_before_marker_is_ignored(self):
        payload = json.dumps(dict(protocol=1, marker=self.marker, workload="stat-absolute",
                                  status="ok", operations=10, checksum=170, duration_ns=5000,
                                  errno=0, stage="complete")).encode()
        stdout = payload + b"\n" + self.marker.encode() + b"\n"
        _, error = self.validate(stdout)
        self.assertIn("result", error)

    def test_wrong_workload(self):
        _, error = self.validate(self.body(workload="stat-relative"))
        self.assertIn("mismatch", error)

    def test_wrong_protocol(self):
        _, error = self.validate(self.body(protocol=2))
        self.assertIn("mismatch", error)

    def test_negative_number(self):
        _, error = self.validate(self.body(operations=-1))
        self.assertEqual(error, "invalid operations")

    def test_bool_is_not_an_integer(self):
        _, error = self.validate(self.body(checksum=True))
        self.assertEqual(error, "invalid checksum")

    def test_operation_mismatch(self):
        _, error = self.validate(self.body(operations=9))
        self.assertIn("validation failed", error)

    def test_checksum_mismatch(self):
        _, error = self.validate(self.body(checksum=169))
        self.assertIn("validation failed", error)

    def test_ok_with_nonzero_exit(self):
        _, error = self.validate(self.body(), returncode=1)
        self.assertIn("nonzero", error)

    def test_error_status_is_an_error_even_with_exit_zero(self):
        _, error = self.validate(self.body(status="error", operations=0, checksum=0,
                                           errno=2, stage="stat"), returncode=0)
        self.assertIn("stage stat", error)

    def test_unsupported_requires_77(self):
        body = self.body(status="unsupported", operations=0, checksum=0, errno=30,
                         stage="destination-send")
        _, error = self.validate(body.replace(b"stat-absolute", b"unix-translated-sendto"),
                                 returncode=77, workload="unix-translated-sendto")
        self.assertIsNone(error)
        _, error = self.validate(body.replace(b"stat-absolute", b"unix-translated-sendto"),
                                 returncode=1, workload="unix-translated-sendto")
        self.assertEqual(error, "invalid unsupported result")

    def test_unsupported_requires_socket_workload_and_send_stage(self):
        body = self.body(status="unsupported", operations=0, checksum=0, errno=30,
                         stage="destination-send")
        _, error = self.validate(body, returncode=77)
        self.assertEqual(error, "invalid unsupported result")
        body = self.body(status="unsupported", operations=0, checksum=0, errno=30, stage="bind")
        _, error = self.validate(body.replace(b"stat-absolute", b"unix-connected-sendto"),
                                 returncode=77, workload="unix-connected-sendto")
        self.assertEqual(error, "invalid unsupported result")

    def test_startup_allows_zero_duration(self):
        body = self.body(workload="startup", operations=1, checksum=1, duration_ns=0)
        _, error = self.validate(body, iterations=1, workload="startup")
        self.assertIsNone(error, error)


class MeasureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.probe = Probe(self.tmp.name)
        self.env = {"PATH": "/usr/bin:/bin"}

    def measure(self, mode, timeout=5.0, extra=(), workload="stat-absolute", marker=None):
        marker = marker or ("SHORT_" + os.urandom(16).hex())
        argv = [a.replace("{workload}", workload).replace("{iterations}", "10")
                 .replace("{marker}", marker).replace("{data_dir}", "/tmp")
                for a in self.probe.command(mode, extra=extra)]
        return bs.measure(argv, self.env, marker, workload, 10, timeout)

    def test_ok_sample(self):
        row = self.measure("ok")
        self.assertEqual(row["status"], "ok")
        self.assertEqual(row["returncode"], 0)
        self.assertIsNone(row["error"])
        self.assertIsNotNone(row["first_output_ms"])

    def test_chunked_marker_is_still_one_line(self):
        row = self.measure("chunked")
        self.assertEqual(row["status"], "ok", row["error"])
        self.assertIsNotNone(row["first_output_ms"])

    def test_crlf_sample(self):
        row = self.measure("crlf")
        self.assertEqual(row["status"], "ok", row["error"])

    def test_duplicate_marker_is_an_error(self):
        row = self.measure("dup_marker")
        self.assertEqual(row["status"], "error")
        self.assertIn("marker", row["error"])

    def test_duplicate_json_is_an_error(self):
        row = self.measure("dup_json")
        self.assertEqual(row["status"], "error")
        self.assertIn("result", row["error"])

    def test_missing_json_is_an_error(self):
        row = self.measure("no_json")
        self.assertEqual(row["status"], "error")

    def test_partial_json_is_an_error(self):
        row = self.measure("partial")
        self.assertEqual(row["status"], "error")

    def test_probe_error_status(self):
        row = self.measure("error")
        self.assertEqual(row["status"], "error")
        self.assertEqual(row["returncode"], 1)
        self.assertEqual(row["probe"]["stage"], "stat")

    def test_unsupported_sample(self):
        row = self.measure("unsupported", workload="unix-translated-sendto")
        self.assertEqual(row["status"], "unsupported", row["error"])
        self.assertEqual(row["returncode"], 77)

    def test_unsupported_with_wrong_exit_is_an_error(self):
        row = self.measure("unsupported_wrong_exit", workload="unix-translated-sendto")
        self.assertEqual(row["status"], "error")

    def test_bad_counts_are_rejected(self):
        self.assertEqual(self.measure("badcount")["status"], "error")
        self.assertEqual(self.measure("badchecksum")["status"], "error")

    def test_missing_binary_is_a_sample_error(self):
        marker = "SHORT_" + os.urandom(16).hex()
        row = bs.measure(["/nonexistent/probe"], self.env, marker, "stat-absolute", 1, 5.0)
        self.assertEqual(row["status"], "error")
        self.assertIsNotNone(row["error"])

    def test_timeout_reclaims_the_whole_process_group(self):
        beat = os.path.join(self.tmp.name, "beat")
        pidfile = os.path.join(self.tmp.name, "pid")
        started = time.monotonic()
        row = self.measure("slow", timeout=0.6, extra=(beat, pidfile))
        elapsed = time.monotonic() - started
        self.assertTrue(row["timed_out"])
        self.assertEqual(row["error"], "sample timeout")
        self.assertLess(elapsed, 10.0, "measure() must not wait for the sample")
        with open(pidfile, encoding="utf-8") as handle:
            grandchild = int(handle.read().strip())
        # The grandchild keeps appending to a heartbeat file; after the timeout
        # it must have stopped, otherwise the process group was not reclaimed.
        size = os.path.getsize(beat)
        time.sleep(0.4)
        self.assertEqual(os.path.getsize(beat), size,
                         "a descendant kept running after the timeout")
        state = None
        try:
            with open("/proc/%d/stat" % grandchild, encoding="utf-8") as handle:
                state = handle.read().rsplit(") ", 1)[1][0]
        except OSError:
            pass  # already reaped
        self.assertIn(state, (None, "Z", "X"), "descendant is still running")


class SummarizeTests(unittest.TestCase):
    def summarize(self, rows, **kwargs):
        options = dict(blocks=2, min_blocks=2, min_samples=4, min_ratio=0.0,
                       max_ratio=1.25, max_noise=0.35)
        options.update(kwargs)
        return bs.summarize(rows, "stat-absolute", options["blocks"], options["min_blocks"],
                            options["min_samples"], options["min_ratio"],
                            options["max_ratio"], options["max_noise"])

    @staticmethod
    def block(index, old, new):
        rows = []
        for value in old:
            rows.append(sample_row("old", index, value))
        for value in new:
            rows.append(sample_row("new", index, value))
        return rows

    def test_ratio_is_the_paired_geometric_mean(self):
        rows = self.block(0, [100, 100], [120, 120]) + self.block(1, [100, 100], [80, 80])
        summary = self.summarize(rows)
        self.assertAlmostEqual(summary["paired_blocks"][0]["ratio"], 1.2)
        self.assertAlmostEqual(summary["paired_blocks"][1]["ratio"], 0.8)
        self.assertAlmostEqual(summary["paired_ratio"]["median"], 1.0)

    def test_pass_within_the_window(self):
        rows = self.block(0, [100, 100], [120, 120]) + self.block(1, [100, 100], [120, 120])
        summary = self.summarize(rows)
        self.assertEqual(summary["status"], "pass", summary["reason"])
        self.assertLessEqual(summary["ratio_band"][1], 1.25)

    def test_regression_fails(self):
        rows = self.block(0, [100, 100], [250, 250]) + self.block(1, [100, 100], [250, 250])
        summary = self.summarize(rows)
        self.assertEqual(summary["status"], "fail")
        self.assertIn("max-ratio", summary["reason"])

    def test_implausible_speedup_fails_only_when_min_ratio_is_set(self):
        rows = self.block(0, [100, 100], [10, 10]) + self.block(1, [100, 100], [10, 10])
        self.assertEqual(self.summarize(rows)["status"], "pass")
        self.assertEqual(self.summarize(rows, min_ratio=0.5)["status"], "fail")

    def test_too_few_samples_is_inconclusive(self):
        rows = self.block(0, [100, 100], [100]) + self.block(1, [100], [100])
        summary = self.summarize(rows)
        self.assertEqual(summary["status"], "inconclusive")
        self.assertIn("complete samples", summary["reason"])

    def test_too_few_blocks_is_inconclusive(self):
        rows = self.block(0, [100, 100], [100, 100])
        summary = self.summarize(rows, min_samples=2)
        self.assertEqual(summary["status"], "inconclusive")
        self.assertIn("paired blocks", summary["reason"])

    def test_single_sample_per_lane_is_inconclusive(self):
        rows = self.block(0, [100], [100]) + self.block(1, [100], [100])
        self.assertEqual(self.summarize(rows)["status"], "inconclusive")

    def test_noisy_ratios_are_inconclusive(self):
        rows = self.block(0, [100, 100], [80, 80]) + self.block(1, [100, 100], [160, 160])
        summary = self.summarize(rows, max_noise=0.05)
        self.assertEqual(summary["status"], "inconclusive")
        self.assertIn("MAD", summary["reason"])

    def test_any_sample_error_fails(self):
        rows = self.block(0, [100, 100], [100, 100]) + self.block(1, [100, 100], [100, 100])
        rows.append(sample_row("new", 1, 1, status="error"))
        summary = self.summarize(rows)
        self.assertEqual(summary["status"], "fail")
        self.assertIn("error", summary["reason"])

    def test_unsupported_is_never_a_pass(self):
        rows = self.block(0, [100, 100], [100, 100]) + self.block(1, [100, 100], [100, 100])
        rows.append(sample_row("old", 0, 1, status="unsupported"))
        summary = self.summarize(rows)
        self.assertEqual(summary["status"], "inconclusive")
        self.assertIn("unsupported", summary["reason"])
        self.assertEqual(len(summary["unsupported"]), 1)

    def test_startup_uses_the_marker_metric(self):
        rows = []
        for block in (0, 1):
            for lane in ("old", "new"):
                for value in (30.0, 30.0):
                    row = sample_row(lane, block, value, workload="startup")
                    row["probe"]["duration_ns"] = 0
                    rows.append(row)
        summary = bs.summarize(rows, "startup", 2, 2, 4, 0.0, 1.25, 0.35)
        self.assertEqual(summary["metric"], "first_output_ms")
        self.assertAlmostEqual(summary["paired_ratio"]["median"], 1.0)


class EnvironmentTests(unittest.TestCase):
    base = {"PATH": "/usr/bin:/bin", "HOME": "/home/x", "LD_PRELOAD": "/opt/neoproot/libstatfast.so",
            "LD_LIBRARY_PATH": "/x", "NEOPROOT_BIN": "/y", "PROOT_MEMFD_LOADER": "0"}

    def test_sanitizes_and_restores_explicitly(self):
        env, removed, restored, digest = bs.environment(
            ["PROOT_MEMFD_LOADER=1", "FOO=bar"], base=self.base)
        self.assertEqual(env, {"PATH": "/usr/bin:/bin", "HOME": "/home/x",
                               "PROOT_MEMFD_LOADER": "1", "FOO": "bar"})
        self.assertEqual(removed, ["LD_LIBRARY_PATH", "LD_PRELOAD", "NEOPROOT_BIN",
                                   "PROOT_MEMFD_LOADER"])
        self.assertEqual(restored, ["PROOT_MEMFD_LOADER"])
        self.assertEqual(len(digest), 64)

    def test_digest_is_stable_and_sensitive(self):
        first = bs.environment(["A=1"], base=self.base)
        second = bs.environment(["A=1"], base=self.base)
        third = bs.environment(["A=2"], base=self.base)
        self.assertEqual(first[3], second[3])
        self.assertNotEqual(first[3], third[3])

    def test_value_may_contain_equals(self):
        env, _, _, _ = bs.environment(["A=b=c"], base={"PATH": "/bin"})
        self.assertEqual(env["A"], "b=c")

    def test_rejects_malformed_settings(self):
        for bad in ("NOPE", "=value", "A\0B=1"):
            with self.assertRaises(ValueError):
                bs.environment([bad], base={"PATH": "/bin"})


class CommandTests(unittest.TestCase):
    def test_accepts_a_complete_template(self):
        argv = bs.command_json('["probe", "{workload}", "{iterations}", "{marker}", "{data_dir}"]')
        self.assertEqual(len(argv), 5)

    def test_rejects_missing_placeholder(self):
        with self.assertRaises(Exception):
            bs.command_json('["probe", "{workload}", "{iterations}", "{marker}"]')

    def test_rejects_non_argv(self):
        for bad in ('"probe"', "[]", '[""]', '[1,2]', '["a", "\\u0000"]', "not json"):
            with self.assertRaises(Exception):
                bs.command_json(bad)


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.probe = Probe(self.tmp.name)

    def run_cli(self, old_mode="ok", new_mode="ok", extra=(), gate=True):
        command = [sys.executable, RUNNER, "--probe", "/guest/probe",
                   "--data-dir", "/guest/data",
                   "--old-command", json.dumps(self.probe.command(old_mode)),
                   "--new-command", json.dumps(self.probe.command(new_mode)),
                   "--workloads", "stat-absolute",
                   "--samples", "4", "--min-samples", "4", "--min-blocks", "2",
                   "--timeout", "5"]
        if gate:
            command.append("--gate")
        command.extend(extra)
        return subprocess.run(command, capture_output=True, text=True, timeout=120)

    @staticmethod
    def rows(result):
        return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]

    def test_pass_gate(self):
        result = self.run_cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = self.rows(result)
        self.assertEqual(rows[0]["type"], "experiment")
        self.assertEqual(rows[-1]["type"], "gate")
        self.assertEqual(rows[-1]["status"], "pass")
        self.assertEqual(sum(row["type"] == "sample" for row in rows), 8)
        self.assertTrue(all(row["order"] in ("ABBA", "BAAB") for row in rows if row["type"] == "sample"))
        self.assertEqual({row["order"] for row in rows if row["type"] == "sample"}, {"ABBA", "BAAB"})

    def test_regression_gate(self):
        result = self.run_cli(old_mode="ok:1000000", new_mode="ok:2000000")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(self.rows(result)[-1]["status"], "fail")

    def test_fixed_durations_decide_even_with_a_tight_noise_ceiling(self):
        # Every sample reports the same duration, so the paired ratio is exactly
        # 1.0 and even a 0.0001 noise ceiling must still produce a decision.
        result = self.run_cli(extra=("--max-relative-mad", "0.0001"))
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.rows(result)[-1]["status"], "pass")

    def test_duplicate_marker_is_fatal_even_without_gate(self):
        result = self.run_cli(new_mode="dup_marker", gate=False)
        self.assertEqual(result.returncode, 1)
        rows = [row for row in self.rows(result) if row["type"] == "sample"
                and row["status"] == "error"]
        self.assertEqual(len(rows), 4)
        self.assertTrue(all(row["lane"] == "new" for row in rows))

    def test_unsupported_is_not_a_pass(self):
        result = self.run_cli(new_mode="unsupported", gate=True,
                              extra=("--workloads", "unix-translated-sendto"))
        self.assertEqual(result.returncode, 3, result.stdout)
        self.assertEqual(self.rows(result)[-1]["status"], "inconclusive")

    def test_bad_environment_setting_is_rejected(self):
        result = self.run_cli(extra=("--env", "NOPE"))
        self.assertEqual(result.returncode, 2)
        self.assertIn("KEY=VALUE", result.stderr)

    def test_bad_command_template_is_rejected(self):
        result = subprocess.run([sys.executable, RUNNER, "--probe", "/p", "--data-dir", "/d",
                                 "--old-command", '["x"]', "--new-command",
                                 json.dumps(self.probe.command()),
                                 "--workloads", "stat-absolute"],
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 2)
        self.assertIn("placeholder", result.stderr)

    def test_relative_probe_path_is_rejected(self):
        result = subprocess.run([sys.executable, RUNNER, "--probe", "probe", "--data-dir", "/d",
                                 "--old-command", json.dumps(self.probe.command()),
                                 "--new-command", json.dumps(self.probe.command())],
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 2)
        self.assertIn("absolute", result.stderr)

    def test_unbalanced_samples_are_rejected(self):
        result = self.run_cli(extra=("--samples", "6", "--min-samples", "6", "--min-blocks", "2"))
        self.assertEqual(result.returncode, 2)
        self.assertIn("multiple of 4", result.stderr)

    def test_odd_min_blocks_are_rejected(self):
        result = self.run_cli(extra=("--min-blocks", "1"))
        self.assertEqual(result.returncode, 2)

    def test_budget_exhaustion_is_inconclusive(self):
        result = self.run_cli(extra=("--budget", "0.001"))
        self.assertEqual(result.returncode, 3, result.stdout)
        self.assertTrue(self.rows(result)[-1]["budget_exhausted"])
        self.assertEqual(self.rows(result)[-1]["status"], "inconclusive")

    def test_timeout_makes_the_gate_fail(self):
        result = self.run_cli(new_mode="slow", extra=("--timeout", "0.5"))
        self.assertEqual(result.returncode, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
