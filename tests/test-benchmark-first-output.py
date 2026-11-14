#!/usr/bin/env python3
"""Host-only regression tests; no neoproot, UML image or phone required."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

TOOL = Path(__file__).resolve().parents[1] / "tools" / "benchmark-first-output.py"
spec = importlib.util.spec_from_file_location("benchmark", TOOL)
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


class BenchmarkTests(unittest.TestCase):
    def measure(self, code, timeout=3, extra=()):
        return bench.measure("mock", [sys.executable, "-c", code, "{marker}", *extra],
                             "UNIQUE_MARKER", timeout, 1)

    def cli(self, fast, um=None, *options):
        return subprocess.run([sys.executable, str(TOOL), "--fast-command", json.dumps(fast),
                               "--um-command", json.dumps(um or fast), "--runs", "1", *options],
                              capture_output=True, text=True, timeout=10)

    def test_exact_complete_lines_and_bounded_chunks(self):
        matcher = bench.MarkerLines("MARK")
        for data in (b"kernel MARK\n", b"MARK suffix\n", b"MARK\rX\n", b"MARK\r\r\n",
                     b"x" * 100000, b"MARK\n", b"MA", b"RK"):
            self.assertFalse(matcher.feed(data))
            self.assertLessEqual(len(matcher.pending), 5)
        self.assertTrue(matcher.feed(b"\r\n"))
        self.assertTrue(matcher.feed(b"MARK\n"))

    def test_guest_marker_not_first_kernel_or_stderr_output(self):
        code = ("import os,sys,time; m=sys.argv[1]; "
                "print('Linux boot '+m,flush=True); print(m,file=sys.stderr,flush=True); "
                "time.sleep(.15); os.write(1,m[:4].encode()); time.sleep(.05); "
                r"os.write(1,(m[4:]+'\r\n').encode()); time.sleep(.15)")
        with mock.patch.object(bench.time, "time", side_effect=AssertionError("wall clock used")):
            row = self.measure(code)
        self.assertEqual(row["returncode"], 0)
        self.assertGreaterEqual(row["first_output_ms"], 180)
        self.assertGreater(row["total_ms"] - row["first_output_ms"], 100)
        self.assertGreater(row["stderr_bytes"], 0)
        self.assertEqual(row["clock"], "time.monotonic_ns")

    def test_missing_marker_and_partial_eof(self):
        for code in ("import sys; print(sys.argv[1],file=sys.stderr)",
                     "import sys; sys.stdout.write(sys.argv[1])",
                     "import sys; print('boot '+sys.argv[1])"):
            with self.subTest(code=code):
                self.assertIsNone(self.measure(code)["first_output_ms"])

    def test_nonzero_signal_and_spawn_error(self):
        row = self.measure("import sys; print(sys.argv[1]); sys.exit(7)")
        self.assertEqual(row["returncode"], 7)
        self.assertIsNotNone(row["first_output_ms"])
        row = self.measure("import os,signal; os.kill(os.getpid(),signal.SIGTERM)")
        self.assertEqual((row["returncode"], row["signal"]), (-signal.SIGTERM, signal.SIGTERM))
        row = bench.measure("mock", ["/nonexistent/neoproot", "{marker}"], "MARK", 1, 1)
        self.assertIsNotNone(row["error"])
        self.assertIsNone(row["returncode"])
        self.assertIsNone(row["total_ms"])

    def test_large_concurrent_streams_do_not_deadlock(self):
        row = self.measure("import os,sys; os.write(2,b'e'*200000); "
                           r"os.write(1,b'b'*200000+b'\n'); print(sys.argv[1])")
        self.assertFalse(row["timed_out"])
        self.assertIsNotNone(row["first_output_ms"])
        self.assertEqual(row["stderr_bytes"], 200000)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux subreaper verifies grandchild reaping")
    def test_timeout_kills_group_even_after_launcher_exits(self):
        # A private parent reaps the grandchild so this test leaves no zombies.
        for exit_parent in (False, True):
            with self.subTest(exit_parent=exit_parent), tempfile.TemporaryDirectory() as tmp:
                pidfile = Path(tmp) / "pid"
                supervisor = subprocess.Popen([sys.executable, "-c",
                    "import ctypes,os,sys,time; "
                    "ctypes.CDLL(None).prctl(36,1,0,0,0); "
                    "sys.path.insert(0,sys.argv[1]); "
                    "import runpy; ns=runpy.run_path(sys.argv[2]); "
                    "code=sys.argv[4]; "
                    "r=ns['measure']('mock',[sys.executable,'-c',code,sys.argv[3]],'M',.3,1); "
                    "print(__import__('json').dumps(r),flush=True); "
                    "os.waitpid(-1,0)", str(TOOL.parent), str(TOOL), str(pidfile),
                    "import os,sys,time; p=os.fork(); "
                    "open(sys.argv[1],'w').write(str(p)) if p else None; "
                    + ("os._exit(0) if p else None; " if exit_parent else "")
                    + "time.sleep(20)"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    out, err = supervisor.communicate(timeout=5)
                    self.assertEqual(supervisor.returncode, 0, err)
                    row = json.loads(out)
                    self.assertTrue(row["timed_out"])
                    self.assertLess(row["elapsed_ms"], 2000)
                    self.assertEqual(row["returncode"], 0 if exit_parent else -signal.SIGKILL)
                    with self.assertRaises(ProcessLookupError):
                        os.kill(int(pidfile.read_text()), 0)
                finally:
                    if supervisor.poll() is None:
                        supervisor.kill()
                        supervisor.communicate()

    def test_environment_cleanup_does_not_mutate_parent(self):
        with mock.patch.dict(os.environ, {"LD_PRELOAD": "bad", "LD_AUDIT": "bad",
                                         "NEOPROOT_STATSHIM_TEST": "bad"}):
            # Inspect the supplied exec environment: an outer tracer may inject
            # its own preload again after Popen, outside this tool's control.
            with mock.patch.object(bench.subprocess, "Popen", wraps=subprocess.Popen) as popen:
                row = self.measure("import sys; print(sys.argv[1])")
            passed_env = popen.call_args.kwargs["env"]
            self.assertFalse(any(k in passed_env for k in
                                 ("LD_PRELOAD", "LD_AUDIT", "NEOPROOT_STATSHIM_TEST")))
            self.assertEqual(row["returncode"], 0)
            self.assertEqual(os.environ["LD_PRELOAD"], "bad")
            self.assertIn("NEOPROOT_STATSHIM_TEST", row["removed_env"])

    def test_cli_jsonl_unique_markers_order_and_exit_status(self):
        cmd = [sys.executable, "-c", "import sys; print(sys.argv[1])", "{marker}"]
        result = self.cli(cmd, None, "--runs", "2")
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual([r["backend"] for r in rows], ["fast", "um", "um", "fast"])
        self.assertEqual(len({r["marker"] for r in rows}), 4)
        for r in rows:
            self.assertIsNotNone(r["first_output_ms"])
        for code in ("import sys; sys.exit(7)", "pass", "import time; time.sleep(2)"):
            result = self.cli([sys.executable, "-c", code, "{marker}"], None, "--timeout", ".15")
            self.assertEqual(result.returncode, 1)
            self.assertEqual(len(result.stdout.splitlines()), 2)

    def test_timeout_retains_marker_but_fails_sample(self):
        row = self.measure("import sys,time; print(sys.argv[1],flush=True); time.sleep(20)", .3)
        self.assertIsNotNone(row["first_output_ms"])
        self.assertTrue(row["timed_out"])
        self.assertEqual(row["returncode"], -signal.SIGKILL)

    def test_invalid_arguments_fail_before_launch(self):
        for value in ('[]', '{}', '["echo"]', '["echo", 1]', '["", "{marker}"]'):
            with self.assertRaises(argparse.ArgumentTypeError):
                bench.command_json(value)
        cmd = [sys.executable, "-c", "pass", "{marker}"]
        for option, value in (("--timeout", "nan"), ("--timeout", "inf"),
                              ("--timeout", "0"), ("--runs", "0")):
            result = self.cli(cmd, None, option, value)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
