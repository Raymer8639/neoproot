#!/usr/bin/env python3
"""Exercise the release installer's runtime-only update without network or ptrace."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
INSTALLER = Path(os.environ.get("NEOPROOT_TEST_INSTALLER", ROOT / "scripts/install.sh"))
TAG = "v6.0.3.0"
KERNEL = "um-arm64-v0.4.1"
PASST = "v0.4.0"
BUNDLE = "https://github.com/Raymer8639/linux-um-arm64/releases/download/" + KERNEL
STANDALONE = "https://github.com/Raymer8639/passt-android/releases/download/" + PASST
FILES = ("linux-bionic", "stub_exe", "umnet", "passt-bionic")

# The installer verifies every payload before it touches the prefix, so the
# fake release has to publish what a real one publishes: SHA256SUMS next to the
# assets, and a MANIFEST (digests and sizes) for the UML runtime.  Serving the
# assets without them would be testing a release that cannot exist.
CURL = r'''#!/usr/bin/env python3
import os
from pathlib import Path
import shutil
import sys

args = sys.argv[1:]
if "-o" not in args:
    # A metadata request (stdout): this fake release does not publish one.
    sys.exit(91)
out = Path(args[args.index("-o") + 1])
url = args[-1]
with open(os.environ["REQUEST_LOG"], "a") as log:
    log.write(url + "\n")

bundle = os.environ["EXPECTED_BUNDLE"]
standalone_dir = os.environ["EXPECTED_STANDALONE"]
name = url.rsplit("/", 1)[1]

if url == bundle + "/MANIFEST":
    shutil.copyfile(os.environ["BUNDLE_MANIFEST"], out)
elif url == bundle + "/SHA256SUMS":
    shutil.copyfile(os.environ["BUNDLE_SUMS"], out)
elif url == standalone_dir + "/SHA256SUMS":
    shutil.copyfile(os.environ["STANDALONE_SUMS"], out)
elif url == bundle + "/" + name and name in (
        "linux-bionic", "stub_exe", "umnet", "passt-bionic"):
    if name == os.environ.get("FAIL_BUNDLE"):
        out.write_text("partial failed download\n")
        sys.exit(22)
    shutil.copyfile(Path(os.environ["PAYLOADS"]) / name, out)
elif url == standalone_dir + "/passt-android-arm64":
    if os.environ.get("FAIL_STANDALONE") == "1":
        out.write_text("partial failed download\n")
        sys.exit(22)
    shutil.copyfile(Path(os.environ["PAYLOADS"]) / "passt-android-arm64", out)
else:
    sys.exit(91)
'''


class InstallerUpdate(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="neoproot-update-")
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.fakebin = self.work / "fakebin"
        self.fakebin.mkdir()
        self.requests = self.work / "requests"
        self.requests.touch()
        self.calls = self.work / "unexpected-build"
        (self.fakebin / "curl").write_text(CURL)
        (self.fakebin / "curl").chmod(0o755)
        # A payload carries its own URL, so a file on disk says which release it
        # came from; the digests below are computed from exactly those bytes.
        self.payloads = self.work / "payloads"
        self.payloads.mkdir()
        sums = []
        manifest = [
            "manifest-format=1",
            "project=Raymer8639/linux-um-arm64",
            "tag=" + KERNEL,
        ]
        for name in FILES:
            body = "#!/bin/sh\n# " + BUNDLE + "/" + name + "\nexit 0\n"
            (self.payloads / name).write_text(body)
            digest = hashlib.sha256(body.encode()).hexdigest()
            sums.append("%s  %s" % (digest, name))
            manifest.append("asset.%s.sha256=%s" % (name, digest))
            manifest.append("asset.%s.size=%d" % (name, len(body)))
        (self.work / "bundle-SHA256SUMS").write_text("\n".join(sums) + "\n")
        (self.work / "bundle-MANIFEST").write_text("\n".join(manifest) + "\n")
        passt = "#!/bin/sh\n# " + STANDALONE + "/passt-android-arm64\nexit 0\n"
        (self.payloads / "passt-android-arm64").write_text(passt)
        (self.work / "standalone-SHA256SUMS").write_text(
            "%s  passt-android-arm64\n" % hashlib.sha256(passt.encode()).hexdigest())
        # A current-version update must never clone, build or install packages.
        for tool in ("git", "make", "clang", "pkg"):
            stub = self.fakebin / tool
            stub.write_text('#!/bin/sh\nprintf "%s\\n" "$0" >>"$BUILD_LOG"\nexit 99\n')
            stub.chmod(0o755)

    def seed(self, name, kernel=KERNEL, passt=PASST, with_um=1):
        prefix = self.work / name
        (prefix / "bin").mkdir(parents=True)
        (prefix / "bin/neoproot").write_text("unchanged tracer\n")
        runtime = prefix / "libexec/neoproot/um"
        runtime.mkdir(parents=True)
        for name in FILES:
            path = runtime / name
            path.write_text("old " + name + "\n")
            path.chmod(0o755)
        state = prefix / "libexec/neoproot/install-state"
        state.write_text(
            f"version={TAG}\nprefix={prefix}\nportable=1\nwith_um={with_um}\n"
            f"um_kernel_tag={kernel}\num_passt_tag={passt}\ninstalled_at=old\n")
        return prefix, runtime, state

    def run_update(self, prefix, mode="termux", **extra):
        self.requests.write_text("")
        env = dict(os.environ)
        # Ignore ambient installer overrides and LD preload settings.
        for key in list(env):
            if key.startswith(("NEOPROOT_", "LD_")):
                del env[key]
        env.update(PATH=str(self.fakebin) + os.pathsep + os.environ["PATH"],
                   PREFIX=str(prefix), HOME=str(self.work), TMPDIR=str(self.work),
                   REQUEST_LOG=str(self.requests), BUILD_LOG=str(self.calls),
                   EXPECTED_BUNDLE=BUNDLE, EXPECTED_STANDALONE=STANDALONE,
                   PAYLOADS=str(self.payloads),
                   BUNDLE_MANIFEST=str(self.work / "bundle-MANIFEST"),
                   BUNDLE_SUMS=str(self.work / "bundle-SHA256SUMS"),
                   STANDALONE_SUMS=str(self.work / "standalone-SHA256SUMS"),
                   **extra)
        result = subprocess.run(
            ["sh", str(INSTALLER), "--update", "--version", TAG, "--mode", mode,
             "--prefix", str(prefix), "--non-interactive"],
            env=env, text=True, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.calls.exists(), "runtime-only update invoked build tools")
        self.assertEqual((prefix / "bin/neoproot").read_text(), "unchanged tracer\n")
        self.assertFalse(list((prefix / "bin").glob("neoproot.prev-*")))
        self.assertFalse(list((prefix / "libexec/neoproot/um").glob(".*.new.*")))
        return self.requests.read_text().splitlines(), result.stdout + result.stderr

    @staticmethod
    def assets(requests):
        """The asset downloads, without the manifest and checksum requests."""
        return [url for url in requests if url.rsplit("/", 1)[1] in FILES]

    def assert_current(self, state):
        text = state.read_text()
        self.assertIn(f"um_kernel_tag={KERNEL}\n", text)
        self.assertIn(f"um_passt_tag={PASST}\n", text)
        self.assertIn("portable=1\nwith_um=1\n", text)

    def test_old_pins_refresh_on_both_platforms(self):
        for mode in ("termux", "linux"):
            with self.subTest(mode=mode):
                prefix, runtime, state = self.seed(mode, "um-arm64-v0.3.0", "v0.3.1")
                requests, _ = self.run_update(prefix, mode)
                self.assertEqual(self.assets(requests),
                                 [BUNDLE + "/" + name for name in FILES])
                for name in FILES:
                    self.assertIn(BUNDLE, (runtime / name).read_text())
                    self.assertTrue(os.access(runtime / name, os.X_OK))
                self.assert_current(state)

    def test_complete_current_runtime_is_untouched(self):
        for mode in ("termux", "linux"):
            with self.subTest(mode=mode):
                prefix, runtime, state = self.seed(mode)
                before = state.read_bytes()
                requests, _ = self.run_update(prefix, mode)
                self.assertEqual(requests, [])
                self.assertEqual(state.read_bytes(), before)
                self.assertEqual((runtime / "linux-bionic").read_text(), "old linux-bionic\n")

    def test_each_missing_helper_triggers_refresh(self):
        for name in FILES:
            with self.subTest(helper=name):
                prefix, runtime, state = self.seed(name)
                (runtime / name).unlink()
                requests, _ = self.run_update(prefix)
                self.assertEqual(len(self.assets(requests)), 4)
                self.assertTrue(os.access(runtime / name, os.X_OK))
                self.assert_current(state)

    def test_non_executable_helper_triggers_refresh(self):
        prefix, runtime, state = self.seed("non-executable")
        (runtime / "umnet").chmod(0o644)
        requests, _ = self.run_update(prefix)
        self.assertEqual(len(self.assets(requests)), 4)
        self.assertTrue(os.access(runtime / "umnet", os.X_OK))
        self.assert_current(state)

    def test_fast_only_stays_disabled(self):
        for mode in ("termux", "linux"):
            with self.subTest(mode=mode):
                prefix, runtime, state = self.seed(mode, "old", "old", with_um=0)
                before = state.read_bytes()
                requests, log = self.run_update(prefix, mode)
                self.assertEqual(requests, [])
                self.assertEqual(state.read_bytes(), before)
                self.assertIn("runtime: disabled", log)

    def test_standalone_passt_fallback_replaces_an_old_copy(self):
        prefix, runtime, state = self.seed("fallback", "old", "old")
        requests, _ = self.run_update(prefix, FAIL_BUNDLE="passt-bionic")
        self.assertEqual(requests[-1], STANDALONE + "/passt-android-arm64")
        self.assertIn(STANDALONE, (runtime / "passt-bionic").read_text())
        self.assert_current(state)

    def test_failed_download_preserves_old_file_and_retries(self):
        prefix, runtime, state = self.seed("failure", "old", "old")
        _, log = self.run_update(prefix, FAIL_BUNDLE="linux-bionic")
        self.assertEqual((runtime / "linux-bionic").read_text(), "old linux-bionic\n")
        self.assertIn("could not fetch", log)
        self.assertNotIn("UML runtime installed into", log)
        self.assertIn("um_kernel_tag=\num_passt_tag=\n", state.read_text())
        requests, _ = self.run_update(prefix)
        self.assertEqual(len(self.assets(requests)), 4)
        self.assert_current(state)

    def test_failed_passt_sources_do_not_confirm_runtime(self):
        prefix, runtime, state = self.seed("passt-failure", "old", "old")
        self.run_update(prefix, FAIL_BUNDLE="passt-bionic", FAIL_STANDALONE="1")
        self.assertEqual((runtime / "passt-bionic").read_text(), "old passt-bionic\n")
        self.assertIn("um_kernel_tag=\num_passt_tag=\n", state.read_text())


if __name__ == "__main__":
    unittest.main(verbosity=2)
