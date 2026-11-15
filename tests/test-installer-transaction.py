#!/usr/bin/env python3
"""Script-level fault injection for the installer's install transaction.

Each case runs the real scripts/install.sh against a release served from a
local directory by a fake curl, and then inspects the prefix: which files were
replaced, which were restored, what install-state says, and what the
transaction directory kept.  No network, no ptrace, no root.

The cases map one-to-one onto the failure modes the transaction exists for:

  * a payload that does not match its digest, or is missing from the release,
    must not be installed and must not be replaced by a cached copy;
  * a rename that fails half way through must restore every file already
    switched, in reverse order, and install-state last;
  * a SIGKILLed install must be rolled back by the next run of any action, and
    --recover must do exactly that;
  * two installers must not write the same prefix at once, and a lock left by
    a killed installer must not block the next run;
  * a successful install writes install-state; a failed one does not.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
INSTALLER = Path(os.environ.get("NEOPROOT_TEST_INSTALLER", ROOT / "scripts/install.sh"))
TAG = "vTEST"
NEOPROOT_BASE = "https://github.com/Raymer8639/neoproot/releases/download/" + TAG
UM_BASE = "https://github.com/Raymer8639/linux-um-arm64/releases/download/um-arm64-v0.4.1"
PASST_BASE = "https://github.com/Raymer8639/passt-android/releases/download/v0.4.0"
API_URL = "https://api.github.com/repos/Raymer8639/neoproot/releases/tags/" + TAG
UM_FILES = ("linux-bionic", "stub_exe", "umnet", "passt-bionic")

CURL = r'''#!/usr/bin/env python3
import os
from pathlib import Path
import shutil
import sys

args = sys.argv[1:]
if "-o" not in args:
    # A stdout request (release metadata); this fake release has none unless a
    # test put one in place.
    sys.exit(91)
out = Path(args[args.index("-o") + 1])
url = args[-1]
with open(os.environ["REQUEST_LOG"], "a") as log:
    log.write(url + "\n")

release = Path(os.environ["RELEASE"])
name = url.rsplit("/", 1)[1]
if url == os.environ["API_URL"]:
    source = release / "api" / "release.json"
elif url.startswith(os.environ["NEOPROOT_BASE"] + "/"):
    source = release / name
elif url.startswith(os.environ["UM_BASE"] + "/"):
    source = release / "um" / name
elif url.startswith(os.environ["PASST_BASE"] + "/"):
    source = release / "passt" / name
else:
    sys.exit(91)
if not source.is_file():
    sys.exit(22)
if name == os.environ.get("FAIL_ASSET"):
    out.write_text("partial failed download\n")
    sys.exit(22)
shutil.copyfile(source, out)
'''

# The installer switches each target with "mv -f <tmp> <target>", where <tmp>
# is .<name>.new.<pid> in the target's directory.  This wrapper can fail or
# SIGKILL the installer at exactly that rename, and leaves every other mv
# (notably the rollback's .<name>.restore.<pid>) alone.
MV = r'''#!/bin/sh
prev=
last=
for a do prev=$last; last=$a; done
kind=
case "$last:$prev" in
*/bin/neoproot:*/.neoproot.new.*) kind=/bin/neoproot ;;
*/bin/neoproot-um:*/.neoproot-um.new.*) kind=/bin/neoproot-um ;;
esac
if [ -n "$kind" ] && [ "$kind" = "$MV_ON" ]; then
	if [ -n "$MV_FAIL" ]; then
		printf 'injected rename failure for %s\n' "$last" >&2
		exit 1
	fi
	if [ -n "$MV_KILL" ]; then
		REAL_MV "$@"
		kill -9 "$PPID"
		exit 137
	fi
fi
exec REAL_MV "$@"
'''


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class InstallerTransaction(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="neoproot-txn-")
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.fakebin = self.work / "fakebin"
        self.fakebin.mkdir()
        self.release = self.work / "release"
        self.requests = self.work / "requests"
        self.requests.touch()
        self.calls = self.work / "unexpected-build"
        self.write_release()

        (self.fakebin / "curl").write_text(CURL)
        (self.fakebin / "curl").chmod(0o755)
        real_mv = shutil.which("mv")
        (self.fakebin / "mv").write_text(MV.replace("REAL_MV", real_mv))
        (self.fakebin / "mv").chmod(0o755)
        # An install must never fall back to a source build in these tests.
        for tool in ("git", "make", "clang", "pkg"):
            stub = self.fakebin / tool
            stub.write_text('#!/bin/sh\nprintf "%s\\n" "$0" >>"$BUILD_LOG"\nexit 99\n')
            stub.chmod(0o755)

    # -- the fake release -------------------------------------------------
    def write_release(self):
        self.release.mkdir()
        tracer = "#!/bin/sh\nprintf 'fake-neoproot vTEST\\n'\n"
        (self.release / "neoproot").write_text(tracer)
        (self.release / "neoproot").chmod(0o755)
        shim = b"not really an ELF, but it never gets that far"
        (self.release / "libstatfast.so").write_bytes(shim)
        (self.release / "SHA256SUMS").write_text(
            "%s  neoproot\n%s  libstatfast.so\n"
            % (hashlib.sha256(tracer.encode()).hexdigest(),
               hashlib.sha256(shim).hexdigest()))

        um = self.release / "um"
        um.mkdir()
        sums = []
        manifest = ["manifest-format=1", "project=Raymer8639/linux-um-arm64",
                    "tag=um-arm64-v0.4.1"]
        for name in UM_FILES:
            body = ("#!/bin/sh\n# " + UM_BASE + "/" + name + "\nexit 0\n")
            (um / name).write_text(body)
            digest = hashlib.sha256(body.encode()).hexdigest()
            sums.append("%s  %s" % (digest, name))
            manifest.append("asset.%s.sha256=%s" % (name, digest))
            manifest.append("asset.%s.size=%d" % (name, len(body)))
        (um / "SHA256SUMS").write_text("\n".join(sums) + "\n")
        (um / "MANIFEST").write_text("\n".join(manifest) + "\n")

        passt = self.release / "passt"
        passt.mkdir()
        body = "#!/bin/sh\n# " + PASST_BASE + "/passt-android-arm64\nexit 0\n"
        (passt / "passt-android-arm64").write_text(body)
        (passt / "SHA256SUMS").write_text(
            "%s  passt-android-arm64\n" % hashlib.sha256(body.encode()).hexdigest())

    def serve_wrong_tracer(self):
        """Keep SHA256SUMS as published, change the bytes that are served."""
        (self.release / "neoproot").write_text("#!/bin/sh\nprintf 'tampered\\n'\n")

    def remove_sums_entry(self, name):
        path = self.release / "SHA256SUMS"
        kept = [line for line in path.read_text().splitlines()
                if line.rsplit("  ", 1)[-1] != name]
        path.write_text("\n".join(kept) + "\n")

    def break_manifest_size(self, name):
        path = self.release / "um/MANIFEST"
        real = (self.release / "um" / name).stat().st_size
        lines = []
        for line in path.read_text().splitlines():
            if line.startswith("asset.%s.size=" % name):
                line = "asset.%s.size=%d" % (name, real + 1)
            lines.append(line)
        path.write_text("\n".join(lines) + "\n")

    def use_real_shim(self):
        """Publish a shim that readelf can identify, so the ABI guard lets it
        through; the digest is recomputed for the new bytes."""
        cc = shutil.which("cc")
        if not cc or not shutil.which("readelf"):
            self.skipTest("no C compiler or readelf")
        fixtures = self.work / "fixtures"
        fixtures.mkdir()
        (fixtures / "stub.c").write_text("void neoproot_abi_stub(void) {}\n")
        (fixtures / "fixture.c").write_text("void neoproot_abi_fixture(void) {}\n")
        subprocess.run([cc, "-shared", "-fPIC", "-nostdlib", "-Wl,-soname,libc.so.6",
                        "-o", str(fixtures / "libc.so.6"),
                        str(fixtures / "stub.c")], check=True)
        subprocess.run([cc, "-shared", "-fPIC", "-nostdlib", "-Wl,--no-as-needed",
                        "-o", str(fixtures / "libstatfast.so"),
                        str(fixtures / "fixture.c"),
                        "-L" + str(fixtures), "-l:libc.so.6"], check=True)
        shim = (fixtures / "libstatfast.so").read_bytes()
        (self.release / "libstatfast.so").write_bytes(shim)
        lines = []
        for line in (self.release / "SHA256SUMS").read_text().splitlines():
            if line.rsplit("  ", 1)[-1] == "libstatfast.so":
                line = "%s  libstatfast.so" % hashlib.sha256(shim).hexdigest()
            lines.append(line)
        (self.release / "SHA256SUMS").write_text("\n".join(lines) + "\n")
        return shim

    def write_release_metadata(self, sizes=None, digests=None):
        assets = []
        for name, source in (("neoproot", self.release / "neoproot"),
                             ("libstatfast.so", self.release / "libstatfast.so")):
            assets.append({
                "name": name,
                "size": (sizes or {}).get(name, source.stat().st_size),
                "digest": "sha256:" + (digests or {}).get(name, sha256(source)),
            })
        (self.release / "api").mkdir(exist_ok=True)
        (self.release / "api" / "release.json").write_text(
            json.dumps({"tag_name": TAG, "name": TAG, "assets": assets}, indent=2))

    # -- prefixes ---------------------------------------------------------
    def seed(self, name="prefix", with_um=True, state=True):
        prefix = self.work / name
        (prefix / "bin").mkdir(parents=True)
        (prefix / "bin/neoproot").write_text("old tracer\n")
        runtime = prefix / "libexec/neoproot/um"
        runtime.mkdir(parents=True)
        for helper in UM_FILES:
            path = runtime / helper
            path.write_text("old " + helper + "\n")
            path.chmod(0o755)
        if state:
            (prefix / "libexec/neoproot/install-state").write_text(
                "version=vOLD\nprefix=%s\nportable=0\nwith_um=%d\n"
                "um_kernel_tag=old\num_passt_tag=old\ninstalled_at=old\n"
                % (prefix, 1 if with_um else 0))
        return prefix

    def env(self, **extra):
        env = dict(os.environ)
        for key in list(env):
            if key.startswith(("NEOPROOT_", "LD_")):
                del env[key]
        env.update(PATH=str(self.fakebin) + os.pathsep + os.environ["PATH"],
                   HOME=str(self.work), TMPDIR=str(self.work),
                   REQUEST_LOG=str(self.requests), BUILD_LOG=str(self.calls),
                   RELEASE=str(self.release),
                   NEOPROOT_BASE=NEOPROOT_BASE, UM_BASE=UM_BASE,
                   PASST_BASE=PASST_BASE, API_URL=API_URL)
        env.update(extra)
        return env

    def install(self, prefix, *args, timeout=60, **env_extra):
        self.requests.write_text("")
        result = subprocess.run(
            ["sh", str(INSTALLER), "--version", TAG, "--mode", "linux",
             "--prefix", str(prefix), "--non-interactive", *args],
            env=self.env(**env_extra), text=True, capture_output=True,
            timeout=timeout)
        self.assertFalse(self.calls.exists(), "the installer invoked build tools")
        self.result = result
        return result

    def log(self, result=None):
        result = result or self.result
        return result.stdout + result.stderr

    # -- assertions -------------------------------------------------------
    def txn_dir(self, prefix):
        return prefix / "libexec/neoproot/.transaction"

    def rolled_back(self, prefix):
        return sorted((prefix / "libexec/neoproot").glob(".transaction.rolledback-*"))

    def assert_untouched(self, prefix, tracer="old tracer\n"):
        self.assertEqual((prefix / "bin/neoproot").read_text(), tracer)
        runtime = prefix / "libexec/neoproot/um"
        for helper in UM_FILES:
            self.assertEqual((runtime / helper).read_text(), "old " + helper + "\n")
        self.assertFalse(self.txn_dir(prefix).exists(),
                         "an open transaction was left behind")
        state = prefix / "libexec/neoproot/install-state"
        if state.exists():
            self.assertIn("version=vOLD\n", state.read_text())

    def assert_restored(self, prefix):
        """A failed run restored everything it had replaced, state included."""
        self.assert_untouched(prefix)
        kept = self.rolled_back(prefix)
        self.assertEqual(len(kept), 1, kept)
        for name in ("plan", "journal"):
            self.assertTrue((kept[0] / name).is_file(), name)
        self.assertIn("the failed transaction is kept", self.log())

    # -- the cases --------------------------------------------------------
    def test_bad_checksum_fails_without_touching_anything(self):
        self.serve_wrong_tracer()
        prefix = self.seed()
        result = self.install(prefix)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum mismatch for neoproot", self.log(result))
        self.assert_untouched(prefix)
        self.assertEqual([], self.rolled_back(prefix))
        self.assertEqual([], list((prefix / "bin").glob("neoproot.prev-*")))

    def test_asset_missing_from_the_release_fails(self):
        (self.release / "neoproot").unlink()
        prefix = self.seed()
        result = self.install(prefix)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("download failed", self.log(result))
        self.assert_untouched(prefix)

    def test_asset_missing_from_sha256sums_fails(self):
        self.remove_sums_entry("neoproot")
        prefix = self.seed()
        result = self.install(prefix)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not listed in", self.log(result))
        self.assert_untouched(prefix)

    def test_manifest_size_mismatch_fails(self):
        self.break_manifest_size("stub_exe")
        prefix = self.seed()
        result = self.install(prefix)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("bytes but", self.log(result))
        self.assert_untouched(prefix)

    def test_rename_failure_rolls_back_in_reverse_order(self):
        prefix = self.seed()
        # The tracer and the runtime are in place; the alias step fails, so the
        # rollback has to undo six finished steps.
        result = self.install(prefix, MV_FAIL="1", MV_ON="/bin/neoproot-um")
        self.assertNotEqual(result.returncode, 0)
        log = self.log(result)
        self.assertIn("injected rename failure", log)
        self.assertIn("transaction: step", log)
        self.assert_restored(prefix)
        # The runtime steps ran before the tracer and were put back; their
        # backups are kept as evidence, and install-state is the last planned
        # step, so it never ran.
        runtime = prefix / "libexec/neoproot/um"
        for helper in UM_FILES:
            self.assertEqual((runtime / helper).read_text(), "old " + helper + "\n")
            self.assertEqual(len(list(runtime.glob(helper + ".prev-*"))), 1, helper)
        # str.splitlines() also breaks on \x1c, which is the plan's own field
        # separator; split on newlines explicitly.
        plan = [line for line in
                (self.rolled_back(prefix)[0] / "plan").read_text().split("\n") if line]
        self.assertEqual(plan[-1].split("\034")[1], "state", plan[-1])
        self.assertNotIn("recorded the install state", log)
        # The tracer was replaced first and restored from its own backup.
        self.assertEqual(len(list((prefix / "bin").glob("neoproot.prev-*"))), 1)

    def test_sigkill_is_recovered_by_recover(self):
        prefix = self.seed()
        result = self.install(prefix, MV_KILL="1", MV_ON="/bin/neoproot")
        self.assertNotEqual(result.returncode, 0)
        # The tracer rename happened; the state step did not.
        self.assertEqual((prefix / "bin/neoproot").read_text(),
                         "#!/bin/sh\nprintf 'fake-neoproot vTEST\\n'\n")
        self.assertIn("version=vOLD\n",
                      (prefix / "libexec/neoproot/install-state").read_text())
        journal = (self.txn_dir(prefix) / "journal").read_text()
        self.assertIn("begin\034", journal)
        self.assertNotIn("done", journal.split("begin\034")[-1])

        self.requests.write_text("")
        recovered = subprocess.run(
            ["sh", str(INSTALLER), "--recover", "--prefix", str(prefix)],
            env=self.env(), text=True, capture_output=True, timeout=60)
        self.assertEqual(recovered.returncode, 0, recovered.stdout + recovered.stderr)
        self.assertIn("found an unfinished install transaction",
                      recovered.stdout + recovered.stderr)
        self.assert_untouched(prefix)
        self.assertEqual(len(self.rolled_back(prefix)), 1)

    def test_sigkill_is_recovered_by_the_next_update(self):
        prefix = self.seed()
        self.install(prefix, MV_KILL="1", MV_ON="/bin/neoproot")
        result = self.install(prefix, "--update")
        self.assertEqual(result.returncode, 0, self.log(result))
        log = self.log(result)
        self.assertIn("found an unfinished install transaction", log)
        self.assertIn("rolling it back", log)
        self.assertFalse(self.txn_dir(prefix).exists())
        state = (prefix / "libexec/neoproot/install-state").read_text()
        self.assertIn("version=" + TAG + "\n", state)
        self.assertIn("with_um=1\n", state)
        self.assertNotIn("um_kernel_tag=\n", state)
        self.assertEqual(
            (prefix / "libexec/neoproot/um/linux-bionic").read_text(),
            "#!/bin/sh\n# " + UM_BASE + "/linux-bionic\nexit 0\n")

    def test_concurrent_installer_is_refused(self):
        prefix = self.seed()
        lock = prefix / "libexec/neoproot/.install-lock"
        lock.write_text("pid=%d\nstart=%s\npurpose=test\nsince=now\n"
                        % (os.getpid(), self.proc_starttime(os.getpid())))
        result = self.install(prefix)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("another neoproot installer", self.log(result))
        self.assert_untouched(prefix)
        self.assertTrue(lock.exists(), "the installer removed a live lock")
        lock.unlink()

        # A lock whose process is gone is stale, not a reason to refuse.
        lock.write_text("pid=999999\nstart=1\npurpose=test\nsince=old\n")
        result = self.install(prefix, "--force")
        self.assertEqual(result.returncode, 0, self.log(result))
        self.assertIn("removing a stale lock", self.log(result))
        self.assertFalse(lock.exists())
        self.assertIn("version=" + TAG + "\n",
                      (prefix / "libexec/neoproot/install-state").read_text())

    @staticmethod
    def proc_starttime(pid):
        text = Path("/proc/%d/stat" % pid).read_text()
        return text[text.rindex(")") + 2:].split()[19]

    def test_successful_install_records_current_once(self):
        prefix = self.seed()
        result = self.install(prefix)
        self.assertEqual(result.returncode, 0, self.log(result))
        log = self.log(result)
        self.assertIn("recorded the install state in", log)
        state = (prefix / "libexec/neoproot/install-state").read_text()
        self.assertIn("version=" + TAG + "\n", state)
        self.assertIn("with_um=1\n", state)
        self.assertIn("um_kernel_tag=um-arm64-v0.4.1\n", state)
        self.assertEqual(state.count("version="), 1)
        self.assertFalse(self.txn_dir(prefix).exists())
        self.assertEqual([], self.rolled_back(prefix))
        self.assertEqual((prefix / "bin/neoproot").read_text(),
                         "#!/bin/sh\nprintf 'fake-neoproot vTEST\\n'\n")
        self.assertEqual((prefix / "bin/neoproot-um").readlink(), Path("neoproot"))
        for helper in UM_FILES:
            self.assertIn(UM_BASE, (prefix / "libexec/neoproot/um" / helper).read_text())
        # The previous files are kept, named, next to their targets.
        self.assertEqual(len(list((prefix / "bin").glob("neoproot.prev-*"))), 1)

    def test_shim_checksum_mismatch_is_refused(self):
        (self.release / "libstatfast.so").write_bytes(b"tampered shim bytes")
        rootfs = self.work / "rootfs"
        (rootfs / "lib").mkdir(parents=True)
        (rootfs / "lib/ld-linux-aarch64.so.1").write_text("")
        (rootfs / "opt/neoproot").mkdir(parents=True)
        guest = rootfs / "opt/neoproot/libstatfast.so"
        guest.write_text("old guest shim\n")
        prefix = self.seed()
        result = self.install(prefix, "--shim-rootfs", str(rootfs))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum mismatch for libstatfast.so", self.log(result))
        self.assertEqual(guest.read_text(), "old guest shim\n")
        self.assert_untouched(prefix)

    def test_verified_shim_replaces_the_guest_copy(self):
        shim = self.use_real_shim()
        rootfs = self.work / "rootfs"
        (rootfs / "lib").mkdir(parents=True)
        (rootfs / "lib/ld-linux-aarch64.so.1").write_text("")
        (rootfs / "opt/neoproot").mkdir(parents=True)
        guest = rootfs / "opt/neoproot/libstatfast.so"
        guest.write_text("old guest shim\n")
        prefix = self.seed()
        result = self.install(prefix, "--shim-rootfs", str(rootfs))
        self.assertEqual(result.returncode, 0, self.log(result))
        self.assertEqual(guest.read_bytes(), shim)
        backups = list((rootfs / "opt/neoproot").glob("libstatfast.so.prev-*"))
        self.assertEqual(len(backups), 1, backups)
        self.assertEqual(backups[0].read_text(), "old guest shim\n")
        # The guest lock is not left behind, and the install is current.
        self.assertFalse((rootfs / "opt/neoproot/.install-lock").exists())
        self.assertIn("version=" + TAG + "\n",
                      (prefix / "libexec/neoproot/install-state").read_text())
        self.assertFalse(self.txn_dir(prefix).exists())

    def test_release_metadata_mismatch_is_refused(self):
        self.write_release_metadata(sizes={"neoproot": 3})
        prefix = self.seed()
        result = self.install(prefix)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("release metadata says 3", self.log(result))
        self.assert_untouched(prefix)

    def test_metadata_that_agrees_changes_nothing(self):
        self.write_release_metadata()
        prefix = self.seed()
        result = self.install(prefix)
        self.assertEqual(result.returncode, 0, self.log(result))
        self.assertIn("verified neoproot", self.log(result))


if __name__ == "__main__":
    unittest.main(verbosity=2)
