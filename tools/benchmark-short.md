# Short old/new performance gate

A short, paired, phone-sized regression experiment between two Neoproot builds
that run the *same* guest payload: one probe ELF, one sanitized environment, one
alternating schedule, ratio-only thresholds. It answers one question — "is the
new build slower than the old build on this device, beyond what this device's
own noise can explain?" — and answers "inconclusive" when the data cannot
support a verdict.

It is not a benchmark suite, not a production SLA and not a substitute for a
full measurement campaign. See [Boundaries](#boundaries) before quoting a number
from it.

## Files

| File | Runs on | Purpose |
| --- | --- | --- |
| `tools/benchmark-short-probe.c` | guest | one workload per process, protocol v1 on stdout |
| `tools/benchmark-short.py` | host | schedule, validate, sample, summarise, gate |
| `tests/test-benchmark-short.py` | host | protocol and gate tests, no Neoproot needed |

## Why a separate probe instead of `time` / shell loops

* A shell loop pays for `fork` + `exec` of the shell itself on every iteration,
  which is exactly the overhead a Neoproot fast path is trying to remove. The
  probe keeps the loop inside one process and times only the loop.
* Work that is not verified is not measured. Every counted operation checks its
  own result (stat size, alias bytes, received payload, child exit status), so a
  build that "finishes fast" by failing cannot produce a fast sample: failures
  are `status=error` with a nonzero exit code and are excluded from every ratio.
* The probe is compiled **inside the guest** with the guest toolchain (glibc on
  the Arch/Alpine rootfs). A bionic ELF or a bionic `.so` copied from Termux
  would not even load in the guest; measuring that would measure the wrong thing.
  The same ELF bytes are used by both builds.

## Protocol v1

The probe writes to stdout, in this order, and nothing else:

1. exactly one complete line containing the marker argument;
2. exactly one line of JSON:

```json
{"protocol":1,"marker":"SHORT_...","workload":"stat-absolute","status":"ok",
 "operations":2000,"checksum":34000,"duration_ns":183421,"errno":0,"stage":"complete"}
```

| Field | Meaning |
| --- | --- |
| `protocol` | always 1 |
| `marker` | echoed from argv, `[A-Za-z0-9_]`, 1..128 chars |
| `workload` | echoed from argv |
| `status` | `ok`, `error` or `unsupported` |
| `operations` | verified operations completed |
| `checksum` | sum of verified units (17 bytes for stat/l2s, 64 for sockets, 1 for fork-exec) |
| `duration_ns` | CLOCK_MONOTONIC around the workload loop only |
| `errno` | errno of the first failure, 0 when `ok` |
| `stage` | `complete`, or where it failed (`mkdtemp`, `chdir`, `create`, `stat`, `l2s-link`, `bind`, `destination-send`, `receive`, `exec-status`, ...) |

Exit codes: `0` ok, `1` error, `77` unsupported capability,
`2` bad invocation (no marker is printed in that case).

`unsupported` is deliberately narrow: `ENOSYS`/`EOPNOTSUPP` for any workload, and
`ENOENT`/`EAFNOSUPPORT` on a *translated* socket destination after a successful
`bind` (the old-version pathname-translation gap). Everything else is an error,
including a short send, a mismatched checksum or a child that exits nonzero. An
unsupported sample makes the affected workload **inconclusive**, never a pass.

## Workloads

Setup (mkdtemp, chdir, file creation) happens before the clock starts; cleanup
happens after it stops. Every sample gets its own temporary directory, so no
sample can inherit page cache or a `.l2s` family from the previous one.

| Workload | Default iterations | What is timed | What is verified |
| --- | --- | --- | --- |
| `startup` | 1 | nothing in the probe; the metric is host-side "launch → marker line" | marker arrival |
| `stat-absolute` | 2000 | `stat()` on a full guest path | regular file, size 17 |
| `stat-relative` | 2000 | `stat()` on a cwd-relative name | regular file, size 17 |
| `l2s` | 32 | `link()` + two `stat()` + `open`/`read` + `unlink()` | alias exposes the same 17 bytes, name disappears after unlink, original survives with intact content |
| `fork-exec` | 8 | `fork()` + `execve` of the probe itself (`--child`) + `waitpid` | exit status 0 |
| `unix-connected-sendto` | 256 | `sendto` on an `AF_UNIX`/`SOCK_DGRAM` socketpair | 64 bytes received byte-for-byte |
| `unix-connected-sendmsg` | 256 | `sendmsg` on the same socketpair | idem |
| `unix-connected-sendmmsg` | 256 | `sendmmsg` batches of 4 on the same socketpair | every message length and payload |
| `unix-translated-sendto` | 256 | `sendto` to a *bound pathname* (`$data_dir/short-XXXXXX/peer`) | idem |
| `unix-translated-sendmsg` | 256 | `sendmsg` to the same pathname | idem |
| `unix-translated-sendmmsg` | 256 | `sendmmsg` batches of 4 to the same pathname | idem |

`stat-relative` uses a plain relative name on purpose: `fstatat(dirfd, name)`
would resolve against a directory fd and skip the guest's cwd translation,
which is the part being measured.

`l2s` deliberately does **not** assert `st_nlink == 2`. Neoproot's
`--link2symlink` emulates hard links and fakes link counts inconsistently between
`stat(2)` and `lstat(2)` on different backends; the invariant that matters for
users is data identity and survivor integrity, and that is what is checked.

## Sampling design

For each block `b` and each workload, both lanes run twice:

* even block: `old new new old` (ABBA)
* odd block: `new old old new` (BAAB)

so a monotone drift inside a block (warming caches, thermal ramp, scheduler
migration) pushes the two lanes in opposite directions and cancels in the paired
ratio. `--samples` must be a multiple of 4, which makes the number of ABBA and
BAAB blocks equal; an odd number of blocks would leave half a cycle of order
bias in the median. `--min-blocks` must be even for the same reason.

There is no hidden warmup and no discarded first block: the first block is where
a cold cache is visible, both lanes see it, and discarding it would hide exactly
the regression a user notices after a reboot. For warm-cache numbers, run the
experiment twice and read the second run.

## Metrics and statistics

* `startup`: host-side milliseconds from `Popen` to the moment the marker line
  is complete on the pipe. This includes the launcher (`sh`, `env`) and Neoproot's
  own start-up, which is what a user waits for.
* everything else: the probe's in-guest `CLOCK_MONOTONIC` loop time in
  milliseconds. Host scheduling, process creation and the pipe are excluded.
* per-lane `median`, `MAD` and `relative_mad` are reported for the record;
  the gate uses the **paired ratio** `new/old` per block
  (geometric mean of that block's two samples per lane), then the median and MAD
  of those block ratios.
* `ratio_band = median ± max(3 · 1.4826 · MAD / sqrt(blocks), 1% · median)`.
  This is a descriptive spread band, not a confidence interval and not a
  significance test.

Decision per workload:

| Condition | Status |
| --- | --- |
| any sample error/timeout/validation failure | `fail` (fatal, even without `--gate`) |
| any unsupported sample | `inconclusive` |
| fewer than `--min-samples` complete samples per lane, or fewer than `--min-blocks` paired blocks | `inconclusive` |
| relative MAD above `--max-relative-mad` | `inconclusive` |
| band starts above `--max-ratio` | `fail` (regression) |
| band ends below `--min-ratio` (when set) | `fail` (implausibly fast: suspect skipped work) |
| band ends at or below `--max-ratio` | `pass` |
| band crosses `--max-ratio` | `inconclusive` |

The experiment status is `fail` if any workload fails, else `inconclusive` if
the budget ran out or any workload is inconclusive, else `pass`.

Runner exit codes: `0` report written (or `--gate` passed), `1` a sample failed
or the gate failed, `3` `--gate` inconclusive, `130` interrupted.

## Configuration

| Option | Default | Note |
| --- | --- | --- |
| `--samples` | 8 | complete samples per lane per workload, multiple of 4 |
| `--min-samples` | 8 | complete samples per lane needed to decide |
| `--min-blocks` | 4 | paired blocks needed to decide, even |
| `--max-ratio` | 1.25 | regression ceiling on `new/old` |
| `--min-ratio` | 0 | optional lower sanity bound, 0 disables |
| `--max-relative-mad` | 0.35 | noise ceiling, exceeded means inconclusive |
| `--timeout` | 8 s | per sample; the process group is killed on expiry |
| `--budget` | 300 s | soft cap; a sample is only started if the full timeout still fits |
| `--iterations` | per workload | `WORKLOAD=N`, repeatable |
| `--env` | none | `KEY=VALUE`, added to the sanitized environment |
| `--workloads` | all 11 | comma separated |
| `--gate` | off | turn the verdict into the exit code |

**No absolute time is configured anywhere.** Every threshold is a ratio between
the two builds on the same device in the same run, which is the only thing that
survives different phones, Android versions and background load. A CI job must
not grow a "startup must be < 40 ms" constant.

The defaults are loose: 25% regression allowance, 35% MAD ceiling, 8 samples.
Tighten them only after a device has shown a stable noise floor, and expect the
gate to answer `inconclusive` rather than `fail` when the phone is busy — that
is the intended behaviour.

## Environment

The runner builds one environment snapshot and passes the identical dict to
both lanes and to every sample:

* every `LD_*`, `NEOPROOT_*` and `PROOT_*` variable is removed (a stat shim, an
  alternate loader or a different backend would silently change the subject);
* `--env KEY=VALUE` adds settings back explicitly; the value is parsed strictly
  (no missing `=`, no empty key, no NUL) and the restored keys are listed in the
  `experiment` row;
* the SHA-256 of the sanitized dict is recorded as `env_sha256` and repeated on
  every sample row, so "same environment" is checkable after the fact.

Both lanes differ **only** in argv. That is why the Termux template below puts
`NEOPROOT_BIN` in an `env` argv prefix instead of the runner environment: putting it
in the environment would either be stripped or leak into both lanes.

## Real run on Termux

Guest rootfs: `$PREFIX/var/lib/proot-distro/containers/archlinuxarm/rootfs`
(Arch Linux ARM, glibc/aarch64). Probe and data live inside the rootfs so both
builds see the same path — the launcher's `--bind=$HOME` keeps the Termux path
`/data/data/com.termux/files/home`, it does **not** map it to `/home/Raymer`.

```sh
# 1. copy the probe source into the rootfs, then compile it with the guest gcc
R=$PREFIX/var/lib/proot-distro/containers/archlinuxarm/rootfs
mkdir -p "$R/opt/neoproot/bench"
cp tools/benchmark-short-probe.c "$R/opt/neoproot/bench/"
$HOME/neoproot/neoproot-start.sh /usr/bin/gcc -O2 -Wall -Wextra   -o /opt/neoproot/bench/short-probe /opt/neoproot/bench/benchmark-short-probe.c

# 2. confirm the ABI before measuring anything
$HOME/neoproot/neoproot-start.sh /usr/bin/file /opt/neoproot/bench/short-probe
$HOME/neoproot/neoproot-start.sh /usr/bin/ldd  /opt/neoproot/bench/short-probe

# 3. run the gate (old = v6.0.2.1, new = v6.0.3.0, same guest shim bytes)
mkdir -p "$PREFIX/tmp/short-bench"
env -i PATH=$PREFIX/bin:/system/bin HOME=$HOME TMPDIR=$PREFIX/tmp   python3 $HOME/neoproot/bench/benchmark-short.py   --probe /opt/neoproot/bench/short-probe   --data-dir /tmp/short-bench   --old-command '["/system/bin/env","NEOPROOT_BIN='$PREFIX'/bin/neoproot.prev-20261114-133613","'$HOME'/neoproot/neoproot-start.sh","{probe}","{workload}","{iterations}","{marker}","{data_dir}"]'   --new-command '["/system/bin/env","NEOPROOT_BIN='$PREFIX'/bin/neoproot","'$HOME'/neoproot/neoproot-start.sh","{probe}","{workload}","{iterations}","{marker}","{data_dir}"]'   --env PROOT_MEMFD_LOADER=1   --samples 8 --min-samples 8 --min-blocks 4   --min-ratio 0 --max-ratio 1.25 --timeout 8 --budget 300   --label "termux/aarch64 archlinuxarm old=v6.0.2.1 new=v6.0.3.0"   --gate > bench.jsonl
```

`--env PROOT_MEMFD_LOADER=1` is the one setting the experiment needs; it is
passed identically to both lanes and is visible in the `experiment` row.

Optional untraced socket baseline (never part of the old/new ratio):

```sh
--native-command '["/opt/neoproot/bench/short-probe","{workload}","{iterations}","{marker}","{data_dir}"]'
```

## Reading the output

`bench.jsonl` is JSON Lines: one `experiment` row (commands, counts, thresholds,
environment digest), one `sample` row per sample (argv, lane, block, position,
order, return code, stdout/stderr byte counts, the probe JSON, validation error),
one `summary` per workload, one `gate` row. The gate row is always last.

```sh
python3 - <<'PY'
import json
for line in open("bench.jsonl"):
    row = json.loads(line)
    if row["type"] == "summary":
        print("%-28s %-12s median=%.3f band=%s" % (
            row["workload"], row["status"], row["paired_ratio"]["median"],
            [round(v, 3) for v in row["ratio_band"] if v is not None]))
    elif row["type"] == "gate":
        print("gate:", row["status"], "elapsed=%.1fs" % row["elapsed_s"])
PY
```

## Boundaries

What this tool is allowed to claim, and what it is not:

* It measures **this device, this rootfs, this shim, this session**, against a
  specific old binary. Nothing transfers to another phone, another Android
  version or another rootfs without re-running it.
* It is a **short** probe: 8 samples per lane per workload. It detects large,
  reproducible regressions. It cannot detect a 3% regression, and it does not
  try; a small effect needs many more samples and a quiet device.
* A `pass` means "no regression larger than `--max-ratio` was visible in this
  run", not "the build is as fast as before". The band is a descriptive spread,
  not a confidence interval; there is no p-value and no significance claim.
* `inconclusive` is a real outcome, not a failure of the tool. On a phone with
  background apps, thermal throttling and CPU-frequency scaling, it is the
  honest answer more often than a gate owner would like.
* `unsupported` means the operation could not be performed by that build; it is
  never scored as fast, and it can only make a workload inconclusive.
* The `startup` metric includes the launcher (`sh` + `env`) and Neoproot's own
  start-up. It is "time until the guest program can speak", not guest init time.
* Android specifics on this host: `TracerPid` is 0 while `Seccomp` is 2, and
  `/proc/loadavg` is not readable from the Termux side. The runner therefore
  records no load average; run the experiment on an otherwise idle phone and
  say so in the label.
* Only one party may drive the phone at a time. Two concurrent runs invalidate
  both.
* The probe must be built by the guest compiler. A host-built (bionic) probe, a
  different shim, or a different rootfs makes the numbers meaningless, not
  merely noisy.

## Troubleshooting

| Symptom | Meaning |
| --- | --- |
| every sample `error: expected exactly one complete marker line` | launcher failed before exec, or it prints the marker itself; check `stderr_tail` |
| `stage=mkdtemp`, `errno=13` | `--data-dir` is not writable by the mapped uid inside the guest |
| `stage=destination-send`, `status=unsupported` | that build cannot send to a translated pathname (old-version gap) |
| `status=error` with `stage=exec-status` | `fork-exec` child did not exit 0; usually a path/`argv[0]` problem |
| `inconclusive` with `excessive relative MAD` | device too noisy for this sample count; lower `--iterations`, quiet the phone, or raise `--samples` |
| `timed_out` | the sample exceeded `--timeout`; the whole process group was killed |
