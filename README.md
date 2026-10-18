[English](README.md) | [简体中文](README.zh-CN.md)

# neoproot

An ARM64-focused PRoot fork for Android/Termux containers. neoproot targets developers who run Debian/Ubuntu userspaces on phones and tablets, especially Node.js, pnpm, TypeScript, nvim, bwrap, and other syscall-heavy workflows.

GitHub Release assets are **ARM64 Linux (glibc)** CI builds. Termux needs a **local bionic** build; do not install those assets as `$PREFIX/bin/neoproot`.

[![CI](https://github.com/Raymer8639/neoproot/actions/workflows/ci.yml/badge.svg)](https://github.com/Raymer8639/neoproot/actions/workflows/ci.yml)
![Platform](https://img.shields.io/badge/platform-ARM64%20%2F%20Android-blue)
![Language](https://img.shields.io/badge/C%2FC%2B%2B-C23%20%2F%20C%2B%2B23-orange)
![License](https://img.shields.io/badge/license-GPLv2-green)

## Install (one command)

```sh
curl -fsSL https://github.com/Raymer8639/neoproot/releases/latest/download/install.sh | sh
```

The script detects the platform and does the right thing: on **Termux** it installs the build dependencies, builds the bionic binary from the tagged source, backs up the previous binary and installs the new one into `$PREFIX/bin`; on **ARM64 Linux** it downloads the release binary, verifies it against `SHA256SUMS`, and installs it into your `PATH`. It never touches a running container's rootfs. Read [scripts/install.sh](scripts/install.sh) before piping it to a shell if you prefer; `sh scripts/install.sh --help` lists `--version`, `--prefix` and `--portable`.

## Start in Termux (manual)

Always build on the Termux host. Linux CI / Release files will not run correctly as the Termux Android binary.

```sh
pkg install clang make llvm binutils pkg-config libtalloc
git clone https://github.com/Raymer8639/neoproot.git
cd neoproot
sh install.sh

# Or build with Meson (GNUmakefile remains the reference implementation):
# Install meson+ninja with your package manager first.
CC=clang CXX=clang++ meson setup builddir
meson compile -C builddir
meson install -C builddir
```

The installer places `neoproot` in `$PREFIX/bin`.

On **ARM64 Linux** (not Termux), download `neoproot` or the lower-instruction-set `neoproot-portable` from [Releases](https://github.com/Raymer8639/neoproot/releases), verify its SHA256, and install it in your `PATH`.

## Why neoproot

- Automatic Termux host setup: wake-lock, file-descriptor limits, and `LD_*` cleanup are handled by the `neoproot` launcher.
- link2symlink hard-link emulation works with pnpm and TypeScript/tsgo workflows that probe real paths through `/proc/<pid>/fd/<fd>`.
- High-frequency path operations avoid the fork's removed translation-thread-pool overhead, keeping nvim and package-manager workflows responsive.
- Optional `--seccomp-notify` (Linux 5.0+) emulates `newfstatat` via seccomp USER_NOTIF so directory metadata scans skip a ptrace stop. Kernel 4+ without the flag is unchanged.
- Optional `--stat-shim=<guest-lib>` preloads a guest-ABI `LD_PRELOAD` library that resolves `stat`/`lstat`/`statx` in-process (bind translation and fake_id0), keeping link2symlink results exact through a flag-gated USER_NOTIF fallback. Off by default. See [stat-shim/README.md](stat-shim/README.md).
- Built-in high-priority scheduling (`setpriority(-20)`) improves CPU availability without root access.
- Fixes include Chinese VNC exit hangs, logout/background-switch issues, and the misleading `signal 11` exit warning.
- The codebase uses a lean C23/C++23 implementation tuned for ARMv8.2, trading generic architecture coverage for ARM64 performance.

## Supported environments

- 64-bit ARM Linux (`aarch64` / ARMv8.2+), with Android/Termux as the primary target.
- Termux or an equivalent Android Linux environment, or an ARM64 Linux host.
- The optimized build is intentionally **not supported on x86_64**. Use an ARM64 machine for the published binaries.

## Container example

```sh
neoproot -0 -r /data/data/com.termux/files/home/rootfs \
    -b /dev -b /proc -b /sys -b /sdcard \
    /usr/bin/env -i HOME=/root TERM=${TERM} PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    /bin/bash --login
```

The command-line interface follows official PRoot conventions. You do not need to manually unset `LD_PRELOAD`, `LD_LIBRARY_PATH`, or `LD_BIND_NOW`; the launcher handles those variables before entering the guest.

## UML backend (the optional second execution backend)

neoproot has two execution backends. The default PRoot tracer -- selected when
`--backend` is omitted, or explicitly with `--backend=fast` -- translates paths
and user/group IDs with `ptrace` (plus optional seccomp USER_NOTIF) and needs no
root. The UML backend is the optional second execution backend: `--backend=um`
boots a separate UML guest kernel through the `neoproot-um` supervisor, so the
command runs on a real Linux kernel instead of behind syscall translation. It
must be started from an untraced Termux host process, not from inside an
existing PRoot container or sandbox.

`-r`/`--rootfs` accepts either a host directory or an ext4 image. A directory is
exported to the guest as UML `hostfs`. An ext4 image is mounted as the guest root
with a per-run temporary COW file that is deleted when the run ends; the base
image is never written. `--cow-file=PATH` keeps the COW file at `PATH` instead
(`PATH` must be absolute): it is created when missing, reused by the next run --
so that run sees what the previous one wrote -- and kept after the run.
`--cow-file` and `--readonly` are mutually exclusive; with `--readonly` an ext4
image is opened directly without a COW file. A COW file is tied to the image it
was created for (its header records the image's size and mtime), and a run
refuses to start when the file was made for a different image. The UML kernel
and `stub_exe` can be supplied with command-line options to `neoproot-um`, or
through these environment variables:

```sh
export NEOPROOT_UM_KERNEL=/path/to/linux-bionic
export NEOPROOT_UM_STUB=/path/to/stub_exe
neoproot --backend=um -r /path/to/rootfs -- /bin/sh
```

Build the kernel and stub with `build-bionic.sh` from the linux-um-arm64 tree,
and keep them matched with the `um-init`, `umnet` and `passt` they are used
with; a mismatched set is not supported.

### Binds

Hostfs exposes the selected host directory directly to the guest; it is not a
security isolation boundary. Bind sources already inside that root can be
mapped with `-b host:guest[:ro]`; sources outside it, controlled targets such
as `/proc`, `/sys`, and `/dev`, and unsafe targets are rejected.

Ext4 mode accepts the same `-b host:guest[:ro]` syntax, with host paths as
sources: an ext4 guest has its own root, so there is no "inside the rootfs" to
restrict a source to. The guest init mounts each source -- itself a hostfs
mount, made read-only for `:ro` -- and a directory target must exist, or be
creatable, inside the guest; with `--readonly` the image cannot be modified, so
a target there must already exist. Ext4 mode requires `/um-init` from the
matching UM harness. The supervisor passes the `session-v1` protocol
parameters after mounting the guest's proc filesystem; the init script mounts
the temporary hostfs session at `/run/neoproot` and returns the command status
through that mount.

Binds need an init that knows how to mount them, and that is carried as an
explicit protocol feature rather than assumed:

- The supervisor writes the requested binds to `/run/neoproot/binds`, one
  record per line with tab-separated fields:
  `source<TAB>target<TAB>dir|file<TAB>ro|rw<TAB>name`. `source` is a hostfs
  mount option (a path relative to the kernel's `hostfs=` root), and `name` is
  the file name for a file bind and `-` for a directory bind.
- An init that implements them writes `/run/neoproot/init-features` before it
  runs the command, with `neoproot-init-protocol=2` and `feature=binds`.
- When binds were requested and that declaration is missing, the supervisor
  refuses to report success (`neoproot-um: the guest /um-init does not support
  binds`), and the generated wrapper refuses to run the command at all. A
  guest-side mount failure is reported through
  `/run/neoproot/protocol-error` and printed as `neoproot-um: guest init
  reported: ...`.

On an ext4 root, `-b` therefore requires an init implementing **init protocol
2** with the `binds` feature. An init that predates it -- including a legacy
`um-init` -- makes the run fail with `neoproot-um: the guest /um-init does not
support binds`; the command is not run with its binds silently missing.
[tests/um-init-ext4.sh](tests/um-init-ext4.sh) is the reference implementation
of that init, and [tests/stability-um-backend.sh](tests/stability-um-backend.sh)
installs it into the images it builds. The UM harness's own `um-init` needs the
same two additions before it can be used with `-b` on an ext4 root.

### Network

`--net` gives the guest a real IPv4 network through `umnet` + `passt`: DHCP,
DNS, ICMP and TCP work, and the guest's exit status still comes back through
the session protocol. `umnet` and `passt` are taken from `$PATH`, or from
`NEOPROOT_UM_NET` / `NEOPROOT_UM_PASST`. `--net-addr=` and
`--net-gateway=` override the guest address and gateway (default
`10.0.2.15/24` via `10.0.2.2`). The guest is told a nameserver only when
`--net-dns=<address>` is given with `--net`; by default `umnet` reads the
host's own resolver, and `--net-dns=none` announces none.

`--net` builds the **link**, not the guest's configuration of it: in UML the
guest owns its interfaces, and the DHCP server `passt` runs only answers a
client that asks. So `--net -- /bin/sh` alone comes up with `vec0` down, no
address and no route. Add `--net-auto` to have the guest side configured for
you -- `udhcpc` against the DHCP server first, then a static fallback using
`--net-addr=`/`--net-gateway=` if there is no client or no lease. It never
fails the run: a guest without a working network still starts its shell.
`--net-auto` implies `--net` and needs a hostfs root (an ext4 root is
configured by its own `/um-init`).

```sh
neoproot --backend=um -r /path/to/rootfs --net-auto -- /bin/sh
```

IPv6 is available with `--net-ipv6`, which tells `umnet` to start its second,
IPv6-only `passt` helper:

```sh
neoproot --backend=um -r /path/to/rootfs --net --net-ipv6 -- /bin/sh
```

`--net-ipv6-addr=ADDR[/PLEN]` and `--net-ipv6-gw=ADDR` override the guest's
IPv6 address and gateway (default `fd00::2/64` and `fe80::1`); without them
`umnet`'s own defaults are used, so neoproot passes no value it would have to
guess. `--net-ipv6-dns=ADDR` announces an IPv6 resolver, `--net-ipv6-dns=none`
announces none, and by default `umnet` reads the host's resolver. The IPv6
options are a mode of `--net`, not a network of their own: without `--net` the
run fails with `neoproot-um: --net-ipv6 options require --net` rather than
starting a guest that was promised a stack it does not get.

IPv6 is a second helper rather than a dual-stack one, so that a `passt`
without prepatched IPv6 support -- which loses its IPv6 half on Android
because it opens `NETLINK_ROUTE` -- leaves IPv4 working. That helper needs a
UM harness built with the support; with an older one the run continues with
IPv4 only and says so.

### Console, lifetime and exit status

The guest console is attached to the caller's terminal, and terminal resizes
(SIGWINCH) are forwarded to the guest, so a full-screen tool started this way
sees the right window size.

The terminal is put into raw mode for the duration of the run and restored
afterwards. Without that, the guest's own line editor asks for the cursor
position (`ESC [ 6 n`), the answer is echoed back and `^[[r;cR` appears on
screen; typed input is echoed twice; and control characters are interpreted
by the host terminal before the guest sees them. Pipes and redirected files
are left untouched.

On a hostfs root the guest command runs under a fresh session (`setsid -c`),
so the console is its controlling terminal: `/dev/tty` opens, login shells
stop printing `can't access tty; job control turned off`, and Ctrl-C / Ctrl-Z
reach the guest's foreground process. An ext4 root is owned by its own
`/um-init`, which does the same for the session it starts.

`--timeout=SECONDS` bounds a run (default 120). The supervisor catches
SIGINT/SIGTERM/SIGHUP/SIGQUIT, signals the UML process group with them, cleans
that group up, and returns a meaningful status:

- the guest's own exit status is returned unchanged;
- a timed-out run returns `124`;
- a forwarded signal returns `128 + signal` (`143` for SIGTERM);
- a guest session/init failure returns `125`, and failure to enter the
  requested working directory returns `126`.

A killed or panicking run no longer leaves a `~/.uml/<umid>` runtime directory
behind: the supervisor removes the directory once the kernel it names is gone.

### Current limits

- Hostfs exposes host paths directly and is not a security isolation boundary.
- Start UML mode from an untraced host process; it cannot be nested inside
  PRoot or another sandbox.
- The guest kernel is uniprocessor (no SMP).
- The guest runs aarch64 userland only: the kernel is built with
  `CONFIG_COMPAT` off, so 32-bit ARM binaries do not run.
- Kernel, stub, `um-init`, `umnet` and `passt` must come from matching
  linux-um-arm64 builds.
- Ext4 roots have been exercised at 64 MB and 256 MB; other sizes are untested.

The on-device stability matrix is 18/18 PASS, covering hostfs with and without
`--net`, guest exit status 7 and 125, ext4 with and without `--net`, ext4
`--readonly`, persistent and temporary COW files, read-write and read-only
binds, refusal of a legacy init, a missing bind target, `--timeout`, and SIGTERM.
See [tests/stability-um-backend.sh](tests/stability-um-backend.sh).

## Backend selection and the command separator

When `--backend` is omitted, neoproot uses the default PRoot backend;
`--backend=fast` selects that same path explicitly.
`--backend=auto` prints its choice to stderr and decides in two steps.

First, the prerequisites: it selects the UML backend only when a kernel **and**
a stub are configured -- through `--kernel`/`--stub` (forwarded to the UML
supervisor, or given to `neoproot-um` directly) or a non-empty
`NEOPROOT_UM_KERNEL` / `NEOPROOT_UM_STUB` -- **and** a rootfs is given with
`-r`/`--rootfs`. Otherwise it uses the default PRoot path. It never probes
`PATH` or the filesystem for a kernel: the optional backend only switches
itself on when the caller has set it up. This is an invariant, not a
heuristic: a command that needs a kernel cannot make `auto` start one that is
not configured.

Second, within that limit, the command decides. PRoot stays the default,
because it is the fast path and most work is path translation; UML is chosen
only for a command that needs a real kernel -- a container runtime's control
plane, a mount, a namespace, a block device, a firewall, a packet filter:

```
docker dockerd podman podman-remote nerdctl containerd ctr runc crun
systemd-nspawn machinectl mount umount losetup swapon swapoff
unshare nsenter ip iptables nft bpftool
```

The default set is a list of names, not a guess. To replace it, use
`--auto-um-commands=LIST` (comma-separated basenames) or the equivalent
`NEOPROOT_UM_AUTO_COMMANDS` environment variable; the option wins when both
are given. An empty value means the default set, and `none` means "never
choose a backend by command":

```sh
neoproot --backend=auto --auto-um-commands=none -r /rootfs -- docker
NEOPROOT_UM_AUTO_COMMANDS=mycmd,other neoproot --backend=auto -r /rootfs -- mycmd
```

The command is the basename at the position where the guest command begins,
so `/usr/bin/docker` and `docker` are the same name. Simple wrappers are
looked through -- `env`, `sudo`, `command`, `exec`, `nohup`, `time` and
`stdbuf` -- including their `VAR=value` arguments and the options that take a
separate value, so `env FOO=1 docker` is judged as `docker`.

The boundary is deliberate and worth knowing: `sh -c 'docker run'` is `sh`
and stays on the default backend, because auto reads the argument vector and
does not parse guest shell code. A value packed into a combined short option
of a wrapper (`sudo -Eu root docker`) is skipped as one argument, so that
wrapper is not looked through. Everything else keeps working as before:
`--backend=fast`, `--backend=um` and the default ignore both the list and the
command.

Both outcomes are reported, so `auto` is never silent about a downgrade:

```
neoproot: --backend=auto selected the um backend (command 'docker' needs a real kernel)
neoproot: --backend=auto selected the default backend
neoproot: --backend=auto would use the um backend for 'docker', but no kernel/stub/rootfs is configured; using the default backend
```

The `--` separator means the same thing on every backend:

```sh
neoproot -r /path/to/rootfs -- /bin/sh
```

The CLI consumes the separator once and does not forward it, so a backend that
does not know it never sees it, and the same command line can be reused with a
different `--backend` -- which is what `auto` needs. The UML dispatcher
restores the delimiter for the UML supervisor, whose own syntax requires it.
Omitting `--` also works, since the CLI already knows where the guest command
begins.

## Why there is no per-syscall hybrid

It is tempting to ask for a mode that "runs normal syscalls through neoproot and
sends the rest to UML". That cannot work, for a structural reason: the two
backends operate at different levels.

- PRoot is a tracer. The guest process is a host process; `ptrace` (and, for
  selected calls, seccomp USER_NOTIF) stops it at the syscall boundary, and
  neoproot rewrites paths, IDs and results before the host kernel runs the call.
- In UML mode the guest is a real kernel. The guest's syscalls are serviced
  inside the UML kernel and never appear as the same syscall on the host, so
  there is no intercepted host syscall to hand to neoproot or to route
  selectively.

A per-syscall split would therefore need one side to see calls it cannot see, or
a kernel-level interface that does not exist today. The supported granularity is
per invocation, or per process tree: choose a backend when the command starts.
That is exactly what `--backend=auto` does. Making this finer would require
deeper kernel changes and is outside neoproot.

This is not "not implemented yet": the architecture does not admit it, so it
should not be proposed again as a backlog item.

## Performance evidence

Measured on a Termux aarch64 device, Arch Linux ARM container, identical output in every mode. Stat-heavy work is what a container spends its time on, and that is what neoproot removes:

**`du -As /usr` (whole-tree metadata walk, output `4007438` in all modes)**

| Mode | Time | vs plain ptrace |
|------|------|-----------------|
| Plain ptrace path | 33.3 s | — |
| `--seccomp-notify` only | 31.2 s | 1.07x |
| **`--stat-shim` + `--seccomp-notify`** | **14.4 s** | **2.32x** |

Later releases cut the remaining ptrace stops further (`fcntl` is now traced only for the two fd-duplication commands), taking the same run from 15.7 s to 13.1 s, and 11-12 s on the device after deployment.

**Single `stat` call (µs/op, plain / notify / shim)**

| Call | plain | notify | shim |
|------|-------|--------|------|
| absolute path | 288.7 | 96.6 | **8.1** |
| dirfd-relative | 308.5 | 114.4 | **4.4** |
| `AT_FDCWD`-relative | 203.8 | 90.9 | 92.9 |
| raw `syscall(SYS_statx)` | 324.5 | 106.5 | **10.4** |

`AT_FDCWD`-relative names keep the tracer in the loop on purpose: the guest's cwd is virtual, so the shim re-issues them through the `--seccomp-notify` channel instead of guessing. That costs about the same as the plain path (103 vs 111 µs) while staying correct.

Compilation is unaffected (80-file `cc -O0` build: 18.2 / 18.5 / 18.3 s across the three modes); the wins are in process startup, parsing and header I/O.

The older sysbench workload, for reference:

| Load | vs official PRoot |
|------|-------------------|
| Low (primes <= 10000) | On par (within noise) |
| Medium-high (50000) | **Ahead by 2.9%** |
| Extreme (100000) | **Ahead by 7.2%** |

When reporting a result, include the device/SoC, Android and Termux versions, exact command, baseline version, and repeated measurements. Use the [performance report form](https://github.com/Raymer8639/neoproot/issues/new?template=performance_report.yml) so results can be compared.

## Build notes

- Default target: `-march=armv8.2-a+fp16+dotprod+lse+rcpc+simd+crc+crypto` (override with `MARCH=`).
- Portable releases use `-march=armv8-a -mtune=generic`; this relaxes CPU instructions but does not promise libc or kernel compatibility.
- Link options include ThinLTO, section garbage collection, identical-code folding, RELRO/NOW, and stripping.
- The build depends on `libtalloc` (Termux package: `talloc`). `upx` is optional.

## Project lineage

neoproot was renamed from `proot-scicat` / `uproot` and continues to track useful fixes from [termux/proot](https://github.com/termux/proot). The original implementation is [proot-me/proot](https://github.com/proot-me/proot); the direct fork ancestor is [scicat-team/proot-scicat](https://gitee.com/scicat-team/proot-scicat). See [CHANGELOG.md](CHANGELOG.md) for version history and attribution.

## Contributing and support

Maintainers may use AI tools to assist with research, drafting, coding, or review.
AI output is treated as untrusted input: maintainers remain responsible for
reviewing and testing changes before merge. See [CONTRIBUTING.md](CONTRIBUTING.md)
for expectations when submitting AI-assisted work.

- [Report a bug](https://github.com/Raymer8639/neoproot/issues/new?template=bug_report.yml)
- [Request a feature](https://github.com/Raymer8639/neoproot/issues/new?template=feature_request.yml)
- [Ask a usage question](https://github.com/Raymer8639/neoproot/discussions)
- Read [help.md](help.md), [SUPPORT.md](SUPPORT.md), [CONTRIBUTING.md](CONTRIBUTING.md), and [SECURITY.md](SECURITY.md)

## Versioning

Versions follow the termux/proot style. Releases before 2026-08-15 used the historical `-scicat` suffix; `v5.7.3` and later releases use the `neoproot` name without that suffix.

## License

GPLv2. The canonical text is in [LICENSE](LICENSE); [COPYING](COPYING) carries the original PRoot/CARE copyright notice from upstream.
