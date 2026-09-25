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

- [Report a bug](https://github.com/Raymer8639/neoproot/issues/new?template=bug_report.yml)
- [Request a feature](https://github.com/Raymer8639/neoproot/issues/new?template=feature_request.yml)
- [Ask a usage question](https://github.com/Raymer8639/neoproot/discussions)
- Read [help.md](help.md), [SUPPORT.md](SUPPORT.md), [CONTRIBUTING.md](CONTRIBUTING.md), and [SECURITY.md](SECURITY.md)

## Versioning

Versions follow the termux/proot style. Releases before 2026-08-15 used the historical `-scicat` suffix; `v5.7.3` and later releases use the `neoproot` name without that suffix.

## License

GPLv2. The canonical text is in [LICENSE](LICENSE); [COPYING](COPYING) carries the original PRoot/CARE copyright notice from upstream.
