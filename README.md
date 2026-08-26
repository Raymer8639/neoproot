[English](README.md) | [简体中文](README.zh-CN.md)

# neoproot

An ARM64-focused PRoot fork for Android/Termux containers. neoproot targets developers who run Debian/Ubuntu userspaces on phones and tablets, especially Node.js, pnpm, TypeScript, nvim, bwrap, and other syscall-heavy workflows.

Current stable binaries: [latest release](https://github.com/Raymer8639/neoproot/releases/latest).

[![CI](https://github.com/Raymer8639/neoproot/actions/workflows/ci.yml/badge.svg)](https://github.com/Raymer8639/neoproot/actions/workflows/ci.yml)
![Platform](https://img.shields.io/badge/platform-ARM64%20%2F%20Android-blue)
![Language](https://img.shields.io/badge/C%2FC%2B%2B-C23%20%2F%20C%2B%2B23-orange)
![License](https://img.shields.io/badge/license-GPLv2-green)

## Start in Termux

Use a release binary when it runs on your device; otherwise build the Termux-native binary:

```sh
pkg install clang make llvm binutils pkg-config talloc
git clone https://github.com/Raymer8639/neoproot.git
cd neoproot
sh build.sh install
```

The installer places `neoproot` in `$PREFIX/bin`. For ARM64 Linux, download `neoproot` or the lower-instruction-set `neoproot-portable` from [Releases](https://github.com/Raymer8639/neoproot/releases), verify its SHA256, and install it in your `PATH`.

## Why neoproot

- Automatic Termux host setup: wake-lock, file-descriptor limits, and `LD_*` cleanup are handled by the `neoproot` launcher.
- link2symlink hard-link emulation works with pnpm and TypeScript/tsgo workflows that probe real paths through `/proc/<pid>/fd/<fd>`.
- High-frequency path operations avoid the fork's removed translation-thread-pool overhead, keeping nvim and package-manager workflows responsive.
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

The table below is from the repository's sysbench workload on an ARM64 device. Results vary with SoC, thermal state, rootfs, and workload; treat them as a reproducible starting point, not a universal guarantee.

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

GPLv2; see [COPYING](COPYING).
