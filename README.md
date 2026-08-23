[English](README.md) | [简体中文](README.zh-CN.md)

# neoproot (binary and project share the name; formerly proot-scicat / uproot)

> A next-generation semi-native lightweight container: faster, more stable and smaller than the official PRoot, optimized for **ARM64 / Android (Termux)**.

[![CI](https://github.com/Raymer8639/neoproot/actions/workflows/ci.yml/badge.svg)](https://github.com/Raymer8639/neoproot/actions/workflows/ci.yml)
![Platform](https://img.shields.io/badge/platform-ARM64%20%2F%20Android-blue)
![Language](https://img.shields.io/badge/C%2FC%2B%2B-C23%20%2F%20C%2B%2B23-orange)
![License](https://img.shields.io/badge/license-GPLv2-green)
![AI](https://img.shields.io/badge/AI-assisted-100%25-purple)

> **🤖 AI statement: all code in this project (including every modification, fix and optimization made during maintenance) was written/reviewed with AI assistance.**

## Upstream relationship (three-way lineage)

```
proot-me/proot (original PRoot, unmaintained)
        │
        ▼ fork: C23/C++23 + full ARMv8.2 performance + trimmed compatibility
gitee.com/scicat-team/proot-scicat (uproot, stale since 2026-05)  ← direct ancestor (fork base)
        │
        ▼ took over maintenance: fixes + performance + compatibility (42+ commits)
Raymer8639/neoproot (this project)
        ▲
        │ keeps tracking & backporting fixes (e.g. link2symlink proc-fd name substitution, 7ff389a1)
github.com/termux/proot (actively maintained)  ← lineage origin / tracking target
```

- **Original PRoot**: [proot-me/proot](https://github.com/proot-me/proot) (effectively unmaintained upstream)
- **Direct ancestor (former upstream)**: [gitee.com/scicat-team/proot-scicat](https://gitee.com/scicat-team/proot-scicat) (**uproot**, extreme-performance C23/C++23 fork; stale since 2026-05)
- **Lineage origin / tracking target**: [github.com/termux/proot](https://github.com/termux/proot) (actively maintained by the Termux team; this project targets the ARM64/Termux use case and shares its origin and ecosystem)
- **This project**: maintained since 2026-02 on top of uproot, **under active development**; fixes and optimizations are original to this project, with fixes backported from termux/proot as needed

## Key features

- ✅ Built-in automatic high-priority scheduling (`setpriority(-20)`) — stronger CPU resource affinity without ROOT
- ✅ Fixes "legacy bugs" such as Chinese VNC exit hangs and logout requiring background switching
- ✅ Eliminates the `signal 11` warning on process exit; adds process liveness checks
- ✅ Max latency down 40%+, smoother; fairer threads, less jitter
- ✅ Modern lean C23/C++23 architecture, trading generic compatibility for full ARMv8.2 performance
- ✅ Built-in `neoproot.c` main program: automatic Termux environment initialization (wake-lock, fd limit, LD_* cleanup) — no manual startup flags needed
- ✅ Removed the upstream-forked path translation thread pool (cond_wait round-trip overhead): on-device syscall handling now matches the official PRoot (lstat 304µs/call vs original 293–312µs), fixing jank in high-frequency operations like nvim
- ✅ link2symlink hard-link emulation fully compatible with pnpm / tsc (tsgo) — the materialization mechanism plus /proc/&lt;pid&gt;/fd/&lt;fd&gt; name substitution (backported from termux/proot 7ff389a1) resolves tsgo's O_PATH+readlink real-path probing (TS2307/TS6054/panic all solved)

## Performance

From sysbench high-load tests (on par with the official PRoot at low load, no extra overhead):

| Load | vs official PRoot |
|------|-------------------|
| Low (primes ≤ 10000) | On par (within noise) |
| Medium-high (50000) | **Ahead by 2.9%** |
| Extreme (100000) | **Ahead by 7.2%** |

## Requirements

- ARM64 Linux or Termux (aarch64 / arm64); the primary runtime target is
  Android/Termux.
- **x86_64 is unsupported.** Generic architecture support is deliberately
  trimmed.

## Quick start

### Option 1: use a released binary (recommended)

Download `neoproot` from [Releases](https://github.com/Raymer8639/neoproot/releases)
for the optimized ARM64 build, or `neoproot-portable` for the ARMv8-A portable
build (`-march=armv8-a -mtune=generic`). Verify the file before installing it:

```sh
sha256sum neoproot
chmod +x neoproot
mv neoproot $PREFIX/bin/
```

Compare the SHA256 output with the checksum published on the release page.

### Option 2: build from source inside Termux

```sh
pkg install clang make llvm binutils talloc
git clone https://github.com/Raymer8639/neoproot.git
cd neoproot
sh build.sh install     # builds and installs to $PREFIX/bin
```

> `sh build.sh` builds `src/neoproot`; `sh build.sh install` also installs it as
> `$PREFIX/bin/neoproot`. `upx` is optional and shrinks the binary.
> You can also use `make -C src neoproot MARCH="-march=native"` to target your CPU's instruction set.

## Using a container

```sh
# Enter a Debian/Ubuntu container as root (requires a prepared rootfs)
neoproot -0 -r /data/data/com.termux/files/home/rootfs \
    -b /dev -b /proc -b /sys -b /sdcard \
    /usr/bin/env -i HOME=/root TERM=${TERM} PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    /bin/bash --login
```

Usage is identical to the official PRoot, but **no** manual `unset LD_PRELOAD LD_LIBRARY_PATH LD_BIND_NOW` is needed — the `neoproot` main program handles it automatically.

## Documentation

- [Change history](CHANGELOG.md)
- [Usage and FAQ](help.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [Support](SUPPORT.md)

## Versioning

Version numbers follow the termux/proot style (e.g. `5.1.107.90`). Releases before 2026-08-15 kept the historical `-scicat` suffix (e.g. `v5.7.2-scicat`); starting with `v5.7.3` (2026-08-15) the suffix is dropped. See [CHANGELOG.md](CHANGELOG.md) for the change history.

## Build notes

- Default compile target: `-march=armv8.2-a+fp16+dotprod+lse+rcpc+simd+crc+crypto` (overridable via `MARCH=`); the portable release target is `-march=armv8-a -mtune=generic`
- Link options: `-flto=thin`, `--gc-sections`, `--icf=all`, RELRO/NOW, stripped
- Dependency: `libtalloc` (Termux package name `talloc`)

## Maintenance

This project is community-maintained. Welcome to:

- Report issues via [Issue](https://github.com/Raymer8639/neoproot/issues)
- Submit PRs for bug fixes and performance improvements
- Discuss at [Discussions](https://github.com/Raymer8639/neoproot/discussions)

## License

GPLv2, see [COPYING](COPYING).
