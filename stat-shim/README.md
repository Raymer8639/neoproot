# neoproot stat-shim

An **optional, in-process fast path for path-stat syscalls**.

neoproot normally intercepts `newfstatat` / `fstatat64` / `statx` (the syscalls
behind `stat(2)`, `lstat(2)`, `statx(2)` and every libc/coreutils use of them),
translates the path and rewrites the result. With `--seccomp-notify` each such
call becomes a `SECCOMP_RET_USER_NOTIF` round trip to the tracer, which costs
tens of microseconds per call.

`libstatfast.so` is an `LD_PRELOAD` library that performs those two transforms
*directly in the guest process*:

1. **guest -> host path translation** from the binding map neoproot exports;
2. **fake_id0 ownership disguise**.

When `--stat-shim=<lib>` is given, the shim marks its own translated raw
syscalls in an upper register word and the seccomp filter allows only those
fast-path calls through. Direct raw stat syscalls from applications are sent
through USER_NOTIF so guest paths are still translated, and
injects the library with `LD_PRELOAD` **only in the first guest process**
(after `fork`, before `execvp`). The tracer itself must not carry that
variable: it is a Termux/bionic binary, and a later host re-exec (sysvipc
shm-helper's `execl("/proc/self/exe")`) would make Android's linker look up
the guest-ABI path and abort with `CANNOT LINK EXECUTABLE "neoproot"`. The
result is a large speed-up for `stat`-heavy work such as `du`, `find`,
`tar`, `git status`, and file-tree walking in general.

link2symlink (L2S) result disguise needs the real symlink chain, which the
tracer also intercepts, so it cannot be reproduced in-process. Instead the
seccomp filter routes untagged direct stat syscalls to `USER_NOTIF`; the shim
uses its sentinel bit `NEOPROOT_STAT_SHIM_FLAG` (`0x40000000`) when a raw result
needs tracer-owned L2S/fake_id0 handling. Whenever a raw result is a symlink (or
an `.l2s.*` storage name) the shim re-issues the call with that sentinel.
Ordinary wrapper-based regular-file stats use the tagged fast path. This
requires `--seccomp-notify`; without it, `--stat-shim` together with
`--link2symlink` is refused (the shim is disabled and a warning is printed)
rather than returning wrong link types or link counts.

## Requirements

* neoproot built with this directory's shim support (the flag, the BPF rule and
  the `NEOPROOT_STAT_SHIM_FLAG` handling in `src/syscall/`).
* A preloadable library built for the **guest ABI**, not the Termux host. For
  the common Arch/glibc aarch64 rootfs that is an aarch64 glibc compiler.
* The library must be reachable from the guest namespace and loadable by the
  guest dynamic loader (a glibc `.so` for a glibc guest, a musl `.so` for a
  musl guest, ...).

## Build

From a shell **inside the guest** (simplest, matches the guest ABI exactly):

    sudo pacman -S --needed base-devel      # or: apt install build-essential
    cd /path/to/neoproot/stat-shim
    CC=gcc ./build.sh                       # writes ./libstatfast.so + ./shim_test
    ./shim_test                             # local self-test, no proot needed

Cross-compiling from an x86_64 host works too:

    CC=aarch64-linux-gnu-gcc ./build.sh /tmp/out

`build.sh` accepts an output directory as its first argument and only requires a
C compiler and `-shared` support. The resulting `libstatfast.so` is the only
artifact to ship; `shim_test` is for native builds.

## Install

The convention is a dedicated folder inside the container rootfs,
`/opt/neoproot/stat-shim/`:

    # from the host, into the rootfs of the container:
    install -Dm755 libstatfast.so \
        $PREFIX/var/lib/proot-distro/containers/<name>/rootfs/opt/neoproot/stat-shim/libstatfast.so

    # or from inside the guest:
    sudo install -Dm755 libstatfast.so /opt/neoproot/stat-shim/libstatfast.so

Because the folder lives in the rootfs, it is part of the container and survives
unless the rootfs is recreated.

## Usage

Add the option to the neoproot command line, next to `--seccomp-notify`:

    neoproot \
        --seccomp-notify \
        --link2symlink \
        --stat-shim=/opt/neoproot/stat-shim/libstatfast.so \
        --change-id=10374:10374 \
        --rootfs=/path/to/rootfs \
        ... \
        /usr/bin/zsh -l

The shim is **off by default**: omitting `--stat-shim` changes nothing, so this
feature carries no regression risk for existing setups.

`--seccomp-notify` is **required** with `--stat-shim`. The shim re-issues three
shapes of request to the tracer through that flag-gated USER_NOTIF channel: a
relative name at `AT_FDCWD` (the tracee's cwd is virtual), a path whose
components are symlinks to guest absolute paths, and the link2symlink result
disguise. Without the channel the stat syscalls stay untraced and those paths
would silently return host-resolved results, so neoproot prints a warning and
runs with the normal traced stats instead.

### Environment (set by neoproot, read by the library)

| Variable | Meaning |
| --- | --- |
| `NEOPROOT_STATSHIM_ROOTFS` | Rootfs prefix, the fallback translation for paths not covered by a bind. |
| `NEOPROOT_STATSHIM_BINDS` | Serialized binding map, `guest<TAB>host` per line; longest guest prefix wins. |
| `NEOPROOT_STATSHIM_UID_REAL` / `_FAKE` | fake_id0 uid mapping. |
| `NEOPROOT_STATSHIM_GID_REAL` / `_FAKE` | fake_id0 gid mapping. |
| `NEOPROOT_STATSHIM_L2S` | Set when link2symlink is enabled. |
| `NEOPROOT_STATSHIM_NOTIF` | Set when the flag-gated USER_NOTIF fallback is available (`--seccomp-notify`). |
| `NEOPROOT_STATSHIM_DEBUG` | If set, print each intercepted call and its raw result to stderr. |

None of these are required in the environment of a normal guest program; they
are set by the tracer on the tracee before `execve`.

## Performance

Measured on the reference device and container (Arch aarch64 glibc, release
build, `--seccomp-notify --link2symlink`), shim `4540d069`, 20000 iterations:

| Workload | OFF (traced) | ON (shim) | Speed-up |
| --- | --- | --- | --- |
| `fstatat`, absolute path | 160.7 us/op | 7.18 us/op | ~22x |
| `fstatat`, dirfd-relative | 195.1 us/op | 2.71 us/op | ~72x |
| raw `newfstatat` (no libc) | 168.8 us/op | 1.05 us/op | ~161x |
| `du -As /usr` | 29.2 s | 16.6 s | ~1.76x (previous baseline) |
| `du -As /usr` live retest | 62.72 s | 21.35 s | ~2.94x |
| 50000 x regular-fd `fstat` | 352.743 us/op | 335.235 us/op | ~1.05x (glibc internal ABI likely bypasses public wrapper) |
| `/usr` `find -xdev -type f` | 36.11 s | 23.86 s | ~1.51x; 81419 paths, identical SHA256 |
| 400 x `/bin/true` | 5.62 s | 6.27 s | -11.5% (preload tax) |

Re-measured on the same device after the glibc-ABI fix (shim `f9a6e98a`,
which interposes `stat64`/`lstat64`/`fstat64`/`fstatat64` and `__xstat*`):

| Workload | OFF (traced) | ON (shim) | Notes |
| --- | --- | --- | --- |
| `du -As /usr` | 31.04 s | 16.88 s | ~1.84x; output hash identical |
| `/usr` `find -xdev -type f` | 20.28 s | 17.83 s | 81419 paths, identical SHA256 |
| `i3 -C ~/.config/i3/config` | exit 0 | exit 0 | config now found through the shim |

The earlier `i3` "unable to find configuration file" regression was a glibc
ABI gap: `stat()` is inlined to `__stat64`/`stat64` in the header, so the
public-symbol-only preload never saw the call and the raw syscall went out
untranslated. Covering the historical `*64`/`__*stat*` entry points fixes it.

The same glibc-internal-call issue affected `eaccess()`: glibc calls its own `stat()` and then `access()`, which need opposite path forms under the shim. The preload now implements `eaccess()` with `faccessat2(AT_EACCESS)` on the guest path; the access syscall remains tracer-translated. This requires a Linux 5.8+ kernel with `faccessat2` (the shim returns `ENOSYS` if it is unavailable). It fixes GNU make 4.4 direct recursive spawns without changing the `fstatat`/`statx` fast path. The manual reproduction is `make -f tests/recursive-make.mk all` under `--stat-shim`; the `shell` target is the shell-mediated control.

The per-process `LD_PRELOAD` cost shows up as a small regression on
process-spawn-dominated workloads; the win dominates on anything that walks a
file tree.

## Self-test

`./build.sh && ./shim_test` builds a throw-away rootfs, points the shim at it
through the same environment the tracer uses, and checks rootfs translation,
bind translation, fake_id0 and the no-fallback behaviour. The L2S flag-gated
path is covered by the ON/OFF container A/B (`docs/stat-shim-exp/`).

## Limitations

* `fstatat`/`fstatat64`/`statx` (`stat`, `lstat`) and glibc historical `stat64`/`__xstat*` entry points are accelerated; `fstat` is
  accelerated only when link2symlink is disabled (the CLI keeps it traced under
  L2S so fd-derived link metadata remains correct). `faccessat`/`faccessat2`
  and `statfs`/`statvfs` remain tracer-handled because their current translation
  and compatibility paths need further semantic and live-kernel validation.
* The shim interposes both the public entry points and libc's variadic
  `syscall()` (libuv issues `statx` through it), so software that calls the stat
  syscalls itself is translated too. Only code that traps into the kernel
  without libc at all (a hand-written `svc` stub) can bypass the preload; such a
  call is not traced either, because `--stat-shim` removes those syscalls from
  the seccomp filter.
* Two shapes of path need the tracer rather than the local fast path, and are
  re-issued through the flag-gated USER_NOTIF channel: a relative name at
  `AT_FDCWD` (the guest cwd is virtual) and any path whose raw host resolution
  fails because a component is a symlink to a guest absolute path (fnm stores
  `fnm_multishells/<id> -> /home/...`). Because of these fallbacks (and the L2S
  disguise) `--stat-shim` requires `--seccomp-notify`: without the channel
  neoproot refuses to enable the shim. Should the library ever be loaded with
  that channel missing, the wrappers still fall back to the guest cwd reported
  by `getcwd()` (relative names) and to the raw result (everything else).
* The bind table is a snapshot taken at launch. The shim caches the last non-root bind prefix per thread, so repeated stats within one bind avoid the full prefix scan.
* The sentinel bit `0x40000000` must stay free in the `AT_*` flag space; the
  kernel never sees it (the tracer clears it before emulating and never
  `CONTINUE`s a sentinel call).
