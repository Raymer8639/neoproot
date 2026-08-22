# bwrap proc dirfd inheritance design

## Problem

Bubblewrap opens /proc before pivot_root, retains the directory fd, and later
performs openat(proc_fd, "self/mountinfo", ...). Neoproot must preserve the
guest view of this special lookup across bwrap proc remounts and pivot_root.

A raw relative pass-through is insufficient: it reads the host mount table,
which does not include neoproot virtual /oldroot. Conversely, the ordinary
relative-dirfd translation used to detranslate a real /proc fd to
/oldroot/proc after pivot_root, so a later openat reached a stale guest path.

## Implemented approach A

Recognize only this narrow case:

1. the syscall has a non-AT_FDCWD directory fd;
2. that fd resolves to host /proc; and
3. the relative path is self/mountinfo or thread-self/mountinfo.

translate_path2() redirects that lookup to the existing virtual
/proc/<tracee-pid>/mountinfo generator. The generator retains the virtual
/oldroot entry and uses a stable tracee pid rather than the bwrap child pid.

In the ordinary relative-dirfd branch, an fd resolving exactly to host /proc
remains the guest /proc base after pivot_root. This deliberately applies to
every relative suffix under that real proc fd: their normal proc-path handling
is preserved, but only the two mountinfo names are redirected to a virtual
file. Absolute paths and directory fds resolving anywhere except /proc retain
their existing behavior.

## Verification

tests/test-bwrap-proc-dirfd.{c,sh} deterministically creates the relevant
tmpfs, bind, pivot_root, and proc-remount sequence. It then verifies that an
inherited /proc fd can open self/mountinfo and that the virtual mountinfo
contains /oldroot. Before the redirect, the probe failed with:
inherited mountinfo misses /oldroot.

The Termux smoke command runs bwrap as an application inside one candidate
neoproot instance; it never launches neoproot inside neoproot.

On 2026-08-22, a Termux-built candidate passed the deterministic probe,
covered-binding oldroot probe, security, link2symlink-dirent, and mountinfo
regressions. It also passed the exact static Codex bwrap smoke command three
consecutive times over SSH. The formal Termux binary was not replaced.
