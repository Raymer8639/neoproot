# Bwrap Oldroot Bindings Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preserve lower bindings covered by emulated mounts so bwrap can access original sources through `put_old` after pivot.

**Architecture:** `Binding` gains a link to the binding it covers. Binding replacement saves that link without changing normal lookup. Pivot uses the underlying binding when the exact new-root mount is moved, and umount promotes the underlying binding.

**Tech Stack:** C23, talloc, shell regression tests, bubblewrap.

---

### Task 1: Add the failing bwrap oldroot regression

**Files:**
- Create: `tests/test-bwrap-oldroot-bind.c`, `tests/test-bwrap-oldroot-bind.sh`
- Modify: `tests/GNUmakefile`

- [x] Create a deterministic mount/umount/pivot probe with an explicit host-to-guest `/tmp` bind; it verifies the bind is hidden by tmpfs, restored by umount, then reachable as `/oldroot/tmp/source` after pivot.
- [x] Run it against the deployed pre-fix binary and confirm the umount assertion fails because the covered binding was discarded.

### Task 2: Preserve mount underlays

**Files:**
- Modify: `src/path/binding.h`
- Modify: `src/path/binding.c`
- Modify: `src/syscall/enter.c`

- [x] Add the covered-binding relation when replacing an exact guest mount target, with a talloc reference to preserve its lifetime.
- [x] Restore the covered binding on emulated umount.
- [x] During pivot, expose the exact new-root binding's covered layer below `put_old`, not the new root itself.

### Task 3: Verify behavior

**Files:**
- Test: `tests/test-bwrap-oldroot-bind.sh`
- Test: `tests/test-mountinfo-tmpfs.c`
- Test: `tests/test-security-regressions.sh`

- [x] Build with container clang and Termux clang; both report `process_vm = yes, seccomp_filter = yes`.
- [x] Run the deterministic oldroot, tmpfs/mountinfo, security, procfd and link2symlink-dirent regressions on Termux.
- [x] Run the real `/usr/bin/bwrap` command on Termux with the full daily startup bindings, then atomically deploy and repeat it through the formal binary.
