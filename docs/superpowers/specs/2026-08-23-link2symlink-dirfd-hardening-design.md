# Link2symlink Descriptor Hardening Design

## Goal

Prevent a tracee from redirecting link2symlink backing-file writes outside the
guest rootfs by replacing `PROOT_L2S_DIR` with a symlink during a session, while
preserving neoproot's existing materialization, legacy-chain, and cleanup
behavior.

## Root Cause

The link2symlink extension performs host-side `access`, `readlink`, `rename`,
`symlink`, `unlink`, and file-open operations on paths derived from
`PROOT_L2S_DIR`. Those paths are intentionally outside normal tracee path
translation. The current code resolves the directory pathname for each raw
syscall. A tracee can therefore remove the checked directory and replace it
with a symlink before the next operation. The next pathname lookup follows the
replacement and writes backing data at the attacker-selected destination.

## Design

Add cached link2symlink directory state in
`src/extension/link2symlink/link2symlink.c`:

- Store the normalized `PROOT_L2S_DIR` string and its length once.
- Open the configured directory on first use with
  `O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`.
- Keep the descriptor for the extension lifetime. The descriptor identifies
  the inode that was checked, even if the tracee later changes the pathname.
- For a direct child of the configured directory, return the cached descriptor
  and basename. For paths outside that directory, keep the existing pathname
  behavior used by unset `PROOT_L2S_DIR`, same-directory legacy chains, and
  intermediate paths outside the backing directory.
- If a path is inside the configured directory but the directory cannot be
  opened, return the underlying error and never fall back to the pathname.

Wrap the raw operations used by link2symlink so they select descriptor-relative
syscalls only for direct backing-directory entries:

- `access` -> `faccessat`
- `readlink` -> `readlinkat`
- `symlink` -> `symlinkat`
- `unlink` -> `unlinkat`
- `rename` -> `renameat`, using `AT_FDCWD` for the side outside the backing
  directory

Use these wrappers in link creation, link-count decrement/rename, cleanup, and
the existing `my_readlink` path. Keep symlink payloads unchanged: they remain
absolute host paths because canonicalization depends on that representation.

Correct the `ENAMETOOLONG` calculation to include the normalized backing
directory length, generated prefix, basename, numeric suffix, and final suffix.

## Compatibility and Error Handling

- No `PROOT_L2S_DIR`: preserve the existing path-based behavior.
- `PROOT_L2S_DIR=/`: preserve the existing root-path behavior; do not treat it
  as a configurable backing directory.
- Existing backing files and symlink payloads remain valid across upgrades.
- A pre-existing symlink at the configured backing-directory pathname is
  rejected by `O_NOFOLLOW` instead of followed.
- A directory replaced after the descriptor is opened cannot redirect future
  operations; operations continue against the originally opened inode.
- `O_CLOEXEC` prevents the implementation descriptor from leaking into an
  executed tracee.

## Regression Test

Add `tests/test-8d3c07f5.sh` using the existing `PROOT` convention. The test
will create a rootfs containing BusyBox, configure a separate `.l2s` directory,
replace `/.l2s` inside the guest with a symlink to an outside directory, and
create a hard link. It passes only when the replacement was attempted and the
outside directory remains empty. Missing `mcookie` or BusyBox produces the
existing suite's skip status `125`.

Add the test to `tests/GNUmakefile` and the ARM64 CI regression list so local
and CI coverage exercise the same security contract.

## Performance

The configured-directory path pays one descriptor open on first use and a
short path-to-basename check per wrapped operation. Subsequent operations avoid
re-resolving the backing-directory pathname and use descriptor-relative syscalls.
The change is expected to be neutral or slightly faster for link2symlink-heavy
workloads and has no effect on ordinary syscalls outside this extension. No
performance claim will be made without a benchmark; correctness and race
resistance are the acceptance criteria.

## Non-goals

- Do not replace neoproot's custom materialization strategy.
- Do not change link2symlink symlink contents or legacy-chain interpretation.
- Do not refactor unrelated path translation or syscall code.
- Do not broaden the patch to all arbitrary host paths; protect the backing
  directory boundary where the vulnerability exists.
