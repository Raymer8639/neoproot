# Link2symlink Descriptor Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the `PROOT_L2S_DIR` symlink-redirection race in neoproot while preserving existing link2symlink materialization and legacy-chain behavior.

**Architecture:** Cache a normalized backing-directory pathname and an `O_NOFOLLOW` directory descriptor in the link2symlink extension. Route only direct children of the configured backing directory through descriptor-relative helpers; leave unset/root/legacy path modes on their current behavior. Add the upstream security regression to the local and ARM64 test gates.

**Tech Stack:** C23, POSIX `*at` filesystem syscalls, existing PRoot extension callbacks, POSIX shell tests, GNU Make, GitHub Actions.

---

### Task 1: Add the regression test first

**Files:**
- Create: `tests/test-8d3c07f5.sh`
- Modify: `tests/GNUmakefile:10-13`

- [ ] **Step 1: Add the failing escape regression**

Create a shell test that exits `125` when `mcookie` or `busybox` is unavailable, creates `rootfs/.l2s` and an outside directory, copies BusyBox into the rootfs, then runs:

```sh
PROOT_L2S_DIR="$rootfs/.l2s" "$PROOT" -l --rootfs="$rootfs" \
  /bin/busybox sh -c '
    echo escaped > /original
    /bin/busybox rm -rf /.l2s
    /bin/busybox ln -s "$outside" /.l2s
    /bin/busybox test -L /.l2s && echo READY
    /bin/busybox ln /original /link
  '
```

The script must require the marker `READY`, count entries in the outside directory, clean its temporary directory, and exit `1` when the outside count is nonzero. Pass the outside path through the single-quoted shell body exactly as the upstream test does so the tracee cannot alter the host-side assertion.

- [ ] **Step 2: Run the new test against the current binary**

Run:

```sh
chmod +x tests/test-8d3c07f5.sh
PROOT=../src/neoproot sh tests/test-8d3c07f5.sh
```

Expected before the fix: the test reaches `READY` and exits `1` because the current path-based raw syscalls create backing files in the outside directory. If the environment lacks `mcookie`, BusyBox, or a usable real PRoot runtime, record the skip/environment failure and run the same test in CI after implementation.

- [ ] **Step 3: Register the regression in the local test list**

Append `test-8d3c07f5.sh` to `TEST_SCRIPTS` in `tests/GNUmakefile`, preserving the existing `sh "$$script"` invocation so executable bits are not required.

- [ ] **Step 4: Commit the red test**

```sh
git add tests/test-8d3c07f5.sh tests/GNUmakefile
git commit -m "test: cover link2symlink directory redirection"
```

### Task 2: Add cached descriptor-relative helpers

**Files:**
- Modify: `src/extension/link2symlink/link2symlink.c:1-80`

- [ ] **Step 1: Add backing-directory state and normalization**

Add `l2s_directory[PATH_MAX]`, `l2s_directory_length`, `l2s_directory_fd = -1`, and `l2s_directory_known`. Implement `get_l2s_directory()` to cache `PROOT_L2S_DIR`, reject an empty value, strip trailing slashes except for `/`, and reject values whose length is at least `PATH_MAX`. Return false for unset or `/` so existing root-path behavior remains unchanged.

- [ ] **Step 2: Add descriptor acquisition and direct-child classification**

Implement `open_l2s_directory()` using:

```c
open(l2s_directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
```

Return `-errno` on failure. Implement `l2s_entry(path, &dir_fd, &name)` so it selects the cached descriptor only when `path` is exactly one component below the configured directory. Paths outside that direct-child boundary retain `dir_fd = -1` and the original path. A path inside the configured directory must return an error when the directory cannot be opened rather than falling back to a path lookup.

- [ ] **Step 3: Add wrappers with the existing return conventions**

Implement helpers for `access`/`faccessat`, `readlink`/`readlinkat`, `symlink`/`symlinkat`, `unlink`/`unlinkat`, and `rename`/`renameat`. For `rename`, use `AT_FDCWD` for a side outside the configured directory. Preserve `errno` behavior expected by the existing callers.

- [ ] **Step 4: Make the helper unit compile**

Run:

```sh
make -C src clean
make -C src -j4 neoproot CC=clang CXX=clang++
```

Expected: the descriptor helper declarations compile without changing runtime behavior yet.

- [ ] **Step 5: Commit the helper layer**

```sh
git add src/extension/link2symlink/link2symlink.c
git commit -m "fix: anchor link2symlink backing directory by fd"
```

### Task 3: Route link2symlink operations through the helpers

**Files:**
- Modify: `src/extension/link2symlink/link2symlink.c:61-294`
- Modify: `src/extension/link2symlink/link2symlink.c:794-925`

- [ ] **Step 1: Update `my_readlink`**

Use the descriptor-relative readlink helper so both link inspection and materialization resolve direct `.l2s` children against the originally opened directory.

- [ ] **Step 2: Update link creation and collision handling**

In `move_and_symlink_path`, use the normalized directory length for the `ENAMETOOLONG` calculation, open the configured directory before creating backing files, and replace direct `access`, `rename`, and `symlink` calls with the wrappers. Preserve the existing concurrent-worker reuse path and notifications.

- [ ] **Step 3: Update link-count decrement and cleanup**

In `decrement_link_count`, replace direct `rename`, `unlink`, and `symlink` calls with the wrappers. Keep notification order, link-count suffix updates, and final-file deletion unchanged.

- [ ] **Step 4: Protect custom materialization and path cleanup**

Audit `materialize_executable` and related link2symlink cleanup calls. Replace only operations whose path is a backing-directory entry; leave destination files and legacy paths on their existing behavior. Ensure descriptor-relative operations do not change the absolute symlink payloads stored in `.l2s`.

- [ ] **Step 5: Run the regression and focused runtime tests**

Run:

```sh
PROOT=../src/neoproot sh tests/test-8d3c07f5.sh
sh tests/test-runtime-bindings.sh
sh tests/test-link2symlink-dirent.sh
```

Expected: the new test exits `0` with no outside files, and existing runtime/link2symlink tests remain green. Environment-only skips must be recorded rather than converted into source failures.

- [ ] **Step 6: Commit the operation routing**

```sh
git add src/extension/link2symlink/link2symlink.c
git commit -m "fix: use dirfd operations for link2symlink storage"
```

### Task 4: Wire the security regression into CI and local gates

**Files:**
- Modify: `.github/workflows/ci.yml:45-64`
- Modify: `tests/GNUmakefile:10-45`

- [ ] **Step 1: Add the test to each ARM64 matrix run**

Add:

```sh
PROOT=../src/neoproot sh test-8d3c07f5.sh
```

after the existing link2symlink and security regressions in the CI test suite. Keep the native ARM64 release/portable matrix unchanged.

- [ ] **Step 2: Confirm local aggregate coverage**

Run:

```sh
make -C tests -n test
```

Expected: the dry run contains `test-8d3c07f5.sh` and invokes it through `sh`.

- [ ] **Step 3: Commit CI coverage**

```sh
git add .github/workflows/ci.yml tests/GNUmakefile
git commit -m "ci: run link2symlink directory escape regression"
```

### Task 5: Verify, review, and publish

**Files:**
- Verify all files changed in Tasks 1-4.

- [ ] **Step 1: Run static checks**

```sh
find . -name '*.sh' -print0 | xargs -0 -n1 sh -n
git diff --check github/master..HEAD
```

- [ ] **Step 2: Build optimized and portable ARM64 binaries**

```sh
make -C src clean
make -C src -j4 neoproot CC=clang CXX=clang++
make -C src clean
make -C src -j4 neoproot CC=clang CXX=clang++ MARCH="-march=armv8-a -mtune=generic"
```

- [ ] **Step 3: Run the complete local suite**

```sh
make -C tests -s all
sh tests/test-build-script.sh
sh tests/test-runtime-bindings.sh
PROOT=../src/neoproot sh tests/basic_test.sh
PROOT=../src/neoproot sh tests/advanced_test.sh
PROOT=../src/neoproot sh tests/test-security-regressions.sh
PROOT=../src/neoproot sh tests/test-link2symlink-dirent.sh
PROOT=../src/neoproot sh tests/test-8d3c07f5.sh
```

- [ ] **Step 4: Review the diff and record residual environment limits**

Confirm only the spec, link2symlink implementation, test, Makefile, and CI files changed. Record that ptrace-dependent tests may be blocked by the local sandbox; require the ARM64 CI result before merge.

- [ ] **Step 5: Commit and publish a draft PR**

```sh
git diff --check github/master..HEAD
git status --short
git push -u github fix/link2symlink-dirfd-hardening
```

Open a draft PR targeting `master` with the security root cause, descriptor design, new regression, local checks, and CI limitations. Do not merge until both ARM64 matrix jobs are green.
