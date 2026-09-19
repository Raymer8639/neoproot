# 变更历史

本项目从 Gitee 上游 [proot-scicat](https://gitee.com/scicat-team/proot-scicat) 接手维护。
以下版本记录整理自上游 git 历史。

## [Unreleased]

**Correct the performance baseline quoted for `--stat-shim`**

- The v5.10.6 entry below compared the shim against `--seccomp-notify` without
  the shim, not against the plain tracer path. Re-measured against a
  no-notify/no-shim baseline on the same device: `du -As /usr` 33.28s ->
  14.37s (**2.32x**, identical output `4007438`), while `--seccomp-notify`
  alone reaches only 31.15s (1.07x). On a small tree (1220 entries) the shim is
  ~1.05x and notify-only is 1.8x *slower* than the plain path, because
  `notif_can_continue_fstatat()` refuses `SECCOMP_USER_NOTIF_FLAG_CONTINUE`
  whenever link2symlink or fake_id0 is active, so every stat is fully
  emulated.
- Per-call cost (2000 calls, us/op, plain / notify / shim): absolute `stat`
  288.7 / 96.6 / 8.1, dirfd-relative 308.5 / 114.4 / 4.4, `AT_FDCWD`-relative
  203.8 / 90.9 / 92.9, direct `syscall(SYS_statx)` 324.5 / 106.5 / 10.4. The
  in-process shim is the optimisation; `--seccomp-notify` is the channel its
  fallbacks need.
- No effect on compilation: an 80-file `cc -O0` build takes 18.23 / 18.45 /
  18.30s, `-O2` 18.99 / 19.12 / 19.29s, and `cc -M` 13.7 / 14.5 / 14.3s across
  the three modes. Builds are bound by process startup, parsing/codegen CPU and
  header I/O, not by the stat syscalls the shim accelerates.

## [v5.10.6] - 2026-09-19

**Keep the guest `LD_PRELOAD` off the tracer**

- Apply the `--stat-shim` preload only in the forked child, right before
  `execvp`, and clear it before the sysvipc shm-helper re-execs the tracer.
  Putting the guest-ABI path into the tracer's own environment made Android's
  bionic linker resolve it on the next host `execl("/proc/self/exe")`, so `i3`
  died with `CANNOT LINK EXECUTABLE "neoproot": library
  ".../libstatfast.so" not found: needed by main executable`.

**Translate the paths the in-process fast path cannot resolve**

- Send a relative name at `AT_FDCWD` (the tracee's cwd is virtual) and any
  stat whose raw host call fails (a component may be a symlink to a guest
  absolute path, e.g. `fnm_multishells/<id> -> /home/...`) back through the
  tracer's USER_NOTIF channel. Before this, `ls -al` printed the host mode of
  the bind source and fnm/Node paths failed with ENOENT.
- Interpose libc's variadic `syscall()` so code that issues `statx` itself
  (libuv does, for `uv_fs_stat`) is translated as well; the shim's own raw
  calls go through `dlsym(RTLD_NEXT, "syscall")` so they cannot recurse.
- `--stat-shim` now requires `--seccomp-notify` unconditionally. Without that
  channel the stat syscalls stay untraced and both cases above would silently
  return host-resolved results, so the shim is refused with a warning.

Device A/B (aarch64 Termux host, glibc guest): ON/OFF `find` over
`/usr/share/doc` byte-identical (5723 paths), `dsh --version` = `0.1.5-rc.1`,
`i3 -C` clean. Microbenchmark (3000 calls, us/op): absolute `stat` 343.6 ->
11.8, dirfd-relative 122.9 -> 8.0, `du`/`find` still 1.08-1.62x faster than
without the shim. The only change is that `AT_FDCWD`-relative stats now take a
round trip (103 vs 110.6, no worse than the traced baseline) instead of
returning wrong results in 7.7.

**Optional `--stat-shim` in-process path-stat fast path**

- Add `--stat-shim=<guest-lib>`: removes `newfstatat`/`fstatat64`/`statx`
  from the seccomp filter and `LD_PRELOAD`s a guest-ABI library that performs
  bind translation and fake_id0 in-process. Add a link2symlink-safe raw `fstat`
  fast path (disabled while L2S is active). On the reference device
  `du -As /usr` drops ~1.8x and a dirfd-relative `fstatat` ~70x.
- link2symlink results stay exact: the BPF routes a stat to USER_NOTIF only
  when the shim ORs the sentinel `NEOPROOT_STAT_SHIM_FLAG` (`0x40000000`) into
  its flags, so only symlink / `.l2s.*` cases pay the tracer round trip.
  `--link2symlink` without `--seccomp-notify` refuses `--stat-shim` instead of
  returning wrong link types or counts.
- Ship `stat-shim/libstatfast.so` (built on the aarch64 glibc CI runner) as a
  Release asset with a `SHA256SUMS` entry, and add `stat-shim/build.sh`,
  `stat-shim/shim_test.c` and `stat-shim/README.md`. Cache the last non-root
  bind prefix per thread to reduce repeated longest-prefix scans.
- Cover the historical glibc stat ABI in the shim: `stat64`/`lstat64`/
  `fstat64`/`fstatat64` and the versioned `__xstat*`/`__fxstatat*` entry points.
  A guest built with `-D_FILE_OFFSET_BITS=64` resolves `stat()` to `stat64`, so
  interposing only the public names let such a call bypass the shim and issue an
  untranslated raw syscall (visible as i3 "unable to find the configuration
  file" under `--stat-shim`). Device A/B: `du -As /usr` 31.04s -> 16.88s with an
  identical output hash, `/usr` `find` unchanged at 81419 paths, L2S and
  fake_id0 results identical ON/OFF.

## [v5.10.2] - 2026-09-12

**Keep Git object-store files as real regular files under `--link2symlink`**

- Skip `link2symlink` when `link`/`linkat` dest is a Git object-store
  path (`objects/<2hex>/<38 or 62 hex>`, `objects/pack/*`,
  `objects/info/*`). The kernel returns `EPERM` on Android; Git
  `finalize_object_file` then `rename`s the tempfile into place. Host
  `git clone --local` no longer dies on L2S chains (CVE-2022-39253).
  pnpm's `files/<2hex>/` store is unchanged. Existing chained objects
  are not rewritten.
- Tests/CI: `test-link2symlink-git-objects`; mmap follow-at-open
  probe no longer uses a Git loose-object layout.
- Chore: share `lower_openat2_to_openat`, free USER_NOTIF buffers on
  partial alloc failure, drop unused `src/.check_seccomp_filter.c`.

## [v5.10.1] - 2026-09-12

**Emulate openat2 resolve flags after lowering to openat**

- Keep lowering `openat2` to `openat` so translated host-absolute
  paths are not rejected by kernel `RESOLVE_BENEATH`. Store the full
  `how.resolve` mask (including the seccomp restart path) and emulate:
  `RESOLVE_NO_SYMLINKS` (`ELOOP` on symlink components, except a final
  `O_PATH|O_NOFOLLOW`), `RESOLVE_BENEATH` (`EXDEV` for absolute or
  escaped paths), `RESOLVE_NO_XDEV` (`EXDEV` across `st_dev`), and
  `RESOLVE_NO_MAGICLINKS` (`ELOOP` on `/proc` magic links).
  `RESOLVE_IN_ROOT` stays the existing bwrap path. `RESOLVE_CACHED` is
  ignored; unknown bits return `EINVAL`.
- Silence the ARM64 pokedata workaround warning when `SETREGSET`
  returns `ESRCH` because the short-lived tracee already exited.
- Docs: GitHub Release assets are ARM64 Linux/glibc CI builds, not
  Termux Android binaries. `make clean` deletes and regenerates
  `src/build.h` so `--help` does not keep a stale `git describe`.
- Tests/CI: `test-openat2` now expects kernel-shaped `ELOOP`/`EXDEV`
  for `NO_SYMLINKS` and `BENEATH` instead of treating those flags as
  no-ops.

## [v5.10.0] - 2026-09-06

**Optional seccomp USER_NOTIF path for `newfstatat`**

- Add `--seccomp-notify` to emulate `newfstatat`/`fstatat64` with
  `SECCOMP_RET_USER_NOTIF` (Linux 5.0+ `NEW_LISTENER`). Without the
  flag, kernel 4+ keeps ptrace `SECCOMP_RET_TRACE`. A failed probe
  exits instead of silently falling back.
- The tracer completes path translation, fake_id0 uid/gid, and L2S
  nlink on a dedicated RECV thread, then `SEND`s the result. Never
  `CONTINUE`. A cached host `O_PATH` dirfd skips `translate_path` on
  the `AT_SYMLINK_NOFOLLOW` basename hot path; `dup2` is checked with
  `kcmp`/inode because it is not in the default BPF list.
- Tests/CI: add CLI probe and pipe regressions for translation, bind
  overlays, L2S nlink, and dirfd cache hit/stale.

## [v5.9.8] - 2026-09-06

**Faster directory metadata scans via dirfd basename reuse**

- Cache the translated directory of a guest `dirfd` and, for a single
  relative component with `AT_SYMLINK_NOFOLLOW`, skip walking parent
  path components. `close`/`dup`/`exec`, binding changes, renamed
  directories, more-specific binds, and SCM_RIGHTS fds stay on the
  slow path.
- Tests/CI: add a dirfd reuse, rename, L2S nlink, nested bind, and
  SCM_RIGHTS regression.

## [v5.9.7] - 2026-09-05

**link2symlink follow-at-open so Git mmap stays BPF-direct**

- Keep guest `/.l2s/<internal>` names guest-shaped during canonicalize.
  Rewriting them to a host-absolute path under `PROOT_L2S_DIR` made the
  next hop walk `/data/data/...` as a guest path and return `ENOENT`,
  so Git could not `open`+`mmap` relative `.git/objects` and Node/Tauri
  reported pnpm-linked modules missing.
- Ordinary `open` follows the L2S backing regular file; `mmap` stays
  unintercepted. Copy-materialize is limited to `execve`, `O_PATH`,
  `readlink`, and absolute ordinary open (Node CJS require). `lstat` /
  `O_NOFOLLOW` keep link semantics, and unmaterialized members still
  masquerade `st_nlink=2`.
- Tests/CI: add a relative `open`+`mmap` regression that checks backing
  contents, nlink masquerade, and that the visible names stay symlinks.

## [v5.9.6] - 2026-09-05

**Gradle/glibc `faccessat2` fallback on kernels without the syscall**

- Lower `faccessat2` to `faccessat` in both syscall enter and seccomp
  restart paths, keeping only `AT_SYMLINK_NOFOLLOW`. Android/PRoot-Distro
  kernels commonly return `ENOSYS`; glibc 2.33+ uses `faccessat2(...,
  AT_EACCESS)` for POSIX `[ -x ]`. Restarting the original syscall left
  the previous result (ENOENT/-2 on ARM64) in `SYSARG_1`, so the next
  check used `dirfd=-2` and failed with `ENETDOWN`.
- Tests/CI: add a missing-then-present `faccessat2(AT_EACCESS)`
  regression covering the Gradle launcher dual `[ -x ]` sequence.

## [v5.9.2] - 2026-08-27

**Codex bubblewrap root-bind compatibility patch**

- bwrap/Codex sandbox: preserve `openat2(..., RESOLVE_IN_ROOT, "/")`
  semantics while lowering to `openat`, so bwrap resolves the original root
  through its `/oldroot` descriptor rather than the temporary tmpfs root.
- bwrap/Codex sandbox: retain the already-assembled virtual binding tree when
  bwrap performs its final `pivot_root(".", ".")`, keeping the Codex executable
  and home tree available to the sandboxed process.
- Tests/CI: register procfd mount targets and the `RESOLVE_IN_ROOT` root-bind
  sequence in the release and portable ARM64 workflows.

## [v5.9.0] - 2026-08-23

**Compatibility, safety, and regression coverage release**

- link2symlink: add the opt-in `--link2symlink-dirent` mode, which reports
  verified `.l2s` pseudo-hard-links as regular directory entries while keeping
  the high-performance default unchanged.
- Performance: restore Termux `HAVE_PROCESS_VM` build detection so eligible
  builds use `process_vm_readv` and `process_vm_writev` instead of ptrace
  word-at-a-time memory access.
- bwrap/Codex sandbox: preserve covered bindings through pivot/oldroot and
  provide the virtual mountinfo view for inherited `/proc` directory fds.
- Safety: reject startup under a pre-existing ptrace tracer and direct users
  to run neoproot from the Termux host rather than nesting PRoot.
- CI: make basic and advanced smoke-script failures fatal; run process-vm,
  covered-oldroot, and traced-startup regressions in both ARM64 build modes.
- Release artifacts: publish the optimized ARM64 `neoproot` binary and the
  `neoproot-portable` build using `-march=armv8-a -mtune=generic`.

## [v5.8.0] - 2026-08-19

**Android/Termux 容器与 sandbox 兼容性发布**

- bwrap / Codex sandbox：补齐 `clone`、`mount`、`pivot_root`、`/oldroot` 与显式 `/proc` binding 的用户态兼容路径，Android/Termux 下的 sandbox 可正常启动、读写和清理工作区文件。
- procfs 与文件描述符：修复经 `/proc/self/fd/N` 的执行和 `readlink` 映射；补齐 `close`、`close_range`、`dup`、`exec`、fork 及进程退出后的缓存生命周期，避免陈旧 fd 路径和 PID 复用。
- 模拟挂载：为运行时 `tmpfs` 补齐与 procfd 一致的 `/proc/self/mountinfo` 视图，修复 bwrap 对挂载点的检查；覆盖 `openat2` 和路径转义。
- 网络与命名空间：选择性回移上游 AF_NETLINK 路由仿真、网络命名空间、挂载命名空间、`devtmpfs`/`devpts` 兼容改动，改善 Android 宿主上的容器程序兼容性。
- 安全与回归：加固路径与 fake-id0 元数据处理；新增/扩展 Termux 下的安全、procfd、`close_range` 和 tmpfs/mountinfo 回归测试。
- 验证：ARM64 CI 的 release / portable 两种构建均通过；Termux 真机验证覆盖 bwrap/Codex sandbox、procfd、`close_range`、fork map、tmpfs/mountinfo 和工作区读写删除。

## [v5.7.3] - 2026-08-15

**neoproot 时代首个正式版（项目/二进制改名后）**

- 上游 termux/proot 跟进（选择性回移）：
  - link2symlink `/proc/<pid>/fd/<fd>` 名字替换（7ff389a1，fork 适配：FILTER_SYSEXIT open 家族 / GUEST_PATH 链名采集 / self-fd 解析 / 同目录模式补记）
  - openat2 支持（114a7c6，现代 tar/coreutils 解包）
  - canon 顺序符号链接计入 MAXSYMLINKS（d86f355）
  - AArch64 SP 16 字节对齐（28baec5）——**容器启动体感加速**
  - seccomp 合成 sysexit 后恢复 SYSARG_1（cd02c79，ARM 寄存器别名）
  - no_new_privs 按 guest 意图报告（571a6c0，enter 侧标记版，sudo-rs 兼容）
- AT_EXECFN 三通道闭环：getauxval（loader 栈上 auxv 修补）+ /proc/self/auxv（open enter 改写）+ PR_GET_AUXV（出口后处理，内核 6.4+ 远期）
- 修复首次 seccomp 事件模式探测竞态（flags=0 首事件误入断言，fork 既有隐患）
- 项目改名 neoproot（GitHub 仓库 Raymer8639/neoproot；二进制 neoproot，uproot 软链兼容）
- README 双语化（英文默认 + README.zh-CN.md）


## [5.6.0-scicat] - 2026-05-01

**（当前版本，上游最后一次提交）**

- 魔改 uproot：C++23 极致性能版
- 裁剪兼容：放弃通用架构，换取 ARMv8.2 满血性能（含 NEON/dotprod/lse 优化）
- 引入 `neoproot` 主程序（历史名 uproot）：自动执行 Termux 环境初始化（wake-lock、`ulimit -n`、清理 `LD_*`）
- 系统调用路径高性能优化（`-fomit-frame-pointer`、`-funroll-loops`、去栈保护）
- 进程退出 `signal 11` 警告消除、进程存活判断
- 中文 VNC 退出卡死修复
- 内置自动高优先级调度 `setpriority(-20)`
- 实测：极重负载性能领先官方 7.2%

## [5.6.0-scicat] - 2026 年初（正式版）

- 修复 ptrace 权限问题，`setresuid`/`setresgid` 可用
- Debian apt 正常运行
- 安卓 12+ 适配

## [5.5.0-scicat] - 正式版

- 双平台兼容版（Termux + Linux）
- 移除 src 目录下的独立 Git 仓库，使其成为普通目录

## [5.1.3-scicat] - aarch64 修复版

- 解决 asm / Shell / 链接错误
- 含 JIT / AI 扩展
- Termux 专属：安卓 12+ 适配、root 模拟、屏蔽 talloc、后台保活

## 初始版本

- 基于官方 PRoot 的 Termux/Linux 优化版首发

---

## 本仓库（GitHub 接管维护）新增

### 2026-08-07（接管首日）

- 移除已停服的 Travis CI 配置，新增 GitHub Actions CI（ARM64 runner 构建 + 测试 + 自动发布）
- 新增 `build.sh`：Termux 一键构建/安装脚本
- Makefile：`MARCH` 变量可覆盖（默认 ARMv8.2 满血优化）；未安装 `upx` 时自动跳过压缩
- 重写 README，新增本变更日志
