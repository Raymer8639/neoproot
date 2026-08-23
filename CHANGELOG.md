# 变更历史

本项目从 Gitee 上游 [proot-scicat](https://gitee.com/scicat-team/proot-scicat) 接手维护。
以下版本记录整理自上游 git 历史。

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
