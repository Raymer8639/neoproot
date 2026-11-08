# fast 后端启动开销优化说明

## 结论

三项都已完成并各自提交；全部在 Termux 宿主上构建、做功能验证，未做任何计时测量。

| # | 改动 | 提交 |
|---|------|------|
| 1 | loader 跨调用缓存 | 32d3cd0 |
| 2 | seccomp 探针不再 fork | 42d1e79 |
| 3 | 启动器去掉 sh -c 一跳 | 09b5db3 |
## 构建与验证环境

- 工作树：`/tmp/bench/wt-startup`（宿主侧 `$PREFIX/tmp/bench/wt-startup`，两边同一棵树）。
- 构建：`sh install.sh --prefix=/tmp/bench/install-startup --without-um --with-shim --non-interactive`
- 安装前缀：`/tmp/bench/install-startup`；rootfs：`/tmp/bench/rootfs`。
- 另用同一棵树做了 `--with-um` 构建（`install-startup-um`），只用于名字分发验证。
- 说明：本树 loader 实测为 **18,048 B**（`src/loader/loader` 18,656 B，strip 后嵌入），不是题目里的 67,272 B；机制与结论不受影响。
## 1. loader 跨调用缓存（32d3cd0）

原实现每次 `extract_loader()` 都用 `open_temp_file()` 写一个新文件。文件名上挂了 talloc 析构器，但
`free_global_temp_ctx()` 全树没有调用点，析构器永远不会执行；宿主 `$PREFIX/tmp` 里已积累 51 个
`proot-loader-<pid>-*` 残留，说明旧路径既重复写又泄漏。

新实现：

- 用 FNV-1a 64 位内容指纹命名 `proot-loader-v1-<hash>`，同一构建稳定复用。
- 复用前用 `O_NOFOLLOW` 打开，校验普通文件、属主为 euid、大小、模式，再逐字节 `memcmp` 嵌入的
  loader；名字只是线索，内容才是依据。损坏/旧版本/同名他人文件会被重写而不是执行。
- 发布用 `mkstemp` + `fchmod 0500` + `rename`，并发启动不会看到半成品；rename 失败则退回本次
  私有临时文件，不阻塞启动。
- `PROOT_MEMFD_LOADER` 现在真正被读取：默认（未设置/1）启用缓存，`0` 保留旧的私有临时文件行为。
  launcher 的默认值改为 `${PROOT_MEMFD_LOADER:-1}`，不再覆盖调用者显式设置。
- 新增 `tests/test-loader-cache.sh`：验证第二次运行 inode 不变、损坏缓存会被修复、opt-out 不写缓存。

风险：缓存会在 `PROOT_TMP_DIR` 留一个 18 KB 文件；目录不可写/不可执行时自动回退旧路径。若同 uid
的进程恶意抢注文件名，内容校验保证不会执行错文件；跨用户 /tmp 场景另有属主检查。
## 2. seccomp 探针不再 fork（42d1e79）

原 `probe_seccomp_user_notif()` fork 一个子进程，实际装一次 NEW_LISTENER filter，通过 pipe 回报，
再 `waitpid`。seccomp filter 不可逆，装进 tracer 后无法回滚，所以它只能用独立进程做。

新实现改用两次只读查询：

- `SECCOMP_GET_ACTION_AVAIL` + `SECCOMP_RET_USER_NOTIF`：内核认识这个 action。
- `SECCOMP_GET_NOTIF_SIZES`：USER_NOTIF ABI（Linux 5.0+）存在，同时给出后续 buffer 尺寸。

NEW_LISTENER 是获得 USER_NOTIF listener 的唯一方式，支持该 action 的内核必然支持该 flag。
代价是不再预检“安装策略”（例如外层沙箱允许查询但拒绝 NEW_LISTENER）：这种环境会在
`set_seccomp_filters()` 的启动子进程里以同样的 errno 失败，旧探针也只能把失败提前报告，不能改变结果。

验证：`--seccomp-notify -r rootfs -- /bin/true` 返回 0、`/bin/sh -c 'exit 7'` 返回 7，
stderr 仍有 “USER_NOTIF listener ready”。风险：极老或被裁剪的内核上 `GET_ACTION_AVAIL` 不可用会判失败；
这类内核本来也没有 USER_NOTIF。
## 3. 启动器去掉 sh -c 一跳（09b5db3）

原启动器 `exec /system/bin/sh -c "termux-wake-lock & ulimit ...; unset LD_*; exec \"$0\" \"$@\""`：
每次启动多一次 shell exec 和 shell 解析，然后才 exec 回 neoproot。

新实现直接在 C 里完成：

- wake-lock：双 fork。中间子进程立刻退出并被 `waitpid` 回收，孙进程交给 init；既不会在 tracer
  生命周期内留僵尸，也不会被 tracer 的 `waitpid(-1)` 误收。stdin/stdout/stderr 重定向到 /dev/null，
  保持非阻塞。
- `ulimit -S -n`：`setrlimit(RLIMIT_NOFILE)` 把 soft 设为 16384；hard 小于 16384 时不改（对应
  shell 版 `ulimit` 失败并保持原值），hard 不动。
- `unset LD_PRELOAD LD_LIBRARY_PATH LD_BIND_NOW`，并设置 `PROOT_MEMFD_LOADER`（若未设置）与
  `PROOT_UNSET_DONE=1`。
- 仍然保留一次 re-exec，但改为直接 `execve("/proc/self/exe", 原 argv)`：Termux 默认
  `LD_PRELOAD=libtermux-exec-ld-preload.so`，`unsetenv()` 无法把已加载的库从当前进程卸下，
  必须让动态链接器重新启动 tracer。于是从“shell + exec neoproot”降为“exec neoproot”一次。
- argv[0] 原样传递；`neoproot-um`/`uproot` 的分发在 bootstrap 之前执行，完全不受影响。
- 新增 `tests/test-launcher-environment.sh`：guest 内检查三个 LD_* 均为空、soft nofile=16384。

验证：`tests/test-bootstrap-nonblocking.sh` 通过；with-um 构建里 `neoproot-um --version` 与
`uproot --version` 仍进入 supervisor，`myroot` 符号链接仍走 fast 后端；fast 路径 0/7 退出码正常。

风险：`/proc` 未挂载且 argv[0] 无路径、又不在 PATH 时，最后回退为进程内 `proot_main`（此时 LD_*
已在 environ 中清掉，但已加载的 preload 仍在内存里）；这是极端环境下的降级路径。soft limit 从宿主
当前的 32768 降到 16384 是旧 shell 行为，保持不变。
## 验证命令与结果

```sh
B=/tmp/bench/install-startup/bin/neoproot; R=/tmp/bench/rootfs
$B --version                                  # 0
$B -r $R -- /bin/true                         # 0
$B -r $R -- /bin/sh -c 'exit 7'               # 7
$B --seccomp-notify -r $R -- /bin/true        # 0，listener ready
$B --seccomp-notify -r $R -- /bin/sh -c 'exit 7'  # 7
PROOT=$B sh tests/test-bootstrap-nonblocking.sh   # passed
PROOT=$B sh tests/test-loader-cache.sh            # passed
PROOT=$B sh tests/test-launcher-environment.sh    # passed
```

## 未做 / 风险提示

- 按要求没有跑任何带计时的基准，启动收益未量化；由 Lead 的测速窗口评估。
- 没有清理历史遗留的 51 个 `proot-loader-<pid>-*`（无法判断哪些仍被运行中的实例使用，需要单独策略）。
- 本说明只覆盖 fast 后端；UML supervisor 自己的 shell 引导脚本未改。
