# stat shim for musl (Alpine) guests

## 结论

- Alpine 3.21.3 + musl 1.2.5 可用：`libstatfast-musl.so` 能被 musl 的
  `LD_PRELOAD` 加载，`fstatat`/`stat`/`lstat`/`fstat`/`statx` 和
  `syscall()` 都被拦截；`busybox stat`、`ls -l` 与不开 shim 的结果逐字节一致。
- tracer 不需要改：`--seccomp-notify` 的 USER_NOTIF tag、`LD_PRELOAD`/
  `NEOPROOT_STATSHIM_*` 注入、stat 结果写回都与 libc ABI 无关；aarch64 上
  musl 的 `struct stat`/`struct statx` 布局和内核一致。
- 部署时注意自动发现只认 guest 内 `/opt/neoproot/libstatfast.so`
  （`src/cli/cli.c`）：Alpine rootfs 要装 musl 版的这个文件名，或显式传
  `--stat-shim=/opt/neoproot/libstatfast-musl.so`。

## 改了什么

1. `stat-shim/shim.c`：把 glibc 专用的 `fstatat64`/`stat64`/`lstat64`/
   `fstat64`、`__xstat*` 和 `eaccess` 放进 `#ifdef __GLIBC__`。
   - musl 没有 `struct stat64` 和 `__xstat*`；它的头文件只在
     `_LARGEFILE64_SOURCE` 下把 `*64` 名字宏映射到普通函数，强行编译只会
     得到 incomplete type 的死符号（clang 报 12 条警告）。
   - musl 的 `eaccess()` 就是 `faccessat(AT_FDCWD, path, mode, AT_EACCESS)`；
     access 族仍由 tracer 翻译，不需要 shim 覆盖。
   - glibc 构建的符号集不变（`eaccess`、`*64`、`__xstat*` 仍在）。
2. 新增 `stat-shim/build-musl.sh`：可复现的交叉构建脚本。
   - 默认从 USTC 的 Alpine 3.21 main/aarch64 下载 `musl` 和 `musl-dev`
     apk（版本从 APKINDEX 自动解析，本次 1.2.5-r12），解包到
     `/tmp/bench/musl-sysroot`；镜像/分支/缓存路径可用环境变量覆盖。
   - Termux clang 21：`clang --target=aarch64-linux-musl --sysroot=<sysroot>
     -O2 -Wall -Wextra -fPIC -shared -nostdlib -Wl,-z,noexecstack ... -lc`。
     `-nostdlib` 是因为 Termux clang 没有 linux-musl 的 crtbeginS/libgcc，
     shim 也用不到。
   - 产物 `stat-shim/libstatfast-musl.so`，`NEEDED` 只有
     `libc.musl-aarch64.so.1`；已加入 `.gitignore`。

## musl 与 glibc 版本的差异

- `struct stat`：aarch64 musl 的字段（`unsigned long __pad` 后接
  `st_size`/`st_blksize`/`st_blocks`/三个 `timespec`）与内核
  `newfstatat` 写回的布局一致，raw syscall 结果可以直接交给调用者。
- `struct statx`：musl 1.2.5 提供与内核一致的 `struct statx` 和
  `statx()` 原型。
- 符号：musl 只有 `fstatat`/`stat`/`lstat`/`fstat`/`statx`，没有 glibc 的
  `stat64`/`fstatat64`/`__xstat*`。musl 源码在 `_LARGEFILE64_SOURCE` 下把
  `stat64` 等宏映射到普通函数，因此不存在 ABI 缺口。
- 动态链接：musl 没有符号版本，`LD_PRELOAD` interposition 规则与 glibc
  相同；busybox 是动态链接，能被覆盖。

## 构建与安装

    cd stat-shim && ./build-musl.sh        # 产物 stat-shim/libstatfast-musl.so

安装到 Alpine rootfs（二选一）：

    cp libstatfast-musl.so <rootfs>/opt/neoproot/libstatfast.so   # 自动发现
    # 或保留文件名，显式指定：
    neoproot ... --seccomp-notify --stat-shim=/opt/neoproot/libstatfast-musl.so ...

不要把非 musl ABI 的 `libstatfast.so` 放进 Alpine rootfs：它的
`NEEDED`（如 `libc.so.6`、`libc.so`）在 musl guest 里找不到。

## 功能验证（未做任何计时）

在 `--seccomp-notify` + `--stat-shim=/opt/neoproot/libstatfast-musl.so`
下运行 Alpine 3.21.3 guest：

    /bin/busybox stat /etc/hostname
    /bin/busybox ls -l /
    cd /etc && /bin/busybox stat hostname                   # 相对路径走 USER_NOTIF
    /bin/busybox stat /bin/sh; /bin/busybox ls -l /bin/sh   # 符号链接
    neoproot -b <host-dir>:/mnt/etc ... -- /bin/busybox stat /mnt/etc/hostname
    neoproot --change-id=0:0 ... -- /bin/busybox stat /etc/hostname

以上输出与不带 shim 的对照逐字节一致（diff 为空）。另外：

- `NEOPROOT_STATSHIM_DEBUG=1`：`stat /etc/hostname` 显示 1 次
  `[stat-shim] fstatat(...)` + `RAW ok`；`ls -l /` 正常。
- `NEOPROOT_TEST_USER_NOTIF=1`：开 shim 时 `fstatat emulate`/`statx emulate`
  为 0 次；不开 shim 的对照组为 1 次。说明 tag 生效，热路径没有走 tracer。
- 手工 `LD_PRELOAD=/opt/neoproot/libstatfast-musl.so` 也能加载并拦截；
  自编译的 musl 测试程序验证了 `stat()`、`syscall(SYS_newfstatat)`、
  `statx()` 三条入口。
- 自动发现：把库放到 `/opt/neoproot/libstatfast.so` 后，不加
  `--stat-shim=` 也会启用（日志显示该路径）。

## 已知限制与风险

- 只加速动态链接的 guest 程序。静态程序（Go/Rust 常见）不会加载 shim，
  它们未打 tag 的 newfstatat/statx 会全部落到 USER_NOTIF 由 tracer 模拟：
  结果正确，但没有加速（与不开 shim 相当），不会回归。
- 相对路径（AT_FDCWD）、guest 绝对符号链接和 link2symlink 结果伪装仍要
  走 `--seccomp-notify` 的 USER_NOTIF；因此 `--stat-shim` 依赖
  `--seccomp-notify`（tracer 已检查，缺失时会拒绝启用）。
- `fstat` 只在 link2symlink 关闭时被 tracer 放行；开启 L2S 时 fstat 仍由
  tracer 处理（与 glibc 版一致）。
- bind 表是启动时快照；运行中新增的 bind 不会被 shim 看到（与 glibc 版
  一致）。
- 只在 Alpine 3.21/musl 1.2.5 上验证；更老的 musl 若没有 `statx` 头，
  需要自行裁剪 statx 入口。
