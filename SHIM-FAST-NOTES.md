# stat shim 性能诊断笔记（fast path）

## 结论

- 参考负载 = `du -s` 跑 4.0 GB / 96,650 个条目的树（= 本机 Arch rootfs `/usr`，
  busybox `du`，每条目 1 次 `lstat`）。计数器显示绝对路径下 shim 每条 stat
  **只发 1 次裸 `newfstatat`、0 次 USER_NOTIF**——所以 4.1 s 不是“每条 stat
  两个系统调用”，也不是 `to_host`/`shim_init`。
- 该负载里唯一的大块开销是 **`--link2symlink` 下每个符号链接结果都回退
  USER_NOTIF**：这棵树有 10,023 个 symlink，于是 10,023 次 tracer 往返，而
  tracer 对其中的 9,668 个无事可做（只有“目标是 `.l2s.` 名”才需要 L2S 伪装）。
- 第二块是 **`AT_FDCWD` 相对名一律走 USER_NOTIF**：`du -s .`（2,021 条）
  = 2,021 次往返 + 0 次裸 syscall，与绝对路径相差两个数量级。
- `probe_is_symlink()` 只在 **follow** stat（`stat`/`stat -L`，无
  `AT_SYMLINK_NOFOLLOW`）时触发；`du`/`ls -l` 全是 lstat，实测 probe=0。
  `shim_init()` 实测每进程只执行一次（init=1）——两者都不是热点。

## 诊断数据（`NEOPROOT_STATSHIM_STATS=1`，只计数不计时）

| 场景 | calls | notif 优化前 | notif 优化后 |
| --- | --- | --- | --- |
| `du -s /usr2`（绝对，L2S off） | 96,650 | 0 | 0 |
| `du -s /usr2`（绝对，L2S on） | 96,650 | **10,782** | **355** |
| `du -s .`（相对，L2S off/on） | 2,021 | **2,021** | **0**（+1 次 getcwd） |
| `cd /etc; stat ../etc/hostname` | 1 | 1 | 1（含 `..`，按设计回退） |
| `stat -L <symlink>`（L2S on） | 1 | 1 | 0（probe=1 + readlink=1） |
| `ls -l /` | 20 | 0 | 0 |

优化后 96,650 条 stat 的裸 syscall = 96,650 stat + 10,023 readlink ≈ 1.10 次/stat；
剩下 355 次往返全部是真 `.l2s.` 链（镜像里残留的 L2S 工件）。

## 改动（每项一个提交）

1. `52e3c6a` 计数器：`NEOPROOT_STATSHIM_STATS=1` 退出时打印总调用、绝对/
   相对/空路径、nofollow、裸 stat/lstat 探测/readlink、raw 失败与 tracer 救回
   次数、USER_NOTIF 按原因拆分（相对名 / raw 失败 / L2S）、bind 命中分布。
   gate 放在 `shim_init()`——constructor 里 `getenv` 还是 NULL。
2. `6977411` L2S 判定改为看链接目标：`readlinkat` 读到的目标 basename 以
   `.l2s.` 开头、或结果名本身是 `.l2s.*`、或读失败，才回退 tracer。为了让这次
   readlink 不停靠，`seccomp.c` 加了一条 tag 化 ALLOW 规则（readlinkat 没有
   flags，tag 放 args[0] 高 32 位，内核只读 int dirfd）；未打 tag 的 guest
   readlink 仍按原样 TRACE。老 tracer 不设 `NEOPROOT_STATSHIM_RL_TAG`，shim
   自动退回旧行为。
3. `4873651` `AT_FDCWD` 相对名本地翻译：缓存 guest cwd（一次 `getcwd()`，同样
   由 tracer 模拟），拼接后走 bind 表翻译再发裸 stat；`chdir`/`fchdir`（libc
   符号和 `syscall()`）清缓存；含 `..`、cwd 翻译不了、raw 失败一律回退。

## 验证（未跑任何计时基准）

- 宿主构建：`sh build.sh --without-um`；musl shim `sh stat-shim/build-musl.sh`；
  glibc shim 在 Arch 容器内 gcc 构建（等价 `CC=gcc sh stat-shim/build.sh`），
  宿主上同一条 build.sh 也能编过（bionic ABI，仅作编译检查）。
- Alpine 3.21.3 guest（musl 1.2.5）功能对照：33 个用例 × 开/关 shim **逐字节
  相同**——busybox stat、`ls -l`、`du`、相对路径与 `..`、dirfd 相对名、
  `/bin/sh` 符号链接、断链、`-b` bind（绝对/相对/cwd 在 bind 内）、
  `--change-id=0:0`、`--link2symlink` 硬链接链与 `%h` 计数、chdir 后相对名。
- Arch glibc guest 抽查（带/不带 `--stat-shim`）：输出相同。
- 仓库测试：`tests/test-stat-shim-raw-stat.sh`、
  `tests/test-link2symlink-stat-guard.sh` 通过。
- `stat-shim/shim_test` 在本机跑不了（Termux 宿主没有可写 `/tmp`；Arch 容器本身
  就跑在 neoproot+shim 里，constructor 与内层 shim 冲突），故功能对照以 guest A/B
  为准。
- 计数器前后对比见上表（同一棵树、同一个 tracer 构建）。

## 风险与后续

- 相对名快路径假设“缓存 guest cwd == tracer 的虚拟 cwd”。只拦截 `chdir`/
  `fchdir`/`syscall(SYS_chdir…)`；若程序用内联汇编改 cwd 缓存会过期，最坏结果
  是按旧 cwd 解析（通常是 ENOENT → 回退）。要绝对保守就不开 `--stat-shim`。
- L2S 判定镜像 `resolve_l2s_stat_path()` 的条件，前缀比 tracer 宽（只要
  `.l2s.`）：多判只多一次往返，方向安全。
- 未做（可继续）：L2S 链本身仍要 1 次往返/链；L2S 下的 follow stat 仍多一次
  nofollow probe（`stat`/`find -L` 类负载），可再省 1 次 syscall。
- 本笔记不含任何计时数据；测速由 Lead 执行。
