# INSTALLER-FIX-NOTES

分支 `fix/installer-um-link`，基于 v6.0.2.0（d5b1384）；两个修复各一个提交，另有本说明一个提交。

## 1. neoproot-um 不更新（0dd845b）

- 原因：`scripts/install.sh` 的 `install_binary` 只替换 `neoproot`，旧安装器留下的独立 `neoproot-um` 二进制（53,536 B，2026-10-24）永远不会跟着更新；而新二进制按 argv[0] 分发（`src/cli/neoproot.c:305-316`），两者不再是同一个构建。
- 修复：`WITH_UM=1` 时把 `$PREFIX/bin/neoproot-um` 刷新为指向 `neoproot` 的相对链接；已有普通文件先备份成 `neoproot-um.prev-<时间戳>`。已有 `uproot` 别名一并刷新，全新安装不创建。`WITH_UM=0` 时旧 `neoproot-um` 改名为 `neoproot-um.stale-<时间戳>`。
- 文档：README.md / README.zh-CN.md 安装段各加一句。
- 测试：新增 `tests/test-installer-links.sh`（链接、备份、uproot、无 UM 四种情况）。

## 2. --shim-rootfs 在 Termux 下无声失效（0e97537）

- 真正原因：`_install_shim_into` 把 rootfs 里已有的 `/opt/neoproot/libstatfast.so` 当成源文件。更新时源=目标，`cp -f` 报 "are the same file"；`2>/dev/null || return 0` 同时吞掉 stderr 和退出码，于是日志没有任何 shim 行，旧文件也不变。
- 排除项：参数解析正常；Termux 分支没有提前 exit；`--yes` 不会重置 `WITH_SHIM`；Termux 路径确实会调用 `_install_shim_into`。
- 修复：优先取请求 tag 的 Release 资产；下载失败才回退到 `$PREFIX/libexec/neoproot/<asset>` 缓存，再回退到同 ABI 的 guest 旧文件，并明确记录用了哪一个（"using cached ..." / "keeping the existing ..."）。mktemp/mkdir/cp 失败不再静默，新增开始/成功日志并注明来源。
- 测试：`tests/test-shim-abi.sh` 增加"guest 已有同 ABI 旧 shim，必须被 release 资产替换"的回归用例。

## 验证（Termux 宿主，`tools/ssh_run.py`）

- 命令：`sh scripts/install.sh --version v6.0.2.0 --prefix $PREFIX/tmp/inst-test --mode termux --with-um --with-shim --shim-rootfs $PREFIX/tmp/inst-rootfs --yes --non-interactive`；真实 clone v6.0.2.0 源码并编译（约 2 分钟）。
- (a) `inst-test/bin/neoproot-um -> neoproot`（readlink=neoproot，与 neoproot 同 inode）；`neoproot --version` 为 v6.0.2.0；首轮旧 `neoproot-um` 备份为 `neoproot-um.prev-20261108-171226`（53,536 B）。
- 注意：`neoproot-um --version` 按 argv[0] 设计进入 supervisor，会报 `invalid or duplicate option '--version'`；版本一致性用链接目标/inode 加 `neoproot --version` 验证。
- (b) rootfs 原有 `/opt/neoproot/libstatfast.so`（73,148 B，带 stale 标记）→ 安装后为 release 的 73,136 B（`cmp` 一致），日志：
  `==> shim (glibc) installed into .../inst-rootfs/opt/neoproot/libstatfast.so from v6.0.2.0 release`
- 最终版在同一 `inst-test` / `inst-rootfs` 上复跑（用已编译二进制作为构建产物，其余走真实安装器）：旧 shim 73,148 B → release 73,136 B（`cmp` 一致），日志 `from v6.0.2.0 release`；链接、`uproot`、同 inode、53,536 B 备份均通过。
- 缓存回退路径（Release 下载失败时）另测：日志先报 `could not fetch libstatfast.so from v6.0.2.0`，再 `from cached ...`。
- 网络说明：当前 GitHub Release 资产返回 504；验证时仅用 PATH 中的 `curl` 替身提供本地真实资产副本（UML runtime 与 libstatfast.so），git clone、编译和安装脚本本身未替换。
- 回归：`sh tests/test-shim-abi.sh`、`sh tests/test-installer-links.sh` 均通过；两条新断言在修复前的 HEAD 脚本上均失败（已确认）。
- 未运行计时基准。
