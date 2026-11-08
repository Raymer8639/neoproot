# SHIM-ABI 实现笔记

## 结论

- `--shim-rootfs=DIR` 现在先探测 guest libc，再选择 shim：
  - `DIR/lib/ld-musl-aarch64.so.1` → musl，用 `stat-shim/build-musl.sh`
    的 `libstatfast-musl.so`；
  - `DIR/lib/ld-linux-aarch64.so.1` 或 `DIR/lib64/ld-linux-aarch64.so.1`
    → glibc，用 `stat-shim/build.sh` 的 `libstatfast.so`。
- 复制进 guest 时两者都叫 `/opt/neoproot/libstatfast.so`，tracer 的
  auto-discovery 路径没有变化。
- 两种 loader 同时存在、或都不存在时明确报错并返回 2，不猜测；新增
  `--shim-abi=musl|glibc` 作为特殊 rootfs 布局的覆盖开关。
- `scripts/install.sh` 按 ABI 下载 Release 资产：glibc 用
  `libstatfast.so`，musl 用 `libstatfast-musl.so`；Release 没有 musl 资产
  时打印明确提示，并建议源码构建或手动放置。

## 改动

- `install.sh`（1792cf1）：新增 `shim_abi_for_rootfs`、
  `shim_artifact_for_abi`、`shim_ensure_built`、
  `shim_install_into_rootfs`；构建前预检所有 rootfs，避免编完 neoproot
  才发现 ABI 不对。
- `scripts/install.sh`（52c14b5）：新增 `_rootfs_abi`、
  `_shim_file_abi`；按 ABI 选资产，下载/缓存后用 `readelf` 核对
  `NEEDED`，不一致就拒绝复制；`--shim-rootfs` 现在在 Termux 源码构建
  路径也生效。
- `tests/test-shim-abi.sh`（686f1c4）：空 loader 的临时 rootfs + 伪造
  两种 `NEEDED` 的 fixture，跑真实 `install.sh` 与
  `scripts/install.sh`（后者用 fake curl 模拟 Release 有/无 musl 资产）。
- 文档（adc6540）：README、README.zh-CN、stat-shim/README.md、
  stat-shim/MUSL.md 与 CHANGELOG 的 `[Unreleased]`。

## 验证

- `sh install.sh --prefix=<tmp> --without-um --non-interactive` 在 Arch
  aarch64 glibc 环境成功，host shim 为 glibc 版。
- 同一次安装带 `--shim-rootfs=<fake musl>` 和 `--shim-rootfs=<fake glibc>`：
  - musl guest 的 `/opt/neoproot/libstatfast.so`：
    `NEEDED libc.musl-aarch64.so.1`；
  - glibc guest 的同一路径：`NEEDED libc.so.6`（另带
    `ld-linux-aarch64.so.1`）。
- `sh tests/test-shim-abi.sh` 在 Arch glibc 与 Termux 宿主（经
  `tools/ssh_run.py`）均通过；覆盖双 loader/无 loader 报错、
  `--shim-abi=musl` 覆盖、Release 有/无 musl 资产。
- 未运行任何计时基准，只做功能验证。

## 风险 / 限制

- 探测只看 aarch64 loader 文件名；x86_64 或其他架构 rootfs 会落到
  “没有 loader”报错，需要 `--shim-abi`（shim 本身也只支持 aarch64）。
- 同时装了 musl 和 glibc loader 的 rootfs（如带 gcompat 的 Alpine）会
  报歧义；这是有意保守，避免装错后到 guest 内才炸。
- 源码安装器的 host 副本仍走 `build.sh`（与改动前一致）；它不代表任何
  guest ABI，真正进容器的副本按上面规则选择。
- `build-musl.sh` 需要网络下载 Alpine musl/musl-dev；离线时要预先放好
  `stat-shim/libstatfast-musl.so`。
- 本仓库 CI 的 release job 目前只发布 `libstatfast.so`，尚未构建
  `libstatfast-musl.so`；一键安装器会走“Release 没有 musl 资产”的提示
  分支。要在 Release 里提供 musl 资产，需要另改 CI 发布流程。
