[English](README.md) | **简体中文**

# neoproot

面向 ARM64 的 PRoot 分支，专为 Android/Termux 容器优化。neoproot 适合在手机、平板上的 Debian/Ubuntu 用户空间中运行 Node.js、pnpm、TypeScript、nvim、bwrap 等高频系统调用工作流。

当前稳定版二进制：[最新发布](https://github.com/Raymer8639/neoproot/releases/latest)。

[![CI](https://github.com/Raymer8639/neoproot/actions/workflows/ci.yml/badge.svg)](https://github.com/Raymer8639/neoproot/actions/workflows/ci.yml)
![平台](https://img.shields.io/badge/platform-ARM64%20%2F%20Android-blue)
![语言](https://img.shields.io/badge/C%2FC%2B%2B-C23%20%2F%20C%2B%2B23-orange)
![许可证](https://img.shields.io/badge/license-GPLv2-green)

## 在 Termux 中开始

如果发布二进制能在你的设备上运行，优先使用它；否则在 Termux 内构建原生版本：

```sh
pkg install clang make llvm binutils pkg-config talloc
git clone https://github.com/Raymer8639/neoproot.git
cd neoproot
sh build.sh install
```

安装脚本会把 `neoproot` 放到 `$PREFIX/bin`。ARM64 Linux 用户可以从 [Releases](https://github.com/Raymer8639/neoproot/releases) 下载 `neoproot` 或降低指令集要求的 `neoproot-portable`，校验 SHA256 后放入 `PATH`。

## 为什么使用 neoproot

- 自动处理 Termux 宿主初始化：wake-lock、文件描述符上限和 `LD_*` 清理由 `neoproot` 启动器完成。
- link2symlink 硬链接模拟兼容 pnpm 和 TypeScript/tsgo 通过 `/proc/<pid>/fd/<fd>` 探测真实路径的工作流。
- 移除分支原有的路径翻译线程池开销，高频路径操作下 nvim 与包管理器更顺畅。
- 内置高优先级调度（`setpriority(-20)`），无需 root 即可改善 CPU 调度倾向。
- 修复中文 VNC 退出卡死、注销/切后台问题和误导性的 `signal 11` 退出警告。
- 采用精简的 C23/C++23 实现并针对 ARMv8.2 调优，以 ARM64 性能换取通用架构覆盖范围。

## 支持的环境

- 64 位 ARM Linux（`aarch64` / ARMv8.2 及以上），主要目标是 Android/Termux。
- Termux 或等效的 Android Linux 环境，也支持 ARM64 Linux 主机。
- 优化构建**不支持 x86_64**。发布二进制请使用 ARM64 设备。

## 容器示例

```sh
neoproot -0 -r /data/data/com.termux/files/home/rootfs \
    -b /dev -b /proc -b /sys -b /sdcard \
    /usr/bin/env -i HOME=/root TERM=${TERM} PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    /bin/bash --login
```

命令行接口遵循官方 PRoot 习惯。无需手动取消设置 `LD_PRELOAD`、`LD_LIBRARY_PATH` 或 `LD_BIND_NOW`；启动器会在进入 guest 前自动处理这些变量。

## 性能依据

下表来自仓库中的 sysbench 工作负载和 ARM64 真机。结果会受 SoC、温度、rootfs 和工作负载影响，应作为可复现起点，而不是普遍保证。

| 负载 | 相对官方 PRoot |
|------|----------------|
| 低负载（素数 <= 10000） | 持平（误差范围内） |
| 中高负载（50000） | **领先 2.9%** |
| 极重负载（100000） | **领先 7.2%** |

报告结果时请附设备/SoC、Android 与 Termux 版本、完整命令、基线版本和多次测量结果。请使用[性能反馈表单](https://github.com/Raymer8639/neoproot/issues/new?template=performance_report.yml)，便于比较不同设备的数据。

## 构建说明

- 默认目标：`-march=armv8.2-a+fp16+dotprod+lse+rcpc+simd+crc+crypto`（可用 `MARCH=` 覆盖）。
- 便携版发布包使用 `-march=armv8-a -mtune=generic`；它只放宽 CPU 指令要求，不保证所有 libc 或内核兼容。
- 链接选项包含 ThinLTO、段垃圾回收、相同代码折叠、RELRO/NOW 和去符号。
- 构建依赖 `libtalloc`（Termux 包名：`talloc`），`upx` 为可选依赖。

## 项目沿革

neoproot 由 `proot-scicat` / `uproot` 更名而来，并持续跟进 [termux/proot](https://github.com/termux/proot) 的有用修复。原始实现是 [proot-me/proot](https://github.com/proot-me/proot)，直接分支祖先是 [scicat-team/proot-scicat](https://gitee.com/scicat-team/proot-scicat)。版本历史和归属见 [CHANGELOG.md](CHANGELOG.md)。

## 贡献与支持

- [报告 Bug](https://github.com/Raymer8639/neoproot/issues/new?template=bug_report.yml)
- [提出功能请求](https://github.com/Raymer8639/neoproot/issues/new?template=feature_request.yml)
- [在 Discussions 提问](https://github.com/Raymer8639/neoproot/discussions)
- 阅读 [help.md](help.md)、[SUPPORT.md](SUPPORT.md)、[CONTRIBUTING.md](CONTRIBUTING.md) 和 [SECURITY.md](SECURITY.md)

## 版本命名

版本号沿用 termux/proot 风格。2026-08-15 前的发布版本使用历史后缀 `-scicat`；`v5.7.3` 及之后的版本使用不带后缀的 `neoproot` 名称。

## 许可证

GPLv2，详见 [COPYING](COPYING)。
