# proot-scicat（uproot）

> 下一代半原生轻量级容器：比官方 PRoot 更快、更稳、更小，专为 **ARM64 / Android (Termux)** 优化。

[![CI](https://github.com/Raymer8639/proot-scicat-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/Raymer8639/proot-scicat-ai/actions/workflows/ci.yml)
![Platform](https://img.shields.io/badge/platform-ARM64%20%2F%20Android-blue)
![Language](https://img.shields.io/badge/C%2FC%2B%2B-C23%20%2F%20C%2B%2B23-orange)
![License](https://img.shields.io/badge/license-GPLv2-green)

proot-scicat（又名 **uproot**）是在原始 [PRoot](https://github.com/proot-me/proot) 项目基础上，由社区爱好者重新维护的增强版本。原始 PRoot 官方自 2023 年起更新放缓，大量编译警告、Android 兼容性问题、用户体验瑕疵长期未修复。

> 本项目自 2026 年 2 月起接手维护，**持续迭代中**。
> 原上游仓库（已基本停更）：[gitee.com/scicat-team/proot-scicat](https://gitee.com/scicat-team/proot-scicat)

## 核心特性

- ✅ 内置自动高优先级调度 `setpriority(-20)`，无需 ROOT 即可获得更强 CPU 资源倾向
- ✅ 修复中文 VNC 退出卡死、注销需切后台等"祖传 bug"
- ✅ 消除进程退出时的 `signal 11` 警告，增加进程存活判断
- ✅ 最大延迟 ↓ 40%+，更顺滑；线程更公平、抖动更小
- ✅ C23/C++23 现代精简架构，放弃通用兼容换取 ARMv8.2 满血性能
- ✅ 内置 `uproot.c` 主程序：自动处理 Termux 环境初始化（wake-lock、fd 上限、LD_* 清理），无需手工加启动参数

## 性能数据

来自 sysbench 高负载测试（低负载下与官方持平，无额外开销）：

| 负载 | 对比官方 PRoot |
|------|---------------|
| 低负载（素数 ≤ 10000） | 持平（误差范围内） |
| 中高负载（50000） | **领先 2.9%** |
| 极重负载（100000） | **领先 7.2%** |

## 环境要求

- 64 位 ARM 设备（aarch64 / ARMv8.2+ 指令集，覆盖绝大多数 Android 手机）
- Termux（或等效 Android Linux 环境）
- **不适用于 x86_64**（代码刻意裁剪掉通用架构支持）

## 快速开始

### 方式一：使用已发布二进制（推荐）

从 [Releases](https://github.com/Raymer8639/proot-scicat-ai/releases) 下载 `uproot`，放入 `$PREFIX/bin` 并赋予执行权限：

```sh
chmod +x uproot
mv uproot $PREFIX/bin/
```

### 方式二：Termux 内源码构建

```sh
pkg install clang make llvm binutils talloc upx
git clone https://github.com/Raymer8639/proot-scicat-ai.git
cd proot-scicat
sh build.sh install     # 构建并安装到 $PREFIX/bin
```

> `upx` 可选：用于压缩二进制减小体积（`--ultra-brute --lzma` 压缩后通常只有 1~2 MB）。
> 也可用 `make -C src uproot MARCH="-march=native"` 针对你的 CPU 定制指令集。

## 使用容器

```sh
# 以 root 身份进入 Debian/Ubuntu 容器（需已准备好 rootfs）
uproot -0 -r /data/data/com.termux/files/home/rootfs \
    -b /dev -b /proc -b /sys -b /sdcard \
    /usr/bin/env -i HOME=/root TERM=$TERM PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    /bin/bash --login
```

与官方 PRoot 用法完全一致，但 **无需** 手动 `unset LD_PRELOAD LD_LIBRARY_PATH LD_BIND_NOW` —— `uproot` 主程序会自动处理。

详细说明与 FAQ（node 报错 13、性能对比、VNC 等）见 [help.md](help.md)。

## 版本命名

基于官方 PRoot 版本号，后缀 `-scicat` 标识本分支，例如 `5.6.0-scicat`。变更历史见 [CHANGELOG.md](CHANGELOG.md)。

## 构建产物说明

- 编译目标默认 `-march=armv8.2-a+fp16+dotprod+lse+rcpc+simd+crc+crypto`（可用 `MARCH=` 覆盖）
- 链接选项：`-flto=thin`、`--gc-sections`、`--icf=all`、RELRO/NOW、去符号
- 依赖：`libtalloc`（Termux 包名 `talloc`）

## 维护

本项目由社区接手维护，欢迎：

- 提交 [Issue](https://github.com/Raymer8639/proot-scicat-ai/issues) 报告问题
- 提交 PR 修复 bug、优化性能
- 在 [Discussions](https://github.com/Raymer8639/proot-scicat-ai/discussions) 交流使用心得

## 许可证

GPLv2，详见 [COPYING](COPYING)。
