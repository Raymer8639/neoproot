**English** | [简体中文](README.zh-CN.md)

# neoproot（二进制与项目同名；历史名 proot-scicat / uproot）

> 下一代半原生轻量级容器：比官方 PRoot 更快、更稳、更小，专为 **ARM64 / Android (Termux)** 优化。

[![CI](https://github.com/Raymer8639/neoproot/actions/workflows/ci.yml/badge.svg)](https://github.com/Raymer8639/neoproot/actions/workflows/ci.yml)
![Platform](https://img.shields.io/badge/platform-ARM64%20%2F%20Android-blue)
![Language](https://img.shields.io/badge/C%2FC%2B%2B-C23%20%2F%20C%2B%2B23-orange)
![License](https://img.shields.io/badge/license-GPLv2-green)
![AI](https://img.shields.io/badge/AI-assisted-100%25-purple)

> **🤖 AI 声明：本项目的全部代码（含维护过程中的所有修改、修复与优化）均使用 AI 辅助编写/审查完成。**

## 上游关系（本项目 = 三方血缘）

```
proot-me/proot（原始 PRoot，停更）
        │
        ▼ 魔改：C23/C++23 + ARMv8.2 满血 + 裁剪兼容
gitee.com/scicat-team/proot-scicat（uproot，2026-05 停更）  ← 直接祖先（fork 起点）
        │
        ▼ 接管维护：修复 + 性能 + 兼容（本项目 42+ 提交）
Raymer8639/neoproot（本项目）
        ▲
        │ 持续跟进、回移修复（如 link2symlink proc-fd 名字替换 7ff389a1）
github.com/termux/proot（活跃维护）  ← 血缘源头 / 跟进目标
```

- **原始 PRoot**：[proot-me/proot](https://github.com/proot-me/proot)（上游已基本停更）
- **直接祖先（原上游）**：[gitee.com/scicat-team/proot-scicat](https://gitee.com/scicat-team/proot-scicat)（**uproot**，C23/C++23 极致性能魔改版；2026-05 起停更）
- **血缘源头 / 跟进目标**：[github.com/termux/proot](https://github.com/termux/proot)（Termux 团队活跃维护；本项目为 ARM64/Termux 场景，与其同源同生态）
- **本项目**：自 2026 年 2 月起在 uproot 基础上接手维护，**持续迭代中**；修复与性能优化为本项目原创，同时按需从 termux/proot 回移修复

## 核心特性

- ✅ 内置自动高优先级调度 `setpriority(-20)`，无需 ROOT 即可获得更强 CPU 资源倾向
- ✅ 修复中文 VNC 退出卡死、注销需切后台等"祖传 bug"
- ✅ 消除进程退出时的 `signal 11` 警告，增加进程存活判断
- ✅ 最大延迟 ↓ 40%+，更顺滑；线程更公平、抖动更小
- ✅ C23/C++23 现代精简架构，放弃通用兼容换取 ARMv8.2 满血性能
- ✅ 内置 `neoproot.c` 主程序：自动处理 Termux 环境初始化（wake-lock、fd 上限、LD_* 清理），无需手工加启动参数
- ✅ 移除上游魔改的路径翻译线程池（cond_wait 往返开销）：真机 syscall 处理速度与官方 PRoot 持平（lstat 304us/次 vs 原版 293-312us），修复 nvim 等高频操作卡顿
- ✅ link2symlink 硬链接模拟全面兼容 pnpm / tsc（tsgo）——物化机制 + /proc/&lt;pid&gt;/fd/&lt;fd&gt; 名字替换（回移自 termux/proot 7ff389a1）解决 tsgo 的 O_PATH+readlink 真实路径探测（TS2307/TS6054/panic 全部解决）

## 性能数据

来自 sysbench 高负载测试（低负载下与官方持平，无额外开销）：

| 负载 | 对比官方 PRoot |
|------|---------------|
| 低负载（素数 ≤ 10000） | 持平（误差范围内） |
| 中高负载（50000） | **领先 2.9%** |
| 极重负载（100000） | **领先 7.2%** |

## 环境要求

- ARM64 Linux 或 Termux（aarch64 / arm64）；主要运行目标为 Android/Termux。
- **不支持 x86_64**（代码刻意裁剪掉通用架构支持）。

## 快速开始

### 方式一：使用已发布二进制（推荐）

从 [Releases](https://github.com/Raymer8639/neoproot/releases) 下载优化版 ARM64
构建 `neoproot`，或下载面向 ARMv8-A 的便携版 `neoproot-portable`
（`-march=armv8-a -mtune=generic`）。安装前请校验文件：

```sh
sha256sum neoproot
chmod +x neoproot
mv neoproot $PREFIX/bin/
```

将输出的 SHA256 与 Release 页面公布的校验值比对。

### 方式二：Termux 内源码构建

```sh
pkg install clang make llvm binutils talloc
git clone https://github.com/Raymer8639/neoproot.git
cd neoproot
sh build.sh install     # 构建并安装到 $PREFIX/bin
```

> `sh build.sh` 只构建 `src/neoproot`；`sh build.sh install` 还会安装为
> `$PREFIX/bin/neoproot`。`upx` 为可选依赖，可用于压缩二进制。
> 也可用 `make -C src neoproot MARCH="-march=native"` 针对你的 CPU 定制指令集。

## 使用容器

```sh
# 以 root 身份进入 Debian/Ubuntu 容器（需已准备好 rootfs）
neoproot -0 -r /data/data/com.termux/files/home/rootfs \
    -b /dev -b /proc -b /sys -b /sdcard \
    /usr/bin/env -i HOME=/root TERM=${TERM} PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    /bin/bash --login
```

与官方 PRoot 用法完全一致，但 **无需** 手动 `unset LD_PRELOAD LD_LIBRARY_PATH LD_BIND_NOW` —— `neoproot` 主程序会自动处理。

## 文档

- [变更历史](CHANGELOG.md)
- [使用说明与 FAQ](help.md)
- [安全策略](SECURITY.md)
- [参与贡献](CONTRIBUTING.md)
- [获取支持](SUPPORT.md)

## 版本命名

版本号沿用 termux/proot 风格（如 `5.1.107.90`）；2026-08-15 前的 Release 保留历史后缀 `-scicat`（如 `v5.7.2-scicat`），**v5.7.3 起停用后缀**。变更历史见 [CHANGELOG.md](CHANGELOG.md)。

## 构建产物说明

- 编译目标默认 `-march=armv8.2-a+fp16+dotprod+lse+rcpc+simd+crc+crypto`（可用 `MARCH=` 覆盖）；便携版 Release 使用 `-march=armv8-a -mtune=generic`
- 链接选项：`-flto=thin`、`--gc-sections`、`--icf=all`、RELRO/NOW、去符号
- 依赖：`libtalloc`（Termux 包名 `talloc`）

## 维护

本项目由社区接手维护，欢迎：

- 提交 [Issue](https://github.com/Raymer8639/neoproot/issues) 报告问题
- 提交 PR 修复 bug、优化性能
- 在 [Discussions](https://github.com/Raymer8639/neoproot/discussions) 交流使用心得

## 许可证

GPLv2，详见 [COPYING](COPYING)。
