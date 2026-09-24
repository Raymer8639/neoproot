[English](README.md) | **简体中文**

# neoproot

面向 ARM64 的 PRoot 分支，专为 Android/Termux 容器优化。neoproot 适合在手机、平板上的 Debian/Ubuntu 用户空间中运行 Node.js、pnpm、TypeScript、nvim、bwrap 等高频系统调用工作流。

GitHub Release 资产是 **ARM64 Linux（glibc）** CI 产物。Termux 必须用 **本机 bionic** 编译，不要把这些文件装进 `$PREFIX/bin/neoproot`。

[![CI](https://github.com/Raymer8639/neoproot/actions/workflows/ci.yml/badge.svg)](https://github.com/Raymer8639/neoproot/actions/workflows/ci.yml)
![平台](https://img.shields.io/badge/platform-ARM64%20%2F%20Android-blue)
![语言](https://img.shields.io/badge/C%2FC%2B%2B-C23%20%2F%20C%2B%2B23-orange)
![许可证](https://img.shields.io/badge/license-GPLv2-green)

## 安装（一条命令）

```sh
curl -fsSL https://github.com/Raymer8639/neoproot/releases/latest/download/install.sh | sh
```

脚本会自动识别平台：在 **Termux** 上安装编译依赖，用对应 tag 的源码编译出 bionic 二进制，备份旧二进制后装进 `$PREFIX/bin`；在 **ARM64 Linux** 上下载 release 二进制、用 `SHA256SUMS` 校验后放进 `PATH`。它**不会**改动正在运行的容器 rootfs。不放心管道执行可以先看 [scripts/install.sh](scripts/install.sh)，`sh scripts/install.sh --help` 可看 `--version`、`--prefix`、`--portable` 参数。

## 在 Termux 中手动编译

务必在 Termux 宿主上编译。Linux CI / Release 文件不能当 Termux 的 Android 二进制用。

```sh
pkg install clang make llvm binutils pkg-config libtalloc
git clone https://github.com/Raymer8639/neoproot.git
cd neoproot
sh install.sh

# 或使用 Meson 构建（GNUmakefile 仍是基准实现）：
# 请先用包管理器安装 meson+ninja。
meson setup builddir
meson compile -C builddir
meson install -C builddir
```

安装脚本会把 `neoproot` 放到 `$PREFIX/bin`。

**ARM64 Linux**（不是 Termux）可以从 [Releases](https://github.com/Raymer8639/neoproot/releases) 下载 `neoproot` 或降低指令集要求的 `neoproot-portable`，校验 SHA256 后放入 `PATH`。

## 为什么使用 neoproot

- 自动处理 Termux 宿主初始化：wake-lock、文件描述符上限和 `LD_*` 清理由 `neoproot` 启动器完成。
- link2symlink 硬链接模拟兼容 pnpm 和 TypeScript/tsgo 通过 `/proc/<pid>/fd/<fd>` 探测真实路径的工作流。
- 移除分支原有的路径翻译线程池开销，高频路径操作下 nvim 与包管理器更顺畅。
- 可选 `--seccomp-notify`（Linux 5.0+）用 seccomp USER_NOTIF 模拟 `newfstatat`，目录元数据扫描少一次 ptrace 停靠。不加该参数时 kernel 4+ 行为不变。
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

以下均为 Termux aarch64 真机 + Arch Linux ARM 容器的实测，各模式输出完全一致。容器真正花时间的是 stat 类调用，而 neoproot 恰好把它们去掉了：

**`du -As /usr`（整树元数据遍历，各模式输出均为 `4007438`）**

| 模式 | 耗时 | 相对纯 ptrace |
|------|------|---------------|
| 纯 ptrace 路径 | 33.3 s | — |
| 仅 `--seccomp-notify` | 31.2 s | 1.07× |
| **`--stat-shim` + `--seccomp-notify`** | **14.4 s** | **2.32×** |

后续版本进一步削减了剩余停靠（`fcntl` 现在只对两个 fd 复制类命令停靠），同一测试从 15.7 s 降到 13.1 s，部署到设备后实测 11–12 s。

**单次 `stat` 调用（µs/次，纯 ptrace / notify / shim）**

| 调用 | 纯 ptrace | notify | shim |
|------|-----------|--------|------|
| 绝对路径 | 288.7 | 96.6 | **8.1** |
| dirfd 相对 | 308.5 | 114.4 | **4.4** |
| `AT_FDCWD` 相对 | 203.8 | 90.9 | 92.9 |
| 原生 `syscall(SYS_statx)` | 324.5 | 106.5 | **10.4** |

`AT_FDCWD` 相对名是**故意**留在 tracer 里的：guest 的当前目录是虚拟的，shim 会把这类调用经 `--seccomp-notify` 通道转交，而不是靠猜。代价与不加速的路径基本持平（103 µs 对 111 µs），换来语义正确。

编译不受影响（80 文件 `cc -O0`：三模式 18.2 / 18.5 / 18.3 s）；收益来自进程启动、解析与头文件 I/O。

更早的 sysbench 结果，供参考：

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

GPLv2。标准全文见 [LICENSE](LICENSE)；[COPYING](COPYING) 保留上游 PRoot/CARE 的原始版权声明。
