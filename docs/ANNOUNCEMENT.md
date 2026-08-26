# neoproot: an ARM64 Android/Termux PRoot fork for real developer workflows

## English announcement

neoproot is an ARM64-focused PRoot fork for people running Linux userspaces on Android and Termux. It is aimed at practical developer workloads such as Node.js, pnpm, TypeScript/tsgo, nvim, containers, and bwrap.

### Release draft for v5.9.1

- Reused metadata and path-resolution state to reduce repeated work in common filesystem paths.
- Hardened link2symlink stat handling and added regression coverage for pnpm/TypeScript-style real-path probing.
- Kept the optimized ARM64 build and a lower-instruction-set `neoproot-portable` build for ARM64 Linux.
- Preserved the Termux launcher behavior that initializes the host environment and removes conflicting `LD_*` variables.

Install instructions and supported-environment limits are in the [English README](../README.md). Chinese readers can use the [简体中文 README](../README.zh-CN.md).

The published benchmark is device- and workload-specific: low load is within noise of official PRoot, while the recorded medium-high and extreme sysbench runs were 2.9% and 7.2% faster. Please report your own device, Android/Termux versions, exact command, baseline, and repeated measurements through the [performance report form](https://github.com/Raymer8639/neoproot/issues/new?template=performance_report.yml).

This project deliberately targets ARM64 and does not claim x86_64 support. Feedback, focused bug reports, and reproducible compatibility fixes are welcome in [Issues](https://github.com/Raymer8639/neoproot/issues) and [Discussions](https://github.com/Raymer8639/neoproot/discussions).

## 简体中文翻译

neoproot 是面向 ARM64 的 PRoot 分支，服务于在 Android/Termux 上运行 Linux 用户空间的开发者，重点覆盖 Node.js、pnpm、TypeScript/tsgo、nvim、容器和 bwrap 等实际工作流。

### v5.9.1 发布稿

- 复用元数据和路径解析状态，减少常见文件系统路径上的重复工作。
- 加固 link2symlink 的 stat 处理，并为 pnpm/TypeScript 风格的真实路径探测增加回归覆盖。
- 保留 ARM64 优化构建，并为 ARM64 Linux 提供降低指令集要求的 `neoproot-portable`。
- 保留 Termux 启动器自动初始化宿主环境、清理冲突 `LD_*` 变量的行为。

安装方式和环境限制请看[英文 README](../README.md)，中文用户可看[简体中文 README](../README.zh-CN.md)。

已发布的性能数据与设备和工作负载有关：低负载与官方 PRoot 在误差内持平，记录中的中高负载和极重负载 sysbench 分别快 2.9% 和 7.2%。欢迎通过[性能反馈表单](https://github.com/Raymer8639/neoproot/issues/new?template=performance_report.yml)提交设备、Android/Termux 版本、完整命令、基线和多次测量结果。

本项目明确以 ARM64 为目标，不宣称支持 x86_64。欢迎在 [Issues](https://github.com/Raymer8639/neoproot/issues) 和 [Discussions](https://github.com/Raymer8639/neoproot/discussions) 提交聚焦的 Bug、可复现的兼容性修复和使用反馈。
