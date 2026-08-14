# 变更历史

本项目从 Gitee 上游 [proot-scicat](https://gitee.com/scicat-team/proot-scicat) 接手维护。
以下版本记录整理自上游 git 历史。

## [5.6.0-scicat] - 2026-05-01

**（当前版本，上游最后一次提交）**

- 魔改 uproot：C++23 极致性能版
- 裁剪兼容：放弃通用架构，换取 ARMv8.2 满血性能（含 NEON/dotprod/lse 优化）
- 引入 `neoproot` 主程序（历史名 uproot）：自动执行 Termux 环境初始化（wake-lock、`ulimit -n`、清理 `LD_*`）
- 系统调用路径高性能优化（`-fomit-frame-pointer`、`-funroll-loops`、去栈保护）
- 进程退出 `signal 11` 警告消除、进程存活判断
- 中文 VNC 退出卡死修复
- 内置自动高优先级调度 `setpriority(-20)`
- 实测：极重负载性能领先官方 7.2%

## [5.6.0-scicat] - 2026 年初（正式版）

- 修复 ptrace 权限问题，`setresuid`/`setresgid` 可用
- Debian apt 正常运行
- 安卓 12+ 适配

## [5.5.0-scicat] - 正式版

- 双平台兼容版（Termux + Linux）
- 移除 src 目录下的独立 Git 仓库，使其成为普通目录

## [5.1.3-scicat] - aarch64 修复版

- 解决 asm / Shell / 链接错误
- 含 JIT / AI 扩展
- Termux 专属：安卓 12+ 适配、root 模拟、屏蔽 talloc、后台保活

## 初始版本

- 基于官方 PRoot 的 Termux/Linux 优化版首发

---

## 本仓库（GitHub 接管维护）新增

### 2026-08-07（接管首日）

- 移除已停服的 Travis CI 配置，新增 GitHub Actions CI（ARM64 runner 构建 + 测试 + 自动发布）
- 新增 `build.sh`：Termux 一键构建/安装脚本
- Makefile：`MARCH` 变量可覆盖（默认 ARMv8.2 满血优化）；未安装 `upx` 时自动跳过压缩
- 重写 README，新增本变更日志
