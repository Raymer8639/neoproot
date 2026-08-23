# neoproot 使用说明与 FAQ

neoproot 是面向 ARM64 Linux 和 Termux 的 PRoot 容器运行工具，重点处理
Termux 下的启动干扰、权限限制和兼容性问题，同时保留 PRoot 的核心使用方式。

## 历史名称

项目直接祖先曾使用 `proot-scicat`，其二进制名称为 `uproot`；这些名称仅用于
说明项目血缘。当前项目和二进制名称均为 `neoproot`。

## 性能有什么提升？

性能结果取决于设备、rootfs、工作负载和宿主环境。下列数据来自 sysbench
高负载测试；轻度使用时差异可能处于测量误差内：

- 低负载（素数上限 10000）：与官方 PRoot 基本持平（误差范围内）。
- 中高负载（50000）：测试中领先 2.9%。
- 极重负载（100000）：测试中领先 7.2%。

## node 会报错 13 吗？

node 通常不会报错 13。绑定特权端口（例如 80）可能因宿主权限限制而失败；
其他端口（>=1024）不受该限制。`node -e "console.log(os.networkInterfaces())"`
通常可以取得网络接口信息。

## 哪些命令使用 neoproot 启动容器可以不加？

以下命令使用 neoproot 启动容器可以不加：

- unset LD_PRELOAD
- unset LD_LIBRARY_PATH
- unset LD_BIND_NOW

`neoproot.c` 是当前主程序，会处理必要的 Termux 环境准备，再启动容器；通常
无需在启动脚本中额外清理这些变量。

## neoproot 执行的这些命令会影响 Termux 吗？

它会在当前终端进程中临时调整环境变量。重新打开 Termux 或切换会话即可得到
新的终端环境。

## 安全与嵌套限制

neoproot 使用 ptrace 模拟 chroot/root，**不提供内核级隔离**。仅运行可信 rootfs，
不要将不受信任的用户当作安全边界隔离在其中。

neoproot 拒绝在另一个 PRoot 的 ptrace 跟踪下启动。请从 Termux 宿主环境启动，
不要嵌套运行 PRoot。
