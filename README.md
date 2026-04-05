# proot-scicat

这是在原始 PRoot 项目基础上，由社区爱好者重新维护的增强版本。

原始 PRoot 官方自 2023 年起更新放缓，大量编译警告、Android 兼容性问题、用户体验瑕疵长期未修复。我们于 2026 年 2 月开始研究轻量级容器实现，在编译原版 proot 源码时发现诸多问题，因此决定接手并持续维护。

## 核心特性

- ✅ 内置自动高优先级调度 setpriority(-20)，无需 ROOT 即可获得更强 CPU 资源倾向
- ✅ 修复中文 VNC 退出卡死、注销需切后台等“祖传 bug”
- ✅ 消除进程退出时的 `signal 11` 警告，增加进程存活判断
- ✅ 新增 `PROOT_PORT_ADD` 环境变量，实现类 Docker 端口映射
- ✅ 新增 `PROOT_NETLINK_ROUTE`，修复 Node.js 获取网络接口权限错误
- ✅ 性能优化：多核负载提升 5%~9%，线程公平性优于官方
- ✅ 精简 arm64 架构，使用 Bionic 库，体积更小、更适合 Android
- 等……
## 版本命名

基于官方版本版，后缀 `-scicat` 标识本分支，例如 `5.6.0-scicat`。持续迭代，专注稳定与性能。

## 适用场景

Termux、Android 环境、嵌入式 Linux 等无 root 权限下需要 chroot / mount 绑定的场景，尤其适合运行 VNC 图形界面、Node.js 服务、容器化 Web 应用。