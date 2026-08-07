# 安全策略

## 报告安全漏洞

- 通过 [GitHub Security Advisories](https://github.com/Raymer8639/proot-scicat-ai/security/advisories/new) 私下报告漏洞（推荐）
- 或通过 [Issues](https://github.com/Raymer8639/proot-scicat-ai/issues) 提交（请勿包含利用细节）

我们会在确认后尽快修复并发布。

## 运行安全

uproot 与官方 PRoot 一样通过 ptrace 模拟 chroot/root，**不提供真正的内核级隔离**。
请仅运行你信任的 rootfs，不要把 untrusted 用户放进来。

另请参阅 Termux 安全策略：https://termux.dev/security
