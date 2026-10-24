# neoproot — announcement drafts

Current public release: **v5.14.0** (2026-10-24), which includes opt-in UML
seccomp, `--quiet`, `--cpus`, `--rootflags` and the cgroup2 reference init.
The separate SMP/Docker kernel profile is a matching kernel asset from
`linux-um-arm64`, not a neoproot binary.

All numbers below are device measurements. Fast-path numbers are from the
existing CHANGELOG benchmarks on a Termux aarch64 device with an Arch Linux ARM
container. UML numbers were measured on the same phone with real UML kernels
and the listed rootfs type. Do not round 2.32x up to “3x”, and do not claim a
compile-time win: compilation is unchanged.

## Where to post

| Place | Why | Note |
| --- | --- | --- |
| [r/termux](https://www.reddit.com/r/termux/) | largest Termux audience | post the English draft, flair as a project |
| [Hacker News](https://news.ycombinator.com/submit) | a faster PRoot plus a real-kernel backend is a concrete systems story | use the Show HN title, then post the first comment yourself |
| [Lobsters](https://lobste.rs/story/new) | linux/BSD systems crowd | tag it `linux`, `mobile`, `performance` |
| [V2EX](https://www.v2ex.com/new) / 少数派 / 酷安 | 中文开发者与 Android 玩机人群 | 用中文稿；配基准图或 `du` 前后对比截图 |
| X / Mastodon | one post is enough | use the one-line version plus a benchmark image |
| a proot-distro discussion, only when someone asks | it answers a real question there | do not open a standalone issue; it reads as spam |

## English draft (Reddit / Lobsters)

**Title:** neoproot — a faster ARM64 PRoot fork for Termux, now with an optional real Linux kernel

---

I run Debian/Arch userspaces on my phone with Termux, mostly for Node.js, pnpm,
TypeScript and nvim. The first bottleneck was PRoot paying a ptrace stop for
metadata work. neoproot fixes that with an opt-in stat shim and seccomp
USER_NOTIF. The second bottleneck is architectural: some workloads need a real
kernel — namespaces, mounts, block devices, Docker — so neoproot also has an
optional UML backend that boots a separate Linux kernel.

### Fast path: less metadata work in the tracer

Measured on a Termux aarch64 device, Arch Linux ARM container, identical output:

- `du -As /usr`: **33.3 s → 14.4 s (2.32×)** with `--stat-shim`;
  `--seccomp-notify` alone gives 31.2 s.
- single `stat`: 288.7 → **8.1 µs** absolute, 308.5 → **4.4 µs** dirfd-relative.
- raw `syscall(SYS_statx)` (what Node/libuv calls): 324.5 → **10.4 µs**.
- compilation is unchanged (80-file `cc -O0`: 18.2 / 18.5 / 18.3 s across modes).

The stat shim runs in the guest process and answers bind-translation and fake-id0
metadata in-process. Names relative to the virtual cwd deliberately go back
through `--seccomp-notify` instead of guessing; that path costs about what it
did before (103 vs 111 µs) and stays correct. Both flags are opt-in.

### UML backend: a real kernel when PRoot is the wrong tool

`--backend=um` boots a separate UML kernel through the in-process
`neoproot-um` supervisor. The guest uses a real ext4 root with a COW file,
real ownership, real namespaces, and the kernel’s own syscall path. The
dispatcher `--backend=auto` chooses per command/rootfs — it does not mix PRoot
and UML per syscall.

Two device A/B runs on the same ext4 image, kernel and syscall-heavy probe:

| metric | UML ptrace | UML seccomp |
|---|---:|---:|
| whole probe | 43–61 s | **4.2–5.1 s** |
| `getpid` | 158–221 µs | **12.5–13.0 µs** |
| `open`+`close` | 501–503 µs | **14–50 µs** |
| `read` | 209–222 µs | **5.9–13.7 µs** |

One boot followed by five `/bin/true` commands took **1.1 s**, versus
**4.5 s** for five separate UML boots. A one-shot command still pays about
0.8–1.1 s of kernel boot; a persistent shell amortises it.

Ext4 is the UML default because ownership is real: 64 MiB sequential write is
295 MB/s vs 242 MB/s on hostfs; read is 1.1 GB/s vs 672 MB/s. `--net-auto`
configures the guest side of the network (DHCP, then static fallback), and the
supervisor restores the host terminal after the run.

### New in v5.14.0

These are included in the v5.14.0 neoproot release:

- `--seccomp=off|auto|on` and `--quiet` for the UML supervisor.
  seccomp is faster but is **not** a security boundary: the UML kernel’s own
  documentation says guest userspace can read/write all physical memory. It is
  opt-in and only for trusted guests.
- `--cpus=N` for an SMP kernel; more than one CPU requires seccomp.
- `--rootflags=OPTS` for ext4 mount options, e.g.
  `commit=60,data=writeback`; read-only runs always keep `noload` first.
- cgroup2 mounted by the reference ext4 init, plus a separate SMP/Docker kernel
  profile: 2/4 CPUs, `PID_NS`/`USER_NS`, `CGROUP_BPF`, overlayfs,
  veth/bridge and netfilter. The default kernel stays the faster uniprocessor
  profile; SMP is opt-in because TREE_RCU/SMP locks make a one-CPU syscall-heavy
  workload slower.
- Stripped kernel assets: UP 91M → **9.3M**, SMP/Docker 136M → **13M**. Startup
  time is essentially unchanged; this is an asset-size win.

### Install

The public release is **v5.14.0**. Termux builds the bionic binary from source;
the release binaries are ARM64 glibc builds:

```sh
curl -fsSL https://github.com/Raymer8639/neoproot/releases/latest/download/install.sh | sh
```

UML also needs a matching kernel and stub from
[linux-um-arm64](https://github.com/Raymer8639/linux-um-arm64), plus its
`um-init`/`umnet` compatibility. The `passt-bionic` companion comes from
[passt-android](https://github.com/Raymer8639/passt-android). The current
`--seccomp`/`--cpus`/`--rootflags` are included in v5.14.0; the matching
SMP/Docker kernel profile is released separately from linux-um-arm64.

ARM64 only: x86_64 is intentionally not supported. UML mode must start from an
untraced host process; ext4 roots have been exercised at 64/128/256 MB.

Details and exact commands: https://github.com/Raymer8639/neoproot

## Show HN

**Title:** Show HN: neoproot – a faster ARM64 PRoot fork with an optional real-kernel backend

**First comment:**

> neoproot is a PRoot fork for Android/Termux with two execution paths. The fast
> path keeps PRoot and moves stat-heavy work in-process with a guest-ABI shim +
> seccomp USER_NOTIF: `du -As /usr` went from 33.3 s to 14.4 s, while
> compilation stayed unchanged. The optional UML path boots a real Linux kernel
> for things PRoot cannot do — namespaces, mounts, block devices, Docker — with
> an ext4 root and COW. Its seccomp userspace mode took a syscall-heavy probe
> from 43–61 s to 4.2–5.1 s; a persistent shell amortises the ~0.9 s boot over
> many commands.
>
> The trade-off is deliberate: PRoot is not per-syscall mixed with UML. `--backend=auto`
> chooses per command or rootfs image, because one process cannot live in two
> kernels. UML seccomp is faster but not a security boundary, so it is opt-in
> and for trusted guests. ARM64 only. I would especially like feedback from
> people running bwrap, Docker/Podman or heavy packaging workloads.

## 中文稿（V2EX / 少数派 / 酷安）

**标题：** neoproot —— 让 Termux 的 PRoot 更快，并可选启动真实 Linux 内核

---

我在手机上用 Termux 跑 Debian/Arch 用户空间，主要是 Node.js、pnpm、
TypeScript 和 nvim。第一个瓶颈是 PRoot 为元数据操作付 ptrace 停靠；neoproot
用可选的 stat shim + seccomp USER_NOTIF 把这条路径搬进 guest 进程。第二个瓶颈
是架构限制：namespace、mount、块设备、Docker 这类负载需要真内核，所以 neoproot
还有一个可选的 UML 后端，启动一个独立的 Linux 内核。

### fast 路径：减少 tracer 里的元数据停靠

Termux aarch64 真机 + Arch Linux ARM 容器，各模式输出一致：

- `du -As /usr`：**33.3 s → 14.4 s（2.32×）**（`--stat-shim`）；
  只用 `--seccomp-notify` 是 31.2 s。
- 单次 `stat`：绝对路径 288.7 → **8.1 µs**，dirfd 相对 308.5 → **4.4 µs**。
- 原生 `syscall(SYS_statx)`（Node/libuv 走的路径）：324.5 → **10.4 µs**。
- 编译速度不变（80 文件 `cc -O0`：三种模式 18.2 / 18.5 / 18.3 s）。

### UML 后端：PRoot 不适合时用真内核

`--backend=um` 通过进程内的 `neoproot-um` supervisor 启动独立的 UML
内核。guest 使用真实 ext4 根 + COW 文件，有真实属主、真实 namespace 和内核自己的
syscall 路径。`--backend=auto` 按命令/rootfs 类型选择，不做 per-syscall 混合。

同一 ext4 镜像、内核和 syscall 密集探针的两轮真机 A/B：

| 指标 | UML ptrace | UML seccomp |
|---|---:|---:|
| 整轮探针 | 43–61 s | **4.2–5.1 s** |
| `getpid` | 158–221 µs | **12.5–13.0 µs** |
| `open`+`close` | 501–503 µs | **14–50 µs** |
| `read` | 209–222 µs | **5.9–13.7 µs** |

一次 boot 后连跑 5 条 `/bin/true` 用 **1.1 s**，5 次单独 boot 用 **4.5 s**。
一次性命令仍要付约 0.8–1.1 s 的内核启动成本；常驻 shell 才能摊薄它。

UML 默认用 ext4，因为属主语义是真的：64 MiB 顺序写 295 MB/s vs hostfs
242 MB/s，读 1.1 GB/s vs 672 MB/s。`--net-auto` 会配好 guest 侧 DHCP/静态回退，
supervisor 在退出时恢复宿主终端。

### v5.14.0 新增内容

这些已包含在 v5.14.0 的 neoproot 发布中：

- UML 的 `--seccomp=off|auto|on` 与 `--quiet`。seccomp 更快，但**不是
  安全边界**：UML 内核文档明确说 guest 用户态可以读写全部物理内存；只对可信
  guest 显式打开。
- `--cpus=N`：SMP 内核才能多 CPU；大于 1 时必须同时启用 seccomp。
- `--rootflags=OPTS`：ext4 挂载选项，例如 `commit=60,data=writeback`；只读
  运行始终先保留 `noload`。
- ext4 init 挂载 cgroup2；另有 SMP/Docker 内核 profile：2/4 CPU、`PID_NS`/
  `USER_NS`、`CGROUP_BPF`、overlayfs、veth/bridge、netfilter。默认仍是更快的
  UP 内核；SMP 单 CPU 的 syscall 负载会因 TREE_RCU/SMP 锁变慢，所以按需开启。
- strip 后内核资产：UP 91M → **9.3M**，SMP/Docker 136M → **13M**；启动时间基本不变，
  主要收益是体积。

### 安装

公开版本是 **v5.14.0**。Termux 从源码构建 bionic 二进制，release 里的二进制是
ARM64 glibc：

```sh
curl -fsSL https://github.com/Raymer8639/neoproot/releases/latest/download/install.sh | sh
```

UML 还需要 [linux-um-arm64](https://github.com/Raymer8639/linux-um-arm64) 的
kernel/stub 和配套的 `um-init`/`umnet`；`passt-bionic` 来自
[passt-android](https://github.com/Raymer8639/passt-android)。当前的
`--seccomp`/`--cpus`/`--rootflags` 已包含在 v5.14.0；配套 SMP/Docker 内核由 linux-um-arm64 单独发布。

只支持 ARM64，x86_64 刻意不支持；UML 必须从未被跟踪的宿主进程启动；ext4 根验证过
64/128/256 MB。细节和完整命令：https://github.com/Raymer8639/neoproot

## One-line version

EN: neoproot — a faster ARM64 PRoot for Termux, now with an optional real-kernel
UML backend. Fast path: `du -As /usr` 33.3→14.4 s, stat 289→8 µs. UML
seccomp: syscall-heavy probe 43–61→4.2–5.1 s. ARM64 only; UML seccomp is opt-in.
https://github.com/Raymer8639/neoproot

中文：neoproot —— 更快的 Termux ARM64 PRoot，并可选启动真实 Linux 内核。
fast 路径 `du -As /usr` 33.3→14.4 s、stat 289→8 µs；UML seccomp 的
syscall 密集探针 43–61→4.2–5.1 s。只支持 ARM64，UML seccomp 需显式开启。
https://github.com/Raymer8639/neoproot

## Posting checklist

- [ ] The release page you link is **v5.14.0** (or a newer tag); do not put
      post-v5.14.0 master features in that tag’s release notes.
- [ ] If you mention UML seccomp/`--cpus`/`--rootflags`, link the matching
      kernel assets from linux-um-arm64 separately.
- [ ] Run the one-line installer on a clean Termux host before posting.
- [ ] Name the device and rootfs; do not round 2.32× up to “3×”.
- [ ] Do not claim a compile-time win, and do not imply x86_64 works.
- [ ] For UML, state that seccomp is not a security boundary and is for trusted guests.
- [ ] Do not claim Docker itself ships in the image: the Docker profile is a kernel
      config, not a userspace Docker installation.
- [ ] Stay in the thread for a day. Useful follow-ups are usually bwrap, pnpm,
      ext4/COW, or fake-id0 uid/gid reporting.
