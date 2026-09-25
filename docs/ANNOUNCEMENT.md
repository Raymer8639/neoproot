# neoproot — announcement drafts

Ready-to-paste drafts for v5.10.9. Every benchmark number below is from
`CHANGELOG.md` and was measured on a Termux aarch64 device with an Arch Linux ARM
container. Nothing here is projected: if a number is not in the CHANGELOG, it is
not in the drafts. The repair release also fixes GNU make 4.4 direct recursive
spawns under `--stat-shim` by translating glibc `eaccess()` through `faccessat2`.
Termux needs Linux 5.8+ for that syscall.

## Where to post, in order of expected reach

| Place | Why | Note |
| --- | --- | --- |
| [r/termux](https://www.reddit.com/r/termux/) | the largest Termux audience | post the English draft, flair it as a project |
| [Hacker News](https://news.ycombinator.com/submit) | "2.3x faster PRoot" is a real story for this crowd | use the Show HN title, then post the first comment yourself |
| [Lobsters](https://lobste.rs/story/new) | linux/BSD systems crowd | tag it `linux`, `mobile`, `performance` |
| [V2EX](https://www.v2ex.com/new) / 少数派 / 酷安 | 中文开发者与 Android 玩机人群 | 用中文稿；少数派走投稿，酷安配一张 `du` 前后对比截图 |
| X / Mastodon | 一条就够 | 用下面的一行版 + 基准图 |
| a proot-distro discussion, only when someone asks about performance | it answers a real question there | do not open a standalone issue for this: it reads as spam |

Rules that keep this from backfiring: say what was measured and on which device,
say which flag is opt-in, and never claim a speedup for compilation (there is
none).

## English draft (Reddit / Lobsters)

**Title:** neoproot — an ARM64 PRoot fork for Termux where stat-heavy work is ~2.3x faster

---

I run Debian/Arch userspaces on my phone with Termux, mostly for Node.js, pnpm,
TypeScript and nvim. The bottleneck was never the CPU: it was the container paying a
ptrace stop for every `stat`. So I forked PRoot (via proot-scicat) and moved the
metadata path out of the tracer.

Measured on a Termux aarch64 device, Arch Linux ARM container, identical output in
every mode:

- `du -As /usr` (whole-tree metadata walk): **33.3 s -> 14.4 s (2.32x)** with
  `--stat-shim`; `--seccomp-notify` alone gives 31.2 s.
- single `stat`: 288.7 -> **8.1 us** absolute, 308.5 -> **4.4 us** dirfd-relative.
- raw `syscall(SYS_statx)` (what Node/libuv actually calls): 324.5 -> **10.4 us**.
- Compilation is unchanged (80-file `cc -O0`: 18.2 / 18.5 / 18.3 s across modes) —
  the win is process startup, parsing and header I/O, not codegen.

How it works: `--stat-shim=<guest lib>` preloads a guest-ABI shim that resolves
`stat`/`lstat`/`statx` in-process (bind translation plus fake_id0). The guest's cwd
is virtual, so `AT_FDCWD`-relative names are deliberately handed back to the tracer
through a `--seccomp-notify` channel instead of being guessed at; that path costs
about what it did before (103 vs 111 us) and stays correct. Both flags are opt-in.

Install (Termux builds from source, because the release binaries are glibc):

```sh
curl -fsSL https://github.com/Raymer8639/neoproot/releases/latest/download/install.sh | sh
```

Also in there: link2symlink that survives pnpm/TypeScript real-path probing, a
launcher that handles the Termux host setup (wake-lock, fd limits, `LD_*`), and
fixes for VNC exit hangs and the misleading `signal 11` warning. v5.10.9 also fixes GNU make 4.4 direct recursive spawns under `--stat-shim`:
glibc `eaccess()` now uses one tracer-translated `faccessat2` call, so `$(MAKE)`
no longer fails before its child is created. Meson and GNUmake builds are both
available; Termux builds locally because release binaries are glibc. Earlier
releases also keep `sudo` working under the shim: the tracer re-injects the shim
environment into every guest `execve`.

ARM64 only, on purpose — x86_64 is not supported. Details, benchmarks and the exact
commands: https://github.com/Raymer8639/neoproot

## Show HN

**Title:** Show HN: neoproot – an ARM64 PRoot fork that makes Termux containers 2.3x faster

**First comment (post it yourself right after submitting):**

> neoproot is a fork of PRoot (via proot-scicat) for Android/Termux. Short version:
> a container running `du`, `find`, pnpm or TypeScript spends most of its time paying
> a ptrace stop per `stat`, so I moved that path in-process with a guest-ABI
> `LD_PRELOAD` shim, and kept a seccomp USER_NOTIF channel for what the shim cannot
> answer on its own (relative names against the virtual cwd, guest absolute
> symlinks, link2symlink disguise).
>
> `du -As /usr`: 33.3 s -> 14.4 s. Single `stat`: 288.7 -> 8.1 us. Compilation:
> unchanged. All numbers and the measurement commands are in the CHANGELOG; the
> device is a phone, so treat them as a starting point rather than a promise.
>
> Both flags are opt-in and the kernel requirements are documented. ARM64 only. I
> would especially like feedback from people running bwrap or heavier packaging
> workloads — that is where I had to chase the ugliest bugs.

## 中文稿（V2EX / 少数派 / 酷安）

**标题：** neoproot —— 让 Termux 容器里 stat 密集的活儿快 2.3 倍的 ARM64 PRoot 分支

---

我在手机上用 Termux 跑 Debian/Arch 用户空间，主要是 Node.js、pnpm、TypeScript 和
nvim。瓶颈从来不是 CPU，而是容器为每一次 `stat` 付一次 ptrace 停靠。所以我把 PRoot
（经 proot-scicat）fork 了一份，把元数据路径从 tracer 里搬了出来。

Termux aarch64 真机 + Arch Linux ARM 容器实测，各模式输出完全一致：

- `du -As /usr`（整树元数据遍历）：**33.3 s → 14.4 s（2.32×）**（`--stat-shim`）；只用
  `--seccomp-notify` 是 31.2 s。
- 单次 `stat`：绝对路径 288.7 → **8.1 µs**，dirfd 相对 308.5 → **4.4 µs**。
- 原生 `syscall(SYS_statx)`（Node/libuv 走的就是它）：324.5 → **10.4 µs**。
- 编译不受影响（80 文件 `cc -O0`：三种模式 18.2 / 18.5 / 18.3 s）——收益在进程启动、
  解析和头文件 I/O，不在代码生成。

原理：`--stat-shim=<guest 库>` 预加载一个 guest ABI 的 shim，在进程内完成
`stat`/`lstat`/`statx` 的绑定翻译与 fake_id0 伪装。guest 的当前目录是虚拟的，所以
`AT_FDCWD` 相对名**故意**交回 tracer，经 `--seccomp-notify` 通道处理，而不是靠猜；
这条路径的代价与原来基本持平（103 µs 对 111 µs），但语义正确。两个开关都是可选的。

安装（Termux 从源码构建，因为 release 里的二进制是 glibc 的）：

```sh
curl -fsSL https://github.com/Raymer8639/neoproot/releases/latest/download/install.sh | sh
```

此外还有：能在 pnpm/TypeScript 的真实路径探测下存活的 link2symlink、自动处理 Termux
宿主环境（wake-lock、fd 上限、`LD_*`）的启动器，以及 VNC 退出挂起和误导性的
`signal 11` 提示的修复。v5.10.7 还让 `sudo` 在 shim 下继续可用：tracer 会把 shim 环境
重新注入每一次 guest `execve`，setuid 启动器再也删不掉路径翻译。

只支持 ARM64（这是刻意的），不宣称支持 x86_64。细节、基准和完整命令都在仓库里：
https://github.com/Raymer8639/neoproot

## 一行版（X / Mastodon / 群里转发）

EN: A PRoot fork for Termux where `stat` costs 8 us instead of 289: `du -As /usr`
33.3 s -> 14.4 s, compilation unchanged. ARM64 only, both flags opt-in.
https://github.com/Raymer8639/neoproot

中文：Termux 容器里的 `du -As /usr` 从 33.3 s 降到 14.4 s（单次 stat 289 → 8 µs，
编译速度不变）。只支持 ARM64，两个加速开关都是可选的。
https://github.com/Raymer8639/neoproot

## Posting checklist

- [ ] `curl ... | sh` runs clean on a phone that has never built the project — this
      is the first thing anyone will try, and the `libtalloc` package-name bug in
      v5.10.6 and earlier is exactly why this line exists.
- [ ] `neoproot --version` prints the tag, and `--help` documents both perf flags.
- [ ] The release page you link shows `install.sh` and puts the install block above
      the auto-generated notes.
- [ ] Name the device and the container in the post; do not round 2.32x up to "3x".
- [ ] Do not claim a compile-time win and do not imply x86_64 works.
- [ ] Stay in the thread for a day. The useful follow-ups are almost always about
      bwrap, pnpm, or the fake-id0 uid/gid reporting (`pacman -Qkk` flags every file
      because the host inodes belong to the Android uid — expected, not a bug).