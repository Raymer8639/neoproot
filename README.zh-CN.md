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
CC=clang CXX=clang++ meson setup builddir
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

## UML 后端（可选的第二执行后端）

neoproot 有两个执行后端。默认是 PRoot tracer：不写 `--backend` 或显式
`--backend=fast` 时使用，通过 `ptrace`（以及可选的 seccomp USER_NOTIF）翻译
路径和用户/组 ID，不需要 root。UML 后端是可选的第二执行后端：
`--backend=um` 通过 `neoproot-um` supervisor 启动独立的 UML guest 内核，命令
运行在真实 Linux 内核上，而不是经过系统调用翻译。它必须从未被跟踪的 Termux
宿主进程启动，不能在已有 PRoot 容器或 sandbox 内嵌套运行。

### 根文件系统：UML 后端默认用 ext4

UML 后端应当配 **ext4 镜像 + COW 文件**使用（启动脚本与本文示例都以此为默认）。
在这台开发机上实测，ext4 根的顺序 IO 比 hostfs 更快 —— 64 MiB 写入 295 vs
242 MB/s、读取 1.1 GB/s vs 672 MB/s —— 因为 hostfs 每次操作要往返用户态，而 ext4
的块层在 guest 内核里成批提交。元数据密集操作相反（300 次 rename：hostfs 0.19 s、
ext4 0.26 s），但绝对差只有几十毫秒。

决定性的理由不是速度而是正确性：hostfs 根把宿主属主原样透传，guest 里看到的还是
Termux 应用 uid，而 `chown` 不会成功（宿主进程没有 `CAP_CHOWN`），于是 `apk add`
每个文件都报 `Failed to set ownership ... Operation not permitted`。ext4 根在 guest
内有真实属主，包管理因此可用：`apk add sudo` 完成并输出 `OK: 10 MiB in 17 packages`。

UML 后端仍可用 `--hostfs`（启动脚本的参数）回到 hostfs 根；PRoot 系后端本来就只能
用目录（路径翻译需要目录树，不能直接吃文件系统镜像）。
`-r`/`--rootfs` 既可以是宿主目录，也可以是 ext4 镜像。目录以 UML `hostfs`
导出给 guest，**这种根不是隔离沙箱**：文件属主用的是宿主真实 uid，原样透传给
guest —— Termux 应用 uid 拥有的文件在 guest 里就显示成那个 uid，而 `chown` 不会
成功（宿主进程没有 `CAP_CHOWN`，而改属主正是这个能力的作用）。只写文件的安装
流程（创建/写入/删除/chmod）正常；需要重新 chown 的不行，`apk add` 就属于后者
（每个文件报 `Failed to set ownership ... Operation not permitted`，但文件已经写
进去了）。需要 guest 侧属主语义时用 ext4 镜像。ext4 镜像作为 guest 根挂载，每次运行使用独立的临时 COW 文件，
运行结束即删除，基础镜像永远不会被写入。`--cow-file=PATH` 改为把 COW 文件
保存在 `PATH`（必须是绝对路径）：文件不存在时创建，下次运行继续复用——因此
下一次能看到上一次写入的内容——运行结束后保留。COW 文件与创建它时的镜像
绑定（文件头记录镜像大小和 mtime），镜像不匹配时会拒绝启动；`--cow-file` 与
`--readonly` 互斥，`--readonly` 直接打开 ext4 镜像，不创建 COW。UML 内核和
`stub_exe` 可以通过 `neoproot-um` 的命令行参数提供，也可以用下面的环境变量：

```sh
export NEOPROOT_UM_KERNEL=/path/to/linux-bionic
export NEOPROOT_UM_STUB=/path/to/stub_exe
neoproot --backend=um --rootfs=/path/to/rootfs -- /bin/sh
neoproot --backend=um --rootfs=/path/to/rootfs.ext4 --readonly -- /bin/true
```

内核和 stub 必须用 linux-um-arm64 仓库的 `build-bionic.sh` 构建，并与配套的
`um-init`、`umnet`、`passt` 一起使用；不匹配的组合不受支持。

### 绑定（`-b`）

hostfs 直接把选定的宿主目录暴露给 guest，**不是**安全隔离边界。源目录已在
该根内时，可以用 `-b host:guest[:ro]` 映射；根外来源、`/proc`、`/sys`、`/dev`
等受控目标以及不安全目标会被拒绝。

ext4 模式接受同样的 `-b host:guest[:ro]`，源是宿主路径：ext4 guest 有自己的
根，不存在“rootfs 内部”这一限制。guest init 负责把每个来源（本身是一个
hostfs 挂载，`:ro` 时只读）挂载到 guest 内；目录目标必须已存在或可在 guest
内创建。ext4 模式要求镜像中的 `/um-init` 来自匹配的 UM harness。supervisor
在挂载 guest 的 proc 后传入 `session-v1` 协议参数，init 脚本把临时 hostfs
会话挂到 `/run/neoproot`，并通过该挂载回传命令状态。

绑定需要 init 真正会挂载它们，这一点作为显式协议特性声明，而不是默认假设：

- supervisor 把请求的绑定写到 `/run/neoproot/binds`，每行一条，字段用制表符
  分隔：`source<TAB>target<TAB>dir|file<TAB>ro|rw<TAB>name`。`source` 是
  hostfs 挂载选项（相对于内核 `hostfs=` 根的路径），`name` 是文件绑定的文件
  名，目录绑定用 `-`。
- 实现该特性的 init 在运行命令前写 `/run/neoproot/init-features`，内容包含
  `neoproot-init-protocol=2` 和 `feature=binds`。
- 请求了绑定却缺少该声明时，supervisor 不会报告成功
  （`neoproot-um: the guest /um-init does not support binds`），生成的包装
  脚本也不会运行命令。guest 侧挂载失败会通过
  `/run/neoproot/protocol-error` 上报，并打印为
  `neoproot-um: guest init reported: ...`。

因此 ext4 根上的 `-b` 要求 init 实现 **init protocol 2** 和 `binds` 特性。
不支持该协议的老 `um-init` 会被明确拒绝，而不是静默跳过绑定。
`tests/um-init-ext4.sh` 是参考实现，`tests/stability-um-backend.sh` 在构建
镜像时会安装它。UM harness 自带的 `um-init` 也需要补上同样的两项，才能用于
ext4 根上的 `-b`。

### 网络

`--net` 通过 `umnet` + `passt` 给 guest 提供真实 IPv4 网络：DHCP、DNS、ICMP、
TCP 均可通，guest 退出码仍经 session 协议回传。`umnet`/`passt` 从 `$PATH`
查找，也可以用 `NEOPROOT_UM_NET`/`NEOPROOT_UM_PASST` 指定；`--net-addr=`、
`--net-gateway=` 分别覆盖客机地址与网关（默认 `10.0.2.15/24`、网关
`10.0.2.2`）。只有显式给出 `--net-dns=<地址>` 时才向 guest 宣告 nameserver；
默认由 `umnet` 读取宿主自己的解析器，`--net-dns=none` 则不宣告任何
nameserver。

`--net` 建的是**链路**，不是 guest 侧的配置：UML 里接口归 guest 所有，而
`passt` 起的 DHCP 服务端只会应答来问的客户端。所以单用 `--net` 时 `vec0` 是
down 的、没有地址也没有路由。加上 `--net-auto` 就由这一侧替你配好：先向
DHCP 服务端跑 `udhcpc`，没有客户端或没拿到租约时用
`--net-addr=`/`--net-gateway=` 做静态回退。它不会让运行失败——网络没起来的
容器仍然是能用的容器。`--net-auto` 蕴含 `--net`，两种根都适用：配置脚本由
supervisor 生成，无论 hostfs 还是 ext4 都由 guest 的 init 执行。

```sh
neoproot --backend=um -r /path/to/rootfs --net-auto -- /bin/sh
```

guest 的 loopback 每次运行都会自动起好，`127.0.0.1` 无需额外设置即可用；
其余网络才依赖 `--net`。


`--net-ipv6` 让 `umnet` 启动它的第二个、纯 IPv6 的 `passt` helper，从而给
guest 提供 IPv6：

```sh
neoproot --backend=um -r /path/to/rootfs --net --net-ipv6 -- /bin/sh
```

`--net-ipv6-addr=ADDR[/PLEN]`、`--net-ipv6-gw=ADDR` 覆盖 guest 的 IPv6 地址
与网关（默认 `fd00::2/64`、`fe80::1`）；不给就用 `umnet` 自己的默认值，
neoproot 不传它只能猜的值。`--net-ipv6-dns=ADDR` 宣告 IPv6 nameserver，
`--net-ipv6-dns=none` 不宣告，默认由 `umnet` 读取宿主的解析器。IPv6 是
`--net` 的一种模式而不是独立网络：没有 `--net` 时直接报错
（`neoproot-um: --net-ipv6 options require --net`），而不是启动一个被许诺了
却拿不到协议栈的 guest。

IPv6 用独立的第二个 helper 而不是双栈 helper，是为了让没有预先打过 IPv6 补丁
的 `passt`（在 Android 上它会因为打开 `NETLINK_ROUTE` 被拒绝而丢掉 IPv6）
不影响 IPv4。该 helper 需要配套构建的 UM harness；旧版会在说明后继续以纯 IPv4
运行。

### 控制台、生命周期与退出状态

guest 控制台连接调用者的终端，终端尺寸变化（SIGWINCH）会转发给 guest，因此从
该模式启动的全屏程序能拿到正确的窗口大小。

运行期间终端会被切到 raw 模式，结束后恢复。否则 guest 自己的行编辑器会向终端
查询光标位置（`ESC [ 6 n`），回复被回显成 `^[[r;cR` 出现在屏幕上；输入会回显
两遍；控制字符也会先被宿主终端解释掉。管道与重定向文件不受影响。

hostfs 根下 guest 命令跑在一个新会话里（`setsid -c`），控制台因此成为它的控制
终端：`/dev/tty` 可以打开，登录 shell 不再打印 `can't access tty; job control
turned off`，Ctrl-C / Ctrl-Z 也能送到 guest 的前台进程。ext4 根由它自己的
`/um-init` 负责同样的会话设置。

`--timeout=SECONDS` 限制单次运行时长（默认 120 秒）。supervisor 会捕获
SIGINT/SIGTERM/SIGHUP/SIGQUIT，用同一信号通知 UML 进程组，清理该进程组，并
返回有明确含义的状态：

- guest 自身的退出码原样返回；
- 超时返回 `124`；
- 被转发的信号返回 `128 + 信号编号`（SIGTERM 为 `143`）；
- guest session/init 失败返回 `125`，无法进入请求的工作目录返回 `126`。

运行被杀死或 guest panic 后不再遗留 `~/.uml/<umid>` 运行时目录：supervisor
会在它记录的内核进程消失后清理。

### 当前边界

- hostfs 直接暴露宿主路径，不是安全隔离边界。
- UML 模式必须从未被跟踪的宿主进程启动，不能嵌套在 PRoot 或其他 sandbox 中。
- guest 内核是单核（uniprocessor），没有 SMP。
- guest 只运行 aarch64 用户态：内核构建时关闭 `CONFIG_COMPAT`，32 位 ARM
  程序不能运行。
- 内核、stub、`um-init`、`umnet`、`passt` 必须来自配套的 linux-um-arm64
  构建。
- ext4 根目前只在 64 MB 和 256 MB 镜像上验证过，其他容量未测试。

真机稳定性矩阵 18/18 PASS，覆盖 hostfs 带/不带 `--net`、guest 退出码 7 和 125、
ext4 带/不带 `--net`、ext4 `--readonly`、持久与临时 COW、读写/只读绑定、
旧 init 被拒绝、绑定目标缺失、`--timeout`、SIGTERM。详见
[tests/stability-um-backend.sh](tests/stability-um-backend.sh)。

## 后端选择与 `--` 分隔符

不写 `--backend` 时使用默认 PRoot 后端；`--backend=fast` 显式选择同一路径。
`--backend=auto` 把选择写到 stderr，并分两步决定。

第一步看前提：只有 kernel 与 stub 都已配置（`--kernel`/`--stub`，或非空的
`NEOPROOT_UM_KERNEL`/`NEOPROOT_UM_STUB`）**且** 用 `-r`/`--rootfs`
给了 rootfs 时才可能选 UML 后端，否则走默认 PRoot 路径。它不会去 `PATH` 或
文件系统里探测内核——可选后端只应在调用者明确配置后启用。这是不变量而不是
启发式：需要真内核的命令也不能让 `auto` 启动一个没配置的内核。

rootfs 本身也会参与决定，而且这一条不是性能偏好：PRoot 把 guest 路径翻译成
宿主路径，所以它需要目录；ext4 镜像是块设备、没有宿主路径，只有 UML 后端能
启动它。当 `-r` 指向镜像（或给了 `--cow-file`）时，`auto` 无论什么命令都选
UML，`--auto-um-commands` 也不能覆盖：

```
neoproot: --backend=auto selected the um backend (the rootfs is a filesystem image, which only the um backend can use)
```

其余后端会给出同样的解释，而不是把镜像当目录去绑定、或在路径翻译时失败（也
不会把 `--cow-file` 报成未知选项）：

```
neoproot: the rootfs is a filesystem image; only the um backend can use it.
neoproot: use --backend=um (or --backend=auto to select it), or pass a directory rootfs.
```

第二步在这个前提内看命令。默认仍是 PRoot——它是快路径，而大部分工作就是路径
翻译；只有需要真内核的命令才选 UML，例如容器运行时控制面、挂载、命名空间、
块设备、防火墙、包过滤：

```
docker dockerd podman podman-remote nerdctl containerd ctr runc crun
systemd-nspawn machinectl mount umount losetup swapon swapoff
unshare nsenter ip iptables nft bpftool
```

默认集合是一张名字表，不是对命令行的猜测。要替换它，用
`--auto-um-commands=LIST`（逗号分隔的 basename）或等价的
`NEOPROOT_UM_AUTO_COMMANDS` 环境变量；两者同时给出时选项优先。空值表示
默认集合，`none` 表示"从不因命令选择后端"：

```sh
neoproot --backend=auto --auto-um-commands=none -r /rootfs -- docker
NEOPROOT_UM_AUTO_COMMANDS=mycmd,other neoproot --backend=auto -r /rootfs -- mycmd
```

命令取 guest 命令起点的 basename，所以 `/usr/bin/docker` 与 `docker` 是同一个
名字。简单包装器会被跳过——`env`、`sudo`、`command`、`exec`、`nohup`、
`time`、`stdbuf`——包括它们的 `VAR=value` 参数和带独立取值的选项，因此
`env FOO=1 docker` 按 `docker` 判断。

边界是刻意划定的，也值得记住：`sh -c 'docker run'` 的命令是 `sh`，仍走默认
后端，因为 auto 只看参数向量，不解析 guest 的 shell 代码。包装器把取值塞进
合写的短选项（`sudo -Eu root docker`）时，该参数整体被跳过，因此这个包装器
不会被看穿。其余行为不变：`--backend=fast`、`--backend=um` 和默认路径都
既不看列表也不看命令。

三种结果都会报告，`auto` 不会悄悄降级：

```
neoproot: --backend=auto selected the um backend (command 'docker' needs a real kernel)
neoproot: --backend=auto selected the um backend (the rootfs is a filesystem image, which only the um backend can use)
neoproot: --backend=auto selected the default backend
neoproot: --backend=auto would use the um backend for 'docker', but no kernel/stub/rootfs is configured; using the default backend
neoproot: --backend=auto would use the um backend because the rootfs is a filesystem image, but no kernel/stub is configured; using the default backend
```

`--` 分隔符在所有后端含义一致：

```sh
neoproot -r /path/to/rootfs -- /bin/sh
```

CLI 自己消费该分隔符、不再向下转发，因此不认识它的后端不会看到它，同一条命令行
可以换 `--backend` 复用——这正是 `auto` 需要的行为。UML 分发器只对 UML
supervisor 把分隔符补回（其语法需要）。不写 `--` 也可以，CLI 已经知道 guest
命令从哪里开始。

## 为什么不做 per-syscall 混合

很容易想到一种“正常系统调用走 neoproot、其余交给 UML”的模式。它在架构上
不成立，因为两个后端处在不同层次：

- PRoot 是 tracer。guest 进程本身就是宿主进程；`ptrace`（以及部分调用上的
  seccomp USER_NOTIF）在系统调用边界拦住它，neoproot 改写路径、ID 和返回值，
  然后才由宿主内核执行。
- UML 模式里 guest 是真实内核。guest 的系统调用由 UML 内核处理，根本不会以
  同一条 syscall 出现在宿主上，因此没有可被 neoproot 拦截、也没有可被按调用
  分流的宿主系统调用。

所以 per-syscall 拆分要么要求一侧看见它本来看不见的调用，要么要求一个今天
不存在的内核接口。受支持的粒度是**调用/进程树粒度**：在命令启动时选定一个
后端，这正是 `--backend=auto` 做的事。要做到更细，必须改动内核层，不属于
neoproot 的范围。

这不是“暂未实现”：该架构不允许这种拆分，不应把它当作待办功能再次提出。

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
