# proot-scicat netlink_route 实现图与整体执行结构

## 1. netlink_route 执行流程图

```mermaid
graph TD
    A[用户程序调用网络相关系统调用] --> B{系统调用拦截}
    B -->|socket| C[netlink_route_callback<br/>SYSCALL_EXIT_END]
    B -->|socketcall| D[netlink_route_callback<br/>SYSCALL_EXIT_END]
    B -->|bind| E[netlink_route_callback<br/>SYSCALL_EXIT_END]
    B -->|sendto| F[netlink_route_callback<br/>SYSCALL_EXIT_END]
    B -->|recvfrom| G[netlink_route_callback<br/>SYSCALL_ENTER_END]
    B -->|recvmsg| H[netlink_route_callback<br/>SYSCALL_ENTER_END]
    B -->|close| I[netlink_route_callback<br/>SYSCALL_EXIT_END]
    
    C --> J[检查是否为 NETLINK_ROUTE 协议]
    D --> J
    J -->|是| K[记住文件描述符]
    J -->|否| L[正常处理]
    
    E --> M[检查是否为 EACCES/EPERM 错误]
    M -->|是| N[模拟 bind 成功]
    M -->|否| L
    
    F --> O[检查是否强制模拟]
    O -->|是| P[构建响应数据]
    P --> Q[存储待处理响应]
    O -->|否| L
    
    G --> R[检查是否有待处理响应]
    R -->|是| S[serve_pending_recvfrom]
    R -->|否| T[检查是否强制模拟]
    T -->|是| U[返回 EAGAIN]
    T -->|否| L
    
    H --> V[检查是否有待处理响应]
    V -->|是| W[serve_pending_recvmsg]
    V -->|否| X[检查是否强制模拟]
    X -->|是| Y[返回 EAGAIN]
    X -->|否| L
    
    S --> Z[将数据写入用户缓冲区]
    W --> Z
    Z --> L
    
    K --> L
    N --> L
    Q --> L
    U --> L
    Y --> L
```

## 2. netlink_route 数据结构图

```mermaid
classDiagram
    class Config {
        +NetlinkRouteFd* fds
        +size_t len
        +PendingReply* pending
        +size_t pending_len
        +bool force_emulation
    }
    
    class NetlinkRouteFd {
        +int fd
        +int protocol
    }
    
    class PendingReply {
        +int fd
        +uint8_t* buf
        +size_t len
        +size_t off
        +uint32_t seq
        +uint32_t pid
    }
    
    Config --> NetlinkRouteFd : 包含
    Config --> PendingReply : 包含
```

## 3. 整体 proot 执行结构图

```mermaid
graph TB
    subgraph "用户程序"
        A[应用程序]
    end
    
    subgraph "proot 主进程"
        B[main.c]
        C[cli.c]
        D[extension_manager]
    end
    
    subgraph "Tracee 管理"
        E[tracee.c]
        F[tracee.h]
        G[ptrace.c]
    end
    
    subgraph "系统调用拦截层"
        H[syscall/syscall.cpp]
        I[syscall/enter.cpp]
        J[syscall/exit.c]
    end
    
    subgraph "扩展模块"
        K[extension/extension.c]
        L[netlink_route]
        M[fake_id0]
        N[kompat]
    end
    
    subgraph "路径处理"
        O[path/path.c]
        P[path/canon.c]
        Q[path/glue.c]
    end
    
    subgraph "内存管理"
        R[tracee/mem.cpp]
        S[tracee/reg.cpp]
    end
    
    A --> B
    B --> C
    B --> D
    D --> E
    E --> F
    E --> G
    G --> H
    H --> I
    H --> J
    I --> K
    J --> K
    K --> L
    K --> M
    K --> N
    L --> O
    M --> O
    N --> O
    O --> P
    P --> Q
    Q --> R
    R --> S
    S --> H
    
    style B fill:#e1f5ff
    style D fill:#fff3e1
    style K fill:#ffe1f5
```

## 4. netlink_route 关键函数调用序列图

```mermaid
sequenceDiagram
    participant User as 用户程序
    participant Proot as proot
    participant NetlinkRoute as netlink_route
    participant Kernel as 内核
    
    User->>Proot: socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)
    Proot->>NetlinkRoute: netlink_route_callback(INITIALIZATION)
    NetlinkRoute->>NetlinkRoute: 记录文件描述符
    
    User->>Proot: bind(fd, sockaddr_nl)
    Proot->>NetlinkRoute: netlink_route_callback(SYSCALL_EXIT_END)
    NetlinkRoute->>NetlinkRoute: 检查 bind 结果
    
    User->>Proot: sendto(fd, request)
    Proot->>NetlinkRoute: netlink_route_callback(SYSCALL_EXIT_END)
    NetlinkRoute->>NetlinkRoute: 构建响应数据
    
    User->>Proot: recvfrom(fd, buffer)
    Proot->>NetlinkRoute: netlink_route_callback(SYSCALL_ENTER_END)
    NetlinkRoute->>NetlinkRoute: serve_pending_recvfrom()
    NetlinkRoute->>User: 返回模拟的网络响应
```

## 5. netlink_route 配置初始化流程

```mermaid
flowchart TD
    A[初始化扩展] --> B[netlink_route_callback<br/>INITIALIZATION]
    B --> C[创建 Config 结构]
    C --> D[设置 force_emulation = true]
    D --> E[配置过滤的系统调用]
    E --> F[PR_socket]
    E --> G[PR_socketcall]
    E --> H[PR_bind]
    E --> I[PR_sendto]
    E --> J[PR_recvfrom]
    E --> K[PR_recvmsg]
    E --> L[PR_close]
    F --> M[扩展初始化完成]
    G --> M
    H --> M
    I --> M
    J --> M
    K --> M
    L --> M
```

## 8. syscall 阻拦执行流程图

```mermaid
graph TD
    A[用户程序调用系统调用] --> B{proot 拦截}
    B --> C[ptrace 事件触发]
    C --> D[translate_syscall]
    D --> E{是否进入阶段}
    
    E -->|是| F[translate_syscall_enter]
    E -->|否| G[translate_syscall_exit]
    
    F --> H[fetch_regs: 获取寄存器]
    H --> I{是否为强制拦截}
    I -->|是| J[save_current_regs: 保存原始寄存器]
    I -->|否| K[检查是否为 bionic 拦截]
    
    J --> L[translate_syscall_enter]
    K --> M[检查是否安全透传]
    M -->|是| N[直接执行系统调用]
    M -->|否| O[检查是否为 GPU 透传]
    O -->|是| N
    O -->|否| L
    
    L --> P[notify_extensions(SYSCALL_ENTER_START)]
    P --> Q{扩展回调返回值}
    Q -->|非0| R[返回错误]
    Q -->|0| S[获取系统调用号]
    S --> T[find_syscall_handler: 查找处理器]
    T --> U{是否有处理器}
    U -->|是| V[调用处理器]
    U -->|否| W[继续执行]
    
    V --> X[处理器处理]
    X --> Y[notify_extensions(SYSCALL_ENTER_END)]
    Y --> Z{扩展回调返回值}
    Z -->|<0| AA[返回错误]
    Z -->|>=0| BB[返回状态]
    
    W --> CC[继续执行]
    CC --> BB
    
    G --> DD[translate_syscall_exit]
    DD --> EE[restore_original_regs: 恢复原始寄存器]
    EE --> FF{是否有链式系统调用}
    FF -->|是| GG[chain_next_syscall]
    FF -->|否| HH[设置状态为 0]
    
    GG --> II[继续执行链式调用]
    HH --> JJ[push_specific_regs]
    JJ --> KK{是否需要重启}
    KK -->|是| LL[重启系统调用]
    KK -->|否| MM[正常返回]
    
    R --> NN[返回错误状态]
    AA --> NN
    BB --> NN
    NN --> OO[proot 返回用户程序]
    MM --> OO
    II --> OO
    LL --> OO
    N --> OO
    
    style D fill:#e1f5ff
    style F fill:#fff3e1
    style G fill:#ffe1f5
    style L fill:#f0f8ff
    style V fill:#f0fff0
    style NN fill:#ffe4c4
```

## 9. syscall 处理器注册与查找流程

```mermaid
flowchart TD
    A[系统启动] --> B[syscall_handlers 数组初始化]
    B --> C[包含所有系统调用处理器]
    C --> D[handler_count = 数组长度]
    D --> E[注册到 syscall 框架]
    
    E --> F[用户程序调用系统调用]
    F --> G[proot 拦截]
    G --> H[translate_syscall_enter]
    H --> I[获取系统调用号]
    I --> J[find_syscall_handler]
    J --> K[bsearch 算法查找]
    K --> L{找到处理器}
    L -->|是| M[调用处理器]
    L -->|否| N[使用默认处理]
    
    M --> O[处理器执行特定逻辑]
    N --> P[继续执行系统调用]
    
    O --> Q[返回处理结果]
    P --> Q
    Q --> R[proot 返回用户程序]
    
    style B fill:#e1f5ff
    style J fill:#fff3e1
    style M fill:#f0fff0
    style Q fill:#ffe4c4
```

## 10. 扩展回调机制流程

```mermaid
sequenceDiagram
    participant User as 用户程序
    participant Proot as proot
    participant Syscall as syscall 框架
    participant Ext as 扩展模块
    participant Kernel as 内核
    
    User->>Proot: 系统调用
    Proot->>Syscall: translate_syscall
    Syscall->>Syscall: translate_syscall_enter
    Syscall->>Ext: notify_extensions(SYSCALL_ENTER_START)
    
    loop 遍历所有扩展
        Ext->>Ext: 执行扩展回调
        Ext->>Ext: 检查返回值
    end
    
    Syscall->>Ext: 获取系统调用号
    Syscall->>Ext: find_syscall_handler
    Ext->>Ext: 调用对应处理器
    
    Ext->>Ext: 处理器执行特定逻辑
    Ext->>Syscall: 返回处理结果
    
    Syscall->>Ext: notify_extensions(SYSCALL_ENTER_END)
    
    loop 遍历所有扩展
        Ext->>Ext: 执行扩展回调
        Ext->>Ext: 检查返回值
    end
    
    Syscall->>Kernel: 执行系统调用
    Kernel->>Proot: 返回结果
    Proot->>User: 返回结果
```

## 11. syscall 处理器示例

```mermaid
classDiagram
    class SyscallHandlerEntry {
        +sysnum_t num
        +syscall_handler_t handler
    }
    
    class syscall_handlers {
        +SyscallHandlerEntry[] entries
        +size_t count
    }
    
    class PathTranslator {
        +translate_sysarg: 路径转换
    }
    
    class SocketHandler {
        +translate_socketcall_enter: socketcall 处理
    }
    
    class PathTranslator <|-- AccessHandler
    class PathTranslator <|-- ChmodHandler
    class PathTranslator <|-- OpenHandler
    class SocketHandler <|-- BindHandler
    
    SyscallHandlerEntry --> PathTranslator : handler
    SyscallHandlerEntry --> SocketHandler : handler
    syscall_handlers --> SyscallHandlerEntry : entries
```

## 12. 完整的 syscall 阻拦架构图

```mermaid
graph TB
    subgraph "用户空间"
        A[应用程序]
    end
    
    subgraph "proot 核心"
        B[main]
        C[ptrace 事件处理]
        D[syscall 框架]
        E[extension 系统]
    end
    
    subgraph "syscall 拦截层"
        F[translate_syscall]
        G[translate_syscall_enter]
        H[translate_syscall_exit]
        I[notify_extensions]
    end
    
    subgraph "扩展模块"
        J[netlink_route]
        K[fake_id0]
        L[kompat]
        M[path]
    end
    
    subgraph "系统调用处理器"
        N[access]
        O[open]
        P[bind]
        Q[socket]
    end
    
    subgraph "内核"
        R[Linux 内核]
    end
    
    A --> B
    B --> C
    C --> D
    D --> E
    D --> F
    F --> G
    F --> H
    G --> I
    H --> I
    I --> J
    I --> K
    I --> L
    I --> M
    I --> N
    I --> O
    I --> P
    I --> Q
    J --> R
    K --> R
    L --> R
    M --> R
    N --> R
    O --> R
    P --> R
    Q --> R
    
    style B fill:#e1f5ff
    style D fill:#fff3e1
    style E fill:#ffe1f5
    style F fill:#f0f8ff
    style J fill:#f0fff0
    style M fill:#f5f0ff
```

## 6. 数据构建函数流程

```mermaid
flowchart TD
    A[请求类型] -->|RTM_GETLINK| B[build_link_reply]
    A -->|RTM_GETADDR| C[build_addr_reply]
    A -->|其他| D[返回错误]
    
    B --> E[socket(SOCK_DGRAM)]
    B --> F[ioctl(SIOCGIFCONF)]
    B --> G[遍历网络接口]
    G --> H[ioctl(SIOCGIFFLAGS)]
    G --> I[构建 RTM_NEWLINK 消息]
    I --> J[添加 IFLA_IFNAME 属性]
    J --> K[添加更多属性]
    K --> L[添加 NLMSG_DONE]
    L --> M[返回完整数据]
    
    C --> N[socket(SOCK_DGRAM)]
    C --> O[ioctl(SIOCGIFCONF)]
    C --> P[遍历网络接口]
    P --> Q[检查 AF_INET]
    Q --> R[ioctl(SIOCGIFNETMASK)]
    R --> S[构建 RTM_NEWADDR 消息]
    S --> T[添加 IFA_ADDRESS 属性]
    T --> U[添加 IFA_LOCAL 属性]
    U --> V[添加 IFA_LABEL 属性]
    V --> W[添加 NLMSG_DONE]
    W --> X[返回完整数据]
```

## 7. 响应处理流程

```mermaid
flowchart TD
    A[接收到数据] --> B[检查是否为 NETLINK_ROUTE FD]
    B -->|是| C[获取 PendingReply 结构]
    B -->|否| D[正常处理]
    
    C --> E[检查是否有待处理数据]
    E -->|有| F[serve_pending_recvfrom/recvmsg]
    E -->|无| G[检查是否强制模拟]
    G -->|是| H[返回 EAGAIN]
    G -->|否| D
    
    F --> I[将数据写入用户缓冲区]
    I --> J[更新偏移量]
    J --> K[检查是否完成]
    K -->|是| L[清空待处理数据]
    K -->|否| D
    L --> D
```