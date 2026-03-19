#ifndef SYSVIPC_INTERNAL_H
#define SYSVIPC_INTERNAL_H

#include "tracee/tracee.h"
#include "sysvipc_sys.h"

#include <sys/queue.h>
#include <sys/msg.h>
#include <stdint.h>
#include <stdbool.h>

/* 移除无用头文件引用（uchar.h 未被使用） */

/******************
 * Message queues *
 *****************/

/** 消息队列单个消息节点 */
struct SysVIpcMsgQueueItem {
    long mtype;                     /* 消息类型（必须为正整数） */
    char *mtext;                    /* 消息数据缓冲区 */
    size_t mtext_length;            /* 消息数据长度（字节） */
    STAILQ_ENTRY(SysVIpcMsgQueueItem) link; /* 队列链表节点 */
};
STAILQ_HEAD(SysVIpcMsgQueueItems, SysVIpcMsgQueueItem); /* 消息队列头结构 */

/** 消息队列整体结构 */
struct SysVIpcMsgQueue {
    int32_t key;                    /* 队列键值（IPC_PRIVATE 或用户指定） */
    int16_t generation;             /* 世代号（用于区分删除后重建的队列） */
    bool valid;                     /* 队列是否有效（未被删除） */
    struct SysVIpcMsgQueueItems *items; /* 消息链表 */
    struct msqid_ds stats;          /* 队列状态信息（兼容标准 msqid_ds） */
};

/**************
 * Semaphores *
 *************/

/** 信号量集结构 */
struct SysVIpcSemaphore {
    int32_t key;                    /* 信号量集键值 */
    int16_t generation;             /* 世代号 */
    bool valid;                     /* 信号量集是否有效 */
    uint16_t *sems;                 /* 信号量值数组 */
    int nsems;                      /* 信号量集中的信号量数量 */
};

/*****************
 * Shared Memory *
 ****************/

/** 共享内存映射结构（跟踪进程附加的共享内存区域） */
struct SysVIpcSharedMemMap {
    word_t addr;                    /* 进程地址空间中的映射起始地址 */
    size_t size;                    /* 映射区域大小（0 表示映射未完成） */
    
    /** 所属的 IPC 命名空间
     * 注：不通过 talloc 跟踪引用，因当前未实现 CLONE_NEWIPC，
     * 持有映射的进程与共享内存必然在同一命名空间 */
    struct SysVIpcNamespace *ipc_namespace;
    size_t shm_index;               /* 在命名空间共享内存数组中的索引 */
    
    LIST_ENTRY(SysVIpcSharedMemMap) link_shmid;  /* 共享内存映射链表节点 */
    LIST_ENTRY(SysVIpcSharedMemMap) link_process;/* 进程映射链表节点 */
};
LIST_HEAD(SysVIpcSharedMemMaps, SysVIpcSharedMemMap); /* 共享内存映射链表头 */

/** 共享内存段结构 */
struct SysVIpcSharedMem {
    int32_t key;                    /* 共享内存键值 */
    int16_t generation;             /* 世代号 */
    bool valid;                     /* 共享内存段是否有效 */
    bool rmid_pending;              /* 是否标记为待删除（等待所有映射解除） */
    int fd;                         /* 底层存储文件描述符（ashmem/tmpfile） */
    struct SysVIpcShmidDs stats;    /* 共享内存状态信息（兼容标准 shmid_ds） */
    
    /** 当前附加的映射列表
     * 存在映射时，IPC_RMID 仅标记 rmid_pending，不立即删除 */
    struct SysVIpcSharedMemMaps *mappings;
};

/*****************
 * Namespace     *
 ****************/

/** SysV IPC 命名空间（隔离消息队列/信号量/共享内存） */
struct SysVIpcNamespace {
    struct SysVIpcMsgQueue *queues;     /* 消息队列数组（1-indexed 映射到 id） */
    struct SysVIpcSemaphore *semaphores;/* 信号量集数组 */
    struct SysVIpcSharedMem *shms;     /* 共享内存段数组 */
};

/*****************
 * State Enums   *
 ****************/

/** 进程等待原因 */
enum SysVIpcWaitReason {
    WR_NOT_WAITING,                  /* 不等待 */
    WR_WAIT_QUEUE_RECV,              /* 等待消息队列接收消息 */
    WR_WAIT_SEMOP,                   /* 等待信号量操作完成 */
    WR_WAIT_SHMAT_HELPER_BUSY        /* 等待 shmat 辅助进程空闲 */
};

/** 进程等待内部状态（仅由等待机制实现使用） */
enum SysVIpcWaitState {
    WSTATE_NOT_WAITING,              /* 不等待 */
    WSTATE_RESTARTED_INTO_PPOLL_CANCELED, /* 重启后进入 ppoll 已取消 */
    WSTATE_RESTARTED_INTO_PPOLL,      /* 重启后进入 ppoll */
    WSTATE_ENTERED_PPOLL,            /* 已进入 ppoll */
    WSTATE_SIGNALED_PPOLL,           /* ppoll 被信号唤醒 */
    WSTATE_ENTERED_GETPID            /* 已进入 getpid */
};

/** 系统调用链式调用状态（用于多步骤操作如 shmat） */
enum SysVIpcChainState {
    CSTATE_NOT_CHAINED,              /* 无链式调用 */
    CSTATE_SINGLE,                   /* 单个链式调用 */
    CSTATE_SHMAT_SOCKET,             /* shmat：创建 UNIX socket */
    CSTATE_SHMAT_CONNECT,            /* shmat：连接辅助进程 socket */
    CSTATE_SHMAT_RECVMSG,            /* shmat：接收辅助进程消息（含 FD） */
    CSTATE_SHMAT_MMAP,               /* shmat：内存映射 */
    CSTATE_MSGRCV_RETRY             /* msgrcv：重试接收消息 */
};

/*****************
 * Process/Config *
 ****************/

/** 进程级 SysV IPC 状态（线程组共享） */
struct SysVIpcProcess {
    int pgid;                        /* 进程组 ID */
    struct SysVIpcSharedMemMaps mapped_shms; /* 进程附加的共享内存映射链表 */
};

/** 线程级 SysV IPC 配置（每个 tracee 独立） */
struct SysVIpcConfig {
    struct SysVIpcNamespace *ipc_namespace; /* 所属 IPC 命名空间 */
    struct SysVIpcProcess *process;         /* 所属进程状态 */
    
    enum SysVIpcWaitReason wait_reason;     /* 等待原因（WR_NOT_WAITING 表示无等待） */
    enum SysVIpcWaitState wait_state;       /* 等待内部状态（仅等待机制访问） */
    enum SysVIpcChainState chain_state;     /* 链式调用状态 */
    word_t status_after_wait;              /* 等待后的返回状态 */
    
    size_t waiting_object_index;           /* 等待的 IPC 对象索引 */
    
    /* msgrcv 相关参数缓存 */
    word_t msgrcv_msgp;    /* 消息接收缓冲区指针 */
    size_t msgrcv_msgsz;   /* 接收缓冲区大小 */
    int msgrcv_msgtyp;     /* 消息类型过滤条件 */
    int msgrcv_msgflg;     /* 接收标志（MSG_NOERROR/MSG_EXCEPT 等） */
    
    struct SysVIpcSembuf *semop_sops;      /* semop 操作数组缓存 */
    
    /* shmat 链式调用参数缓存 */
    word_t shmat_guest_buf;  /* 进程内存中的 socket 地址缓冲区 */
    int shmat_socket_fd;     /* 创建的 UNIX socket FD */
    int shmat_mem_fd;        /* 接收的共享内存 FD */
};

/*****************
 * Macros        *
 ****************/

/**
 * 查找 tracee 请求的 IPC 对象
 * @param out_index 输出对象在数组中的索引（size_t）
 * @param out_object 输出对象指针（struct SysVIpc[MsgQueue/Semaphore/SharedMem]）
 * @param objects_array IPC 对象数组（queues/semaphores/shms）
 * @return 失败返回 -EINVAL，成功则填充 out_index 和 out_object
 */
#define LOOKUP_IPC_OBJECT(out_index, out_object, objects_array) \
{ \
    int object_id = peek_reg(tracee, CURRENT, SYSARG_1); \
    int object_index = object_id & 0xFFF; \
    if (object_index <= 0 || object_index > (int)talloc_array_length(objects_array)) { \
        return -EINVAL; \
    } \
    out_index = object_index - 1; \
    out_object = &(objects_array)[object_index - 1]; \
    if (!out_object->valid || out_object->generation != ((object_id >> 12) & 0xFFFF)) { \
        return -EINVAL; \
    } \
}

/**
 * 生成 IPC 对象 ID（索引+1 + 世代号左移12位）
 * @param index 对象在数组中的索引（0-based）
 * @param object IPC 对象指针
 * @return IPC 对象 ID
 */
#define IPC_OBJECT_ID(index, object) \
    ((index + 1) | (object->generation << 12))

/**
 * 遍历指定 IPC 命名空间中的所有 tracee
 * @param out_tracee 输出 tracee 指针（Tracee *）
 * @param out_config 输出 tracee 的 IPC 配置（struct SysVIpcConfig *）
 * @param checked_namespace 目标 IPC 命名空间
 */
#define SYSVIPC_FOREACH_TRACEE(out_tracee, out_config, checked_namespace) \
    LIST_FOREACH((out_tracee), get_tracees_list_head(), link) \
    if ( \
        ((out_config) = sysvipc_get_config(out_tracee)) != NULL && \
        (out_config)->ipc_namespace == (checked_namespace) \
    )

/**
 * 遍历所有存在 IPC 配置的 tracee（不限制命名空间）
 * @param out_tracee 输出 tracee 指针（Tracee *）
 * @param out_config 输出 tracee 的 IPC 配置（struct SysVIpcConfig *）
 */
#define SYSVIPC_FOREACH_TRACEE_ANY_NAMESPACE(out_tracee, out_config) \
    LIST_FOREACH((out_tracee), get_tracees_list_head(), link) \
    if ( \
        ((out_config) = sysvipc_get_config(out_tracee)) != NULL \
    )

/*****************
 * API Prototypes *
 ****************/

/**
 * 唤醒等待中的 tracee
 * @param tracee 目标 tracee
 * @param config tracee 的 IPC 配置
 * @param status 唤醒后的返回状态
 */
void sysvipc_wake_tracee(Tracee *tracee, struct SysVIpcConfig *config, int status);

/**
 * 获取 tracee 的 SysV IPC 配置
 * @param tracee 目标 tracee
 * @return 成功返回配置指针，失败返回 NULL
 */
struct SysVIpcConfig *sysvipc_get_config(Tracee *tracee);

/* 消息队列模块接口 */
int sysvipc_msgget(Tracee *tracee, struct SysVIpcConfig *config);
int sysvipc_msgsnd(Tracee *tracee, struct SysVIpcConfig *config);
int sysvipc_msgrcv(Tracee *tracee, struct SysVIpcConfig *config);
int sysvipc_msgrcv_retry(Tracee *tracee, struct SysVIpcConfig *config);
int sysvipc_msgctl(Tracee *tracee, struct SysVIpcConfig *config);

/* 信号量模块接口 */
int sysvipc_semget(Tracee *tracee, struct SysVIpcConfig *config);
int sysvipc_semop(Tracee *tracee, struct SysVIpcConfig *config);
void sysvipc_semop_timedout(Tracee *tracee, struct SysVIpcConfig *config);
int sysvipc_semctl(Tracee *tracee, struct SysVIpcConfig *config);

/* 共享内存模块接口 */
int sysvipc_shmget(Tracee *tracee, struct SysVIpcConfig *config);
int sysvipc_shmat(Tracee *tracee, struct SysVIpcConfig *config);
int sysvipc_shmat_chain(Tracee *tracee, struct SysVIpcConfig *config);
int sysvipc_shmdt(Tracee *tracee, struct SysVIpcConfig *config);
int sysvipc_shmctl(Tracee *tracee, struct SysVIpcConfig *config);
void sysvipc_shm_inherit_process(struct SysVIpcProcess *parent, struct SysVIpcProcess *child);
void sysvipc_shm_remove_mappings_from_process(struct SysVIpcProcess *process);
void sysvipc_shm_fill_proc(FILE *proc_file, struct SysVIpcNamespace *ipc_namespace);
int sysvipc_shm_namespace_destructor(struct SysVIpcNamespace *ipc_namespace);

#endif // SYSVIPC_INTERNAL_H
