#include "extension/extension.h"
#include "syscall/sysnum.h"  /* PR_* syscall numbers */
#include <unistd.h>

/**
 * 核心回调：直接透传所有 SysV IPC 系统调用，无任何额外处理
 * @param extension 扩展句柄
 * @param event 触发事件
 * @param data1 事件数据1
 * @param data2 事件数据2
 * @return 0-成功，1-允许继承，<0-错误码
 */
int sysvipc_callback(Extension *extension, ExtensionEvent event,
                     intptr_t data1 UNUSED, intptr_t data2 UNUSED)
{
    if (extension == NULL)
        return -EINVAL;

    switch (event) {
    case INITIALIZATION: {
        // 注册所有 SysV IPC 系统调用，无过滤标志（纯透传）
        static const FilteredSysnum filtered_sysnums[] = {
            { PR_msgget,     0 },    // 消息队列创建/获取
            { PR_msgsnd,     0 },    // 消息发送
            { PR_msgrcv,     0 },    // 消息接收
            { PR_msgctl,     0 },    // 消息队列控制
            { PR_semget,     0 },    // 信号量集创建/获取
            { PR_semop,      0 },    // 信号量操作
            { PR_semtimedop, 0 },    // 带超时的信号量操作
            { PR_semctl,     0 },    // 信号量集控制
            { PR_shmget,     0 },    // 共享内存创建/获取
            { PR_shmat,      0 },    // 共享内存附加
            { PR_shmdt,      0 },    // 共享内存脱离
            { PR_shmctl,     0 },    // 共享内存控制
            FILTERED_SYSNUM_END,
        };
        extension->filtered_sysnums = (FilteredSysnum *)filtered_sysnums;
        return 0;
    }

    case SYSCALL_ENTER_START:
        // 系统调用进入时直接返回0，允许内核执行原调用
        return 0;

    case SYSCALL_EXIT_END:
        // 系统调用退出时直接返回0，无任何后处理
        return 0;

    case INHERIT_PARENT:
        // 允许子进程继承该扩展配置
        return 1;

    default:
        // 忽略其他事件，返回0不影响系统调用流程
        return 0;
    }
}
