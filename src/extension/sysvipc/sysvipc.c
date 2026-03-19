/*
 * This file is part of proot-scicat.
 *
 * Copyright (C) 2026 Scicat
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 *
 * Description: Core SysV IPC extension handler - dispatch syscalls, manage state, handle waiting
 * Support: Syscall chaining, process inheritance, /proc/sysvipc/shm emulation
 */

#include "extension/sysvipc/sysvipc.h"
#include "tracee/seccomp.h"
#include "syscall/chain.h"
#include "path/path.h"
#include "path/temp.h"

#include <assert.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <sched.h>
#include <string.h>
#include <signal.h>

#include "sysvipc_internal.h"

/* 注册需要处理的 SysV IPC 系统调用 */
static FilteredSysnum filtered_sysnums[] = {
    { PR_msgget,     0 },
    { PR_msgsnd,     0 },
    { PR_msgrcv,     0 },
    { PR_msgctl,     0 },
    { PR_semget,     0 },
    { PR_semop,      0 },
    { PR_semtimedop, 0 },
    { PR_semctl,     0 },
    { PR_shmget,     0 },
    { PR_shmat,      0 },
    { PR_shmdt,      0 },
    { PR_shmctl,     0 },
    FILTERED_SYSNUM_END,
};

/**
 * SysV IPC 系统调用通用处理逻辑
 * @param tracee 进程追踪句柄
 * @param config IPC 配置
 * @param from_sigsys 是否来自 SIGSYS 信号（seccomp 触发）
 * @return 0-继续默认处理，1-重启系统调用，2-处理完成
 */
static int sysvipc_syscall_common(Tracee *tracee, struct SysVIpcConfig *config, bool from_sigsys)
{
    if (tracee == NULL || config == NULL)
        return 0;

    assert(config->wait_state == WSTATE_NOT_WAITING);

    int status = 0;
    word_t timeout = 0;
    word_t sysnum = get_sysnum(tracee, CURRENT);

    // 分发到对应 IPC 子模块处理
    switch (sysnum) {
    case PR_msgget:    status = sysvipc_msgget(tracee, config);    break;
    case PR_msgsnd:    status = sysvipc_msgsnd(tracee, config);    break;
    case PR_msgrcv:    status = sysvipc_msgrcv(tracee, config);    break;
    case PR_msgctl:    status = sysvipc_msgctl(tracee, config);    break;
    case PR_semget:    status = sysvipc_semget(tracee, config);    break;
    case PR_semtimedop:
        timeout = peek_reg(tracee, CURRENT, SYSARG_4); // 读取超时参数
        // fallthrough 到 semop 处理
    case PR_semop:     status = sysvipc_semop(tracee, config);     break;
    case PR_semctl:    status = sysvipc_semctl(tracee, config);    break;
    case PR_shmget:    status = sysvipc_shmget(tracee, config);    break;
    case PR_shmat:     status = sysvipc_shmat(tracee, config);     break;
    case PR_shmdt:     status = sysvipc_shmdt(tracee, config);     break;
    case PR_shmctl:    status = sysvipc_shmctl(tracee, config);    break;
    default:
        return 0; // 不处理的系统调用，返回默认流程
    }

    // 处理链式调用状态
    if (config->chain_state != CSTATE_NOT_CHAINED) {
        assert(config->chain_state == CSTATE_SINGLE || config->chain_state == CSTATE_SHMAT_SOCKET);
        if (config->chain_state == CSTATE_SINGLE) {
            config->chain_state = CSTATE_NOT_CHAINED;
        }
        tracee->restart_how = PTRACE_SYSCALL;
        if (from_sigsys) {
            restart_syscall_after_seccomp(tracee);
            return 2;
        }
        return 1;
    }
    // 处理等待状态（需要阻塞等待 IPC 事件）
    else if (config->wait_reason != WR_NOT_WAITING) {
        // 替换为 ppoll 系统调用实现等待
        poke_reg(tracee, SYSARG_1, 0);
        poke_reg(tracee, SYSARG_2, 0);
        poke_reg(tracee, SYSARG_3, timeout);
        poke_reg(tracee, SYSARG_4, 0);
        set_sysnum(tracee, PR_ppoll);
        tracee->restart_how = PTRACE_SYSCALL;

        if (from_sigsys) {
            config->wait_state = WSTATE_RESTARTED_INTO_PPOLL;
            restart_syscall_after_seccomp(tracee);
            return 2;
        } else {
            config->wait_state = WSTATE_ENTERED_PPOLL;
            return 1;
        }
    }
    // 处理完成，返回结果
    else {
        if (from_sigsys) {
            set_result_after_seccomp(tracee, status);
            return 2;
        } else {
            config->status_after_wait = status;
            config->wait_state = WSTATE_ENTERED_GETPID;
            set_sysnum(tracee, PR_getpid); // 用 getpid 占位，触发后续结果返回
            tracee->restart_how = PTRACE_SYSCALL;
            return 1;
        }
    }
}

/**
 * 生成 /proc/sysvipc/shm 临时文件（模拟系统 proc 文件）
 * @param out_path 输出临时文件路径
 * @param extension 扩展句柄
 * @param handler 数据填充回调函数
 * @return 1-成功，<0-错误码
 */
static int sysvipc_proc_handler(char *out_path, Extension *extension,
                               void (*handler)(FILE *proc_file, struct SysVIpcNamespace *ipc_namespace))
{
    if (out_path == NULL || extension == NULL || handler == NULL)
        return -EINVAL;

    Tracee *tracee = TRACEE(extension);
    struct SysVIpcConfig *config = extension->config;
    if (config == NULL || config->ipc_namespace == NULL)
        return -EINVAL;

    // 创建临时文件
    const char *temp_path = create_temp_file(tracee->ctx, "prootseq");
    if (temp_path == NULL)
        return -ENOMEM;

    // 写入 proc 数据
    FILE *fp = fopen(temp_path, "w");
    if (fp == NULL)
        return -EIO;

    handler(fp, config->ipc_namespace);
    fclose(fp);

    // 复制路径到输出
    strncpy(out_path, temp_path, PATH_MAX - 1);
    out_path[PATH_MAX - 1] = '\0';
    return 1;
}

/**
 * SysV IPC 扩展核心回调函数
 * @param extension 扩展句柄
 * @param event 触发事件
 * @param data1 事件数据1
 * @param data2 事件数据2
 * @return 0-成功，1-允许继承，<0-错误码
 */
int sysvipc_callback(Extension *extension, ExtensionEvent event, intptr_t data1, intptr_t data2)
{
    if (extension == NULL)
        return -EINVAL;

    switch (event) {
    case INITIALIZATION: {
        // 初始化 IPC 配置（命名空间、进程状态）
        Tracee *tracee = TRACEE(extension);
        struct SysVIpcConfig *config = talloc_zero(extension, struct SysVIpcConfig);
        if (config == NULL)
            return -ENOMEM;

        // 初始化 IPC 命名空间
        config->ipc_namespace = talloc_zero(config, struct SysVIpcNamespace);
        if (config->ipc_namespace == NULL) {
            talloc_free(config);
            return -ENOMEM;
        }
        talloc_set_destructor(config->ipc_namespace, sysvipc_shm_namespace_destructor);

        // 初始化进程状态
        config->process = talloc_zero(config, struct SysVIpcProcess);
        if (config->process == NULL) {
            talloc_free(config);
            return -ENOMEM;
        }
        config->process->pgid = tracee->pid;

        extension->config = config;
        extension->filtered_sysnums = filtered_sysnums;
        return 0;
    }

    case INHERIT_PARENT:
        // 允许子进程继承该扩展配置
        return 1;

    case INHERIT_CHILD: {
        // 子进程继承 IPC 配置
        Extension *parent_ext = (Extension *)data1;
        struct SysVIpcConfig *parent_config = parent_ext->config;
        if (parent_config == NULL)
            return -EINVAL;

        struct SysVIpcConfig *child_config = talloc_zero(extension, struct SysVIpcConfig);
        if (child_config == NULL)
            return -ENOMEM;

        // 线程克隆（CLONE_THREAD）：共享进程状态；否则创建新进程状态
        if (data2 & CLONE_THREAD) {
            child_config->process = talloc_reference(child_config, parent_config->process);
        } else {
            Tracee *tracee = TRACEE(extension);
            child_config->process = talloc_zero(child_config, struct SysVIpcProcess);
            if (child_config->process == NULL) {
                talloc_free(child_config);
                return -ENOMEM;
            }
            child_config->process->pgid = tracee->pid;
            // 继承共享内存映射
            sysvipc_shm_inherit_process(parent_config->process, child_config->process);
        }

        // 继承 IPC 命名空间
        child_config->ipc_namespace = talloc_reference(child_config, parent_config->ipc_namespace);
        extension->config = child_config;
        return 0;
    }

    case SYSCALL_ENTER_END: {
        // execve 执行完成后，移除进程的共享内存映射
        if (data1 == 0) {
            Tracee *tracee = TRACEE(extension);
            if (get_sysnum(tracee, CURRENT) == PR_execve) {
                struct SysVIpcConfig *config = extension->config;
                if (config != NULL && config->process != NULL) {
                    sysvipc_shm_remove_mappings_from_process(config->process);
                }
            }
        }
        return 0;
    }

    case SYSCALL_ENTER_START: {
        // 系统调用进入时处理（等待状态恢复、通用调度）
        Tracee *tracee = TRACEE(extension);
        struct SysVIpcConfig *config = extension->config;
        if (config == NULL)
            return 0;

        switch (config->wait_state) {
        case WSTATE_NOT_WAITING:
            // 无等待状态，进入通用处理
            return sysvipc_syscall_common(tracee, config, false);

        case WSTATE_RESTARTED_INTO_PPOLL:
            // 重启后进入 ppoll 等待
            assert(get_sysnum(tracee, CURRENT) == PR_ppoll);
            config->wait_state = WSTATE_ENTERED_PPOLL;
            tracee->restart_how = PTRACE_SYSCALL;
            return 1;

        case WSTATE_RESTARTED_INTO_PPOLL_CANCELED:
            // 等待取消，处理重试逻辑
            {
                int status = config->status_after_wait;
                if (config->chain_state == CSTATE_MSGRCV_RETRY) {
                    status = sysvipc_msgrcv_retry(tracee, config);
                }
                poke_reg(tracee, SYSARG_RESULT, status);
                set_sysnum(tracee, PR_void);
                config->wait_state = WSTATE_NOT_WAITING;
                return 1;
            }

        default:
            assert(!"Invalid wait_state in SYSCALL_ENTER_START");
            return 0;
        }
    }

    case SIGSYS_OCC: {
        // seccomp 触发的 SIGSYS 信号处理
        Tracee *tracee = TRACEE(extension);
        struct SysVIpcConfig *config = extension->config;
        if (config == NULL)
            return 0;
        return sysvipc_syscall_common(tracee, config, true);
    }

    case SYSCALL_EXIT_START: {
        // 系统调用退出时处理（链式调用、等待结束）
        Tracee *tracee = TRACEE(extension);
        struct SysVIpcConfig *config = extension->config;
        if (config == NULL)
            return 0;

        // 处理 shmat 链式调用
        if (config->chain_state >= CSTATE_SHMAT_SOCKET && config->chain_state <= CSTATE_SHMAT_MMAP) {
            assert(config->chain_state == CSTATE_SHMAT_SOCKET);
            return sysvipc_shmat_chain(tracee, config);
        }

        // 处理等待状态结束
        switch (config->wait_state) {
        case WSTATE_NOT_WAITING:
            return 0;

        case WSTATE_ENTERED_PPOLL:
            // ppoll 等待结束
            config->wait_state = WSTATE_NOT_WAITING;
            switch (config->wait_reason) {
            case WR_NOT_WAITING:
                assert(!"Unexpected WR_NOT_WAITING in WSTATE_ENTERED_PPOLL");
                break;
            case WR_WAIT_SEMOP:
                // semop 超时处理
                sysvipc_semop_timedout(tracee, config);
                break;
            default:
                config->wait_reason = WR_NOT_WAITING;
                break;
            }
            assert(config->wait_reason == WR_NOT_WAITING);

            // 处理 ppoll 返回状态
            int ppoll_status = (int)peek_reg(tracee, CURRENT, SYSARG_RESULT);
            if (ppoll_status == -EFAULT || ppoll_status == -EINTR)
                return 1;
            return -EINTR;

        case WSTATE_SIGNALED_PPOLL:
        case WSTATE_ENTERED_GETPID:
            // 等待被唤醒或占位 getpid 结束，返回结果
            assert(config->wait_reason == WR_NOT_WAITING);
            config->wait_state = WSTATE_NOT_WAITING;

            int status = config->status_after_wait;
            if (config->chain_state == CSTATE_MSGRCV_RETRY) {
                status = sysvipc_msgrcv_retry(tracee, config);
            }
            poke_reg(tracee, SYSARG_RESULT, status);
            return 1;

        default:
            assert(!"Invalid wait_state in SYSCALL_EXIT_START");
            return 0;
        }
    }

    case SYSCALL_CHAINED_ENTER: {
        // 链式调用进入处理
        struct SysVIpcConfig *config = extension->config;
        if (config == NULL)
            return 0;

        switch (config->wait_state) {
        case WSTATE_NOT_WAITING:
            break;
        case WSTATE_RESTARTED_INTO_PPOLL_CANCELED:
            // 取消等待，标记为信号唤醒
            {
                Tracee *tracee = TRACEE(extension);
                poke_reg(tracee, SYSARG_3, 1);
                config->wait_state = WSTATE_SIGNALED_PPOLL;
                break;
            }
        default:
            assert(!"Invalid wait_state in SYSCALL_CHAINED_ENTER");
            break;
        }
        return 0;
    }

    case SYSCALL_CHAINED_EXIT: {
        // 链式调用退出处理
        Tracee *tracee = TRACEE(extension);
        struct SysVIpcConfig *config = extension->config;
        if (config == NULL)
            return 0;

        switch (config->wait_state) {
        case WSTATE_NOT_WAITING:
            break;
        case WSTATE_SIGNALED_PPOLL:
            // 信号唤醒，结束等待
            config->wait_state = WSTATE_NOT_WAITING;
            return 0;
        default:
            assert(!"Invalid wait_state in SYSCALL_CHAINED_EXIT");
            break;
        }

        // 继续 shmat 链式调用
        if (config->chain_state >= CSTATE_SHMAT_SOCKET && config->chain_state <= CSTATE_SHMAT_MMAP) {
            sysvipc_shmat_chain(tracee, config);
        }
        return 0;
    }

    case GUEST_PATH: {
        // 模拟 /proc/sysvipc/shm 路径
        if (strcmp((const char *)data2, "/proc/sysvipc/shm") == 0) {
            return sysvipc_proc_handler((char *)data1, extension, sysvipc_shm_fill_proc);
        }
        return 0;
    }

    default:
        return 0;
    }
}

/**
 * 获取 tracee 的 SysV IPC 配置
 * @param tracee 进程追踪句柄
 * @return 成功返回配置指针，失败返回 NULL
 */
struct SysVIpcConfig *sysvipc_get_config(Tracee *tracee)
{
    if (tracee == NULL)
        return NULL;

    Extension *extension = get_extension(tracee, sysvipc_callback);
    if (extension == NULL || extension->config == NULL)
        return NULL;

    return talloc_get_type_abort(extension->config, struct SysVIpcConfig);
}

/**
 * 唤醒等待中的 IPC 进程
 * @param tracee 目标进程追踪句柄
 * @param config IPC 配置
 * @param status 唤醒后返回的状态
 */
void sysvipc_wake_tracee(Tracee *tracee, struct SysVIpcConfig *config, int status)
{
    if (tracee == NULL || config == NULL)
        return;

    assert(config->wait_reason != WR_NOT_WAITING);

    // 更新等待状态和返回结果
    config->wait_reason = WR_NOT_WAITING;
    config->status_after_wait = status;

    // 根据当前等待状态处理唤醒逻辑
    if (config->wait_state == WSTATE_ENTERED_PPOLL) {
        // 正在 ppoll 等待，发送 SIGSTOP 唤醒
        config->wait_state = WSTATE_SIGNALED_PPOLL;
        syscall(__NR_tkill, tracee->pid, SIGSTOP);
        tracee->sigstop = SIGSTOP_IGNORED;
    } else if (config->wait_state == WSTATE_RESTARTED_INTO_PPOLL) {
        // 已重启进入 ppoll，标记为取消
        config->wait_state = WSTATE_RESTARTED_INTO_PPOLL_CANCELED;
    } else {
        assert(!"Invalid wait_state in sysvipc_wake_tracee");
    }
}
