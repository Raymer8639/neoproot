#include "sysvipc_internal.h"
#include "sysvipc_sys.h"

#include "tracee/reg.h"
#include "tracee/mem.h"
#include "tracee/tracee.h"

#include <sys/errno.h>
#include <string.h>
#include <assert.h>
#include <limits.h>

/* 信号量资源限制配置 */
#define SYSVIPC_MAX_SEMS     512    /* 系统最大信号量集数量 */
#define SYSVIPC_MAX_NSEMS    512    /* 单个信号量集最大信号量数 */
#define SYSVIPC_MAX_NSOPS    512    /* 单个semop调用最大操作数 */
#define SYSVIPC_MAX_SEMVAL   0x7000 /* 信号量最大值 */

/**
 * 检查并执行信号量操作（内部辅助函数）
 * @param config SysV IPC配置
 * @param semaphore 目标信号量集
 * @param out_wait_type 输出等待类型（'n'-等待递增，'z'-等待为0，NULL则不输出）
 * @return 0-执行成功，1-需继续等待，<0-错误码
 */
static int sysvipc_sem_check(struct SysVIpcConfig *config, struct SysVIpcSemaphore *semaphore, char *out_wait_type)
{
    assert(config != NULL && semaphore != NULL);
    assert(config->wait_reason == WR_WAIT_SEMOP);

    size_t nsops = talloc_array_length(config->semop_sops);
    uint16_t new_sem_vals[semaphore->nsems];
    int sem_nsems = (int)semaphore->nsems; // 转为有符号，统一比较类型

    // 复制当前信号量值，避免直接修改原数据
    memcpy(new_sem_vals, semaphore->sems, semaphore->nsems * sizeof(uint16_t));

    // 遍历所有信号量操作
    for (size_t i = 0; i < nsops; i++) {
        const struct SysVIpcSembuf *sop = &config->semop_sops[i];
        int op = sop->sem_op;
        int sem_num = sop->sem_num; // 保持有符号类型，统一比较

        // 检查信号量索引有效性（全有符号比较，彻底消除警告）
        if (sem_num < 0 || sem_num >= sem_nsems)
            return -EFBIG;

        // 处理操作类型：0-等待信号量为0
        if (op == 0) {
            if (new_sem_vals[sem_num] != 0) {
                if (sop->sem_flg & IPC_NOWAIT)
                    return -EAGAIN;
                if (out_wait_type != NULL)
                    *out_wait_type = 'z';
                return 1; // 需等待
            }
        }
        // 处理操作类型：非0-增减信号量值
        else {
            int new_val = (int)new_sem_vals[sem_num] + op;
            // 检查值范围有效性
            if (new_val < 0) {
                if (sop->sem_flg & IPC_NOWAIT)
                    return -EAGAIN;
                if (out_wait_type != NULL)
                    *out_wait_type = 'n';
                return 1; // 需等待
            }
            if (new_val > SYSVIPC_MAX_SEMVAL)
                return -ERANGE;

            new_sem_vals[sem_num] = (uint16_t)new_val;
        }
    }

    // 所有操作验证通过，更新信号量值
    memcpy(semaphore->sems, new_sem_vals, semaphore->nsems * sizeof(uint16_t));
    return 0;
}

/**
 * 实现semget系统调用：创建/获取信号量集
 * @param tracee 进程追踪句柄
 * @param config SysV IPC配置
 * @return 成功返回semid，失败返回-errno
 */
int sysvipc_semget(Tracee *tracee, struct SysVIpcConfig *config)
{
    if (tracee == NULL || config == NULL || config->ipc_namespace == NULL)
        return -EINVAL;

    word_t sem_key = peek_reg(tracee, CURRENT, SYSARG_1);
    int nsems = (int)peek_reg(tracee, CURRENT, SYSARG_2);
    int sem_flg = (int)peek_reg(tracee, CURRENT, SYSARG_3);

    // 检查信号量数量有效性
    if (nsems <= 0 || nsems > SYSVIPC_MAX_NSEMS)
        return -EINVAL;

    struct SysVIpcSemaphore *semaphores = config->ipc_namespace->semaphores;
    size_t num_semaphores = talloc_array_length(semaphores);
    size_t unused_slot = 0;
    size_t sem_idx = 0;
    bool found_unused = false;
    bool found_existing = false;

    // 查找已存在的信号量集或未使用的槽位
    for (; sem_idx < num_semaphores; sem_idx++) {
        if (semaphores[sem_idx].valid) {
            // 找到匹配key的信号量集
            if (sem_key != IPC_PRIVATE && semaphores[sem_idx].key == (int32_t)sem_key) {
                found_existing = true;
                break;
            }
        } else if (!found_unused) {
            unused_slot = sem_idx;
            found_unused = true;
        }
    }

    struct SysVIpcSemaphore *sem = NULL;
    // 未找到已存在的信号量集，需创建新集
    if (!found_existing) {
        // 未指定IPC_CREAT，返回不存在错误
        if (!(sem_flg & IPC_CREAT))
            return -ENOENT;

        // 检查系统信号量集数量限制
        if (!found_unused && num_semaphores >= SYSVIPC_MAX_SEMS)
            return -ENOSPC;

        // 分配新槽位
        if (found_unused) {
            sem_idx = unused_slot;
            sem = &semaphores[sem_idx];
            memset(sem, 0, sizeof(*sem));
        } else {
            semaphores = talloc_realloc(config->ipc_namespace, semaphores,
                                       struct SysVIpcSemaphore, num_semaphores + 1);
            if (semaphores == NULL)
                return -ENOMEM;
            config->ipc_namespace->semaphores = semaphores;
            sem_idx = num_semaphores;
            sem = &semaphores[sem_idx];
            memset(sem, 0, sizeof(*sem));
        }

        // 初始化新信号量集
        sem->key = sem_key;
        sem->valid = true;
        sem->nsems = (size_t)nsems;
        sem->sems = talloc_array(config->ipc_namespace, uint16_t, nsems);
        if (sem->sems == NULL) {
            sem->valid = false;
            return -ENOMEM;
        }
        memset(sem->sems, 0, nsems * sizeof(uint16_t));
    }
    // 找到已存在的信号量集
    else {
        sem = &semaphores[sem_idx];
        // 同时指定IPC_CREAT和IPC_EXCL，返回已存在错误
        if ((sem_flg & IPC_CREAT) && (sem_flg & IPC_EXCL))
            return -EEXIST;
        // 检查信号量数量匹配（全有符号比较）
        if ((int)sem->nsems < nsems)
            return -EINVAL;
    }

    // 生成semid：索引+1（避免0值） | 世代号左移12位
    return (int)((sem_idx + 1) | (sem->generation << 12));
}

/**
 * 实现semop系统调用：执行信号量操作
 * @param tracee 进程追踪句柄
 * @param config SysV IPC配置
 * @return 0-等待中，成功返回0，失败返回-errno
 */
int sysvipc_semop(Tracee *tracee, struct SysVIpcConfig *config)
{
    if (tracee == NULL || config == NULL || config->ipc_namespace == NULL)
        return -EINVAL;

    // 查找目标信号量集
    size_t sem_idx;
    struct SysVIpcSemaphore *sem;
    LOOKUP_IPC_OBJECT(sem_idx, sem, config->ipc_namespace->semaphores);

    // 读取semop参数
    word_t sops_ptr = peek_reg(tracee, CURRENT, SYSARG_2);
    size_t nsops = (size_t)peek_reg(tracee, CURRENT, SYSARG_3);
    int sem_nsems = (int)sem->nsems; // 转为有符号，统一比较类型

    // 检查操作数有效性
    if (nsops == 0 || nsops > SYSVIPC_MAX_NSOPS)
        return -EINVAL;

    // 读取信号量操作数组
    struct SysVIpcSembuf *sops = talloc_array(config, struct SysVIpcSembuf, nsops);
    if (sops == NULL)
        return -ENOMEM;

    int status = read_data(tracee, sops, sops_ptr, sizeof(struct SysVIpcSembuf) * nsops);
    if (status < 0) {
        talloc_free(sops);
        return status;
    }

    // 检查所有操作的信号量索引有效性（全有符号比较，消除警告）
    for (size_t i = 0; i < nsops; i++) {
        int sem_num = sops[i].sem_num;
        if (sem_num < 0 || sem_num >= sem_nsems) {
            talloc_free(sops);
            return -EFBIG;
        }
    }

    // 保存操作信息，准备执行检查
    config->wait_reason = WR_WAIT_SEMOP;
    config->waiting_object_index = sem_idx;
    config->semop_sops = sops;
    int op_status = sysvipc_sem_check(config, sem, NULL);

    // 唤醒等待同一信号量集的其他进程
    Tracee *other_tracee;
    struct SysVIpcConfig *other_config;
    SYSVIPC_FOREACH_TRACEE(other_tracee, other_config, config->ipc_namespace) {
        if (other_config == config)
            continue;
        if (other_config->wait_reason == WR_WAIT_SEMOP &&
            other_config->waiting_object_index == sem_idx) {
            int other_op_status = sysvipc_sem_check(other_config, sem, NULL);
            if (other_op_status != 1) {
                TALLOC_FREE(other_config->semop_sops);
                sysvipc_wake_tracee(other_tracee, other_config, other_op_status);
            }
        }
    }

    // 处理当前进程操作结果
    if (op_status == 1) {
        // 需等待，保留操作信息
        return 0;
    } else {
        // 执行完成或失败，释放操作信息
        TALLOC_FREE(config->semop_sops);
        config->wait_reason = WR_NOT_WAITING;
        return op_status;
    }
}

/**
 * semop超时处理：释放等待资源
 * @param tracee 进程追踪句柄
 * @param config SysV IPC配置
 */
void sysvipc_semop_timedout(Tracee *tracee, struct SysVIpcConfig *config)
{
    (void)tracee; // 未使用参数
    if (config == NULL)
        return;

    TALLOC_FREE(config->semop_sops);
    config->wait_reason = WR_NOT_WAITING;
}

/**
 * 实现semctl系统调用：控制信号量集
 * @param tracee 进程追踪句柄
 * @param config SysV IPC配置
 * @return 成功返回对应值，失败返回-errno
 */
int sysvipc_semctl(Tracee *tracee, struct SysVIpcConfig *config)
{
    if (tracee == NULL || config == NULL || config->ipc_namespace == NULL)
        return -EINVAL;

    // 查找目标信号量集
    size_t sem_idx;
    struct SysVIpcSemaphore *sem;
    LOOKUP_IPC_OBJECT(sem_idx, sem, config->ipc_namespace->semaphores);

    int sem_num = (int)peek_reg(tracee, CURRENT, SYSARG_2); // 有符号类型
    int sem_nsems = (int)sem->nsems; // 转为有符号，统一比较类型
    int cmd = (int)peek_reg(tracee, CURRENT, SYSARG_3);
    word_t cmd_arg = peek_reg(tracee, CURRENT, SYSARG_4);

    // 剥离64位标志，统一处理命令
    cmd &= ~SYSVIPC_IPC_64;

    switch (cmd) {
    case SYSVIPC_GETVAL:
        // 获取单个信号量值（全有符号比较）
        if (sem_num < 0 || sem_num >= sem_nsems)
            return -EINVAL;
        return (int)sem->sems[sem_num];

    case SYSVIPC_SETVAL:
        // 设置单个信号量值（全有符号比较）
        if (sem_num < 0 || sem_num >= sem_nsems)
            return -EINVAL;
        if (cmd_arg > SYSVIPC_MAX_SEMVAL)
            return -ERANGE;
        sem->sems[sem_num] = (uint16_t)cmd_arg;
        return 0;

    case SYSVIPC_GETALL:
        // 获取所有信号量值
        {
            int status = write_data(tracee, cmd_arg, sem->sems, sem->nsems * sizeof(uint16_t));
            return (status < 0) ? status : 0;
        }

    case IPC_RMID:
        // 删除信号量集
        {
            // 唤醒所有等待该信号量集的进程
            Tracee *waiting_tracee;
            struct SysVIpcConfig *waiting_config;
            SYSVIPC_FOREACH_TRACEE(waiting_tracee, waiting_config, config->ipc_namespace) {
                if (waiting_config->wait_reason == WR_WAIT_SEMOP &&
                    waiting_config->waiting_object_index == sem_idx) {
                    sysvipc_wake_tracee(waiting_tracee, waiting_config, -EIDRM);
                }
            }

            // 标记为无效，释放资源
            sem->valid = false;
            sem->generation++;
            TALLOC_FREE(sem->sems);
            return 0;
        }

    case SYSVIPC_IPC_INFO:
    case SYSVIPC_SEM_INFO:
        // 获取信号量资源限制信息
        {
            struct SysVIpcSeminfo sem_info = {0};
            sem_info.semmni = SYSVIPC_MAX_SEMS;
            sem_info.semmns = SYSVIPC_MAX_SEMS * SYSVIPC_MAX_NSEMS;
            sem_info.semmsl = SYSVIPC_MAX_NSEMS;
            sem_info.semopm = SYSVIPC_MAX_NSOPS;
            sem_info.semvmx = SYSVIPC_MAX_SEMVAL;

            // SEM_INFO命令需要补充当前使用统计
            if (cmd == SYSVIPC_SEM_INFO) {
                struct SysVIpcSemaphore *semaphores = config->ipc_namespace->semaphores;
                size_t num_sems = talloc_array_length(semaphores);
                sem_info.semusz = (int)num_sems;

                // 统计总信号量数
                sem_info.semaem = 0;
                for (size_t i = 0; i < num_sems; i++) {
                    if (semaphores[i].valid)
                        sem_info.semaem += (int)semaphores[i].nsems;
                }
            }

            // 写入结果到进程内存
            int status = write_data(tracee, cmd_arg, &sem_info, sizeof(sem_info));
            return (status < 0) ? status : 0;
        }

    default:
        // 不支持的命令
        return -EINVAL;
    }
}
