#include "sysvipc_internal.h"
#include "sysvipc_sys.h"

#include "tracee/reg.h"
#include "tracee/mem.h"
#include "tracee/tracee.h"

#include <sys/errno.h>
#include <string.h>
#include <assert.h>
#include <limits.h>

#define SYSVIPC_MAX_SEMS     512U
#define SYSVIPC_MAX_NSEMS    512U
#define SYSVIPC_MAX_NSOPS    512U
#define SYSVIPC_MAX_SEMVAL   0x7000U

#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define ALWAYS_INLINE __attribute__((always_inline, flatten))
#define HOT __attribute__((hot))
#define ALIGNED __attribute__((aligned(8)))

static ALWAYS_INLINE int sem_check(struct SysVIpcConfig *restrict config,
                                   struct SysVIpcSemaphore *restrict sem,
                                   char *restrict out_wait_type) {
    assert(config && sem);
    assert(config->wait_reason == WR_WAIT_SEMOP);
    size_t nsops = talloc_array_length(config->semop_sops);
    uint16_t new_vals[SYSVIPC_MAX_NSEMS];
    if (UNLIKELY((unsigned int)sem->nsems > SYSVIPC_MAX_NSEMS)) return -EFBIG;
    memcpy(new_vals, sem->sems, sem->nsems * sizeof(uint16_t));
    for (size_t i = 0; i < nsops; ++i) {
        const struct SysVIpcSembuf *sop = &config->semop_sops[i];
        int sem_num = sop->sem_num;
        if (UNLIKELY(sem_num < 0 || (unsigned int)sem_num >= (unsigned int)sem->nsems)) return -EFBIG;
        int op = sop->sem_op;
        if (op == 0) {
            if (new_vals[sem_num] != 0) {
                if (sop->sem_flg & IPC_NOWAIT) return -EAGAIN;
                if (out_wait_type) *out_wait_type = 'z';
                return 1;
            }
        } else {
            int new_val = (int)new_vals[sem_num] + op;
            if (new_val < 0) {
                if (sop->sem_flg & IPC_NOWAIT) return -EAGAIN;
                if (out_wait_type) *out_wait_type = 'n';
                return 1;
            }
            if (UNLIKELY((unsigned int)new_val > SYSVIPC_MAX_SEMVAL)) return -ERANGE;
            new_vals[sem_num] = (uint16_t)new_val;
        }
    }
    memcpy(sem->sems, new_vals, sem->nsems * sizeof(uint16_t));
    return 0;
}

HOT int sysvipc_semget(Tracee *restrict tracee, struct SysVIpcConfig *restrict config) {
    if (UNLIKELY(!tracee || !config || !config->ipc_namespace)) return -EINVAL;
    word_t key = peek_reg(tracee, CURRENT, SYSARG_1);
    int nsems = (int)peek_reg(tracee, CURRENT, SYSARG_2);
    int flg = (int)peek_reg(tracee, CURRENT, SYSARG_3);
    if (nsems <= 0 || (unsigned int)nsems > SYSVIPC_MAX_NSEMS) return -EINVAL;
    struct SysVIpcSemaphore *sems = config->ipc_namespace->semaphores;
    size_t num = talloc_array_length(sems);
    size_t unused = 0, idx = 0;
    bool found_unused = false, found_existing = false;
    for (; idx < num; ++idx) {
        if (sems[idx].valid) {
            if (key != IPC_PRIVATE && sems[idx].key == (int32_t)key) {
                found_existing = true; break;
            }
        } else if (!found_unused) {
            unused = idx; found_unused = true;
        }
    }
    struct SysVIpcSemaphore *sem = NULL;
    if (!found_existing) {
        if (!(flg & IPC_CREAT)) return -ENOENT;
        if (!found_unused && num >= SYSVIPC_MAX_SEMS) return -ENOSPC;
        if (found_unused) {
            idx = unused;
            sem = &sems[idx];
            memset(sem, 0, sizeof(*sem));
        } else {
            sems = talloc_realloc(config->ipc_namespace, sems, struct SysVIpcSemaphore, num + 1);
            if (!sems) return -ENOMEM;
            config->ipc_namespace->semaphores = sems;
            idx = num;
            sem = &sems[idx];
            memset(sem, 0, sizeof(*sem));
        }
        sem->key = key;
        sem->valid = true;
        sem->nsems = nsems;
        sem->sems = talloc_array(config->ipc_namespace, uint16_t, nsems);
        if (!sem->sems) { sem->valid = false; return -ENOMEM; }
        memset(sem->sems, 0, nsems * sizeof(uint16_t));
    } else {
        sem = &sems[idx];
        if ((flg & IPC_CREAT) && (flg & IPC_EXCL)) return -EEXIST;
        if (sem->nsems < nsems) return -EINVAL;
    }
    return (int)((idx + 1) | ((unsigned int)sem->generation << 12));
}

HOT int sysvipc_semop(Tracee *restrict tracee, struct SysVIpcConfig *restrict config) {
    if (UNLIKELY(!tracee || !config || !config->ipc_namespace)) return -EINVAL;
    size_t idx;
    struct SysVIpcSemaphore *sem;
    LOOKUP_IPC_OBJECT(idx, sem, config->ipc_namespace->semaphores);
    word_t sops_ptr = peek_reg(tracee, CURRENT, SYSARG_2);
    size_t nsops = (size_t)peek_reg(tracee, CURRENT, SYSARG_3);
    if (nsops == 0 || nsops > SYSVIPC_MAX_NSOPS) return -EINVAL;
    struct SysVIpcSembuf *sops = talloc_array(config, struct SysVIpcSembuf, nsops);
    if (!sops) return -ENOMEM;
    int st = read_data(tracee, sops, sops_ptr, sizeof(struct SysVIpcSembuf) * nsops);
    if (UNLIKELY(st < 0)) { talloc_free(sops); return st; }
    for (size_t i = 0; i < nsops; ++i) {
        int sem_num = sops[i].sem_num;
        if (UNLIKELY(sem_num < 0 || (unsigned int)sem_num >= (unsigned int)sem->nsems)) {
            talloc_free(sops); return -EFBIG;
        }
    }
    config->wait_reason = WR_WAIT_SEMOP;
    config->waiting_object_index = idx;
    config->semop_sops = sops;
    int op_st = sem_check(config, sem, NULL);
    Tracee *ot;
    struct SysVIpcConfig *ocfg;
    SYSVIPC_FOREACH_TRACEE(ot, ocfg, config->ipc_namespace) {
        if (ocfg == config) continue;
        if (ocfg->wait_reason == WR_WAIT_SEMOP && ocfg->waiting_object_index == idx) {
            int other_st = sem_check(ocfg, sem, NULL);
            if (other_st != 1) {
                TALLOC_FREE(ocfg->semop_sops);
                sysvipc_wake_tracee(ot, ocfg, other_st);
            }
        }
    }
    if (op_st == 1) return 0;
    TALLOC_FREE(config->semop_sops);
    config->wait_reason = WR_NOT_WAITING;
    return op_st;
}

void sysvipc_semop_timedout(Tracee *tracee, struct SysVIpcConfig *config) {
    (void)tracee;
    if (config) {
        TALLOC_FREE(config->semop_sops);
        config->wait_reason = WR_NOT_WAITING;
    }
}

HOT int sysvipc_semctl(Tracee *restrict tracee, struct SysVIpcConfig *restrict config) {
    if (UNLIKELY(!tracee || !config || !config->ipc_namespace)) return -EINVAL;
    size_t idx;
    struct SysVIpcSemaphore *sem;
    LOOKUP_IPC_OBJECT(idx, sem, config->ipc_namespace->semaphores);
    int sem_num = (int)peek_reg(tracee, CURRENT, SYSARG_2);
    int cmd = (int)peek_reg(tracee, CURRENT, SYSARG_3);
    word_t arg = peek_reg(tracee, CURRENT, SYSARG_4);
    cmd &= ~SYSVIPC_IPC_64;
    switch (cmd) {
    case SYSVIPC_GETVAL:
        if (UNLIKELY(sem_num < 0 || (unsigned int)sem_num >= (unsigned int)sem->nsems)) return -EINVAL;
        return (int)sem->sems[sem_num];
    case SYSVIPC_SETVAL:
        if (UNLIKELY(sem_num < 0 || (unsigned int)sem_num >= (unsigned int)sem->nsems)) return -EINVAL;
        if (UNLIKELY(arg > SYSVIPC_MAX_SEMVAL)) return -ERANGE;
        sem->sems[sem_num] = (uint16_t)arg;
        return 0;
    case SYSVIPC_GETALL: {
        int st = write_data(tracee, arg, sem->sems, sem->nsems * sizeof(uint16_t));
        return st < 0 ? st : 0;
    }
    case IPC_RMID: {
        Tracee *wt;
        struct SysVIpcConfig *wcfg;
        SYSVIPC_FOREACH_TRACEE(wt, wcfg, config->ipc_namespace) {
            if (wcfg->wait_reason == WR_WAIT_SEMOP && wcfg->waiting_object_index == idx)
                sysvipc_wake_tracee(wt, wcfg, -EIDRM);
        }
        sem->valid = false;
        sem->generation++;
        TALLOC_FREE(sem->sems);
        return 0;
    }
    case SYSVIPC_IPC_INFO:
    case SYSVIPC_SEM_INFO: {
        struct SysVIpcSeminfo info = {0};
        info.semmni = SYSVIPC_MAX_SEMS;
        info.semmns = SYSVIPC_MAX_SEMS * SYSVIPC_MAX_NSEMS;
        info.semmsl = SYSVIPC_MAX_NSEMS;
        info.semopm = SYSVIPC_MAX_NSOPS;
        info.semvmx = SYSVIPC_MAX_SEMVAL;
        if (cmd == SYSVIPC_SEM_INFO) {
            struct SysVIpcSemaphore *sems = config->ipc_namespace->semaphores;
            size_t num = talloc_array_length(sems);
            info.semusz = (int)num;
            info.semaem = 0;
            for (size_t i = 0; i < num; ++i)
                if (sems[i].valid) info.semaem += (int)sems[i].nsems;
        }
        int st = write_data(tracee, arg, &info, sizeof(info));
        return st < 0 ? st : 0;
    }
    default:
        return -EINVAL;
    }
}