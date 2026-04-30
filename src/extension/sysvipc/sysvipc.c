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

#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define ALWAYS_INLINE __attribute__((always_inline, flatten))
#define HOT __attribute__((hot))

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

static HOT int sysvipc_syscall_common(Tracee *restrict tracee, struct SysVIpcConfig *restrict config, bool from_sigsys) {
    if (UNLIKELY(!tracee || !config)) return 0;
    assert(config->wait_state == WSTATE_NOT_WAITING);

    int status = 0;
    word_t timeout = 0;
    word_t sysnum = get_sysnum(tracee, CURRENT);

    switch (sysnum) {
        case PR_msgget:    status = sysvipc_msgget(tracee, config);    break;
        case PR_msgsnd:    status = sysvipc_msgsnd(tracee, config);    break;
        case PR_msgrcv:    status = sysvipc_msgrcv(tracee, config);     break;
        case PR_msgctl:    status = sysvipc_msgctl(tracee, config);     break;
        case PR_semget:    status = sysvipc_semget(tracee, config);     break;
        case PR_semtimedop: timeout = peek_reg(tracee, CURRENT, SYSARG_4);
        case PR_semop:     status = sysvipc_semop(tracee, config);      break;
        case PR_semctl:    status = sysvipc_semctl(tracee, config);     break;
        case PR_shmget:    status = sysvipc_shmget(tracee, config);     break;
        case PR_shmat:     status = sysvipc_shmat(tracee, config);      break;
        case PR_shmdt:     status = sysvipc_shmdt(tracee, config);      break;
        case PR_shmctl:    status = sysvipc_shmctl(tracee, config);     break;
        default: return 0;
    }

    if (config->chain_state != CSTATE_NOT_CHAINED) {
        if (config->chain_state == CSTATE_SINGLE)
            config->chain_state = CSTATE_NOT_CHAINED;
        tracee->restart_how = PTRACE_SYSCALL;
        if (from_sigsys) {
            restart_syscall_after_seccomp(tracee);
            return 2;
        }
        return 1;
    }

    if (config->wait_reason != WR_NOT_WAITING) {
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

    if (from_sigsys) {
        set_result_after_seccomp(tracee, status);
        return 2;
    } else {
        config->status_after_wait = status;
        config->wait_state = WSTATE_ENTERED_GETPID;
        set_sysnum(tracee, PR_getpid);
        tracee->restart_how = PTRACE_SYSCALL;
        return 1;
    }
}

static ALWAYS_INLINE int sysvipc_proc_handler(char *out_path, Extension *restrict ext,
                                              void (*fn)(FILE *, struct SysVIpcNamespace *)) {
    if (UNLIKELY(!out_path || !ext || !fn)) return -EINVAL;
    Tracee *tracee = TRACEE(ext);
    struct SysVIpcConfig *config = ext->config;
    if (UNLIKELY(!config || !config->ipc_namespace)) return -EINVAL;
    const char *tmp = create_temp_file(tracee->ctx, "prootseq");
    if (UNLIKELY(!tmp)) return -ENOMEM;
    FILE *fp = fopen(tmp, "w");
    if (UNLIKELY(!fp)) return -EIO;
    fn(fp, config->ipc_namespace);
    fclose(fp);
    strncpy(out_path, tmp, PATH_MAX - 1);
    out_path[PATH_MAX - 1] = '\0';
    return 1;
}

HOT
int sysvipc_callback(Extension *restrict ext, ExtensionEvent ev, intptr_t d1, intptr_t d2) {
    if (UNLIKELY(!ext)) return -EINVAL;
    switch (ev) {
        case INITIALIZATION: {
            Tracee *tracee = TRACEE(ext);
            struct SysVIpcConfig *c = talloc_zero(ext, struct SysVIpcConfig);
            if (UNLIKELY(!c)) return -ENOMEM;
            c->ipc_namespace = talloc_zero(c, struct SysVIpcNamespace);
            if (UNLIKELY(!c->ipc_namespace)) { talloc_free(c); return -ENOMEM; }
            talloc_set_destructor(c->ipc_namespace, sysvipc_shm_namespace_destructor);
            c->process = talloc_zero(c, struct SysVIpcProcess);
            if (UNLIKELY(!c->process)) { talloc_free(c); return -ENOMEM; }
            c->process->pgid = tracee->pid;
            ext->config = c;
            ext->filtered_sysnums = filtered_sysnums;
            return 0;
        }
        case INHERIT_PARENT:
            return 1;
        case INHERIT_CHILD: {
            Extension *parent = (Extension *)d1;
            struct SysVIpcConfig *pcfg = parent->config;
            if (UNLIKELY(!pcfg)) return -EINVAL;
            struct SysVIpcConfig *ccfg = talloc_zero(ext, struct SysVIpcConfig);
            if (UNLIKELY(!ccfg)) return -ENOMEM;
            if (d2 & CLONE_THREAD) {
                ccfg->process = talloc_reference(ccfg, pcfg->process);
            } else {
                Tracee *t = TRACEE(ext);
                ccfg->process = talloc_zero(ccfg, struct SysVIpcProcess);
                if (UNLIKELY(!ccfg->process)) { talloc_free(ccfg); return -ENOMEM; }
                ccfg->process->pgid = t->pid;
                sysvipc_shm_inherit_process(pcfg->process, ccfg->process);
            }
            ccfg->ipc_namespace = talloc_reference(ccfg, pcfg->ipc_namespace);
            ext->config = ccfg;
            return 0;
        }
        case SYSCALL_ENTER_END: {
            if (!d1) {
                Tracee *t = TRACEE(ext);
                if (get_sysnum(t, CURRENT) == PR_execve) {
                    struct SysVIpcConfig *c = ext->config;
                    if (c && c->process)
                        sysvipc_shm_remove_mappings_from_process(c->process);
                }
            }
            return 0;
        }
        case SYSCALL_ENTER_START: {
            Tracee *t = TRACEE(ext);
            struct SysVIpcConfig *c = ext->config;
            if (UNLIKELY(!c)) return 0;
            switch (c->wait_state) {
                case WSTATE_NOT_WAITING:
                    return sysvipc_syscall_common(t, c, false);
                case WSTATE_RESTARTED_INTO_PPOLL:
                    c->wait_state = WSTATE_ENTERED_PPOLL;
                    t->restart_how = PTRACE_SYSCALL;
                    return 1;
                case WSTATE_RESTARTED_INTO_PPOLL_CANCELED: {
                    int st = c->status_after_wait;
                    if (c->chain_state == CSTATE_MSGRCV_RETRY)
                        st = sysvipc_msgrcv_retry(t, c);
                    poke_reg(t, SYSARG_RESULT, st);
                    set_sysnum(t, PR_void);
                    c->wait_state = WSTATE_NOT_WAITING;
                    return 1;
                }
                default:
                    return 0;
            }
        }
        case SIGSYS_OCC: {
            Tracee *t = TRACEE(ext);
            struct SysVIpcConfig *c = ext->config;
            return c ? sysvipc_syscall_common(t, c, true) : 0;
        }
        case SYSCALL_EXIT_START: {
            Tracee *t = TRACEE(ext);
            struct SysVIpcConfig *c = ext->config;
            if (UNLIKELY(!c)) return 0;
            if (c->chain_state >= CSTATE_SHMAT_SOCKET && c->chain_state <= CSTATE_SHMAT_MMAP)
                return sysvipc_shmat_chain(t, c);
            switch (c->wait_state) {
                case WSTATE_NOT_WAITING: return 0;
                case WSTATE_ENTERED_PPOLL:
                    c->wait_state = WSTATE_NOT_WAITING;
                    if (c->wait_reason == WR_WAIT_SEMOP)
                        sysvipc_semop_timedout(t, c);
                    c->wait_reason = WR_NOT_WAITING;
                    {
                        int st = (int)peek_reg(t, CURRENT, SYSARG_RESULT);
                        if (st == -EFAULT || st == -EINTR) return 1;
                        return -EINTR;
                    }
                case WSTATE_SIGNALED_PPOLL:
                case WSTATE_ENTERED_GETPID:
                    c->wait_state = WSTATE_NOT_WAITING;
                    {
                        int res = c->status_after_wait;
                        if (c->chain_state == CSTATE_MSGRCV_RETRY)
                            res = sysvipc_msgrcv_retry(t, c);
                        poke_reg(t, SYSARG_RESULT, res);
                        return 1;
                    }
                default:
                    return 0;
            }
        }
        case SYSCALL_CHAINED_ENTER: {
            struct SysVIpcConfig *c = ext->config;
            if (!c) return 0;
            if (c->wait_state == WSTATE_RESTARTED_INTO_PPOLL_CANCELED) {
                Tracee *t = TRACEE(ext);
                poke_reg(t, SYSARG_3, 1);
                c->wait_state = WSTATE_SIGNALED_PPOLL;
            }
            return 0;
        }
        case SYSCALL_CHAINED_EXIT: {
            Tracee *t = TRACEE(ext);
            struct SysVIpcConfig *c = ext->config;
            if (!c) return 0;
            if (c->wait_state == WSTATE_SIGNALED_PPOLL) {
                c->wait_state = WSTATE_NOT_WAITING;
                return 0;
            }
            if (c->chain_state >= CSTATE_SHMAT_SOCKET && c->chain_state <= CSTATE_SHMAT_MMAP)
                sysvipc_shmat_chain(t, c);
            return 0;
        }
        case GUEST_PATH:
            if (strcmp((const char *)d2, "/proc/sysvipc/shm") == 0)
                return sysvipc_proc_handler((char *)d1, ext, sysvipc_shm_fill_proc);
            return 0;
        default:
            return 0;
    }
}

struct SysVIpcConfig *sysvipc_get_config(Tracee *tracee) {
    if (UNLIKELY(!tracee)) return NULL;
    Extension *ext = get_extension(tracee, sysvipc_callback);
    if (!ext || !ext->config) return NULL;
    return talloc_get_type_abort(ext->config, struct SysVIpcConfig);
}

void sysvipc_wake_tracee(Tracee *t, struct SysVIpcConfig *c, int status) {
    if (UNLIKELY(!t || !c)) return;
    assert(c->wait_reason != WR_NOT_WAITING);
    c->wait_reason = WR_NOT_WAITING;
    c->status_after_wait = status;
    if (c->wait_state == WSTATE_ENTERED_PPOLL) {
        c->wait_state = WSTATE_SIGNALED_PPOLL;
        syscall(__NR_tkill, t->pid, SIGSTOP);
        t->sigstop = SIGSTOP_IGNORED;
    } else if (c->wait_state == WSTATE_RESTARTED_INTO_PPOLL) {
        c->wait_state = WSTATE_RESTARTED_INTO_PPOLL_CANCELED;
    }
}