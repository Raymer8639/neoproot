#include <sys/ptrace.h>
#include <errno.h>
#include <assert.h>
#include <stdbool.h>
#include <signal.h>
#include <sys/uio.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <string.h>

#include "ptrace/ptrace.h"
#include "ptrace/user.h"
#include "tracee/tracee.h"
#include "syscall/sysnum.h"
#include "tracee/reg.h"
#include "tracee/mem.h"
#include "tracee/abi.h"
#include "tracee/event.h"
#include "cli/note.h"
#include "arch.h"
#include "compat.h"

#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define ALWAYS_INLINE __attribute__((always_inline, flatten))
#define HOT __attribute__((hot))

#if defined(ARCH_ARM64)
#define user_fpregs_struct user_fpsimd_struct
#else
#error "Only ARM64 architecture is supported"
#endif

// 简化的请求字符串（仅用于警告，可保留）
static const char *stringify_ptrace(int request) {
#define CASE_STR(a) case a: return #a;
    switch (request) {
    CASE_STR(PTRACE_TRACEME)      CASE_STR(PTRACE_PEEKTEXT)      CASE_STR(PTRACE_PEEKDATA)
    CASE_STR(PTRACE_PEEKUSER)     CASE_STR(PTRACE_POKETEXT)      CASE_STR(PTRACE_POKEDATA)
    CASE_STR(PTRACE_POKEUSER)     CASE_STR(PTRACE_CONT)          CASE_STR(PTRACE_KILL)
    CASE_STR(PTRACE_SINGLESTEP)   CASE_STR(PTRACE_GETREGS)       CASE_STR(PTRACE_SETREGS)
    CASE_STR(PTRACE_GETFPREGS)    CASE_STR(PTRACE_SETFPREGS)     CASE_STR(PTRACE_ATTACH)
    CASE_STR(PTRACE_DETACH)       CASE_STR(PTRACE_GETFPXREGS)    CASE_STR(PTRACE_SETFPXREGS)
    CASE_STR(PTRACE_SYSCALL)      CASE_STR(PTRACE_SETOPTIONS)    CASE_STR(PTRACE_GETEVENTMSG)
    CASE_STR(PTRACE_GETSIGINFO)   CASE_STR(PTRACE_SETSIGINFO)    CASE_STR(PTRACE_GETREGSET)
    CASE_STR(PTRACE_SETREGSET)    CASE_STR(PTRACE_SEIZE)         CASE_STR(PTRACE_INTERRUPT)
    CASE_STR(PTRACE_LISTEN)       CASE_STR(PTRACE_SET_SYSCALL)   CASE_STR(PTRACE_GETVFPREGS)
    CASE_STR(PTRACE_SINGLEBLOCK)  CASE_STR(PTRACE_ARCH_PRCTL)
    default: return "PTRACE_???";
    }
#undef CASE_STR
}

int translate_ptrace_enter(Tracee *tracee) {
    set_sysnum(tracee, PR_void);
    return 0;
}

void attach_to_ptracer(Tracee *ptracee, Tracee *ptracer) {
    memset(&PTRACEE, 0, sizeof(PTRACEE));
    PTRACEE.ptracer = ptracer;
    PTRACER.nb_ptracees++;
}

void detach_from_ptracer(Tracee *ptracee) {
    Tracee *ptracer = PTRACEE.ptracer;
    PTRACEE.ptracer = NULL;
    assert(PTRACER.nb_ptracees > 0);
    PTRACER.nb_ptracees--;
}

HOT
int translate_ptrace_exit(Tracee *restrict tracee) {
    word_t request = peek_reg(tracee, ORIGINAL, SYSARG_1);
    word_t pid     = peek_reg(tracee, ORIGINAL, SYSARG_2);
    word_t address = peek_reg(tracee, ORIGINAL, SYSARG_3);
    word_t data    = peek_reg(tracee, ORIGINAL, SYSARG_4);
    word_t result;
    Tracee *ptracee, *ptracer;
    int forced_signal = -1;
    int signal;
    int status;

    // PTRACE_TRACEME
    if (request == PTRACE_TRACEME) {
        ptracer = tracee->parent;
        ptracee = tracee;
        if (UNLIKELY(PTRACEE.ptracer != NULL || ptracee == ptracer))
            return -EPERM;
        attach_to_ptracer(ptracee, ptracer);
        if (PTRACER.waits_in == WAITS_IN_KERNEL) {
            if (kill(ptracer->pid, SIGSTOP) < 0)
                note(tracee, WARNING, INTERNAL, "can't wake ptracer %d", ptracer->pid);
            else {
                ptracer->sigstop = SIGSTOP_IGNORED;
                PTRACER.waits_in = WAITS_IN_PROOT;
            }
        }
        if (tracee->seccomp == ENABLED)
            tracee->seccomp = DISABLING;
        return 0;
    }

    // PTRACE_ATTACH
    if (request == PTRACE_ATTACH) {
        ptracer = tracee;
        ptracee = get_tracee(ptracer, pid, false);
        if (UNLIKELY(!ptracee))
            return -ESRCH;
        if (UNLIKELY(PTRACEE.ptracer != NULL || ptracee == ptracer))
            return -EPERM;
        attach_to_ptracer(ptracee, ptracer);
        kill(pid, SIGSTOP);
        return 0;
    }

    // 其他请求需要 ptracee 处于停止状态
    ptracer = tracee;
    ptracee = get_stopped_ptracee(ptracer, pid, false, __WALL);
    if (UNLIKELY(!ptracee)) {
        static bool warned = false;
        ptracee = get_tracee(tracee, pid, false);
        if (ptracee && ptracee->exe == NULL && !warned) {
            warned = true;
            note(ptracer, WARNING, INTERNAL, "ptrace request to an unexpected ptracee");
        }
        return -ESRCH;
    }
    if (UNLIKELY(PTRACEE.is_zombie || PTRACEE.ptracer != ptracer || pid == (word_t)-1))
        return -ESRCH;

    switch (request) {
    case PTRACE_SYSCALL:
        PTRACEE.ignore_syscalls = false;
        forced_signal = (int)data;
        status = 0;
        break;
    case PTRACE_CONT:
        PTRACEE.ignore_syscalls = true;
        forced_signal = (int)data;
        status = 0;
        break;
    case PTRACE_SINGLESTEP:
        ptracee->restart_how = PTRACE_SINGLESTEP;
        forced_signal = (int)data;
        status = 0;
        break;
    case PTRACE_SINGLEBLOCK:
        ptracee->restart_how = PTRACE_SINGLEBLOCK;
        forced_signal = (int)data;
        status = 0;
        break;
    case PTRACE_DETACH:
        detach_from_ptracer(ptracee);
        status = 0;
        break;
    case PTRACE_KILL:
        status = ptrace(request, pid, NULL, NULL);
        break;
    case PTRACE_SETOPTIONS:
        PTRACEE.options = data;
        return 0;
    case PTRACE_GETEVENTMSG:
        status = ptrace(request, pid, NULL, &result);
        if (UNLIKELY(status < 0)) return -errno;
        poke_word(ptracer, data, result);
        return errno ? -errno : 0;
    case PTRACE_PEEKUSER:
    case PTRACE_PEEKTEXT:
    case PTRACE_PEEKDATA:
        errno = 0;
        result = (word_t)ptrace(request, pid, address, NULL);
        if (UNLIKELY(errno != 0)) return -errno;
        poke_word(ptracer, data, result);
        return errno ? -errno : 0;
    case PTRACE_POKEUSER:
    case PTRACE_POKETEXT:
    case PTRACE_POKEDATA:
        status = ptrace(request, pid, address, data);
        return status < 0 ? -errno : 0;
    case PTRACE_GETSIGINFO: {
        siginfo_t siginfo;
        status = ptrace(request, pid, NULL, &siginfo);
        if (UNLIKELY(status < 0)) return -errno;
        status = write_data(ptracer, data, &siginfo, sizeof(siginfo));
        return status < 0 ? status : 0;
    }
    case PTRACE_SETSIGINFO: {
        siginfo_t siginfo;
        status = read_data(ptracer, &siginfo, data, sizeof(siginfo));
        if (UNLIKELY(status < 0)) return status;
        status = ptrace(request, pid, NULL, &siginfo);
        return status < 0 ? -errno : 0;
    }
    case PTRACE_GETREGS: {
        struct user_regs_struct regs;
        status = ptrace(request, pid, NULL, &regs);
        if (UNLIKELY(status < 0)) return -errno;
        status = write_data(ptracer, data, &regs, sizeof(regs));
        return status < 0 ? status : 0;
    }
    case PTRACE_SETREGS: {
        struct user_regs_struct regs;
        status = read_data(ptracer, &regs, data, sizeof(regs));
        if (UNLIKELY(status < 0)) return status;
        status = ptrace(request, pid, NULL, &regs);
        return status < 0 ? -errno : 0;
    }
    case PTRACE_GETFPREGS: {
        struct user_fpregs_struct fpregs;
        status = ptrace(request, pid, NULL, &fpregs);
        if (UNLIKELY(status < 0)) return -errno;
        status = write_data(ptracer, data, &fpregs, sizeof(fpregs));
        return status < 0 ? status : 0;
    }
    case PTRACE_SETFPREGS: {
        struct user_fpregs_struct fpregs;
        status = read_data(ptracer, &fpregs, data, sizeof(fpregs));
        if (UNLIKELY(status < 0)) return status;
        status = ptrace(request, pid, NULL, &fpregs);
        return status < 0 ? -errno : 0;
    }
    case PTRACE_GETREGSET: {
        struct iovec local;
        word_t base = peek_word(ptracer, data);
        if (UNLIKELY(errno != 0)) return -errno;
        word_t len = peek_word(ptracer, data + sizeof_word(ptracer));
        if (UNLIKELY(errno != 0)) return -errno;
        local.iov_len = len;
        local.iov_base = talloc_zero_size(ptracer->ctx, len);
        if (UNLIKELY(!local.iov_base)) return -ENOMEM;
        status = ptrace(PTRACE_GETREGSET, pid, address, &local);
        if (UNLIKELY(status < 0)) return status;
        len = MIN(len, local.iov_len);
        status = writev_data(ptracer, base, &local, 1);
        if (UNLIKELY(status < 0)) return status;
        poke_word(ptracer, data + sizeof_word(ptracer), len);
        return errno ? -errno : 0;
    }
    case PTRACE_SETREGSET: {
        struct iovec local;
        word_t base = peek_word(ptracer, data);
        if (UNLIKELY(errno != 0)) return -errno;
        word_t len = peek_word(ptracer, data + sizeof_word(ptracer));
        if (UNLIKELY(errno != 0)) return -errno;
        local.iov_len = len;
        local.iov_base = talloc_zero_size(ptracer->ctx, len);
        if (UNLIKELY(!local.iov_base)) return -ENOMEM;
        status = read_data(ptracer, local.iov_base, base, len);
        if (UNLIKELY(status < 0)) return status;
        status = ptrace(PTRACE_SETREGSET, pid, address, &local);
        return status < 0 ? -errno : 0;
    }
    case PTRACE_SET_SYSCALL:
        status = ptrace(request, pid, address, data);
        return status < 0 ? -errno : 0;
    default:
        static bool warned = false;
        if (!warned) {
            note(ptracer, WARNING, INTERNAL, "ptrace request '%s' not supported", stringify_ptrace(request));
            warned = true;
        }
        return -ENOTSUP;
    }

    // 恢复 tracee 执行
    signal = PTRACEE.event4.proot.pending
        ? handle_tracee_event(ptracee, PTRACEE.event4.proot.value)
        : PTRACEE.event4.proot.value;
    if (forced_signal != -1)
        signal = forced_signal;
    (void)restart_tracee(ptracee, signal);
    return status;
}