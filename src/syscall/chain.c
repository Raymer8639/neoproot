#include <talloc.h>
#include <sys/queue.h>
#include <errno.h>
#include <assert.h>

#include "cli/note.h"
#include "syscall/chain.h"
#include "syscall/sysnum.h"
#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "arch.h"

#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define ALWAYS_INLINE __attribute__((always_inline, flatten))

struct chained_syscall {
    Sysnum sysnum;
    word_t sysargs[6];
    STAILQ_ENTRY(chained_syscall) link;
};

STAILQ_HEAD(chained_syscalls, chained_syscall);

static struct chained_syscalls g_syscall_pool = STAILQ_HEAD_INITIALIZER(g_syscall_pool);

static ALWAYS_INLINE struct chained_syscall *get_from_pool(void) {
    if (LIKELY(!STAILQ_EMPTY(&g_syscall_pool))) {
        struct chained_syscall *syscall = STAILQ_FIRST(&g_syscall_pool);
        STAILQ_REMOVE_HEAD(&g_syscall_pool, link);
        return syscall;
    }
    return NULL;
}

static ALWAYS_INLINE void return_to_pool(struct chained_syscall *syscall) {
    if (LIKELY(syscall != NULL))
        STAILQ_INSERT_TAIL(&g_syscall_pool, syscall, link);
}

static int register_chained_syscall_internal(Tracee *restrict tracee, Sysnum sysnum,
                                             word_t sysarg_1, word_t sysarg_2,
                                             word_t sysarg_3, word_t sysarg_4,
                                             word_t sysarg_5, word_t sysarg_6,
                                             bool at_front) {
    struct chained_syscall *syscall;

    if (UNLIKELY(tracee->chain.syscalls == NULL)) {
        tracee->chain.syscalls = talloc_zero(tracee, struct chained_syscalls);
        if (UNLIKELY(tracee->chain.syscalls == NULL))
            return -ENOMEM;
        STAILQ_INIT(tracee->chain.syscalls);
    }

    syscall = get_from_pool();
    if (UNLIKELY(syscall == NULL)) {
        syscall = talloc_zero(tracee, struct chained_syscall);
        if (UNLIKELY(syscall == NULL))
            return -ENOMEM;
    }

    syscall->sysnum     = sysnum;
    syscall->sysargs[0] = sysarg_1;
    syscall->sysargs[1] = sysarg_2;
    syscall->sysargs[2] = sysarg_3;
    syscall->sysargs[3] = sysarg_4;
    syscall->sysargs[4] = sysarg_5;
    syscall->sysargs[5] = sysarg_6;

    if (at_front)
        STAILQ_INSERT_HEAD(tracee->chain.syscalls, syscall, link);
    else
        STAILQ_INSERT_TAIL(tracee->chain.syscalls, syscall, link);

    return 0;
}

int register_chained_syscall(Tracee *restrict tracee, Sysnum sysnum,
                             word_t sysarg_1, word_t sysarg_2, word_t sysarg_3,
                             word_t sysarg_4, word_t sysarg_5, word_t sysarg_6) {
    return register_chained_syscall_internal(tracee, sysnum,
                                             sysarg_1, sysarg_2, sysarg_3,
                                             sysarg_4, sysarg_5, sysarg_6,
                                             false);
}

void chain_next_syscall(Tracee *restrict tracee) {
    struct chained_syscall *syscall;
    word_t instr_pointer;
    word_t sysnum;

    assert(tracee->chain.syscalls != NULL);

    if (UNLIKELY(STAILQ_EMPTY(tracee->chain.syscalls))) {
        TALLOC_FREE(tracee->chain.syscalls);
        if (tracee->chain.force_final_result)
            poke_reg(tracee, SYSARG_RESULT, tracee->chain.final_result);
        tracee->chain.force_final_result = false;
        tracee->chain.final_result = 0;
        VERBOSE(tracee, 2, "chain_next_syscall finish");
        return;
    }

    VERBOSE(tracee, 2, "chain_next_syscall continue");

    tracee->restore_original_regs = false;

    syscall = STAILQ_FIRST(tracee->chain.syscalls);
    STAILQ_REMOVE_HEAD(tracee->chain.syscalls, link);

    poke_reg(tracee, SYSARG_1, syscall->sysargs[0]);
    poke_reg(tracee, SYSARG_2, syscall->sysargs[1]);
    poke_reg(tracee, SYSARG_3, syscall->sysargs[2]);
    poke_reg(tracee, SYSARG_4, syscall->sysargs[3]);
    poke_reg(tracee, SYSARG_5, syscall->sysargs[4]);
    poke_reg(tracee, SYSARG_6, syscall->sysargs[5]);

    sysnum = detranslate_sysnum(get_abi(tracee), syscall->sysnum);
    poke_reg(tracee, SYSTRAP_NUM, sysnum);

    instr_pointer = peek_reg(tracee, CURRENT, INSTR_POINTER);
    poke_reg(tracee, INSTR_POINTER, instr_pointer - get_systrap_size(tracee));

    return_to_pool(syscall);

    tracee->restart_how = PTRACE_SYSCALL;
}

void force_chain_final_result(Tracee *restrict tracee, word_t forced_result) {
    tracee->chain.force_final_result = true;
    tracee->chain.final_result = forced_result;
}

int restart_original_syscall(Tracee *restrict tracee) {
    return register_chained_syscall(tracee,
                                    get_sysnum(tracee, ORIGINAL),
                                    peek_reg(tracee, ORIGINAL, SYSARG_1),
                                    peek_reg(tracee, ORIGINAL, SYSARG_2),
                                    peek_reg(tracee, ORIGINAL, SYSARG_3),
                                    peek_reg(tracee, ORIGINAL, SYSARG_4),
                                    peek_reg(tracee, ORIGINAL, SYSARG_5),
                                    peek_reg(tracee, ORIGINAL, SYSARG_6));
}

int restart_current_syscall_as_chained(Tracee *restrict tracee) {
    assert(tracee->chain.sysnum_workaround_state == SYSNUM_WORKAROUND_INACTIVE);
    tracee->chain.sysnum_workaround_state = SYSNUM_WORKAROUND_PROCESS_FAULTY_CALL;
    return register_chained_syscall_internal(tracee,
                                             get_sysnum(tracee, CURRENT),
                                             peek_reg(tracee, CURRENT, SYSARG_1),
                                             peek_reg(tracee, CURRENT, SYSARG_2),
                                             peek_reg(tracee, CURRENT, SYSARG_3),
                                             peek_reg(tracee, CURRENT, SYSARG_4),
                                             peek_reg(tracee, CURRENT, SYSARG_5),
                                             peek_reg(tracee, CURRENT, SYSARG_6),
                                             true);
}