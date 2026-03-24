#ifndef CHAIN_H
#define CHAIN_H

#include "tracee/tracee.h"
#include "syscall/sysnum.h"
#include "arch.h"

extern int register_chained_syscall(Tracee *tracee, Sysnum sysnum,
			word_t sysarg_1, word_t sysarg_2, word_t sysarg_3,
			word_t sysarg_4, word_t sysarg_5, word_t sysarg_6);

extern void force_chain_final_result(Tracee *tracee, word_t forced_result);

extern int restart_original_syscall(Tracee *tracee);

extern void chain_next_syscall(Tracee *tracee);

extern int restart_current_syscall_as_chained(Tracee *tracee);


#endif /* CHAIN_H */
