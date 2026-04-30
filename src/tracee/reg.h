#ifndef TRACEE_REG_H
#define TRACEE_REG_H

#include "tracee/tracee.h"
#include "arch.h"

typedef enum {
	SYSARG_NUM = 0,
	SYSARG_1,
	SYSARG_2,
	SYSARG_3,
	SYSARG_4,
	SYSARG_5,
	SYSARG_6,
	SYSARG_RESULT,
	STACK_POINTER,
	INSTR_POINTER,
	RTLD_FINI,
	STATE_FLAGS,
	USERARG_1,
} Reg;

extern int fetch_regs(Tracee *tracee);
extern int push_specific_regs(Tracee *tracee, bool including_sysnum);
extern int push_regs(Tracee *tracee);

extern word_t peek_reg(const Tracee *tracee, RegVersion version, Reg reg);
extern void poke_reg(Tracee *tracee, Reg reg, word_t value);

extern void print_current_regs(Tracee *tracee, int verbose_level, const char *message);
extern void save_current_regs(Tracee *tracee, RegVersion version);

extern word_t get_systrap_size(Tracee *tracee);

#endif /* TRACEE_REG_H */
