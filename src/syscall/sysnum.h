#ifndef SYSNUM_H
#define SYSNUM_H

#include <stdbool.h>

#include "tracee/tracee.h"
#include "tracee/abi.h"
#include "tracee/reg.h"

#define SYSNUM(item) PR_ ## item,
typedef enum {
	PR_void = 0,
	#include "syscall/sysnums.list"
	PR_NB_SYSNUM
} Sysnum;
#undef SYSNUM

extern Sysnum get_sysnum(const Tracee *tracee, RegVersion version);
extern void set_sysnum(Tracee *tracee, Sysnum sysnum);
extern word_t detranslate_sysnum(Abi abi, Sysnum sysnum);
extern const char *stringify_sysnum(Sysnum sysnum);

#endif /* SYSNUM_H */
