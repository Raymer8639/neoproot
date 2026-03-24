#ifndef SYSCALL_H
#define SYSCALL_H

#include <limits.h>     /* PATH_MAX, */

#include "tracee/tracee.h"
#include "tracee/reg.h"

#ifdef __cplusplus
extern "C" {
#endif

extern int get_sysarg_path(const Tracee *tracee, char path[PATH_MAX], Reg reg);
extern int set_sysarg_path(Tracee *tracee, const char path[PATH_MAX], Reg reg);
extern int set_sysarg_data(Tracee *tracee, const void *tracer_ptr, word_t size, Reg reg);

extern void translate_syscall(Tracee *tracee);
extern int  translate_syscall_enter(Tracee *tracee);
extern void translate_syscall_exit(Tracee *tracee);

#ifdef __cplusplus
}
#endif

#endif /* SYSCALL_H */
