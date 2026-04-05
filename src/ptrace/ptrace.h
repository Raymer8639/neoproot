#ifndef PTRACE_H
#define PTRACE_H

#include "tracee/tracee.h"

extern int translate_ptrace_enter(Tracee *tracee);
extern int translate_ptrace_exit(Tracee *tracee);
extern void attach_to_ptracer(Tracee *ptracee, Tracee *ptracer);
extern void detach_from_ptracer(Tracee *ptracee);

#define PTRACEE (ptracee->as_ptracee)
#define PTRACER (ptracer->as_ptracer)

#endif /* PTRACE_H */
