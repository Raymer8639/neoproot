#ifndef TRACEE_EVENT_H
#define TRACEE_EVENT_H

#include <stdbool.h>

#include "tracee/tracee.h"

extern int launch_process(Tracee *tracee, char *const argv[]);
extern int event_loop();
extern int handle_tracee_event(Tracee *tracee, int tracee_status);
extern bool restart_tracee(Tracee *tracee, int signal);
extern bool seccomp_event_happens_after_enter_sigtrap();

#endif /* TRACEE_EVENT_H */
