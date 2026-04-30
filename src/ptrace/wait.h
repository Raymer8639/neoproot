#ifndef PTRACE_WAIT_H
#define PTRACE_WAIT_H

#include <sys/wait.h> /* for __WALL */

#include "tracee/tracee.h"

extern int translate_wait_enter(Tracee *ptracer);
extern int translate_wait_exit(Tracee *ptracer);
extern bool handle_ptracee_event(Tracee *ptracee, int wait_status);

/* __WCLONE: Wait for "clone" children only.  If omitted then wait for
 * "non-clone" children only.  (A "clone" child is one which delivers
 * no signal, or a signal other than SIGCHLD to its parent upon
 * termination.)  This option is ignored if __WALL is also specified.
 *
 * __WALL: Wait for all children, regardless of type ("clone" or
 * "non-clone").
 *
 * -- wait(2) man-page
 */
#define EXPECTED_WAIT_CLONE(wait_options, tracee)		\
	((((wait_options) & __WALL) != 0)			\
      || ((((wait_options) & __WCLONE) != 0) && (tracee)->clone) \
      || ((((wait_options) & __WCLONE) == 0) && !(tracee)->clone))

#endif /* PTRACE_WAIT_H */
