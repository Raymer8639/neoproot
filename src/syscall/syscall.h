#ifndef SYSCALL_H
#define SYSCALL_H

#include <limits.h>     /* PATH_MAX, */

#include "tracee/tracee.h"
#include "tracee/reg.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * State passed along with the READLINK_PROC_FD event, that is, the
 * result of a readlink(2) against "/proc/@pid/fd/@fd".
 */
struct readlink_proc_fd_state {
	/* Process the descriptor belongs to.  */
	pid_t pid;

	/* Descriptor whose content was read.  */
	int fd;

	/* Host path the kernel reported, ie. the path of the file the
	 * descriptor refers to.  An extension may overwrite it with
	 * another host path -- the buffer is PATH_MAX bytes long -- and
	 * set @substituted accordingly.  */
	char *host_path;

	/* Whether @host_path was replaced by an extension.  */
	bool substituted;
};

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
