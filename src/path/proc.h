#ifndef PROC_H
#define PROC_H

#include <limits.h>

#include "tracee/tracee.h"
#include "path/path.h"

/* Action to do after a call to readlink_proc().  */
typedef enum {
	DEFAULT,           /* Nothing special to do, treat it as a regular link.  */
	CANONICALIZE,      /* The symlink was dereferenced, now canonicalize it.  */
	DONT_CANONICALIZE, /* The symlink shouldn't be dereferenced nor canonicalized.  */
} Action;


extern Action readlink_proc(const Tracee *tracee, char result[PATH_MAX], const char path[PATH_MAX],
			const char component[NAME_MAX],	Comparison comparison);

extern ssize_t readlink_proc2(const Tracee *tracee, char result[PATH_MAX], const char path[PATH_MAX]);

#endif /* PROC_H */
