#ifndef LDSO_H
#define LDSO_H

#include <linux/limits.h>
#include <stdbool.h>

#include "execve/aoxp.h"
#include "execve/elf.h"

extern int ldso_env_passthru(const Tracee *tracee, ArrayOfXPointers *envp, ArrayOfXPointers *argv,
			const char *define, const char *undefine, size_t offset);

extern int rebuild_host_ldso_paths(Tracee *tracee, const char t_program[PATH_MAX],
				ArrayOfXPointers *envp);

extern int compare_xpointee_env(ArrayOfXPointers *envp, size_t index, const char *name);

extern bool is_env_name(const char *variable, const char *name);

#endif /* LDSO_H */
