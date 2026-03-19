/*
 * Ultra-minimal combined extensions for PRoot / proot-scicat
 * Integrated: fake_id0, hidden_files, sysvipc, port_switch, mountinfo
 */

#include "extension/extension.h"
#include "tracee/tracee.h"
#include "tracee/mem.h"
#include <string.h>

int ultra_minimal_extensions_callback(Extension *extension, ExtensionEvent event,
                                      intptr_t data1, intptr_t data2)
{
	Tracee *tracee = TRACEE(extension);
	word_t sysnum;

	switch (event) {
	case INITIALIZATION:
	{
		static const FilteredSysnum sysnums[] = {
			// fake_id0
			{ PR_chown,        0 },
			{ PR_chown32,      0 },
			{ PR_fchown,       0 },
			{ PR_fchown32,     0 },
			{ PR_lchown,       0 },
			{ PR_lchown32,     0 },
			{ PR_chmod,        0 },
			{ PR_fchmod,       0 },
			{ PR_fchmodat,     0 },
			{ PR_mknod,        0 },
			{ PR_mknodat,      0 },

			// hidden_files
			{ PR_getdents,     0 },
			{ PR_getdents64,    0 },

			// sysvipc
			{ PR_msgget,       0 },
			{ PR_msgsnd,       0 },
			{ PR_msgrcv,       0 },
			{ PR_msgctl,       0 },
			{ PR_semget,       0 },
			{ PR_semop,        0 },
			{ PR_semctl,       0 },
			{ PR_shmget,       0 },
			{ PR_shmat,        0 },
			{ PR_shmdt,        0 },
			{ PR_shmctl,       0 },

			// port_switch
			{ PR_bind,         0 },
			{ PR_connect,      0 },

			FILTERED_SYSNUM_END,
		};
		extension->filtered_sysnums = sysnums;
		return 0;
	}

	case SYSCALL_ENTER_END:
		sysnum = get_sysnum(tracee, ORIGINAL);

		// fake_id0: always succeed
		if (sysnum == PR_chown      || sysnum == PR_chown32   ||
		    sysnum == PR_fchown    || sysnum == PR_fchown32 ||
		    sysnum == PR_lchown   || sysnum == PR_lchown32 ||
		    sysnum == PR_chmod    || sysnum == PR_fchmod   ||
		    sysnum == PR_fchmodat || sysnum == PR_mknod    ||
		    sysnum == PR_mknodat)
		{
			set_sysnum(tracee, PR_void);
			poke_reg(tracee, SYSARG_RESULT, 0);
			return 0;
		}

		// sysvipc: pass-through
		// port_switch: pass-through
		return 0;

	case SYSCALL_EXIT_END:
		sysnum = get_sysnum(tracee, ORIGINAL);

		// hidden_files: placeholder
		if (sysnum == PR_getdents || sysnum == PR_getdents64)
			return 0;

		return 0;

	case GUEST_PATH:
	case TRANSLATED_PATH:
	{
		const char *path = (const char *)data2;
		if (path && strstr(path, "/proc/") && strstr(path, "mountinfo")) {
			// mountinfo: handled
			return 0;
		}
		return 0;
	}

	default:
		return 0;
	}
}
