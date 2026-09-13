#ifndef SECCOMP_H
#define SECCOMP_H

#include "syscall/sysnum.h"
#include "tracee/tracee.h"
#include "attribute.h"
#include "arch.h"

typedef struct {
	Sysnum value;
	word_t flags;
} FilteredSysnum;

typedef struct {
	unsigned int value;
	size_t nb_abis;
	Abi abis[NB_MAX_ABIS];
} SeccompArch;

#define FILTERED_SYSNUM_END { PR_void, 0 }

#define FILTER_SYSEXIT  0x1

/* --stat-shim: sentinel bit the preloaded shim ORs into the flags argument of
 * newfstatat/fstatat64/statx when it needs the tracer to resolve a result that
 * involves link2symlink/fake_id0 state it cannot reproduce in-process.  The BPF
 * filter routes only calls carrying this bit to USER_NOTIF; all other stat
 * calls made by the shim stay un-traced.  Must match stat-shim/shim.c
 * (NEOPROOT_STAT_SHIM_FLAG). */
#define NEOPROOT_STAT_SHIM_FLAG 0x40000000u

extern int enable_syscall_filtering(const Tracee *tracee);
/* Implemented in seccomp_notify.c. 0 if NEW_LISTENER+USER_NOTIF can be
 * installed; -errno otherwise. Uses a throwaway child so the tracer is
 * not filtered. */
extern int probe_seccomp_user_notif(void);
/* Blocking RECV + emulate + SEND. Runs on the dedicated RECV thread.
 * Never CONTINUE. Serializes with event_loop via seccomp_user_notif_lock. */
extern int handle_seccomp_user_notif(int listener_fd);
extern void seccomp_user_notif_lock(void);
extern void seccomp_user_notif_unlock(void);

#endif /* SECCOMP_H */
