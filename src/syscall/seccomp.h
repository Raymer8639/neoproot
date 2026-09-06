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

extern int enable_syscall_filtering(const Tracee *tracee);
/* 0 if NEW_LISTENER+USER_NOTIF can be installed; -errno otherwise.
 * Uses a throwaway child so the tracer is not filtered. */
extern int probe_seccomp_user_notif(void);
/* Drain one USER_NOTIF. Plumbing: newfstatat/fstatat64 get a magic
 * struct stat or identity-rootfs host fstatat (no path translation).
 * Guest memory via process_vm_*; never CONTINUE. Safe from a RECV thread. */
extern int handle_seccomp_user_notif(int listener_fd);

/* Isolation-test plumbing: this relative name gets a magic st_size. */
#define NEOPROOT_NOTIFY_PLUMBING_SIZE 0x4e4f5449LL
#define NEOPROOT_NOTIFY_SENTINEL "neoproot-notify-sentinel"

#endif /* SECCOMP_H */
