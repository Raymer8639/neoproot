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
/* Blocking ioctl(RECV) into a one-slot queue. Runs on the RECV thread. */
extern int recv_seccomp_user_notif(int listener_fd);
/* Main-thread complete: path translation + fake_id0 + L2S nlink + SEND.
 * Never CONTINUE. No-op if the queue is empty. */
extern int complete_seccomp_user_notif(int listener_fd);

#endif /* SECCOMP_H */
