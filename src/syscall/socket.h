#ifndef SOCKET_H
#define SOCKET_H

#include "arch.h" /* word_t */
#include "tracee/tracee.h"

int translate_socketcall_enter(Tracee *tracee, word_t *sock_addr, int size);
int translate_socketcall_exit(Tracee *tracee, word_t sock_addr, word_t size_addr, word_t max_size);

int translate_send_address(Tracee *tracee, word_t *address, int size);
int translate_sendmsg_enter(Tracee *tracee, word_t *address);
/* Production sendmmsg lowering: start returns 0 for the native fast path,
 * 1 after installing the first sendmsg (caller keeps pushed args), or -errno.
 * finish is called at the ORIGINAL sendmmsg exit, including kernel errors;
 * true means it handled the result.  chained_exit must be called only for
 * SYSCALL_CHAINED_EXIT, after extension notifications and before chain_next.
 * Pending state belongs to Tracee and survives tracee->ctx destruction.
 * process_vm_readv/writev support and permission are required; there is no
 * ptrace fallback, including when writev fails after a message was sent. */
int translate_sendmmsg_start(Tracee *tracee, word_t address, word_t vlen);
bool translate_sendmmsg_finish(Tracee *tracee);
void translate_sendmmsg_chained_exit(Tracee *tracee);

/* Legacy copy helpers, retained for callers testing address translation.
 * Do not use these to execute a translated batch: copying all headers loses
 * the kernel's ordering between sends and stores to the original msg_len. */
int translate_sendmmsg_enter(Tracee *tracee, word_t *address, word_t *vlen);
int translate_sendmmsg_exit(Tracee *tracee, word_t address, word_t copy, word_t count);

#endif /* SOCKET_H */
