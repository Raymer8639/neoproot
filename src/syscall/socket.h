#ifndef SOCKET_H
#define SOCKET_H

#include "arch.h" /* word_t */
#include "tracee/tracee.h"

int translate_socketcall_enter(Tracee *tracee, word_t *sock_addr, int size);
int translate_socketcall_exit(Tracee *tracee, word_t sock_addr, word_t size_addr, word_t max_size);

int translate_send_address(Tracee *tracee, word_t *address, int size);
int translate_sendmsg_enter(Tracee *tracee, word_t *address);
int translate_sendmmsg_enter(Tracee *tracee, word_t *address, word_t *vlen);
int translate_sendmmsg_exit(Tracee *tracee, word_t address, word_t copy, word_t count);

#endif /* SOCKET_H */
