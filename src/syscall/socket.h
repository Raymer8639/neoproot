#ifndef SOCKET_H
#define SOCKET_H

#include "arch.h" /* word_t */
#include "tracee/tracee.h"

int translate_socketcall_enter(Tracee *tracee, word_t *sock_addr, int size);
int translate_socketcall_exit(Tracee *tracee, word_t sock_addr, word_t size_addr, word_t max_size);

#endif /* SOCKET_H */
