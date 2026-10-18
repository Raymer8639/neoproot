#ifndef NEOPROOT_AUTO_BACKEND_H
#define NEOPROOT_AUTO_BACKEND_H

#include <stdbool.h>
#include <stddef.h>

#include "cli/backend.h"

/*
 * The capability-aware half of --backend=auto.
 *
 * Kept out of neoproot.c so it can be exercised without a kernel, a rootfs or
 * ptrace: tests/test-auto-backend.c links this file directly and checks both
 * the decision and the exact sentence neoproot prints about it.
 */

/* The command the caller asked for, with simple wrappers peeled off. */
const char *neoproot_auto_guest_command(int argc, char *const argv[],
                                        int command_index);

/* Whether a command is in the list; a NULL list means the default set. */
bool neoproot_auto_command_needs_kernel(const char *command,
                                        const char *list);

/* The list in force: option, then environment, then the default set. */
const char *neoproot_auto_effective_list(const char *list_option);

/*
 * Decide the backend for --backend=auto.
 *
 * Returns 1 for the UML backend and 0 for the default one, and writes the
 * sentence to report on stderr into *message* (without a trailing newline).
 */
int neoproot_auto_select(int argc, char *const argv[], int command_index,
                         const char *list_option, bool um_configured,
                         enum neoproot_rootfs_kind rootfs_kind,
                         char *message, size_t message_size);

#endif
