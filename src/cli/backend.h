#ifndef NEOPROOT_BACKEND_H
#define NEOPROOT_BACKEND_H

#include <stdbool.h>

/*
 * neoproot's own command line, as it is handed to a backend.
 *
 * These are the two things the dispatcher does before running anything: it
 * parses its own options (and consumes them), and it decides where the guest
 * command begins.  tests/test-backend-argv.c drives both directly.
 */

enum backend_mode {
    BACKEND_DEFAULT,
    BACKEND_FAST,
    BACKEND_UM,
    BACKEND_AUTO,
};

/*
 * Strip neoproot's options from argv, leaving the vector a backend receives.
 *
 * On success *result is a malloc'd vector of *result_argc entries, *mode is the
 * requested backend, *command_index is the position of the guest command (0
 * when there is none), and *auto_commands points at the --auto-um-commands
 * value, or NULL when the option was not given.  Returns -1 after printing an
 * error, in which case nothing is allocated.
 */
int neoproot_prepare_backend_argv(int argc, char *const argv[],
                                  char ***result, int *result_argc,
                                  enum backend_mode *mode,
                                  int *command_index,
                                  const char **auto_commands);

/* Whether a kernel, a stub and a rootfs were all configured. */
bool neoproot_um_backend_is_configured(int argc, char *const argv[]);

#endif
