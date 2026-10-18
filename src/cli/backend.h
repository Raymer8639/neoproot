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

/*
 * What the -r/--rootfs argument names.
 *
 * PRoot translates guest paths to host paths, so it can only run a directory;
 * an ext4 image is a block device without a host path and only the UML backend
 * can boot it.  The dispatcher looks at this before choosing a backend,
 * because --backend=auto must not hand an image to PRoot.
 */
enum neoproot_rootfs_kind {
    NEOPROOT_ROOTFS_NONE = 0,
    NEOPROOT_ROOTFS_DIRECTORY,
    NEOPROOT_ROOTFS_IMAGE,
};

/* The kind of -r/--rootfs, or NONE when it was not given or cannot be read. */
enum neoproot_rootfs_kind neoproot_rootfs_kind(int argc, char *const argv[],
                                               int command_index);

/* Whether --cow-file was given (it only means anything with an image). */
bool neoproot_has_cow_file(int argc, char *const argv[], int command_index);

#endif
