#include "cli/backend.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * neoproot's own command line, as the backends see it.
 *
 * Kept beside the auto policy and out of main() because it is exactly the part
 * a test can check without a kernel, a rootfs or ptrace: which options neoproot
 * consumes, what the forwarded vector looks like, and where the guest command
 * starts.  Before this existed, a change here could only be noticed by running
 * a real container.
 */

static bool option_takes_separate_value(const char *argument)
{
    static const char *const options[] = {
        "-r", "--rootfs", "--cow-file", "-b", "--bind", "-m", "--mount",
        "-w", "--pwd", "--cwd", "-k", "--kernel-release",
        "-i", "--change-id", "-v", "--verbose", "-R", "-S", NULL
    };
    size_t index;

    for (index = 0; options[index] != NULL; index++)
        if (strcmp(argument, options[index]) == 0)
            return true;
    return false;
}

/*
 * Whether the UML backend's prerequisites have actually been configured.
 *
 * Both a kernel and a stub, given either as options or through the environment
 * the supervisor also reads, plus a rootfs for them to boot.  Nothing is
 * probed: the point is to distinguish "the caller set this up" from "something
 * with that name happens to exist".
 */
bool neoproot_um_backend_is_configured(int argc, char *const argv[])
{
    bool kernel = false, stub = false, rootfs = false;
    const char *value;
    int index;

    /*
     * A variable that is set to the empty string is not configuration.  Testing
     * only for non-NULL made `NEOPROOT_UM_KERNEL= neoproot --backend=auto` pick
     * the UML backend and then fail with "set --kernel/--stub", which is the
     * auto selection getting it wrong rather than the backend.
     */
    const char *environment_kernel = getenv("NEOPROOT_UM_KERNEL");
    const char *environment_stub = getenv("NEOPROOT_UM_STUB");

    if (environment_kernel != NULL && environment_kernel[0] != '\0')
        kernel = true;
    if (environment_stub != NULL && environment_stub[0] != '\0')
        stub = true;

    for (index = 1; index < argc; index++) {
        value = argv[index];
        if (value == NULL || value[0] != '-')
            continue;
        if (strncmp(value, "--kernel=", 9) == 0)
            kernel = true;
        else if (strcmp(value, "--kernel") == 0)
            kernel = true;
        else if (strncmp(value, "--stub=", 7) == 0)
            stub = true;
        else if (strcmp(value, "--stub") == 0)
            stub = true;
        else if (strncmp(value, "--rootfs=", 9) == 0)
            rootfs = true;
        else if (strcmp(value, "--rootfs") == 0)
            rootfs = true;
        else if (strcmp(value, "-r") == 0)
            rootfs = true;
    }
    return kernel && stub && rootfs;
}

int neoproot_prepare_backend_argv(int argc, char *const argv[],
                                  char ***result, int *result_argc,
                                  enum backend_mode *mode, int *command_index,
                                  const char **auto_commands)
{
    char **filtered;
    int output_argc = 1;
    int index;
    bool command_started = false;
    bool backend_set = false;
    bool auto_commands_set = false;

    *mode = BACKEND_DEFAULT;
    *command_index = 0;
    *auto_commands = NULL;
    filtered = calloc((size_t)argc + 2, sizeof(*filtered));
    if (filtered == NULL)
        return -1;
    filtered[0] = argv[0];
    for (index = 1; index < argc; index++) {
        const char *value = NULL;

        if (command_started) {
            filtered[output_argc++] = argv[index];
            continue;
        }
        /*
         * The separator belongs to neoproot's own CLI and is not part of the
         * vector any backend should receive.  It used to be copied through
         * unconditionally, which meant `neoproot -r /rootfs -- /bin/sh` died
         * with "unknown option '--'" on every backend except UM -- the one
         * backend whose syntax does want it.  The UM dispatcher puts it back.
         */
        if (strcmp(argv[index], "--") == 0) {
            command_started = true;
            *command_index = output_argc;
            continue;
        }
        if (argv[index][0] != '-') {
            command_started = true;
            *command_index = output_argc;
            filtered[output_argc++] = argv[index];
            continue;
        }
        if (strncmp(argv[index], "--backend=", 10) == 0) {
            value = argv[index] + 10;
        } else if (strcmp(argv[index], "--backend") == 0) {
            if (++index >= argc) {
                fprintf(stderr, "neoproot: --backend requires a value\n");
                free(filtered);
                return -1;
            }
            value = argv[index];
        } else if (strncmp(argv[index], "--auto-um-commands=", 19) == 0) {
            /*
             * neoproot's own option: it decides the auto policy, and no
             * backend knows it, so it never reaches the forwarded vector.
             * An empty value means "the default set", which is also what
             * omitting the option means; "none" is the way to say "never
             * choose a backend by command".
             */
            if (auto_commands_set) {
                fprintf(stderr,
                        "neoproot: duplicate --auto-um-commands option\n");
                free(filtered);
                return -1;
            }
            auto_commands_set = true;
            *auto_commands = argv[index] + 19;
            continue;
        } else if (strcmp(argv[index], "--auto-um-commands") == 0) {
            if (auto_commands_set) {
                fprintf(stderr,
                        "neoproot: duplicate --auto-um-commands option\n");
                free(filtered);
                return -1;
            }
            if (++index >= argc) {
                fprintf(stderr,
                        "neoproot: --auto-um-commands requires a value\n");
                free(filtered);
                return -1;
            }
            auto_commands_set = true;
            *auto_commands = argv[index];
            continue;
        } else {
            output_argc++;
            filtered[output_argc - 1] = argv[index];
            if (option_takes_separate_value(argv[index]) && index + 1 < argc)
                filtered[output_argc++] = argv[++index];
            continue;
        }
        if (backend_set) {
            fprintf(stderr, "neoproot: duplicate --backend option\n");
            free(filtered);
            return -1;
        }
        backend_set = true;
        if (strcmp(value, "fast") == 0)
            *mode = BACKEND_FAST;
        else if (strcmp(value, "um") == 0)
            *mode = BACKEND_UM;
        else if (strcmp(value, "auto") == 0)
            *mode = BACKEND_AUTO;
        else {
            fprintf(stderr, "neoproot: unknown backend '%s'\n", value);
            free(filtered);
            return -1;
        }
    }
    filtered[output_argc] = NULL;
    *result = filtered;
    *result_argc = output_argc;
    return 0;
}
