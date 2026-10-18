/*
 * The capability-aware half of --backend=auto, checked without a kernel.
 *
 * The decision is a pure function of the command vector, the configured list
 * and whether the UML prerequisites are set up, so it can be exercised directly
 * -- including the sentences neoproot prints, which are the only thing a user
 * sees when auto picks a backend.  tests/test-auto-commands.sh covers the
 * dispatch end to end; this covers the policy, and runs anywhere.
 */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cli/auto_backend.h"
#include "cli/backend.h"

static int failures;

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); \
        failures++; \
    } \
} while (0)

static void check_command_at(const char *expected, int argc,
                             char *const argv[], int start, int line)
{
    const char *actual = neoproot_auto_guest_command(argc, argv, start);

    if (expected == NULL ? actual != NULL
                         : (actual == NULL || strcmp(actual, expected) != 0)) {
        fprintf(stderr, "FAIL %d: expected command %s, got %s\n", line,
                expected != NULL ? expected : "(none)",
                actual != NULL ? actual : "(none)");
        failures++;
    }
}

#define COMMAND(expected, ...) do { \
    char *vector[] = { __VA_ARGS__ }; \
    check_command_at(expected, (int)(sizeof(vector) / sizeof(vector[0])), \
                     vector, 1, __LINE__); \
} while (0)

static void check_needs_kernel(bool expected, const char *command,
                               const char *list)
{
    bool actual = neoproot_auto_command_needs_kernel(command, list);

    if (actual != expected) {
        fprintf(stderr, "FAIL: command %s with list %s: expected %d, got %d\n",
                command != NULL ? command : "(none)",
                list != NULL ? list : "(default)", expected, actual);
        failures++;
    }
}

static void check_selection_rootfs(int expected_backend,
                                  const char *expected_message, int argc,
                                  char *const argv[], int start,
                                  const char *list, bool configured,
                                  enum neoproot_rootfs_kind rootfs_kind)
{
    char message[512];
    int backend = neoproot_auto_select(argc, argv, start, list, configured,
                                       rootfs_kind,
                                       message, sizeof(message));

    if (backend != expected_backend) {
        fprintf(stderr, "FAIL: expected backend %d, got %d\n",
                expected_backend, backend);
        failures++;
    }
    if (strcmp(message, expected_message) != 0) {
        fprintf(stderr, "FAIL: message was \"%s\"\n", message);
        fprintf(stderr, "      expected     \"%s\"\n", expected_message);
        failures++;
    }
}

/* The common case: a directory rootfs, which both backends can use. */
static void check_selection(int expected_backend, const char *expected_message,
                            int argc, char *const argv[], int start,
                            const char *list, bool configured)
{
    check_selection_rootfs(expected_backend, expected_message, argc, argv,
                           start, list, configured,
                           NEOPROOT_ROOTFS_DIRECTORY);
}


/*
 * The dispatcher half: neoproot's own options are consumed, the vector a
 * backend receives is what is left, and the guest command starts where the
 * parser says it does.  --auto-um-commands is one of those options, so this is
 * also where "the option never reaches a backend" is checked.
 */
static void check_forwarded(const char *name, int argc, char *const argv[],
                            int expected_argc, const char *const *expected,
                            enum backend_mode expected_mode,
                            int expected_command_index,
                            const char *expected_auto_commands)
{
    char **forwarded = NULL;
    int forwarded_argc = 0;
    int command_index = -1;
    const char *auto_commands = NULL;
    enum backend_mode mode = BACKEND_DEFAULT;
    int index;
    int status = neoproot_prepare_backend_argv(argc, argv, &forwarded,
                                               &forwarded_argc, &mode,
                                               &command_index,
                                               &auto_commands);
    if (status < 0) {
        fprintf(stderr, "FAIL: %s: parse failed\n", name);
        failures++;
        return;
    }
    if (mode != expected_mode) {
        fprintf(stderr, "FAIL: %s: mode %d, expected %d\n", name, mode,
                expected_mode);
        failures++;
    }
    if (forwarded_argc != expected_argc) {
        fprintf(stderr, "FAIL: %s: %d forwarded arguments, expected %d\n",
                name, forwarded_argc, expected_argc);
        failures++;
    }
    for (index = 0; index < expected_argc && index < forwarded_argc; index++)
        if (strcmp(forwarded[index], expected[index]) != 0) {
            fprintf(stderr, "FAIL: %s: forwarded[%d] is '%s', expected '%s'\n",
                    name, index, forwarded[index], expected[index]);
            failures++;
        }
    if (command_index != expected_command_index) {
        fprintf(stderr, "FAIL: %s: command index %d, expected %d\n", name,
                command_index, expected_command_index);
        failures++;
    }
    if (expected_auto_commands == NULL ? auto_commands != NULL
            : (auto_commands == NULL ||
               strcmp(auto_commands, expected_auto_commands) != 0)) {
        fprintf(stderr, "FAIL: %s: list is %s\n", name,
                auto_commands != NULL ? auto_commands : "(default)");
        failures++;
    }
    free(forwarded);
}

/*
 * A convenience wrapper: the call site writes the whole command line, and the
 * expected forwarded vector, which is the same line minus neoproot's own
 * options and minus the separator.
 */
#define FORWARDED(name, mode, index, list, expected, ...) do { \
    char *vector[] = { __VA_ARGS__ }; \
    check_forwarded(name, (int)(sizeof(vector) / sizeof(vector[0])), vector, \
                    (int)(sizeof(expected) / sizeof(expected[0])) - 1, \
                    expected, mode, index, list); \
} while (0)

static void check_dispatcher(void)
{
    static const char *const no_options[] = {
        "neoproot", "-r", "/rootfs", "docker", NULL
    };
    static const char *const with_mount[] = {
        "neoproot", "-r", "/rootfs", "-w", "/tmp", "docker", NULL
    };

    /*
     * --auto-um-commands is neoproot's, and only neoproot's: it is not in the
     * vector a backend is handed.  The backend option goes the same way, and
     * the separator is consumed -- the UML dispatcher puts it back itself.
     */
    FORWARDED("--auto-um-commands is consumed", BACKEND_AUTO, 3, "none",
              no_options,
              "neoproot", "--backend=auto", "--auto-um-commands=none",
              "-r", "/rootfs", "--", "docker");
    FORWARDED("--auto-um-commands with a separate value", BACKEND_AUTO, 3,
              "a,b", no_options,
              "neoproot", "--backend=auto", "--auto-um-commands",
              "a,b", "-r", "/rootfs", "--", "docker");
    FORWARDED("an empty list is an empty string", BACKEND_AUTO, 3, "",
              no_options,
              "neoproot", "--backend=auto", "--auto-um-commands=",
              "-r", "/rootfs", "--", "docker");
    FORWARDED("no option means no list", BACKEND_AUTO, 3, NULL,
              no_options,
              "neoproot", "--backend=auto", "-r", "/rootfs", "--", "docker");
    FORWARDED("the separator is consumed", BACKEND_UM, 3, NULL,
              no_options,
              "neoproot", "--backend=um", "-r", "/rootfs", "--", "docker");
    FORWARDED("without a separator", BACKEND_AUTO, 3, NULL,
              no_options,
              "neoproot", "--backend=auto", "-r", "/rootfs", "docker");
    /* Options that take a separate value stay paired with it. */
    FORWARDED("an option value is not a command", BACKEND_DEFAULT, 5, NULL,
              with_mount,
              "neoproot", "-r", "/rootfs", "-w", "/tmp", "docker");
    FORWARDED("the backend is not forwarded", BACKEND_FAST, 3, NULL,
              no_options,
              "neoproot", "--backend", "fast", "-r", "/rootfs", "--",
              "docker");
}

int main(void)
{
    check_dispatcher();

    /* --- the guest command, and the wrappers that only start it ---------- */
    COMMAND("docker", "neoproot", "docker");
    {
        char *vector[] = { "neoproot", "-r", "/rootfs", "mount" };
        check_command_at("mount", 4, vector, 3, __LINE__);
    }
    /* The basename is what matters: an absolute path is the same command. */
    {
        char *vector[] = { "neoproot", "-r", "/rootfs", "--", "/usr/bin/docker" };
        check_command_at("docker", 5, vector, 4, __LINE__);
    }
    COMMAND("docker", "neoproot", "env", "FOO=1", "docker");
    COMMAND("docker", "neoproot", "env", "-u", "FOO", "docker");
    COMMAND("docker", "neoproot", "env", "-i", "HOME=/root", "docker");
    COMMAND("docker", "neoproot", "sudo", "-u", "root", "docker");
    COMMAND("docker", "neoproot", "command", "-p", "docker");
    COMMAND("docker", "neoproot", "exec", "-a", "name", "docker");
    COMMAND("docker", "neoproot", "nohup", "docker");
    COMMAND("docker", "neoproot", "time", "-o", "/tmp/out", "docker");
    COMMAND("docker", "neoproot", "stdbuf", "-oL", "docker");
    COMMAND("docker", "neoproot", "env", "sudo", "docker");
    COMMAND("docker", "neoproot", "env", "--", "docker");
    /* A shell string is one command: auto does not parse guest shell code. */
    COMMAND("sh", "neoproot", "sh", "-c", "docker run hello");
    /* Nothing left to run, or nothing to look at. */
    COMMAND(NULL, "neoproot", "env", "FOO=1");
    COMMAND(NULL, "neoproot", "env");
    COMMAND(NULL, "neoproot");
    {
        char *vector[] = { "neoproot", "--backend=auto", "-r", "/rootfs" };
        check_command_at(NULL, 4, vector, 0, __LINE__);
    }

    /* --- the default set ------------------------------------------------- */
    {
        static const char *const documented[] = {
            "docker", "dockerd", "podman", "podman-remote", "nerdctl",
            "containerd", "ctr", "runc", "crun", "systemd-nspawn",
            "machinectl", "mount", "umount", "losetup", "swapon", "swapoff",
            "unshare", "nsenter", "ip", "iptables", "nft", "bpftool", NULL
        };
        size_t index;

        for (index = 0; documented[index] != NULL; index++)
            check_needs_kernel(true, documented[index], NULL);
        check_needs_kernel(false, "true", NULL);
        check_needs_kernel(false, "sh", NULL);
        check_needs_kernel(false, "bash", NULL);
        check_needs_kernel(false, NULL, NULL);
    }

    /* --- an explicit list replaces the default set ----------------------- */
    check_needs_kernel(true, "mycmd", "mycmd");
    check_needs_kernel(true, "mycmd", "other,mycmd , third");
    check_needs_kernel(false, "docker", "mycmd");
    check_needs_kernel(false, "mycmd", "mycommand");
    check_needs_kernel(false, "docker", "none");
    check_needs_kernel(false, "docker", " none ");
    check_needs_kernel(false, "docker", "");
    /* “none” is special only as the whole list; elsewhere it is a name. */
    check_needs_kernel(true, "none", "none,mycmd");

    /* --- which list is in force ------------------------------------------ */
    unsetenv("NEOPROOT_UM_AUTO_COMMANDS");
    CHECK(neoproot_auto_effective_list(NULL) == NULL);
    CHECK(strcmp(neoproot_auto_effective_list("a,b"), "a,b") == 0);
    /* An empty option value is the default set, not an empty set. */
    CHECK(neoproot_auto_effective_list("") == NULL);
    setenv("NEOPROOT_UM_AUTO_COMMANDS", "from-environment", 1);
    CHECK(strcmp(neoproot_auto_effective_list(NULL), "from-environment") == 0);
    CHECK(strcmp(neoproot_auto_effective_list("from-option"),
                 "from-option") == 0);
    setenv("NEOPROOT_UM_AUTO_COMMANDS", "", 1);
    CHECK(neoproot_auto_effective_list(NULL) == NULL);
    unsetenv("NEOPROOT_UM_AUTO_COMMANDS");

    /* --- the decision, and the sentence that explains it ----------------- */
    {
        char *docker[] = { "neoproot", "--backend=auto", "-r", "/rootfs",
                           "--", "docker" };
        char *plain[] = { "neoproot", "--backend=auto", "-r", "/rootfs",
                          "--", "true" };

        check_selection(1,
                        "neoproot: --backend=auto selected the um backend "
                        "(command 'docker' needs a real kernel)",
                        6, docker, 5, NULL, true);
        check_selection(0,
                        "neoproot: --backend=auto selected the default backend",
                        6, plain, 5, NULL, true);
        /* The invariant: no configured kernel/stub/rootfs, no UML. */
        check_selection(0,
                        "neoproot: --backend=auto would use the um backend for "
                        "'docker', but no kernel/stub/rootfs is configured; "
                        "using the default backend",
                        6, docker, 5, NULL, false);
        check_selection(0,
                        "neoproot: --backend=auto selected the default backend",
                        6, plain, 5, NULL, false);
        check_selection(0,
                        "neoproot: --backend=auto selected the default backend",
                        6, docker, 5, "none", true);
        check_selection(0,
                        "neoproot: --backend=auto selected the default backend",
                        6, plain, 5, "none", true);
    }
    {
        char *custom[] = { "neoproot", "--backend=auto", "-r", "/rootfs",
                           "--", "mycmd" };

        check_selection(1,
                        "neoproot: --backend=auto selected the um backend "
                        "(command 'mycmd' needs a real kernel)",
                        6, custom, 5, "mycmd", true);
        check_selection(0,
                        "neoproot: --backend=auto selected the default backend",
                        6, custom, 5, "docker,mount", true);
    }
    /* A wrapped command is judged by the command it runs. */
    {
        char *wrapped[] = { "neoproot", "--backend=auto", "-r", "/rootfs",
                            "--", "env", "FOO=1", "docker" };

        check_selection(1,
                        "neoproot: --backend=auto selected the um backend "
                        "(command 'docker' needs a real kernel)",
                        8, wrapped, 5, NULL, true);
    }

    /* --- a filesystem image forces the UML backend ------------------------ */
    /*
     * PRoot needs a directory to translate guest paths into; an ext4 image has
     * no host path, so this is not a speed question and --auto-um-commands=none
     * must not turn it off.  The decision is made on the -r argument itself.
     */
    {
        char *plain[] = { "neoproot", "--backend=auto", "-r", "/rootfs.img",
                          "--", "true" };
        char *docker[] = { "neoproot", "--backend=auto", "-r", "/rootfs.img",
                           "--", "docker" };

        check_selection_rootfs(
            1,
            "neoproot: --backend=auto selected the um backend "
            "(the rootfs is a filesystem image, which only the um backend "
            "can use)",
            6, plain, 5, NULL, true, NEOPROOT_ROOTFS_IMAGE);
        check_selection_rootfs(
            1,
            "neoproot: --backend=auto selected the um backend "
            "(the rootfs is a filesystem image and command 'docker' needs a "
            "real kernel)",
            6, docker, 5, NULL, true, NEOPROOT_ROOTFS_IMAGE);
        /* The command list cannot override the rootfs kind. */
        check_selection_rootfs(
            1,
            "neoproot: --backend=auto selected the um backend "
            "(the rootfs is a filesystem image, which only the um backend "
            "can use)",
            6, plain, 5, "none", true, NEOPROOT_ROOTFS_IMAGE);
        /* Without a kernel/stub the image cannot run anywhere; say so. */
        check_selection_rootfs(
            0,
            "neoproot: --backend=auto would use the um backend because the "
            "rootfs is a filesystem image, but no kernel/stub is configured; "
            "using the default backend",
            6, plain, 5, NULL, false, NEOPROOT_ROOTFS_IMAGE);
        /* A directory rootfs keeps the command-based behaviour. */
        check_selection_rootfs(
            0,
            "neoproot: --backend=auto selected the default backend",
            6, plain, 5, NULL, true, NEOPROOT_ROOTFS_DIRECTORY);
        /* No rootfs at all stays on the default path. */
        check_selection_rootfs(
            0,
            "neoproot: --backend=auto selected the default backend",
            6, plain, 5, NULL, true, NEOPROOT_ROOTFS_NONE);
    }

    if (failures != 0) {
        fprintf(stderr, "%d auto backend check(s) failed\n", failures);
        return EXIT_FAILURE;
    }
    printf("auto backend policy tests passed\n");
    return EXIT_SUCCESS;
}
