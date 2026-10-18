#include "cli/auto_backend.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Which guest commands need a real kernel?
 *
 * PRoot translates paths, IDs and results in front of the host kernel; it is
 * fast because it never becomes one.  A command that asks the kernel for a
 * facility PRoot cannot emulate -- a mount, a namespace, a block device, a
 * packet filter, a container runtime's control plane -- therefore needs the
 * UML backend, where the guest is a kernel.  This is the default set; it is a
 * list of names, not a guess about the command line, and
 * --auto-um-commands / NEOPROOT_UM_AUTO_COMMANDS replace it.
 */
static const char *const auto_um_default_commands[] = {
    "docker", "dockerd", "podman", "podman-remote", "nerdctl", "containerd",
    "ctr", "runc", "crun", "systemd-nspawn", "machinectl",
    "mount", "umount", "losetup", "swapon", "swapoff",
    "unshare", "nsenter", "ip", "iptables", "nft", "bpftool",
    NULL
};

/*
 * Wrappers that only change how a command is started.  The guest command is
 * the one they end up running, so the wrapper's own name and options are
 * skipped before the decision.  Only the options that take a separate value
 * are listed: everything else beginning with "-" is skipped by position, and
 * a combined short form such as "sudo -Eu root" is not unwrapped -- the
 * boundary is documented in the manual rather than guessed at.
 */
struct auto_wrapper {
    const char *name;
    const char *const *value_options;
};

static const char *const auto_env_value_options[] = {
    "-u", "--unset", "-C", "--chdir", NULL
};
static const char *const auto_sudo_value_options[] = {
    "-u", "--user", "-g", "--group", "-p", "--prompt", "-C", "--close-from",
    "-D", "--chdir", "-h", "--host", "-r", "--role", "-t", "--type",
    "-T", "--command-timeout", "-U", "--other-user", "-R", "--chroot", NULL
};
static const char *const auto_exec_value_options[] = { "-a", NULL };
static const char *const auto_time_value_options[] = {
    "-o", "--output", "-f", "--format", NULL
};
static const char *const auto_stdbuf_value_options[] = {
    "-i", "--input", "-o", "--output", "-e", "--error", NULL
};

/*
 * command's own options (-p, -v) and nohup's are flags: they take no value.
 * A combined short form such as "stdbuf -oL" or "sudo -Eu root" is skipped as
 * one argument, so a wrapper that packs a value into its flags is not unwrapped
 * past the real command.  That is the documented boundary: write the flags
 * separately when a wrapper in front of a command that needs a kernel has to
 * be looked through.
 */
static const struct auto_wrapper auto_um_wrappers[] = {
    { "env", auto_env_value_options },
    { "sudo", auto_sudo_value_options },
    { "command", NULL },
    { "exec", auto_exec_value_options },
    { "nohup", NULL },
    { "time", auto_time_value_options },
    { "stdbuf", auto_stdbuf_value_options },
};

/* How many wrappers may be peeled off before the search gives up. */
#define AUTO_MAX_WRAPPERS 8

static const char *auto_basename(const char *path)
{
    const char *slash = strrchr(path, '/');

    return slash != NULL ? slash + 1 : path;
}

/* NAME=VALUE, as env takes them: an assignment, not a command. */
static bool auto_is_assignment(const char *argument)
{
    const char *equals = strchr(argument, '=');
    const char *cursor;

    if (equals == NULL || equals == argument)
        return false;
    if (!(argument[0] == '_' || isalpha((unsigned char)argument[0])))
        return false;
    for (cursor = argument + 1; cursor < equals; cursor++)
        if (!(*cursor == '_' || isalnum((unsigned char)*cursor)))
            return false;
    return true;
}

static const struct auto_wrapper *auto_find_wrapper(const char *name)
{
    size_t index;

    for (index = 0;
         index < sizeof(auto_um_wrappers) / sizeof(auto_um_wrappers[0]);
         index++)
        if (strcmp(auto_um_wrappers[index].name, name) == 0)
            return &auto_um_wrappers[index];
    return NULL;
}

static bool auto_option_takes_value(const struct auto_wrapper *wrapper,
                                    const char *argument)
{
    size_t index;

    if (wrapper->value_options == NULL)
        return false;
    for (index = 0; wrapper->value_options[index] != NULL; index++)
        if (strcmp(wrapper->value_options[index], argument) == 0)
            return true;
    return false;
}

/*
 * The command the caller actually asked for: the basename at the guest command
 * position, with simple wrappers peeled off.  NULL when there is no command or
 * when the wrappers never end.
 *
 * This reads the vector, not a shell string: "sh -c 'docker run'" is "sh" and
 * stays on the default backend, which is the documented boundary.  Getting
 * that wrong in the other direction would only cost speed, but inventing a
 * command that is not there would make auto unpredictable, so the search stops
 * rather than guess.
 */
const char *neoproot_auto_guest_command(int argc, char *const argv[], int start)
{
    int index = start;
    int depth = 0;

    if (start <= 0 || start >= argc)
        return NULL;
    while (index < argc) {
        const struct auto_wrapper *wrapper;
        int next;

        /*
         * The vector neoproot hands over is a command line, and its own
         * separator can still be in it in the no-command case; it is not a
         * command and it is not a wrapper argument.  An assignment is skipped
         * only where env would put one -- in front of the command -- because
         * once a wrapper is found, its arguments belong to the wrapper.
         */
        if (strcmp(argv[index], "--") == 0) {
            index++;
            continue;
        }
        wrapper = auto_find_wrapper(auto_basename(argv[index]));
        if (wrapper == NULL) {
            if (auto_is_assignment(argv[index])) {
                index++;
                continue;
            }
            return auto_basename(argv[index]);
        }
        if (++depth > AUTO_MAX_WRAPPERS)
            return NULL;
        next = index + 1;
        while (next < argc) {
            const char *candidate = argv[next];

            if (strcmp(candidate, "--") == 0) {
                next++;
                break;
            }
            if (auto_is_assignment(candidate)) {
                next++;
                continue;
            }
            if (candidate[0] != '-' || candidate[1] == '\0')
                break;
            next += auto_option_takes_value(wrapper, candidate) ? 2 : 1;
        }
        if (next >= argc)
            return NULL;
        index = next;
    }
    return NULL;
}

/* Whitespace around a list or an entry is not part of a command name. */
static const char *auto_trim_start(const char *text)
{
    while (*text == ' ' || *text == '\t')
        text++;
    return text;
}

static const char *auto_trim_end(const char *start, const char *end)
{
    while (end > start && (end[-1] == ' ' || end[-1] == '\t'))
        end--;
    return end;
}

/* A list whose only entry is "none" disables command-based selection. */
static bool auto_list_is_none(const char *list)
{
    const char *start = auto_trim_start(list);
    const char *end = auto_trim_end(start, start + strlen(start));

    return (size_t)(end - start) == 4 && strncmp(start, "none", 4) == 0;
}

static bool auto_list_matches(const char *list, const char *command)
{
    const char *segment = list;
    size_t command_length = strlen(command);

    while (segment != NULL && *segment != '\0') {
        const char *comma = strchr(segment, ',');
        const char *end = comma != NULL ? comma : segment + strlen(segment);
        const char *start = auto_trim_start(segment);
        size_t length;

        end = auto_trim_end(start, end);
        length = (size_t)(end - start);
        if (length == command_length && strncmp(start, command, length) == 0)
            return true;
        segment = comma != NULL ? comma + 1 : NULL;
    }
    return false;
}

bool neoproot_auto_command_needs_kernel(const char *command, const char *list)
{
    size_t index;

    if (command == NULL)
        return false;
    if (list == NULL) {
        for (index = 0; auto_um_default_commands[index] != NULL; index++)
            if (strcmp(auto_um_default_commands[index], command) == 0)
                return true;
        return false;
    }
    if (auto_list_is_none(list))
        return false;
    return auto_list_matches(list, command);
}

/*
 * The list in force: the option when it was given (an empty value means the
 * default set), then NEOPROOT_UM_AUTO_COMMANDS, then the default set itself.
 */
const char *neoproot_auto_effective_list(const char *option)
{
    const char *environment;

    if (option != NULL)
        return option[0] != '\0' ? option : NULL;
    environment = getenv("NEOPROOT_UM_AUTO_COMMANDS");
    if (environment != NULL && environment[0] != '\0')
        return environment;
    return NULL;
}

/*
 * Decide, and say why.  The message is the whole contract: a caller who asked
 * for auto has to be able to tell from stderr which backend ran and -- when
 * the answer is "not the one the command wanted" -- why not.
 */
int neoproot_auto_select(int argc, char *const argv[], int command_index,
                         const char *list_option, bool um_configured,
                         enum neoproot_rootfs_kind rootfs_kind,
                         char *message, size_t message_size)
{
    const char *list = neoproot_auto_effective_list(list_option);
    const char *command = neoproot_auto_guest_command(argc, argv,
                                                      command_index);
    bool needs_kernel = neoproot_auto_command_needs_kernel(command, list);
    /*
     * A filesystem image is not a performance question: PRoot has no host path
     * to translate it to and cannot run it at all, so an image rootfs forces
     * the UML backend whatever the command is.  --cow-file is not part of this
     * decision: it only means anything next to an image, and a caller that
     * passes it with a directory gets the explanation from the dispatcher.
     */
    bool image_rootfs = rootfs_kind == NEOPROOT_ROOTFS_IMAGE;
    int use_um = um_configured && (needs_kernel || image_rootfs);

    if (message != NULL && message_size > 0) {
        if (use_um && image_rootfs) {
            if (needs_kernel && command != NULL)
                snprintf(message, message_size,
                         "neoproot: --backend=auto selected the um backend "
                         "(the rootfs is a filesystem image and command '%s' "
                         "needs a real kernel)", command);
            else
                snprintf(message, message_size,
                         "neoproot: --backend=auto selected the um backend "
                         "(the rootfs is a filesystem image, which only the "
                         "um backend can use)");
        } else if (!um_configured && image_rootfs)
            snprintf(message, message_size,
                     "neoproot: --backend=auto would use the um backend "
                     "because the rootfs is a filesystem image, but no "
                     "kernel/stub is configured; using the default backend");
        else if (use_um)
            snprintf(message, message_size,
                     "neoproot: --backend=auto selected the um backend "
                     "(command '%s' needs a real kernel)", command);
        else if (needs_kernel)
            snprintf(message, message_size,
                     "neoproot: --backend=auto would use the um backend for "
                     "'%s', but no kernel/stub/rootfs is configured; "
                     "using the default backend", command);
        else
            snprintf(message, message_size,
                     "neoproot: --backend=auto selected the default backend");
    }
    return use_um;
}
