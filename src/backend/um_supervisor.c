#include "backend/um_supervisor.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <float.h>
#include <limits.h>
#include <math.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define UM_SESSION_TEMPLATE "/.neoproot-um-XXXXXX"
#define UM_WRAPPER_NAME "init.sh"
#define UM_INPUT_LIMIT (64U * 1024U)
#define UM_OUTPUT_LIMIT (16U * 1024U * 1024U)
#define UM_SIGNAL_GRACE_SECONDS 2.0
#define UM_DRAIN_SECONDS 2.0

typedef struct {
    const char *kernel;
    const char *stub;
    const char *rootfs;
    const char *cwd;
    double timeout;
    bool hostfs;
    bool saw_delimiter;
    char *resolved_kernel;
    char *resolved_stub;
    char *resolved_rootfs;
} UmConfig;

typedef struct {
    unsigned char *data;
    size_t start;
    size_t end;
    size_t capacity;
} UmBuffer;

static volatile sig_atomic_t um_requested_signal;

static void um_signal_handler(int signal_number)
{
    um_requested_signal = signal_number;
}

static double um_now(void)
{
    struct timespec value;

    if (clock_gettime(CLOCK_MONOTONIC, &value) < 0)
        return 0.0;
    return (double)value.tv_sec + (double)value.tv_nsec / 1000000000.0;
}

static int um_write_all(int fd, const void *data, size_t length)
{
    const unsigned char *cursor = data;

    while (length != 0) {
        ssize_t written = write(fd, cursor, length);
        if (written > 0) {
            cursor += (size_t)written;
            length -= (size_t)written;
            continue;
        }
        if (written < 0 && errno == EINTR)
            continue;
        return -1;
    }
    return 0;
}

static int um_write_text(int fd, const char *text)
{
    return um_write_all(fd, text, strlen(text));
}

static int um_write_shell_word(int fd, const char *value)
{
    const char *cursor;

    if (um_write_text(fd, "'") < 0)
        return -1;
    for (cursor = value; *cursor != '\0'; cursor++) {
        if (*cursor == '\'') {
            if (um_write_text(fd, "'\\''") < 0)
                return -1;
        } else if (um_write_all(fd, cursor, 1) < 0) {
            return -1;
        }
    }
    return um_write_text(fd, "'");
}

static bool um_path_has_parent_component(const char *path)
{
    const char *cursor = path;

    while (*cursor != '\0') {
        const char *component = cursor;
        size_t length;

        while (*cursor == '/')
            cursor++;
        component = cursor;
        while (*cursor != '\0' && *cursor != '/')
            cursor++;
        length = (size_t)(cursor - component);
        if (length == 2 && component[0] == '.' && component[1] == '.')
            return true;
    }
    return false;
}

static int um_validate_guest_path(const char *name, const char *value)
{
    if (value == NULL || value[0] != '/') {
        fprintf(stderr, "neoproot-um: %s must be an absolute path\n", name);
        return -1;
    }
    if (strlen(value) >= PATH_MAX || um_path_has_parent_component(value)) {
        fprintf(stderr, "neoproot-um: invalid %s path\n", name);
        return -1;
    }
    return 0;
}

static int um_resolve_host_path(const char *name, const char *value,
                                bool directory, bool executable, char **result)
{
    char resolved[PATH_MAX];
    struct stat status;
    char *copy;

    if (um_validate_guest_path(name, value) < 0)
        return -1;
    if (realpath(value, resolved) == NULL) {
        fprintf(stderr, "neoproot-um: cannot resolve %s '%s': %s\n",
                name, value, strerror(errno));
        return -1;
    }
    if (stat(resolved, &status) < 0) {
        fprintf(stderr, "neoproot-um: cannot stat %s '%s': %s\n",
                name, resolved, strerror(errno));
        return -1;
    }
    if ((directory && !S_ISDIR(status.st_mode)) ||
        (!directory && !S_ISREG(status.st_mode))) {
        fprintf(stderr, "neoproot-um: %s has the wrong file type\n", name);
        return -1;
    }
    if (executable && access(resolved, X_OK) < 0) {
        fprintf(stderr, "neoproot-um: %s is not executable: %s\n",
                name, strerror(errno));
        return -1;
    }
    if (directory && resolved[0] == '/' && resolved[1] == '\0') {
        fprintf(stderr, "neoproot-um: refusing to use '/' as hostfs root\n");
        return -1;
    }
    copy = strdup(resolved);
    if (copy == NULL) {
        perror("neoproot-um: strdup");
        return -1;
    }
    *result = copy;
    return 0;
}

static int um_parse_timeout(const char *value, double *timeout)
{
    char *end;
    const char *literal = value;
    double parsed;

    if (value == NULL || value[0] == '\0' || isspace((unsigned char)value[0]))
        return -1;
    if (*literal == '+' || *literal == '-')
        literal++;
    if (strncasecmp(literal, "nan", 3) == 0 ||
        strncasecmp(literal, "inf", 3) == 0)
        return -1;
    errno = 0;
    parsed = strtod(value, &end);
    if (errno != 0 || end == value || *end != '\0' ||
        parsed == HUGE_VAL || parsed == -HUGE_VAL ||
        parsed <= 0.0 || parsed > DBL_MAX / 2.0)
        return -1;
    *timeout = parsed;
    return 0;
}

static int um_parse_args(int argc, char *const argv[], UmConfig *config,
                         int *guest_index)
{
    int index;
    bool kernel_set = false;
    bool stub_set = false;
    bool rootfs_set = false;
    bool cwd_set = false;
    bool timeout_set = false;

    memset(config, 0, sizeof(*config));
    config->cwd = "/";
    config->timeout = 120.0;

    for (index = 1; index < argc; index++) {
        const char *argument = argv[index];

        if (strcmp(argument, "--") == 0) {
            config->saw_delimiter = true;
            index++;
            break;
        }
        if (strncmp(argument, "--kernel=", 9) == 0) {
            if (kernel_set || argument[9] == '\0')
                goto invalid;
            config->kernel = argument + 9;
            kernel_set = true;
        } else if (strncmp(argument, "--stub=", 7) == 0) {
            if (stub_set || argument[7] == '\0')
                goto invalid;
            config->stub = argument + 7;
            stub_set = true;
        } else if (strcmp(argument, "-r") == 0 ||
                   strcmp(argument, "--rootfs") == 0) {
            if (++index >= argc || rootfs_set)
                goto invalid;
            config->rootfs = argv[index];
            rootfs_set = true;
        } else if (strncmp(argument, "--rootfs=", 9) == 0) {
            if (rootfs_set || argument[9] == '\0')
                goto invalid;
            config->rootfs = argument + 9;
            rootfs_set = true;
        } else if (strcmp(argument, "--hostfs") == 0) {
            if (config->hostfs)
                goto invalid;
            config->hostfs = true;
        } else if (strcmp(argument, "-w") == 0 ||
                   strcmp(argument, "--pwd") == 0) {
            if (++index >= argc || cwd_set)
                goto invalid;
            config->cwd = argv[index];
            cwd_set = true;
        } else if (strncmp(argument, "--cwd=", 6) == 0 ||
                   strncmp(argument, "--pwd=", 6) == 0) {
            if (cwd_set || argument[6] == '\0')
                goto invalid;
            config->cwd = argument + 6;
            cwd_set = true;
        } else if (strncmp(argument, "--timeout=", 10) == 0) {
            if (timeout_set || um_parse_timeout(argument + 10,
                                                &config->timeout) < 0)
                goto invalid;
            timeout_set = true;
        } else {
            goto invalid;
        }
    }
    if (!config->saw_delimiter || index >= argc) {
        fprintf(stderr, "neoproot-um: use -- before the guest command\n");
        return -1;
    }
    *guest_index = index;

    if (!config->hostfs) {
        fprintf(stderr, "neoproot-um: only explicit --hostfs mode is supported\n");
        return -1;
    }
    if (!rootfs_set) {
        fprintf(stderr, "neoproot-um: --rootfs=DIR is required\n");
        return -1;
    }
    if (!kernel_set)
        config->kernel = getenv("NEOPROOT_UM_KERNEL");
    if (!stub_set)
        config->stub = getenv("NEOPROOT_UM_STUB");
    if (config->kernel == NULL || config->stub == NULL ||
        config->kernel[0] == '\0' || config->stub[0] == '\0') {
        fprintf(stderr,
                "neoproot-um: set --kernel/--stub or NEOPROOT_UM_KERNEL/NEOPROOT_UM_STUB\n");
        return -1;
    }
    if (um_validate_guest_path("cwd", config->cwd) < 0)
        return -1;
    if (um_resolve_host_path("kernel", config->kernel, false, true,
                             &config->resolved_kernel) < 0 ||
        um_resolve_host_path("stub", config->stub, false, true,
                             &config->resolved_stub) < 0 ||
        um_resolve_host_path("rootfs", config->rootfs, true, false,
                             &config->resolved_rootfs) < 0)
        return -1;
    return 0;

invalid:
    fprintf(stderr, "neoproot-um: invalid or duplicate option '%s'\n",
            index < argc ? argv[index] : "");
    return -1;
}

static int um_check_untraced(void)
{
    FILE *status_file;
    char line[256];
    bool found = false;

    status_file = fopen("/proc/self/status", "r");
    if (status_file == NULL) {
        fprintf(stderr, "neoproot-um: cannot inspect TracerPid: %s\n",
                strerror(errno));
        return -1;
    }
    while (fgets(line, sizeof(line), status_file) != NULL) {
        char *end;
        long tracer_pid;

        if (strncmp(line, "TracerPid:", 10) != 0)
            continue;
        found = true;
        errno = 0;
        tracer_pid = strtol(line + 10, &end, 10);
        if (errno != 0 || end == line + 10 || tracer_pid < 0) {
            fclose(status_file);
            fprintf(stderr, "neoproot-um: invalid TracerPid value\n");
            return -1;
        }
        if (tracer_pid != 0) {
            fclose(status_file);
            fprintf(stderr,
                    "neoproot-um: refusing to start while traced (TracerPid=%ld)\n",
                    tracer_pid);
            return -1;
        }
        break;
    }
    fclose(status_file);
    if (!found) {
        fprintf(stderr, "neoproot-um: TracerPid is unavailable\n");
        return -1;
    }
    return 0;
}

static bool um_valid_environment_name(const char *name, size_t length)
{
    size_t index;

    if (length == 0 || !(name[0] == '_' ||
                         isalpha((unsigned char)name[0])))
        return false;
    for (index = 1; index < length; index++) {
        if (!(name[index] == '_' ||
              isalnum((unsigned char)name[index])))
            return false;
    }
    return true;
}

static bool um_skip_environment_name(const char *name, size_t length)
{
    static const char *const exact_names[] = {
        "HOME", "PATH", "PWD", "OLDPWD", "TMPDIR", "PREFIX",
        "SHELL", NULL
    };
    static const char *const prefixes[] = {
        "ANDROID_", "LD_", "NEOPROOT_", "PROOT_", "TERMUX_", "UML_", NULL
    };
    size_t index;

    for (index = 0; exact_names[index] != NULL; index++) {
        if (strlen(exact_names[index]) == length &&
            strncmp(name, exact_names[index], length) == 0)
            return true;
    }
    for (index = 0; prefixes[index] != NULL; index++) {
        size_t prefix_length = strlen(prefixes[index]);

        if (length >= prefix_length &&
            strncmp(name, prefixes[index], prefix_length) == 0)
            return true;
    }
    return false;
}

static bool um_allow_environment_name(const char *name, size_t length)
{
    static const char *const exact_names[] = {
        "LANG", "TERM", "COLORTERM", "TZ", "USER", "LOGNAME",
        "EDITOR", "VISUAL", NULL
    };
    size_t index;

    for (index = 0; exact_names[index] != NULL; index++) {
        if (strlen(exact_names[index]) == length &&
            strncmp(name, exact_names[index], length) == 0)
            return true;
    }
    return length > 3 && strncmp(name, "LC_", 3) == 0;
}

static int um_write_wrapper(const char *wrapper_path, const char *cwd,
                            const char *status_path, int guest_argc,
                            char *const guest_argv[])
{
    int fd;
    char **environment;
    int index;

    fd = open(wrapper_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC |
              O_NOFOLLOW, 0700);
    if (fd < 0) {
        fprintf(stderr, "neoproot-um: cannot create wrapper '%s': %s\n",
                wrapper_path, strerror(errno));
        return -1;
    }
        if (um_write_text(fd, "#!/bin/sh\n"
                         "um_fail() { printf '%s\\n' \"$1\" > ") < 0 ||
        um_write_shell_word(fd, status_path) < 0 ||
        um_write_text(fd, "; sync; poweroff -f; while :; do sleep 3600; done; }\n"
                         "mount -t proc proc /proc 2>/dev/null || "
                         "test -r /proc/self/status || um_fail 125\n"
                         "mount -t sysfs sysfs /sys 2>/dev/null || "
                         "test -d /sys/kernel || um_fail 125\n"
                         "mount -t devtmpfs devtmpfs /dev 2>/dev/null || "
                         "test -c /dev/null || um_fail 125\n"
                         "cd ") < 0 ||
        um_write_shell_word(fd, cwd) < 0 ||
        um_write_text(fd, " || exit 126\n"
                         "unset LD_PRELOAD LD_LIBRARY_PATH LD_BIND_NOW "
                         "NEOPROOT_MEMFD_LOADER NEOPROOT_UNSET_DONE "
                         "BASH_ENV ENV CDPATH IFS\n"
                         "HOME=/root\nexport HOME\n"
                         "TMPDIR=/tmp\nexport TMPDIR\n"
                         "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
                         "export PATH\n") < 0)
        goto failed;

    for (environment = environ; environment != NULL && *environment != NULL;
         environment++) {
        const char *separator = strchr(*environment, '=');
        size_t name_length;

        if (separator == NULL)
            continue;
        name_length = (size_t)(separator - *environment);
        if (!um_valid_environment_name(*environment, name_length) ||
            um_skip_environment_name(*environment, name_length) ||
            !um_allow_environment_name(*environment, name_length))
            continue;
        if (um_write_all(fd, *environment, name_length) < 0 ||
            um_write_text(fd, "=") < 0 ||
            um_write_shell_word(fd, separator + 1) < 0 ||
            um_write_text(fd, "\nexport ") < 0 ||
            um_write_all(fd, *environment, name_length) < 0 ||
            um_write_text(fd, "\n") < 0)
            goto failed;
    }

    if (um_write_text(fd, "set --") < 0)
        goto failed;
    for (index = 0; index < guest_argc; index++) {
        if (um_write_text(fd, " ") < 0 ||
            um_write_shell_word(fd, guest_argv[index]) < 0)
            goto failed;
    }
    if (um_write_text(fd, "\n\"$@\"\nrc=$?\nprintf '%s\\n' \"$rc\" > ") < 0 ||
        um_write_shell_word(fd, status_path) < 0 ||
        um_write_text(fd, "\nsync\npoweroff -f\nwhile :; do sleep 3600; done\n") < 0 ||
        fsync(fd) < 0)
        goto failed;
    if (close(fd) < 0) {
        unlink(wrapper_path);
        return -1;
    }
    return 0;

failed:
    fprintf(stderr, "neoproot-um: failed to write wrapper '%s': %s\n",
            wrapper_path, strerror(errno));
    close(fd);
    unlink(wrapper_path);
    return -1;
}

static int um_buffer_reserve(UmBuffer *buffer, size_t additional,
                             size_t limit)
{
    size_t length = buffer->end - buffer->start;
    size_t needed;
    size_t capacity;
    unsigned char *replacement;

    if (additional > limit - length)
        return -1;
    needed = length + additional;
    if (needed <= buffer->capacity - buffer->start)
        return 0;
    if (buffer->start != 0) {
        memmove(buffer->data, buffer->data + buffer->start, length);
        buffer->start = 0;
        buffer->end = length;
        if (needed <= buffer->capacity)
            return 0;
    }
    capacity = buffer->capacity == 0 ? 4096 : buffer->capacity;
    while (capacity < needed) {
        if (capacity > limit / 2) {
            capacity = limit;
            break;
        }
        capacity *= 2;
    }
    replacement = realloc(buffer->data, capacity);
    if (replacement == NULL)
        return -1;
    buffer->data = replacement;
    buffer->capacity = capacity;
    return 0;
}

static int um_buffer_append(UmBuffer *buffer, const void *data, size_t length,
                            size_t limit)
{
    if (um_buffer_reserve(buffer, length, limit) < 0)
        return -1;
    memcpy(buffer->data + buffer->end, data, length);
    buffer->end += length;
    return 0;
}

static void um_buffer_consume(UmBuffer *buffer, size_t length)
{
    buffer->start += length;
    if (buffer->start == buffer->end) {
        buffer->start = 0;
        buffer->end = 0;
    }
}

static void um_buffer_release(UmBuffer *buffer)
{
    free(buffer->data);
    memset(buffer, 0, sizeof(*buffer));
}

static int um_flush_buffer(UmBuffer *buffer, int fd)
{
    while (buffer->start < buffer->end) {
        ssize_t written = write(fd, buffer->data + buffer->start,
                                buffer->end - buffer->start);
        if (written > 0) {
            um_buffer_consume(buffer, (size_t)written);
            continue;
        }
        if (written < 0 && (errno == EINTR || errno == EAGAIN ||
                            errno == EWOULDBLOCK))
            return 0;
        return -1;
    }
    return 0;
}

static int um_set_nonblocking(int fd, int *old_flags)
{
    int flags = fcntl(fd, F_GETFL);

    if (flags < 0)
        return -1;
    *old_flags = flags;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        return -1;
    return 0;
}

static void um_kill_group(pid_t pid, int signal_number)
{
    if (pid > 0) {
        (void)kill(pid, signal_number);
        (void)kill(-pid, signal_number);
    }
}

static int um_install_signal_handlers(struct sigaction old_actions[5])
{
    static const int signals[5] = {
        SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGPIPE
    };
    struct sigaction action;
    int index;

    memset(&action, 0, sizeof(action));
    sigemptyset(&action.sa_mask);
    action.sa_handler = um_signal_handler;
    for (index = 0; index < 5; index++) {
        if (signals[index] == SIGPIPE) {
            action.sa_handler = SIG_IGN;
        } else {
            action.sa_handler = um_signal_handler;
        }
        if (sigaction(signals[index], &action, &old_actions[index]) < 0) {
            while (index-- > 0)
                sigaction(signals[index], &old_actions[index], NULL);
            return -1;
        }
    }
    return 0;
}

static void um_restore_signal_handlers(const struct sigaction old_actions[5])
{
    static const int signals[5] = {
        SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGPIPE
    };
    int index;

    for (index = 0; index < 5; index++)
        (void)sigaction(signals[index], &old_actions[index], NULL);
}

static void um_print_usage(void)
{
    puts("Usage: neoproot-um --rootfs=DIR --hostfs [options] -- command [args...]");
    puts("Options:");
    puts("  --kernel=PATH       UML kernel executable");
    puts("  --stub=PATH         UML stub_exe executable");
    puts("  --rootfs=DIR        hostfs root directory");
    puts("  --hostfs            enable explicit hostfs mode");
    puts("  --cwd=PATH          guest working directory");
    puts("  --timeout=SECONDS   bounded runtime (default: 120)");
    puts("Environment defaults: NEOPROOT_UM_KERNEL, NEOPROOT_UM_STUB");
}

static int um_wait_for_process(pid_t pid, int *status)
{
    pid_t result;

    do {
        result = waitpid(pid, status, 0);
    } while (result < 0 && errno == EINTR);
    return result == pid ? 0 : -1;
}

static int um_read_guest_status(const char *status_path, int *status)
{
    char buffer[32];
    char *end;
    long value;
    int fd;
    ssize_t length;

    fd = open(status_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    length = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);
    if (length <= 0 || length >= (ssize_t)sizeof(buffer) - 1)
        return -1;
    buffer[length] = '\0';
    errno = 0;
    value = strtol(buffer, &end, 10);
    if (errno != 0 || end == buffer || value < 0 || value > 255)
        return -1;
    while (*end == '\n' || *end == '\r' || *end == ' ' || *end == '\t')
        end++;
    if (*end != '\0')
        return -1;
    *status = (int)value;
    return 0;
}

static int um_run_kernel(const UmConfig *config, const char *init_path,
                         const char *session_path, const char *status_path)
{
    char init_argument[PATH_MAX + 6];
    char root_argument[PATH_MAX + 10];
    char stub_argument[PATH_MAX + 6];
    char slave_name[PATH_MAX];
    char *kernel_argv[12];
    struct sigaction old_actions[5];
    UmBuffer input = { 0 };
    UmBuffer output = { 0 };
    int master_fd = -1;
    int master_flags = -1;
    int stdin_flags = -1;
    int stdout_flags = -1;
    pid_t child_pid = -1;
    int child_status = 0;
    bool child_done = false;
    bool master_eof = false;
    bool stdin_eof = false;
    bool output_failed = false;
    bool group_cleaned = false;
    bool termination_sent = false;
    bool timed_out = false;
    int forwarded_signal = 0;
    bool guest_status_valid = false;
    double deadline;
    double termination_deadline = 0.0;
    double drain_deadline = 0.0;
    int result = EXIT_FAILURE;
    int index = 0;

    if (snprintf(init_argument, sizeof(init_argument), "init=%s", init_path)
            >= (int)sizeof(init_argument) ||
        snprintf(root_argument, sizeof(root_argument), "rootflags=%s",
                 config->resolved_rootfs) >= (int)sizeof(root_argument) ||
        snprintf(stub_argument, sizeof(stub_argument), "stub_exe=%s",
                 config->resolved_stub) >= (int)sizeof(stub_argument)) {
        fprintf(stderr, "neoproot-um: UML argument is too long\n");
        return EXIT_FAILURE;
    }

    kernel_argv[index++] = config->resolved_kernel;
    kernel_argv[index++] = "mem=512M";
    kernel_argv[index++] = "rw";
    kernel_argv[index++] = init_argument;
    kernel_argv[index++] = "con=null";
    kernel_argv[index++] = "con0=fd:0,fd:1";
    kernel_argv[index++] = stub_argument;
    kernel_argv[index++] = "rootfstype=hostfs";
    kernel_argv[index++] = root_argument;
    kernel_argv[index++] = "panic=1";
    kernel_argv[index] = NULL;
    (void)session_path;

    master_fd = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (master_fd < 0 || grantpt(master_fd) < 0 || unlockpt(master_fd) < 0 ||
        ptsname_r(master_fd, slave_name, sizeof(slave_name)) != 0) {
        fprintf(stderr, "neoproot-um: cannot set up PTY: %s\n",
                strerror(errno));
        if (master_fd >= 0)
            close(master_fd);
        return EXIT_FAILURE;
    }
    if (um_set_nonblocking(master_fd, &master_flags) < 0) {
        fprintf(stderr, "neoproot-um: cannot configure PTY: %s\n",
                strerror(errno));
        close(master_fd);
        return EXIT_FAILURE;
    }
    if (um_set_nonblocking(STDIN_FILENO, &stdin_flags) < 0)
        stdin_flags = -1;
    if (um_set_nonblocking(STDOUT_FILENO, &stdout_flags) < 0)
        stdout_flags = -1;

    if (um_install_signal_handlers(old_actions) < 0) {
        fprintf(stderr, "neoproot-um: cannot install signal handlers: %s\n",
                strerror(errno));
        goto cleanup;
    }
    um_requested_signal = 0;
    child_pid = fork();
    if (child_pid < 0) {
        fprintf(stderr, "neoproot-um: fork: %s\n", strerror(errno));
        um_restore_signal_handlers(old_actions);
        goto cleanup;
    }
    if (child_pid == 0) {
        int child_slave;
        char tmpdir_environment[PATH_MAX + 8];
        char home_environment[PATH_MAX + 6];
        const char *host_tmpdir = getenv("TMPDIR");
        const char *host_home = getenv("HOME");

        close(master_fd);
        if (setsid() < 0) {
            dprintf(STDERR_FILENO, "neoproot-um: setsid: %s\n", strerror(errno));
            _exit(127);
        }
        child_slave = open(slave_name, O_RDWR);
        if (child_slave < 0) {
            dprintf(STDERR_FILENO, "neoproot-um: open PTY slave: %s\n", strerror(errno));
            _exit(127);
        }
        if (ioctl(child_slave, TIOCSCTTY, 0) < 0) {
            dprintf(STDERR_FILENO, "neoproot-um: TIOCSCTTY: %s\n", strerror(errno));
            _exit(127);
        }
        if (dup2(child_slave, STDIN_FILENO) < 0 ||
            dup2(child_slave, STDOUT_FILENO) < 0 ||
            dup2(child_slave, STDERR_FILENO) < 0) {
            dprintf(STDERR_FILENO, "neoproot-um: dup2 PTY: %s\n", strerror(errno));
            _exit(127);
        }
        if (child_slave > STDERR_FILENO)
            close(child_slave);
        {
            if (host_tmpdir == NULL || host_tmpdir[0] != '/' ||
                strlen(host_tmpdir) >= PATH_MAX - 8)
                host_tmpdir = "/tmp";
            snprintf(tmpdir_environment, sizeof(tmpdir_environment),
                     "TMPDIR=%s", host_tmpdir);
            if (host_home == NULL || host_home[0] != '/' ||
                strlen(host_home) >= PATH_MAX - 6)
                host_home = "/tmp";
            snprintf(home_environment, sizeof(home_environment),
                     "HOME=%s", host_home);
            static char *const kernel_environment[] = {
                (char *)"PATH=/usr/bin:/bin",
                NULL
            };
            char *environment[4];

            environment[0] = home_environment;
            environment[1] = kernel_environment[0];
            environment[2] = tmpdir_environment;
            environment[3] = NULL;

            execve(config->resolved_kernel, kernel_argv,
                   environment);
        }
        dprintf(STDERR_FILENO, "neoproot-um: exec %s: %s\n",
                config->resolved_kernel, strerror(errno));
        _exit(127);
    }

    deadline = um_now() + config->timeout;
    while (!child_done || !master_eof || output.start != output.end) {
        struct pollfd descriptors[3];
        nfds_t descriptor_count = 0;
        int master_index;
        int stdin_index = -1;
        int stdout_index = -1;
        int poll_timeout;
        double now;
        int wait_result;

        do {
            wait_result = waitpid(child_pid, &child_status, WNOHANG);
        } while (wait_result < 0 && errno == EINTR);
        if (wait_result == child_pid && !child_done) {
            child_done = true;
            drain_deadline = um_now() + UM_DRAIN_SECONDS;
            if (!group_cleaned) {
                um_kill_group(child_pid, SIGKILL);
                group_cleaned = true;
            }
        } else if (wait_result < 0 && errno != EINTR) {
            child_done = true;
        }

        now = um_now();
        if (um_requested_signal != 0 && forwarded_signal == 0) {
            forwarded_signal = um_requested_signal;
            termination_sent = true;
            termination_deadline = now + UM_SIGNAL_GRACE_SECONDS;
            um_kill_group(child_pid, forwarded_signal);
        }
        if (!child_done && forwarded_signal == 0 && now >= deadline) {
            timed_out = true;
            termination_sent = true;
            forwarded_signal = SIGKILL;
            termination_deadline = now;
            um_kill_group(child_pid, SIGKILL);
        }
        if (!child_done && termination_sent && now >= termination_deadline) {
            um_kill_group(child_pid, SIGKILL);
            termination_deadline = now + UM_SIGNAL_GRACE_SECONDS;
        }
        if (child_done && drain_deadline != 0.0 && now >= drain_deadline)
            break;
        if (child_done && master_eof && output.start == output.end)
            break;

        master_index = (int)descriptor_count;
        descriptors[descriptor_count++] = (struct pollfd){
            .fd = master_fd,
            .events = POLLIN | POLLERR | POLLHUP |
                      (input.start != input.end ? POLLOUT : 0),
            .revents = 0
        };
        if (!child_done && !stdin_eof && input.end - input.start < UM_INPUT_LIMIT) {
            stdin_index = (int)descriptor_count;
            descriptors[descriptor_count++] = (struct pollfd){
                .fd = STDIN_FILENO, .events = POLLIN | POLLHUP, .revents = 0
            };
        }
        if (!output_failed && output.start != output.end) {
            stdout_index = (int)descriptor_count;
            descriptors[descriptor_count++] = (struct pollfd){
                .fd = STDOUT_FILENO, .events = POLLOUT, .revents = 0
            };
        }
        now = um_now();
        poll_timeout = 100;
        if (!child_done && forwarded_signal == 0) {
            double remaining = deadline - now;
            if (remaining <= 0.0)
                poll_timeout = 0;
            else if (remaining < 0.1)
                poll_timeout = (int)(remaining * 1000.0) + 1;
        } else if (!child_done && termination_sent) {
            double remaining = termination_deadline - now;
            if (remaining <= 0.0)
                poll_timeout = 0;
            else if (remaining < 0.1)
                poll_timeout = (int)(remaining * 1000.0) + 1;
        }
        if (poll(descriptors, descriptor_count, poll_timeout) < 0 &&
            errno != EINTR)
            break;

        if (stdin_index >= 0 &&
            (descriptors[stdin_index].revents & (POLLIN | POLLHUP))) {
            unsigned char data[16384];
            ssize_t length = read(STDIN_FILENO, data, sizeof(data));
            if (length > 0) {
                if (um_buffer_append(&input, data, (size_t)length,
                                     UM_INPUT_LIMIT) < 0)
                    stdin_eof = true;
            } else if (length == 0 || (length < 0 && errno != EINTR &&
                                       errno != EAGAIN && errno != EWOULDBLOCK)) {
                stdin_eof = true;
                (void)um_buffer_append(&input, "\004", 1, UM_INPUT_LIMIT);
            }
        }
        if (descriptors[master_index].revents & POLLOUT)
            (void)um_flush_buffer(&input, master_fd);
        if (descriptors[master_index].revents & (POLLIN | POLLERR | POLLHUP)) {
            unsigned char data[65536];
            for (;;) {
                ssize_t length = read(master_fd, data, sizeof(data));
                if (length > 0) {
                    if (um_buffer_append(&output, data, (size_t)length,
                                         UM_OUTPUT_LIMIT) < 0) {
                        output_failed = true;
                        um_kill_group(child_pid, SIGKILL);
                        break;
                    }
                    continue;
                }
                if (length < 0 && (errno == EINTR))
                    continue;
                if (length < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                    break;
                master_eof = true;
                break;
            }
        }
        if (stdout_index >= 0 &&
            (descriptors[stdout_index].revents & POLLOUT))
            if (um_flush_buffer(&output, STDOUT_FILENO) < 0)
                output_failed = true;
    }

    if (!child_done) {
        um_kill_group(child_pid, SIGKILL);
        if (um_wait_for_process(child_pid, &child_status) == 0)
            child_done = true;
    }
    if (!group_cleaned)
        um_kill_group(child_pid, SIGKILL);
    while (output.start != output.end && !output_failed) {
        if (um_flush_buffer(&output, STDOUT_FILENO) < 0)
            output_failed = true;
    }
    um_restore_signal_handlers(old_actions);

    if (output_failed)
        result = EXIT_FAILURE;
    else if (timed_out)
        result = 124;
    else if (um_requested_signal != 0)
        result = 128 + um_requested_signal;
    else if (um_read_guest_status(status_path, &result) == 0)
        guest_status_valid = true;
    else if (child_done && WIFEXITED(child_status))
        result = WEXITSTATUS(child_status);
    else if (child_done && WIFSIGNALED(child_status))
        result = 128 + WTERMSIG(child_status);
    else if (!guest_status_valid)
        result = EXIT_FAILURE;

cleanup:
    if (child_pid > 0) {
        um_kill_group(child_pid, SIGKILL);
        if (!child_done)
            (void)um_wait_for_process(child_pid, &child_status);
    }
    if (stdin_flags >= 0)
        (void)fcntl(STDIN_FILENO, F_SETFL, stdin_flags);
    if (stdout_flags >= 0)
        (void)fcntl(STDOUT_FILENO, F_SETFL, stdout_flags);
    if (master_flags >= 0)
        (void)fcntl(master_fd, F_SETFL, master_flags);
    if (master_fd >= 0)
        close(master_fd);
    um_buffer_release(&input);
    um_buffer_release(&output);
    return result;
}

static int um_make_session(const char *rootfs, char **session_path,
                           char **wrapper_path, char **init_path,
                           char **status_path)
{
    char session[PATH_MAX];
    char wrapper[PATH_MAX];
    char init[PATH_MAX];
    char status[PATH_MAX];
    const char *session_name;
    int length;
    char *session_copy = NULL;
    char *wrapper_copy = NULL;
    char *init_copy = NULL;

    wrapper[0] = '\0';

    length = snprintf(session, sizeof(session), "%s%s", rootfs,
                      UM_SESSION_TEMPLATE);
    if (length < 0 || (size_t)length >= sizeof(session))
        return -1;
    if (mkdtemp(session) == NULL) {
        fprintf(stderr, "neoproot-um: cannot create session directory: %s\n",
                strerror(errno));
        return -1;
    }
    session_name = strrchr(session, '/') + 1;
    if (snprintf(wrapper, sizeof(wrapper), "%s/%s", session,
                 UM_WRAPPER_NAME) >= (int)sizeof(wrapper) ||
        snprintf(init, sizeof(init), "/%s/%s", session_name,
                 UM_WRAPPER_NAME) >= (int)sizeof(init) ||
        snprintf(status, sizeof(status), "%s/status", session) >=
            (int)sizeof(status))
        goto failed;
    session_copy = strdup(session);
    wrapper_copy = strdup(wrapper);
    init_copy = strdup(init);
    *status_path = strdup(status);
    if (session_copy == NULL || wrapper_copy == NULL || init_copy == NULL ||
        *status_path == NULL)
        goto failed;
    *session_path = session_copy;
    *wrapper_path = wrapper_copy;
    *init_path = init_copy;
    return 0;

failed:
    unlink(wrapper);
    rmdir(session);
    free(session_copy);
    free(wrapper_copy);
    free(init_copy);
    free(*status_path);
    *status_path = NULL;
    return -1;
}

int neoproot_um_supervisor_main(int argc, char *const argv[])
{
    UmConfig config;
    char *session_path = NULL;
    char *wrapper_path = NULL;
    char *init_path = NULL;
    char *status_path = NULL;
    char status_guest_path[PATH_MAX];
    const char *session_name;
    int guest_index;
    int result;

    if (argc == 2 && strcmp(argv[1], "--help") == 0) {
        um_print_usage();
        return EXIT_SUCCESS;
    }
    if (argc < 2) {
        um_print_usage();
        return EXIT_FAILURE;
    }
    if (um_check_untraced() < 0 ||
        um_parse_args(argc, argv, &config, &guest_index) < 0)
        return EXIT_FAILURE;
    if (um_make_session(config.resolved_rootfs, &session_path, &wrapper_path,
                        &init_path, &status_path) < 0)
        goto failed;
    session_name = strrchr(session_path, '/') + 1;
    if (snprintf(status_guest_path, sizeof(status_guest_path), "/%s/status",
                 session_name) >= (int)sizeof(status_guest_path))
        goto failed;
    if (um_write_wrapper(wrapper_path, config.cwd, status_guest_path,
                         argc - guest_index,
                         &argv[guest_index]) < 0)
        goto failed;
    result = um_run_kernel(&config, init_path, session_path, status_path);
    unlink(wrapper_path);
    unlink(status_path);
    rmdir(session_path);
    free(session_path);
    free(wrapper_path);
    free(init_path);
    free(status_path);
    free(config.resolved_kernel);
    free(config.resolved_stub);
    free(config.resolved_rootfs);
    return result;

failed:
    if (wrapper_path != NULL)
        unlink(wrapper_path);
    if (status_path != NULL)
        unlink(status_path);
    if (session_path != NULL)
        rmdir(session_path);
    free(session_path);
    free(wrapper_path);
    free(init_path);
    free(status_path);
    free(config.resolved_kernel);
    free(config.resolved_stub);
    free(config.resolved_rootfs);
    return EXIT_FAILURE;
}
