#include "backend/um_supervisor.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <float.h>
#include <limits.h>
#include <math.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

/* Defined next to the other shutdown helpers, far below its first caller. */
static void um_remove_umid_directory(pid_t kernel_pid);

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
#define UM_MAX_BINDS 64

/*
 * Files the supervisor and a session-aware guest init exchange through the
 * session directory (guest path /run/neoproot/<name>).  The init declares what
 * it implements in init-features before it runs init.sh; the supervisor puts
 * the requested binds in binds and any guest-side protocol failure in
 * protocol-error.
 */
#define UM_BINDS_NAME "binds"
#define UM_INIT_FEATURES_NAME "init-features"
#define UM_PROTOCOL_ERROR_NAME "protocol-error"
#define UM_INIT_FEATURE_BINDS "feature=binds"

/*
 * UML COW v3 header, as written by arch/um/drivers/cow_user.c.  Only the
 * fields validated here are named; backing_file and the reserved tail are not
 * interpreted.
 */
#define UM_COW_MAGIC 0x4f4f4f4dU
#define UM_COW_VERSION 3
#define UM_COW_HEADER_SIZE 32U
#define UM_COW_OFFSET_VERSION 4U
#define UM_COW_OFFSET_MTIME 8U
#define UM_COW_OFFSET_SIZE 12U

/* umnet's own arguments before the `--` that introduces the kernel vector */
#define UM_NETWORK_OPTIONS 18
#define UM_MAX_CREATED_PATHS (UM_MAX_BINDS * 4)
#define UM_CLOSE_RANGE_CLOEXEC (1U << 2)

typedef enum {
    UM_ROOTFS_HOSTFS,
    UM_ROOTFS_EXT4
} UmRootfsKind;

/*
 * How the UML kernel runs guest userspace.  The default is the kernel's own
 * default, ptrace: it is slower but does not trust the guest with the host
 * address space.  seccomp is opt-in and the kernel documentation is explicit
 * that its filter is not restrictive enough for untrusted userspace.
 */
typedef enum {
    UM_SECCOMP_OFF,
    UM_SECCOMP_AUTO,
    UM_SECCOMP_ON
} UmSeccompMode;

typedef struct {
    char *host;
    char *guest;
    char *source_guest;
    /*
     * ext4 only: the hostfs mount option that reaches the source, relative to
     * the kernel's hostfs= root (the runtime directory).  The guest init
     * mounts these itself; hostfs is not a directory the ext4 guest can see.
     */
    char *mount_source;
    bool readonly;
    bool source_directory;
} UmBind;

typedef struct {
    const char *kernel;
    const char *stub;
    const char *rootfs;
    const char *cow_file;
    const char *cwd;
    double timeout;
    unsigned int cpus;
    const char *rootflags;
    bool hostfs;
    bool readonly;
    bool quiet;
    UmSeccompMode seccomp;
    bool saw_delimiter;
    UmRootfsKind rootfs_kind;
    char *resolved_kernel;
    char *resolved_stub;
    char *resolved_rootfs;
    char *resolved_cow;
    int rootfs_fd;
    char *resolved_hostfs;
    bool network;
    /*
     * Whether the guest's own side of the link is configured for the caller.
     *
     * --net builds the link (umnet + passt, DHCP *server* included) but does
     * not run a DHCP client inside the guest: the guest is the side that has to
     * ask for an address.  Leaving that to the caller is the honest behaviour,
     * but it means a plain "--net -- /bin/sh" comes up with vec0 down and no
     * route, so every command that reaches the network fails as if there were
     * none.  --net-auto asks this side to configure the guest instead: DHCP
     * first, then a static fallback that uses the address the server was told
     * to hand out, and no failure if neither works (the shell still starts,
     * just without a network).
     */
    bool network_auto;
    char net_addr[32];
    char net_gateway[32];
    char net_dns[32];
    const char *net_mask;
    /*
     * IPv6 is a second, independent helper in umnet.  Empty fields mean "not
     * named", and umnet then uses its own defaults (fd00::2/64, fe80::1) and
     * reads the host's resolv.conf -- the same "no guess from here" rule the
     * IPv4 nameserver follows.
     */
    bool net_ipv6;
    char net_ipv6_addr[64];
    char net_ipv6_gw[64];
    char net_ipv6_dns[64];
    char *resolved_umnet;
    char *resolved_passt;
    UmBind binds[UM_MAX_BINDS];
    size_t bind_count;
    char *created_paths[UM_MAX_CREATED_PATHS];
    size_t created_path_count;
} UmConfig;

typedef struct {
    unsigned char *data;
    size_t start;
    size_t end;
    size_t capacity;
} UmBuffer;

static volatile sig_atomic_t um_requested_signal;
static volatile sig_atomic_t um_window_changed;

static void um_signal_handler(int signal_number)
{
    if (signal_number == SIGWINCH) {
        um_window_changed = 1;
        return;
    }
    um_requested_signal = signal_number;
}

/*
 * Mirror the caller's terminal size onto the guest PTY.
 *
 * Without this the guest keeps the 80x24 default for its whole life, which
 * breaks anything that draws to the terminal -- an editor or a pager lays out
 * for the wrong width and the user sees garbage.  Both directions can fail
 * harmlessly: if our stdin is not a terminal, or the size is unavailable, there
 * is nothing to copy and the PTY keeps whatever it had.
 */
static void um_apply_window_size(int master_fd)
{
    struct winsize size;

    if (ioctl(STDIN_FILENO, TIOCGWINSZ, &size) < 0)
        return;
    if (size.ws_row == 0 || size.ws_col == 0)
        return;
    if (ioctl(master_fd, TIOCSWINSZ, &size) < 0)
        return;
}

/*
 * Nothing to arrange for the resize notification itself: the kernel delivers
 * SIGWINCH to the foreground process group when the terminal changes size, and
 * um_install_signal_handlers() already installs our handler for it.  An
 * F_SETOWN/O_ASYNC dance here would only be a way to lose the flag again,
 * since um_set_nonblocking() owns stdin's flags later in startup.
 */

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

static bool um_path_has_kernel_separator(const char *path)
{
    const unsigned char *cursor = (const unsigned char *)path;

    while (*cursor != '\0') {
        if (*cursor <= ' ' || *cursor == ',')
            return true;
        cursor++;
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

static bool um_is_controlled_guest_path(const char *path)
{
    static const char *const prefixes[] = { "/proc", "/sys", "/dev", NULL };
    size_t index;

    if (strcmp(path, "/") == 0)
        return true;
    for (index = 0; prefixes[index] != NULL; index++) {
        size_t length = strlen(prefixes[index]);

        if (strcmp(path, prefixes[index]) == 0 ||
            (strncmp(path, prefixes[index], length) == 0 &&
             path[length] == '/'))
            return true;
    }
    return false;
}

static void um_free_bind(UmBind *bind)
{
    free(bind->host);
    free(bind->guest);
    free(bind->source_guest);
    free(bind->mount_source);
    memset(bind, 0, sizeof(*bind));
}

static void um_free_config(UmConfig *config)
{
    size_t index;

    free(config->resolved_kernel);
    free(config->resolved_stub);
    free(config->resolved_rootfs);
    free(config->resolved_cow);
    if (config->rootfs_fd >= 0)
        close(config->rootfs_fd);
    free(config->resolved_hostfs);
    free(config->resolved_umnet);
    free(config->resolved_passt);
    for (index = 0; index < config->bind_count; index++)
        um_free_bind(&config->binds[index]);
    for (index = 0; index < config->created_path_count; index++)
        free(config->created_paths[index]);
    memset(config, 0, sizeof(*config));
}

static int um_parse_bind(UmConfig *config, const char *value)
{
    char *copy;
    char *separator;
    char *option;
    UmBind *bind;

    if (config->bind_count >= UM_MAX_BINDS || value == NULL || value[0] == '\0')
        return -1;
    copy = strdup(value);
    if (copy == NULL)
        return -1;
    separator = strchr(copy, ':');
    if (separator == NULL || separator == copy || separator[1] == '\0')
        goto invalid;
    *separator++ = '\0';
    option = strchr(separator, ':');
    if (option != NULL) {
        *option++ = '\0';
        if (strcmp(option, "ro") != 0 || strchr(option, ':') != NULL)
            goto invalid;
    }
    if (um_validate_guest_path("bind target", separator) < 0 ||
        um_is_controlled_guest_path(separator) ||
        copy[0] != '/' || strchr(copy, ',') != NULL)
        goto invalid;
    bind = &config->binds[config->bind_count];
    bind->host = strdup(copy);
    bind->guest = strdup(separator);
    if (bind->host == NULL || bind->guest == NULL)
        goto invalid;
    bind->readonly = option != NULL;
    for (size_t existing = 0; existing < config->bind_count; existing++) {
        if (strcmp(config->binds[existing].guest, bind->guest) == 0)
            goto invalid;
    }
    config->bind_count++;
    free(copy);
    return 0;

invalid:
    if (config->bind_count < UM_MAX_BINDS)
        um_free_bind(&config->binds[config->bind_count]);
    free(copy);
    return -1;
}

static int um_resolve_bind_sources(UmConfig *config)
{
    size_t index;
    size_t root_length = strlen(config->resolved_rootfs);

    for (index = 0; index < config->bind_count; index++) {
        UmBind *bind = &config->binds[index];
        char resolved[PATH_MAX];
        struct stat status;

        if (realpath(bind->host, resolved) == NULL ||
            stat(resolved, &status) < 0) {
            fprintf(stderr, "neoproot-um: cannot resolve bind source '%s': %s\n",
                    bind->host, strerror(errno));
            return -1;
        }
        if (strncmp(resolved, config->resolved_rootfs, root_length) != 0 ||
            (resolved[root_length] != '\0' && resolved[root_length] != '/') ||
            resolved[root_length] == '\0' || strchr(resolved, ',') != NULL) {
            fprintf(stderr, "neoproot-um: bind source '%s' escapes rootfs\n",
                    bind->host);
            return -1;
        }
        {
            const char *relative = resolved + root_length;

            if (relative[0] == '\0')
                return -1;
            free(bind->source_guest);
            bind->source_guest = strdup(relative);
        }
        free(bind->host);
        bind->host = strdup(resolved);
        bind->source_directory = S_ISDIR(status.st_mode);
        if (!bind->source_directory && !S_ISREG(status.st_mode)) {
            fprintf(stderr, "neoproot-um: bind source must be a file or directory: %s\n",
                    resolved);
            return -1;
        }
        if (bind->host == NULL || bind->source_guest == NULL)
            return -1;
    }
    return 0;
}

static int um_bind_compare(const void *left, const void *right)
{
    const UmBind *a = left;
    const UmBind *b = right;
    size_t a_length = strlen(a->guest);
    size_t b_length = strlen(b->guest);

    if (a_length < b_length)
        return -1;
    if (a_length > b_length)
        return 1;
    return strcmp(a->guest, b->guest);
}

static int um_record_created_path(UmConfig *config, const char *path)
{
    if (config->created_path_count >= UM_MAX_CREATED_PATHS)
        return -1;
    config->created_paths[config->created_path_count] = strdup(path);
    if (config->created_paths[config->created_path_count] == NULL)
        return -1;
    config->created_path_count++;
    return 0;
}

static int um_ensure_bind_parent(UmConfig *config, const char *root,
                                 const char *parent)
{
    char path[PATH_MAX];
    size_t root_length = strlen(root);
    size_t length;
    size_t index;

    if (strncmp(parent, root, root_length) != 0 ||
        (parent[root_length] != '\0' && parent[root_length] != '/') ||
        strlen(parent) >= sizeof(path))
        return -1;
    strcpy(path, parent);
    length = strlen(path);
    for (index = root_length + 1; index <= length; index++) {
        struct stat status;
        char saved;

        if (index != length && path[index] != '/')
            continue;
        saved = path[index];
        path[index] = '\0';
        if (lstat(path, &status) < 0) {
            if (errno != ENOENT || mkdir(path, 0700) < 0 ||
                um_record_created_path(config, path) < 0)
                return -1;
            if (lstat(path, &status) < 0)
                return -1;
        }
        path[index] = saved;
        if (S_ISLNK(status.st_mode) || !S_ISDIR(status.st_mode))
            return -1;
    }
    return 0;
}

static int um_prepare_bind_targets(UmConfig *config)
{
    size_t index;
    size_t root_length = strlen(config->resolved_rootfs);

    for (index = 0; index < config->bind_count; index++) {
        const UmBind *bind = &config->binds[index];
        char target[PATH_MAX];
        char parent[PATH_MAX];
        char parent_real[PATH_MAX];
        struct stat status;
        char *last_slash;
        int length;

        length = snprintf(target, sizeof(target), "%s%s",
                          config->resolved_rootfs, bind->guest);
        if (length < 0 || (size_t)length >= sizeof(target))
            return -1;
        snprintf(parent, sizeof(parent), "%s", target);
        last_slash = strrchr(parent, '/');
        if (last_slash == NULL || last_slash == parent)
            strcpy(parent, config->resolved_rootfs);
        else
            *last_slash = '\0';
        if (um_ensure_bind_parent(config, config->resolved_rootfs, parent) < 0 ||
            realpath(parent, parent_real) == NULL ||
            strncmp(parent_real, config->resolved_rootfs, root_length) != 0 ||
            (parent_real[root_length] != '\0' &&
             parent_real[root_length] != '/')) {
            fprintf(stderr, "neoproot-um: bind target parent escapes rootfs: %s\n",
                    bind->guest);
            return -1;
        }
        if (lstat(target, &status) == 0) {
            if (S_ISLNK(status.st_mode) ||
                (bind->source_directory && !S_ISDIR(status.st_mode)) ||
                (!bind->source_directory && !S_ISREG(status.st_mode))) {
                fprintf(stderr, "neoproot-um: bind target type mismatch: %s\n",
                        bind->guest);
                return -1;
            }
            continue;
        }
        if (errno != ENOENT)
            return -1;
        if (bind->source_directory) {
            if (mkdir(target, 0700) < 0) {
                if (errno != EEXIST)
                    return -1;
            } else if (um_record_created_path(config, target) < 0) {
                return -1;
            }
        } else {
            int fd = open(target, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);

            if (fd < 0 && errno != EEXIST)
                return -1;
            if (fd >= 0) {
                close(fd);
                if (um_record_created_path(config, target) < 0)
                    return -1;
            }
        }
    }
    return 0;
}

static void um_cleanup_created_paths(UmConfig *config)
{
    while (config->created_path_count > 0) {
        const char *path = config->created_paths[--config->created_path_count];
        struct stat status;

        if (lstat(path, &status) == 0) {
            if (S_ISDIR(status.st_mode))
                (void)rmdir(path);
            else
                (void)unlink(path);
        }
        free(config->created_paths[config->created_path_count]);
        config->created_paths[config->created_path_count] = NULL;
    }
}

/*
 * Express a host path as a hostfs mount option.
 *
 * The kernel resolves a hostfs mount option as "<hostfs= root>/<option>", so
 * reaching an arbitrary host path from the runtime directory means walking up
 * to "/" and back down.  Both strings are realpath() output, so every '/'
 * separates a component and the count is exact.  The guest init passes the
 * result straight to mount -t hostfs -o, which is how an ext4 guest -- whose
 * root is an image file -- gets at a host directory or file.
 */
static int um_hostfs_mount_source(const char *root, const char *path,
                                  char **result)
{
    size_t components = 0;
    size_t path_length;
    char *value;
    char *cursor;
    const char *relative = path;
    const char *scan;

    for (scan = root; *scan != '\0'; scan++)
        if (*scan == '/')
            components++;
    while (*relative == '/')
        relative++;
    path_length = strlen(relative);
    value = malloc(components * 3 + path_length + 1);
    if (value == NULL) {
        perror("neoproot-um: malloc");
        return -1;
    }
    cursor = value;
    for (size_t index = 0; index < components; index++) {
        memcpy(cursor, "../", 3);
        cursor += 3;
    }
    memcpy(cursor, relative, path_length + 1);
    *result = value;
    return 0;
}

/*
 * Resolve "-b HOST:GUEST[:ro]" for an ext4 root.
 *
 * In hostfs mode the source lives inside the directory the guest sees as "/",
 * so the wrapper binds it by guest path.  An ext4 guest has its own root, and
 * the only host directory it can reach is the runtime directory through
 * hostfs.  So the supervisor hands the guest a mount option per source (see
 * um_hostfs_mount_source) and the guest init performs the mount.  The hostfs
 * mount of a file is not possible, so a file source is described by its parent
 * directory plus a name.
 */
static int um_prepare_ext4_binds(UmConfig *config)
{
    size_t index;

    if (config->rootfs_kind != UM_ROOTFS_EXT4 || config->bind_count == 0)
        return 0;
    /* Shortest guest path first, so a bind inside another bind is mounted
     * after the directory that contains it. */
    qsort(config->binds, config->bind_count, sizeof(config->binds[0]),
          um_bind_compare);
    for (index = 0; index < config->bind_count; index++) {
        UmBind *bind = &config->binds[index];
        char resolved[PATH_MAX];
        char directory[PATH_MAX];
        struct stat status;
        char *slash;

        if (realpath(bind->host, resolved) == NULL ||
            stat(resolved, &status) < 0) {
            fprintf(stderr, "neoproot-um: cannot resolve bind source '%s': %s\n",
                    bind->host, strerror(errno));
            return -1;
        }
        if (!S_ISDIR(status.st_mode) && !S_ISREG(status.st_mode)) {
            fprintf(stderr,
                    "neoproot-um: bind source must be a file or directory: %s\n",
                    resolved);
            return -1;
        }
        /*
         * The guest reads one record per line with tab-separated fields, so a
         * control character in a host path would corrupt the protocol instead
         * of failing it.
         */
        if (strpbrk(resolved, "\t\n\r") != NULL) {
            fprintf(stderr,
                    "neoproot-um: bind source contains an unsupported character: %s\n",
                    resolved);
            return -1;
        }
        free(bind->host);
        bind->host = strdup(resolved);
        if (bind->host == NULL) {
            perror("neoproot-um: strdup");
            return -1;
        }
        bind->source_directory = S_ISDIR(status.st_mode);
        if (snprintf(directory, sizeof(directory), "%s", resolved) >=
            (int)sizeof(directory))
            return -1;
        if (!bind->source_directory) {
            slash = strrchr(directory, '/');
            if (slash == NULL)
                return -1;
            if (slash == directory)
                directory[1] = '\0';
            else
                *slash = '\0';
        }
        free(bind->mount_source);
        bind->mount_source = NULL;
        if (um_hostfs_mount_source(config->resolved_hostfs, directory,
                                   &bind->mount_source) < 0)
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
    if (um_path_has_kernel_separator(resolved)) {
        fprintf(stderr, "neoproot-um: %s contains an unsupported character\n",
                name);
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

/*
 * Resolve a helper by name, searching PATH when the value has no separator.
 * umnet and passt are normally installed beside the neoproot-um binary or on
 * PATH, so a bare name has to work.
 */
static int um_resolve_helper(const char *name, const char *value, char **result)
{
    const char *path;
    char candidate[PATH_MAX];

    if (strchr(value, '/') != NULL)
        return um_resolve_host_path(name, value, false, true, result);

    path = getenv("PATH");
    if (path == NULL || path[0] == '\0')
        path = "/usr/bin:/bin";

    while (*path != '\0') {
        const char *end = strchr(path, ':');
        size_t length = end != NULL ? (size_t)(end - path) : strlen(path);

        if (length == 0) {
            if (snprintf(candidate, sizeof(candidate), "./%s", value) >=
                (int)sizeof(candidate))
                return -1;
        } else {
            if (length + strlen(value) + 2 > sizeof(candidate))
                return -1;
            memcpy(candidate, path, length);
            candidate[length] = '/';
            snprintf(candidate + length + 1, sizeof(candidate) - length - 1,
                     "%s", value);
        }
        if (access(candidate, X_OK) == 0)
            return um_resolve_host_path(name, candidate, false, true, result);
        if (end == NULL)
            break;
        path = end + 1;
    }

    fprintf(stderr, "neoproot-um: cannot find %s '%s' on PATH\n", name, value);
    return -1;
}


static int um_resolve_ext4_image(const char *value, char **result,
                                 int *image_fd)
{
    unsigned char magic[2];
    struct stat link_status;
    struct stat status;
    char resolved[PATH_MAX];
    int fd = -1;
    ssize_t length;

    if (um_validate_guest_path("rootfs", value) < 0 ||
        strchr(value, ',') != NULL || strchr(value, ':') != NULL ||
        um_path_has_kernel_separator(value))
        return -1;
    if (lstat(value, &link_status) < 0 || S_ISLNK(link_status.st_mode)) {
        fprintf(stderr, "neoproot-um: rootfs image must not be a symlink\n");
        return -1;
    }
    if (realpath(value, resolved) == NULL ||
        lstat(resolved, &status) < 0 || !S_ISREG(status.st_mode)) {
        fprintf(stderr, "neoproot-um: rootfs image must be a regular file\n");
        return -1;
    }
    fd = open(resolved, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        fprintf(stderr, "neoproot-um: cannot open rootfs image '%s': %s\n",
                resolved, strerror(errno));
        return -1;
    }
    if (fd < 3) {
        int duplicate = fcntl(fd, F_DUPFD_CLOEXEC, 3);

        if (duplicate < 0) {
            close(fd);
            return -1;
        }
        close(fd);
        fd = duplicate;
    }
    if (fstat(fd, &status) < 0 || status.st_size < 1024 + 0x3a) {
        fprintf(stderr, "neoproot-um: rootfs image is too small\n");
        close(fd);
        return -1;
    }
    length = pread(fd, magic, sizeof(magic), 1024 + 0x38);
    if (length != (ssize_t)sizeof(magic) || magic[0] != 0x53 ||
        magic[1] != 0xef) {
        fprintf(stderr, "neoproot-um: rootfs image is not ext4\n");
        close(fd);
        return -1;
    }
    *result = strdup(resolved);
    if (*result == NULL) {
        perror("neoproot-um: strdup");
        close(fd);
        return -1;
    }
    *image_fd = fd;
    return 0;
}

static uint32_t um_be32(const unsigned char *value)
{
    return ((uint32_t)value[0] << 24) | ((uint32_t)value[1] << 16) |
           ((uint32_t)value[2] << 8) | (uint32_t)value[3];
}

static uint32_t um_le32(const unsigned char *value)
{
    return ((uint32_t)value[3] << 24) | ((uint32_t)value[2] << 16) |
           ((uint32_t)value[1] << 8) | (uint32_t)value[0];
}

static uint64_t um_be64(const unsigned char *value)
{
    return ((uint64_t)um_be32(value) << 32) | (uint64_t)um_be32(value + 4);
}

/*
 * Judge an existing COW file before the kernel sees it.
 *
 * A COW file is only reusable with the image it was created for: its v3 header
 * records the backing file's size and mtime.  The kernel checks the same two
 * values, but it does so while opening the root device, and answers a mismatch
 * with a failed mount and a panic -- after the caller has already waited for a
 * boot.  Checking here turns that into a message and an exit status.
 *
 * Files in the older v1/v2 formats are left to the kernel, which still reads
 * them; only the format this kernel writes is interpreted.
 */
static int um_check_cow_file(const char *cow_path, const char *image_path)
{
    unsigned char header[UM_COW_HEADER_SIZE];
    struct stat image;
    uint32_t magic;
    uint32_t version;
    uint32_t mtime;
    uint64_t size;
    ssize_t length;
    int fd;

    fd = open(cow_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        fprintf(stderr, "neoproot-um: cannot open cow file '%s': %s\n",
                cow_path, strerror(errno));
        return -1;
    }
    length = read(fd, header, sizeof(header));
    close(fd);
    if (length != (ssize_t)sizeof(header)) {
        fprintf(stderr, "neoproot-um: cow file is not a UML COW file: %s\n",
                cow_path);
        return -1;
    }
    magic = um_be32(header);
    if (magic != UM_COW_MAGIC) {
        if (um_le32(header) != UM_COW_MAGIC) {
            fprintf(stderr,
                    "neoproot-um: cow file is not a UML COW file: %s\n",
                    cow_path);
            return -1;
        }
        return 0;
    }
    version = um_be32(header + UM_COW_OFFSET_VERSION);
    if (version != UM_COW_VERSION)
        return 0;
    mtime = um_be32(header + UM_COW_OFFSET_MTIME);
    size = um_be64(header + UM_COW_OFFSET_SIZE);
    if (stat(image_path, &image) < 0) {
        fprintf(stderr, "neoproot-um: cannot stat rootfs image '%s': %s\n",
                image_path, strerror(errno));
        return -1;
    }
    if (size != (uint64_t)image.st_size ||
        mtime != (uint32_t)image.st_mtime) {
        fprintf(stderr,
                "neoproot-um: cow file '%s' was created for a different rootfs image\n",
                cow_path);
        fprintf(stderr,
                "neoproot-um: remove it, or use another --cow-file\n");
        return -1;
    }
    return 0;
}

/*
 * Validate and canonicalise a caller-supplied COW file.
 *
 * The kernel opens it by name, so every property it relies on has to hold
 * before the run: an absolute path with no kernel-separator characters, a
 * parent directory that exists, and -- when the file is already there -- either
 * a COW header written for this very image or nothing at all.
 */
static int um_resolve_cow_file(const UmConfig *config, char **result)
{
    const char *value = config->cow_file;
    char parent[PATH_MAX];
    char directory[PATH_MAX];
    char full[PATH_MAX];
    char name[PATH_MAX];
    struct stat status;
    struct stat image;
    char *slash;

    if (um_validate_guest_path("cow file", value) < 0)
        return -1;
    if (um_path_has_kernel_separator(value)) {
        fprintf(stderr,
                "neoproot-um: cow file contains an unsupported character\n");
        return -1;
    }
    if (snprintf(parent, sizeof(parent), "%s", value) >=
        (int)sizeof(parent)) {
        fprintf(stderr, "neoproot-um: cow file path is too long\n");
        return -1;
    }
    slash = strrchr(parent, '/');
    if (snprintf(name, sizeof(name), "%s", slash + 1) >= (int)sizeof(name))
        return -1;
    if (slash == parent)
        strcpy(parent, "/");
    else
        *slash = '\0';
    if (realpath(parent, directory) == NULL) {
        fprintf(stderr,
                "neoproot-um: cow file directory is not usable: %s: %s\n",
                parent, strerror(errno));
        return -1;
    }
    if (snprintf(full, sizeof(full), "%s/%s",
                 strcmp(directory, "/") == 0 ? "" : directory, name) >=
        (int)sizeof(full)) {
        fprintf(stderr, "neoproot-um: cow file path is too long\n");
        return -1;
    }
    if (lstat(value, &status) == 0) {
        if (S_ISLNK(status.st_mode)) {
            fprintf(stderr,
                    "neoproot-um: cow file must not be a symlink: %s\n",
                    value);
            return -1;
        }
    } else if (errno != ENOENT) {
        fprintf(stderr, "neoproot-um: cannot stat cow file '%s': %s\n",
                value, strerror(errno));
        return -1;
    }
    if (lstat(full, &status) == 0) {
        if (!S_ISREG(status.st_mode)) {
            fprintf(stderr,
                    "neoproot-um: cow file must be a regular file: %s\n",
                    full);
            return -1;
        }
        if (stat(config->resolved_rootfs, &image) == 0 &&
            image.st_dev == status.st_dev && image.st_ino == status.st_ino) {
            fprintf(stderr,
                    "neoproot-um: cow file must not be the rootfs image: %s\n",
                    full);
            return -1;
        }
        if (status.st_size == 0) {
            /*
             * A zero-length file cannot hold a COW header, so the kernel would
             * refuse it.  It is a placeholder -- "touch the path, then run" --
             * and removing it is what lets the kernel create the COW there.
             */
            if (unlink(full) < 0) {
                fprintf(stderr,
                        "neoproot-um: cannot replace empty cow file '%s': %s\n",
                        full, strerror(errno));
                return -1;
            }
        } else if (um_check_cow_file(full, config->resolved_rootfs) < 0) {
            return -1;
        }
    } else if (errno != ENOENT) {
        fprintf(stderr, "neoproot-um: cannot stat cow file '%s': %s\n",
                full, strerror(errno));
        return -1;
    }
    *result = strdup(full);
    if (*result == NULL) {
        perror("neoproot-um: strdup");
        return -1;
    }
    return 0;
}

static void um_remove_runtime_marker(const char *runtime_path);

static int um_write_runtime_marker(const char *runtime_path)
{
    char owner_path[PATH_MAX];
    char owner_data[64];
    int owner_fd;

    if (runtime_path == NULL ||
        snprintf(owner_path, sizeof(owner_path), "%s/.owner", runtime_path) >=
            (int)sizeof(owner_path) ||
        snprintf(owner_data, sizeof(owner_data), "neoproot-um-owner:%ld\n",
                 (long)getpid()) >= (int)sizeof(owner_data))
        return -1;
    owner_fd = open(owner_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC |
                    O_NOFOLLOW, 0600);
    if (owner_fd < 0)
        return -1;
    if (um_write_text(owner_fd, owner_data) < 0 || fsync(owner_fd) < 0) {
        close(owner_fd);
        unlink(owner_path);
        return -1;
    }
    close(owner_fd);
    return 0;
}

static int um_make_runtime_root(char **result)
{
    const char *tmpdir = getenv("TMPDIR");
    char template[PATH_MAX];
    char resolved[PATH_MAX];
    struct stat status;
    char *copy;

    if (tmpdir == NULL || tmpdir[0] != '/' ||
        um_path_has_kernel_separator(tmpdir) || strlen(tmpdir) >= PATH_MAX - 32)
        tmpdir = "/tmp";
    if (stat(tmpdir, &status) < 0 || !S_ISDIR(status.st_mode))
        tmpdir = "/tmp";
    if (snprintf(template, sizeof(template), "%s/neoproot-um-XXXXXX",
                 tmpdir) >= (int)sizeof(template))
        return -1;
    if (mkdtemp(template) == NULL) {
        fprintf(stderr, "neoproot-um: cannot create runtime directory: %s\n",
                strerror(errno));
        return -1;
    }
    /*
     * Canonicalise before anyone remembers the path.  It is handed to the
     * kernel as hostfs= and the guest's bind mount options are computed
     * relative to it, so a symlinked TMPDIR component would make ".." refer to
     * the link's target's parent rather than to the parent of this name.
     */
    if (realpath(template, resolved) == NULL) {
        fprintf(stderr,
                "neoproot-um: cannot resolve runtime directory '%s': %s\n",
                template, strerror(errno));
        rmdir(template);
        return -1;
    }
    if (chmod(resolved, 0700) < 0) {
        rmdir(resolved);
        return -1;
    }
    if (um_write_runtime_marker(resolved) < 0) {
        rmdir(resolved);
        return -1;
    }
    copy = strdup(resolved);
    if (copy == NULL) {
        um_remove_runtime_marker(resolved);
        rmdir(resolved);
        return -1;
    }
    *result = copy;
    return 0;
}

static void um_remove_runtime_marker(const char *runtime_path)
{
    char owner_path[PATH_MAX];

    if (runtime_path == NULL ||
        snprintf(owner_path, sizeof(owner_path), "%s/.owner", runtime_path) >=
            (int)sizeof(owner_path))
        return;
    (void)unlink(owner_path);
}

static int um_cleanup_runtime_root(const char *runtime_path)
{
    int result;

    if (runtime_path == NULL)
        return -1;
    um_remove_runtime_marker(runtime_path);
    result = rmdir(runtime_path);
    if (result < 0) {
        (void)um_write_runtime_marker(runtime_path);
        fprintf(stderr, "neoproot-um: runtime directory retained: %s\n",
                runtime_path);
    }
    return result;
}

static int um_parse_cpus(const char *value, unsigned int *cpus)
{
    char *end;
    unsigned long parsed;

    if (value[0] == '\0')
        return -1;
    errno = 0;
    parsed = strtoul(value, &end, 10);
    if (errno != 0 || *end != '\0' || parsed < 1 || parsed > 64)
        return -1;
    *cpus = (unsigned int)parsed;
    return 0;
}

/*
 * rootflags reaches the guest kernel's ext4 mount.  Keep it to characters that
 * mount options actually use and that cannot terminate or split the kernel
 * command line; the value is still the caller's choice of mount semantics, not
 * a second command line.
 */
static int um_set_rootflags(const char *value, const char **rootflags)
{
    size_t index;

    if (value[0] == '\0' || strlen(value) > 256)
        return -1;
    for (index = 0; value[index] != '\0'; index++) {
        unsigned char character = (unsigned char)value[index];

        if (!isalnum(character) && strchr(",=._-", character) == NULL)
            return -1;
    }
    *rootflags = value;
    return 0;
}

static int um_parse_seccomp_mode(const char *value, UmSeccompMode *mode)
{
    if (strcmp(value, "off") == 0) {
        *mode = UM_SECCOMP_OFF;
        return 0;
    }
    if (strcmp(value, "auto") == 0) {
        *mode = UM_SECCOMP_AUTO;
        return 0;
    }
    if (strcmp(value, "on") == 0) {
        *mode = UM_SECCOMP_ON;
        return 0;
    }
    return -1;
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

/*
 * Copy one network value into its fixed buffer.
 *
 * Empty values, values that do not fit, and values carrying whitespace or a
 * comma are refused here rather than handed to umnet: a malformed argument
 * would be rejected by umnet with a message naming its own parser instead of
 * the option the caller actually wrote.
 */
static int um_set_net_value(char *destination, size_t size, const char *value)
{
    size_t index;

    if (value[0] == '\0')
        return -1;
    for (index = 0; value[index] != '\0'; index++)
        if (isspace((unsigned char)value[index]) || value[index] == ',')
            return -1;
    if (snprintf(destination, size, "%s", value) >= (int)size)
        return -1;
    return 0;
}

static int um_parse_args(int argc, char *const argv[], UmConfig *config,
                         int *guest_index)
{
    int index;
    bool kernel_set = false;
    bool stub_set = false;
    bool rootfs_set = false;
    bool cow_file_set = false;
    bool cwd_set = false;
    bool timeout_set = false;
    bool cpus_set = false;
    bool rootflags_set = false;
    bool seccomp_set = false;
    bool ipv6_flag_set = false;
    bool ipv6_requested = false;

    memset(config, 0, sizeof(*config));
    config->rootfs_fd = -1;
    config->cwd = "/";
    config->timeout = 120.0;
    config->cpus = 1;
    snprintf(config->net_addr, sizeof(config->net_addr), "%s", "10.0.2.15");
    snprintf(config->net_gateway, sizeof(config->net_gateway), "%s", "10.0.2.2");
    /*
     * net_dns is deliberately left empty: no nameserver is announced unless
     * the caller asks for one, and umnet then works it out from the host's
     * resolv.conf.  A literal here is a guess about the network rather than
     * about the build -- 1.1.1.1 was that guess, and on a network that blocks
     * it the guest loses DNS while everything else still looks healthy.
     */
    config->net_mask = "24";

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
        } else if (strcmp(argument, "--cow-file") == 0) {
            if (++index >= argc || cow_file_set || argv[index][0] == '\0')
                goto invalid;
            config->cow_file = argv[index];
            cow_file_set = true;
        } else if (strncmp(argument, "--cow-file=", 11) == 0) {
            if (cow_file_set || argument[11] == '\0')
                goto invalid;
            config->cow_file = argument + 11;
            cow_file_set = true;
        } else if (strcmp(argument, "-b") == 0 ||
                   strcmp(argument, "--bind") == 0) {
            if (++index >= argc || um_parse_bind(config, argv[index]) < 0)
                goto invalid;
        } else if (strncmp(argument, "--bind=", 7) == 0 ||
                   strncmp(argument, "--mount=", 8) == 0) {
            const char *value = argument +
                (argument[2] == 'b' ? 7 : 8);

            if (um_parse_bind(config, value) < 0)
                goto invalid;
        } else if (strcmp(argument, "-m") == 0 ||
                   strcmp(argument, "--mount") == 0) {
            if (++index >= argc || um_parse_bind(config, argv[index]) < 0)
                goto invalid;
        } else if (strcmp(argument, "--net") == 0) {
            if (config->network)
                goto invalid;
            config->network = true;
        } else if (strcmp(argument, "--net-auto") == 0) {
            if (config->network_auto)
                goto invalid;
            config->network_auto = true;
            config->network = true;
        } else if (strncmp(argument, "--net-addr=", 11) == 0) {
            if (argument[11] == '\0' ||
                snprintf(config->net_addr, sizeof(config->net_addr), "%s",
                         argument + 11) >= (int)sizeof(config->net_addr))
                goto invalid;
        } else if (strncmp(argument, "--net-gateway=", 14) == 0) {
            if (argument[14] == '\0' ||
                snprintf(config->net_gateway, sizeof(config->net_gateway), "%s",
                         argument + 14) >= (int)sizeof(config->net_gateway))
                goto invalid;
        } else if (strncmp(argument, "--net-dns=", 10) == 0) {
            if (argument[10] == '\0' ||
                snprintf(config->net_dns, sizeof(config->net_dns), "%s",
                         argument + 10) >= (int)sizeof(config->net_dns))
                goto invalid;
        } else if (strcmp(argument, "--net-ipv6") == 0) {
            if (ipv6_flag_set)
                goto invalid;
            ipv6_flag_set = true;
            ipv6_requested = true;
            config->net_ipv6 = true;
        } else if (strncmp(argument, "--net-ipv6-addr=", 16) == 0) {
            if (um_set_net_value(config->net_ipv6_addr,
                                 sizeof(config->net_ipv6_addr),
                                 argument + 16) < 0)
                goto invalid;
            ipv6_requested = true;
            config->net_ipv6 = true;
        } else if (strncmp(argument, "--net-ipv6-gw=", 14) == 0) {
            if (um_set_net_value(config->net_ipv6_gw,
                                 sizeof(config->net_ipv6_gw),
                                 argument + 14) < 0)
                goto invalid;
            ipv6_requested = true;
            config->net_ipv6 = true;
        } else if (strncmp(argument, "--net-ipv6-dns=", 15) == 0) {
            if (um_set_net_value(config->net_ipv6_dns,
                                 sizeof(config->net_ipv6_dns),
                                 argument + 15) < 0)
                goto invalid;
            ipv6_requested = true;
            config->net_ipv6 = true;
        } else if (strcmp(argument, "--hostfs") == 0) {
            if (config->hostfs)
                goto invalid;
            config->hostfs = true;
        } else if (strcmp(argument, "--readonly") == 0) {
            if (config->readonly)
                goto invalid;
            config->readonly = true;
        } else if (strncmp(argument, "--seccomp=", 10) == 0) {
            if (seccomp_set ||
                um_parse_seccomp_mode(argument + 10, &config->seccomp) < 0) {
                fprintf(stderr,
                        "neoproot-um: --seccomp expects off, auto, or on\n");
                return -1;
            }
            seccomp_set = true;
        } else if (strcmp(argument, "--quiet") == 0) {
            if (config->quiet)
                goto invalid;
            config->quiet = true;
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
        } else if (strncmp(argument, "--cpus=", 7) == 0 ||
                   strncmp(argument, "--ncpus=", 8) == 0) {
            const char *value = argument + (argument[2] == 'c' ? 7 : 8);

            if (cpus_set || um_parse_cpus(value, &config->cpus) < 0) {
                fprintf(stderr,
                        "neoproot-um: --cpus expects a value from 1 to 64\n");
                return -1;
            }
            cpus_set = true;
        } else if (strncmp(argument, "--rootflags=", 12) == 0) {
            if (rootflags_set ||
                um_set_rootflags(argument + 12, &config->rootflags) < 0) {
                fprintf(stderr,
                        "neoproot-um: --rootflags expects comma-separated "
                        "ext4 mount options\n");
                return -1;
            }
            rootflags_set = true;
        } else {
            goto invalid;
        }
    }
    if (!config->saw_delimiter || index >= argc) {
        fprintf(stderr, "neoproot-um: use -- before the guest command\n");
        return -1;
    }
    *guest_index = index;

    if (!rootfs_set) {
        fprintf(stderr, "neoproot-um: --rootfs is required\n");
        return -1;
    }
    /*
     * IPv6 is a mode of the network, not a network of its own: there is no
     * helper to start without --net, and accepting the option silently would
     * promise a guest a stack it never gets.
     */
    if (ipv6_requested && !config->network) {
        fprintf(stderr,
                "neoproot-um: --net-ipv6 options require --net\n");
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
    if (um_validate_guest_path("cwd", config->cwd) < 0 ||
        um_path_has_kernel_separator(config->cwd))
        return -1;
    if (um_resolve_host_path("kernel", config->kernel, false, true,
                             &config->resolved_kernel) < 0 ||
        um_resolve_host_path("stub", config->stub, false, true,
                             &config->resolved_stub) < 0)
        return -1;
    {
        struct stat root_status;

        if (stat(config->rootfs, &root_status) < 0) {
            fprintf(stderr, "neoproot-um: cannot stat rootfs '%s': %s\n",
                    config->rootfs, strerror(errno));
            return -1;
        }
        if (S_ISDIR(root_status.st_mode)) {
            if (config->readonly) {
                fprintf(stderr, "neoproot-um: --readonly requires an ext4 image\n");
                return -1;
            }
            if (config->cow_file != NULL) {
                fprintf(stderr,
                        "neoproot-um: --cow-file requires an ext4 rootfs image\n");
                return -1;
            }
            config->rootfs_kind = UM_ROOTFS_HOSTFS;
            if (um_resolve_host_path("rootfs", config->rootfs, true, false,
                                     &config->resolved_rootfs) < 0)
                return -1;
            config->resolved_hostfs = strdup(config->resolved_rootfs);
            if (config->resolved_hostfs == NULL) {
                perror("neoproot-um: strdup");
                return -1;
            }
        } else {
            if (config->hostfs) {
                fprintf(stderr, "neoproot-um: --hostfs requires a rootfs directory\n");
                return -1;
            }
            config->rootfs_kind = UM_ROOTFS_EXT4;
            if (um_resolve_ext4_image(config->rootfs,
                                      &config->resolved_rootfs,
                                      &config->rootfs_fd) < 0)
                return -1;
            if (config->cow_file != NULL) {
                if (config->readonly) {
                    fprintf(stderr,
                            "neoproot-um: --cow-file and --readonly are mutually exclusive\n");
                    return -1;
                }
                if (um_resolve_cow_file(config, &config->resolved_cow) < 0)
                    return -1;
            }
        }
        if (config->rootfs_kind == UM_ROOTFS_HOSTFS &&
            config->resolved_hostfs == NULL)
            return -1;
    }
    if (config->rootflags != NULL &&
        config->rootfs_kind != UM_ROOTFS_EXT4) {
        fprintf(stderr,
                "neoproot-um: --rootflags requires an ext4 rootfs image\n");
        return -1;
    }
    if (config->cpus > 1 && config->seccomp == UM_SECCOMP_OFF) {
        fprintf(stderr,
                "neoproot-um: --cpus greater than 1 requires --seccomp=auto "
                "or --seccomp=on; ptrace userspace runs on one CPU\n");
        return -1;
    }
    if (config->rootfs_kind == UM_ROOTFS_HOSTFS) {
        if (config->bind_count > 0 && um_resolve_bind_sources(config) < 0)
            return -1;
        if (config->bind_count > 0) {
            qsort(config->binds, config->bind_count, sizeof(config->binds[0]),
                  um_bind_compare);
            if (um_prepare_bind_targets(config) < 0)
                return -1;
        }
    }
    if (config->rootfs_kind == UM_ROOTFS_EXT4 && config->hostfs) {
        fprintf(stderr, "neoproot-um: invalid hostfs mode for ext4 image\n");
        return -1;
    }
    if (config->network) {
        const char *umnet = getenv("NEOPROOT_UM_NET");
        const char *passt = getenv("NEOPROOT_UM_PASST");

        if (umnet == NULL || umnet[0] == '\0')
            umnet = "umnet";
        if (passt == NULL || passt[0] == '\0')
            passt = "passt";
        if (um_resolve_helper("umnet", umnet, &config->resolved_umnet) < 0 ||
            um_resolve_helper("passt", passt, &config->resolved_passt) < 0) {
            fprintf(stderr,
                    "neoproot-um: --net needs umnet and passt; set "
                    "NEOPROOT_UM_NET/NEOPROOT_UM_PASST or put them on PATH\n");
            return -1;
        }
    }
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

/*
 * Hand the requested ext4 binds to the guest init.
 *
 * The session directory is already the channel for init.sh and the command
 * status, and it is the only host directory the guest can see, so the list
 * travels the same way.  One record per line, tab-separated:
 *
 *     source<TAB>target<TAB>dir|file<TAB>ro|rw<TAB>name
 *
 * source is the hostfs mount option computed by um_prepare_ext4_binds (the
 * init passes it to mount -t hostfs -o), name is the basename of a file bind
 * and "-" for a directory bind.  Lines starting with '#' are ignored.
 */
static int um_write_binds_file(const UmConfig *config,
                               const char *session_path)
{
    char path[PATH_MAX];
    size_t index;
    int fd;

    if (config->rootfs_kind != UM_ROOTFS_EXT4 || config->bind_count == 0)
        return 0;
    if (snprintf(path, sizeof(path), "%s/%s", session_path, UM_BINDS_NAME) >=
        (int)sizeof(path)) {
        fprintf(stderr, "neoproot-um: session path is too long\n");
        return -1;
    }
    fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
              0600);
    if (fd < 0) {
        fprintf(stderr, "neoproot-um: cannot create bind list '%s': %s\n",
                path, strerror(errno));
        return -1;
    }
    if (um_write_text(fd,
                      "# neoproot binds v1\n"
                      "# source<TAB>target<TAB>dir|file<TAB>ro|rw<TAB>name\n") <
        0)
        goto failed;
    for (index = 0; index < config->bind_count; index++) {
        const UmBind *bind = &config->binds[index];
        const char *name = strrchr(bind->host, '/');

        name = name != NULL ? name + 1 : bind->host;
        if (um_write_text(fd, bind->mount_source) < 0 ||
            um_write_text(fd, "\t") < 0 ||
            um_write_text(fd, bind->guest) < 0 ||
            um_write_text(fd, "\t") < 0 ||
            um_write_text(fd, bind->source_directory ? "dir" : "file") < 0 ||
            um_write_text(fd, "\t") < 0 ||
            um_write_text(fd, bind->readonly ? "ro" : "rw") < 0 ||
            um_write_text(fd, "\t") < 0 ||
            um_write_text(fd, bind->source_directory ? "-" : name) < 0 ||
            um_write_text(fd, "\n") < 0)
            goto failed;
    }
    if (fsync(fd) < 0)
        goto failed;
    if (close(fd) < 0) {
        unlink(path);
        return -1;
    }
    return 0;

failed:
    fprintf(stderr, "neoproot-um: failed to write bind list '%s': %s\n",
            path, strerror(errno));
    close(fd);
    unlink(path);
    return -1;
}

static int um_write_wrapper(const char *wrapper_path, const char *cwd,
                            const char *status_path, const UmConfig *config,
                            bool ext4_rootfs, bool ext4_binds,
                            int guest_argc,
                            char *const guest_argv[])
{
    int fd;
    char **environment;
    int index;
    size_t bind_index;

    fd = open(wrapper_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC |
              O_NOFOLLOW, 0700);
    if (fd < 0) {
        fprintf(stderr, "neoproot-um: cannot create wrapper '%s': %s\n",
                wrapper_path, strerror(errno));
        return -1;
    }
    if (ext4_rootfs) {
        if (um_write_text(fd, "#!/bin/sh\n") < 0)
            goto failed;
        /*
         * Binds for an ext4 root are mounted by the guest init, which has to
         * declare that it knows how before this script runs the caller's
         * command.  Without the declaration the command would run with the
         * binds silently absent -- which is exactly the failure a user cannot
         * see.  A legacy /um-init writes no declaration, so this refuses to
         * run rather than pretending.
         */
        if (ext4_binds &&
            um_write_text(fd,
                          "um_bind_declared=\n"
                          "if [ -r /run/neoproot/init-features ]; then\n"
                          "    while IFS= read -r um_line; do\n"
                          "        [ \"$um_line\" = \"feature=binds\" ] && um_bind_declared=1\n"
                          "    done < /run/neoproot/init-features\n"
                          "fi\n"
                          "if [ -z \"$um_bind_declared\" ]; then\n"
                          "    printf '%s\\n' 'UM_PROTOCOL_ERROR=binds-unsupported' >&2\n"
                          "    exit 125\n"
                          "fi\n") < 0)
            goto failed;
    } else if (um_write_text(fd, "#!/bin/sh\n"
                              "um_fail() { printf '%s\\n' \"$1\" > ") < 0 ||
               um_write_shell_word(fd, status_path) < 0 ||
               um_write_text(fd, "; sync; poweroff -f; while :; do sleep 3600; done; }\n"
                              "mount -t proc proc /proc 2>/dev/null || "
                              "test -r /proc/self/status || um_fail 125\n"
                              "mount -t sysfs sysfs /sys 2>/dev/null || "
                              "test -d /sys/kernel || um_fail 125\n"
                              "mount -t devtmpfs devtmpfs /dev 2>/dev/null || "
                              "test -c /dev/null || um_fail 125\n") < 0)
        goto failed;

    /*
     * Bring the loopback up.  Nothing else does it: the kernel does not
     * configure interfaces, and this wrapper is the guest's init.  Without lo,
     * 127.0.0.1 is unreachable and anything that talks to itself over it fails
     * with "Network unreachable" -- which looks like a networking bug rather
     * than a missing interface.
     *
     * Runs for both root kinds: the wrapper is executed inside the guest either
     * way (as PID 1 for hostfs, from /um-init for an ext4 image), and neither
     * the kernel nor a stock /um-init brings lo up.  Before --net-auto, so that
     * function only has to deal with vec0.  Best effort: a guest without an ip
     * tool still starts.
     */
    if (um_write_text(fd,
                      "if command -v ip >/dev/null 2>&1; then\n"
                      "    ip link set lo up 2>/dev/null\n"
                      "elif command -v ifconfig >/dev/null 2>&1; then\n"
                      "    ifconfig lo up 2>/dev/null\n"
                      "fi\n") < 0)
        goto failed;

    if (um_write_text(fd, "unset LD_PRELOAD LD_LIBRARY_PATH LD_BIND_NOW "
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

    for (bind_index = 0; !ext4_rootfs && bind_index < config->bind_count;
         bind_index++) {
        const UmBind *bind = &config->binds[bind_index];

        if (um_write_text(fd, "mount --bind ") < 0 ||
            um_write_shell_word(fd, bind->source_guest) < 0 ||
            um_write_text(fd, " ") < 0 ||
            um_write_shell_word(fd, bind->guest) < 0 ||
            um_write_text(fd, " || um_fail 125\n") < 0)
            goto failed;
        if (bind->readonly &&
            (um_write_text(fd, "mount -o remount,bind,ro ") < 0 ||
             um_write_shell_word(fd, bind->guest) < 0 ||
             um_write_text(fd, " || um_fail 125\n") < 0))
            goto failed;
    }

    /*
     * Configure the guest side of the link when the caller asked for it.
     *
     * vec0 exists as soon as the kernel is up (umnet appended it to the command
     * line), but nothing brings it up or gives it an address: in UML the guest
     * owns its interfaces, and the DHCP server that passt runs only answers a
     * client that asks.  The gate has always done this by hand; --net-auto is
     * the same sequence for everybody else.
     *
     * DHCP is the path that gets the resolver from the server.  If udhcpc is
     * missing or gets nothing, the static fallback uses the very address and
     * gateway the server was told to hand out, so the link still ends up
     * usable.  Neither failure stops the command: a container whose network
     * did not come up is still a container, and refusing to start would take
     * the shell away for a problem the user can see and fix.
     */
    if (config->network_auto) {
        if (um_write_text(fd,
                          "um_net_auto() {\n"
                          "    [ -e /proc/net/dev ] || return 0\n"
                          "    if ! grep -q '^ *vec0:' /proc/net/dev; then\n"
                          "        printf '%s\\n' 'neoproot-um: --net-auto: guest has no vec0'\n"
                          "        return 0\n"
                          "    fi\n"
                          "    ip link set vec0 up 2>/dev/null\n"
                          "    if command -v udhcpc >/dev/null 2>&1 &&\n"
                          "       udhcpc -n -q -t 3 -T 1 -i vec0 >/dev/null 2>&1; then\n"
                          "        :\n"
                          "    else\n"
                          "        ip addr add ") < 0)
            goto failed;
        /*
         * Every value below comes from the caller and ends up in a shell
         * script that runs as root inside the guest, so it is quoted rather
         * than interpolated raw.  A value like "10.0.2.2;id" is a valid
         * argv token -- it has no whitespace, so the option parser accepts
         * it -- and unquoted it would end the ip command and run "id".
         */
        if (um_write_shell_word(fd, config->net_addr) < 0 ||
            um_write_text(fd, "/") < 0 ||
            um_write_text(fd, config->net_mask) < 0 ||
            um_write_text(fd, " dev vec0 2>/dev/null\n"
                              "        ip route add default via ") < 0)
            goto failed;
        if (um_write_shell_word(fd, config->net_gateway) < 0 ||
            um_write_text(fd, " dev vec0 2>/dev/null\n"
                              "    fi\n") < 0)
            goto failed;
        /*
         * IPv6 is not DHCP: umnet runs a second, IPv6-only passt whose guest
         * side has a fixed address and a link-local gateway.  When the caller
         * asked for it, put it on vec0 here -- otherwise --net-ipv6 gives the
         * guest a stack with no address and every v6 command fails.
         */
        if (config->net_ipv6) {
            if (um_write_text(fd,
                              "    ip -6 addr add ") < 0)
                goto failed;
            if (config->net_ipv6_addr[0] != '\0') {
                /*
                 * "ip addr add" needs a prefix length.  A bare address is a
                 * natural thing to pass, and without this it is accepted here
                 * and then rejected by ip inside the guest, where every error
                 * is discarded -- leaving a guest with IPv6 enabled and no
                 * address on it.  Append the same /64 umnet defaults to.
                 */
                if (um_write_shell_word(fd, config->net_ipv6_addr) < 0)
                    goto failed;
                if (strchr(config->net_ipv6_addr, '/') == NULL &&
                    um_write_text(fd, "/64") < 0)
                    goto failed;
            } else if (um_write_text(fd, "fd00::2/64") < 0)
                goto failed;
            if (um_write_text(fd, " dev vec0 2>/dev/null\n"
                              "    ip -6 route add default via ") < 0)
                goto failed;
            if (config->net_ipv6_gw[0] != '\0') {
                if (um_write_shell_word(fd, config->net_ipv6_gw) < 0)
                    goto failed;
            } else if (um_write_text(fd, "fe80::1") < 0)
                goto failed;
            if (um_write_text(fd, " dev vec0 2>/dev/null\n") < 0)
                goto failed;
        }
        if (um_write_text(fd, "}\num_net_auto\n") < 0)
            goto failed;
    }

    if (um_write_text(fd, "cd ") < 0 ||
        um_write_shell_word(fd, cwd) < 0 ||
        um_write_text(fd, " || exit 126\n") < 0)
        goto failed;

    /*
     * Give the command a controlling terminal.
     *
     * The kernel execs this script as PID 1.  Before exec it opens /dev/console
     * and dup2()s it onto 0,1,2, but the session leader test in
     * tty_open_proc_set_tty() fails for init: ksys_setsid() is never called on
     * it, so its pgrp and session are 0 and the console does not become its
     * controlling terminal.  /dev/tty then cannot be opened and every login
     * shell prints
     *
     *     /bin/sh: can't access tty; job control turned off
     *
     * with no Ctrl-C, no Ctrl-Z and no job control in the guest.
     *
     * setsid(1) -c fixes both halves at once: it is a fresh session leader (so
     * the console open in the child is allowed to claim the tty) and its -c
     * flag explicitly sets the controlling terminal to stdin.  Without -c the
     * new session would have no controlling terminal at all, which is worse
     * than what we started with.
     *
     * The same reasoning holds for an ext4 root: /um-init is PID 1 there and
     * does not call setsid() either, so the command it runs has the same
     * missing controlling terminal.  Old roots without setsid keep the old
     * behaviour rather than failing the run.
     */
    if (um_write_text(fd, "um_session_leader() {\n"
                      "    if command -v setsid >/dev/null 2>&1; then\n"
                      "        setsid -c \"$@\"\n"
                      "    else\n"
                      "        \"$@\"\n"
                      "    fi\n"
                      "}\n") < 0)
        goto failed;

    if (um_write_text(fd, "set --") < 0)
        goto failed;
    for (index = 0; index < guest_argc; index++) {
        if (um_write_text(fd, " ") < 0 ||
            um_write_shell_word(fd, guest_argv[index]) < 0)
            goto failed;
    }
    if (ext4_rootfs) {
        if (um_write_text(fd, "\num_session_leader \"$@\"\nexit $?\n") < 0)
            goto failed;
    } else if (um_write_text(fd,
                             "\num_session_leader \"$@\"\nrc=$?\n"
                             "printf '%s\\n' \"$rc\" > ") < 0 ||
               um_write_shell_word(fd, status_path) < 0 ||
               um_write_text(fd, "\nsync\npoweroff -f\nwhile :; do sleep 3600; done\n") < 0)
        goto failed;
    if (fsync(fd) < 0)
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

static int um_flush_buffer_until(UmBuffer *buffer, int fd, double deadline)
{
    while (buffer->start < buffer->end) {
        struct pollfd descriptor = {
            .fd = fd,
            .events = POLLOUT,
            .revents = 0
        };
        double remaining = deadline - um_now();
        int timeout;
        int poll_result;

        if (remaining <= 0.0)
            return -1;
        timeout = remaining >= 1.0 ? 1000 : (int)(remaining * 1000.0) + 1;
        if (um_flush_buffer(buffer, fd) < 0)
            return -1;
        if (buffer->start == buffer->end)
            return 0;
        do {
            poll_result = poll(&descriptor, 1, timeout);
        } while (poll_result < 0 && errno == EINTR);
        if (poll_result <= 0)
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

/*
 * Put the caller's terminal into raw mode for the duration of the run.
 *
 * The console path is a PTY: UML writes to the master side and the guest reads
 * the slave.  Leaving the host terminal in its default (cooked) mode has three
 * visible consequences, all of them reported as bugs:
 *
 *   - The guest's own line editor asks the terminal for the cursor position
 *     (ESC [ 6 n) and the terminal answers with ESC [ row ; col R.  In cooked
 *     mode the answer is echoed back, so the escape sequence shows up on screen
 *     as literal text: the "^[[r;cR" leak.
 *   - Typed input is echoed twice, once by the host terminal and once by the
 *     guest tty, so every command appears two or three times.
 *   - Control characters are interpreted by the host terminal first, so ^C
 *     reaches the guest as a signal to the supervisor instead of as input the
 *     guest can deliver to its foreground process, and job control cannot work
 *     across the boundary.
 *
 * The kernel side of the fd channel would normally raw() the fd itself
 * (arch/um/drivers/fd.c, raw=1 for the console channel), but that happens in
 * the UML process, whose stdin is our PTY master's slave -- not the user's
 * terminal.  Raw'ing that slave does not affect the terminal the user types on,
 * because the master side is where the user's terminal settings live.  So it
 * has to be done here, by the process that owns the real terminal.
 *
 * Saving is conditional on isatty(): pipes and redirected files are left exactly
 * as they were, and a failed tcgetattr is not an error for the same reason.
 */
struct um_terminal_state {
    bool valid;
    struct termios saved;
};

static void um_enter_raw_terminal(struct um_terminal_state *state)
{
    struct termios raw;

    state->valid = false;
    if (!isatty(STDIN_FILENO))
        return;
    if (tcgetattr(STDIN_FILENO, &state->saved) < 0)
        return;
    raw = state->saved;
    cfmakeraw(&raw);
    /*
     * cfmakeraw() clears OPOST, which also disables the conversion of \n to
     * \r\n on output.  The guest sends bare newlines and expects the terminal
     * to advance to column zero; without this the output staircases.
     */
    raw.c_oflag |= OPOST;
    if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) < 0)
        return;
    state->valid = true;
}

static void um_leave_raw_terminal(const struct um_terminal_state *state)
{
    if (!state->valid)
        return;
    (void)tcsetattr(STDIN_FILENO, TCSANOW, &state->saved);
}

static void um_kill_group(pid_t pid, int signal_number, bool group_ready)
{
    if (pid > 0) {
        (void)kill(pid, signal_number);
        if (group_ready)
            (void)kill(-pid, signal_number);
    }
}

static int um_mark_fd_range_cloexec(int first, int last)
{
    int fd;

    if (first > last)
        return 0;
#ifdef __NR_close_range
    if (syscall(__NR_close_range, (unsigned int)first,
                (unsigned int)last, UM_CLOSE_RANGE_CLOEXEC) == 0)
        return 0;
#endif
    for (fd = first; fd <= last; fd++) {
        int flags = fcntl(fd, F_GETFD);

        if (flags < 0) {
            if (errno == EBADF)
                continue;
            return -1;
        }
        if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0)
            return -1;
    }
    return 0;
}

static int um_mark_inherited_fds_cloexec(int keep_fd)
{
    struct rlimit limits;
    long open_max;
    int maximum;

    if (getrlimit(RLIMIT_NOFILE, &limits) == 0 &&
        limits.rlim_cur <= (rlim_t)INT_MAX) {
        maximum = (int)limits.rlim_cur - 1;
    } else {
        open_max = sysconf(_SC_OPEN_MAX);
        maximum = open_max > 0 && open_max <= INT_MAX
            ? (int)open_max - 1 : 65535;
    }
    if (maximum < 3)
        return 0;
    if (keep_fd >= 3 && keep_fd <= maximum) {
        if (um_mark_fd_range_cloexec(3, keep_fd - 1) < 0 ||
            um_mark_fd_range_cloexec(keep_fd + 1, maximum) < 0)
            return -1;
    } else {
        if (um_mark_fd_range_cloexec(3, maximum) < 0)
            return -1;
    }
    return 0;
}

static bool um_wait_for_group_exit(pid_t pgid, double deadline)
{
    struct timespec delay = { .tv_sec = 0, .tv_nsec = 10000000L };

    if (pgid <= 0)
        return true;
    while (um_now() < deadline) {
        if (kill(-pgid, 0) < 0 && errno == ESRCH)
            return true;
        nanosleep(&delay, NULL);
    }
    return kill(-pgid, 0) < 0 && errno == ESRCH;
}

static void um_watchdog_main(int control_fd, pid_t uml_pid)
{
    struct timespec delay = { .tv_sec = 0, .tv_nsec = 10000000L };
    struct rlimit limits;
    long maximum;
    int fd;

    if (setsid() < 0)
        _exit(127);
    if (getrlimit(RLIMIT_NOFILE, &limits) == 0 && limits.rlim_cur < 65536)
        maximum = (long)limits.rlim_cur;
    else
        maximum = 65536;
    for (fd = 0; fd < maximum; fd++)
        if (fd != control_fd)
            close(fd);

    for (;;) {
        struct pollfd descriptor = {
            .fd = control_fd,
            .events = POLLIN | POLLHUP,
            .revents = 0
        };
        int poll_result;
        char command;

        do {
            poll_result = poll(&descriptor, 1, -1);
        } while (poll_result < 0 && errno == EINTR);
        if (poll_result < 0)
            break;
        if (read(control_fd, &command, 1) == 1 && command == 'S') {
            close(control_fd);
            _exit(0);
        }
        break;
    }

    (void)kill(uml_pid, SIGKILL);
    for (int attempt = 0; attempt < 300; attempt++) {
        if (getpgid(uml_pid) == uml_pid)
            (void)kill(-uml_pid, SIGKILL);
        if (kill(-uml_pid, 0) < 0 && errno == ESRCH)
            break;
        nanosleep(&delay, NULL);
    }
    close(control_fd);
    _exit(0);
}

#define UM_HANDLED_SIGNALS 6

static int um_install_signal_handlers(struct sigaction old_actions[UM_HANDLED_SIGNALS])
{
    static const int signals[UM_HANDLED_SIGNALS] = {
        SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGPIPE, SIGWINCH
    };
    struct sigaction action;
    int index;

    memset(&action, 0, sizeof(action));
    sigemptyset(&action.sa_mask);
    action.sa_handler = um_signal_handler;
    for (index = 0; index < UM_HANDLED_SIGNALS; index++) {
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

static void um_restore_signal_handlers(const struct sigaction old_actions[UM_HANDLED_SIGNALS])
{
    static const int signals[UM_HANDLED_SIGNALS] = {
        SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGPIPE, SIGWINCH
    };
    int index;

    /* Must cover every signal um_install_signal_handlers() touched, or the
     * last one keeps our handler after this supervisor returns. */
    for (index = 0; index < UM_HANDLED_SIGNALS; index++)
        (void)sigaction(signals[index], &old_actions[index], NULL);
}

static void um_print_usage(void)
{
    puts("Usage: neoproot-um --rootfs=DIR|IMAGE [options] -- command [args...]");
    puts("Options:");
    puts("  --kernel=PATH       UML kernel executable");
    puts("  --stub=PATH         UML stub_exe executable");
    puts("  --rootfs=PATH       hostfs directory or ext4 image");
    puts("  --hostfs            require directory hostfs mode");
    puts("  --readonly          open an ext4 image without a COW file");
    puts("  --cow-file=PATH     keep the ext4 COW file at PATH (created if missing)");
    puts("  --seccomp=MODE      UML syscall mode: off (ptrace, default), auto, or on");
    puts("                      auto/on are faster but unsafe for untrusted guests");
    puts("  --quiet             suppress UML boot messages (quiet loglevel=1)");
    puts("  --cpus=N            guest CPUs, 1-64 (default: 1); >1 needs --seccomp");
    puts("  --rootflags=OPTS    extra ext4 root mount options (ro adds noload)");
    puts("  --cwd=PATH          guest working directory");
    puts("  --timeout=SECONDS   bounded runtime (default: 120)");
    puts("  -b HOST:GUEST[:ro]  bind a rootfs path into the guest");
    puts("  --net               give the guest a network via umnet + passt");
    puts("  --net-auto          also configure the guest side of --net (DHCP,");
    puts("                      then a static fallback); implies --net");
    puts("  --net-addr=ADDR     guest IPv4 address (default: 10.0.2.15)");
    puts("  --net-gateway=ADDR  guest default gateway (default: 10.0.2.2)");
    puts("  --net-dns=ADDR      nameserver announced to the guest ('none' omits it)");
    puts("  --net-ipv6          also give the guest IPv6 (a second passt, via umnet)");
    puts("  --net-ipv6-addr=A[/P]  guest IPv6 address (default: fd00::2/64)");
    puts("  --net-ipv6-gw=ADDR  guest IPv6 gateway (default: fe80::1)");
    puts("  --net-ipv6-dns=ADDR IPv6 nameserver ('none' omits it, default: host resolver)");
    puts("Environment defaults: NEOPROOT_UM_KERNEL, NEOPROOT_UM_STUB,");
    puts("  NEOPROOT_UM_NET, NEOPROOT_UM_PASST");
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

/*
 * Read what a session-aware guest init declared before running init.sh.
 *
 * The declaration is written into the session directory, so it survives the
 * run and can be checked from here: a run that asked for binds and got no
 * declaration ran without them, whatever status the guest reported.
 */
static bool um_session_declares(const char *session_path, const char *feature)
{
    char path[PATH_MAX];
    char line[256];
    bool found = false;
    FILE *file;

    if (snprintf(path, sizeof(path), "%s/%s", session_path,
                 UM_INIT_FEATURES_NAME) >= (int)sizeof(path))
        return false;
    file = fopen(path, "r");
    if (file == NULL)
        return false;
    while (fgets(line, sizeof(line), file) != NULL) {
        size_t length = strlen(line);

        while (length > 0 &&
               (line[length - 1] == '\n' || line[length - 1] == '\r'))
            line[--length] = '\0';
        if (strcmp(line, feature) == 0) {
            found = true;
            break;
        }
    }
    fclose(file);
    return found;
}

/* The first line of a guest-reported protocol failure, if there is one. */
static bool um_session_error(const char *session_path, char *result,
                             size_t size)
{
    char path[PATH_MAX];
    FILE *file;

    if (size == 0 || snprintf(path, sizeof(path), "%s/%s", session_path,
                              UM_PROTOCOL_ERROR_NAME) >= (int)sizeof(path))
        return false;
    file = fopen(path, "r");
    if (file == NULL)
        return false;
    if (fgets(result, (int)size, file) == NULL)
        result[0] = '\0';
    fclose(file);
    result[strcspn(result, "\r\n")] = '\0';
    return true;
}

static int um_run_kernel(const UmConfig *config, const char *init_path,
                         const char *session_path, const char *status_path,
                         bool *group_gone)
{
    char init_argument[PATH_MAX + 6];
    char root_argument[PATH_MAX + 10];
    char cow_argument[PATH_MAX * 2 + 8];
    char image_argument[PATH_MAX + 32];
    char hostfs_argument[PATH_MAX + 8];
    char session_argument[PATH_MAX + 24];
    char cwd_argument[PATH_MAX + 16];
    char protocol_argument[] = "neoproot_protocol=session-v1";
    char readonly_argument[PATH_MAX + 8];
    char stub_argument[PATH_MAX + 6];
    char seccomp_argument[32];
    char cpus_argument[32];
    char rootflags_argument[320];
    char slave_name[PATH_MAX];
    char *kernel_argv[28];
    struct sigaction old_actions[UM_HANDLED_SIGNALS];
    UmBuffer input = { 0 };
    UmBuffer output = { 0 };
    int master_fd = -1;
    int master_flags = -1;
    int stdin_flags = -1;
    int stdout_flags = -1;
    struct um_terminal_state terminal = { .valid = false };
    pid_t child_pid = -1;
    pid_t watchdog_pid = -1;
    pid_t supervisor_pid = getpid();
    int group_pipe[2] = { -1, -1 };
    int watchdog_pipe[2] = { -1, -1 };
    char group_marker;
    int child_status = 0;
    bool child_done = false;
    bool master_eof = false;
    bool stdin_eof = false;
    bool output_failed = false;
    bool group_cleaned = false;
    bool group_ready = false;
    bool group_handshake_closed = false;
    bool group_handshake_untrusted = false;
    bool termination_sent = false;
    bool timed_out = false;
    int forwarded_signal = 0;
    bool guest_status_valid = false;
    double deadline;
    double termination_deadline = 0.0;
    double drain_deadline = 0.0;
    int result = EXIT_FAILURE;
    int index = 0;

    *group_gone = true;

    if (snprintf(stub_argument, sizeof(stub_argument), "stub_exe=%s",
                 config->resolved_stub) >= (int)sizeof(stub_argument) ||
        snprintf(hostfs_argument, sizeof(hostfs_argument), "hostfs=%s",
                 config->resolved_hostfs) >= (int)sizeof(hostfs_argument) ||
        snprintf(cwd_argument, sizeof(cwd_argument), "neoproot_cwd=%s",
                 config->cwd) >= (int)sizeof(cwd_argument) ||
        snprintf(cpus_argument, sizeof(cpus_argument), "ncpus=%u",
                 config->cpus) >= (int)sizeof(cpus_argument)) {
        fprintf(stderr, "neoproot-um: UML argument is too long\n");
        return EXIT_FAILURE;
    }

    if (config->rootfs_kind == UM_ROOTFS_HOSTFS) {
        if (snprintf(init_argument, sizeof(init_argument), "init=%s", init_path)
                >= (int)sizeof(init_argument) ||
            snprintf(root_argument, sizeof(root_argument), "rootflags=%s",
                     config->resolved_rootfs) >= (int)sizeof(root_argument)) {
            fprintf(stderr, "neoproot-um: UML argument is too long\n");
            return EXIT_FAILURE;
        }
    } else if (snprintf(init_argument, sizeof(init_argument), "init=/um-init")
                   >= (int)sizeof(init_argument) ||
               snprintf(session_argument, sizeof(session_argument),
                        "neoproot_session=/%s",
                        strrchr(session_path, '/') + 1) >=
                   (int)sizeof(session_argument) ||
               snprintf(image_argument, sizeof(image_argument),
                        "/proc/self/fd/%d", config->rootfs_fd) >=
                   (int)sizeof(image_argument)) {
        fprintf(stderr, "neoproot-um: UML argument is too long\n");
        return EXIT_FAILURE;
    }

    rootflags_argument[0] = '\0';
    if (config->rootfs_kind == UM_ROOTFS_EXT4 &&
        (config->readonly || config->rootflags != NULL)) {
        int written;

        if (config->readonly && config->rootflags != NULL)
            written = snprintf(rootflags_argument, sizeof(rootflags_argument),
                               "rootflags=noload,%s", config->rootflags);
        else if (config->readonly)
            written = snprintf(rootflags_argument, sizeof(rootflags_argument),
                               "rootflags=noload");
        else
            written = snprintf(rootflags_argument, sizeof(rootflags_argument),
                               "rootflags=%s", config->rootflags);
        if (written >= (int)sizeof(rootflags_argument)) {
            fprintf(stderr, "neoproot-um: UML argument is too long\n");
            return EXIT_FAILURE;
        }
    }

    if (!config->readonly && config->rootfs_kind == UM_ROOTFS_EXT4) {
        const char *cow_path = config->resolved_cow;
        const char *backing = image_argument;
        char temporary_cow[PATH_MAX];

        if (cow_path == NULL) {
            if (snprintf(temporary_cow, sizeof(temporary_cow), "%s/root.cow",
                         session_path) >= (int)sizeof(temporary_cow)) {
                fprintf(stderr, "neoproot-um: UML argument is too long\n");
                return EXIT_FAILURE;
            }
            cow_path = temporary_cow;
        } else {
            /*
             * A COW header names its backing file, and the kernel resolves
             * /proc/self/fd/N through its own /proc, so with the descriptor
             * the header would record /proc/<pid>/fd/N and every reuse would
             * look like a backing-file change (the kernel answers that by
             * rewriting the header and logging two errors).  Naming the image
             * keeps the header stable, which is what makes a persistent COW
             * reopen quietly.  The temporary COW keeps the descriptor: it is
             * written once and thrown away.
             */
            backing = config->resolved_rootfs;
        }
        if (snprintf(cow_argument, sizeof(cow_argument), "ubd0=%s,%s",
                     cow_path, backing) >= (int)sizeof(cow_argument)) {
            fprintf(stderr, "neoproot-um: UML argument is too long\n");
            return EXIT_FAILURE;
        }
    }

    kernel_argv[index++] = config->resolved_kernel;
    kernel_argv[index++] = "mem=512M";
    kernel_argv[index++] = cpus_argument;
    if (config->seccomp != UM_SECCOMP_OFF) {
        const char *mode = config->seccomp == UM_SECCOMP_ON ? "on" : "auto";

        if (snprintf(seccomp_argument, sizeof(seccomp_argument),
                     "seccomp=%s", mode) >= (int)sizeof(seccomp_argument))
            return EXIT_FAILURE;
        kernel_argv[index++] = seccomp_argument;
    }
    if (config->quiet) {
        kernel_argv[index++] = "quiet";
        kernel_argv[index++] = "loglevel=1";
    }
    kernel_argv[index++] = config->readonly ? "ro" : "rw";
    kernel_argv[index++] = init_argument;
    kernel_argv[index++] = "con=null";
    kernel_argv[index++] = "con0=fd:0,fd:1";
    kernel_argv[index++] = stub_argument;
    if (config->rootfs_kind == UM_ROOTFS_HOSTFS) {
        kernel_argv[index++] = "rootfstype=hostfs";
        kernel_argv[index++] = root_argument;
    } else {
        if (config->readonly) {
            if (snprintf(readonly_argument, sizeof(readonly_argument),
                         "ubd0r=%s", image_argument) >=
                    (int)sizeof(readonly_argument))
                return EXIT_FAILURE;
            kernel_argv[index++] = readonly_argument;
        } else {
            kernel_argv[index++] = cow_argument;
        }
        kernel_argv[index++] = "root=/dev/ubda";
        kernel_argv[index++] = "rootfstype=ext4";
        kernel_argv[index++] = hostfs_argument;
        kernel_argv[index++] = protocol_argument;
        kernel_argv[index++] = session_argument;
        kernel_argv[index++] = cwd_argument;
        if (rootflags_argument[0] != '\0')
            kernel_argv[index++] = rootflags_argument;
    }
    kernel_argv[index++] = "panic=1";
    kernel_argv[index] = NULL;
    if (pipe2(group_pipe, O_CLOEXEC) < 0) {
        fprintf(stderr, "neoproot-um: pipe: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }
    if (pipe2(watchdog_pipe, O_CLOEXEC) < 0) {
        fprintf(stderr, "neoproot-um: watchdog pipe: %s\n", strerror(errno));
        close(group_pipe[0]);
        close(group_pipe[1]);
        return EXIT_FAILURE;
    }
    master_fd = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (master_fd < 0 || grantpt(master_fd) < 0 || unlockpt(master_fd) < 0 ||
        ptsname_r(master_fd, slave_name, sizeof(slave_name)) != 0) {
        fprintf(stderr, "neoproot-um: cannot set up PTY: %s\n",
                strerror(errno));
        if (master_fd >= 0)
            close(master_fd);
        close(group_pipe[0]);
        close(group_pipe[1]);
        close(watchdog_pipe[0]);
        close(watchdog_pipe[1]);
        return EXIT_FAILURE;
    }
    /* Give the guest the caller's terminal geometry before it starts, and
     * arrange to be told when that geometry changes. */
    um_apply_window_size(master_fd);

    if (um_set_nonblocking(master_fd, &master_flags) < 0) {
        fprintf(stderr, "neoproot-um: cannot configure PTY: %s\n",
                strerror(errno));
        close(master_fd);
        close(group_pipe[0]);
        close(group_pipe[1]);
        close(watchdog_pipe[0]);
        close(watchdog_pipe[1]);
        return EXIT_FAILURE;
    }
    if (um_set_nonblocking(STDIN_FILENO, &stdin_flags) < 0) {
        fprintf(stderr, "neoproot-um: cannot configure stdin: %s\n",
                strerror(errno));
        goto cleanup;
    }
    if (um_set_nonblocking(STDOUT_FILENO, &stdout_flags) < 0) {
        fprintf(stderr, "neoproot-um: cannot configure stdout: %s\n",
                strerror(errno));
        goto cleanup;
    }

    if (um_install_signal_handlers(old_actions) < 0) {
        fprintf(stderr, "neoproot-um: cannot install signal handlers: %s\n",
                strerror(errno));
        goto cleanup;
    }
    um_requested_signal = 0;
    um_window_changed = 0;
    /*
     * Raw mode is entered around the run, not inside it: everything between
     * here and the cleanup block below can return early, and the terminal must
     * be restored exactly once on all of them.  um_leave_raw_terminal() is
     * called on the way out of cleanup.
     */
    um_enter_raw_terminal(&terminal);
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
        char prefix_environment[PATH_MAX + 8];
        const char *host_tmpdir = getenv("TMPDIR");
        const char *host_home = getenv("HOME");
        const char *host_prefix = getenv("PREFIX");

        close(watchdog_pipe[0]);
        close(watchdog_pipe[1]);
        close(group_pipe[0]);
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0 ||
            getppid() != supervisor_pid)
            _exit(127);
        close(master_fd);
        if (setsid() < 0) {
            dprintf(STDERR_FILENO, "neoproot-um: setsid: %s\n", strerror(errno));
            _exit(127);
        }
        if (um_write_all(group_pipe[1], "G", 1) < 0)
            _exit(127);
        close(group_pipe[1]);
        /*
         * Leave the controlling terminal to UML.
         *
         * UML relays host window-size changes to the guest through a helper
         * process that attaches to the console fd itself (winch_thread():
         * setsid() + ioctl(fd, TIOCSCTTY, 0), see chan_user.c).  A PTY can be
         * the controlling terminal of exactly one session, so if we claim it
         * here that helper dies with
         *
         *     winch_thread : TIOCSCTTY failed on fd 1 err = 1
         *
         * and the guest keeps its startup geometry for the whole run, even
         * though we keep copying the host size onto the PTY.
         *
         * A session leader's first tty open() claims the tty implicitly, so
         * O_NOCTTY -- not dropping the explicit TIOCSCTTY alone -- is what
         * leaves it free.  The device still has to exist and be usable here,
         * but this process needs no controlling terminal of its own.
         */
        child_slave = open(slave_name, O_RDWR | O_NOCTTY | O_CLOEXEC);
        if (child_slave < 0) {
            dprintf(STDERR_FILENO, "neoproot-um: open PTY slave: %s\n", strerror(errno));
            _exit(127);
        }
        if (dup2(child_slave, STDIN_FILENO) < 0 ||
            dup2(child_slave, STDOUT_FILENO) < 0 ||
            dup2(child_slave, STDERR_FILENO) < 0) {
            dprintf(STDERR_FILENO, "neoproot-um: dup2 PTY: %s\n", strerror(errno));
            _exit(127);
        }
        for (int standard_fd = STDIN_FILENO;
             standard_fd <= STDERR_FILENO; standard_fd++) {
            int flags = fcntl(standard_fd, F_GETFD);

            if (flags < 0 ||
                fcntl(standard_fd, F_SETFD, flags & ~FD_CLOEXEC) < 0)
                _exit(127);
        }
        if (child_slave > STDERR_FILENO)
            close(child_slave);
        if (config->rootfs_fd >= 3 &&
            fcntl(config->rootfs_fd, F_SETFD, 0) < 0)
            _exit(127);
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
            char *environment[5];

            /*
             * PREFIX is how umnet finds Termux's $PREFIX/etc/resolv.conf.  On
             * Android there is no /etc/resolv.conf at all (DNS goes through
             * netd), so without this the helper cannot read the host's
             * nameserver, falls back to the compiled-in 1.1.1.1, and hands the
             * guest a resolver the network may well block -- lookups then fail
             * after DHCP has already succeeded, which reads like a broken
             * bridge.  Only passed when it is an absolute path.
             */
            if (host_prefix == NULL || host_prefix[0] != '/' ||
                strlen(host_prefix) >= PATH_MAX - 8)
                host_prefix = NULL;
            if (host_prefix != NULL)
                snprintf(prefix_environment, sizeof(prefix_environment),
                         "PREFIX=%s", host_prefix);

            environment[0] = home_environment;
            environment[1] = kernel_environment[0];
            environment[2] = tmpdir_environment;
            environment[3] = host_prefix != NULL ? prefix_environment : NULL;
            environment[4] = NULL;

            if (um_mark_inherited_fds_cloexec(
                    config->rootfs_kind == UM_ROOTFS_EXT4
                        ? config->rootfs_fd : -1) < 0)
                _exit(127);
            /*
             * With networking, umnet owns the UML process: it creates the
             * datagram/stream socketpair pair, appends the vec0 fd argument,
             * and execs the kernel itself.  It must stay our direct child so
             * the PTY, signals and exit status keep flowing through us
             * unchanged.
             */
            if (config->network) {
                /*
                 * umnet's own options, then `--`, then the complete kernel
                 * vector.  The vector must be copied in full: dropping its tail
                 * loses rootfs parameters rather than failing, and in ext4 mode
                 * that silently discards the caller's command (um-init keys the
                 * session off the neoproot_* parameters that sit at the end).
                 * The bound is derived from the two arrays, not guessed.
                 */
                char *network_argv[UM_NETWORK_OPTIONS + (int)(sizeof(kernel_argv) /
                                                             sizeof(kernel_argv[0]))];
                int network_index = 0;

                network_argv[network_index++] = (char *)"umnet";
                network_argv[network_index++] = (char *)"--passt";
                network_argv[network_index++] = config->resolved_passt;
                network_argv[network_index++] = (char *)"--addr";
                network_argv[network_index++] = (char *)config->net_addr;
                network_argv[network_index++] = (char *)"--mask";
                network_argv[network_index++] = (char *)config->net_mask;
                network_argv[network_index++] = (char *)"--gw";
                network_argv[network_index++] = (char *)config->net_gateway;
                /*
                 * Only when the caller named one.  Passing an empty --dns would
                 * make umnet announce nothing at all, and passing a default
                 * would put the guess back.
                 */
                if (config->net_dns[0] != '\0') {
                    network_argv[network_index++] = (char *)"--dns";
                    network_argv[network_index++] = (char *)config->net_dns;
                }
                /*
                 * IPv6 is one switch to umnet plus up to three values.  Only
                 * the switch is passed when the caller named no values: the
                 * address and gateway then stay umnet's own defaults, and the
                 * resolver is still read from the host rather than invented
                 * here -- the same rule as the IPv4 nameserver above.
                 */
                if (config->net_ipv6) {
                    network_argv[network_index++] = (char *)"--ipv6";
                    if (config->net_ipv6_addr[0] != '\0') {
                        network_argv[network_index++] = (char *)"--ipv6-addr";
                        network_argv[network_index++] =
                            (char *)config->net_ipv6_addr;
                    }
                    if (config->net_ipv6_gw[0] != '\0') {
                        network_argv[network_index++] = (char *)"--ipv6-gw";
                        network_argv[network_index++] =
                            (char *)config->net_ipv6_gw;
                    }
                    if (config->net_ipv6_dns[0] != '\0') {
                        network_argv[network_index++] = (char *)"--ipv6-dns";
                        network_argv[network_index++] =
                            (char *)config->net_ipv6_dns;
                    }
                }
                network_argv[network_index++] = (char *)"--";
                for (int kernel_index = 0; kernel_index < index; kernel_index++)
                    network_argv[network_index++] = kernel_argv[kernel_index];
                network_argv[network_index] = NULL;
                execve(config->resolved_umnet, network_argv, environment);
                dprintf(STDERR_FILENO, "neoproot-um: exec %s: %s\n",
                        config->resolved_umnet, strerror(errno));
                _exit(127);
            }
            execve(config->resolved_kernel, kernel_argv,
                   environment);
        }
        dprintf(STDERR_FILENO, "neoproot-um: exec %s: %s\n",
                config->resolved_kernel, strerror(errno));
        _exit(127);
    }

    watchdog_pid = fork();
    if (watchdog_pid < 0) {
        fprintf(stderr, "neoproot-um: watchdog fork: %s\n", strerror(errno));
        goto cleanup;
    }
    if (watchdog_pid == 0) {
        close(watchdog_pipe[1]);
        close(group_pipe[0]);
        close(group_pipe[1]);
        close(master_fd);
        um_watchdog_main(watchdog_pipe[0], child_pid);
    }
    close(watchdog_pipe[0]);
    watchdog_pipe[0] = -1;

    *group_gone = false;
    close(group_pipe[1]);
    {
        int flags = fcntl(group_pipe[0], F_GETFL);

        if (flags < 0 || fcntl(group_pipe[0], F_SETFL, flags | O_NONBLOCK) < 0) {
            group_handshake_untrusted = true;
            close(group_pipe[0]);
            group_pipe[0] = -1;
        }
    }
    if (group_pipe[0] >= 0) {
        ssize_t handshake_read = read(group_pipe[0], &group_marker, 1);

        if (handshake_read == 1) {
            group_ready = true;
            close(group_pipe[0]);
            group_pipe[0] = -1;
        } else if (handshake_read == 0) {
            group_handshake_closed = true;
            close(group_pipe[0]);
            group_pipe[0] = -1;
        } else if (handshake_read < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            group_handshake_untrusted = true;
            close(group_pipe[0]);
            group_pipe[0] = -1;
        }
    }
    group_pipe[1] = -1;

    deadline = um_now() + config->timeout;
    while (!child_done || !master_eof || output.start != output.end ||
           group_pipe[0] >= 0) {
        struct pollfd descriptors[4];
        nfds_t descriptor_count = 0;
        int master_index;
        int group_index = -1;
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
                um_kill_group(child_pid, SIGKILL, group_ready);
                group_cleaned = true;
            }
        } else if (wait_result < 0 && errno != EINTR) {
            child_done = true;
        }

        now = um_now();
        /*
         * A resize is not a reason to stop.  Copy the new geometry onto the
         * guest PTY and let it notice through its own SIGWINCH.
         */
        if (um_window_changed) {
            um_window_changed = 0;
            um_apply_window_size(master_fd);
        }
        if (um_requested_signal != 0 && forwarded_signal == 0) {
            forwarded_signal = um_requested_signal;
            termination_sent = true;
            termination_deadline = now + UM_SIGNAL_GRACE_SECONDS;
            um_kill_group(child_pid, forwarded_signal, group_ready);
        }
        if (!child_done && forwarded_signal == 0 && now >= deadline) {
            timed_out = true;
            termination_sent = true;
            forwarded_signal = SIGKILL;
            termination_deadline = now;
            um_kill_group(child_pid, SIGKILL, group_ready);
        }
        if (!child_done && termination_sent && now >= termination_deadline) {
            um_kill_group(child_pid, SIGKILL, group_ready);
            termination_deadline = now + UM_SIGNAL_GRACE_SECONDS;
        }
        if (child_done && drain_deadline != 0.0 && now >= drain_deadline)
            break;
        if (child_done && master_eof && output.start == output.end &&
            group_pipe[0] < 0)
            break;

        if (group_pipe[0] >= 0) {
            group_index = (int)descriptor_count;
            descriptors[descriptor_count++] = (struct pollfd){
                .fd = group_pipe[0], .events = POLLIN | POLLHUP,
                .revents = 0
            };
        }
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

        if (group_index >= 0 && descriptors[group_index].revents != 0) {
            ssize_t handshake_read = read(group_pipe[0], &group_marker, 1);

            if (handshake_read == 1)
                group_ready = true;
            if (handshake_read == 1 || handshake_read == 0 ||
                (handshake_read < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
                if (handshake_read == 0)
                    group_handshake_closed = true;
                else if (handshake_read < 0)
                    group_handshake_untrusted = true;
                close(group_pipe[0]);
                group_pipe[0] = -1;
            }
        }

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
                        um_kill_group(child_pid, SIGKILL, group_ready);
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
        um_kill_group(child_pid, SIGKILL, group_ready);
        if (um_wait_for_process(child_pid, &child_status) == 0)
            child_done = true;
    }
    if (!group_cleaned)
        um_kill_group(child_pid, SIGKILL, group_ready);
    if (group_ready)
        *group_gone = um_wait_for_group_exit(child_pid, um_now() +
                                             UM_SIGNAL_GRACE_SECONDS);
    else if (group_handshake_closed && !group_handshake_untrusted && child_done)
        *group_gone = true;
    else
        *group_gone = false;
    if (!*group_gone)
        fprintf(stderr, "neoproot-um: UML process group did not exit\n");
    if (!output_failed && um_flush_buffer_until(&output, STDOUT_FILENO,
                                                um_now() + UM_DRAIN_SECONDS) < 0)
        output_failed = true;
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
        um_kill_group(child_pid, SIGKILL, group_ready);
        if (!child_done)
            (void)um_wait_for_process(child_pid, &child_status);
        /*
         * By now the kernel is gone however it went.  If it shut down by
         * itself it has already removed its umid directory and this finds
         * nothing; if it was killed, this is the only thing that will.
         */
        um_remove_umid_directory(child_pid);
        if (group_ready)
            *group_gone = um_wait_for_group_exit(child_pid, um_now() +
                                                 UM_SIGNAL_GRACE_SECONDS);
        else if (!(group_handshake_closed && !group_handshake_untrusted &&
                   child_done))
            *group_gone = false;
    }
    if (watchdog_pipe[1] >= 0) {
        if (watchdog_pid > 0 && *group_gone)
            (void)um_write_all(watchdog_pipe[1], "S", 1);
        close(watchdog_pipe[1]);
    }
    if (watchdog_pipe[0] >= 0)
        close(watchdog_pipe[0]);
    if (watchdog_pid > 0) {
        int watchdog_status;

        if (um_wait_for_process(watchdog_pid, &watchdog_status) < 0) {
            (void)kill(watchdog_pid, SIGKILL);
            (void)um_wait_for_process(watchdog_pid, &watchdog_status);
        }
    }
    if (group_pipe[0] >= 0)
        close(group_pipe[0]);
    if (group_pipe[1] >= 0)
        close(group_pipe[1]);
    if (stdin_flags >= 0)
        (void)fcntl(STDIN_FILENO, F_SETFL, stdin_flags);
    if (stdout_flags >= 0)
        (void)fcntl(STDOUT_FILENO, F_SETFL, stdout_flags);
    um_leave_raw_terminal(&terminal);
    if (master_flags >= 0)
        (void)fcntl(master_fd, F_SETFL, master_flags);
    if (master_fd >= 0)
        close(master_fd);
    um_buffer_release(&input);
    um_buffer_release(&output);
    return result;
}

static int um_make_session(const UmConfig *config, char **session_path,
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

    length = snprintf(session, sizeof(session), "%s%s",
                      config->rootfs_kind == UM_ROOTFS_EXT4
                          ? config->resolved_hostfs : config->resolved_rootfs,
                      UM_SESSION_TEMPLATE);
    if (length < 0 || (size_t)length >= sizeof(session))
        return -1;
    if (mkdtemp(session) == NULL) {
        /*
         * Name the path.  "Permission denied" on its own leaves the reader to
         * guess which of the several directories involved is the one that
         * refused -- and this one is derived from the rootfs argument, so it is
         * a path the caller can actually do something about.
         */
        fprintf(stderr,
                "neoproot-um: cannot create session directory '%s': %s\n",
                session, strerror(errno));
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

static void um_unlink_session_file(const char *session_path, const char *name)
{
    char path[PATH_MAX];

    if (snprintf(path, sizeof(path), "%s/%s", session_path, name) <
        (int)sizeof(path))
        (void)unlink(path);
}

/*
 * Remove the umid directory the kernel made for this run.
 *
 * The kernel removes it itself, through an exitcall on the shutdown path.  That
 * path only runs when the guest shuts down under its own power, so every run
 * that ends any other way -- a timeout, a forwarded signal, a guest panic --
 * leaves the directory behind, and they accumulate.  Forty-two had built up on
 * the phone this was written for, every one of them holding a pid that had been
 * dead for weeks.
 *
 * The kernel picks the umid and exposes no way to name it: there is no `umid=`
 * command line parameter (only `uml_dir=`), and make_umid() runs mkstemp() on a
 * template.  So it is found by content instead.  The pid file inside holds the
 * kernel's own pid, and that pid is the one this process started and has just
 * reaped, which makes the match exact rather than a guess.
 *
 * Best effort by design.  A directory that is not there, a pid file that cannot
 * be read, an entry that will not unlink -- none of that is a reason to report
 * a run as failed, and after a forced kill the whole point is that the guest
 * did not get to tidy up after itself.
 */
static void um_remove_umid_directory(pid_t kernel_pid)
{
    char uml_dir[PATH_MAX];
    const char *home = getenv("HOME");
    DIR *directory;
    struct dirent *entry;

    if (kernel_pid <= 0 || home == NULL || home[0] != '/')
        return;
    if (snprintf(uml_dir, sizeof(uml_dir), "%s/.uml", home) >=
        (int)sizeof(uml_dir))
        return;

    directory = opendir(uml_dir);
    if (directory == NULL)
        return;

    while ((entry = readdir(directory)) != NULL) {
        char path[PATH_MAX];
        char pid_text[32];
        char *end;
        long pid;
        ssize_t count;
        int fd;

        /* Skips "." and ".." along with anything else hidden. */
        if (entry->d_name[0] == '.')
            continue;
        if (snprintf(path, sizeof(path), "%s/%s/pid", uml_dir,
                     entry->d_name) >= (int)sizeof(path))
            continue;

        fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0)
            continue;
        count = read(fd, pid_text, sizeof(pid_text) - 1);
        close(fd);
        if (count <= 0)
            continue;
        pid_text[count] = '\0';

        pid = strtol(pid_text, &end, 10);
        if (end == pid_text || pid != (long)kernel_pid)
            continue;

        /* Ours, and the process that wrote it is gone. */
        (void)unlink(path);
        if (snprintf(path, sizeof(path), "%s/%s/mconsole", uml_dir,
                     entry->d_name) < (int)sizeof(path))
            (void)unlink(path);
        if (snprintf(path, sizeof(path), "%s/%s", uml_dir,
                     entry->d_name) < (int)sizeof(path))
            (void)rmdir(path);
    }

    closedir(directory);
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
    bool group_gone = true;

    if (argc == 2 && strcmp(argv[1], "--help") == 0) {
        um_print_usage();
        return EXIT_SUCCESS;
    }
    if (argc < 2) {
        um_print_usage();
        return EXIT_FAILURE;
    }
    if (um_check_untraced() < 0)
        return EXIT_FAILURE;
    if (um_parse_args(argc, argv, &config, &guest_index) < 0) {
        um_cleanup_created_paths(&config);
        um_free_config(&config);
        return EXIT_FAILURE;
    }
    if (config.rootfs_kind == UM_ROOTFS_EXT4 &&
        um_make_runtime_root(&config.resolved_hostfs) < 0)
        goto failed;
    if (um_prepare_ext4_binds(&config) < 0)
        goto failed;
    if (um_make_session(&config, &session_path, &wrapper_path,
                        &init_path, &status_path) < 0)
        goto failed;
    if (um_write_binds_file(&config, session_path) < 0)
        goto failed;
    session_name = strrchr(session_path, '/') + 1;
    if (snprintf(status_guest_path, sizeof(status_guest_path), "/%s/status",
                 session_name) >= (int)sizeof(status_guest_path))
        goto failed;
    if (um_write_wrapper(wrapper_path, config.cwd, status_guest_path, &config,
                         config.rootfs_kind == UM_ROOTFS_EXT4,
                         config.bind_count > 0,
                         argc - guest_index,
                         &argv[guest_index]) < 0)
        goto failed;
    result = um_run_kernel(&config, init_path, session_path, status_path,
                           &group_gone);
    if (!group_gone) {
        fprintf(stderr,
                "neoproot-um: leaving runtime directory because UML is still running: %s\n",
                config.resolved_hostfs);
        free(session_path);
        free(wrapper_path);
        free(init_path);
        free(status_path);
        um_cleanup_created_paths(&config);
        um_free_config(&config);
        return EXIT_FAILURE;
    }
    /*
     * A COW file the caller named is theirs to keep; the temporary one belongs
     * to this run and goes away with it.
     */
    if (config.rootfs_kind == UM_ROOTFS_EXT4 && config.resolved_cow == NULL)
        um_unlink_session_file(session_path, "root.cow");
    /*
     * Binds were requested and the guest never declared that it can mount
     * them: the command may have reported success, but it ran without them.
     */
    if (config.rootfs_kind == UM_ROOTFS_EXT4 && config.bind_count > 0) {
        char protocol_error[256];

        if (um_session_error(session_path, protocol_error,
                             sizeof(protocol_error))) {
            fprintf(stderr, "neoproot-um: guest init reported: %s\n",
                    protocol_error);
            result = EXIT_FAILURE;
        } else if (!um_session_declares(session_path, UM_INIT_FEATURE_BINDS)) {
            fprintf(stderr,
                    "neoproot-um: the guest /um-init does not support binds "
                    "(init protocol 2)\n");
            fprintf(stderr,
                    "neoproot-um: update /um-init in the image, or drop -b\n");
            result = EXIT_FAILURE;
        }
    }
    um_unlink_session_file(session_path, UM_BINDS_NAME);
    um_unlink_session_file(session_path, UM_INIT_FEATURES_NAME);
    um_unlink_session_file(session_path, UM_PROTOCOL_ERROR_NAME);
    unlink(wrapper_path);
    unlink(status_path);
    if (config.rootfs_kind == UM_ROOTFS_EXT4) {
        if (rmdir(session_path) == 0) {
            (void)um_cleanup_runtime_root(config.resolved_hostfs);
        } else {
            fprintf(stderr,
                    "neoproot-um: session directory retained: %s\n",
                    session_path);
        }
    } else {
        (void)rmdir(session_path);
    }
    free(session_path);
    free(wrapper_path);
    free(init_path);
    free(status_path);
    um_cleanup_created_paths(&config);
    um_free_config(&config);
    return result;

failed:
    if (wrapper_path != NULL)
        unlink(wrapper_path);
    if (status_path != NULL)
        unlink(status_path);
    if (session_path != NULL) {
        um_unlink_session_file(session_path, UM_BINDS_NAME);
        um_unlink_session_file(session_path, UM_INIT_FEATURES_NAME);
        um_unlink_session_file(session_path, UM_PROTOCOL_ERROR_NAME);
        rmdir(session_path);
    }
    if (config.rootfs_kind == UM_ROOTFS_EXT4 && config.resolved_hostfs != NULL) {
        (void)um_cleanup_runtime_root(config.resolved_hostfs);
    }
    free(session_path);
    free(wrapper_path);
    free(init_path);
    free(status_path);
    um_cleanup_created_paths(&config);
    um_free_config(&config);
    return EXIT_FAILURE;
}
