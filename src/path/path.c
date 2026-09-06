#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdio.h>
#include <errno.h>
#include <stddef.h>
#include <inttypes.h>
#include <arm_neon.h>
#include <stdlib.h>

#include "path/path.h"
#include "path/binding.h"
#include "path/canon.h"
#include "path/proc.h"
#include "path/temp.h"
#include "path/f2fs-bug.h"
#include "extension/extension.h"
#include "cli/note.h"
#include "build.h"
#include "compat.h"

#define PROC_PREFIX_LEN 6

static inline int is_proc_path(const char *s)
{
    return (s[0] == '/' &&
            s[1] == 'p' &&
            s[2] == 'r' &&
            s[3] == 'o' &&
            s[4] == 'c' &&
            s[5] == '/');
}

/* bubblewrap deliberately reaches the host procfs through the old-root
 * alias (for example /oldroot/proc/self/fd/N).  Leaving that prefix in the
 * path makes procfs resolve "self" against the outer neoproot process rather
 * than the tracee.  Only the alias recorded by the emulated pivot_root is
 * trusted here; ordinary /oldroot paths keep their normal binding semantics. */
static const char *proc_path_after_alias(const Tracee *tracee,
                                         const char *path)
{
    const char *alias;
    size_t alias_len;

    if (tracee == NULL || tracee->fs == NULL ||
        tracee->fs->cwd_alias_prefix == NULL)
        return NULL;

    alias = tracee->fs->cwd_alias_prefix;
    alias_len = strlen(alias);
    if (alias_len == 0 || strncmp(path, alias, alias_len) != 0 ||
        path[alias_len] != '/')
        return NULL;

    path += alias_len;
    return is_proc_path(path) ? path : NULL;
}

static const char **proc_map_slot(Tracee *tracee, const char *path)
{
    static const char self_prefix[] = "/proc/self/";
    char pid_prefix[32];
    const char *entry = NULL;
    int length;

    if (strncmp(path, self_prefix, sizeof(self_prefix) - 1) == 0) {
        entry = path + sizeof(self_prefix) - 1;
    } else {
        length = snprintf(pid_prefix, sizeof(pid_prefix), "/proc/%d/",
                          tracee->pid);
        if (length < 0 || (size_t)length >= sizeof(pid_prefix) ||
            strncmp(path, pid_prefix, (size_t)length) != 0)
            return NULL;
        entry = path + length;
    }

    if (strcmp(entry, "uid_map") == 0)
        return &tracee->fs->proc_uid_map;
    if (strcmp(entry, "gid_map") == 0)
        return &tracee->fs->proc_gid_map;
    if (strcmp(entry, "setgroups") == 0)
        return &tracee->fs->proc_setgroups;
    return NULL;
}

static int translate_proc_passthrough(Tracee *tracee, char result[PATH_MAX],
                                      const char *path)
{
    Binding *binding;
    const char **map_slot;
    const char *tmp;
    int ret;

    /* A specific binding must retain precedence over proc compatibility
     * handling.  The plain /proc binding is intentionally passthrough. */
    binding = get_binding(tracee, GUEST, path);
    if (binding != NULL && is_proc_path(binding->guest.path) &&
        strcmp(binding->guest.path, "/proc") != 0) {
        strncpy(result, path, PATH_MAX - 1);
        result[PATH_MAX - 1] = 0;
        ret = substitute_binding(tracee, GUEST, result);
        if (ret < 0)
            return ret;
        goto translated;
    }

    if (strcmp(path, "/proc/self/mountinfo") == 0 ||
        strcmp(path, "/proc/thread-self/mountinfo") == 0) {
        int len = snprintf(result, PATH_MAX, "/proc/%d/mountinfo", tracee->pid);
        if (len < 0 || len >= PATH_MAX)
            return -ENAMETOOLONG;
        goto translated;
    }

    if (strncmp(path, "/proc/self/fd/", 14) == 0) {
        const char *fd = path + 14;
        char *end = NULL;
        long n = strtol(fd, &end, 10);
        if (*fd != 0 && *end == 0 && n >= 0) {
            int len = snprintf(result, PATH_MAX, "/proc/%d/fd/%ld", tracee->pid, n);
            if (len < 0 || len >= PATH_MAX)
                return -ENAMETOOLONG;
            goto translated;
        }
    }

    map_slot = proc_map_slot(tracee, path);
    if (map_slot != NULL) {
        if (*map_slot == NULL)
            *map_slot = create_temp_file(tracee->fs, "proc-map");
        tmp = *map_slot;
        if (tmp == NULL)
            return -ENOMEM;
        if (strlen(tmp) >= PATH_MAX)
            return -ENAMETOOLONG;
        strcpy(result, tmp);
        goto translated;
    }

    strncpy(result, path, PATH_MAX - 1);
    result[PATH_MAX - 1] = 0;

translated:
    ret = notify_extensions(tracee, TRANSLATED_PATH, (intptr_t)result, 0);
    return ret < 0 ? ret : 0;
}

int join_paths(int number_paths, char result[PATH_MAX], ...)
{
    va_list paths;
    size_t length = 0;
    int i;

    result[0] = '\0';

    va_start(paths, result);
    for (i = 0; i < number_paths; i++) {
        const char *path = va_arg(paths, const char *);
        if (!path || *path == '\0')
            continue;

        size_t path_len = strlen(path);
        int need_slash = (length > 0 && result[length-1] != '/' && path[0] != '/');
        size_t new_len = length + path_len + (need_slash ? 1 : 0);

        if (new_len + 1 >= PATH_MAX) {
            va_end(paths);
            return -ENAMETOOLONG;
        }

        if (need_slash) {
            result[length++] = '/';
        }
        else if (length > 0 && result[length-1] == '/' && path[0] == '/') {
            path++;
            path_len--;
        }

        memcpy(result + length, path, path_len);
        length += path_len;
    }
    va_end(paths);

    result[length] = '\0';
    return 0;
}

int which(Tracee *tracee, const char *paths, char host_path[PATH_MAX], const char *command)
{
    char path[PATH_MAX];
    const char *cursor;
    struct stat statr;
    bool is_explicit;
    bool found;

    assert(command != NULL);
    is_explicit = (strchr(command, '/') != NULL);

    if (realpath2(tracee, host_path, command, true) == 0 &&
        stat(host_path, &statr) == 0)
    {
        if (is_explicit && !S_ISREG(statr.st_mode)) {
            note(tracee, ERROR, USER, "'%s' is not a regular file", command);
            return -EACCES;
        }
        if (is_explicit && !(statr.st_mode & S_IXUSR)) {
            note(tracee, ERROR, USER, "'%s' is not executable", command);
            return -EACCES;
        }
        found = true;
        realpath2(tracee, host_path, command, false);
    } else
        found = false;

    if (is_explicit)
        return found ? 0 : -1;

    paths = paths ?: getenv("PATH");
    if (!paths || !*paths)
        goto not_found;

    cursor = paths;
    do {
        size_t len = strcspn(cursor, ":");
        if (len >= PATH_MAX) {
            cursor += len + 1;
            continue;
        }

        if (len == 0)
            path[0] = '.';
        else
            memcpy(path, cursor, len);
        path[len] = '/';
        strcpy(path + len + 1, command);

        if (realpath2(tracee, host_path, path, true) == 0 &&
            stat(host_path, &statr) == 0 &&
            S_ISREG(statr.st_mode) &&
            (statr.st_mode & S_IXUSR))
            return 0;

        cursor += len + 1;
    } while (*cursor);

not_found:
    getcwd2(tracee, path);
    note(tracee, ERROR, USER, "'%s' not found", command);
    return -1;
}

int realpath2(Tracee *tracee, char host_path[PATH_MAX], const char *path, bool deref_final)
{
    if (!tracee)
        return realpath(path, host_path) ? 0 : -errno;

    return translate_path(tracee, host_path, AT_FDCWD, path, deref_final);
}

int getcwd2(Tracee *tracee, char guest_path[PATH_MAX])
{
    if (!tracee)
        return getcwd(guest_path, PATH_MAX) ? 0 : -errno;

    size_t len = strlen(tracee->fs->cwd);
    if (len >= PATH_MAX)
        return -ENAMETOOLONG;

    memcpy(guest_path, tracee->fs->cwd, len + 1);
    return 0;
}

const char *get_reported_cwd(const Tracee *tracee)
{
    const char *cwd = tracee->fs->cwd;
    const char *alias = tracee->fs->cwd_alias_prefix;
    size_t alias_len;

    if (alias == NULL)
        return cwd;

    alias_len = strlen(alias);
    if (strncmp(cwd, alias, alias_len) != 0 ||
        (cwd[alias_len] != '\0' && cwd[alias_len] != '/'))
        return cwd;

    return cwd[alias_len] == '\0' ? "/" : cwd + alias_len;
}

static bool path_has_prefix(const char *path, const char *prefix)
{
    size_t prefix_len = strlen(prefix);

    return strncmp(path, prefix, prefix_len) == 0 &&
        (path[prefix_len] == '\0' || path[prefix_len] == '/');
}

/* The internal /oldroot spelling is an alias only when it points at the same
 * physical root as guest /.  A regular pivot keeps the old root at a
 * different host path and must retain its /oldroot cwd. */
void refresh_cwd_alias_prefix(Tracee *tracee)
{
    Binding *alias_binding;
    Binding *root_binding;

    if (tracee == NULL || tracee->fs == NULL)
        return;

    alias_binding = get_binding(tracee, GUEST, "/oldroot");
    root_binding = get_binding(tracee, GUEST, "/");
    if (alias_binding == NULL || root_binding == NULL ||
        strcmp(alias_binding->guest.path, "/oldroot") != 0 ||
        strcmp(root_binding->guest.path, "/") != 0 ||
        compare_paths2(alias_binding->host.path, alias_binding->host.length,
                       root_binding->host.path, root_binding->host.length) !=
            PATHS_ARE_EQUAL) {
        TALLOC_FREE(tracee->fs->cwd_alias_prefix);
        return;
    }

    if (tracee->fs->cwd_alias_prefix != NULL &&
        strcmp(tracee->fs->cwd_alias_prefix, "/oldroot") == 0)
        return;

    TALLOC_FREE(tracee->fs->cwd_alias_prefix);
    tracee->fs->cwd_alias_prefix = talloc_strdup(tracee->fs, "/oldroot");
}

/* A bwrap pivot can leave the tracer's cwd below /oldroot even though the
 * same physical directory is visible at its normal guest path.  Rebase only
 * when a non-alias binding proves that alternate path exists.  This keeps a
 * normal pivot's genuinely old-root cwd unchanged. */
int rebase_cwd_alias(Tracee *tracee)
{
    const char *alias;
    Binding *alias_binding;
    Binding *root_binding;
    Binding *binding;
    Binding *best = NULL;
    char host_path[PATH_MAX];
    char guest_path[PATH_MAX];
    size_t host_len;
    size_t best_host_len = 0;
    size_t guest_len;
    int status;

    if (tracee == NULL || tracee->fs == NULL || tracee->fs->cwd == NULL)
        return 0;

    alias = tracee->fs->cwd_alias_prefix;
    if (alias == NULL)
        return 0;
    if (!path_has_prefix(tracee->fs->cwd, alias))
        return 0;

    alias_binding = get_binding(tracee, GUEST, alias);
    root_binding = get_binding(tracee, GUEST, "/");
    if (alias_binding != NULL &&
        strcmp(alias_binding->guest.path, alias) != 0)
        alias_binding = NULL;
    if (root_binding == NULL || strcmp(root_binding->guest.path, "/") != 0)
        return 0;

    if (alias_binding != NULL &&
        compare_paths2(alias_binding->host.path, alias_binding->host.length,
                       root_binding->host.path, root_binding->host.length) !=
             PATHS_ARE_EQUAL)
        return 0;

    /* bwrap removes /oldroot before its second pivot, then briefly returns
     * there through a saved fd to detach it.  The prefix was verified while
     * the binding existed, so it remains valid until a later mount refreshes
     * the binding table. */
    if (alias_binding == NULL && strcmp(alias, "/oldroot") != 0)
        return 0;

    if (strlen(tracee->fs->cwd) >= sizeof(host_path))
        return -ENAMETOOLONG;
    strcpy(host_path, tracee->fs->cwd);
    status = substitute_binding(tracee, GUEST, host_path);
    if (status < 0)
        return 0;
    host_len = strlen(host_path);

    for (binding = CIRCLEQ_FIRST(tracee->fs->bindings.guest);
         binding != (void *) tracee->fs->bindings.guest;
         binding = CIRCLEQ_NEXT(binding, link.guest)) {
        Comparison cmp;

        if (!binding->need_substitution ||
            path_has_prefix(binding->guest.path, alias))
            continue;
        cmp = compare_paths2(binding->host.path, binding->host.length,
                             host_path, host_len);
        if ((cmp == PATHS_ARE_EQUAL || cmp == PATH1_IS_PREFIX) &&
            binding->host.length > best_host_len) {
            best = binding;
            best_host_len = binding->host.length;
        }
    }
    if (best == NULL)
        return 0;

    strcpy(guest_path, host_path);
    guest_len = substitute_path_prefix(guest_path, best->host.length,
                                       best->guest.path, best->guest.length);
    if (guest_len >= PATH_MAX)
        return -ENAMETOOLONG;
    if (strcmp(guest_path, tracee->fs->cwd) == 0)
        return 0;

    char *cwd = talloc_strdup(tracee->fs, guest_path);
    if (cwd == NULL)
        return -ENOMEM;
    TALLOC_FREE(tracee->fs->cwd);
    tracee->fs->cwd = cwd;
    talloc_set_name_const(tracee->fs->cwd, "$cwd");
    return 1;
}

void chop_finality(char *path)
{
    size_t len = strlen(path);
    if (len < 2) return;

    if (path[len-1] == '.')
        path[(len == 2) ? len-1 : len-2] = '\0';
    else if (path[len-1] == '/')
        path[len-1] = '\0';
}

int readlink_proc_pid_fd(pid_t pid, int fd, char path[PATH_MAX])
{
    char link[32];
    int st = snprintf(link, sizeof(link), "/proc/%d/fd/%d", pid, fd);
    if (st < 0 || (size_t)st >= sizeof(link))
        return -EBADF;

    st = readlink(link, path, PATH_MAX);
    if (st < 0) return -EBADF;
    if (st >= PATH_MAX) return -ENAMETOOLONG;
    path[st] = '\0';
    return 0;
}

#define DIRFD_CACHE_SIZE 64

static struct {
    pid_t pid;
    int fd;
    int host_fd;
    char proc_path[PATH_MAX];
    char guest_dir[PATH_MAX];
} dirfd_cache[DIRFD_CACHE_SIZE];
static size_t dirfd_cache_next;
static bool dirfd_cache_inited;
static int dirfd_fast_test = -1;
static int host_dirfd_test = -1;

static bool dirfd_fast_test_enabled(void)
{
    if (dirfd_fast_test < 0)
        dirfd_fast_test =
            getenv("NEOPROOT_TEST_DIRFD_FAST_PATH") != NULL ? 1 : 0;
    return dirfd_fast_test == 1;
}

static void dirfd_fast_note(const char *what)
{
    if (dirfd_fast_test_enabled())
        fprintf(stderr, "neoproot dirfd-fast: %s\n", what);
}

static bool host_dirfd_test_enabled(void)
{
    if (host_dirfd_test < 0)
        host_dirfd_test =
            getenv("NEOPROOT_TEST_HOST_DIRFD") != NULL ? 1 : 0;
    return host_dirfd_test == 1;
}

static void host_dirfd_note(const char *what)
{
    if (host_dirfd_test_enabled())
        fprintf(stderr, "neoproot host-dirfd: %s\n", what);
}

static void dirfd_cache_init(void)
{
    size_t index;

    if (dirfd_cache_inited)
        return;
    for (index = 0; index < DIRFD_CACHE_SIZE; index++) {
        dirfd_cache[index].fd = -1;
        dirfd_cache[index].host_fd = -1;
    }
    dirfd_cache_inited = true;
}

static void close_host_dirfd_slot(size_t index)
{
    if (dirfd_cache[index].host_fd >= 0) {
        close(dirfd_cache[index].host_fd);
        dirfd_cache[index].host_fd = -1;
    }
}

static int dup_cloexec(int fd)
{
    int copy;

    if (fd < 0)
        return -1;
    copy = dup(fd);
    if (copy < 0)
        return -1;
    (void)fcntl(copy, F_SETFD, FD_CLOEXEC);
    return copy;
}

static bool is_single_path_component(const char *path)
{
    const char *cursor;

    if (path == NULL || path[0] == '\0' || path[0] == '/')
        return false;
    if (path[0] == '.' &&
        (path[1] == '\0' || (path[1] == '.' && path[2] == '\0')))
        return false;
    if (strncmp(path, ".l2s.", 5) == 0 ||
        strncmp(path, ".proot.l2s.", 11) == 0)
        return false;
    for (cursor = path; *cursor != '\0'; cursor++) {
        if (*cursor == '/')
            return false;
    }
    return true;
}

static int dirfd_cache_slot(pid_t pid, int fd)
{
    size_t index;

    dirfd_cache_init();
    if (fd < 0)
        return -1;
    for (index = 0; index < DIRFD_CACHE_SIZE; index++) {
        if (dirfd_cache[index].pid == pid && dirfd_cache[index].fd == fd)
            return (int)index;
    }
    return -1;
}

void forget_translated_dirfd(pid_t pid, int fd)
{
    int slot = dirfd_cache_slot(pid, fd);

    if (slot < 0)
        return;
    close_host_dirfd_slot((size_t)slot);
    dirfd_cache[slot].pid = 0;
    dirfd_cache[slot].fd = -1;
    dirfd_cache[slot].proc_path[0] = '\0';
    dirfd_cache[slot].guest_dir[0] = '\0';
}

void forget_translated_dirfds_range(pid_t pid, unsigned int first, unsigned int last)
{
    size_t index;

    for (index = 0; index < DIRFD_CACHE_SIZE; index++) {
        int fd = dirfd_cache[index].fd;
        if (dirfd_cache[index].pid == pid && fd >= 0 &&
            (unsigned int)fd >= first && (unsigned int)fd <= last)
            forget_translated_dirfd(pid, fd);
    }
}

void clear_translated_dirfds(pid_t pid)
{
    size_t index;

    for (index = 0; index < DIRFD_CACHE_SIZE; index++) {
        if (dirfd_cache[index].pid == pid)
            forget_translated_dirfd(pid, dirfd_cache[index].fd);
    }
}

static void remember_translated_dirfd(pid_t pid, int fd,
                                      const char *proc_path,
                                      const char *guest_dir)
{
    int slot;

    if (fd < 0 || proc_path == NULL || proc_path[0] != '/' ||
        guest_dir == NULL || guest_dir[0] != '/')
        return;

    slot = dirfd_cache_slot(pid, fd);
    if (slot >= 0) {
        if (strcmp(dirfd_cache[slot].proc_path, proc_path) == 0 &&
            strcmp(dirfd_cache[slot].guest_dir, guest_dir) == 0)
            return;
        close_host_dirfd_slot((size_t)slot);
    } else {
        slot = (int)dirfd_cache_next;
        dirfd_cache_next = (dirfd_cache_next + 1) % DIRFD_CACHE_SIZE;
        close_host_dirfd_slot((size_t)slot);
    }
    dirfd_cache[slot].pid = pid;
    dirfd_cache[slot].fd = fd;
    dirfd_cache[slot].host_fd = -1;
    strncpy(dirfd_cache[slot].proc_path, proc_path, PATH_MAX - 1);
    dirfd_cache[slot].proc_path[PATH_MAX - 1] = '\0';
    strncpy(dirfd_cache[slot].guest_dir, guest_dir, PATH_MAX - 1);
    dirfd_cache[slot].guest_dir[PATH_MAX - 1] = '\0';
}

static void attach_host_dirfd(pid_t pid, int fd, int host_fd)
{
    int slot;

    if (host_fd < 0)
        return;
    slot = dirfd_cache_slot(pid, fd);
    if (slot < 0) {
        close(host_fd);
        return;
    }
    close_host_dirfd_slot((size_t)slot);
    dirfd_cache[slot].host_fd = host_fd;
}

void copy_translated_dirfd(pid_t pid, int source_fd, int target_fd)
{
    int slot = dirfd_cache_slot(pid, source_fd);
    char proc_path[PATH_MAX];
    char guest_dir[PATH_MAX];
    int host_dup = -1;

    if (slot < 0) {
        forget_translated_dirfd(pid, target_fd);
        return;
    }
    strcpy(proc_path, dirfd_cache[slot].proc_path);
    strcpy(guest_dir, dirfd_cache[slot].guest_dir);
    host_dup = dup_cloexec(dirfd_cache[slot].host_fd);
    remember_translated_dirfd(pid, target_fd, proc_path, guest_dir);
    attach_host_dirfd(pid, target_fd, host_dup);
}

void inherit_translated_dirfds(pid_t parent_pid, pid_t child_pid)
{
    size_t index;

    dirfd_cache_init();
    clear_translated_dirfds(child_pid);
    for (index = 0; index < DIRFD_CACHE_SIZE; index++) {
        char proc_path[PATH_MAX];
        char guest_dir[PATH_MAX];
        int fd;
        int host_dup;

        if (dirfd_cache[index].pid != parent_pid)
            continue;
        fd = dirfd_cache[index].fd;
        strcpy(proc_path, dirfd_cache[index].proc_path);
        strcpy(guest_dir, dirfd_cache[index].guest_dir);
        host_dup = dup_cloexec(dirfd_cache[index].host_fd);
        remember_translated_dirfd(child_pid, fd, proc_path, guest_dir);
        attach_host_dirfd(child_pid, fd, host_dup);
    }
}

static int try_dirfd_component_fast(Tracee *tracee, char result[PATH_MAX],
                                    int dir_fd, const char *user_path,
                                    const char *proc_path)
{
    int slot;
    int status;
    char guest_full[PATH_MAX];
    Binding *dir_binding;
    Binding *full_binding;

    slot = dirfd_cache_slot(tracee->pid, dir_fd);
    if (slot < 0 ||
        strcmp(dirfd_cache[slot].proc_path, proc_path) != 0) {
        dirfd_fast_note("miss");
        return -1;
    }

    status = join_paths(2, guest_full, dirfd_cache[slot].guest_dir, user_path);
    if (status < 0)
        return -1;

    dir_binding = get_binding(tracee, GUEST, dirfd_cache[slot].guest_dir);
    full_binding = get_binding(tracee, GUEST, guest_full);
    if (full_binding != dir_binding) {
        dirfd_fast_note("miss");
        return -1;
    }
    if (should_skip_file_access_due_to_f2fs_bug(tracee,
                                                dirfd_cache[slot].guest_dir))
        return -1;

    strcpy(result, dirfd_cache[slot].guest_dir);
    status = notify_extensions(tracee, GUEST_PATH, (intptr_t)result,
                               (intptr_t)user_path);
    if (status < 0)
        return status;
    if (status > 0)
        goto translated;

    strcpy(result, guest_full);
    if (is_proc_path(result) || proc_path_after_alias(tracee, result) != NULL)
        return -1;
    status = substitute_binding(tracee, GUEST, result);
    if (status < 0)
        return status;

translated:
    notify_extensions(tracee, TRANSLATED_PATH, (intptr_t)result, 0);
    dirfd_fast_note("hit");
    return 0;
}

static int ensure_host_dirfd(int slot, pid_t pid, int guest_fd)
{
    int fd;
    char procfd[64];

    if (slot < 0)
        return -1;
    if (dirfd_cache[slot].host_fd >= 0)
        return dirfd_cache[slot].host_fd;

    snprintf(procfd, sizeof(procfd), "/proc/%d/fd/%d", (int)pid, guest_fd);
    fd = open(procfd, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    dirfd_cache[slot].host_fd = fd;
    return fd;
}

static int populate_dirfd_cache(Tracee *tracee, int dir_fd)
{
    char proc_path[PATH_MAX];
    char guest_dir[PATH_MAX];
    int slot;

    if (readlink_proc_pid_fd(tracee->pid, dir_fd, proc_path) < 0)
        return -1;
    if (proc_path[0] != '/' || strcmp(proc_path, "/proc") == 0)
        return -1;
    strcpy(guest_dir, proc_path);
    if (detranslate_path(tracee, guest_dir, NULL) < 0)
        return -1;
    remember_translated_dirfd(tracee->pid, dir_fd, proc_path, guest_dir);
    slot = dirfd_cache_slot(tracee->pid, dir_fd);
    return slot;
}

int try_fstatat_cached_host_dirfd(Tracee *tracee, int dir_fd,
                                  const char *user_path, int flags,
                                  struct stat *st, char host_path[PATH_MAX])
{
    int slot;
    int host_fd;
    int status;
    char guest_full[PATH_MAX];
    Binding *dir_binding;
    Binding *full_binding;

    if (tracee == NULL || st == NULL || user_path == NULL || host_path == NULL)
        return 1;
    if (dir_fd == AT_FDCWD || dir_fd < 0)
        return 1;
    if ((flags & AT_SYMLINK_NOFOLLOW) == 0 || (flags & AT_EMPTY_PATH) != 0)
        return 1;
    if (!is_single_path_component(user_path))
        return 1;

    dirfd_cache_init();
    slot = dirfd_cache_slot(tracee->pid, dir_fd);
    if (slot < 0) {
        slot = populate_dirfd_cache(tracee, dir_fd);
        if (slot < 0) {
            host_dirfd_note("miss");
            return 1;
        }
    }

    if (dirfd_cache[slot].proc_path[0] == '\0' ||
        strcmp(dirfd_cache[slot].proc_path, "/proc") == 0 ||
        is_proc_path(dirfd_cache[slot].guest_dir) ||
        proc_path_after_alias(tracee, dirfd_cache[slot].guest_dir) != NULL) {
        host_dirfd_note("miss");
        return 1;
    }
    if (should_skip_file_access_due_to_f2fs_bug(tracee,
                                                dirfd_cache[slot].guest_dir))
        return 1;

    status = join_paths(2, guest_full, dirfd_cache[slot].guest_dir, user_path);
    if (status < 0) {
        host_dirfd_note("miss");
        return 1;
    }
    dir_binding = get_binding(tracee, GUEST, dirfd_cache[slot].guest_dir);
    full_binding = get_binding(tracee, GUEST, guest_full);
    if (full_binding != dir_binding) {
        host_dirfd_note("miss");
        return 1;
    }

    host_fd = ensure_host_dirfd(slot, tracee->pid, dir_fd);
    if (host_fd < 0) {
        host_dirfd_note("miss");
        return 1;
    }

    if (fstatat(host_fd, user_path, st, flags) < 0)
        return errno ? -errno : -ENOENT;

    if (join_paths(2, host_path, dirfd_cache[slot].proc_path, user_path) < 0)
        return 1;

    host_dirfd_note("hit");
    return 0;
}

bool is_proc_fd_mountinfo(const Tracee *tracee, int dir_fd,
                          const char *user_path)
{
    char proc_path[PATH_MAX];

    if (tracee == NULL || dir_fd == AT_FDCWD || user_path == NULL ||
        user_path[0] == '/' ||
        (strcmp(user_path, "self/mountinfo") != 0 &&
         strcmp(user_path, "thread-self/mountinfo") != 0))
        return false;

    if (readlink_proc_pid_fd(tracee->pid, dir_fd, proc_path) < 0)
        return false;

    return strcmp(proc_path, "/proc") == 0;
}

// 仅修改了这个入口函数，兼容线程池+原版双逻辑
int translate_path(Tracee *tracee, char result[PATH_MAX], int dir_fd,
                   const char *user_path, bool deref_final)
{
    char guest_path[PATH_MAX];
    const char *proc_path;
    int ret;

    if (is_proc_path(user_path)) {
        return translate_proc_passthrough(tracee, result, user_path);
    }

    proc_path = proc_path_after_alias(tracee, user_path);
    if (proc_path != NULL)
        return translate_proc_passthrough(tracee, result, proc_path);

    if (user_path[0] == '/') {
        result[0] = '/';
        result[1] = '\0';
    }
    else if (dir_fd != AT_FDCWD) {
        char fd_proc_path[PATH_MAX];

        ret = readlink_proc_pid_fd(tracee->pid, dir_fd, result);
        if (ret < 0)
            return ret;
        if (result[0] != '/')
            return -ENOTDIR;

        /* A directory fd referencing the real host procfs must remain the
         * guest /proc base even after pivot_root has exposed that same host
         * path through /oldroot. */
        if (strcmp(result, "/proc") != 0) {
            if (!deref_final && is_single_path_component(user_path) &&
                try_dirfd_component_fast(tracee, result, dir_fd, user_path,
                                         result) == 0)
                return 0;

            strcpy(fd_proc_path, result);
            ret = detranslate_path(tracee, result, NULL);
            if (ret < 0)
                return ret;
            remember_translated_dirfd(tracee->pid, dir_fd, fd_proc_path, result);
        }
    }
    else {
        ret = getcwd2(tracee, result);
        if (ret < 0) return ret;
    }

    ret = notify_extensions(tracee, GUEST_PATH, (intptr_t)result, (intptr_t)user_path);
    if (ret < 0) return ret;
    if (ret > 0) goto skip;

    ret = join_paths(2, guest_path, result, user_path);
    if (ret < 0) return ret;

    if (is_proc_path(guest_path)) {
        return translate_proc_passthrough(tracee, result, guest_path);
    }

    proc_path = proc_path_after_alias(tracee, guest_path);
    if (proc_path != NULL)
        return translate_proc_passthrough(tracee, result, proc_path);

    ret = canonicalize(tracee, guest_path, deref_final, result, 0);
    if (ret < 0) return ret;

    ret = substitute_binding(tracee, GUEST, result);
    if (ret < 0) return ret;

skip:
    notify_extensions(tracee, TRANSLATED_PATH, (intptr_t)result, 0);
    /* 必须返回 0：substitute_binding 成功时返回 1（“已替换”信号），
     * 不能外泄给调用者（which/realpath2 等只认 0 为成功）。
     * 2026-08-08 线程池删除后验证：原降级路径 return ret 泄漏 1
     * → which 失败 → 启动 fatal（真机 nothread 版复现）。上游 proot 同。 */
    return 0;
}

static int normalize_cwd_alias_path(const Tracee *tracee, char path[PATH_MAX])
{
    const char *alias;
    Binding *binding;
    size_t alias_len;
    ssize_t new_len;

    if (tracee == NULL || tracee->fs == NULL ||
        tracee->fs->cwd_alias_prefix == NULL)
        return 0;

    /* After bwrap detaches its old root, directory fds inherited from its
     * final chdir can still be reported through /oldroot.  This alias has
     * already been verified by refresh_cwd_alias_prefix(), so it is a guest
     * path, not a host path to detranslate again. */
    alias = tracee->fs->cwd_alias_prefix;
    alias_len = strlen(alias);
    if (alias_len == 0)
        return 0;
    if (strncmp(path, alias, alias_len) != 0 ||
        (path[alias_len] != '\0' && path[alias_len] != '/'))
        return 0;

    /* Do not collapse a more-specific binding below /oldroot.  It can be a
     * distinct bwrap mount whose guest path must retain the old-root prefix. */
    binding = get_binding(tracee, GUEST, path);
    if (binding == NULL || strcmp(binding->guest.path, alias) != 0)
        return 0;

    if (path[alias_len] == '\0') {
        path[0] = '/';
        path[1] = '\0';
        return 2;
    }

    new_len = strlen(path) - alias_len;
    memmove(path, path + alias_len, new_len + 1);
    return new_len + 1;
}

int detranslate_path(Tracee *tracee, char path[PATH_MAX], const char t_referrer[PATH_MAX])
{
    size_t root_len, prefix_len;
    ssize_t new_len;
    int status;

    if (strnlen(path, PATH_MAX) >= PATH_MAX)
        return -ENAMETOOLONG;
    if (path[0] != '/')
        return 0;

    if (is_proc_path(path))
        return strlen(path) + 1;

    bool follow_binding = true;
    if (t_referrer) {
        if (compare_paths("/proc/", t_referrer) == PATH1_IS_PREFIX) {
            char proc_path[PATH_MAX];
            memcpy(proc_path, path, PATH_MAX);
            int nl = readlink_proc2(tracee, proc_path, t_referrer);
            if (nl < 0) return nl;
            if (nl != 0) {
                memcpy(path, proc_path, PATH_MAX);
                return nl + 1;
            }
        }
        else if (!belongs_to_guestfs(tracee, t_referrer)) {
            const char *b_to = get_path_binding(tracee, HOST, path);
            const char *b_from = get_path_binding(tracee, HOST, t_referrer);
            if (b_to && b_from)
                follow_binding = (compare_paths(b_to, b_from) == PATHS_ARE_EQUAL);
        }
    }

    if (follow_binding) {
        int st = substitute_binding(tracee, HOST, path);
        if (st == 0) return 0;
        if (st == 1) {
            status = normalize_cwd_alias_path(tracee, path);
            return status != 0 ? status : strlen(path) + 1;
        }
    }

    switch (compare_paths(get_root(tracee), path)) {
        case PATH1_IS_PREFIX:
            root_len = strlen(get_root(tracee));
            prefix_len = (root_len == 1) ? 0 : root_len;
            new_len = strlen(path) - prefix_len;
            memmove(path, path + prefix_len, new_len + 1);
            return new_len + 1;

        case PATHS_ARE_EQUAL:
            path[0] = '/';
            path[1] = '\0';
            return 2;

        default:
            return (t_referrer == NULL) ? -EPERM : 0;
    }
}

bool belongs_to_guestfs(const Tracee *tracee, const char *host_path)
{
    Comparison c = compare_paths(get_root(tracee), host_path);
    return (c == PATHS_ARE_EQUAL || c == PATH1_IS_PREFIX);
}

Comparison compare_paths2(const char *path1, size_t len1,
                          const char *path2, size_t len2)
{
    size_t min_len;
    char end;

    if (len1 == 0 || len2 == 0)
        return PATHS_ARE_NOT_COMPARABLE;

    if (path1[len1-1] == '/') len1--;
    if (path2[len2-1] == '/') len2--;

    if (len1 < len2) {
        min_len = len1;
        end = path2[min_len];
    } else {
        min_len = len2;
        end = path1[min_len];
    }

    if (end != '/' && end != '\0')
        return PATHS_ARE_NOT_COMPARABLE;

    size_t i = 0;
    for (; i + 16 <= min_len; i += 16) {
        uint8x16_t v1 = vld1q_u8((const uint8_t *)(path1 + i));
        uint8x16_t v2 = vld1q_u8((const uint8_t *)(path2 + i));
        uint8x16_t eq = vceqq_u8(v1, v2);
        /* vmaxvq 无法检测"存在不等"（只要有一个字节相等最大值就是 0xff）
         * 必须用 vminvq：任一字节不等（0x00）则最小值非 0xff */
        if (vminvq_u8(eq) != 0xff)
            return PATHS_ARE_NOT_COMPARABLE;
    }
    for (; i < min_len; i++) {
        if (path1[i] != path2[i])
            return PATHS_ARE_NOT_COMPARABLE;
    }

    if (len1 == len2)
        return PATHS_ARE_EQUAL;
    return (len1 < len2) ? PATH1_IS_PREFIX : PATH2_IS_PREFIX;
}

Comparison compare_paths(const char *path1, const char *path2)
{
    return compare_paths2(path1, strlen(path1), path2, strlen(path2));
}

static int foreach_fd(const Tracee *tracee,
                      int (*callback)(const Tracee*, int, char*))
{
    struct dirent *dirent;
    char path[PATH_MAX], proc_fd[32];
    DIR *dirp;

    snprintf(proc_fd, sizeof(proc_fd), "/proc/%d/fd", tracee->pid);
    dirp = opendir(proc_fd);
    if (!dirp) return 0;

    while ((dirent = readdir(dirp))) {
        size_t l1 = strlen(proc_fd);
        size_t l2 = strlen(dirent->d_name);
        if (l1 + l2 + 2 >= PATH_MAX) continue;

        memcpy(path, proc_fd, l1);
        path[l1] = '/';
        strcpy(path + l1 + 1, dirent->d_name);

        int st = readlink(path, path, PATH_MAX);
        if (st <= 0 || st >= PATH_MAX) continue;
        if (path[0] != '/') continue;

        if (callback(tracee, atoi(dirent->d_name), path) < 0)
            break;
    }

    closedir(dirp);
    return 0;
}

static int list_open_fd_callback(const Tracee *tracee, int fd, char path[PATH_MAX])
{
    (void)tracee; (void)fd; (void)path;
    return 0;
}

int list_open_fd(const Tracee *tracee)
{
    return foreach_fd(tracee, list_open_fd_callback);
}

size_t substitute_path_prefix(char path[PATH_MAX], size_t old_prefix_len,
                              const char *new_prefix, size_t new_prefix_len)
{
    size_t path_len = strlen(path);
    size_t new_len;

    /* new_prefix 是 "/"（如 detranslate 回 guest 根）：
     * 结果 = 剩余部分（path[old_prefix_len..]，其自身已含前导 '/'，故 new_prefix
     * 隐含其中）；边界：整个路径被替换时结果应为 "/"（原代码得空串的 bug）。 */
    if (new_prefix_len == 1) {
        new_len = path_len - old_prefix_len;
        if (new_len == 0) {
            path[0] = '/';
            new_len = 1;
        }
        else
            memmove(path, path + old_prefix_len, new_len);
        path[new_len] = '\0';
        return new_len;
    }

    /* old_prefix 是 "/"（guest 根绑定）：结果 = new_prefix + 完整路径（含前导 '/'），
     * 路径长度 = new_prefix_len + path_len。
     * 历史 bug：path_len==1（路径就是 "/"）时原 memmove 被跳过，path[new_prefix_len]
     * 位置未写终止符，把调用者缓冲残留字节（栈垃圾）拼进结果——真机症状：
     * stat("/") 翻译成 ".../rootfsq"（多一个 'q'）→ ENOENT → rm -rf 报
     * "failed to get attributes of '/'"。线程池版因 worker 的 memset(result,0)
     * 恰好清零掩盖了此 bug（83e37e0 移除线程池后暴露）。 */
    if (old_prefix_len == 1) {
        if (path_len == 1) {
            new_len = new_prefix_len;
            if (new_len >= PATH_MAX) return -ENAMETOOLONG;
            memcpy(path, new_prefix, new_prefix_len);
            path[new_len] = '\0';
            return new_len;
        }
        new_len = new_prefix_len + path_len;
        if (new_len >= PATH_MAX) return -ENAMETOOLONG;
        memmove(path + new_prefix_len, path, path_len + 1);
        memcpy(path, new_prefix, new_prefix_len);
        return new_len;
    }

    new_len = new_prefix_len + (path_len - old_prefix_len);
    if (new_len >= PATH_MAX) return -ENAMETOOLONG;

    memmove(path + new_prefix_len, path + old_prefix_len, path_len - old_prefix_len);
    memcpy(path, new_prefix, new_prefix_len);
    path[new_len] = '\0';
    return new_len;
}
