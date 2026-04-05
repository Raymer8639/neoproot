#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include "path/proc.h"
#include "tracee/tracee.h"
#include "path/path.h"
#include "path/binding.h"

static inline int fast_strcmp(const char *a, const char *b)
{
    while (*a && *b && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

static inline size_t fast_strlen(const char *s)
{
    const char *p = s;
    while (*p) p++;
    return p - s;
}

static inline char *fast_strrchr(const char *s, int c)
{
    const char *last = NULL;
    while (*s) {
        if ((unsigned char)*s == (unsigned char)c) last = s;
        s++;
    }
    return (char *)last;
}

#define PROC_PREFIX         "/proc/"
#define PROC_PREFIX_LEN     6
#define PROC_SELF           "self"
#define PROC_SELF_LEN       4
#define PROC_EXE            "exe"
#define PROC_CWD            "cwd"
#define PROC_ROOT           "root"
#define PROC_FD             "fd"

Action readlink_proc(const Tracee *tracee, char result[PATH_MAX],
                     const char base[PATH_MAX], const char component[NAME_MAX],
                     Comparison comparison)
{
    const Tracee *known_tracee;
    char proc_path[64];
    int status;
    pid_t pid;

    if (comparison == PATHS_ARE_EQUAL) {
        if (fast_strlen(component) != PROC_SELF_LEN || fast_strcmp(component, PROC_SELF) != 0)
            return DEFAULT;

        status = snprintf(result, PATH_MAX, "/proc/%d", tracee->pid);
        if (status < 0 || status >= PATH_MAX)
            return -ENAMETOOLONG;

        return CANONICALIZE;
    }

    if (comparison != PATH1_IS_PREFIX)
        return DEFAULT;

    pid = atoi(base + PROC_PREFIX_LEN);
    if (pid == 0)
        return DEFAULT;

    snprintf(proc_path, sizeof(proc_path), "/proc/%d", pid);
    comparison = compare_paths(proc_path, base);

    if (comparison == PATHS_ARE_EQUAL) {
        known_tracee = get_tracee(tracee, pid, false);
        if (known_tracee == NULL)
            return DEFAULT;

        if (fast_strcmp(component, PROC_EXE) == 0) {
            size_t len = fast_strlen(known_tracee->exe);
            if (len >= PATH_MAX) return -ENAMETOOLONG;
            memcpy(result, known_tracee->exe, len + 1);
            return CANONICALIZE;
        }
        if (fast_strcmp(component, PROC_CWD) == 0) {
            size_t len = fast_strlen(known_tracee->fs->cwd);
            if (len >= PATH_MAX) return -ENAMETOOLONG;
            memcpy(result, known_tracee->fs->cwd, len + 1);
            return CANONICALIZE;
        }
        if (fast_strcmp(component, PROC_ROOT) == 0) {
            const char *root = get_root(known_tracee);
            size_t len = fast_strlen(root);
            if (len >= PATH_MAX) return -ENAMETOOLONG;
            memcpy(result, root, len + 1);
            return CANONICALIZE;
        }
        return DEFAULT;
    }

    snprintf(proc_path, sizeof(proc_path), "/proc/%d/fd", pid);
    comparison = compare_paths(proc_path, base);
    if (comparison == PATHS_ARE_EQUAL) {
        char *end_ptr;
        long fd_num = strtol(component, &end_ptr, 10);
        if (end_ptr == component || *end_ptr != '\0' || fd_num < 0)
            return -ENOENT;

        size_t base_len = fast_strlen(base);
        size_t comp_len = fast_strlen(component);
        if (base_len + 1 + comp_len >= PATH_MAX)
            return -ENAMETOOLONG;

        memcpy(result, base, base_len);
        result[base_len] = '/';
        memcpy(result + base_len + 1, component, comp_len + 1);
        return DONT_CANONICALIZE;
    }

    return DEFAULT;
}

ssize_t readlink_proc2(const Tracee *tracee, char result[PATH_MAX], const char referer[PATH_MAX])
{
    size_t referer_len = fast_strlen(referer);
    if (referer_len >= PATH_MAX)
        return -ENAMETOOLONG;

    if (referer_len < PROC_PREFIX_LEN || memcmp(referer, PROC_PREFIX, PROC_PREFIX_LEN) != 0)
        return 0;

    char base[PATH_MAX];
    memcpy(base, referer, referer_len + 1);

    char *component = fast_strrchr(base, '/');
    if (component == NULL || component == base)
        return 0;

    *component = '\0';
    component++;
    if (*component == '\0')
        return 0;

    Action action = readlink_proc(tracee, result, base, component, PATH1_IS_PREFIX);
    return (action == CANONICALIZE) ? (ssize_t)fast_strlen(result) : 0;
}
