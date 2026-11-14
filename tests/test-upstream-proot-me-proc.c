/* Preserve the existing proc path fixes while importing auxv changes. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "path/proc.h"

Tracee *get_tracee(const Tracee *tracee, pid_t pid, bool create)
{
    assert(!create);
    return pid == tracee->pid ? (Tracee *)tracee : NULL;
}

const char *get_root(const Tracee *tracee)
{
    (void)tracee;
    return "/guest-root";
}

static ssize_t read_proc(const Tracee *tracee, char result[PATH_MAX], const char *name)
{
    char path[PATH_MAX];
    assert(strlen(name) < sizeof(path));
    strcpy(path, name);
    return readlink_proc2(tracee, result, path);
}

int main(void)
{
    FileSystemNameSpace fs = { .cwd = "/guest-cwd" };
    Tracee tracee = { .pid = getpid(), .fs = &fs, .exe = "/guest-bin" };
    char result[PATH_MAX], expected[PATH_MAX], path[PATH_MAX];
    snprintf(expected, sizeof(expected), "/proc/%d", tracee.pid);
    assert(read_proc(&tracee, result, "/proc/self") == (ssize_t)strlen(expected));
    assert(strcmp(result, expected) == 0);
    assert(read_proc(&tracee, result, "/proc/self/exe") == 10);
    assert(strcmp(result, "/guest-bin") == 0);
    assert(read_proc(&tracee, result, "/proc/self/cwd") == 10);
    assert(strcmp(result, "/guest-cwd") == 0);
    assert(read_proc(&tracee, result, "/proc/self/root") == 11);
    assert(strcmp(result, "/guest-root") == 0);
    assert(read_proc(&tracee, result, "/proc/device-tree") == 0);
    assert(read_proc(&tracee, result, "/proc/selfish/exe") == 0);

    snprintf(path, sizeof(path), "/proc/%d/exe", tracee.pid);
    assert(read_proc(&tracee, result, path) == 10);
    assert(strcmp(result, "/guest-bin") == 0);
    /* The bind /proc/self/fd:/dev/fd must retain the tracee's fd namespace. */
    char fd_base[PATH_MAX] = "/proc/self/fd";
    char fd_component[NAME_MAX] = "17";
    assert(readlink_proc(&tracee, result, fd_base, fd_component,
                         PATH1_IS_PREFIX) == DONT_CANONICALIZE);
    snprintf(expected, sizeof(expected), "/proc/%d/fd/17", tracee.pid);
    assert(strcmp(result, expected) == 0);
    puts("proot-me proc/self and procfd normalization passed");
    return 0;
}
