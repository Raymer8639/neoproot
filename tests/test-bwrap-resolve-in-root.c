#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <limits.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int fail(const char *message)
{
    perror(message);
    return 1;
}

static int make_dir(const char *path)
{
    if (mkdir(path, 0700) < 0 && errno != EEXIST)
        return fail(path);
    return 0;
}

static int openat_in_root(int dirfd, const char *path)
{
    struct open_how how = {
        .flags = O_PATH | O_CLOEXEC,
        .resolve = RESOLVE_IN_ROOT,
    };

    return syscall(SYS_openat2, dirfd, path, &how, sizeof(how));
}

static int check_relative_cwd(const char *context)
{
    struct stat stat_buffer;

    if (stat("relative-probe", &stat_buffer) < 0)
        return fail(context);
    if (!S_ISREG(stat_buffer.st_mode)) {
        fprintf(stderr, "%s did not resolve a regular file\n", context);
        return 1;
    }
    return 0;
}

static int check_reported_cwd(void)
{
    static const char expected[] = "/cwd-probe";
    char cwd[PATH_MAX];
    char proc_cwd[PATH_MAX];
    char proc_pid[64];
    char exact[sizeof(expected)];
    char truncated[4];
    ssize_t length;

    if (getcwd(cwd, sizeof(cwd)) == NULL)
        return fail("getcwd after bwrap pivot");
    if (strcmp(cwd, expected) != 0) {
        fprintf(stderr, "getcwd reported %s, expected /cwd-probe\n", cwd);
        return 1;
    }
    if (check_relative_cwd("relative stat after bwrap pivot") != 0)
        return 1;

    length = readlink("/proc/self/cwd", proc_cwd, sizeof(proc_cwd) - 1);
    if (length < 0)
        return fail("readlink /proc/self/cwd after bwrap pivot");
    proc_cwd[length] = '\0';
    if (strcmp(proc_cwd, expected) != 0) {
        fprintf(stderr, "/proc/self/cwd reported %s, expected /cwd-probe\n",
                proc_cwd);
        return 1;
    }

    length = readlink("/proc/self/cwd", exact, sizeof(exact));
    if (length != (ssize_t)strlen(expected) ||
        memcmp(exact, expected, strlen(expected)) != 0) {
        fprintf(stderr, "/proc/self/cwd exact buffer returned %zd\n", length);
        return 1;
    }

    length = readlink("/proc/self/cwd", truncated, sizeof(truncated));
    if (length != (ssize_t)sizeof(truncated) ||
        memcmp(truncated, expected, sizeof(truncated)) != 0) {
        fprintf(stderr, "/proc/self/cwd truncated buffer returned %zd\n", length);
        return 1;
    }

    if (snprintf(proc_pid, sizeof(proc_pid), "/proc/%d/cwd", getpid()) >=
        (int)sizeof(proc_pid))
        return fail("format /proc/pid/cwd");
    length = readlink(proc_pid, exact, sizeof(exact));
    if (length != (ssize_t)strlen(expected) ||
        memcmp(exact, expected, strlen(expected)) != 0) {
        fprintf(stderr, "/proc/pid/cwd exact buffer returned %zd\n", length);
        return 1;
    }

    return 0;
}

static int single_pivot_child(void *opaque)
{
    (void) opaque;

    if (mount("tmpfs", "/tmp", "tmpfs", 0, NULL) < 0)
        return fail("mount tmpfs for single pivot");
    if (make_dir("/tmp/newroot") != 0 || make_dir("/tmp/oldroot") != 0)
        return 1;
    if (mount("/tmp/newroot", "/tmp/newroot", NULL,
              MS_BIND | MS_REC | MS_SILENT, NULL) < 0)
        return fail("bind newroot for single pivot");
    if (syscall(SYS_pivot_root, "/tmp", "/tmp/oldroot") < 0)
        return fail("single pivot_root");
    if (chdir("/") < 0)
        return fail("chdir after single pivot_root");
    if (chdir("/oldroot/cwd-probe") < 0)
        return fail("chdir oldroot cwd after single pivot");

    return check_relative_cwd("relative stat after single pivot");
}

static int bwrap_like_child(void *opaque)
{
    char source_proc_path[64];
    char target_proc_path[64];
    int oldroot_fd;
    int source_fd;
    int target_fd;
    int fd;

    (void) opaque;

    if (mount("/", "/", NULL, MS_BIND | MS_REC | MS_RDONLY, NULL) < 0)
        return fail("bind virtual root read-only");
    if (mount("tmpfs", "/tmp", "tmpfs", 0, NULL) < 0)
        return fail("mount tmpfs /tmp");
    if (make_dir("/tmp/newroot") != 0 || make_dir("/tmp/oldroot") != 0)
        return 1;
    if (mount("/tmp/newroot", "/tmp/newroot", NULL,
              MS_BIND | MS_REC | MS_SILENT, NULL) < 0)
        return fail("bind /tmp/newroot");
    if (syscall(SYS_pivot_root, "/tmp", "/tmp/oldroot") < 0)
        return fail("pivot_root /tmp /tmp/oldroot");
    if (chdir("/") < 0)
        return fail("chdir after pivot_root");
    if (make_dir("/oldroot/cwd-probe") != 0)
        return 1;
    if (make_dir("/proc") != 0)
        return 1;
    if (mount("oldroot/proc", "proc", NULL, MS_BIND | MS_REC | MS_SILENT,
              NULL) < 0)
        return fail("bind oldroot proc");

    oldroot_fd = open("/oldroot", O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (oldroot_fd < 0)
        return fail("open oldroot");
    source_fd = openat_in_root(oldroot_fd, "/");
    close(oldroot_fd);
    if (source_fd < 0)
        return fail("openat2 oldroot /");

    target_fd = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (target_fd < 0) {
        close(source_fd);
        return fail("open newroot");
    }
    if (snprintf(source_proc_path, sizeof(source_proc_path),
                 "/proc/self/fd/%d", source_fd) >=
            (int) sizeof(source_proc_path) ||
        snprintf(target_proc_path, sizeof(target_proc_path),
                 "/proc/self/fd/%d", target_fd) >=
            (int) sizeof(target_proc_path)) {
        close(target_fd);
        close(source_fd);
        return fail("format procfd path");
    }
    if (mount(source_proc_path, target_proc_path, NULL,
              MS_BIND | MS_REC | MS_SILENT, NULL) < 0) {
        close(target_fd);
        close(source_fd);
        return fail("bind oldroot to newroot");
    }
    close(target_fd);
    close(source_fd);

    if (chdir("/newroot") < 0)
        return fail("chdir bwrap newroot");
    if (syscall(SYS_pivot_root, ".", ".") < 0)
        return fail("second pivot_root bwrap newroot");
    if (chdir("/") < 0)
        return fail("chdir after second pivot_root");

    if (mount("proc", "/proc", "proc", 0, NULL) < 0)
        return fail("mount fresh proc after second pivot_root");

    if (chdir("/oldroot/cwd-probe") < 0)
        return fail("chdir oldroot cwd probe");
    if (check_reported_cwd() != 0)
        return 1;

    fd = open("/probe", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return fail("probe is missing from bwrap root bind");
    close(fd);
    return 0;
}

static int run_child(const char *name, int (*child_fn)(void *))
{
    void *stack;
    pid_t child;
    int status;

    stack = malloc(1024 * 1024);
    if (stack == NULL)
        return fail("allocate clone stack");
    child = clone(child_fn, (char *) stack + 1024 * 1024,
                  CLONE_NEWNS | CLONE_NEWPID | SIGCHLD, NULL);
    if (child < 0) {
        free(stack);
        return fail("clone bwrap-like child");
    }
    if (waitpid(child, &status, 0) < 0) {
        free(stack);
        return fail("wait bwrap-like child");
    }
    free(stack);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "%s failed (status %d)\n", name, status);
        return 1;
    }
    return 0;
}

int main(void)
{
    if (run_child("single-pivot child", single_pivot_child) != 0)
        return 1;
    return run_child("bwrap-like child", bwrap_like_child);
}
