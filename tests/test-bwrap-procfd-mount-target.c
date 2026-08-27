#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
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

static int mountinfo_has_mountpoint(int fd, const char *expected)
{
    FILE *mountinfo;
    char *line = NULL;
    size_t line_size = 0;
    int found = 0;

    mountinfo = fdopen(fd, "r");
    if (mountinfo == NULL) {
        close(fd);
        return -1;
    }
    while (getline(&line, &line_size, mountinfo) >= 0) {
        char *field = line;
        char *mountpoint;
        int i;

        for (i = 0; i < 4; i++) {
            field = strchr(field, ' ');
            if (field == NULL)
                break;
            field++;
        }
        if (field == NULL || i != 4)
            continue;
        mountpoint = field;
        field = strchr(mountpoint, ' ');
        if (field == NULL)
            continue;
        *field = '\0';
        if (strcmp(mountpoint, expected) == 0) {
            found = 1;
            break;
        }
    }
    free(line);
    fclose(mountinfo);
    return found;
}

static int bwrap_like_child(void *opaque)
{
    char proc_path[64];
    char resolved[PATH_MAX];
    int newroot_fd;
    int oldroot_fd;
    int dev_fd;
    int node_fd;
    int source_fd;
    int mountinfo_fd;
    int present;
    ssize_t length;

    (void) opaque;

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
    if (make_dir("/proc") != 0)
        return 1;
    if (mount("oldroot/proc", "proc", NULL, MS_BIND | MS_REC | MS_SILENT,
              NULL) < 0)
        return fail("bind oldroot proc");
    newroot_fd = open("/newroot", O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (newroot_fd < 0)
        return fail("open newroot");
    if (mkdirat(newroot_fd, "dev", 0755) < 0 && errno != EEXIST) {
        close(newroot_fd);
        return fail("mkdir newroot dev");
    }
    dev_fd = openat(newroot_fd, "dev", O_PATH | O_DIRECTORY | O_CLOEXEC);
    close(newroot_fd);
    if (dev_fd < 0)
        return fail("open newroot dev");
    if (snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", dev_fd)
        >= (int) sizeof(proc_path)) {
        close(dev_fd);
        return fail("format dev procfd");
    }
    if (mount("tmpfs", proc_path, "tmpfs", MS_NOSUID | MS_NODEV, NULL) < 0) {
        close(dev_fd);
        return fail("mount tmpfs on dev procfd");
    }
    close(dev_fd);

    newroot_fd = open("/newroot", O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (newroot_fd < 0)
        return fail("reopen newroot");
    dev_fd = openat(newroot_fd, "dev", O_PATH | O_DIRECTORY | O_CLOEXEC);
    close(newroot_fd);
    if (dev_fd < 0)
        return fail("reopen newroot dev");
    node_fd = openat(dev_fd, "null",
                     O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0444);
    if (node_fd < 0) {
        close(dev_fd);
        return fail("create newroot dev null");
    }
    close(node_fd);
    node_fd = openat(dev_fd, "null", O_PATH | O_NOFOLLOW | O_CLOEXEC);
    close(dev_fd);
    if (node_fd < 0)
        return fail("open newroot dev null");
    if (snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", node_fd)
        >= (int) sizeof(proc_path)) {
        close(node_fd);
        return fail("format node procfd");
    }
    length = readlink(proc_path, resolved, sizeof(resolved) - 1);
    if (length < 0)
        goto fail_node_fd;
    resolved[length] = '\0';
    if (strcmp(resolved, "/newroot/dev/null") != 0) {
        fprintf(stderr, "procfd target is %s, expected /newroot/dev/null\n",
                resolved);
        return 1;
    }

    oldroot_fd = open("/oldroot", O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (oldroot_fd < 0)
        return fail("open oldroot");
    source_fd = openat(oldroot_fd, "dev/null", O_PATH | O_CLOEXEC);
    close(oldroot_fd);
    if (source_fd < 0)
        return fail("open oldroot dev null");
    if (snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", source_fd)
        >= (int) sizeof(proc_path)) {
        close(source_fd);
        return fail("format source procfd");
    }
    {
        char dest_proc_path[64];

        if (snprintf(dest_proc_path, sizeof(dest_proc_path), "/proc/self/fd/%d",
                     node_fd) >= (int) sizeof(dest_proc_path)) {
            close(source_fd);
            close(node_fd);
            return fail("format destination procfd");
        }
        if (mount(proc_path, dest_proc_path, NULL,
                  MS_BIND | MS_REC | MS_SILENT, NULL) < 0) {
            close(source_fd);
            close(node_fd);
            return fail("bind device procfd");
        }
    }
    close(source_fd);
    close(node_fd);

    mountinfo_fd = open("/proc/self/mountinfo", O_RDONLY | O_CLOEXEC);
    if (mountinfo_fd < 0)
        return fail("open virtual mountinfo");
    present = mountinfo_has_mountpoint(mountinfo_fd, "/newroot/dev/null");
    if (present < 0)
        return fail("read virtual mountinfo");
    if (present == 0) {
        fprintf(stderr, "virtual mountinfo misses /newroot/dev/null procfd bind\n");
        return 1;
    }

    return 0;

fail_node_fd:
    close(node_fd);
    return fail("readlink newroot dev null procfd");
}

int main(void)
{
    void *stack;
    pid_t child;
    int status;

    stack = malloc(1024 * 1024);
    if (stack == NULL)
        return fail("allocate clone stack");
    child = clone(bwrap_like_child, (char *) stack + 1024 * 1024,
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
        fprintf(stderr, "bwrap-like child failed (status %d)\n", status);
        return 1;
    }
    return 0;
}
