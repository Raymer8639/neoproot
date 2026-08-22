#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static int fail(const char *message)
{
    perror(message);
    return 1;
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

int main(void)
{
    int proc_fd;
    int fd;
    int present;

    proc_fd = open("/proc", O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (proc_fd < 0)
        return fail("open /proc");

    if (mount("tmpfs", "/tmp", "tmpfs", 0, NULL) < 0)
        return fail("mount tmpfs /tmp");
    if (mkdir("/tmp/newroot", 0700) < 0)
        return fail("mkdir /tmp/newroot");
    if (mount("/tmp/newroot", "/tmp/newroot", NULL,
              MS_BIND | MS_REC | MS_SILENT, NULL) < 0)
        return fail("bind /tmp/newroot");
    if (mkdir("/tmp/oldroot", 0700) < 0)
        return fail("mkdir /tmp/oldroot");
    if (syscall(SYS_pivot_root, "/tmp", "/tmp/oldroot") < 0)
        return fail("pivot_root /tmp /tmp/oldroot");
    if (chdir("/") < 0)
        return fail("chdir after pivot_root");
    if (mount("/oldroot", "/newroot", NULL,
              MS_BIND | MS_REC | MS_SILENT, NULL) < 0)
        return fail("bind /oldroot /newroot");
    if (mount("proc", "/proc", "proc", 0, NULL) < 0)
        return fail("mount proc /proc");

    fd = openat(proc_fd, "self", O_PATH | O_CLOEXEC);
    if (fd < 0)
        return fail("openat inherited /proc self");
    close(fd);

    fd = openat(proc_fd, "self/mountinfo", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return fail("openat inherited /proc fd");
    present = mountinfo_has_mountpoint(fd, "/oldroot");
    if (present < 0)
        return fail("read inherited mountinfo");
    if (present == 0) {
        fprintf(stderr, "inherited mountinfo misses /oldroot\n");
        return 1;
    }

    return 0;
}
