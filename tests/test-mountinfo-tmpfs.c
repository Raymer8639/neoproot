#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <unistd.h>

static int fail(const char *message)
{
    perror(message);
    return 1;
}

static void unescape_mountinfo(char *dst, size_t dst_size, const char *src)
{
    size_t out = 0;

    while (*src != '\0' && out + 1 < dst_size) {
        if (src[0] == '\\' && src[1] >= '0' && src[1] <= '7' &&
            src[2] >= '0' && src[2] <= '7' && src[3] >= '0' && src[3] <= '7') {
            dst[out++] = (char)(((src[1] - '0') << 6) |
                                ((src[2] - '0') << 3) |
                                (src[3] - '0'));
            src += 4;
        } else {
            dst[out++] = *src++;
        }
    }
    dst[out] = '\0';
}

static int mountinfo_has_mountpoint(const char *expected)
{
    FILE *mountinfo;
    char *line = NULL;
    size_t line_size = 0;
    int found = 0;

    mountinfo = fopen("/proc/self/mountinfo", "r");
    if (mountinfo == NULL)
        return -1;

    while (getline(&line, &line_size, mountinfo) >= 0) {
        char *field = line;
        char *mountpoint;
        char decoded[4096];
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
        unescape_mountinfo(decoded, sizeof(decoded), mountpoint);
        if (strcmp(decoded, expected) == 0) {
            found = 1;
            break;
        }
    }

    free(line);
    fclose(mountinfo);
    return found;
}

int main(int argc, char *argv[])
{
    const char *target;
    char procfd[64];
    char backing[4096];
    int fd;
    int present;
    ssize_t size;

    if (argc != 2) {
        fprintf(stderr, "usage: %s TARGET\n", argv[0]);
        return 2;
    }
    target = argv[1];

    if (mount("tmpfs", target, "tmpfs", 0, NULL) < 0)
        return fail("mount tmpfs");

    fd = open(target, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
        return fail("open tmpfs target");

    if (snprintf(procfd, sizeof(procfd), "/proc/self/fd/%d", fd) >=
        (int)sizeof(procfd)) {
        fprintf(stderr, "procfd path too long\n");
        close(fd);
        return 1;
    }
    size = readlink(procfd, backing, sizeof(backing) - 1);
    if (size < 0) {
        close(fd);
        return fail("readlink tmpfs procfd");
    }
    backing[size] = '\0';

    present = mountinfo_has_mountpoint(backing);
    if (present < 0) {
        close(fd);
        return fail("open mountinfo");
    }
    if (present == 0) {
        fprintf(stderr, "mountinfo misses procfd target: %s\n", backing);
        close(fd);
        return 1;
    }

    if (umount(target) < 0) {
        close(fd);
        return fail("umount tmpfs");
    }
    close(fd);

    present = mountinfo_has_mountpoint(backing);
    if (present < 0)
        return fail("reopen mountinfo");
    if (present != 0) {
        fprintf(stderr, "mountinfo kept removed tmpfs target: %s\n", backing);
        return 1;
    }

    return 0;
}
