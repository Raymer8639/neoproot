#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int fail(const char *message)
{
    perror(message);
    return 1;
}

int main(int argc, char *argv[])
{
    int fd;

    if (argc != 2) {
        fprintf(stderr, "usage: %s OUTSIDE_DIRECTORY\n", argv[0]);
        return 2;
    }

    fd = open("/safe/probe", O_RDONLY);
    if (fd < 0)
        return fail("open cached directory");
    close(fd);

    if (unlink("/safe/probe") < 0 || rmdir("/safe") < 0)
        return fail("replace cached directory");
    if (symlink(argv[1], "/safe") < 0)
        return fail("create replacement symlink");

    fd = open("/safe/secret", O_RDONLY);
    if (fd >= 0) {
        close(fd);
        fprintf(stderr, "rootfs escape through stale path state\n");
        return 1;
    }
    if (errno != ENOENT && errno != EACCES && errno != ENOTDIR)
        return fail("reject replacement symlink");

    if (symlink(".l2s.malformed", "/l2s/victim") < 0 ||
        symlink("x", "/l2s/.l2s.malformed") < 0)
        return fail("create malformed l2s chain");
    if (unlink("/l2s/victim") < 0)
        return fail("reject malformed l2s chain");

    fd = open("/owned", O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
        return fail("create fake-id0 file");
    close(fd);
    if (chown("/owned", 123, 456) < 0)
        return fail("update fake-id0 metadata");

    return 0;
}
