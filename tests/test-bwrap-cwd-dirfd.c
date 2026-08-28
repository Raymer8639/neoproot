#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(void)
{
    int marker;
    int private_fd;
    char value;

    if (fcntl(9, F_GETFD) < 0) {
        perror("fcntl inherited directory fd");
        return 1;
    }

    marker = openat(9, "child/marker", O_RDONLY | O_CLOEXEC);
    if (marker < 0) {
        perror("openat inherited directory fd");
        return 1;
    }
    if (read(marker, &value, 1) != 1 || value != 'c') {
        perror("read child marker");
        close(marker);
        return 1;
    }
    close(marker);

    private_fd = openat(9, "private", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (private_fd < 0) {
        perror("openat nested binding directory");
        return 1;
    }
    marker = openat(private_fd, "marker", O_RDONLY | O_CLOEXEC);
    if (marker < 0) {
        perror("openat nested binding");
        close(private_fd);
        return 1;
    }
    if (read(marker, &value, 1) != 1 || value != 'p') {
        perror("read private marker");
        close(marker);
        close(private_fd);
        return 1;
    }
    close(marker);
    close(private_fd);
    return 0;
}
