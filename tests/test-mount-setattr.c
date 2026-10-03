#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SYS_mount_setattr
#define SYS_mount_setattr 442
#endif
#ifndef AT_RECURSIVE
#define AT_RECURSIVE 0x8000
#endif

typedef struct {
    uint64_t attr_set;
    uint64_t attr_clr;
    uint64_t propagation;
    uint64_t userns_fd;
} MountAttributes;

static int change_attributes(int dirfd, const char *path, unsigned int flags,
                             const MountAttributes *attributes, size_t size)
{
    return syscall(SYS_mount_setattr, dirfd, path, flags, attributes, size);
}

static int expect_error(int result, int expected, const char *operation)
{
    if (result == -1 && errno == expected)
        return 0;
    fprintf(stderr, "%s: result=%d errno=%d expected=%d\n", operation, result, errno, expected);
    return 1;
}

static int expect_open(const char *path, int flags, int expected)
{
    int descriptor = open(path, flags);
    int status = expected ? expect_error(descriptor, expected, path) : descriptor < 0;
    if (expected == 0 && descriptor < 0)
        perror(path);
    if (descriptor >= 0)
        close(descriptor);
    return status;
}

static int check_rw_mount_identity(void *argument)
{
    (void)argument;
    MountAttributes readonly = {.attr_set = MS_RDONLY};
    char procfd[64];
    int source_fd = open("/workspace-source", O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (source_fd < 0 || mount("/", "/", NULL, MS_BIND | MS_REC, NULL) < 0 ||
        change_attributes(AT_FDCWD, "/", AT_RECURSIVE, &readonly, sizeof(readonly)) < 0)
        return 1;
    snprintf(procfd, sizeof(procfd), "/proc/self/fd/%d", source_fd);
    if (mount(procfd, "/rw-workspace", NULL, MS_BIND | MS_REC, NULL) < 0 ||
        expect_open("/rw-workspace/marker", O_WRONLY, 0) ||
        expect_open("/workspace-source/marker", O_WRONLY, EROFS)) {
        perror("rw bind must preserve source fd mount identity");
        return 1;
    }
    close(source_fd);
    int protected_fd = open("/workspace-source/protected", O_PATH | O_DIRECTORY | O_CLOEXEC);
    snprintf(procfd, sizeof(procfd), "/proc/self/fd/%d", protected_fd);
    if (protected_fd < 0 || mount(procfd, "/rw-workspace/protected", NULL, MS_BIND, NULL) < 0 ||
        expect_open("/rw-workspace/protected/marker", O_WRONLY, EROFS))
        return 1;
    close(protected_fd);
    return 0;
}

static int check_clone(void *argument)
{
    (void)argument;
    return expect_open("/mnt/file", O_WRONLY, EROFS) ||
           expect_open("/mnt/child/file", O_WRONLY, EROFS) ||
           expect_open("/mnt/device", O_RDONLY, EACCES);
}

static int check_unshare_isolation(void *argument)
{
    int child_status;
    pid_t child_pid;

    (void)argument;
    child_pid = fork();
    if (child_pid == 0) {
        MountAttributes readonly = {.attr_set = MS_RDONLY};
        if (unshare(CLONE_NEWNS) < 0 ||
            change_attributes(AT_FDCWD, "/", AT_RECURSIVE,
                              &readonly, sizeof(readonly)) < 0 ||
            expect_open("/parent-write/marker", O_WRONLY, EROFS) != 0)
            _exit(1);
        _exit(0);
    }
    if (child_pid < 0 || waitpid(child_pid, &child_status, 0) != child_pid ||
        !WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0)
        return 1;
    return expect_open("/parent-write/marker", O_WRONLY, 0);
}

static int clone_readonly_namespace(void *argument)
{
    MountAttributes readonly = {.attr_set = MS_RDONLY};

    (void)argument;
    if (change_attributes(AT_FDCWD, "/", AT_RECURSIVE,
                           &readonly, sizeof(readonly)) < 0 ||
        expect_open("/parent-write/marker", O_WRONLY, EROFS) != 0)
        return 1;
    return 0;
}

static int check_clone_fs_isolation(void)
{
    const size_t stack_size = 65536;
    void *child_stack = malloc(stack_size);
    int child_status = 0;
    pid_t child_pid;

    if (child_stack == NULL)
        return 1;
    child_pid = clone(clone_readonly_namespace,
                      (char *)child_stack + stack_size,
                      CLONE_NEWNS | CLONE_FS | SIGCHLD, NULL);
    if (child_pid < 0 || waitpid(child_pid, &child_status, 0) != child_pid ||
        !WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0) {
        free(child_stack);
        return 1;
    }
    free(child_stack);
    return expect_open("/parent-write/marker", O_WRONLY, 0);
}

int main(int argc, char **argv)
{
    MountAttributes attributes = {0};
    struct {
        MountAttributes attributes;
        uint64_t extra;
    } extended = {0};
    int descriptor;
    int status = 0;
    pid_t child_pid;
    void *child_stack;
    const size_t stack_size = 65536;

    if (argc == 2 && strcmp(argv[1], "nosuid") == 0) {
        if (geteuid() != 1234 || getegid() != 1234) {
            fprintf(stderr, "nosuid lost virtual identity: uid=%u gid=%u\n", geteuid(), getegid());
            return 1;
        }
        return 0;
    }
    child_stack = malloc(stack_size);
    if (child_stack == NULL)
        return 1;
    child_pid = clone(check_rw_mount_identity, (char *)child_stack + stack_size,
                      CLONE_NEWNS | SIGCHLD, NULL);
    if (child_pid < 0 || waitpid(child_pid, &status, 0) != child_pid ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "rw mount identity child failed: status=%d\n", status);
        return 1;
    }
    free(child_stack);
    if (check_unshare_isolation(NULL) != 0) {
        fprintf(stderr, "unshare mount namespace leaked readonly state to parent\n");
        return 1;
    }
    if (check_clone_fs_isolation() != 0) {
        fprintf(stderr, "clone CLONE_FS mount namespace leaked readonly state to parent\n");
        return 1;
    }
    MountAttributes proc_attributes = {.attr_set = MS_RDONLY};
    if (change_attributes(AT_FDCWD, "/proc", 0, &proc_attributes, sizeof(proc_attributes)) < 0)
        return 1;
    int device_source = open("/dev/null", O_RDONLY | O_CLOEXEC);
    char device_source_path[64];
    snprintf(device_source_path, sizeof(device_source_path), "/proc/self/fd/%d", device_source);
    if (device_source < 0 ||
        mount(device_source_path, "/fd-device", NULL, MS_BIND, NULL) < 0 ||
        expect_open("/fd-device", O_WRONLY, 0)) {
        perror("device fd must not inherit proc mount attributes");
        return 1;
    }
    close(device_source);
    if (mount("/source", "/mnt", NULL, MS_BIND, NULL) < 0 ||
        mount("/child-source", "/mnt/child", NULL, MS_BIND, NULL) < 0 ||
        mount("/dev/null", "/mnt/device", NULL, MS_BIND, NULL) < 0) {
        perror("mount fixtures");
        return 1;
    }
    descriptor = open("/mnt", O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (descriptor < 0)
        return 1;
    if (expect_error(change_attributes(descriptor, "", 0, &attributes, sizeof(attributes)),
                     ENOENT, "empty path without AT_EMPTY_PATH") ||
        expect_error(change_attributes(descriptor, "", AT_EMPTY_PATH, &attributes, 31),
                     EINVAL, "short attributes") ||
        expect_error(change_attributes(descriptor, "", AT_EMPTY_PATH, &attributes, 4097),
                     E2BIG, "oversized attributes") ||
        expect_error(change_attributes(descriptor, "", AT_EMPTY_PATH, NULL, sizeof(attributes)),
                     EFAULT, "invalid attributes pointer") ||
        expect_error(change_attributes(descriptor, "", 0x40000000, &attributes, sizeof(attributes)),
                     EINVAL, "unknown flags") ||
        expect_error(change_attributes(AT_FDCWD, "/missing", 0, &attributes, sizeof(attributes)),
                     ENOENT, "missing path"))
        return 1;
    extended.extra = 1;
    if (expect_error(change_attributes(descriptor, "", AT_EMPTY_PATH,
                                       &extended.attributes, sizeof(extended)),
                     E2BIG, "nonzero attribute extension"))
        return 1;
    attributes.attr_set = MS_NOEXEC;
    if (expect_error(change_attributes(descriptor, "", AT_EMPTY_PATH,
                                       &attributes, sizeof(attributes)),
                     EOPNOTSUPP, "unsupported attribute"))
        return 1;
    attributes.attr_set = MS_RDONLY | MS_NOSUID | MS_NODEV;
    puts("mount_setattr argument validation passed");
    if (change_attributes(descriptor, "", AT_EMPTY_PATH | AT_RECURSIVE,
                          &attributes, sizeof(attributes)) < 0) {
        perror("recursive mount_setattr through fd");
        return 1;
    }
    close(descriptor);
    if (check_clone(NULL) || expect_open("/mnt/device", O_PATH, 0))
        return 1;
    puts("mount_setattr readonly/nodev checks passed");
    child_stack = malloc(stack_size);
    if (child_stack == NULL)
        return 1;
    child_pid = clone(check_clone, (char *)child_stack + stack_size,
                      CLONE_NEWNS | SIGCHLD, NULL);
    if (child_pid < 0) {
        perror("clone mount namespace");
        return 1;
    }
    if (waitpid(child_pid, &status, 0) != child_pid) {
        perror("wait mount namespace child");
        return 1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "mount attribute child failed: status=%d\n", status);
        return 1;
    }
    free(child_stack);
    if (mount("/mnt", "/copy", NULL, MS_BIND | MS_REC, NULL) < 0 ||
        expect_open("/copy/file", O_WRONLY, EROFS) ||
        expect_open("/copy/child/file", O_WRONLY, EROFS)) {
        perror("recursive bind of mount attributes");
        return 1;
    }
    attributes.attr_set = 0;
    attributes.attr_clr = MS_RDONLY;
    if (change_attributes(AT_FDCWD, "/mnt/child", 0, &attributes, sizeof(attributes)) < 0 ||
        expect_open("/mnt/child/file", O_WRONLY, 0) ||
        expect_open("/mnt/file", O_WRONLY, EROFS)) {
        perror("clear readonly on child mount");
        return 1;
    }
    attributes.attr_clr = MS_NODEV;
    if (change_attributes(AT_FDCWD, "/mnt/device", 0, &attributes, sizeof(attributes)) < 0 ||
        expect_open("/mnt/device", O_RDONLY, 0)) {
        perror("clear nodev on device bind");
        return 1;
    }
    child_pid = fork();
    if (child_pid == 0) {
        execl("/mnt/suid-probe", "/mnt/suid-probe", "nosuid", NULL);
        _exit(1);
    }
    if (child_pid < 0 || waitpid(child_pid, &status, 0) != child_pid ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "nosuid child failed: status=%d\n", status);
        return 1;
    }
    puts("mount_setattr fd/path, recursive readonly, nodev, nosuid and argument validation passed");
    return 0;
}
