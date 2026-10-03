#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct {
    char socket_path[108];
    char surviving_socket_path[108];
    char reverse_socket_path[108];
    char exec_socket_path[108];
    char replay_path[108];
    char auxv_path[64];
    char tmpfs_backing[PATH_MAX];
} ProbePaths;

static int fail(const char *operation)
{
    perror(operation);
    return 1;
}

static int expect_mountpoint(const char *path, int expected)
{
    FILE *mountinfo = fopen("/proc/self/mountinfo", "r");
    char line[8192];
    char mountpoint[PATH_MAX];
    int present = 0;

    if (mountinfo == NULL)
        return fail("open mountinfo");
    while (fgets(line, sizeof(line), mountinfo) != NULL) {
        if (sscanf(line, "%*s %*s %*s %*s %4095s", mountpoint) == 1 &&
            strcmp(mountpoint, path) == 0) {
            present = 1;
            break;
        }
    }
    if (ferror(mountinfo)) {
        fclose(mountinfo);
        return fail("read mountinfo");
    }
    fclose(mountinfo);
    if (present != expected) {
        fprintf(stderr, "mountinfo %s: expected=%d actual=%d\n", path, expected, present);
        return 1;
    }
    return 0;
}

static int exchange(int server_fd, const char *path)
{
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    struct stat socket_info;
    char message = 'x';
    int client_fd;
    int accepted_fd;

    if (strlen(path) >= sizeof(address.sun_path))
        return 1;
    strcpy(address.sun_path, path);
    if (stat(path, &socket_info) < 0 || !S_ISSOCK(socket_info.st_mode))
        return fail("stat Unix socket");
    client_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (client_fd < 0)
        return fail("create client socket");
    if (connect(client_fd, (struct sockaddr *)&address,
                offsetof(struct sockaddr_un, sun_path) + strlen(path) + 1) < 0 ||
        write(client_fd, &message, 1) != 1) {
        close(client_fd);
        return fail("connect/send Unix socket");
    }
    accepted_fd = accept(server_fd, NULL, NULL);
    if (accepted_fd < 0) {
        close(client_fd);
        return fail("accept Unix socket");
    }
    if (read(accepted_fd, &message, 1) != 1 || message != 'x') {
        close(accepted_fd);
        close(client_fd);
        return fail("receive Unix socket");
    }
    close(accepted_fd);
    close(client_fd);
    return 0;
}

static int send_message(const char *path)
{
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    char message = 'x';
    int client_fd;

    if (strlen(path) >= sizeof(address.sun_path))
        return 1;
    strcpy(address.sun_path, path);
    client_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (client_fd < 0)
        return fail("create client socket");
    if (connect(client_fd, (struct sockaddr *)&address,
                offsetof(struct sockaddr_un, sun_path) + strlen(path) + 1) < 0 ||
        write(client_fd, &message, 1) != 1) {
        close(client_fd);
        return fail("connect/send Unix socket");
    }
    close(client_fd);
    return 0;
}

static int check_view(const ProbePaths *paths, const char *prefix)
{
    const char *hidden[] = {paths->socket_path, paths->replay_path, paths->auxv_path};
    const char *visible[] = {"/file-bind", "/dir-bind", "/tmp/socket-bind-visible",
                             "/bind-replay", "/bind-replay/socket-bind-visible"};
    char path[PATH_MAX];
    size_t index;

    for (index = 0; index < sizeof(hidden) / sizeof(hidden[0]); index++) {
        snprintf(path, sizeof(path), "%s%s", prefix, hidden[index]);
        if (expect_mountpoint(path, 0) != 0)
            return 1;
    }
    for (index = 0; index < sizeof(visible) / sizeof(visible[0]); index++) {
        snprintf(path, sizeof(path), "%s%s", prefix, visible[index]);
        if (expect_mountpoint(path, 1) != 0)
            return 1;
    }
    return 0;
}

static int check_clone(void *argument)
{
    ProbePaths *paths = argument;
    struct stat socket_info;

    if (stat(paths->socket_path, &socket_info) < 0 || !S_ISSOCK(socket_info.st_mode))
        return fail("stat socket in mount namespace child");
    return check_view(paths, "") ||
           expect_mountpoint("/tmpfs", 1) ||
           expect_mountpoint(paths->tmpfs_backing, 1);
}

static int check_socket_after_creator_exit(const char *path, const char *link_path)
{
    int report[2];
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    pid_t creator;
    int creator_status;
    char result;

    if (pipe(report) < 0 || strlen(path) >= sizeof(address.sun_path))
        return fail("prepare socket lifetime test");
    strcpy(address.sun_path, path);
    creator = fork();
    if (creator < 0)
        return fail("fork socket creator");
    if (creator == 0) {
        int server_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        pid_t connector;

        close(report[0]);
        if (server_fd < 0 ||
            bind(server_fd, (struct sockaddr *)&address,
                 offsetof(struct sockaddr_un, sun_path) + strlen(path) + 1) < 0 ||
            listen(server_fd, 1) < 0 ||
            symlink(path, link_path) < 0)
            _exit(1);
        connector = fork();
        if (connector < 0)
            _exit(1);
        if (connector == 0) {
            int status = exchange(server_fd, link_path);
            result = status == 0 ? '1' : '0';
            write(report[1], &result, 1);
            _exit(status == 0 ? 0 : 1);
        }
        close(server_fd);
        _exit(0);
    }

    close(report[1]);
    if (waitpid(creator, &creator_status, 0) != creator ||
        !WIFEXITED(creator_status) || WEXITSTATUS(creator_status) != 0 ||
        read(report[0], &result, 1) != 1 || result != '1') {
        fprintf(stderr, "socket mapping did not survive creator exit\n");
        close(report[0]);
        return 1;
    }
    close(report[0]);
    return 0;
}

static int check_socket_created_by_child(const char *path, const char *link_path)
{
    int ready[2];
    int report[2];
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    pid_t creator;
    int creator_status;
    char result;

    if (pipe(ready) < 0 || pipe(report) < 0 || strlen(path) >= sizeof(address.sun_path))
        return fail("prepare reverse socket lifetime test");
    strcpy(address.sun_path, path);
    creator = fork();
    if (creator < 0)
        return fail("fork reverse socket creator");
    if (creator == 0) {
        int server_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        int accepted_fd;

        close(ready[0]);
        close(report[0]);
        if (server_fd < 0 ||
            bind(server_fd, (struct sockaddr *)&address,
                 offsetof(struct sockaddr_un, sun_path) + strlen(path) + 1) < 0 ||
            listen(server_fd, 1) < 0 ||
            symlink(path, link_path) < 0 ||
            write(ready[1], "1", 1) != 1)
            _exit(1);
        close(ready[1]);
        accepted_fd = accept(server_fd, NULL, NULL);
        if (accepted_fd < 0 || read(accepted_fd, &result, 1) != 1 || result != 'x')
            _exit(1);
        result = '1';
        write(report[1], &result, 1);
        close(accepted_fd);
        close(server_fd);
        _exit(0);
    }

    close(ready[1]);
    close(report[1]);
    if (read(ready[0], &result, 1) != 1 || result != '1') {
        fprintf(stderr, "child did not report socket ready: errno=%d\n", errno);
        close(ready[0]);
        close(report[0]);
        return 1;
    }
    if (send_message(link_path) != 0) {
        fprintf(stderr, "parent could not connect to child-created socket: errno=%d\n", errno);
        close(ready[0]);
        close(report[0]);
        return 1;
    }
    if (read(report[0], &result, 1) != 1 || result != '1') {
        fprintf(stderr, "child did not report accepted message: errno=%d\n", errno);
        close(ready[0]);
        close(report[0]);
        return 1;
    }
    if (waitpid(creator, &creator_status, 0) != creator ||
        !WIFEXITED(creator_status) || WEXITSTATUS(creator_status) != 0) {
        fprintf(stderr, "child socket creator failed: status=%d errno=%d\n",
                creator_status, errno);
        close(ready[0]);
        close(report[0]);
        return 1;
    }
    close(ready[0]);
    close(report[0]);
    return 0;
}

static int run_socket_server_after_exec(const char *path, const char *link_path,
                                        int ready_fd, int report_fd)
{
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    int server_fd;
    int accepted_fd;
    char message;

    if (strlen(path) >= sizeof(address.sun_path))
        return 1;
    strcpy(address.sun_path, path);
    server_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (server_fd < 0) {
        fprintf(stderr, "exec server socket failed: errno=%d\n", errno);
        return 1;
    }
    if (bind(server_fd, (struct sockaddr *)&address,
             offsetof(struct sockaddr_un, sun_path) + strlen(path) + 1) < 0) {
        fprintf(stderr, "exec server bind failed: errno=%d\n", errno);
        return 1;
    }
    if (listen(server_fd, 1) < 0) {
        fprintf(stderr, "exec server listen failed: errno=%d\n", errno);
        return 1;
    }
    if (symlink(path, link_path) < 0) {
        fprintf(stderr, "exec server symlink failed: errno=%d\n", errno);
        return 1;
    }
    if (write(ready_fd, "1", 1) != 1) {
        fprintf(stderr, "exec server ready pipe failed: errno=%d\n", errno);
        return 1;
    }
    close(ready_fd);
    accepted_fd = accept(server_fd, NULL, NULL);
    if (accepted_fd < 0) {
        fprintf(stderr, "exec server accept failed: errno=%d\n", errno);
        return 1;
    }
    if (read(accepted_fd, &message, 1) != 1 || message != 'x') {
        fprintf(stderr, "exec server read failed: errno=%d message=%d\n", errno, message);
        return 1;
    }
    message = '1';
    if (write(report_fd, &message, 1) != 1) {
        fprintf(stderr, "exec server report pipe failed: errno=%d\n", errno);
        return 1;
    }
    close(accepted_fd);
    close(server_fd);
    unlink(link_path);
    unlink(path);
    return 0;
}

static int check_socket_created_by_exec(const char *path, const char *link_path)
{
    int ready[2];
    int report[2];
    char ready_text[16];
    char report_text[16];
    char *child_argv[7];
    pid_t child;
    int child_status;
    char result;

    if (pipe(ready) < 0 || pipe(report) < 0)
        return fail("prepare exec socket lifetime test");
    child = fork();
    if (child < 0)
        return fail("fork exec socket creator");
    if (child == 0) {
        close(ready[0]);
        close(report[0]);
        snprintf(ready_text, sizeof(ready_text), "%d", ready[1]);
        snprintf(report_text, sizeof(report_text), "%d", report[1]);
        child_argv[0] = "/probe";
        child_argv[1] = "--socket-server";
        child_argv[2] = (char *)path;
        child_argv[3] = (char *)link_path;
        child_argv[4] = ready_text;
        child_argv[5] = report_text;
        child_argv[6] = NULL;
        execv(child_argv[0], child_argv);
        _exit(1);
    }

    close(ready[1]);
    close(report[1]);
    if (read(ready[0], &result, 1) != 1 || result != '1') {
        fprintf(stderr, "parent did not receive exec ready: errno=%d\n", errno);
        close(ready[0]);
        close(report[0]);
        return 1;
    }
    if (send_message(link_path) != 0) {
        fprintf(stderr, "parent could not connect to exec-created socket\n");
        close(ready[0]);
        close(report[0]);
        return 1;
    }
    if (read(report[0], &result, 1) != 1 || result != '1') {
        fprintf(stderr, "parent did not receive exec report: errno=%d\n", errno);
        close(ready[0]);
        close(report[0]);
        return 1;
    }
    if (waitpid(child, &child_status, 0) != child ||
        !WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0) {
        fprintf(stderr, "exec socket creator failed: status=%d errno=%d\n",
                child_status, errno);
        close(ready[0]);
        close(report[0]);
        return 1;
    }
    close(ready[0]);
    close(report[0]);
    unlink(link_path);
    unlink(path);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 6 && strcmp(argv[1], "--socket-server") == 0)
        return run_socket_server_after_exec(argv[2], argv[3], atoi(argv[4]), atoi(argv[5]));

    ProbePaths paths = {0};
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    char auxv_buffer[16];
    char procfd[64];
    char pivot_socket[108];
    void *child_stack;
    pid_t child_pid;
    int child_status;
    int server_fd;
    int tmpfs_fd;
    int auxv_fd;
    ssize_t length;
    const size_t stack_size = 65536;

    strcpy(paths.socket_path, "/tmp/codex-daemon-mountinfo/");
    memset(paths.socket_path + strlen(paths.socket_path), 'a', 60);
    strcpy(paths.surviving_socket_path, "/tmp/codex-daemon-surviving/");
    memset(paths.surviving_socket_path + strlen(paths.surviving_socket_path), 'b', 58);
    strcpy(paths.reverse_socket_path, "/tmp/codex-daemon-reverse/");
    memset(paths.reverse_socket_path + strlen(paths.reverse_socket_path), 'c', 58);
    strcpy(paths.exec_socket_path, "/tmp/codex-daemon-exec/");
    memset(paths.exec_socket_path + strlen(paths.exec_socket_path), 'd', 58);
    snprintf(paths.replay_path, sizeof(paths.replay_path), "/bind-replay%s",
             paths.socket_path + strlen("/tmp"));
    snprintf(paths.auxv_path, sizeof(paths.auxv_path), "/proc/%d/auxv", getpid());
    if (check_socket_after_creator_exit(paths.surviving_socket_path,
                                        "/socket-control-link") != 0)
        return 1;
    if (check_socket_created_by_child(paths.reverse_socket_path,
                                      "/socket-control-link-reverse") != 0)
        return 1;
    if (check_socket_created_by_exec(paths.exec_socket_path,
                                     "/socket-control-link-exec") != 0)
        return 1;
    if (expect_mountpoint(paths.socket_path, 0) != 0)
        return 1;
    strcpy(address.sun_path, paths.socket_path);
    server_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (server_fd < 0 ||
        bind(server_fd, (struct sockaddr *)&address,
             offsetof(struct sockaddr_un, sun_path) + strlen(paths.socket_path) + 1) < 0 ||
        listen(server_fd, 1) < 0)
        return fail("bind/listen Unix socket");
    if (exchange(server_fd, paths.socket_path) != 0 ||
        expect_mountpoint(paths.socket_path, 0) != 0)
        return 1;

    auxv_fd = open("/proc/self/auxv", O_RDONLY | O_CLOEXEC);
    if (auxv_fd < 0)
        return fail("open auxv");
    length = read(auxv_fd, auxv_buffer, sizeof(auxv_buffer));
    close(auxv_fd);
    if (length != sizeof(auxv_buffer))
        return fail("read auxv");
    if (expect_mountpoint(paths.auxv_path, 0) != 0)
        return 1;

    if (mount(paths.socket_path, "/tmp/socket-bind-visible", NULL, MS_BIND, NULL) < 0 ||
        mount("/tmp", "/bind-replay", NULL, MS_BIND | MS_REC, NULL) < 0)
        return fail("bind socket and recursively bind its directory");
    if (check_view(&paths, "") != 0 ||
        exchange(server_fd, "/tmp/socket-bind-visible") != 0 ||
        exchange(server_fd, paths.replay_path) != 0)
        return 1;

    if (mount("tmpfs", "/tmpfs", "tmpfs", 0, NULL) < 0)
        return fail("mount tmpfs");
    tmpfs_fd = open("/tmpfs", O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (tmpfs_fd < 0)
        return fail("open tmpfs");
    snprintf(procfd, sizeof(procfd), "/proc/self/fd/%d", tmpfs_fd);
    length = readlink(procfd, paths.tmpfs_backing, sizeof(paths.tmpfs_backing) - 1);
    close(tmpfs_fd);
    if (length < 0)
        return fail("readlink tmpfs backing");
    paths.tmpfs_backing[length] = '\0';
    if (expect_mountpoint("/tmpfs", 1) != 0 ||
        expect_mountpoint(paths.tmpfs_backing, 1) != 0)
        return 1;

    child_stack = malloc(stack_size);
    if (child_stack == NULL)
        return fail("allocate clone stack");
    child_pid = clone(check_clone, (char *)child_stack + stack_size,
                      CLONE_NEWNS | SIGCHLD, &paths);
    if (child_pid < 0)
        return fail("clone mount namespace");
    if (waitpid(child_pid, &child_status, 0) != child_pid)
        return fail("wait for mount namespace child");
    free(child_stack);
    if (!WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0) {
        fprintf(stderr, "mount namespace child failed: status=%d\n", child_status);
        return 1;
    }
    if (umount("/tmpfs") < 0)
        return fail("unmount tmpfs");
    if (expect_mountpoint("/tmpfs", 0) != 0 ||
        expect_mountpoint(paths.tmpfs_backing, 0) != 0)
        return 1;

    if (mount("proc", "/newroot/proc", "proc", 0, NULL) < 0 ||
        syscall(SYS_pivot_root, "/newroot", "/newroot/oldroot") < 0 ||
        chdir("/") < 0)
        return fail("pivot root");
    if (check_view(&paths, "/oldroot") != 0)
        return 1;
    snprintf(pivot_socket, sizeof(pivot_socket), "/oldroot%s", paths.socket_path);
    if (exchange(server_fd, pivot_socket) != 0)
        return 1;
    close(server_fd);
    unlink(pivot_socket);
    puts("internal socket/auxv aliases hidden; real binds and tmpfs preserved across clone, recursive bind and pivot");
    return 0;
}
