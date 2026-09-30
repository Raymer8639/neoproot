#define _GNU_SOURCE
#include <sched.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

struct spawn_args { const char *target; char **envp; };
static int spawn_child(void *opaque)
{
    struct spawn_args *args = opaque;
    char *argv[] = { (char *)args->target, NULL };
    execve(args->target, argv, args->envp);
    _exit(111);
}
int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    const size_t guard_size = 65536, stack_size = 8192, payload_size = 49152;
    unsigned char *area = mmap(NULL, guard_size + stack_size,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (area == MAP_FAILED) { perror("mmap"); return 2; }
    memset(area, 0x5a, guard_size);
    char *payload = malloc(payload_size);
    if (payload == NULL) return 2;
    memset(payload, 'X', payload_size);
    memcpy(payload, "UNCHANGED=", 10);
    payload[payload_size - 1] = 0;
    char *envp[] = { payload, "PATH=/usr/bin:/bin", NULL };
    struct spawn_args args = { argv[1], envp };
    pid_t child = clone(spawn_child, area + guard_size + stack_size,
                        CLONE_VM | CLONE_VFORK | SIGCHLD, &args);
    if (child < 0) { perror("clone"); return 2; }
    int status;
    if (waitpid(child, &status, 0) != child) return 2;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "child exec failed: status=%d\n", status);
        return 1;
    }
    for (size_t i = 0; i < guard_size; ++i) {
        if (area[i] != 0x5a) {
            fprintf(stderr, "exec environment overwrote shared stack guard at %zu\n", i);
            return 1;
        }
    }
    puts("exec environment stack regression passed");
    free(payload);
    munmap(area, guard_size + stack_size);
    return 0;
}
