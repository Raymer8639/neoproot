#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

// 声明cli.c中的核心函数
extern int proot_main(int argc, char *const argv[]);
extern int neoproot_um_supervisor_main(int argc, char *const argv[]);

enum backend_mode {
    BACKEND_DEFAULT,
    BACKEND_FAST,
    BACKEND_UM,
    BACKEND_AUTO,
};

static bool option_takes_separate_value(const char *argument)
{
    static const char *const options[] = {
        "-r", "--rootfs", "-b", "--bind", "-m", "--mount",
        "-w", "--pwd", "--cwd", "-k", "--kernel-release",
        "-i", "--change-id", "-v", "--verbose", "-R", "-S", NULL
    };
    size_t index;

    for (index = 0; options[index] != NULL; index++)
        if (strcmp(argument, options[index]) == 0)
            return true;
    return false;
}

static int prepare_backend_argv(int argc, char *const argv[],
                                char ***result, int *result_argc,
                                enum backend_mode *mode)
{
    char **filtered;
    int output_argc = 1;
    int index;
    bool command_started = false;
    bool backend_set = false;

    *mode = BACKEND_DEFAULT;
    filtered = calloc((size_t)argc + 2, sizeof(*filtered));
    if (filtered == NULL)
        return -1;
    filtered[0] = argv[0];
    for (index = 1; index < argc; index++) {
        const char *value = NULL;

        if (command_started) {
            filtered[output_argc++] = argv[index];
            continue;
        }
        if (strcmp(argv[index], "--") == 0) {
            command_started = true;
            filtered[output_argc++] = argv[index];
            continue;
        }
        if (argv[index][0] != '-') {
            command_started = true;
            filtered[output_argc++] = argv[index];
            continue;
        }
        if (strncmp(argv[index], "--backend=", 10) == 0) {
            value = argv[index] + 10;
        } else if (strcmp(argv[index], "--backend") == 0) {
            if (++index >= argc) {
                fprintf(stderr, "neoproot: --backend requires a value\n");
                free(filtered);
                return -1;
            }
            value = argv[index];
        } else {
            output_argc++;
            filtered[output_argc - 1] = argv[index];
            if (option_takes_separate_value(argv[index]) && index + 1 < argc)
                filtered[output_argc++] = argv[++index];
            continue;
        }
        if (backend_set) {
            fprintf(stderr, "neoproot: duplicate --backend option\n");
            free(filtered);
            return -1;
        }
        backend_set = true;
        if (strcmp(value, "fast") == 0)
            *mode = BACKEND_FAST;
        else if (strcmp(value, "um") == 0)
            *mode = BACKEND_UM;
        else if (strcmp(value, "auto") == 0)
            *mode = BACKEND_AUTO;
        else {
            fprintf(stderr, "neoproot: unknown backend '%s'\n", value);
            free(filtered);
            return -1;
        }
    }
    if (*mode == BACKEND_UM) {
        memmove(filtered + 2, filtered + 1,
                (size_t)(output_argc - 1) * sizeof(*filtered));
        filtered[1] = "--hostfs";
        output_argc++;
    }
    filtered[output_argc] = NULL;
    *result = filtered;
    *result_argc = output_argc;
    return 0;
}

/* 优先使用 Android 的 /system/bin/sh；
 * 在嵌入式 Linux / 其他环境回退到 /bin/sh，避免 execve 直接失败 */
static const char *find_shell(void)
{
    if (access("/system/bin/sh", X_OK) == 0)
        return "/system/bin/sh";
    if (access("/bin/sh", X_OK) == 0)
        return "/bin/sh";
    /* 两者都不存在时返回默认值，由 execve 报告具体错误 */
    return "/system/bin/sh";
}


static int reject_traced_startup(void)
{
    FILE *status;
    char line[128];

    status = fopen("/proc/self/status", "r");
    if (status == NULL)
        return 0;

    while (fgets(line, sizeof(line), status) != NULL) {
        char *end;
        long tracer_pid;

        if (strncmp(line, "TracerPid:", sizeof("TracerPid:") - 1) != 0)
            continue;
        errno = 0;
        tracer_pid = strtol(line + sizeof("TracerPid:") - 1, &end, 10);
        fclose(status);
        while (*end == ' ' || *end == '\t' || *end == '\n')
            end++;
        if (errno != 0 || end == line + sizeof("TracerPid:") - 1
            || *end != 0 || tracer_pid <= 0)
            return 0;

        fprintf(stderr,
                "neoproot: refusing to start while already traced (TracerPid=%ld).\n"
                "Run neoproot from the Termux host after exiting the current PRoot container.\n",
                tracer_pid);
        return 1;
    }

    fclose(status);
    return 0;
}

int main(int argc, char *const argv[])
{
    char **effective_argv;
    int effective_argc;
    enum backend_mode backend;

    if (reject_traced_startup())
        return EXIT_FAILURE;
    if (prepare_backend_argv(argc, argv, &effective_argv, &effective_argc,
                             &backend) < 0)
        return EXIT_FAILURE;
    if (backend == BACKEND_UM) {
        int status = neoproot_um_supervisor_main(effective_argc,
                                                  effective_argv);

        free(effective_argv);
        return status;
    }

    // 要传递给termux的命令
    char *shell_cmd = 
        "termux-wake-lock >/dev/null 2>&1 & "
        "ulimit -n 16384; "
        "unset LD_PRELOAD LD_LIBRARY_PATH LD_BIND_NOW ; "
        "export PROOT_MEMFD_LOADER=1; "
        "export PROOT_UNSET_DONE=1; "
        "exec \"$0\" \"$@\"";

    char **sh_argv = malloc(((size_t)effective_argc + 4) * sizeof(char *));
    if (!sh_argv) {
        perror("malloc failed");
        free(effective_argv);
        return 1;
    }

    int idx = 0;
    sh_argv[idx++] = (char *)find_shell();
    sh_argv[idx++] = "-c";
    sh_argv[idx++] = shell_cmd;
    sh_argv[idx++] = effective_argv[0];

    for (int i = 1; i < effective_argc; i++) {
        sh_argv[idx++] = effective_argv[i];
    }
    sh_argv[idx] = NULL;

    // 执行完shell环境初始化后，直接走 proot_main
    if (getenv("PROOT_UNSET_DONE")) {
        free(sh_argv);
        int status = proot_main(effective_argc, effective_argv);

        free(effective_argv);
        return status;
    }

    // 首选 shell 执行失败时（例如 proot 容器内 /system 目录不可 exec），
    // 自动回退到 /bin/sh 再试一次
    if (execve(sh_argv[0], sh_argv, environ) != 0
        && strcmp(sh_argv[0], "/system/bin/sh") == 0
        && access("/bin/sh", X_OK) == 0) {
        sh_argv[0] = "/bin/sh";
        execve(sh_argv[0], sh_argv, environ);
    }

    perror("execve shell failed");
    free(sh_argv);
    free(effective_argv);
    return 1;
}
