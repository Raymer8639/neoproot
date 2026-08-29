#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

// 声明cli.c中的核心函数
extern int proot_main(int argc, char *const argv[]);

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
        while (*end == 32 || *end == 9 || *end == 10)
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
    if (reject_traced_startup())
        return EXIT_FAILURE;

    // 要传递给termux的命令
    char *shell_cmd = 
        "termux-wake-lock >/dev/null 2>&1 & "
        "ulimit -n 16384; "
        "unset LD_PRELOAD LD_LIBRARY_PATH LD_BIND_NOW ; "
        "export PROOT_MEMFD_LOADER=1; "
        "export PROOT_UNSET_DONE=1; "
        "exec \"$0\" \"$@\"";

    char **sh_argv = malloc((argc + 4) * sizeof(char *));
    if (!sh_argv) {
        perror("malloc failed");
        return 1;
    }

    int idx = 0;
    sh_argv[idx++] = (char *)find_shell();
    sh_argv[idx++] = "-c";
    sh_argv[idx++] = shell_cmd;
    sh_argv[idx++] = argv[0];

    for (int i = 1; i < argc; i++) {
        sh_argv[idx++] = argv[i];
    }
    sh_argv[idx] = NULL;

    // 执行完shell环境初始化后，直接走 proot_main
    if (getenv("PROOT_UNSET_DONE")) {
        free(sh_argv);
        return proot_main(argc, argv);
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
    return 1;
}
