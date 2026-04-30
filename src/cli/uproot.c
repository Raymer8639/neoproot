#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

// 声明cli.c中的核心函数
extern int proot_main(int argc, char *const argv[]);

int main(int argc, char *const argv[])
{
    // 要传递给termux的命令
    char *shell_cmd = 
        "termux-wake-lock; "
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
    sh_argv[idx++] = "/system/bin/sh";
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

    execve("/system/bin/sh", sh_argv, environ);

    perror("execve shell failed");
    free(sh_argv);
    return 1;
}
