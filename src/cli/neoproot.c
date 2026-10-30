#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "um-config.h"

#include "cli/auto_backend.h"
#include "cli/backend.h"

// 声明cli.c中的核心函数
extern int proot_main(int argc, char *const argv[]);
/*
 * The UML backend is optional at build time (make WITH_UM=0).  A build
 * without it keeps the dispatcher and the messages -- only the supervisor
 * itself is missing, and the branch below says so instead of failing to link.
 */
#ifdef NEOPROOT_WITH_UM
extern int neoproot_um_supervisor_main(int argc, char *const argv[]);
#endif

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
    int command_index;
    const char *auto_commands_option;
    enum neoproot_rootfs_kind rootfs_kind;
    bool cow_file;

    if (reject_traced_startup())
        return EXIT_FAILURE;
    if (neoproot_prepare_backend_argv(argc, argv, &effective_argv,
                                      &effective_argc, &backend,
                                      &command_index,
                                      &auto_commands_option) < 0)
        return EXIT_FAILURE;

    /*
     * What -r names decides two things: whether auto may pick PRoot at all (it
     * cannot run an image), and the message the other backends give instead of
     * failing somewhere deeper.  --cow-file is an image-only option and gets
     * the second treatment: passing it elsewhere is a usage error, not
     * something to discover inside PRoot's option parser.
     */
    rootfs_kind = neoproot_rootfs_kind(effective_argc, effective_argv,
                                       command_index);
    cow_file = neoproot_has_cow_file(effective_argc, effective_argv,
                                     command_index);

    if (backend == BACKEND_AUTO) {
        char message[512];
        /*
         * Pick between the two paths rather than refusing to choose.  The
         * condition is deliberately narrow: the UML backend is only taken when
         * the caller has set up for it -- a kernel and a stub are configured,
         * and there is a rootfs to put behind them.  "auto" must not turn an
         * experimental backend on for somebody who never asked for it by
         * relying on what happens to be on PATH.
         *
         * Within that limit the choice is made from the command: PRoot is
         * faster and is the default, and UML is chosen only for a command that
         * needs a real kernel.  When such a command cannot have UML, saying so
         * is the point -- silently falling back would leave the caller
         * wondering why "docker" behaved as if it had no daemon.
         */
        backend = neoproot_auto_select(effective_argc, effective_argv,
                                       command_index, auto_commands_option,
                                       neoproot_um_backend_is_configured(
                                           effective_argc, effective_argv),
                                       rootfs_kind,
                                       message, sizeof(message))
#ifdef NEOPROOT_WITH_UM
                     ? BACKEND_UM : BACKEND_DEFAULT;
#else
                     /* Nothing to select: this build has no supervisor. */
                     ? BACKEND_DEFAULT : BACKEND_DEFAULT;
#endif
        fprintf(stderr, "%s\n", message);
    }

    /*
     * Only the UML backend can boot a filesystem image: PRoot translates guest
     * paths to host paths, and an image has none.  Left to PRoot, an image
     * rootfs reaches it as a bind whose first path translation fails, and
     * --cow-file reaches it as an unknown option -- neither says what is wrong
     * or what to do.  Say it here, before either backend starts.
     */
    if (backend != BACKEND_UM && rootfs_kind == NEOPROOT_ROOTFS_IMAGE) {
        fprintf(stderr,
                "neoproot: the rootfs is a filesystem image; only the um backend can use it.\n"
                "neoproot: use --backend=um (or --backend=auto to select it), or pass a directory rootfs.\n");
        free(effective_argv);
        return EXIT_FAILURE;
    }
    if (backend != BACKEND_UM && cow_file) {
        fprintf(stderr,
                "neoproot: --cow-file only works with a filesystem image rootfs, and only the um backend can use one.\n"
                "neoproot: use --backend=um (or --backend=auto to select it), or drop --cow-file.\n");
        free(effective_argv);
        return EXIT_FAILURE;
    }

    if (backend == BACKEND_UM) {
#ifdef NEOPROOT_WITH_UM
        int status;

        /*
         * The UM supervisor's syntax has the delimiter before the guest
         * command; neoproot's CLI consumed it as a separator and did not
         * forward it, so put it back for this backend only.  The vector was
         * allocated with room for it.
         */
        if (command_index > 0) {
            memmove(&effective_argv[command_index + 1],
                    &effective_argv[command_index],
                    (size_t)(effective_argc - command_index + 1) *
                        sizeof(char *));
            effective_argv[command_index] = (char *)"--";
            effective_argc++;
        }

        status = neoproot_um_supervisor_main(effective_argc, effective_argv);
        free(effective_argv);
        return status;
#else
        fprintf(stderr,
                "neoproot: this build has no um backend (built with WITH_UM=0).\n"
                "neoproot: rebuild with 'make WITH_UM=1', or use --backend=fast for a\n"
                "neoproot: directory rootfs.\n");
        free(effective_argv);
        return EXIT_FAILURE;
#endif
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
