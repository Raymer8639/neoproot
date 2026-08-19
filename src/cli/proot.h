#ifndef PROOT_CLI_H
#define PROOT_CLI_H

#include "cli/cli.h"

#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>

#ifndef VERSION
#define VERSION "5.7.0-scicat"
#endif

static const char *recommended_bindings[] = {
    "/etc/host.conf", "/etc/hosts", "/etc/mtab", "/etc/passwd", "/etc/group",
    "/etc/nsswitch.conf", "/etc/resolv.conf", "/etc/localtime",
    "/dev/", "/sys/", "/proc/", "/tmp/", "/run/",
    "/var/run/dbus/system_bus_socket", "$HOME", "*path*", NULL
};

static const char *recommended_su_bindings[] = {
    "/etc/hosts", "/etc/nsswitch.conf", "/etc/resolv.conf",
    "/dev/", "/sys/", "/proc/", "/tmp/", "/run/shm", "$HOME", "*path*", NULL
};
//彩蛋需要时再复活
//" "占位，单用""就可能会被忽略
static const char *egg_msgs[] = { " " };
static int egg_first_help = 0;

void egg_show_final(void) {
    srand(time(NULL) ^ getpid());
    if (!egg_first_help) {
        egg_first_help = 1;
    }
    int idx = rand() % (sizeof(egg_msgs)/sizeof(egg_msgs[0]));
    if (*egg_msgs[idx]) {
        printf("\n\033[1;35m%s\033[0m\n", egg_msgs[idx]);
        fflush(stdout);
    }
}

void egg_try(void) {}
void egg_mark_h(void) {}
void egg_mark_v(void) {}

static int handle_option_r(Tracee *, const Cli *, const char *);
static int handle_option_b(Tracee *, const Cli *, const char *);
static int handle_option_w(Tracee *, const Cli *, const char *);
static int handle_option_v(Tracee *, const Cli *, const char *);
static int handle_option_V(Tracee *, const Cli *, const char *);
static int handle_option_h(Tracee *, const Cli *, const char *);
static int handle_option_k(Tracee *, const Cli *, const char *);
static int handle_option_0(Tracee *, const Cli *, const char *);
static int handle_option_i(Tracee *, const Cli *, const char *);
static int handle_option_R(Tracee *, const Cli *, const char *);
static int handle_option_S(Tracee *, const Cli *, const char *);
static int handle_option_link2symlink(Tracee *, const Cli *, const char *);
static int handle_option_link2symlink_dirent(Tracee *, const Cli *, const char *);
static int handle_option_ashmem_memfd(Tracee *, const Cli *, const char *);
static int handle_option_sysvipc(Tracee *, const Cli *, const char *);
static int handle_option_kill_on_exit(Tracee *, const Cli *, const char *);
static int handle_option_L(Tracee *, const Cli *, const char *);
static int handle_option_H(Tracee *, const Cli *, const char *);
static int handle_option_p(Tracee *, const Cli *, const char *);

static int pre_initialize_bindings(Tracee *, const Cli *, size_t, char *const *, size_t);
static int post_initialize_exe(Tracee *, const Cli *, size_t, char *const *, size_t);

static Cli proot_cli = {
    .version  = VERSION,
    .name     = "neoproot",
    .subtitle = "chroot & bind mount without privileges",
    .synopsis = "neoproot [option]... [command]",

    .colophon =
        "Copyright (C) 2026 scicat, GPLv2+\n"
        "https://gitee.com/scicat-team/proot-scicat",

    .logo =
"\n"
"  UU   UU  PPPP   RRRR   OOO   OOO   TTTTT\n"
"  UU   UU  PP  P  RR  R OO OO OO OO   TTT\n"
"  UU   UU  PPPP   RRRR  OO OO OO OO   TTT\n"
"  UU   UU  PP     RR R  OO OO OO OO   TTT\n"
"   UUUUU   PP     RR  R  OOO   OOO    TTT\n"
"\nUproot: next generation Proot.\n"
"built by scicat-team.\n",

    .pre_initialize_bindings = pre_initialize_bindings,
    .post_initialize_exe     = post_initialize_exe,

    .options = {
        {
            .class = "Regular options",
            .arguments = {
                { .name = "-r",          .separator = ' ', .value = "path" },
                { .name = "--rootfs",    .separator = '=', .value = "path" },
                { .name = NULL, 0, NULL }
            },
            .handler = handle_option_r,
            .description = "Set root filesystem to path.",
            .detail = ""
        },
        {
            .class = "Regular options",
            .arguments = {
                { .name = "-b", .separator = ' ', .value = "path" },
                { .name = "--bind", .separator = '=', .value = "path" },
                { .name = "-m", .separator = ' ', .value = "path" },
                { .name = "--mount", .separator = '=', .value = "path" },
                { .name = NULL, 0, NULL }
            },
            .handler = handle_option_b,
            .description = "Bind host path to guest.",
            .detail = "Format: -b host:guest"
        },
        {
            .class = "Regular options",
            .arguments = {
                { .name = "-w", .separator = ' ', .value = "path" },
                { .name = "--pwd", .separator = '=', .value = "path" },
                { .name = "--cwd", .separator = '=', .value = "path" },
                { .name = NULL, 0, NULL }
            },
            .handler = handle_option_w,
            .description = "Set initial working directory.",
            .detail = ""
        },
        {
            .class = "Regular options",
            .arguments = {
                { .name = "--kill-on-exit", 0, NULL },
                { .name = NULL, 0, NULL }
            },
            .handler = handle_option_kill_on_exit,
            .description = "Kill all child processes on exit.",
            .detail = ""
        },
        {
            .class = "Regular options",
            .arguments = {
                { .name = "-v", .separator = ' ', .value = "num" },
                { .name = "--verbose", .separator = '=', .value = "num" },
                { .name = NULL, 0, NULL }
            },
            .handler = handle_option_v,
            .description = "Set log level.",
            .detail = ""
        },
        {
            .class = "Regular options",
            .arguments = {
                { .name = "-V", 0, NULL },
                { .name = "--version", 0, NULL },
                { .name = "--about", 0, NULL },
                { .name = NULL, 0, NULL }
            },
            .handler = handle_option_V,
            .description = "Show version info.",
            .detail = ""
        },
        {
            .class = "Regular options",
            .arguments = {
                { .name = "-h", 0, NULL },
                { .name = "--help", 0, NULL },
                { .name = "--usage", 0, NULL },
                { .name = NULL, 0, NULL }
            },
            .handler = handle_option_h,
            .description = "Show this help.",
            .detail = ""
        },

        {
            .class = "Extensions",
            .arguments = {
                { .name = "-k", .separator = ' ', .value = "str" },
                { .name = "--kernel-release", .separator = '=', .value = "str" },
                { .name = NULL, 0, NULL }
            },
            .handler = handle_option_k,
            .description = "Fake kernel version.",
            .detail = ""
        },
        {
            .class = "Extensions",
            .arguments = {
                { .name = "-0", 0, NULL },
                { .name = "--root-id", 0, NULL },
                { .name = NULL, 0, NULL }
            },
            .handler = handle_option_0,
            .description = "Fake UID/GID 0 (root).",
            .detail = ""
        },
        {
            .class = "Extensions",
            .arguments = {
                { .name = "-i", .separator = ' ', .value = "uid:gid" },
                { .name = "--change-id", .separator = '=', .value = "uid:gid" },
                { .name = NULL, 0, NULL }
            },
            .handler = handle_option_i,
            .description = "Fake UID:GID.",
            .detail = ""
        },
        {
            .class = "Extensions",
            .arguments = {
                { .name = "--link2symlink-dirent", 0, NULL },
                { .name = NULL, 0, NULL }
            },
            .handler = handle_option_link2symlink_dirent,
            .description = "Report emulated hardlinks as regular files in readdir().",
            .detail = "Also enables --link2symlink. This opt-in mode intercepts getdents64."
        },
        {
            .class = "Extensions",
            .arguments = {
                { .name = "--link2symlink", 0, NULL },
                { .name = "-l", 0, NULL },
                { .name = NULL, 0, NULL }
            },
            .handler = handle_option_link2symlink,
            .description = "Convert hardlink to symlink.",
            .detail = ""
        },
        {
            .class = "Extensions",
            .arguments = {
                { .name = "--sysvipc", 0, NULL },
                { .name = NULL, 0, NULL }
            },
            .handler = handle_option_sysvipc,
            .description = "Enable System V IPC emulation.",
            .detail = ""
        },
        {
            .class = "Extensions",
            .arguments = {
                { .name = "--ashmem-memfd", 0, NULL },
                { .name = NULL, 0, NULL }
            },
            .handler = handle_option_ashmem_memfd,
            .description = "Ashmem for memfd emulation.",
            .detail = ""
        },
        {
            .class = "Extensions",
            .arguments = {
                { .name = "-H", 0, NULL },
                { .name = NULL, 0, NULL }
            },
            .handler = handle_option_H,
            .description = "Hide temp files.",
            .detail = ""
        },
        {
            .class = "Extensions",
            .arguments = {
                { .name = "-p", 0, NULL },
                { .name = NULL, 0, NULL }
            },
            .handler = handle_option_p,
            .description = "Redirect privileged ports.",
            .detail = ""
        },
        {
            .class = "Extensions",
            .arguments = {
                { .name = "-L", 0, NULL },
                { .name = NULL, 0, NULL }
            },
            .handler = handle_option_L,
            .description = "Fix symlink size reporting.",
            .detail = ""
        },

        {
            .class = "Aliases",
            .arguments = {
                { .name = "-R", .separator = ' ', .value = "path" },
                { .name = NULL, 0, NULL }
            },
            .handler = handle_option_R,
            .description = "-r path + recommended binds.",
            .detail = ""
        },
        {
            .class = "Aliases",
            .arguments = {
                { .name = "-S", .separator = ' ', .value = "path" },
                { .name = NULL, 0, NULL }
            },
            .handler = handle_option_S,
            .description = "-0 -r path + minimal binds.",
            .detail = ""
        },

        END_OF_OPTIONS
    }
};

#endif
