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
#define VERSION "5.6.0-scicat"
#endif

static const char *recommended_bindings[] = {
    "/etc/host.conf",
    "/etc/hosts",
    "/etc/hosts.equiv",
    "/etc/mtab",
    "/etc/netgroup",
    "/etc/networks",
    "/etc/passwd",
    "/etc/group",
    "/etc/nsswitch.conf",
    "/etc/resolv.conf",
    "/etc/localtime",
    "/dev/",
    "/sys/",
    "/proc/",
    "/tmp/",
    "/run/",
    "/var/run/dbus/system_bus_socket",
    "$HOME",
    "*path*",
    NULL
};

static const char *recommended_su_bindings[] = {
    "/etc/host.conf",
    "/etc/hosts",
    "/etc/nsswitch.conf",
    "/etc/resolv.conf",
    "/dev/",
    "/sys/",
    "/proc/",
    "/tmp/",
    "/run/shm",
    "$HOME",
    "*path*",
    NULL
};
//" "占位，单用""就可能会被忽略
static const char *egg_msgs[] = {
    "代码为令，指针为兵，驭终端万象，破权限樊笼，技行四海，心向开源无界",
    "代码为令，指针驭物，执终端权柄，破桎梏樊笼，技行无疆，自在永恒",
    " ",
    "方寸之端藏天地，代码为律定乾坤，破界无声，行技万里，心向自由",
    " ",
    "执技以行，无界无拘，令行于心，码驭万物，开源为骨，一往无前",
    "技贯九天，令行八荒，终端之内万物伏，秉开源志，永逐星光",
    " ",
    "以码为戈，以令为盾，纵横终端无桎梏，开源为魂，行遍四方",
    "技行于端，权藏于心，无缚无拘，破界前行，永守开源初心",
};

static int egg_first_help = 0;

void egg_show_final(void) {
    srand(time(NULL) ^ getpid());

    if (!egg_first_help) {
        egg_first_help = 1;
        int idx;
        do { idx = rand() % (sizeof(egg_msgs)/sizeof(egg_msgs[0])); } while (*egg_msgs[idx] == 0);
        printf("\n\033[1;35m%s\033[0m\n", egg_msgs[idx]);
        fflush(stdout);
        return;
    }

    int idx = rand() % (sizeof(egg_msgs)/sizeof(egg_msgs[0]));
    if (*egg_msgs[idx] != 0) {
        printf("\n\033[1;35m%s\033[0m\n", egg_msgs[idx]);
        fflush(stdout);
    }
}

void egg_try(void) {}
void egg_mark_h(void) {}
void egg_mark_v(void) {}

static int handle_option_r(Tracee *, const Cli *, const char *);
static int handle_option_b(Tracee *, const Cli *, const char *);
static int handle_option_q(Tracee *, const Cli *, const char *);
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
    .name     = "proot",
    .subtitle = "chroot, mount --bind, and binfmt_misc without privilege/setup",
    .synopsis = "proot [option] ... [command]",

    .colophon =
        "Copyright (C) 2026 scicat, released under GPL.\n"
        "Visit https://gitee.com/scicat-team/proot-scicat for help and updates.",

    .logo =
"\n"
"  UU   UU  PPPP   RRRR   OOO   OOO   TTTTT\n"
"  UU   UU  PP  P  RR  R OO OO OO OO   TTT\n"
"  UU   UU  PPPP   RRRR  OO OO OO OO   TTT\n"
"  UU   UU  PP     RR R  OO OO OO OO   TTT\n"
"   UUUUU   PP     RR  R  OOO   OOO    TTT\n"
"\nUproot: the next generation Proot.\nbuilt by scicat-team.\n",

    .pre_initialize_bindings = pre_initialize_bindings,
    .post_initialize_exe     = post_initialize_exe,

    .options = {
        {
            .class = "Regular options",
            .arguments = {
                { .name = "-r",          .separator = ' ', .value = "path" },
                { .name = "--rootfs",    .separator = '=', .value = "path" },
                { .name = NULL,         .separator = 0,   .value = NULL }
            },
            .handler = handle_option_r,
            .description = "Use *path* as the new guest root file-system (default: /).",
            .detail = "\tThe specified path typically contains a Linux distribution\n"
                      "\twhere all new programs will be confined. Prefer -R or -S."
        },
        {
            .class = "Regular options",
            .arguments = {
                { .name = "-b",          .separator = ' ', .value = "path" },
                { .name = "--bind",      .separator = '=', .value = "path" },
                { .name = "-m",          .separator = ' ', .value = "path" },
                { .name = "--mount",     .separator = '=', .value = "path" },
                { .name = NULL,         .separator = 0,   .value = NULL }
            },
            .handler = handle_option_b,
            .description = "Make the content of *path* accessible inside the guest.",
            .detail = "\tBind host path to guest; syntax: -b host:guest."
        },
        {
            .class = "Regular options",
            .arguments = {
                { .name = "-q",          .separator = ' ', .value = "command" },
                { .name = "--qemu",      .separator = '=', .value = "command" },
                { .name = NULL,         .separator = 0,   .value = NULL }
            },
            .handler = handle_option_q,
            .description = "Execute guest programs through QEMU user-mode.",
            .detail = "\tFor cross-architecture execution, emulates the guest CPU."
        },
        {
            .class = "Regular options",
            .arguments = {
                { .name = "-w",          .separator = ' ', .value = "path" },
                { .name = "--pwd",       .separator = '=', .value = "path" },
                { .name = "--cwd",       .separator = '=', .value = "path" },
                { .name = NULL,         .separator = 0,   .value = NULL }
            },
            .handler = handle_option_w,
            .description = "Set the initial working directory to *path*.",
            .detail = ""
        },
        {
            .class = "Regular options",
            .arguments = {
                { .name = "--kill-on-exit", .separator = 0, .value = NULL },
                { .name = NULL,             .separator = 0, .value = NULL }
            },
            .handler = handle_option_kill_on_exit,
            .description = "Kill all processes when the initial command exits.",
            .detail = ""
        },
        {
            .class = "Regular options",
            .arguments = {
                { .name = "-v",          .separator = ' ', .value = "value" },
                { .name = "--verbose",   .separator = '=', .value = "value" },
                { .name = NULL,         .separator = 0,   .value = NULL }
            },
            .handler = handle_option_v,
            .description = "Set verbosity level to *value* (higher = more verbose).",
            .detail = ""
        },
        {
            .class = "Regular options",
            .arguments = {
                { .name = "-V",          .separator = 0, .value = NULL },
                { .name = "--version",   .separator = 0, .value = NULL },
                { .name = "--about",     .separator = 0, .value = NULL },
                { .name = NULL,         .separator = 0, .value = NULL }
            },
            .handler = handle_option_V,
            .description = "Print version, license, and contact information, then exit.",
            .detail = ""
        },
        {
            .class = "Regular options",
            .arguments = {
                { .name = "-h",          .separator = 0, .value = NULL },
                { .name = "--help",      .separator = 0, .value = NULL },
                { .name = "--usage",     .separator = 0, .value = NULL },
                { .name = NULL,         .separator = 0, .value = NULL }
            },
            .handler = handle_option_h,
            .description = "Print usage and detailed help, then exit.",
            .detail = ""
        },

        {
            .class = "Extension options",
            .arguments = {
                { .name = "-k",          .separator = ' ', .value = "string" },
                { .name = "--kernel-release", .separator = '=', .value = "string" },
                { .name = NULL,         .separator = 0,   .value = NULL }
            },
            .handler = handle_option_k,
            .description = "Fake kernel release string (kompat extension).",
            .detail = ""
        },
        {
            .class = "Extension options",
            .arguments = {
                { .name = "-0",          .separator = 0, .value = NULL },
                { .name = "--root-id",   .separator = 0, .value = NULL },
                { .name = NULL,         .separator = 0, .value = NULL }
            },
            .handler = handle_option_0,
            .description = "Appear as root (uid/gid 0) via fake_id0 extension.",
            .detail = ""
        },
        {
            .class = "Extension options",
            .arguments = {
                { .name = "-i",          .separator = ' ', .value = "string" },
                { .name = "--change-id", .separator = '=', .value = "string" },
                { .name = NULL,         .separator = 0,   .value = NULL }
            },
            .handler = handle_option_i,
            .description = "Fake uid:gid as \"uid:gid\" via fake_id0 extension.",
            .detail = ""
        },
        {
            .class = "Extension options",
            .arguments = {
                { .name = "--link2symlink", .separator = 0, .value = NULL },
                { .name = "-l",             .separator = 0, .value = NULL },
                { .name = NULL,             .separator = 0, .value = NULL }
            },
            .handler = handle_option_link2symlink,
            .description = "Convert hard links to symlinks (link2symlink extension).",
            .detail = ""
        },
        {
            .class = "Extension options",
            .arguments = {
                { .name = "--sysvipc",   .separator = 0, .value = NULL },
                { .name = NULL,         .separator = 0, .value = NULL }
            },
            .handler = handle_option_sysvipc,
            .description = "Enable System V IPC emulation (sysvipc extension).",
            .detail = ""
        },
        {
            .class = "Extension options",
            .arguments = {
                { .name = "--ashmem-memfd", .separator = 0, .value = NULL },
                { .name = NULL,             .separator = 0, .value = NULL }
            },
            .handler = handle_option_ashmem_memfd,
            .description = "Emulate memfd using ashmem (ashmem-memfd extension).",
            .detail = ""
        },
        {
            .class = "Extension options",
            .arguments = {
                { .name = "-H",          .separator = 0, .value = NULL },
                { .name = NULL,         .separator = 0, .value = NULL }
            },
            .handler = handle_option_H,
            .description = "Hide temporary files (hidden-files extension).",
            .detail = ""
        },
        {
            .class = "Extension options",
            .arguments = {
                { .name = "-p",          .separator = 0, .value = NULL },
                { .name = NULL,         .separator = 0, .value = NULL }
            },
            .handler = handle_option_p,
            .description = "Redirect privileged ports (port-switch extension).",
            .detail = ""
        },
        {
            .class = "Extension options",
            .arguments = {
                { .name = "-L",          .separator = 0, .value = NULL },
                { .name = NULL,         .separator = 0, .value = NULL }
            },
            .handler = handle_option_L,
            .description = "Fix symlink size reporting (fix-symlink-size extension).",
            .detail = ""
        },

        {
            .class = "Alias options",
            .arguments = {
                { .name = "-R",          .separator = ' ', .value = "path" },
                { .name = NULL,         .separator = 0,   .value = NULL }
            },
            .handler = handle_option_R,
            .description = "Equivalent to -r path plus recommended bindings.",
            .detail = ""
        },
        {
            .class = "Alias options",
            .arguments = {
                { .name = "-S",          .separator = ' ', .value = "path" },
                { .name = NULL,         .separator = 0,   .value = NULL }
            },
            .handler = handle_option_S,
            .description = "Equivalent to -0 -r path plus minimal safe bindings.",
            .detail = ""
        },

        END_OF_OPTIONS
    }
};

#endif
