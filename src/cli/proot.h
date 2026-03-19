#ifndef PROOT_CLI_H
#define PROOT_CLI_H

#include "cli/cli.h"

#ifndef VERSION
#define VERSION "5.4.0-scicat"
#endif

/* ------------------------------------------------------------------------- */
/*  Recommended binding sets                                                 */
/* ------------------------------------------------------------------------- */

static const char *recommended_bindings[] = {
    "/etc/host.conf",        "/etc/hosts",        "/etc/hosts.equiv",
    "/etc/mtab",             "/etc/netgroup",     "/etc/networks",
    "/etc/passwd",           "/etc/group",        "/etc/nsswitch.conf",
    "/etc/resolv.conf",      "/etc/localtime",    "/dev/",
    "/sys/",                 "/proc/",            "/tmp/",
    "/run/",                 "/var/run/dbus/system_bus_socket",
    "$HOME",                 "*path*",
    NULL
};

static const char *recommended_su_bindings[] = {
    "/etc/host.conf",        "/etc/hosts",        "/etc/nsswitch.conf",
    "/etc/resolv.conf",      "/dev/",             "/sys/",
    "/proc/",                "/tmp/",             "/run/shm",
    "$HOME",                 "*path*",
    NULL
};

/* ------------------------------------------------------------------------- */
/*  Option handler forward declarations                                      */
/* ------------------------------------------------------------------------- */

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

/* ------------------------------------------------------------------------- */
/*  Initialization hook forward declarations                                 */
/* ------------------------------------------------------------------------- */

static int pre_initialize_bindings(Tracee *, const Cli *, size_t, char *const *, size_t);
static int post_initialize_exe(Tracee *, const Cli *, size_t, char *const *, size_t);

/* ------------------------------------------------------------------------- */
/*  Main CLI descriptor                                                      */
/* ------------------------------------------------------------------------- */

static Cli proot_cli = {
    .version  = VERSION,
    .name     = "proot",
    .subtitle = "chroot, mount --bind, and binfmt_misc without privilege/setup",
    .synopsis = "proot [option] ... [command]",

    .colophon = "Copyright (C) 2026 scicat, released under MIT.\n"
                "Visit https://gitee.com/scicat-team/proot-scicat for help and updates.",

    .logo = " __    __            __   \n"
            "/ / /\\ \\ \\ ___  ___  \\ \\  \n"
            "\\ \\/  \\/ / _ \\/ _ \\  \\ \\ \n"
            " \\  /\\  /  __/  __/  / / \n"
            "  \\/  \\/ \\___|\\___| /_/  \n"
            "      Uproot - GPL License",

    .pre_initialize_bindings = pre_initialize_bindings,
    .post_initialize_exe     = post_initialize_exe,

    .options = {
        /* Regular options */
        {
            .class = "Regular options",
            .arguments = {
                { .name = "-r", .separator = ' ', .value = "path" },
                { .name = "--rootfs", .separator = '=', .value = "path" },
                { .name = NULL }
            },
            .handler = handle_option_r,
            .description = "Use *path* as the new guest root file-system (default: /).",
            .detail = "\tThe specified path typically contains a Linux distribution\n"
                      "\twhere all new programs will be confined. Prefer -R or -S."
        },
        {
            .class = "Regular options",
            .arguments = {
                { .name = "-b", .separator = ' ', .value = "path" },
                { .name = "--bind", .separator = '=', .value = "path" },
                { .name = "-m", .separator = ' ', .value = "path" },
                { .name = "--mount", .separator = '=', .value = "path" },
                { .name = NULL }
            },
            .handler = handle_option_b,
            .description = "Make the content of *path* accessible inside the guest.",
            .detail = "\tBind host path to guest; syntax: -b host:guest."
        },
        {
            .class = "Regular options",
            .arguments = {
                { .name = "-q", .separator = ' ', .value = "command" },
                { .name = "--qemu", .separator = '=', .value = "command" },
                { .name = NULL }
            },
            .handler = handle_option_q,
            .description = "Execute guest programs through QEMU user-mode.",
            .detail = "\tFor cross-architecture execution, emulates the guest CPU."
        },
        {
            .class = "Regular options",
            .arguments = {
                { .name = "-w", .separator = ' ', .value = "path" },
                { .name = "--pwd", .separator = '=', .value = "path" },
                { .name = "--cwd", .separator = '=', .value = "path" },
                { .name = NULL }
            },
            .handler = handle_option_w,
            .description = "Set the initial working directory to *path*."
        },
        {
            .class = "Regular options",
            .arguments = {
                { .name = "--kill-on-exit", .separator = '\0', .value = NULL },
                { .name = NULL }
            },
            .handler = handle_option_kill_on_exit,
            .description = "Kill all processes when the initial command exits."
        },
        {
            .class = "Regular options",
            .arguments = {
                { .name = "-v", .separator = ' ', .value = "value" },
                { .name = "--verbose", .separator = '=', .value = "value" },
                { .name = NULL }
            },
            .handler = handle_option_v,
            .description = "Set verbosity level to *value* (higher = more verbose)."
        },
        {
            .class = "Regular options",
            .arguments = {
                { .name = "-V", .separator = '\0', .value = NULL },
                { .name = "--version", .separator = '\0', .value = NULL },
                { .name = "--about", .separator = '\0', .value = NULL },
                { .name = NULL }
            },
            .handler = handle_option_V,
            .description = "Print version, license, and contact information, then exit."
        },
        {
            .class = "Regular options",
            .arguments = {
                { .name = "-h", .separator = '\0', .value = NULL },
                { .name = "--help", .separator = '\0', .value = NULL },
                { .name = "--usage", .separator = '\0', .value = NULL },
                { .name = NULL }
            },
            .handler = handle_option_h,
            .description = "Print usage and detailed help, then exit."
        },

        /* Extension options */
        {
            .class = "Extension options",
            .arguments = {
                { .name = "-k", .separator = ' ', .value = "string" },
                { .name = "--kernel-release", .separator = '=', .value = "string" },
                { .name = NULL }
            },
            .handler = handle_option_k,
            .description = "Fake kernel release string (kompat extension)."
        },
        {
            .class = "Extension options",
            .arguments = {
                { .name = "-0", .separator = '\0', .value = NULL },
                { .name = "--root-id", .separator = '\0', .value = NULL },
                { .name = NULL }
            },
            .handler = handle_option_0,
            .description = "Appear as root (uid/gid 0) via fake_id0 extension."
        },
        {
            .class = "Extension options",
            .arguments = {
                { .name = "-i", .separator = ' ', .value = "string" },
                { .name = "--change-id", .separator = '=', .value = "string" },
                { .name = NULL }
            },
            .handler = handle_option_i,
            .description = "Fake uid:gid as \"uid:gid\" via fake_id0 extension."
        },
        {
            .class = "Extension options",
            .arguments = {
                { .name = "--link2symlink", .separator = '\0', .value = NULL },
                { .name = "-l", .separator = '\0', .value = NULL },
                { .name = NULL }
            },
            .handler = handle_option_link2symlink,
            .description = "Convert hard links to symlinks (link2symlink extension)."
        },
        {
            .class = "Extension options",
            .arguments = {
                { .name = "--sysvipc", .separator = '\0', .value = NULL },
                { .name = NULL }
            },
            .handler = handle_option_sysvipc,
            .description = "Enable System V IPC emulation (sysvipc extension)."
        },
        {
            .class = "Extension options",
            .arguments = {
                { .name = "--ashmem-memfd", .separator = '\0', .value = NULL },
                { .name = NULL }
            },
            .handler = handle_option_ashmem_memfd,
            .description = "Emulate memfd using ashmem (ashmem-memfd extension)."
        },
        {
            .class = "Extension options",
            .arguments = {
                { .name = "-H", .separator = '\0', .value = NULL },
                { .name = NULL }
            },
            .handler = handle_option_H,
            .description = "Hide temporary files (hidden-files extension)."
        },
        {
            .class = "Extension options",
            .arguments = {
                { .name = "-p", .separator = '\0', .value = NULL },
                { .name = NULL }
            },
            .handler = handle_option_p,
            .description = "Redirect privileged ports (port-switch extension)."
        },
        {
            .class = "Extension options",
            .arguments = {
                { .name = "-L", .separator = '\0', .value = NULL },
                { .name = NULL }
            },
            .handler = handle_option_L,
            .description = "Fix symlink size reporting (fix-symlink-size extension)."
        },

        /* Alias options */
        {
            .class = "Alias options",
            .arguments = {
                { .name = "-R", .separator = ' ', .value = "path" },
                { .name = NULL }
            },
            .handler = handle_option_R,
            .description = "Equivalent to -r path plus recommended bindings."
        },
        {
            .class = "Alias options",
            .arguments = {
                { .name = "-S", .separator = ' ', .value = "path" },
                { .name = NULL }
            },
            .handler = handle_option_S,
            .description = "Equivalent to -0 -r path plus minimal safe bindings."
        },

        END_OF_OPTIONS
    }
};

#endif /* PROOT_CLI_H */