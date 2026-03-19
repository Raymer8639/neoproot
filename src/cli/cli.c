#include <stdio.h>
#include <stdbool.h>
#include <linux/limits.h>
#include <string.h>
#include <talloc.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <libgen.h>
#ifdef __GLIBC__
#include <execinfo.h>
#endif
#include <limits.h>

#include "cli/cli.h"
#include "cli/note.h"
#include "extension/extension.h"
#include "tracee/tracee.h"
#include "tracee/event.h"
#include "path/binding.h"
#include "path/canon.h"
#include "path/path.h"
#include "extension/sysvipc/sysvipc.h"

#include "build.h"
#include "attribute.h"

/* ------------------------------------------------------------------------- */
/*  Global flag                                                              */
/* ------------------------------------------------------------------------- */
bool exit_failure = true;

/* ------------------------------------------------------------------------- */
/*  Public functions                                                         */
/* ------------------------------------------------------------------------- */

void print_usage(Tracee *tracee, const Cli *cli, bool detailed)
{
    /* Build output dynamically to avoid fixed strings */
    char buffer[8192];
    size_t pos = 0;

    if (detailed) {
        pos += snprintf(buffer + pos, sizeof(buffer) - pos,
                        "%s %s: %s.\n\n", cli->name, cli->version, cli->subtitle);
    }
    pos += snprintf(buffer + pos, sizeof(buffer) - pos,
                    "Usage:\n  %s\n", cli->synopsis);
    if (detailed)
        pos += snprintf(buffer + pos, sizeof(buffer) - pos, "\n");

    const Option *opt = cli->options;
    const char *last_class = NULL;

    for (size_t i = 0; opt[i].class != NULL; ++i) {
        /* Print class header if changed */
        if (last_class == NULL || strcmp(opt[i].class, last_class) != 0) {
            pos += snprintf(buffer + pos, sizeof(buffer) - pos,
                            "\n%s:\n", opt[i].class);
            last_class = opt[i].class;
        }

        /* Print option names */
        pos += snprintf(buffer + pos, sizeof(buffer) - pos, "  ");
        int first = 1;
        for (size_t j = 0; opt[i].arguments[j].name != NULL; ++j) {
            const Argument *arg = &opt[i].arguments[j];
            if (!first)
                pos += snprintf(buffer + pos, sizeof(buffer) - pos, ", ");
            pos += snprintf(buffer + pos, sizeof(buffer) - pos, "%s", arg->name);
            if (arg->separator != '\0' && arg->value != NULL)
                pos += snprintf(buffer + pos, sizeof(buffer) - pos,
                                "%c%s", arg->separator, arg->value);
            first = 0;
        }
        pos += snprintf(buffer + pos, sizeof(buffer) - pos, "\n\t%s\n", opt[i].description);
        if (detailed && opt[i].detail[0] != '\0')
            pos += snprintf(buffer + pos, sizeof(buffer) - pos, "\n%s\n\n", opt[i].detail);
    }

    notify_extensions(tracee, PRINT_USAGE, detailed, 0);

    if (detailed)
        pos += snprintf(buffer + pos, sizeof(buffer) - pos, "%s\n", cli->colophon);

    /* Write the buffer in one go to stdout */
    fwrite(buffer, 1, pos, stdout);
}

void print_version(const Cli *cli)
{
    printf("%s %s\n\n", cli->logo, cli->version);
    /* Keep accelerator info, but reformat */
    const char *vm = 
#ifdef __ANDROID__
        "yes";
#else
#if defined(HAVE_PROCESS_VM)
        "yes";
#else
        "no";
#endif
#endif
    const char *seccomp = 
#ifdef __ANDROID__
        "yes";
#else
#if defined(HAVE_SECCOMP_FILTER)
        "yes";
#else
        "no";
#endif
#endif
    printf("built-in: process_vm=%s, seccomp_filter=%s\n", vm, seccomp);
}

int parse_integer_option(const Tracee *tracee, int *var, const char *val, const char *opt)
{
    char *end;
    long num;
    errno = 0;
    num = strtol(val, &end, 10);
    if (errno != 0 || end == val || *end != '\0') {
        /* Use a custom error message */
        char msg[256];
        snprintf(msg, sizeof(msg), "option %s requires numeric value", opt);
        note(tracee, ERROR, USER, "%s", msg);
        return -1;
    }
    *var = (int)num;
    return 0;
}

const char *expand_front_variable(TALLOC_CTX *ctx, const char *str)
{
    if (*str != '$')
        return str;

    const char *slash = strchr(str, '/');
    if (!slash) {
        const char *env = getenv(str + 1);
        return env ? env : str;
    }

    size_t vlen = slash - str - 1;
    if (vlen == 0)
        return str;

    char *vname = talloc_strndup(ctx, str + 1, vlen);
    if (!vname)
        return str;

    const char *env = getenv(vname);
    talloc_free(vname);
    if (!env)
        return str;

    char *result = talloc_asprintf(ctx, "%s%s", env, slash);
    return result ? result : str;
}

/* ------------------------------------------------------------------------- */
/*  Internal helpers (completely new implementation)                         */
/* ------------------------------------------------------------------------- */

/* Emit an error about option separator */
static void emit_sep_error(const Tracee *t, const Argument *a)
{
    char buf[256];
    if (a->separator == '\0')
        snprintf(buf, sizeof(buf), "option '%s' cannot take a value", a->name);
    else
        snprintf(buf, sizeof(buf), "option '%s' requires separator '%c'", a->name, a->separator);
    note(t, ERROR, USER, "%s", buf);
}

/* Format an argument vector into a string (different from original) */
static void format_argv(const Tracee *t, const char *tag, char *const argv[], char *out, size_t outsz)
{
    (void)t; /* unused parameter */
    size_t pos = 0;
    pos += snprintf(out + pos, outsz - pos, "%s =", tag);
    for (size_t i = 0; argv && argv[i]; ++i) {
        if (pos + 1 + strlen(argv[i]) >= outsz)
            break;
        pos += snprintf(out + pos, outsz - pos, " %s", argv[i]);
    }
}

/* Display configuration */
static void dump_config(Tracee *t, char *const argv[])
{
    if (t->verbose <= 0)
        return;

    char buffer[ARG_MAX];

    if (t->qemu) {
        snprintf(buffer, sizeof(buffer), "host rootfs = %s", HOST_ROOTFS);
        note(t, INFO, USER, "%s", buffer);
    }
    if (t->glue) {
        snprintf(buffer, sizeof(buffer), "glue rootfs = %s", t->glue);
        note(t, INFO, USER, "%s", buffer);
    }

    snprintf(buffer, sizeof(buffer), "exe = %s", t->exe);
    note(t, INFO, USER, "%s", buffer);

    format_argv(t, "argv", argv, buffer, sizeof(buffer));
    note(t, INFO, USER, "%s", buffer);
    format_argv(t, "qemu", t->qemu, buffer, sizeof(buffer));
    if (t->qemu)
        note(t, INFO, USER, "%s", buffer);

    snprintf(buffer, sizeof(buffer), "initial cwd = %s", t->fs->cwd);
    note(t, INFO, USER, "%s", buffer);
    snprintf(buffer, sizeof(buffer), "verbose level = %d", t->verbose);
    note(t, INFO, USER, "%s", buffer);

    notify_extensions(t, PRINT_CONFIG, 0, 0);
}

/* Provide execve failure hints (different wording) */
static void execve_failure_help(const Tracee *t, const char *prog, int err)
{
    char msg[512];
    snprintf(msg, sizeof(msg), "execve(\"%s\") failed", prog);
    note(t, ERROR, SYSTEM, "%s", msg);

    if (err == -ENOENT && getenv("LD_PRELOAD") &&
        strstr(getenv("LD_PRELOAD"), "libtermux-exec.so")) {
        note(t, INFO, USER, "LD_PRELOAD contains termux-exec; try unsetting it");
        return;
    }

    if (err == -EPERM && !getenv("PROOT_NO_SECCOMP")) {
        note(t, INFO, USER, "Possible kernel bug: set PROOT_NO_SECCOMP=1 to work around");
        return;
    }

    note(t, INFO, USER,
         "Typical reasons:\n"
         " - missing script interpreter (like /bin/sh)\n"
         " - missing dynamic linker (ld-linux.so)\n"
         " - foreign binary without -q QEMU\n"
         " - QEMU malfunction\n"
         " - loader issues");
}

/* ------------------------------------------------------------------------- */
/*  Initialization steps (reorganized)                                       */
/* ------------------------------------------------------------------------- */

static int setup_working_dir(Tracee *t)
{
    char base[PATH_MAX], combined[PATH_MAX], result[PATH_MAX];
    int rc;

    if (t->fs->cwd[0] != '/') {
        rc = getcwd2(t->reconf.tracee, base);
        if (rc < 0) {
            note(t, ERROR, INTERNAL, "getcwd error: %s", strerror(-rc));
            return -1;
        }
    } else {
        strcpy(base, "/");
    }

    rc = join_paths(3, combined, base, t->fs->cwd, ".");
    if (rc < 0) {
        note(t, ERROR, INTERNAL, "path join error");
        return -1;
    }

    strcpy(result, "/");
    rc = canonicalize(t, combined, true, result, 0);
    if (rc < 0) {
        note(t, WARNING, USER, "cannot change to '%s': %s", combined, strerror(-rc));
        note(t, INFO, USER, "fallback to '/'");
        strcpy(result, "/");
    }
    chop_finality(result);

    TALLOC_FREE(t->fs->cwd);
    t->fs->cwd = talloc_strdup(t->fs, result);
    if (!t->fs->cwd)
        return -1;
    talloc_set_name_const(t->fs->cwd, "cwd");

    setenv("PWD", result, 1);
    return 0;
}

static int setup_executable(Tracee *t, const char *exe)
{
    char path[PATH_MAX];
    int rc;

    if (!exe)
        exe = "/bin/sh";

    rc = which(t, t->reconf.paths, path, exe);
    if (rc < 0)
        return -1;

    rc = detranslate_path(t, path, NULL);
    if (rc < 0)
        return -1;

    t->exe = talloc_strdup(t, path);
    if (!t->exe)
        return -1;
    talloc_set_name_const(t->exe, "exe");

    return 0;
}

/* ------------------------------------------------------------------------- */
/*  Command line parsing (completely restructured)                           */
/* ------------------------------------------------------------------------- */

static int scan_arguments(Tracee *t, size_t argc, char *const argv[], size_t *first_arg)
{
    const Cli *cli = get_proot_cli(t->ctx);
    size_t cur = 1;
    option_handler_t pending = NULL;
    int rc;

    t->tool_name = cli->name;

    if (argc == 1) {
        print_usage(t, cli, false);
        return -1;
    }

    while (cur < argc) {
        const char *arg = argv[cur];

        if (pending) {
            rc = pending(t, cli, arg);
            if (rc < 0)
                return -1;
            pending = NULL;
            ++cur;
            continue;
        }

        if (arg[0] != '-')
            break;

        const Option *opt = cli->options;
        int found = 0;

        for (size_t o = 0; opt[o].class != NULL && !found; ++o) {
            const Argument *alist = opt[o].arguments;
            for (size_t a = 0; alist[a].name != NULL && !found; ++a) {
                size_t nlen = strlen(alist[a].name);
                if (strncmp(arg, alist[a].name, nlen) != 0)
                    continue;

                if (strlen(arg) > nlen && arg[nlen] != alist[a].separator) {
                    emit_sep_error(t, &alist[a]);
                    return -1;
                }

                if (!alist[a].value) {
                    rc = opt[o].handler(t, cli, NULL);
                    if (rc < 0)
                        return -1;
                    found = 1;
                    break;
                }

                if (alist[a].separator == arg[nlen]) {
                    rc = opt[o].handler(t, cli, arg + nlen + 1);
                    if (rc < 0)
                        return -1;
                    found = 1;
                    break;
                }

                if (alist[a].separator != ' ') {
                    emit_sep_error(t, &alist[a]);
                    return -1;
                }

                pending = opt[o].handler;
                found = 1;
                break;
            }
        }

        if (!found) {
            char err[256];
            snprintf(err, sizeof(err), "unrecognized option '%s'", arg);
            note(t, ERROR, USER, "%s", err);
            return -1;
        }

        if (!pending)
            ++cur;
        else
            ++cur;
    }

    if (pending) {
        note(t, ERROR, USER, "option requires a value");
        return -1;
    }

    *first_arg = cur;
    return 0;
}

/* ------------------------------------------------------------------------- */
/*  Main entry point                                                         */
/* ------------------------------------------------------------------------- */

int main(int argc, char *const argv[])
{
    Tracee *tracee;
    int rc;
    size_t first_non_opt;

    talloc_enable_leak_report();
#if TALLOC_VERSION_MAJOR >= 2
    talloc_set_log_stderr();
#endif

    if (argc == 2 && strcmp(argv[1], "--shm-helper") == 0) {
        sysvipc_shm_helper_main();
        /* not reached */
    }

    tracee = get_tracee(NULL, 0, true);
    if (!tracee)
        goto fail;
    tracee->pid = getpid();

    const char *env_verb = getenv("PROOT_VERBOSE");
    if (env_verb) {
        tracee->verbose = strtol(env_verb, NULL, 10);
        global_verbose_level = tracee->verbose;
    }

    rc = scan_arguments(tracee, (size_t)argc, argv, &first_non_opt);
    if (rc < 0)
        goto fail;

    /* Invoke hooks (if any) */
    const Cli *cli = get_proot_cli(tracee->ctx);
#define RUN_HOOK(h) do { if (cli->h) { rc = cli->h(tracee, cli, argc, argv, first_non_opt); if (rc < 0) goto fail; } } while (0)

    RUN_HOOK(pre_initialize_bindings);
    rc = initialize_bindings(tracee);
    if (rc < 0)
        goto fail;
    RUN_HOOK(post_initialize_bindings);
    RUN_HOOK(pre_initialize_cwd);

    rc = setup_working_dir(tracee);
    if (rc < 0)
        goto fail;

    RUN_HOOK(post_initialize_cwd);
    RUN_HOOK(pre_initialize_exe);

    rc = setup_executable(tracee, (first_non_opt < (size_t)argc) ? argv[first_non_opt] : NULL);
    if (rc < 0)
        goto fail;

    RUN_HOOK(post_initialize_exe);
#undef RUN_HOOK

    dump_config(tracee, &argv[first_non_opt]);

    if (!getenv("PROOT_NO_MOUNTINFO"))
        initialize_extension(tracee, mountinfo_callback, NULL);

    rc = launch_process(tracee, &argv[first_non_opt]);
    if (rc < 0) {
        execve_failure_help(tracee, tracee->exe, rc);
        goto fail;
    }

    exit(event_loop());

fail:
    TALLOC_FREE(tracee);
    if (exit_failure) {
        fprintf(stderr, "fatal: see `%s --help`.\n", basename(argv[0]));
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

/* ------------------------------------------------------------------------- */
/*  GCC instrumentation (unchanged, but rarely used)                         */
/* ------------------------------------------------------------------------- */

static int trace_depth = 0;

void __cyg_profile_func_enter(void *func UNUSED, void *call UNUSED) DONT_INSTRUMENT;
void __cyg_profile_func_enter(void *func UNUSED, void *call UNUSED)
{
#ifdef __GLIBC__
    void *ptrs[] = { func, call };
    char **sym = backtrace_symbols(ptrs, 2);
    if (sym) {
        fprintf(stderr, "%*s from %s\n", (int)strlen(sym[0]) + trace_depth, sym[0], sym[1]);
        free(sym);
    }
#endif
    if (trace_depth < INT_MAX)
        ++trace_depth;
}

void __cyg_profile_func_exit(void *func UNUSED, void *call UNUSED) DONT_INSTRUMENT;
void __cyg_profile_func_exit(void *func UNUSED, void *call UNUSED)
{
    if (trace_depth > 0)
        --trace_depth;
}