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
#include <limits.h>
#include <sys/resource.h>

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

#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define ALWAYS_INLINE __attribute__((always_inline)) inline
#define HOT __attribute__((hot))

static ALWAYS_INLINE size_t fast_strlen(const char *s) {
    return __builtin_strlen(s);
}
static ALWAYS_INLINE char* fast_strcpy(char *d, const char *s) {
    return __builtin_strcpy(d, s);
}
static ALWAYS_INLINE int fast_strcmp(const char *a, const char *b) {
    return __builtin_strcmp(a, b);
}
static ALWAYS_INLINE int fast_strncmp(const char *a, const char *b, size_t n) {
    return __builtin_strncmp(a, b, n);
}
static ALWAYS_INLINE char* fast_strncat(char *d, const char *s, size_t n) {
    return __builtin_strncat(d, s, n);
}
static ALWAYS_INLINE char* fast_strchr(const char *s, int c) {
    return __builtin_strchr(s, c);
}
static ALWAYS_INLINE char* fast_strstr(const char *h, const char *n) {
    return __builtin_strstr(h, n);
}

#define STRCMP(a, b)     fast_strcmp(a, b)
#define STRNCMP(a, b, n) fast_strncmp(a, b, n)
#define STRCPY(a, b)     fast_strcpy(a, b)
#define STRNCAT(a, b, n) fast_strncat(a, b, n)
#define STRLEN(a)        fast_strlen(a)
#define STRCHR(a, c)     fast_strchr(a, c)
#define STRSTR(a, b)     fast_strstr(a, b)

#define SAFE_GETENV getenv

void sysvipc_shm_helper_main(void);

void print_usage(Tracee *restrict tracee, const Cli *restrict cli, bool detailed) {
    const char *current_class = "none";
    const Option *options;
    size_t i, j;
#define DETAIL(a) if (detailed) a
    DETAIL(printf("%s %s: %s.\n\n", cli->name, cli->version, cli->subtitle));
    printf("Usage:\n  %s\n", cli->synopsis);
    DETAIL(printf("\n"));
    options = cli->options;
    for (i = 0; options[i].class != NULL; ++i) {
        for (j = 0; ; ++j) {
            const Argument *argument = &options[i].arguments[j];
            if (!argument->name || (!detailed && j != 0)) {
                DETAIL(printf("\n"));
                printf("\t%s\n", options[i].description);
                if (detailed) {
                    if (options[i].detail[0] != '\0')
                        printf("\n%s\n\n", options[i].detail);
                    else
                        printf("\n");
                }
                break;
            }
            if (STRCMP(options[i].class, current_class) != 0) {
                current_class = options[i].class;
                printf("\n%s:\n", current_class);
            }
            if (j == 0)
                printf("  %s", argument->name);
            else
                printf(", %s", argument->name);
            if (argument->separator != '\0')
                printf("%c*%s*", argument->separator, argument->value);
            else if (!detailed)
                printf("\t");
        }
    }
    notify_extensions(tracee, PRINT_USAGE, detailed, 0);
    if (detailed)
        printf("%s\n", cli->colophon);
}

void print_version(const Cli *restrict cli) {
    printf("%s %s\n\n", cli->logo, cli->version);
    printf("built-in accelerators: process_vm = %s, seccomp_filter = %s\n",
#if defined(HAVE_PROCESS_VM)
        "yes",
#else
        "no",
#endif
#if defined(HAVE_SECCOMP_FILTER)
        "yes"
#else
        "no"
#endif
    );
}

static void print_execve_help(const Tracee *restrict tracee, const char *argv0, int status) {
    note(tracee, ERROR, SYSTEM, "execve(\"%s\")", argv0);
    if (status == -ENOENT) {
        const char *ld_preload = SAFE_GETENV("LD_PRELOAD");
        if (ld_preload && STRSTR(ld_preload, "libtermux-exec.so") != NULL) {
            note(tracee, INFO, USER,
"It seems that termux-exec is active and is prepending /data/data/com.termux/... to executable paths\n"
"If this is path is not available inside proot, please \"unset LD_PRELOAD\"");
            return;
        }
    }
    if (status == -EPERM && SAFE_GETENV("PROOT_NO_SECCOMP") == NULL) {
        note(tracee, INFO, USER,
"Android: execve denied. Fix with: export PROOT_NO_SECCOMP=1");
        return;
    }
    note(tracee, INFO, USER, "possible causes:\n"
"Executable error:\n"
"Script interpreter not found (e.g. /bin/sh)\n"
"ELF interpreter not found (e.g. ld-linux.so)\n"
"QEMU not specified for foreign arch\n"
"QEMU or loader invalid\n");
}

static void print_error_separator(const Tracee *restrict tracee, const Argument *restrict argument) {
    if (argument->separator == '\0')
        note(tracee, ERROR, USER, "option '%s' expects no value.", argument->name);
    else
        note(tracee, ERROR, USER, "option '%s' and its value must be separated by '%c'.",
            argument->name, argument->separator);
}

static void print_argv(const Tracee *restrict tracee, const char *prompt, char *const argv[]) {
    char string[ARG_MAX] = "";
    size_t i;
    if (!argv) return;
#define APPEND(post) do { \
    size_t rem = sizeof(string) - 1 - STRLEN(string); \
    if (rem == 0) break; \
    STRNCAT(string, post, rem); \
} while(0)
    APPEND(prompt);
    APPEND(" =");
    for (i = 0; argv[i] != NULL; ++i) {
        APPEND(" ");
        APPEND(argv[i]);
    }
    string[sizeof(string) - 1] = '\0';
#undef APPEND
    note(tracee, INFO, USER, "%s", string);
}

static void print_config(Tracee *restrict tracee, char *const argv[]) {
    if (tracee->verbose <= 0) return;
    if (tracee->qemu)
        note(tracee, INFO, USER, "host rootfs = %s", HOST_ROOTFS);
    if (tracee->glue)
        note(tracee, INFO, USER, "glue rootfs = %s", tracee->glue);
    note(tracee, INFO, USER, "exe = %s", tracee->exe);
    print_argv(tracee, "argv", argv);
    print_argv(tracee, "qemu", tracee->qemu);
    note(tracee, INFO, USER, "initial cwd = %s", tracee->fs->cwd);
    note(tracee, INFO, USER, "verbose level = %d", tracee->verbose);
    notify_extensions(tracee, PRINT_CONFIG, 0, 0);
}

static int initialize_cwd(Tracee *restrict tracee) {
    char path2[PATH_MAX];
    char path[PATH_MAX];
    int status;
    if (tracee->fs->cwd[0] != '/') {
        status = getcwd2(tracee->reconf.tracee, path);
        if (UNLIKELY(status < 0))
            return -1;
    } else {
        STRCPY(path, "/");
    }
    status = join_paths(3, path2, path, tracee->fs->cwd, ".");
    if (UNLIKELY(status < 0))
        return -1;
    STRCPY(path, "/");
    status = canonicalize(tracee, path2, true, path, 0);
    if (UNLIKELY(status < 0))
        STRCPY(path, "/");
    chop_finality(path);
    TALLOC_FREE(tracee->fs->cwd);
    tracee->fs->cwd = talloc_strdup(tracee->fs, path);
    setenv("PWD", path, 1);
    return 0;
}

static int initialize_exe(Tracee *restrict tracee, const char *exe) {
    char path[PATH_MAX];
    int status;
    status = which(tracee, tracee->reconf.paths, path, exe ?: "/bin/sh");
    if (UNLIKELY(status < 0))
        return -1;
    status = detranslate_path(tracee, path, NULL);
    if (UNLIKELY(status < 0))
        return -1;
    tracee->exe = talloc_strdup(tracee, path);
    return 0;
}

HOT
static int parse_config(Tracee *restrict tracee, size_t argc, char *const argv[]) {
    option_handler_t handler = NULL;
    const Option *options;
    const Cli *cli = NULL;
    size_t argc_offset;
    size_t i, j, k;
    int status;
    cli = get_proot_cli(tracee->ctx);
    tracee->tool_name = cli->name;
    if (argc == 1) {
        print_usage(tracee, cli, false);
        return -1;
    }
    for (i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        if (handler != NULL) {
            status = handler(tracee, cli, arg);
            if (UNLIKELY(status < 0))
                return -1;
            handler = NULL;
            continue;
        }
        if (arg[0] != '-')
            break;
        options = cli->options;
        for (j = 0; options[j].class != NULL; ++j) {
            const Option *option = &options[j];
            for (k = 0; ; ++k) {
                const Argument *argument;
                size_t length;
                argument = &option->arguments[k];
                if (!argument->name)
                    break;
                length = STRLEN(argument->name);
                if (STRNCMP(arg, argument->name, length) != 0)
                    continue;
                if (STRLEN(arg) > length && arg[length] != argument->separator) {
                    print_error_separator(tracee, argument);
                    return -1;
                }
                if (!argument->value) {
                    status = option->handler(tracee, cli, NULL);
                    if (UNLIKELY(status < 0))
                        return -1;
                    goto known_option;
                }
                if (argument->separator == arg[length]) {
                    status = option->handler(tracee, cli, &arg[length + 1]);
                    if (UNLIKELY(status < 0))
                        return -1;
                    goto known_option;
                }
                if (argument->separator != ' ') {
                    print_error_separator(tracee, argument);
                    return -1;
                }
                handler = option->handler;
                goto known_option;
            }
        }
        note(tracee, ERROR, USER, "unknown option '%s'.", arg);
        return -1;
known_option:
        if (handler != NULL && i == argc - 1) {
            note(tracee, ERROR, USER, "missing value for option '%s'.", arg);
            return -1;
        }
    }
    argc_offset = i;
#define HOOK_CONFIG(cb) do { \
    if (cli->cb != NULL) { \
        status = cli->cb(tracee, cli, argc, argv, i); \
        if (UNLIKELY(status < 0)) return -1; \
        i = status; \
    } \
} while(0)
    HOOK_CONFIG(pre_initialize_bindings);
    status = initialize_bindings(tracee);
    if (UNLIKELY(status < 0)) return -1;
    HOOK_CONFIG(post_initialize_bindings);
    HOOK_CONFIG(pre_initialize_cwd);
    status = initialize_cwd(tracee);
    if (UNLIKELY(status < 0)) return -1;
    HOOK_CONFIG(post_initialize_cwd);
    HOOK_CONFIG(pre_initialize_exe);
    status = initialize_exe(tracee, argv[argc_offset]);
    if (UNLIKELY(status < 0)) return -1;
    HOOK_CONFIG(post_initialize_exe);
#undef HOOK_CONFIG
    print_config(tracee, &argv[argc_offset]);
    return (int)argc_offset;
}

bool exit_failure = true;

HOT
int proot_main(int argc, char *const argv[]) {
    Tracee *tracee;
    int status;
    talloc_set_log_fn(NULL);
    putenv("ANDROID_PRIORITY=DISPLAY");
    setpriority(PRIO_PROCESS, 0, -20);
#ifdef __BIONIC__
    setenv("MALLOC_MMAP_THRESHOLD_", "16384", 1);
    setenv("MALLOC_TRIM_THRESHOLD_", "32768", 1);
#endif
    if (argc == 2 && STRCMP(argv[1], "--shm-helper") == 0) {
        sysvipc_shm_helper_main();
        exit(0);
    }
    tracee = get_tracee(NULL, 0, true);
    if (UNLIKELY(!tracee)) goto error;
    tracee->pid = getpid();
    const char *e = SAFE_GETENV("PROOT_VERBOSE");
    if (e) {
        tracee->verbose = atoi(e);
        global_verbose_level = tracee->verbose;
    }
    status = parse_config(tracee, (size_t)argc, argv);
    if (UNLIKELY(status < 0)) goto error;
    if (!SAFE_GETENV("PROOT_NO_MOUNTINFO"))
        initialize_extension(tracee, mountinfo_callback, NULL);
    status = launch_process(tracee, &argv[status]);
    if (UNLIKELY(status < 0)) {
        print_execve_help(tracee, tracee->exe, status);
        goto error;
    }
    exit(event_loop());
error:
    TALLOC_FREE(tracee);
    if (exit_failure) {
        char *b = talloc_strdup(NULL, argv[0]);
        fprintf(stderr, "fatal error: see `%s --help`.\n", basename(b));
        TALLOC_FREE(b);
        exit(EXIT_FAILURE);
    }
    exit(EXIT_SUCCESS);
}

int parse_integer_option(const Tracee *restrict tracee, int *var, const char *val, const char *opt) {
    char *e;
    *var = (int)strtol(val, &e, 10);
    if (UNLIKELY(e == val)) {
        note(tracee, ERROR, USER, "option `%s` expects integer.", opt);
        return -1;
    }
    return 0;
}

const char *expand_front_variable(TALLOC_CTX *restrict ctx, const char *s) {
    const char *su;
    char *ex;
    ptrdiff_t sz;
    if (*s != '$') return s;
    su = STRCHR(s, '/');
    if (!su) return SAFE_GETENV(s+1) ?: s;
    sz = su - s;
    if (sz <= 1) return s;
    ex = talloc_strndup(ctx, s+1, sz-1);
    const char *ev = SAFE_GETENV(ex);
    TALLOC_FREE(ex);
    if (!ev) return s;
    ex = talloc_asprintf(ctx, "%s%s", ev, su);
    return ex ?: s;
}