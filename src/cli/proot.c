#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>

#include "cli/cli.h"
#include "cli/note.h"
#include "extension/extension.h"
#include "extension/sysvipc/sysvipc.h"
#include "extension/netlink_route/netlink_route.h"
#include "path/binding.h"
#include "attribute.h"

#include "build.h"
#include "cli/proot.h"

#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define ALWAYS_INLINE __attribute__((always_inline)) inline

#define STRCMP(a, b) __builtin_strcmp(a, b)

void egg_mark_h(void);
void egg_mark_v(void);
void egg_try(void);
void egg_show_final(void);

static ALWAYS_INLINE void apply_bindings(Tracee *restrict t, const char *list[], const char *base) {
    for (int i = 0; list[i] != NULL; ++i) {
        const char *src = list[i];
        if (STRCMP(src, "*path*") == 0)
            src = base;
        else
            src = expand_front_variable(t->ctx, src);
        (void) new_binding(t, src, NULL, false);
    }
}

static int handle_option_r(Tracee *restrict t, const Cli *restrict c, const char *val) {
    (void)c;
    Binding *b = new_binding(t, val, "/", true);
    return b ? 0 : -1;
}

static int handle_option_b(Tracee *restrict t, const Cli *restrict c, const char *val) {
    (void)c;
    char *copy = talloc_strdup(t->ctx, val);
    if (UNLIKELY(!copy)) {
        note(t, ERROR, INTERNAL, "out of memory");
        return -1;
    }
    char *guest = strchr(copy, ':');
    bool readonly = false;
    if (guest) {
        *guest = '\0';
        guest++;
        char *opt = strchr(guest, ':');
        if (opt) {
            *opt = '\0';
            opt++;
            if (STRCMP(opt, "ro") == 0)
                readonly = true;
            else if (opt[0] != '\0')
                note(t, WARNING, USER, "unknown bind option '%s', ignored", opt);
        }
    }
    Binding *b = new_binding(t, copy, guest, true);
    if (b && readonly)
        b->readonly = true;
    int ret = b ? 0 : -1;
    talloc_free(copy);
    return ret;
}

static int handle_option_w(Tracee *restrict t, const Cli *restrict c, const char *val) {
    (void)c;
    TALLOC_FREE(t->fs->cwd);
    t->fs->cwd = talloc_strdup(t->fs, val);
    return t->fs->cwd ? 0 : -1;
}

static int handle_option_k(Tracee *restrict t, const Cli *restrict c, const char *val) {
    (void)c;
    void *ext = get_extension(t, kompat_callback);
    if (ext) {
        note(t, WARNING, USER, "multiple -k options; using last");
        TALLOC_FREE(ext);
    }
    int rc = initialize_extension(t, kompat_callback, val);
    if (UNLIKELY(rc < 0))
        note(t, WARNING, INTERNAL, "kompat init failed for '%s'", val);
    return 0;
}

static int handle_option_i(Tracee *restrict t, const Cli *restrict c, const char *val) {
    (void)c;
    void *ext = get_extension(t, fake_id0_callback);
    if (ext) {
        note(t, WARNING, USER, "multiple -i/-0/-S; using last");
        TALLOC_FREE(ext);
    }
    (void)initialize_extension(t, fake_id0_callback, val);
    return 0;
}

static int handle_option_0(Tracee *restrict t, const Cli *restrict c, const char *v) {
    (void)v;
    return handle_option_i(t, c, "0:0");
}

static int handle_option_kill_on_exit(Tracee *restrict t, const Cli *restrict c, const char *v) {
    (void)c; (void)v;
    t->killall_on_exit = true;
    return 0;
}

static int handle_option_v(Tracee *restrict t, const Cli *restrict c, const char *val) {
    (void)c;
    int lvl;
    if (parse_integer_option(t, &lvl, val, "-v") < 0)
        return -1;
    t->verbose = lvl;
    global_verbose_level = lvl;
    return 0;
}

static int handle_option_V(Tracee *restrict t, const Cli *restrict c, const char *v) {
    (void)t; (void)v;
    egg_mark_v();
    egg_try();
    print_version(c);
    printf("\n%s\n", c->colophon);
    egg_show_final();
    fflush(stdout);
    exit_failure = false;
    return -1;
}

static int handle_option_h(Tracee *restrict t, const Cli *restrict c, const char *v) {
    (void)v;
    egg_mark_h();
    egg_try();
    print_usage(t, c, true);
    egg_show_final();
    fflush(stdout);
    exit_failure = false;
    return -1;
}

static int handle_option_R(Tracee *restrict t, const Cli *restrict c, const char *val) {
    int rc = handle_option_r(t, c, val);
    if (UNLIKELY(rc < 0)) return rc;
    apply_bindings(t, recommended_bindings, val);
    return 0;
}

static int handle_option_S(Tracee *restrict t, const Cli *restrict c, const char *val) {
    int rc = handle_option_0(t, c, val);
    if (UNLIKELY(rc < 0)) return rc;
    rc = handle_option_r(t, c, val);
    if (UNLIKELY(rc < 0)) return rc;
    apply_bindings(t, recommended_su_bindings, val);
    return 0;
}

static int handle_option_link2symlink(Tracee *restrict t, const Cli *restrict c, const char *v) {
    (void)c; (void)v;
    int rc = initialize_extension(t, link2symlink_callback, NULL);
    if (UNLIKELY(rc < 0))
        note(t, WARNING, INTERNAL, "link2symlink init failed");
    return 0;
}

static int handle_option_ashmem_memfd(Tracee *restrict t, const Cli *restrict c, const char *v) {
    (void)c; (void)v;
    int rc = initialize_extension(t, ashmem_memfd_callback, NULL);
    if (UNLIKELY(rc < 0))
        note(t, WARNING, INTERNAL, "ashmem-memfd init failed");
    return 0;
}

static int handle_option_sysvipc(Tracee *restrict t, const Cli *restrict c, const char *v) {
    (void)c; (void)v;
    int rc = initialize_extension(t, sysvipc_callback, NULL);
    if (UNLIKELY(rc < 0))
        note(t, WARNING, INTERNAL, "sysvipc init failed");
    return 0;
}

static int handle_option_L(Tracee *restrict t, const Cli *restrict c, const char *v) {
    (void)c; (void)v;
    (void)initialize_extension(t, fix_symlink_size_callback, NULL);
    return 0;
}

static int handle_option_H(Tracee *restrict t, const Cli *restrict c, const char *v) {
    (void)c; (void)v;
    (void)initialize_extension(t, hidden_files_callback, NULL);
    return 0;
}

static int handle_option_p(Tracee *restrict t, const Cli *restrict c, const char *v) {
    (void)c; (void)v;
    (void)initialize_extension(t, port_switch_callback, NULL);
    return 0;
}

static int pre_initialize_bindings(Tracee *restrict t, const Cli *restrict c,
                                   size_t ac, char *const av[], size_t cur) {
    (void)ac; (void)av;
    if (!t->fs->cwd) {
        if (handle_option_w(t, c, ".") < 0)
            return -1;
    }
    if (!get_root(t)) {
        if (handle_option_r(t, c, "/") < 0)
            return -1;
    }
    int status = initialize_extension(t, netlink_route_callback, NULL);
    if (UNLIKELY(status < 0))
        note(t, WARNING, INTERNAL, "netlink_route not initialized");
    return (int)cur;
}

static int post_initialize_exe(Tracee *restrict t, const Cli *restrict c,
                               size_t ac, char *const av[], size_t cur) {
    (void)t; (void)c; (void)ac; (void)av;
    return (int)cur;
}

const Cli *get_proot_cli(TALLOC_CTX *ctx) {
    (void)ctx;
    global_tool_name = proot_cli.name;
    return &proot_cli;
}
