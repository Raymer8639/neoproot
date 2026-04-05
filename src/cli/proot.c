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

// 纯Bionic环境：直接使用系统原生优化的字符串函数（aarch64平台手写汇编优化，性能最优）
#define STRCMP(a, b) strcmp(a, b)

// 彩蛋函数声明
void egg_mark_h(void);
void egg_mark_v(void);
void egg_try(void);
void egg_show_final(void);

static void apply_bindings(Tracee *t, const char *list[], const char *base)
{
    for (int i = 0; list[i] != NULL; ++i) {
        const char *src = list[i];
        if (STRCMP(src, "*path*") == 0)
            src = base;
        else
            src = expand_front_variable(t->ctx, src);
        new_binding(t, src, NULL, false);
    }
}

static int handle_option_r(Tracee *t, const Cli *c, const char *val)
{
    (void)c;
    Binding *b = new_binding(t, val, "/", true);
    return b ? 0 : -1;
}

static int handle_option_b(Tracee *t, const Cli *c, const char *val)
{
    (void)c;
    char *copy = talloc_strdup(t->ctx, val);
    if (!copy) {
        note(t, ERROR, INTERNAL, "out of memory");
        return -1;
    }

    char *guest = strchr(copy, ':');
    if (guest) {
        *guest = '\0';
        guest++;
    }

    int ret = (new_binding(t, copy, guest, true) != NULL) ? 0 : -1;
    talloc_free(copy);
    return ret;
}

static int handle_option_q(Tracee *t, const Cli *c, const char *val)
{
    (void)c;
    int cnt = 0;
    const char *p = val;
    while (*p) {
        while (*p == ' ') ++p;
        if (!*p) break;
        ++cnt;
        while (*p && *p != ' ') ++p;
    }

    if (cnt == 0) {
        note(t, ERROR, USER, "QEMU command cannot be empty");
        return -1;
    }

    t->qemu = talloc_zero_array(t, char *, cnt + 1);
    if (!t->qemu) return -1;
    talloc_set_name_const(t->qemu, "qemu");

    int idx = 0;
    p = val;
    while (*p) {
        while (*p == ' ') ++p;
        if (!*p) break;
        const char *start = p;
        while (*p && *p != ' ') ++p;
        size_t len = p - start;
        t->qemu[idx] = talloc_strndup(t->qemu, start, len);
        if (!t->qemu[idx]) return -1;
        ++idx;
    }
    assert(idx == cnt);
    t->qemu[idx] = NULL;

    if (!new_binding(t, "/", HOST_ROOTFS, true))
        note(t, WARNING, INTERNAL, "failed to bind host rootfs for QEMU");
    if (!new_binding(t, "/dev/null", "/etc/ld.so.preload", false))
        note(t, WARNING, INTERNAL, "failed to bind ld.so.preload");

    return 0;
}

static int handle_option_w(Tracee *t, const Cli *c, const char *val)
{
    (void)c;
    TALLOC_FREE(t->fs->cwd);
    t->fs->cwd = talloc_strdup(t->fs, val);
    if (!t->fs->cwd) return -1;
    talloc_set_name_const(t->fs->cwd, "cwd");
    return 0;
}

static int handle_option_k(Tracee *t, const Cli *c, const char *val)
{
    (void)c;
    void *ext = get_extension(t, kompat_callback);
    if (ext) {
        note(t, WARNING, USER, "multiple -k options; using last");
        TALLOC_FREE(ext);
    }
    int rc = initialize_extension(t, kompat_callback, val);
    if (rc < 0)
        note(t, WARNING, INTERNAL, "kompat init failed for '%s'", val);
    return 0;
}

static int handle_option_i(Tracee *t, const Cli *c, const char *val)
{
    (void)c;
    void *ext = get_extension(t, fake_id0_callback);
    if (ext) {
        note(t, WARNING, USER, "multiple -i/-0/-S; using last");
        TALLOC_FREE(ext);
    }
    (void)initialize_extension(t, fake_id0_callback, val);
    return 0;
}

static int handle_option_0(Tracee *t, const Cli *c, const char *v)
{
    return handle_option_i(t, c, "0:0");
}

static int handle_option_kill_on_exit(Tracee *t, const Cli *c, const char *v)
{
    (void)c;
    (void)v;
    t->killall_on_exit = true;
    return 0;
}

static int handle_option_v(Tracee *t, const Cli *c, const char *val)
{
    (void)c;
    int lvl;
    if (parse_integer_option(t, &lvl, val, "-v") < 0)
        return -1;
    t->verbose = lvl;
    global_verbose_level = lvl;
    return 0;
}

static int handle_option_V(Tracee *t, const Cli *c, const char *v)
{
    (void)t;
    (void)v;

    egg_mark_v();
    egg_try();

    print_version(c);
    printf("\n%s\n", c->colophon);
    egg_show_final();
    fflush(stdout);
    exit_failure = false;
    return -1;
}

static int handle_option_h(Tracee *t, const Cli *c, const char *v)
{
    (void)v;

    egg_mark_h();
    egg_try();

    print_usage(t, c, true);
    egg_show_final();
    exit_failure = false;
    return -1;
}

static int handle_option_R(Tracee *t, const Cli *c, const char *val)
{
    int rc = handle_option_r(t, c, val);
    if (rc < 0) return rc;
    apply_bindings(t, recommended_bindings, val);
    return 0;
}

static int handle_option_S(Tracee *t, const Cli *c, const char *val)
{
    int rc = handle_option_0(t, c, val);
    if (rc < 0) return rc;
    rc = handle_option_r(t, c, val);
    if (rc < 0) return rc;
    apply_bindings(t, recommended_su_bindings, val);
    return 0;
}

static int handle_option_link2symlink(Tracee *t, const Cli *c, const char *v)
{
    (void)c;
    (void)v;
    int rc = initialize_extension(t, link2symlink_callback, NULL);
    if (rc < 0)
        note(t, WARNING, INTERNAL, "link2symlink init failed");
    return 0;
}

static int handle_option_ashmem_memfd(Tracee *t, const Cli *c, const char *v)
{
    (void)c;
    (void)v;
    int rc = initialize_extension(t, ashmem_memfd_callback, NULL);
    if (rc < 0)
        note(t, WARNING, INTERNAL, "ashmem-memfd init failed");
    return 0;
}

static int handle_option_sysvipc(Tracee *t, const Cli *c, const char *v)
{
    (void)c;
    (void)v;
    int rc = initialize_extension(t, sysvipc_callback, NULL);
    if (rc < 0)
        note(t, WARNING, INTERNAL, "sysvipc init failed");
    return 0;
}

static int handle_option_L(Tracee *t, const Cli *c, const char *v)
{
    (void)c;
    (void)v;
    (void)initialize_extension(t, fix_symlink_size_callback, NULL);
    return 0;
}

static int handle_option_H(Tracee *t, const Cli *c, const char *v)
{
    (void)c;
    (void)v;
    (void)initialize_extension(t, hidden_files_callback, NULL);
    return 0;
}

static int handle_option_p(Tracee *t, const Cli *c, const char *v)
{
    (void)c;
    (void)v;
    (void)initialize_extension(t, port_switch_callback, NULL);
    return 0;
}

static int pre_initialize_bindings(Tracee *t, const Cli *c,
                                    size_t ac, char *const av[], size_t cur)
{
    (void)ac;
    (void)av;
    if (!t->fs->cwd) {
        if (handle_option_w(t, c, ".") < 0)
            return -1;
    }
    if (!get_root(t)) {
        if (handle_option_r(t, c, "/") < 0)
            return -1;
    }

    // ==================== netlink_route 自动强制加载（无需环境变量）====================
    int status = initialize_extension(t, netlink_route_callback, NULL);
    if (status < 0)
        note(t, WARNING, INTERNAL, "netlink_route not initialized");

    return (int)cur;
}

static int post_initialize_exe(Tracee *t, const Cli *c,
                                size_t ac, char *const av[], size_t cur)
{
    (void)c;
    (void)ac;
    (void)av;
    if (!t->qemu)
        return (int)cur;

    char path[PATH_MAX];
    int rc = which(t->reconf.tracee, t->reconf.paths, path, t->qemu[0]);
    if (rc < 0)
        return -1;

    if (t->reconf.tracee) {
        rc = detranslate_path(t->reconf.tracee, path, NULL);
        if (rc < 0)
            return -1;
    }

    char *new_path = talloc_strdup(t->qemu, path);
    if (!new_path)
        return -1;
    TALLOC_FREE(t->qemu[0]);
    t->qemu[0] = new_path;

    return (int)cur;
}

const Cli *get_proot_cli(TALLOC_CTX *ctx)
{
    (void)ctx;
    global_tool_name = proot_cli.name;
    return &proot_cli;
}
