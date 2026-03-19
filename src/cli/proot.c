#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <unistd.h>

#include "cli/cli.h"
#include "cli/note.h"
#include "extension/extension.h"
#include "extension/sysvipc/sysvipc.h"
#include "path/binding.h"
#include "attribute.h"

#include "build.h"
#include "cli/proot.h"

/* ------------------------------------------------------------------------- */
/*  Helper for creating multiple bindings                                    */
/* ------------------------------------------------------------------------- */
static void apply_bindings(Tracee *t, const char *list[], const char *base)
{
    for (int i = 0; list[i] != NULL; ++i) {
        const char *src = list[i];
        if (strcmp(src, "*path*") == 0)
            src = base;
        else
            src = expand_front_variable(t->ctx, src);
        new_binding(t, src, NULL, false);
    }
}

/* ------------------------------------------------------------------------- */
/*  Option handlers (each implemented with different internal details)       */
/* ------------------------------------------------------------------------- */

static int handle_option_r(Tracee *t, const Cli *c UNUSED, const char *val)
{
    Binding *b = new_binding(t, val, "/", true);
    return b ? 0 : -1;
}

static int handle_option_b(Tracee *t, const Cli *c UNUSED, const char *val)
{
    char *copy = talloc_strdup(t->ctx, val);
    if (!copy) {
        note(t, ERROR, INTERNAL, "out of memory");
        return -1;
    }
    char *guest = strchr(copy, ':');
    if (guest) {
        *guest = '\0';
        ++guest;
    }
    int ok = (new_binding(t, copy, guest, true) != NULL) ? 0 : -1;
    talloc_free(copy);
    return ok;
}

static int handle_option_q(Tracee *t, const Cli *c UNUSED, const char *val)
{
    /* Count tokens */
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

    new_binding(t, "/", HOST_ROOTFS, true);
    new_binding(t, "/dev/null", "/etc/ld.so.preload", false);
    return 0;
}

static int handle_option_w(Tracee *t, const Cli *c UNUSED, const char *val)
{
    t->fs->cwd = talloc_strdup(t->fs, val);
    if (!t->fs->cwd) return -1;
    talloc_set_name_const(t->fs->cwd, "cwd");
    return 0;
}

static int handle_option_k(Tracee *t, const Cli *c UNUSED, const char *val)
{
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

static int handle_option_i(Tracee *t, const Cli *c UNUSED, const char *val)
{
    void *ext = get_extension(t, fake_id0_callback);
    if (ext) {
        note(t, WARNING, USER, "multiple -i/-0/-S; using last");
        TALLOC_FREE(ext);
    }
    (void)initialize_extension(t, fake_id0_callback, val);
    return 0;
}

static int handle_option_0(Tracee *t, const Cli *c, const char *v UNUSED)
{
    return handle_option_i(t, c, "0:0");
}

static int handle_option_kill_on_exit(Tracee *t, const Cli *c UNUSED, const char *v UNUSED)
{
    t->killall_on_exit = true;
    return 0;
}

static int handle_option_v(Tracee *t, const Cli *c UNUSED, const char *val)
{
    int lvl;
    if (parse_integer_option(t, &lvl, val, "-v") < 0)
        return -1;
    t->verbose = lvl;
    global_verbose_level = lvl;
    return 0;
}

/* Embedded licenses */
extern unsigned char WEAK _binary_licenses_start;
extern unsigned char WEAK _binary_licenses_end;

static int handle_option_V(Tracee *t UNUSED, const Cli *c, const char *v UNUSED)
{
    print_version(c);
    printf("\n%s\n", c->colophon);
    fflush(stdout);
    size_t len = &_binary_licenses_end - &_binary_licenses_start;
    if (len > 0)
        write(STDOUT_FILENO, &_binary_licenses_start, len);
    exit_failure = false;
    return -1;
}

static int handle_option_h(Tracee *t, const Cli *c, const char *v UNUSED)
{
    print_usage(t, c, true);
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

static int handle_option_link2symlink(Tracee *t, const Cli *c UNUSED, const char *v UNUSED)
{
    int rc = initialize_extension(t, link2symlink_callback, NULL);
    if (rc < 0)
        note(t, WARNING, INTERNAL, "link2symlink failed");
    return 0;
}

static int handle_option_ashmem_memfd(Tracee *t, const Cli *c UNUSED, const char *v UNUSED)
{
    int rc = initialize_extension(t, ashmem_memfd_callback, NULL);
    if (rc < 0)
        note(t, WARNING, INTERNAL, "ashmem-memfd failed");
    return 0;
}

static int handle_option_sysvipc(Tracee *t, const Cli *c UNUSED, const char *v UNUSED)
{
    int rc = initialize_extension(t, sysvipc_callback, NULL);
    if (rc < 0)
        note(t, WARNING, INTERNAL, "sysvipc failed");
    return 0;
}

static int handle_option_L(Tracee *t, const Cli *c UNUSED, const char *v UNUSED)
{
    (void)initialize_extension(t, fix_symlink_size_callback, NULL);
    return 0;
}

static int handle_option_H(Tracee *t, const Cli *c UNUSED, const char *v UNUSED)
{
    (void)initialize_extension(t, hidden_files_callback, NULL);
    return 0;
}

static int handle_option_p(Tracee *t, const Cli *c UNUSED, const char *v UNUSED)
{
    (void)initialize_extension(t, port_switch_callback, NULL);
    return 0;
}

/* ------------------------------------------------------------------------- */
/*  Initialization hooks                                                     */
/* ------------------------------------------------------------------------- */

static int pre_initialize_bindings(Tracee *t, const Cli *c,
                                    size_t ac UNUSED, char *const av[] UNUSED, size_t cur)
{
    if (!t->fs->cwd) {
        if (handle_option_w(t, c, ".") < 0)
            return -1;
    }
    if (!get_root(t)) {
        if (handle_option_r(t, c, "/") < 0)
            return -1;
    }
    return (int)cur;
}

static int post_initialize_exe(Tracee *t, const Cli *c UNUSED,
                                size_t ac UNUSED, char *const av[] UNUSED, size_t cur UNUSED)
{
    if (!t->qemu)
        return 0;

    char path[PATH_MAX];
    int rc = which(t->reconf.tracee, t->reconf.paths, path, t->qemu[0]);
    if (rc < 0)
        return -1;

    if (t->reconf.tracee) {
        rc = detranslate_path(t->reconf.tracee, path, NULL);
        if (rc < 0)
            return -1;
    }

    t->qemu[0] = talloc_strdup(t->qemu, path);
    return (t->qemu[0] != NULL) ? 0 : -1;
}

/* ------------------------------------------------------------------------- */
/*  Public API                                                               */
/* ------------------------------------------------------------------------- */

const Cli *get_proot_cli(TALLOC_CTX *ctx UNUSED)
{
    global_tool_name = proot_cli.name;
    return &proot_cli;
}