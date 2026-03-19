/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * This file is part of proot-scicat.
 *
 * Copyright (C) 2026 scicat
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <talloc.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>

#include "execve/execve.h"
#include "execve/shebang.h"
#include "execve/aoxp.h"
#include "execve/ldso.h"
#include "execve/elf.h"
#include "path/path.h"
#include "path/temp.h"
#include "path/binding.h"
#include "tracee/tracee.h"
#include "syscall/syscall.h"
#include "syscall/sysnum.h"
#include "arch.h"
#include "cli/note.h"

#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define LIKELY(x) __builtin_expect(!!(x), 1)
#define PAGE_SIZE_DEFAULT 0x1000

static TALLOC_CTX *g_loader_ctx = NULL;

static void loader_ctx_cleanup(void)
{
    if (g_loader_ctx) {
        talloc_free(g_loader_ctx);
        g_loader_ctx = NULL;
    }
}

__attribute__((constructor))
static void loader_ctx_init(void)
{
    if (!g_loader_ctx) {
        g_loader_ctx = talloc_new(NULL);
        if (g_loader_ctx)
            atexit(loader_ctx_cleanup);
    }
}

static int map_segment(LoadInfo *info, const ProgramHeader *ph)
{
    size_t n;
    word_t page_size, page_mask;
    word_t vaddr, fsz, msz, off, flags;
    word_t start, end;
    Mapping *m;

    static word_t cached_ps = 0;
    static word_t cached_pm = 0;

    if (cached_ps == 0) {
        cached_ps = sysconf(_SC_PAGE_SIZE);
        if (cached_ps <= 0)
            cached_ps = PAGE_SIZE_DEFAULT;
        cached_pm = ~(cached_ps - 1);
    }
    page_size = cached_ps;
    page_mask = cached_pm;

    if (!info->mappings)
        n = 0;
    else
        n = talloc_array_length(info->mappings);

    info->mappings = talloc_realloc(info, info->mappings, Mapping, n + 1);
    if (!info->mappings)
        return -ENOMEM;

    vaddr = IS_CLASS64(info->elf_header) ? ph->class64.p_vaddr : ph->class32.p_vaddr;
    fsz   = IS_CLASS64(info->elf_header) ? ph->class64.p_filesz : ph->class32.p_filesz;
    msz   = IS_CLASS64(info->elf_header) ? ph->class64.p_memsz : ph->class32.p_memsz;
    off   = IS_CLASS64(info->elf_header) ? ph->class64.p_offset : ph->class32.p_offset;
    flags = IS_CLASS64(info->elf_header) ? ph->class64.p_flags : ph->class32.p_flags;

    start = vaddr & page_mask;
    end   = (vaddr + fsz + page_size) & page_mask;

    m = &info->mappings[n];
    m->fd    = -1;
    m->offset = off & page_mask;
    m->addr   = start;
    m->length = end - start;
    m->flags  = MAP_PRIVATE | MAP_FIXED;
    m->prot   = 0;
    if (flags & PF_R) m->prot |= PROT_READ;
    if (flags & PF_W) m->prot |= PROT_WRITE;
    if (flags & PF_X) m->prot |= PROT_EXEC;
    m->clear_length = 0;

    if (msz > fsz) {
        size_t n2;
        word_t new_start, new_end;

        m->clear_length = end - vaddr - fsz;
        new_start = end;
        new_end   = (vaddr + msz + page_size) & page_mask;

        if (new_end <= new_start)
            return 0;

        n2 = n + 1;
        info->mappings = talloc_realloc(info, info->mappings, Mapping, n2 + 1);
        if (!info->mappings)
            return -ENOMEM;

        m = &info->mappings[n2];
        m->fd    = -1;
        m->offset = 0;
        m->addr   = new_start;
        m->length = new_end - new_start;
        m->flags  = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED;
        m->prot   = info->mappings[n].prot;
        m->clear_length = 0;
    }

    return 0;
}

int translate_and_check_exec(Tracee *tr, char host[PATH_MAX], const char *user)
{
    int ret;
    struct stat st;

    if (user[0] == '\0')
        return -ENOEXEC;

    ret = translate_path(tr, host, AT_FDCWD, user, true);
    if (ret < 0)
        return ret;

    if (access(host, F_OK | X_OK) < 0)
        return (errno == ENOENT) ? -ENOENT : -EACCES;

    if (lstat(host, &st) < 0)
        return -EPERM;

    return 0;
}

static int add_interp(Tracee *tr, int fd, LoadInfo *info, const ProgramHeader *ph)
{
    char host[PATH_MAX];
    char *user = NULL;
    size_t fsz;
    word_t off;
    int ret;

    if (info->interp)
        return -EINVAL;

    info->interp = talloc_zero(info, LoadInfo);
    if (!info->interp)
        return -ENOMEM;

    fsz = IS_CLASS64(info->elf_header) ? ph->class64.p_filesz : ph->class32.p_filesz;
    off = IS_CLASS64(info->elf_header) ? ph->class64.p_offset : ph->class32.p_offset;

    user = talloc_size(tr->ctx, fsz + 1);
    if (!user)
        return -ENOMEM;

    ret = pread(fd, user, fsz, off);
    if ((size_t)ret != fsz) {
        TALLOC_FREE(user);
        return -EIO;
    }
    user[fsz] = '\0';

    if (tr->qemu && user[0] == '/') {
        char *new_user = talloc_asprintf(tr->ctx, "%s%s", HOST_ROOTFS, user);
        if (!new_user) {
            TALLOC_FREE(user);
            return -ENOMEM;
        }
        TALLOC_FREE(user);
        user = new_user;
    }

    ret = translate_and_check_exec(tr, host, user);
    if (ret < 0) {
        TALLOC_FREE(user);
        return ret;
    }

    info->interp->host_path = talloc_strdup(info->interp, host);
    info->interp->user_path = talloc_strdup(info->interp, user);
    TALLOC_FREE(user);

    if (!info->interp->host_path || !info->interp->user_path)
        return -ENOMEM;

    return 0;
}

struct ph_iter_data {
    Tracee    *tr;
    LoadInfo  *info;
    int        fd;
};

static int ph_callback(const ElfHeader *eh, const ProgramHeader *ph, void *data)
{
    struct ph_iter_data *d = data;
    uint32_t type;
    int ret;

    type = IS_CLASS64(*eh) ? ph->class64.p_type : ph->class32.p_type;

    switch (type) {
        case PT_LOAD:
            ret = map_segment(d->info, ph);
            break;
        case PT_INTERP:
            ret = add_interp(d->tr, d->fd, d->info, ph);
            break;
        case PT_GNU_STACK:
            d->info->needs_executable_stack =
                (IS_CLASS64(*eh) ? ph->class64.p_flags : ph->class32.p_flags) & PF_X;
            ret = 0;
            break;
        default:
            ret = 0;
    }

    return ret;
}

static int extract_load_info(Tracee *tr, LoadInfo *info)
{
    int fd, ret;
    uint32_t type;
    struct ph_iter_data data;

    assert(info && info->host_path);

    fd = open_elf(info->host_path, &info->elf_header);
    if (fd < 0)
        return fd;

    type = ELF_FIELD(info->elf_header, type);
    if (type != ET_EXEC && type != ET_DYN) {
        close(fd);
        return -ENOEXEC;
    }

    data.tr   = tr;
    data.info = info;
    data.fd   = fd;

    ret = iterate_program_headers(tr, fd, &info->elf_header, ph_callback, &data);
    close(fd);
    return ret;
}

static void apply_load_base(LoadInfo *info, word_t base)
{
    size_t i, n;
    Mapping *m;

    if (!info->mappings)
        return;

    n = talloc_array_length(info->mappings);
    for (i = 0; i < n; i++) {
        m = &info->mappings[i];
        m->addr += base;
    }

    if (IS_CLASS64(info->elf_header))
        info->elf_header.class64.e_entry += base;
    else
        info->elf_header.class32.e_entry += base;
}

static void compute_load_addresses(Tracee *tr)
{
    LoadInfo *main = tr->load_info;
    LoadInfo *interp;

    if (!main || !main->mappings)
        return;

    if (IS_POSITION_INDEPENDANT(main->elf_header) && main->mappings[0].addr == 0) {
#if defined(HAS_LOADER_32BIT)
        if (IS_CLASS32(main->elf_header))
            apply_load_base(main, EXEC_PIC_ADDRESS_32);
        else
#endif
            apply_load_base(main, EXEC_PIC_ADDRESS);
    }

    interp = main->interp;
    if (!interp || !interp->mappings)
        return;

    if (IS_POSITION_INDEPENDANT(interp->elf_header) && interp->mappings[0].addr == 0) {
#if defined(HAS_LOADER_32BIT)
        if (IS_CLASS32(main->elf_header))
            apply_load_base(interp, INTERP_PIC_ADDRESS_32);
        else
#endif
            apply_load_base(interp, INTERP_PIC_ADDRESS);
    }
}

static int expand_runner(Tracee *tr, char host[PATH_MAX], char user[PATH_MAX])
{
    ArrayOfXPointers *env, *argv;
    char *arg0;
    size_t nq;
    int ret;

    ret = fetch_array_of_xpointers(tr, &env, SYSARG_3, 0);
    if (ret < 0)
        return ret;
    env->compare_xpointee = (void *)compare_xpointee_env;

    if (is_host_elf(tr, host))
        goto patch_env;

    tr->skip_proot_loader = (getenv("PROOT_USE_LOADER_FOR_QEMU") == NULL);

    ret = fetch_array_of_xpointers(tr, &argv, SYSARG_2, 0);
    if (ret < 0)
        return ret;

    ret = read_xpointee_as_string(argv, 0, &arg0);
    if (ret < 0)
        return ret;

    nq = tr->qemu ? talloc_array_length(tr->qemu) - 1 : 0;
    ret = resize_array_of_xpointers(argv, 1, nq + 2);
    if (ret < 0) {
        TALLOC_FREE(arg0);
        return ret;
    }

    for (size_t i = 0; i < nq; i++) {
        ret = write_xpointee(argv, i, tr->qemu[i]);
        if (ret < 0) {
            TALLOC_FREE(arg0);
            return ret;
        }
    }

    ret = write_xpointees(argv, nq, 3, "-0", arg0, user);
    TALLOC_FREE(arg0);
    if (ret < 0)
        return ret;

    ret = ldso_env_passthru(tr, env, argv, "-E", "-U", (int)nq);
    if (ret < 0)
        return ret;

    ret = push_array_of_xpointers(argv, SYSARG_2);
    if (ret < 0)
        return ret;

    snprintf(host, PATH_MAX, "%s", tr->qemu[0]);
    if (tr->skip_proot_loader)
        snprintf(user, PATH_MAX, "%s", host);
    else
        snprintf(user, PATH_MAX, "%s%s", HOST_ROOTFS, host);

patch_env:
    ret = rebuild_host_ldso_paths(tr, host, env);
    if (ret < 0)
        return ret;

    return push_array_of_xpointers(env, SYSARG_3);
}

#if !defined(PROOT_UNBUNDLE_LOADER)
extern unsigned char _binary_loader_exe_start;
extern unsigned char _binary_loader_exe_end;
extern unsigned char WEAK _binary_loader_m32_exe_start;
extern unsigned char WEAK _binary_loader_m32_exe_end;

static char *extract_loader(bool m32)
{
    char path[PATH_MAX];
    void *start;
    size_t len;
    int fd;
    FILE *f;
    char *out = NULL;
    ssize_t w;

    if (!g_loader_ctx)
        return NULL;

    f = open_temp_file(NULL, "proot-loader");
    if (!f)
        return NULL;

    fd = fileno(f);

    if (m32) {
        start = &_binary_loader_m32_exe_start;
        len   = &_binary_loader_m32_exe_end - &_binary_loader_m32_exe_start;
    } else {
        start = &_binary_loader_exe_start;
        len   = &_binary_loader_exe_end - &_binary_loader_exe_start;
    }

    w = write(fd, start, len);
    if ((size_t)w != len)
        goto out;

    fchmod(fd, S_IRUSR | S_IXUSR);
    if (readlink_proc_pid_fd(getpid(), fd, path) < 0)
        goto out;

    if (access(path, X_OK) < 0)
        goto out;

    out = talloc_strdup(g_loader_ctx, path);

out:
    fclose(f);
    return out;
}
#endif

static const char *get_loader_path(const Tracee *tr)
{
    (void)tr; // 🔥 干掉最后一个警告

#if defined(PROOT_UNBUNDLE_LOADER)
    const char *env;
#if defined(HAS_LOADER_32BIT)
    if (IS_CLASS32(tr->load_info->elf_header)) {
        env = getenv("PROOT_LOADER_32");
        if (env && access(env, X_OK) == 0)
            return env;
        return PROOT_UNBUNDLE_LOADER "/loader32";
    }
#endif
    env = getenv("PROOT_LOADER");
    if (env && access(env, X_OK) == 0)
        return env;
    return PROOT_UNBUNDLE_LOADER "/loader";
#else
    static char *loader = NULL;
#if defined(HAS_LOADER_32BIT)
    static char *loader32 = NULL;
#endif

    if (!g_loader_ctx)
        return NULL;

#if defined(HAS_LOADER_32BIT)
    if (IS_CLASS32(tr->load_info->elf_header)) {
        if (!loader32) {
            const char *env = getenv("PROOT_LOADER_32");
            if (env && access(env, X_OK) == 0)
                loader32 = talloc_strdup(g_loader_ctx, env);
            else
                loader32 = extract_loader(true);
        }
        return loader32;
    }
#endif

    if (!loader) {
        const char *env = getenv("PROOT_LOADER");
        if (env && access(env, X_OK) == 0)
            loader = talloc_strdup(g_loader_ctx, env);
        else
            loader = extract_loader(false);
    }
    return loader;
#endif
}

int translate_execve_enter(Tracee *tr)
{
    char user[PATH_MAX], host[PATH_MAX], new_exe[PATH_MAX];
    char *raw = NULL;
    const char *loader;
    int ret;

    if (IS_NOTIFICATION_PTRACED_LOAD_DONE(tr)) {
        tr->as_ptracee.ignore_loader_syscalls = false;
        set_sysnum(tr, PR_void);
        return 0;
    }

    ret = get_sysarg_path(tr, user, SYSARG_1);
    if (ret < 0)
        return ret;

    raw = talloc_strdup(tr->ctx, user);
    if (!raw)
        return -ENOMEM;

    ret = expand_shebang(tr, host, user);
    if (ret < 0) {
        TALLOC_FREE(raw);
        return (ret == -EISDIR) ? -EACCES : ret;
    }

    if (ret == 0 && !tr->qemu) {
        TALLOC_FREE(raw);
        raw = NULL;
    }

    talloc_unlink(tr, tr->host_exe);
    tr->host_exe = talloc_strdup(tr, host);

    snprintf(new_exe, PATH_MAX, "%s", host);
    detranslate_path(tr, new_exe, NULL);
    talloc_unlink(tr, tr->new_exe);
    tr->new_exe = talloc_strdup(tr, new_exe);

    tr->skip_proot_loader = false;
    if (tr->qemu) {
        ret = expand_runner(tr, host, user);
        if (ret < 0) {
            TALLOC_FREE(raw);
            return ret;
        }
    }

    if (tr->skip_proot_loader) {
        TALLOC_FREE(raw);
        tr->heap->disabled = true;
        return set_sysarg_path(tr, host, SYSARG_1);
    }

    talloc_unlink(tr, tr->load_info);
    tr->load_info = talloc_zero(tr, LoadInfo);
    if (!tr->load_info) {
        TALLOC_FREE(raw);
        return -ENOMEM;
    }

    tr->load_info->host_path = talloc_strdup(tr->load_info, host);
    tr->load_info->user_path = talloc_strdup(tr->load_info, user);
    if (!tr->load_info->host_path || !tr->load_info->user_path) {
        TALLOC_FREE(raw);
        return -ENOMEM;
    }

    if (raw) {
        tr->load_info->raw_path = talloc_reparent(tr->ctx, tr->load_info, raw);
        raw = NULL;
    } else {
        tr->load_info->raw_path = talloc_strdup(tr->load_info, tr->load_info->user_path);
    }

    if (!tr->load_info->raw_path)
        return -ENOMEM;

    ret = extract_load_info(tr, tr->load_info);
    if (ret < 0)
        return ret;

    if (tr->load_info->interp) {
        ret = extract_load_info(tr, tr->load_info->interp);
        if (ret < 0)
            return ret;
        TALLOC_FREE(tr->load_info->interp->interp);
    }

    compute_load_addresses(tr);

    loader = get_loader_path(tr);
    if (!loader)
        return -ENOENT;

    ret = set_sysarg_path(tr, loader, SYSARG_1);
    tr->as_ptracee.ignore_loader_syscalls = true;
    return ret;
}
