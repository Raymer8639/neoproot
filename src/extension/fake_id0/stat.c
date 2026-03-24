#include <linux/limits.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>

#include "tracee/mem.h"
#include "syscall/syscall.h"
#include "syscall/sysnum.h"
#include "syscall/seccomp.h"
#include "extension/fake_id0/stat.h"
#include "extension/fake_id0/helper_functions.h"
#include "tracee/statx.h"

#ifndef USERLAND
int handle_stat_exit_end(Tracee *tracee, Config *config, Reg stat_sysarg)
{
    word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
    if (result != 0)
        return 0;

    word_t addr = peek_reg(tracee, ORIGINAL, stat_sysarg);

    assert(sizeof(uid_t) == sizeof(uint32_t));
    assert(sizeof(gid_t) == sizeof(uint32_t));

    uid_t real_uid = getuid();
    uid_t file_uid = peek_uint32(tracee, addr + offsetof_stat_uid(tracee));

    gid_t real_gid = getgid();
    gid_t file_gid = peek_uint32(tracee, addr + offsetof_stat_gid(tracee));

    if (file_uid == real_uid)
        poke_uint32(tracee, addr + offsetof_stat_uid(tracee), config->suid);

    if (file_gid == real_gid)
        poke_uint32(tracee, addr + offsetof_stat_gid(tracee), config->sgid);

    return 0;
}
#endif

#ifdef USERLAND
int handle_stat_enter_end(Tracee *tracee, Reg fd_sysarg)
{
    char link_path[64];
    snprintf(link_path, sizeof(link_path), "/proc/%d/fd/%d",
             tracee->pid, (int)peek_reg(tracee, CURRENT, fd_sysarg));

    word_t link_addr = alloc_mem(tracee, sizeof(link_path));
    word_t path_addr = alloc_mem(tracee, PATH_MAX);

    write_data(tracee, link_addr, link_path, sizeof(link_path));

    set_sysnum(tracee, PR_readlinkat);
    poke_reg(tracee, SYSARG_1, AT_FDCWD);
    poke_reg(tracee, SYSARG_2, link_addr);
    poke_reg(tracee, SYSARG_3, path_addr);
    poke_reg(tracee, SYSARG_4, PATH_MAX);

    return 0;
}

int handle_stat_exit_end(Tracee *tracee, Config *config, word_t sysnum)
{
    word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
    if (result != 0)
        return 0;

    char path[PATH_MAX];
    int ret;

    if (sysnum == PR_fstat || sysnum == PR_fstat64)
        ret = read_sysarg_path(tracee, path, SYSARG_2, CURRENT);
    else if (sysnum == PR_fstatat64 || sysnum == PR_newfstatat)
        ret = read_sysarg_path(tracee, path, SYSARG_2, MODIFIED);
    else
        ret = read_sysarg_path(tracee, path, SYSARG_1, MODIFIED);

    if (ret != 0)
        return ret;

    Reg stat_arg;
    if (sysnum == PR_fstatat64 || sysnum == PR_newfstatat)
        stat_arg = SYSARG_3;
    else
        stat_arg = SYSARG_2;

    char meta_path[PATH_MAX];
    if (get_meta_path(path, meta_path) == 0 && path_exists(meta_path) == 0) {
        mode_t mode;
        uid_t uid;
        gid_t gid;
        read_meta_file(meta_path, &mode, &uid, &gid, config);

        struct stat st;
        read_data(tracee, &st, peek_reg(tracee, ORIGINAL, stat_arg), sizeof(st));

        st.st_mode = mode | (st.st_mode & (S_IFMT | 07000));
        st.st_uid = uid;
        st.st_gid = gid;

        write_data(tracee, peek_reg(tracee, ORIGINAL, stat_arg), &st, sizeof(st));
        return 0;
    }

    word_t addr = peek_reg(tracee, ORIGINAL, stat_arg);

    assert(sizeof(uid_t) == sizeof(uint32_t));
    assert(sizeof(gid_t) == sizeof(uint32_t));

    uid_t real_uid = getuid();
    uid_t file_uid = peek_uint32(tracee, addr + offsetof_stat_uid(tracee));

    gid_t real_gid = getgid();
    gid_t file_gid = peek_uint32(tracee, addr + offsetof_stat_gid(tracee));

    if (file_uid == real_uid)
        poke_uint32(tracee, addr + offsetof_stat_uid(tracee), config->suid);

    if (file_gid == real_gid)
        poke_uint32(tracee, addr + offsetof_stat_gid(tracee), config->sgid);

    return 0;
}
#endif

int fake_id0_handle_statx_syscall(Tracee *tracee, Config *config, uintptr_t statx_state_raw)
{
    (void)tracee;
    struct statx_syscall_state *state = (struct statx_syscall_state *)statx_state_raw;

    if (state->statx_buf.stx_mask & STATX_UID) {
        if (state->statx_buf.stx_uid == getuid()) {
            state->statx_buf.stx_uid = config->suid;
            state->updated_stats = true;
        }
    }

    if (state->statx_buf.stx_mask & STATX_GID) {
        if (state->statx_buf.stx_gid == getgid()) {
            state->statx_buf.stx_gid = config->sgid;
            state->updated_stats = true;
        }
    }

    return 0;
}
