#include <assert.h>
#include <stdint.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <linux/audit.h>
#include <string.h>
#include <stdlib.h>
#include <linux/auxvec.h>
#include <sys/socket.h>
#include <linux/net.h>

#include "extension/extension.h"
#include "syscall/syscall.h"
#include "syscall/sysnum.h"
#include "syscall/seccomp.h"
#include "syscall/chain.h"
#include "execve/execve.h"
#include "tracee/tracee.h"
#include "tracee/abi.h"
#include "tracee/mem.h"
#include "execve/auxv.h"
#include "path/binding.h"
#include "path/f2fs-bug.h"
#include "extension/fake_id0/helper_functions.h"
#include "arch.h"

#include "extension/fake_id0/chown.h"
#include "extension/fake_id0/chroot.h"
#include "extension/fake_id0/getsockopt.h"
#include "extension/fake_id0/sendmsg.h"
#include "extension/fake_id0/socket.h"
#include "extension/fake_id0/stat.h"

#ifdef USERLAND
#include "extension/fake_id0/open.h"
#include "extension/fake_id0/unlink.h"
#include "extension/fake_id0/rename.h"
#include "extension/fake_id0/chmod.h"
#include "extension/fake_id0/utimensat.h"
#include "extension/fake_id0/access.h"
#include "extension/fake_id0/exec.h"
#include "extension/fake_id0/link.h"
#include "extension/fake_id0/symlink.h"
#include "extension/fake_id0/mk.h"
#include "extension/fake_id0/helper_functions.h"
#endif

#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define ALWAYS_INLINE __attribute__((always_inline, flatten))
#define HOT __attribute__((hot))

#define POKE_MEM_ID(sysarg, field) do {                                 \
    poke_uint32(tracee, peek_reg(tracee, ORIGINAL, sysarg), config->field); \
    if (UNLIKELY(errno != 0)) return -errno;                            \
} while(0)

#define SETXID(id, version) do {                                        \
    id ## _t id_val = peek_reg(tracee, version, SYSARG_1);              \
    bool allowed = false;                                               \
    allowed = (config->euid == 0                                        \
        || id_val == config->r ## id                                    \
        || id_val == config->e ## id                                    \
        || id_val == config->s ## id);                                  \
    if (UNLIKELY(!allowed)) {                                           \
        if (id_val == gete ## id() && config->e ## id == gete ## id())  \
            allowed = true;                                             \
        else if (config->e ## id != 0 && id_val == get ## id())         \
            allowed = true;                                             \
    }                                                                   \
    if (UNLIKELY(!allowed)) return -EPERM;                              \
    if (LIKELY(config->euid == 0)) {                                    \
        config->r ## id = id_val;                                       \
        config->s ## id = id_val;                                       \
    }                                                                   \
    config->e ## id  = id_val;                                          \
    config->fs ## id = id_val;                                          \
    poke_reg(tracee, SYSARG_RESULT, 0);                                 \
    return 0;                                                           \
} while(0)

#define UNSET_ID(id) ((id) == (uid_t)-1)

#define UNCHANGED_ID(id, cfg_id) (UNSET_ID(id) || (id) == (cfg_id))

#define SETREXID(id, version) do {                                      \
    id ## _t r ## id = peek_reg(tracee, version, SYSARG_1);             \
    id ## _t e ## id = peek_reg(tracee, version, SYSARG_2);             \
    bool allowed = false;                                               \
    allowed = (config->euid == 0                                        \
        || (UNCHANGED_ID(e ## id, config->e ## id) && UNCHANGED_ID(r ## id, config->r ## id)) \
        || (r ## id == config->e ## id && (e ## id == config->r ## id || UNCHANGED_ID(e ## id, config->e ## id))) \
        || (e ## id == config->r ## id && (r ## id == config->e ## id || UNCHANGED_ID(r ## id, config->r ## id))) \
        || (e ## id == config->s ## id && UNCHANGED_ID(r ## id, config->r ## id))); \
    if (UNLIKELY(!allowed)) return -EPERM;                              \
    if (!UNSET_ID(e ## id)) {                                           \
        if (e ## id != config->r ## id)                                 \
            config->s ## id = e ## id;                                  \
        config->e ## id  = e ## id;                                     \
        config->fs ## id = e ## id;                                     \
    }                                                                   \
    if (!UNSET_ID(r ## id)) {                                           \
        if (!UNSET_ID(e ## id)) config->s ## id = e ## id;              \
        config->r ## id = r ## id;                                      \
    }                                                                   \
    poke_reg(tracee, SYSARG_RESULT, 0);                                 \
    return 0;                                                           \
} while(0)

#define EQUALS_ANY_ID(var, type, cfg) (var == cfg->r ## type ## id      \
    || var == cfg->e ## type ## id                                      \
    || var == cfg->s ## type ## id)

#define SETRESXID(type, version) do {                                   \
    type ## id_t r ## type ## id = peek_reg(tracee, version, SYSARG_1); \
    type ## id_t e ## type ## id = peek_reg(tracee, version, SYSARG_2); \
    type ## id_t s ## type ## id = peek_reg(tracee, version, SYSARG_3); \
    bool allowed = false;                                               \
    allowed = (config->euid == 0                                        \
        || ((UNSET_ID(r ## type ## id) || EQUALS_ANY_ID(r ## type ## id, type, config)) \
         && (UNSET_ID(e ## type ## id) || EQUALS_ANY_ID(e ## type ## id, type, config)) \
         && (UNSET_ID(s ## type ## id) || EQUALS_ANY_ID(s ## type ## id, type, config)))); \
    if (UNLIKELY(!allowed)) return -EPERM;                              \
    if (!UNSET_ID(r ## type ## id)) config->r ## type ## id = r ## type ## id; \
    if (!UNSET_ID(e ## type ## id)) {                                   \
        config->e ## type ## id  = e ## type ## id;                     \
        config->fs ## type ## id = e ## type ## id;                     \
    }                                                                   \
    if (!UNSET_ID(s ## type ## id)) config->s ## type ## id = s ## type ## id; \
    poke_reg(tracee, SYSARG_RESULT, 0);                                 \
    return 0;                                                           \
} while(0)

#define SETFSXID(type) do {                                             \
    uid_t fs ## type ## id = peek_reg(tracee, ORIGINAL, SYSARG_1);      \
    uid_t old_fs ## type ## id = config->fs ## type ## id;              \
    bool allowed = false;                                               \
    allowed = (config->euid == 0                                        \
        || fs ## type ## id == config->fs ## type ## id                 \
        || EQUALS_ANY_ID(fs ## type ## id, type, config));              \
    if (LIKELY(allowed)) config->fs ## type ## id = fs ## type ## id;   \
    poke_reg(tracee, SYSARG_RESULT, old_fs ## type ## id);              \
    return 0;                                                           \
} while(0)

typedef struct {
    char *path;
    mode_t mode;
} ModifiedNode;

static FilteredSysnum filtered_sysnums[] = {
#ifdef USERLAND
    { PR_access,        FILTER_SYSEXIT },
    { PR_creat,         FILTER_SYSEXIT },
    { PR_faccessat,     FILTER_SYSEXIT },
    { PR_faccessat2,    FILTER_SYSEXIT },
    { PR_link,          FILTER_SYSEXIT },
    { PR_linkat,        FILTER_SYSEXIT },
    { PR_mkdir,         FILTER_SYSEXIT },
    { PR_mkdirat,       FILTER_SYSEXIT },
    { PR_symlink,       FILTER_SYSEXIT },
    { PR_symlinkat,     FILTER_SYSEXIT },
    { PR_umask,         FILTER_SYSEXIT },
    { PR_unlink,        FILTER_SYSEXIT },
    { PR_unlinkat,      FILTER_SYSEXIT },
    { PR_utimensat,     FILTER_SYSEXIT },
#endif
    { PR_capset,        FILTER_SYSEXIT },
    { PR_chmod,         FILTER_SYSEXIT },
    { PR_chown,         FILTER_SYSEXIT },
    { PR_chown32,       FILTER_SYSEXIT },
    { PR_chroot,        FILTER_SYSEXIT },
    { PR_execve,        FILTER_SYSEXIT },
    { PR_fchmod,        FILTER_SYSEXIT },
    { PR_fchmodat,      FILTER_SYSEXIT },
    { PR_fchown,        FILTER_SYSEXIT },
    { PR_fchown32,      FILTER_SYSEXIT },
    { PR_fchownat,      FILTER_SYSEXIT },
    { PR_fstat,         FILTER_SYSEXIT },
    { PR_fstat64,       FILTER_SYSEXIT },
    { PR_fstatat64,     FILTER_SYSEXIT },
    { PR_getegid,       FILTER_SYSEXIT },
    { PR_getegid32,     FILTER_SYSEXIT },
    { PR_geteuid,       FILTER_SYSEXIT },
    { PR_geteuid32,     FILTER_SYSEXIT },
    { PR_getgid,        FILTER_SYSEXIT },
    { PR_getgid32,      FILTER_SYSEXIT },
    { PR_getgroups,     FILTER_SYSEXIT },
    { PR_getgroups32,   FILTER_SYSEXIT },
    { PR_getresgid,     FILTER_SYSEXIT },
    { PR_getresgid32,   FILTER_SYSEXIT },
    { PR_getresuid,     FILTER_SYSEXIT },
    { PR_getresuid32,   FILTER_SYSEXIT },
    { PR_getuid,        FILTER_SYSEXIT },
    { PR_getuid32,      FILTER_SYSEXIT },
    { PR_getsockopt,    FILTER_SYSEXIT },
    { PR_lchown,        FILTER_SYSEXIT },
    { PR_lchown32,      FILTER_SYSEXIT },
    { PR_lstat,         FILTER_SYSEXIT },
    { PR_lstat64,       FILTER_SYSEXIT },
    { PR_mknod,         FILTER_SYSEXIT },
    { PR_mknodat,       FILTER_SYSEXIT },
    { PR_newfstatat,    FILTER_SYSEXIT },
    { PR_oldlstat,      FILTER_SYSEXIT },
    { PR_oldstat,       FILTER_SYSEXIT },
    { PR_sendmsg,       0 },
    { PR_setfsgid,      FILTER_SYSEXIT },
    { PR_setfsgid32,    FILTER_SYSEXIT },
    { PR_setfsuid,      FILTER_SYSEXIT },
    { PR_setfsuid32,    FILTER_SYSEXIT },
    { PR_setgid,        FILTER_SYSEXIT },
    { PR_setgid32,      FILTER_SYSEXIT },
    { PR_setgroups,     FILTER_SYSEXIT },
    { PR_setgroups32,   FILTER_SYSEXIT },
    { PR_setregid,      FILTER_SYSEXIT },
    { PR_setregid32,    FILTER_SYSEXIT },
    { PR_setreuid,      FILTER_SYSEXIT },
    { PR_setreuid32,    FILTER_SYSEXIT },
    { PR_setresgid,     FILTER_SYSEXIT },
    { PR_setresgid32,   FILTER_SYSEXIT },
    { PR_setresuid,     FILTER_SYSEXIT },
    { PR_setresuid32,   FILTER_SYSEXIT },
    { PR_setuid,        FILTER_SYSEXIT },
    { PR_setuid32,      FILTER_SYSEXIT },
    { PR_setxattr,      FILTER_SYSEXIT },
    { PR_setdomainname, FILTER_SYSEXIT },
    { PR_sethostname,   FILTER_SYSEXIT },
    { PR_socket,        FILTER_SYSEXIT },
    { PR_lsetxattr,     FILTER_SYSEXIT },
    { PR_fsetxattr,     FILTER_SYSEXIT },
    { PR_stat,          FILTER_SYSEXIT },
    { PR_stat64,        FILTER_SYSEXIT },
    { PR_statfs,        FILTER_SYSEXIT },
    { PR_statfs64,      FILTER_SYSEXIT },
    FILTERED_SYSNUM_END,
};

static ALWAYS_INLINE int restore_mode(ModifiedNode *node) {
    if (LIKELY(node && node->path))
        (void)chmod(node->path, node->mode);
    return 0;
}

static ALWAYS_INLINE void override_permissions(const Tracee *tracee, const char *path, bool is_final) {
    if (UNLIKELY(!tracee || !path || should_skip_file_access_due_to_f2fs_bug(tracee, path)))
        return;
    ModifiedNode *node = NULL;
    struct stat perms;
    if (UNLIKELY(stat(path, &perms) < 0)) return;
    mode_t new_mode = perms.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO);
    new_mode |= (S_IRUSR | S_IWUSR);
    if (S_ISDIR(perms.st_mode)) new_mode |= S_IXUSR;
    if (LIKELY(new_mode == (perms.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO)))) return;
    node = talloc_zero(tracee->ctx, ModifiedNode);
    if (UNLIKELY(!node)) return;
    if (!is_final) {
        node->mode = perms.st_mode;
    } else {
        switch (get_sysnum((Tracee *)tracee, ORIGINAL)) {
        case PR_chmod:   node->mode = peek_reg((Tracee *)tracee, ORIGINAL, SYSARG_2); break;
        case PR_fchmodat: node->mode = peek_reg((Tracee *)tracee, ORIGINAL, SYSARG_3); break;
        case PR_fstatat64:
        case PR_lstat:
        case PR_lstat64:
        case PR_newfstatat:
        case PR_oldlstat:
        case PR_oldstat:
        case PR_stat:
        case PR_stat64:
        case PR_statfs:
        case PR_statfs64:
            TALLOC_FREE(node); return;
        default: node->mode = perms.st_mode; break;
        }
    }
    node->path = talloc_strdup(node, path);
    if (UNLIKELY(!node->path)) { TALLOC_FREE(node); return; }
    talloc_set_destructor(node, restore_mode);
    (void)chmod(path, new_mode);
}

static ALWAYS_INLINE int adjust_elf_auxv(Tracee *tracee, Config *config) {
    if (UNLIKELY(!tracee || !config)) return -EINVAL;
    word_t vectors_address = get_elf_aux_vectors_address(tracee);
    if (UNLIKELY(vectors_address == 0)) return 0;
    ElfAuxVector *vectors = fetch_elf_aux_vectors(tracee, vectors_address);
    if (UNLIKELY(!vectors)) return 0;
    for (ElfAuxVector *v = vectors; v->type != AT_NULL; ++v) {
        switch (v->type) {
        case AT_UID:  v->value = config->ruid; break;
        case AT_EUID: v->value = config->euid; break;
        case AT_GID:  v->value = config->rgid; break;
        case AT_EGID: v->value = config->egid; break;
        default: break;
        }
    }
    push_elf_aux_vectors(tracee, vectors, vectors_address);
    return 0;
}

static ALWAYS_INLINE int handle_perm_err_exit_end(Tracee *tracee, Config *config, bool even_if_not_root) {
    if (UNLIKELY(!tracee || !config)) return -EINVAL;
    word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
#ifdef USERLAND
    if (get_sysnum(tracee, CURRENT) == PR_getuid && (int)result != 0)
        poke_reg(tracee, SYSARG_RESULT, 0);
    if (get_sysnum(tracee, CURRENT) == PR_void && (int)result != 0)
        poke_reg(tracee, SYSARG_RESULT, 0);
#endif
    if (LIKELY((int)result != -EPERM && (int)result != -EACCES)) return 0;
    if (even_if_not_root || config->euid == 0)
        poke_reg(tracee, SYSARG_RESULT, 0);
    return 0;
}

static ALWAYS_INLINE int handle_getresuid_exit_end(Tracee *tracee, Config *config) {
    POKE_MEM_ID(SYSARG_1, ruid);
    POKE_MEM_ID(SYSARG_2, euid);
    POKE_MEM_ID(SYSARG_3, suid);
    return 0;
}

static ALWAYS_INLINE int handle_getresgid_exit_end(Tracee *tracee, Config *config) {
    POKE_MEM_ID(SYSARG_1, rgid);
    POKE_MEM_ID(SYSARG_2, egid);
    POKE_MEM_ID(SYSARG_3, sgid);
    return 0;
}

static HOT int handle_sysenter_end(Tracee *restrict tracee, Config *restrict config) {
    if (UNLIKELY(!tracee || !config)) return -EINVAL;
    word_t sysnum = get_sysnum(tracee, ORIGINAL);
    Reg uid_sysarg = SYSARG_2, gid_sysarg = SYSARG_3;
    switch (sysnum) {
#ifdef USERLAND
    case PR_openat: return handle_open_enter_end(tracee, SYSARG_1, SYSARG_2, SYSARG_3, SYSARG_4, config);
    case PR_open:   return handle_open_enter_end(tracee, IGNORE_SYSARG, SYSARG_1, SYSARG_2, SYSARG_3, config);
    case PR_creat:  return handle_open_enter_end(tracee, IGNORE_SYSARG, SYSARG_1, IGNORE_SYSARG, SYSARG_2, config);
    case PR_mkdirat: return handle_mk_enter_end(tracee, SYSARG_1, SYSARG_2, SYSARG_3, config);
    case PR_mkdir:   return handle_mk_enter_end(tracee, IGNORE_SYSARG, SYSARG_1, SYSARG_2, config);
    case PR_mknodat: return handle_mk_enter_end(tracee, SYSARG_1, SYSARG_2, SYSARG_3, config);
    case PR_mknod:   return handle_mk_enter_end(tracee, IGNORE_SYSARG, SYSARG_1, SYSARG_2, config);
    case PR_unlinkat: return handle_unlink_enter_end(tracee, SYSARG_1, SYSARG_2, config);
    case PR_rmdir:
    case PR_unlink:   return handle_unlink_enter_end(tracee, IGNORE_SYSARG, SYSARG_1, config);
    case PR_renameat: return handle_rename_enter_end(tracee, SYSARG_1, SYSARG_2, SYSARG_3, SYSARG_4, config);
    case PR_rename:   return handle_rename_enter_end(tracee, IGNORE_SYSARG, SYSARG_1, IGNORE_SYSARG, SYSARG_2, config);
    case PR_chmod:    return handle_chmod_enter_end(tracee, SYSARG_1, SYSARG_2, IGNORE_SYSARG, IGNORE_SYSARG, config);
    case PR_fchmod:   return handle_chmod_enter_end(tracee, IGNORE_SYSARG, SYSARG_2, SYSARG_1, IGNORE_SYSARG, config);
    case PR_fchmodat: return handle_chmod_enter_end(tracee, SYSARG_2, SYSARG_3, IGNORE_SYSARG, SYSARG_1, config);
    case PR_chown:
    case PR_chown32:
    case PR_lchown:
    case PR_lchown32: return handle_chown_enter_end(tracee, SYSARG_1, SYSARG_2, SYSARG_3, IGNORE_SYSARG, IGNORE_SYSARG, config);
    case PR_fchown:
    case PR_fchown32: return handle_chown_enter_end(tracee, IGNORE_SYSARG, SYSARG_2, SYSARG_3, SYSARG_1, IGNORE_SYSARG, config);
    case PR_fchownat: return handle_chown_enter_end(tracee, SYSARG_2, SYSARG_3, SYSARG_4, IGNORE_SYSARG, SYSARG_1, config);
    case PR_utimensat: return handle_utimensat_enter_end(tracee, SYSARG_1, SYSARG_2, SYSARG_3, config);
    case PR_access:    return handle_access_enter_end(tracee, SYSARG_1, SYSARG_2, IGNORE_SYSARG, config);
    case PR_faccessat:
    case PR_faccessat2: return handle_access_enter_end(tracee, SYSARG_2, SYSARG_3, SYSARG_1, config);
    case PR_execve:    return handle_exec_enter_end(tracee, SYSARG_1, config);
    case PR_link:      return handle_link_enter_end(tracee, IGNORE_SYSARG, SYSARG_1, IGNORE_SYSARG, SYSARG_2, config);
    case PR_linkat:    return handle_link_enter_end(tracee, SYSARG_1, SYSARG_2, SYSARG_3, SYSARG_4, config);
    case PR_symlink:   return handle_symlink_enter_end(tracee, SYSARG_1, IGNORE_SYSARG, SYSARG_2, config);
    case PR_symlinkat: return handle_symlink_enter_end(tracee, SYSARG_1, SYSARG_2, SYSARG_3, config);
    case PR_fstat:
    case PR_fstat64:   return handle_stat_enter_end(tracee, SYSARG_1);
#endif
    case PR_sendmsg:
    case PR_socketcall: return handle_sendmsg_enter_end(tracee, sysnum);
    case PR_setuid:
    case PR_setuid32:
    case PR_setgid:
    case PR_setgid32:
    case PR_setreuid:
    case PR_setreuid32:
    case PR_setregid:
    case PR_setregid32:
    case PR_setresuid:
    case PR_setresuid32:
    case PR_setresgid:
    case PR_setresgid32:
    case PR_setfsuid:
    case PR_setfsuid32:
    case PR_setfsgid:
    case PR_setfsgid32:
#ifdef USERLAND
    case PR_umask:
#endif
        set_sysnum(tracee, PR_void);
        return 0;
#ifndef USERLAND
    case PR_fchownat: uid_sysarg = SYSARG_3; gid_sysarg = SYSARG_4;
    case PR_chown:
    case PR_chown32:
    case PR_lchown:
    case PR_lchown32:
    case PR_fchown:
    case PR_fchown32:
        return handle_chown_enter_end(tracee, config, uid_sysarg, gid_sysarg);
#endif
    case PR_setgroups:
    case PR_setgroups32:
    case PR_getgroups:
    case PR_getgroups32:
#ifdef USERLAND
        if (sysnum == PR_getgroups || sysnum == PR_getgroups32) {
            word_t count = peek_reg(tracee, ORIGINAL, SYSARG_1);
            word_t list_addr = peek_reg(tracee, ORIGINAL, SYSARG_2);
            if (count > 0 && list_addr != 0) {
                if (poke_word(tracee, list_addr, (word_t)config->rgid) == 0) {
                    poke_reg(tracee, SYSARG_RESULT, 1);
                    config->egid = config->rgid;
                    config->sgid = config->rgid;
                } else {
                    poke_reg(tracee, SYSARG_RESULT, 0);
                }
            } else {
                poke_reg(tracee, SYSARG_RESULT, 0);
            }
            return 0;
        }
        if (sysnum == PR_setgroups || sysnum == PR_setgroups32) {
            poke_reg(tracee, SYSARG_RESULT, 0);
            return 0;
        }
        set_sysnum(tracee, PR_void);
#endif
        return 0;
    default:
        return 0;
    }
    __builtin_unreachable();
    return 0;
}

static HOT int handle_sysexit_end(Tracee *restrict tracee, Config *restrict config) {
    if (UNLIKELY(!tracee || !config)) return -EINVAL;
    word_t sysnum = get_sysnum(tracee, ORIGINAL);
#ifndef USERLAND
    Reg stat_sysarg = SYSARG_2;
#endif
#ifdef USERLAND
    word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
    word_t curr_sysnum = get_sysnum(tracee, CURRENT);
    if ((curr_sysnum == PR_fstat || curr_sysnum == PR_fstat64) && result == 0) {
        Reg sysarg = SYSARG_2;
        word_t address = peek_reg(tracee, ORIGINAL, sysarg);
        uid_t uid = peek_uint32(tracee, address + offsetof_stat_uid(tracee));
        if (errno != 0) uid = 0;
        gid_t gid = peek_uint32(tracee, address + offsetof_stat_gid(tracee));
        if (errno != 0) gid = 0;
        if (uid == getuid())
            poke_uint32(tracee, address + offsetof_stat_uid(tracee), config->suid);
        if (gid == getgid())
            poke_uint32(tracee, address + offsetof_stat_gid(tracee), config->sgid);
        return 0;
    }
    if ((sysnum == PR_fstat || sysnum == PR_fstat64) && curr_sysnum == PR_readlinkat) {
        result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
        poke_reg(tracee, SYSARG_RESULT, 0);
        if ((int)result <= 0) return result;
        char path[PATH_MAX];
        int status = read_sysarg_path(tracee, path, SYSARG_3, MODIFIED);
        if (status < 0) return status;
        path[result] = '\0';
        size_t len = __builtin_strlen(path);
        if ((len >= 10 && __builtin_memcmp(path + len - 10, " (deleted)", 10) == 0) ||
            (len >= 4 && __builtin_memcmp(path, "pipe", 4) == 0)) {
            register_chained_syscall(tracee, sysnum,
                peek_reg(tracee, ORIGINAL, SYSARG_1),
                peek_reg(tracee, ORIGINAL, SYSARG_2), 0, 0, 0, 0);
        } else {
            write_data(tracee, peek_reg(tracee, MODIFIED, SYSARG_3), path, sizeof(path));
            register_chained_syscall(tracee, PR_fstatat64, AT_FDCWD,
                peek_reg(tracee, MODIFIED, SYSARG_3),
                peek_reg(tracee, ORIGINAL, SYSARG_2), 0, 0, 0);
        }
        return 0;
    }
#endif
    switch (sysnum) {
    case PR_setuid:
    case PR_setuid32:   SETXID(uid, ORIGINAL);
    case PR_setgid:
    case PR_setgid32:   SETXID(gid, ORIGINAL);
    case PR_setreuid:
    case PR_setreuid32: SETREXID(uid, ORIGINAL);
    case PR_setregid:
    case PR_setregid32: SETREXID(gid, ORIGINAL);
    case PR_setresuid:
    case PR_setresuid32: SETRESXID(u, ORIGINAL);
    case PR_setresgid:
    case PR_setresgid32: SETRESXID(g, ORIGINAL);
    case PR_setfsuid:
    case PR_setfsuid32: SETFSXID(u);
    case PR_setfsgid:
    case PR_setfsgid32: SETFSXID(g);
    case PR_getuid:
    case PR_getuid32:   poke_reg(tracee, SYSARG_RESULT, config->ruid); return 0;
    case PR_getgid:
    case PR_getgid32:   poke_reg(tracee, SYSARG_RESULT, config->rgid); return 0;
    case PR_geteuid:
    case PR_geteuid32:  poke_reg(tracee, SYSARG_RESULT, config->euid); return 0;
    case PR_getegid:
    case PR_getegid32:  poke_reg(tracee, SYSARG_RESULT, config->egid); return 0;
    case PR_getresuid:
    case PR_getresuid32: return handle_getresuid_exit_end(tracee, config);
    case PR_getresgid:
    case PR_getresgid32: return handle_getresgid_exit_end(tracee, config);
#ifdef USERLAND
    case PR_umask:
        poke_reg(tracee, SYSARG_RESULT, config->umask);
        config->umask = (mode_t)peek_reg(tracee, MODIFIED, SYSARG_1);
        return 0;
    case PR_setgroups:
    case PR_setgroups32:
    case PR_getgroups:
    case PR_getgroups32:
        poke_reg(tracee, SYSARG_RESULT, 0);
        return 0;
#endif
    case PR_setdomainname:
    case PR_sethostname:
#ifndef USERLAND
    case PR_setgroups:
    case PR_setgroups32:
#endif
    case PR_mknod:
    case PR_mknodat:
    case PR_capset:
    case PR_chmod:
    case PR_chown:
    case PR_fchmod:
    case PR_fchown:
    case PR_lchown:
    case PR_chown32:
    case PR_fchown32:
    case PR_lchown32:
    case PR_fchmodat:
    case PR_fchownat:
        return handle_perm_err_exit_end(tracee, config, false);
    case PR_setxattr:
    case PR_lsetxattr:
    case PR_fsetxattr:
        return handle_perm_err_exit_end(tracee, config, true);
    case PR_socket:
        return handle_socket_exit_end(tracee, config);
#ifndef USERLAND
    case PR_fstatat64:
    case PR_newfstatat: stat_sysarg = SYSARG_3;
    case PR_stat64:
    case PR_lstat64:
    case PR_fstat64:
    case PR_stat:
    case PR_lstat:
    case PR_fstat:
        return handle_stat_exit_end(tracee, config, stat_sysarg);
#endif
#ifdef USERLAND
    case PR_fstatat64:
    case PR_newfstatat:
    case PR_stat64:
    case PR_lstat64:
    case PR_fstat64:
    case PR_stat:
    case PR_lstat:
    case PR_fstat:
        return handle_stat_exit_end(tracee, config, sysnum);
    case PR_open:
    case PR_openat:
    case PR_creat: {
        Reg sysarg = (sysnum == PR_open || sysnum == PR_creat) ? SYSARG_1 : SYSARG_2;
        char path[PATH_MAX];
        if (read_sysarg_path(tracee, path, sysarg, MODIFIED) < 0) return 0;
        if (path[0] == '\0') return 0;
        if (path_exists(path) == 0) return 0;
        char meta[PATH_MAX];
        if (get_meta_path(path, meta) < 0) return 0;
        if (path_exists(meta) == 0) remove_meta_file(meta);
        return 0;
    }
#endif
    case PR_chroot:
        return handle_chroot_exit_end(tracee, config, false);
    case PR_getsockopt:
        return handle_getsockopt_exit_end(tracee);
    default:
        return 0;
    }
}

static ALWAYS_INLINE int handle_sigsys(Tracee *restrict tracee, Config *restrict config) {
    if (UNLIKELY(!tracee || !config)) return -EINVAL;
    word_t sysnum = get_sysnum(tracee, CURRENT);
    switch (sysnum) {
    case PR_setuid:
    case PR_setuid32:   SETXID(uid, CURRENT);
    case PR_setgid:
    case PR_setgid32:   SETXID(gid, CURRENT);
    case PR_setreuid:
    case PR_setreuid32: SETREXID(uid, CURRENT);
    case PR_setregid:
    case PR_setregid32: SETREXID(gid, CURRENT);
    case PR_setresuid:
    case PR_setresuid32: SETRESXID(u, CURRENT);
    case PR_setresgid:
    case PR_setresgid32: SETRESXID(g, CURRENT);
    case PR_chroot:
        return handle_chroot_exit_end(tracee, config, true);
    default:
        return 0;
    }
}

static ALWAYS_INLINE int handle_sysexit_start(Tracee *restrict tracee, Config *restrict config) {
    if (UNLIKELY(!tracee || !config)) return -EINVAL;
    word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
    word_t sysnum = get_sysnum(tracee, ORIGINAL);
    if (UNLIKELY((int)result < 0 || tracee->status < 0 || sysnum != PR_execve)) return 0;
    if (!tracee->skip_proot_loader) adjust_elf_auxv(tracee, config);
    struct stat mode;
    if (UNLIKELY(stat(tracee->host_exe, &mode) < 0)) return 0;
    if ((mode.st_mode & S_ISUID) != 0) { config->euid = 0; config->suid = 0; }
    if ((mode.st_mode & S_ISGID) != 0) { config->egid = 0; config->sgid = 0; }
    return 0;
}

HOT int fake_id0_callback(Extension *restrict extension, ExtensionEvent event,
                          intptr_t data1, intptr_t data2 UNUSED) {
    if (UNLIKELY(!extension)) return -EINVAL;
    switch (event) {
    case INITIALIZATION: {
        const char *uid_string = (const char *)data1;
        const char *gid_string = NULL;
        int uid = getuid(), gid = getgid();
        errno = 0;
        if (uid_string) {
            uid = (int)strtol(uid_string, NULL, 10);
            if (UNLIKELY(errno != 0)) uid = getuid();
            gid_string = __builtin_strchr(uid_string, ':');
            if (gid_string) {
                errno = 0;
                gid = (int)strtol(gid_string + 1, NULL, 10);
                if (UNLIKELY(errno != 0)) gid = getgid();
            }
        }
        extension->config = talloc(extension, Config);
        if (UNLIKELY(!extension->config)) return -1;
        Config *config = talloc_get_type_abort(extension->config, Config);
        config->ruid  = uid; config->euid  = uid; config->suid  = uid; config->fsuid = uid;
        config->rgid  = gid; config->egid  = gid; config->sgid  = gid; config->fsgid = gid;
        config->umask = 022;
#ifdef USERLAND
        if (initialize_meta_store() < 0)
            return -1;
#endif
        extension->filtered_sysnums = filtered_sysnums;
        return 0;
    }
    case INHERIT_PARENT:
        return 1;
    case INHERIT_CHILD: {
        Extension *parent = (Extension *)data1;
        if (UNLIKELY(!parent || !parent->config)) return -1;
        extension->config = talloc_zero(extension, Config);
        if (UNLIKELY(!extension->config)) return -1;
        __builtin_memcpy(extension->config, parent->config, sizeof(Config));
        return 0;
    }
    case HOST_PATH: {
        Tracee *tracee = TRACEE(extension);
        Config *config = talloc_get_type_abort(extension->config, Config);
        if (config->euid == 0)
            override_permissions(tracee, (char *)data1, (bool)data2);
        return 0;
    }
#ifdef USERLAND
    case LINK2SYMLINK_RENAME: {
        char old_meta[PATH_MAX], new_meta[PATH_MAX];
        if (get_meta_path((char *)data1, old_meta) < 0) return 0;
        if (path_exists(old_meta) != 0) return 0;
        if (get_meta_path((char *)data2, new_meta) < 0) return 0;
        return rename_meta_file(old_meta, new_meta);
    }
    case LINK2SYMLINK_UNLINK: {
        char meta[PATH_MAX];
        if (get_meta_path((char *)data1, meta) < 0) return 0;
        if (path_exists(meta) != 0) return 0;
        return remove_meta_file(meta);
    }
#endif
    case SYSCALL_ENTER_END: {
        Tracee *tracee = TRACEE(extension);
        Config *config = talloc_get_type_abort(extension->config, Config);
        return handle_sysenter_end(tracee, config);
    }
    case SYSCALL_EXIT_END: {
        Tracee *tracee = TRACEE(extension);
        Config *config = talloc_get_type_abort(extension->config, Config);
        return handle_sysexit_end(tracee, config);
    }
    case SIGSYS_OCC: {
        Tracee *tracee = TRACEE(extension);
        Config *config = talloc_get_type_abort(extension->config, Config);
        word_t sysnum = get_sysnum(tracee, CURRENT);
        switch (sysnum) {
        case PR_setuid: case PR_setuid32:
        case PR_setgid: case PR_setgid32:
        case PR_setreuid: case PR_setreuid32:
        case PR_setregid: case PR_setregid32:
        case PR_setresuid: case PR_setresuid32:
        case PR_setresgid: case PR_setresgid32:
        case PR_chroot:
            if (handle_sigsys(tracee, config) < 0) return -1;
            return 1;
        default:
            return 0;
        }
    }
    case SYSCALL_EXIT_START: {
        Tracee *tracee = TRACEE(extension);
        Config *config = talloc_get_type_abort(extension->config, Config);
        return handle_sysexit_start(tracee, config);
    }
    case STATX_SYSCALL: {
        Tracee *tracee = TRACEE(extension);
        Config *config = talloc_get_type_abort(extension->config, Config);
        return fake_id0_handle_statx_syscall(tracee, config, data1);
    }
    default:
        return 0;
    }
}

#undef POKE_MEM_ID
#undef SETXID
#undef UNSET_ID
#undef UNCHANGED_ID
#undef SETREXID
#undef EQUALS_ANY_ID
#undef SETRESXID
#undef SETFSXID
