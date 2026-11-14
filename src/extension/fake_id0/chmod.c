#include <errno.h>
#include <linux/limits.h>
#include <string.h>
#include <sys/stat.h>
#include <talloc.h>

#include "syscall/sysnum.h"
#include "tracee/mem.h"
#include "extension/fake_id0/chmod.h"
#include "extension/fake_id0/helper_functions.h"

#ifdef USERLAND
#define ACL_ACCESS_XATTR "system.posix_acl_access"

/* Config may be shared by extensions. Pending work belongs to a syscall of
 * one tracee, and must survive replacement of its temporary ctx between stops. */
typedef struct PendingModeChange {
    Tracee *tracee;
    char path[PATH_MAX];
    mode_t mode;
    struct PendingModeChange *next;
} PendingModeChange;

static PendingModeChange *pending_changes;

static int remove_pending_change(PendingModeChange *pending)
{
    PendingModeChange **cursor = &pending_changes;
    while (*cursor != NULL && *cursor != pending)
        cursor = &(*cursor)->next;
    if (*cursor != NULL)
        *cursor = pending->next;
    return 0;
}

static PendingModeChange *get_pending_change(Tracee *tracee)
{
    for (PendingModeChange *pending = pending_changes; pending; pending = pending->next)
        if (pending->tracee == tracee)
            return pending;
    return NULL;
}

static void clear_pending_change(Tracee *tracee)
{
    PendingModeChange *pending = get_pending_change(tracee);
    if (pending != NULL)
        talloc_free(pending);
}

static int defer_mode_change(Tracee *tracee, const char *path, mode_t mode)
{
    PendingModeChange *pending = talloc_zero(tracee, PendingModeChange);
    if (pending == NULL)
        return -ENOMEM;
    pending->tracee = tracee;
    strcpy(pending->path, path);
    pending->mode = mode;
    pending->next = pending_changes;
    pending_changes = pending;
    talloc_set_destructor(pending, remove_pending_change);
    return 0;
}

static int get_target_path(Tracee *tracee, char path[PATH_MAX], Reg path_sysarg,
                           Reg fd_sysarg)
{
    if (path_sysarg == IGNORE_SYSARG)
        return get_fd_path(tracee, path, fd_sysarg, CURRENT);
    int status = read_sysarg_path(tracee, path, path_sysarg, CURRENT);
    if (status >= 0) {
        int resolved = resolve_proc_fd_path(tracee, path);
        if (resolved >= 0)
            status = resolved;
    }
    return status;
}

/* Keep the actual owner's access, and leave set-id bits in the record only. */
static mode_t get_real_mode(mode_t mode, const char *path)
{
    struct stat st;
    mode_t real_mode = (mode & 01777) | S_IRUSR | S_IWUSR;
    if ((mode & 0111) != 0 || (stat(path, &st) == 0 && S_ISDIR(st.st_mode)))
        real_mode |= S_IXUSR;
    return real_mode;
}

int handle_chmod_enter_end(Tracee *tracee, Reg path_sysarg, Reg mode_sysarg,
                           Reg fd_sysarg, Reg dirfd_sysarg, Config *config)
{
    char path[PATH_MAX], rel_path[PATH_MAX], meta_path[PATH_MAX];
    mode_t old_mode, mode;
    uid_t owner;
    gid_t group;
    int status;

    clear_pending_change(tracee);
    status = get_target_path(tracee, path, path_sysarg, fd_sysarg);
    if (status < 0)
        return status;
    if (status == 1) {
        set_sysnum(tracee, PR_getuid);
        return 0;
    }
    if (get_meta_path(path, meta_path) < 0 || path_exists(meta_path) < 0)
        return 0;
    status = get_fd_path(tracee, rel_path, dirfd_sysarg, CURRENT);
    if (status < 0)
        return status;
    status = check_dir_perms(tracee, 'w', path, rel_path, config);
    if (status < 0)
        return status;
    read_meta_file(meta_path, &old_mode, &owner, &group, config);
    if (config->euid != 0 && config->euid != owner)
        return -EPERM;

    mode = peek_reg(tracee, ORIGINAL, mode_sysarg) & 07777;
    status = defer_mode_change(tracee, path, mode);
    if (status < 0)
        return status;
    poke_reg(tracee, mode_sysarg, get_real_mode(mode, path));
    return 0;
}

int handle_chmod_exit_end(Tracee *tracee, Config *config)
{
    PendingModeChange *pending = get_pending_change(tracee);
    char meta_path[PATH_MAX];
    mode_t mode;
    uid_t owner;
    gid_t group;
    int status = 0;
    if (pending == NULL)
        return 0;
    if (peek_reg(tracee, CURRENT, SYSARG_RESULT) == 0
        && get_meta_path(pending->path, meta_path) == 0 && path_exists(meta_path) == 0) {
        read_meta_file(meta_path, &mode, &owner, &group, config);
        status = write_meta_file(meta_path, pending->mode, owner, group, false, config);
    }
    talloc_free(pending);
    return status;
}

int handle_acl_enter_end(Tracee *tracee, Reg path_sysarg, Reg fd_sysarg, Config *config)
{
    char name[sizeof(ACL_ACCESS_XATTR)], path[PATH_MAX], meta_path[PATH_MAX];
    mode_t mode;
    uid_t owner;
    gid_t group;
    clear_pending_change(tracee);
    int status = read_string(tracee, name, peek_reg(tracee, CURRENT, SYSARG_2), sizeof(name));
    if (status != sizeof(name) || name[sizeof(name) - 1] != '\0'
        || strcmp(name, ACL_ACCESS_XATTR) != 0)
        return 0;
    if (get_target_path(tracee, path, path_sysarg, fd_sysarg) != 0
        || get_meta_path(path, meta_path) < 0 || path_exists(meta_path) < 0)
        return 0;
    read_meta_file(meta_path, &mode, &owner, &group, config);
    if (config->euid != 0 && config->euid != owner)
        return -EPERM;
    return defer_mode_change(tracee, path, 0);
}

int handle_acl_exit_end(Tracee *tracee, Config *config)
{
    PendingModeChange *pending = get_pending_change(tracee);
    char meta_path[PATH_MAX];
    struct stat st;
    mode_t mode;
    uid_t owner;
    gid_t group;
    if (pending == NULL)
        return 0;
    if (peek_reg(tracee, CURRENT, SYSARG_RESULT) == 0
        && get_meta_path(pending->path, meta_path) == 0 && path_exists(meta_path) == 0
        && stat(pending->path, &st) == 0) {
        read_meta_file(meta_path, &mode, &owner, &group, config);
        mode = (mode & 07000) | (st.st_mode & 0777);
        if (write_meta_file(meta_path, mode, owner, group, false, config) == 0) {
            mode_t real_mode = get_real_mode(mode, pending->path);
            if (real_mode != (st.st_mode & 07777))
                (void)chmod(pending->path, real_mode);
        }
    }
    talloc_free(pending);
    return 0;
}
#endif /* USERLAND */
