#include <errno.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>

#include "tracee/reg.h"
#include "tracee/mem.h"
#include "path/path.h"
#include "path/binding.h"
#include "extension/fake_id0/chroot.h"

int handle_chroot_exit_end(Tracee *tracee, Config *config, bool from_sigsys)
{
    char path[PATH_MAX] = {0};
    char path_guest[PATH_MAX] = {0};
    char path_host_abs[PATH_MAX] = {0};
    word_t result;
    struct stat st;
    bool has_bad_binding = false;
    Binding *b;
    int ret;

    if (config->euid != 0) {
        return from_sigsys ? -EPERM : 0;
    }

    if (!from_sigsys) {
        result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
        if ((int)result != -EPERM)
            return 0;
    }

    if (from_sigsys) {
        word_t input = peek_reg(tracee, CURRENT, SYSARG_1);
        ret = read_path(tracee, path_guest, input);
        if (ret < 0) return ret;
        ret = translate_path(tracee, path, AT_FDCWD, path_guest, true);
    } else {
        word_t input = peek_reg(tracee, MODIFIED, SYSARG_1);
        ret = read_path(tracee, path, input);
    }
    if (ret < 0) return ret;

    if (!realpath(path, path_host_abs))
        return -errno;

    if (compare_paths(get_root(tracee), path_host_abs) == PATHS_ARE_EQUAL) {
        if (from_sigsys) return 1;
        poke_reg(tracee, SYSARG_RESULT, 0);
        return 0;
    }

    if (stat(path_host_abs, &st) < 0 || !S_ISDIR(st.st_mode))
        return -ENOTDIR;

    if (!from_sigsys) {
        word_t input = peek_reg(tracee, ORIGINAL, SYSARG_1);
        if (read_path(tracee, path_guest, input) < 0)
            return -errno;
    }

    for (b = CIRCLEQ_FIRST(tracee->fs->bindings.guest);
         b != CIRCLEQ_LAST(tracee->fs->bindings.guest);
         b = CIRCLEQ_NEXT(b, link.guest))
    {
        bool is_root = (b == CIRCLEQ_LAST(tracee->fs->bindings.guest));
        if (!is_root && compare_paths(path_guest, b->guest.path) == PATH1_IS_PREFIX) {
            has_bad_binding = true;
            break;
        }
    }

    if (has_bad_binding)
        return from_sigsys ? -ENOSYS : 0;

    char old_cwd[PATH_MAX] = {0};
    if (translate_path(tracee, old_cwd, AT_FDCWD, tracee->fs->cwd, true) < 0)
        return -errno;

    talloc_unlink(tracee, tracee->fs);
    tracee->fs = talloc_zero(tracee, FileSystemNameSpace);
    new_binding(tracee, path_host_abs, "/", true);
    initialize_bindings(tracee);

    if (detranslate_path(tracee, old_cwd, NULL) > 0)
        tracee->fs->cwd = talloc_strdup(tracee->fs, old_cwd);
    else
        tracee->fs->cwd = talloc_strdup(tracee->fs, "/");

    if (from_sigsys)
        return 1;

    poke_reg(tracee, SYSARG_RESULT, 0);
    return 0;
}
