#include <errno.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>

#include "tracee/reg.h"
#include "tracee/mem.h"
#include "path/path.h"
#include "path/binding.h"
#include "extension/fake_id0/chroot.h"

#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define ALWAYS_INLINE __attribute__((always_inline, flatten))
#define HOT __attribute__((hot))

HOT
int handle_chroot_exit_end(Tracee *restrict tracee, Config *restrict config,
                           bool from_sigsys) {
    if (UNLIKELY(config->euid != 0)) {
        return from_sigsys ? -EPERM : 0;
    }

    char path[PATH_MAX];
    char path_guest[PATH_MAX];
    char path_host_abs[PATH_MAX];
    struct stat st;
    int ret;

    if (UNLIKELY(!from_sigsys)) {
        word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
        if (LIKELY((int)result != -EPERM))
            return 0;
    }

    // 获取路径（处理 from_sigsys 与正常路径的差异）
    if (from_sigsys) {
        word_t input = peek_reg(tracee, CURRENT, SYSARG_1);
        ret = read_path(tracee, path_guest, input);
        if (UNLIKELY(ret < 0)) return ret;
        ret = translate_path(tracee, path, AT_FDCWD, path_guest, true);
    } else {
        word_t input = peek_reg(tracee, MODIFIED, SYSARG_1);
        ret = read_path(tracee, path, input);
    }
    if (UNLIKELY(ret < 0)) return ret;

    if (UNLIKELY(!realpath(path, path_host_abs)))
        return -errno;

    // 如果 chroot 到当前根目录，直接成功
    if (LIKELY(compare_paths(get_root(tracee), path_host_abs) == PATHS_ARE_EQUAL)) {
        if (from_sigsys) return 1;
        poke_reg(tracee, SYSARG_RESULT, 0);
        return 0;
    }

    // 检查目标是否为目录
    if (UNLIKELY(stat(path_host_abs, &st) < 0 || !S_ISDIR(st.st_mode)))
        return -ENOTDIR;

    // 检查是否有绑定挂载冲突（非根目录的绑定）
    if (!from_sigsys) {
        word_t input = peek_reg(tracee, ORIGINAL, SYSARG_1);
        if (UNLIKELY(read_path(tracee, path_guest, input) < 0))
            return -errno;
    }

    bool has_bad_binding = false;
    Binding *b;
    CIRCLEQ_FOREACH(b, tracee->fs->bindings.guest, link.guest) {
        bool is_root = (b == CIRCLEQ_LAST(tracee->fs->bindings.guest));
        if (!is_root && compare_paths(path_guest, b->guest.path) == PATH1_IS_PREFIX) {
            has_bad_binding = true;
            break;
        }
    }

    if (UNLIKELY(has_bad_binding))
        return from_sigsys ? -ENOSYS : 0;

    // 保存当前工作目录（在 guest 视角下）
    char old_cwd[PATH_MAX];
    if (UNLIKELY(translate_path(tracee, old_cwd, AT_FDCWD, tracee->fs->cwd, true) < 0))
        return -errno;

    // 重建文件系统命名空间
    talloc_unlink(tracee, tracee->fs);
    tracee->fs = talloc_zero(tracee, FileSystemNameSpace);
    (void)new_binding(tracee, path_host_abs, "/", true);
    (void)initialize_bindings(tracee);

    // 恢复工作目录（如果仍在新的根下）
    if (detranslate_path(tracee, old_cwd, NULL) > 0)
        tracee->fs->cwd = talloc_strdup(tracee->fs, old_cwd);
    else
        tracee->fs->cwd = talloc_strdup(tracee->fs, "/");

    if (from_sigsys)
        return 1;

    poke_reg(tracee, SYSARG_RESULT, 0);
    return 0;
}