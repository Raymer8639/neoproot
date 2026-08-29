#include <sys/types.h>
#include <limits.h>
#include <sys/param.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <arm_neon.h>

#include "path/canon.h"
#include "path/path.h"
#include "path/binding.h"
#include "path/glue.h"
#include "path/proc.h"
#include "path/f2fs-bug.h"
#include "extension/extension.h"

#define NEON_VEC_BYTES        16

#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define ALWAYS_INLINE __attribute__((always_inline)) inline

/*
 * These operate on unbounded C strings.  Vector loads here must not cross a
 * string object's end: short literals such as "." and ".." made the former
 * NEON implementations read into ASAN redzones.  libc supplies safe,
 * optimized implementations; keep NEON only in copy_component(), where len
 * bounds every vector access.
 */
static ALWAYS_INLINE size_t path_strlen(const char *s) {
    return s == NULL ? 0 : strlen(s);
}

static ALWAYS_INLINE int path_strcmp(const char *a, const char *b) {
    return strcmp(a, b);
}

static ALWAYS_INLINE void path_strcpy(char *restrict d, const char *restrict s) {
    strcpy(d, s);
}

/* 复制已知长度的组件（含终止符） */
static ALWAYS_INLINE void copy_component(char *restrict d, const char *restrict s, size_t len) {
    size_t i = 0;
    for (; i + NEON_VEC_BYTES <= len; i += NEON_VEC_BYTES)
        vst1q_u8((uint8_t *)(d + i), vld1q_u8((const uint8_t *)(s + i)));
    for (; i < len; i++) d[i] = s[i];
    d[len] = '\0';
}

static ALWAYS_INLINE void pop_component(char *restrict path) {
    if (UNLIKELY(!path || *path != '/')) return;
    int len = path_strlen(path) - 1;
    if (len <= 0) return;
    while (len > 1 && path[len] == '/') len--;
    while (len > 1 && path[len] != '/') len--;
    path[len] = '\0';
}

static ALWAYS_INLINE Finality next_component(char component[NAME_MAX], const char **restrict cursor) {
    if (UNLIKELY(!component || !cursor || !*cursor)) return FINAL_NORMAL;
    while (**cursor == '/') (*cursor)++;
    const char *start = *cursor;
    while (**cursor && **cursor != '/') (*cursor)++;
    size_t len = *cursor - start;
    if (UNLIKELY(len >= NAME_MAX)) return -ENAMETOOLONG;
    copy_component(component, start, len);
    int want_dir = (**cursor == '/');
    while (**cursor == '/') (*cursor)++;
    if (!**cursor) return want_dir ? FINAL_SLASH : FINAL_NORMAL;
    return NOT_FINAL;
}

static int substitute_binding_stat(Tracee *restrict tracee, Finality finality,
                                   unsigned int recursion_level,
                                   const char guest_path[PATH_MAX],
                                   char host_path[PATH_MAX]) {
    struct stat statl;
    int res;
    path_strcpy(host_path, guest_path);
    res = substitute_binding(tracee, GUEST, host_path);
    if (UNLIKELY(res < 0)) return res;
    /* Extensions may need to resolve host-only paths even when procfs glue is
     * active; link2symlink uses this during recursive external-chain lookup. */
    res = notify_extensions(tracee, HOST_PATH, (intptr_t)host_path,
                            IS_FINAL(finality) && recursion_level == 0);
    if (UNLIKELY(res < 0)) return res;
    if (should_skip_file_access_due_to_f2fs_bug(tracee, host_path)) {
        res = -ENOENT;
    } else {
        res = lstat(host_path, &statl);
        if (UNLIKELY(res < 0 && errno == EACCES)) {
            if (path_strcmp(host_path, "/linkerconfig") == 0 ||
                path_strcmp(host_path, "/system")     == 0 ||
                path_strcmp(host_path, "/vendor")     == 0) {
                res = 0;
                statl.st_mode = S_IFDIR | 0755;
            }
        }
    }
    if (UNLIKELY(res < 0 && tracee->glue_type != 0)) {
        statl.st_mode = build_glue(tracee, guest_path, host_path, finality);
        if (UNLIKELY(statl.st_mode == 0)) return -1;
        res = 0;
    }
    if (!IS_FINAL(finality) && !S_ISDIR(statl.st_mode) && !S_ISLNK(statl.st_mode))
        return res < 0 ? -ENOENT : -ENOTDIR;
    return S_ISLNK(statl.st_mode) ? 1 : 0;
}

int canonicalize(Tracee *restrict tracee, const char *restrict user_path,
                 bool deref_final, char guest_path[PATH_MAX],
                 unsigned int recursion_level) {
    char scratch_path[PATH_MAX];
    Finality fin;
    const char *cursor;
    int res;
    unsigned int symlinks_followed = 0; /* 上游 d86f355：跨顺序链计数 */
    if (UNLIKELY(recursion_level > MAXSYMLINKS)) return -ELOOP;
    if (UNLIKELY(!user_path || !guest_path)) return -EINVAL;
    if (UNLIKELY(path_strlen(user_path) >= PATH_MAX)) return -ENAMETOOLONG;
    if (user_path[0] != '/') {
        if (guest_path[0] != '/') {
            if (recursion_level == 0) {
                guest_path[0] = '/'; guest_path[1] = 0;
            } else return -EINVAL;
        }
    } else {
        guest_path[0] = '/'; guest_path[1] = 0;
    }
    cursor = user_path;
    fin = NOT_FINAL;
    while (!IS_FINAL(fin)) {
        char comp[NAME_MAX];
        char host_path[PATH_MAX];
        fin = next_component(comp, &cursor);
        if (UNLIKELY((int)fin < 0)) return (int)fin;
        if (path_strcmp(comp, ".") == 0) {
            if (IS_FINAL(fin)) fin = FINAL_DOT;
            continue;
        }
        if (path_strcmp(comp, "..") == 0) {
            pop_component(guest_path);
            if (IS_FINAL(fin)) fin = FINAL_SLASH;
            continue;
        }
        res = join_paths(2, scratch_path, guest_path, comp);
        if (UNLIKELY(res < 0)) return res;
        res = substitute_binding_stat(tracee, fin, recursion_level, scratch_path, host_path);
        if (UNLIKELY(res < 0)) return res;
        if (res <= 0 || (fin == FINAL_NORMAL && !deref_final)) {
            path_strcpy(scratch_path, guest_path);
            res = join_paths(2, guest_path, scratch_path, comp);
            if (UNLIKELY(res < 0)) return res;
            continue;
        }
        Comparison cmp = compare_paths("/proc", guest_path);
        if (cmp == PATHS_ARE_EQUAL || cmp == PATH1_IS_PREFIX) {
            res = readlink_proc(tracee, scratch_path, guest_path, comp, cmp);
            if (res == CANONICALIZE) goto canon_symlink;
            if (res == DONT_CANONICALIZE) {
                if (fin == FINAL_NORMAL) {
                    path_strcpy(guest_path, scratch_path);
                    return 0;
                }
            } else if (UNLIKELY(res < 0)) return res;
        }
        res = readlink(host_path, scratch_path, PATH_MAX - 1);
        if (UNLIKELY(res < 0)) {
            /* 文件可在路径解析期间改变；重新 lstat，若已不再是符号链接则
             * 按普通文件继续，避免将陈旧的链接状态带到最终宿主 syscall。 */
            const int saved_errno = errno;
            struct stat st_now;
            if (LIKELY(lstat(host_path, &st_now) == 0 && !S_ISLNK(st_now.st_mode))) {
                path_strcpy(scratch_path, guest_path);
                res = join_paths(2, guest_path, scratch_path, comp);
                if (UNLIKELY(res < 0)) return res;
                continue;
            }
            return -saved_errno;
        }
        if (UNLIKELY((size_t)res >= PATH_MAX)) return -ENAMETOOLONG;
        scratch_path[res] = '\0';
        res = detranslate_path(tracee, scratch_path, host_path);
        if (UNLIKELY(res < 0)) return res;
        /* The symlink target may point into an external L2S backing directory.
         * Give extensions one more chance to remap that host-only component
         * before recursively canonicalizing it under the guest root. */
        res = notify_extensions(tracee, HOST_PATH, (intptr_t)scratch_path,
                                IS_FINAL(fin) && recursion_level == 0);
        if (UNLIKELY(res < 0)) return res;
canon_symlink:
        /* 上游 d86f355：顺序符号链接也计入 MAXSYMLINKS（单路径内多条
         * 不同的链逐个解引用时同样受限，不只深层嵌套） */
        res = canonicalize(tracee, scratch_path, true, guest_path, recursion_level + (++symlinks_followed));
        if (UNLIKELY(res < 0)) return res;
        res = substitute_binding_stat(tracee, fin, recursion_level, guest_path, host_path);
        if (UNLIKELY(res < 0)) return res;
    }
    if (recursion_level == 0) {
        switch (fin) {
            case FINAL_SLASH:
                join_paths(2, scratch_path, guest_path, "");
                path_strcpy(guest_path, scratch_path);
                break;
            case FINAL_DOT:
                join_paths(2, scratch_path, guest_path, ".");
                path_strcpy(guest_path, scratch_path);
                break;
            default: break;
        }
    }
    return 0;
}
