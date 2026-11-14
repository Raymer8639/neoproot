#include "extension/extension.h"
#include "tracee/mem.h"
#include "tracee/abi.h"
#include "syscall/chain.h"
#include "path/path.h"
#include <string.h>
#include <limits.h>

#define HIDDEN_PREFIX ".proot"
#define HIDDEN_PREFIX_LEN (sizeof(HIDDEN_PREFIX) - 1)

#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define ALWAYS_INLINE __attribute__((always_inline, flatten))
#define HOT __attribute__((hot))

struct linux_dirent {
    unsigned long  d_ino;
    unsigned long  d_off;
    unsigned short d_reclen;
    char           d_name[];
};

struct linux_dirent64 {
    unsigned long long d_ino;
    long long          d_off;
    unsigned short     d_reclen;
    unsigned char      d_type;
    char               d_name[];
};

static ALWAYS_INLINE int has_prefix(const char *prefix, const char *str, size_t plen) {
    return __builtin_memcmp(prefix, str, plen) == 0;
}

static ALWAYS_INLINE int belongs_to_guestfs_fast(Tracee *tracee, const char *path) {
    if (UNLIKELY(!tracee || !path)) return 0;
    char root[PATH_MAX];
    if (translate_path(tracee, root, AT_FDCWD, "/", true) < 0) return 0;
    size_t root_len = __builtin_strlen(root);
    if (root_len == 1 && root[0] == '/') return 1;
    return strlen(path) >= root_len && __builtin_memcmp(path, root, root_len) == 0
        && (path[root_len] == '\0' || path[root_len] == '/');
}

static HOT int handle_getdents(Tracee *restrict tracee) {
    if (UNLIKELY(!tracee)) return -1;
    word_t sysnum = get_sysnum(tracee, ORIGINAL);
    if (sysnum != PR_getdents && sysnum != PR_getdents64)
        return 0;
    /* A failed getdents has no output buffer to filter. */
    long result = (long)peek_reg(tracee, CURRENT, SYSARG_RESULT);
    if (result <= 0)
        return 0;
    word_t fd = peek_reg(tracee, ORIGINAL, SYSARG_1);
    word_t buf_addr = peek_reg(tracee, CURRENT, SYSARG_2);
    word_t count = peek_reg(tracee, CURRENT, SYSARG_3);
    if ((word_t)result > count)
        return 0;
    char path[PATH_MAX];
    if (readlink_proc_pid_fd(tracee->pid, fd, path) < 0
        || !belongs_to_guestfs_fast(tracee, path))
        return 0;

    size_t res = result;
    char *orig = talloc_size(tracee->ctx, res);
    char *filtered = talloc_size(tracee->ctx, res);
    int status = 0;
    if (orig == NULL || filtered == NULL)
        goto out;
    status = read_data(tracee, orig, buf_addr, res);
    if (status < 0)
        goto out;

    size_t reclen_offset = sysnum == PR_getdents64 ? 16 : 2 * sizeof_word(tracee);
    size_t name_offset = sysnum == PR_getdents64 ? 19 : reclen_offset + 2;
    size_t offset = 0, filtered_len = 0;
    while (offset < res) {
        unsigned short reclen;
        if (res - offset <= name_offset)
            goto out;
        memcpy(&reclen, orig + offset + reclen_offset, sizeof(reclen));
        if (reclen <= name_offset || reclen > res - offset)
            goto out;
        const char *name = orig + offset + name_offset;
        size_t name_size = reclen - name_offset;
        if (memchr(name, '\0', name_size) == NULL)
            goto out;
        if (name_size < HIDDEN_PREFIX_LEN
            || !has_prefix(HIDDEN_PREFIX, name, HIDDEN_PREFIX_LEN)) {
            memcpy(filtered + filtered_len, orig + offset, reclen);
            filtered_len += reclen;
        }
        offset += reclen;
    }
    if (filtered_len == 0) {
        status = register_chained_syscall(tracee, sysnum, fd, buf_addr, count, 0, 0, 0);
    } else {
        status = write_data(tracee, buf_addr, filtered, filtered_len);
        if (status == 0)
            poke_reg(tracee, SYSARG_RESULT, filtered_len);
    }
out:
    talloc_free(orig);
    talloc_free(filtered);
    return status;
}

HOT
int hidden_files_callback(Extension *restrict extension, ExtensionEvent event,
                          intptr_t data1 UNUSED, intptr_t data2 UNUSED) {
    if (UNLIKELY(!extension)) return -1;
    switch (event) {
    case INITIALIZATION: {
        static FilteredSysnum filtered_sysnums[] = {
            { PR_getdents,    FILTER_SYSEXIT },
            { PR_getdents64,  FILTER_SYSEXIT },
            FILTERED_SYSNUM_END,
        };
        extension->filtered_sysnums = filtered_sysnums;
        return 0;
    }
    case SYSCALL_CHAINED_EXIT:
    case SYSCALL_EXIT_END:
        return handle_getdents(TRACEE(extension));
    default:
        return 0;
    }
}