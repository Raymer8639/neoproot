#include "extension/extension.h"
#include "tracee/mem.h"
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
    return __builtin_memcmp(path, root, root_len) == 0;
}

static HOT int handle_getdents(Tracee *restrict tracee) {
    if (UNLIKELY(!tracee)) return -1;
    word_t sysnum = get_sysnum(tracee, ORIGINAL);
    if (UNLIKELY(sysnum != PR_getdents && sysnum != PR_getdents64))
        return 0;

    word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
    if (UNLIKELY((long)result <= 0))
        return (int)result;

    word_t fd = peek_reg(tracee, ORIGINAL, SYSARG_1);
    word_t buf_addr = peek_reg(tracee, CURRENT, SYSARG_2);
    word_t count = peek_reg(tracee, CURRENT, SYSARG_3);
    if (UNLIKELY(count == 0 || count > PATH_MAX * 1024))
        return 0;

    char path[PATH_MAX];
    if (UNLIKELY(readlink_proc_pid_fd(tracee->pid, fd, path) < 0))
        return 0;
    if (UNLIKELY(!belongs_to_guestfs_fast(tracee, path)))
        return 0;

    size_t res = (size_t)result;
    char orig_data[res];
    if (UNLIKELY(read_data(tracee, orig_data, buf_addr, res) < 0))
        return -1;

    char filtered_data[res];
    char *orig = orig_data;
    char *filt = filtered_data;
    size_t filt_len = 0;

    if (sysnum == PR_getdents64) {
        while (orig < orig_data + res) {
            struct linux_dirent64 *d = (struct linux_dirent64 *)orig;
            if (LIKELY(!has_prefix(HIDDEN_PREFIX, d->d_name, HIDDEN_PREFIX_LEN))) {
                size_t reclen = d->d_reclen;
                __builtin_memcpy(filt, orig, reclen);
                filt += reclen;
                filt_len += reclen;
            }
            orig += d->d_reclen;
        }
    } else {
        while (orig < orig_data + res) {
            struct linux_dirent *d = (struct linux_dirent *)orig;
            if (LIKELY(!has_prefix(HIDDEN_PREFIX, d->d_name, HIDDEN_PREFIX_LEN))) {
                size_t reclen = d->d_reclen;
                __builtin_memcpy(filt, orig, reclen);
                filt += reclen;
                filt_len += reclen;
            }
            orig += d->d_reclen;
        }
    }

    if (UNLIKELY(filt_len == 0)) {
        register_chained_syscall(tracee, sysnum,
            peek_reg(tracee, ORIGINAL, SYSARG_1),
            buf_addr, count, 0, 0, 0);
    } else {
        if (UNLIKELY(write_data(tracee, buf_addr, filtered_data, filt_len) < 0))
            return -1;
        poke_reg(tracee, SYSARG_RESULT, (word_t)filt_len);
    }
    return 0;
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