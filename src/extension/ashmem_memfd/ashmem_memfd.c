#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <linux/ashmem.h>
#include <linux/memfd.h>
#include <string.h>
#include <errno.h>

#include <talloc.h>

#include "extension/extension.h"
#include "path/path.h"
#include "tracee/mem.h"
#include "tracee/seccomp.h"
#include "syscall/chain.h"
#include "syscall/syscall.h"

#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define ALWAYS_INLINE __attribute__((always_inline, flatten))
#define HOT __attribute__((hot))

typedef enum {
    CS_IDLE,
    CS_WAIT_STAT,
    CS_WAIT_IOCTL
} ChainState;

typedef struct {
    int memfd_avail;
    ChainState state;
    int fd;
    word_t st_size_addr;
} AshmemState;

static FilteredSysnum filtered_sysnums[] = {
    { PR_memfd_create, 0 },
    { PR_ftruncate,    0 },
    { PR_ftruncate64,  0 },
    { PR_fstat,        0 },
    { PR_fstat64,      0 },
    { PR_fstatat64,    0 },
    FILTERED_SYSNUM_END,
};

static ALWAYS_INLINE int probe_memfd(void) {
    const char *env = getenv("PROOT_ASSUME_MEMFD_UNSUPPORTED");
    if (LIKELY(!env)) goto probe;
    if (__builtin_strcmp(env, "1") == 0) return 0;
    if (__builtin_strcmp(env, "0") == 0) return 1;
probe:
    int fd = syscall(__NR_memfd_create, "probe", MFD_CLOEXEC);
    if (fd >= 0) { close(fd); return 1; }
    return 0;
}

static ALWAYS_INLINE int is_ashmem(Tracee *restrict tracee, int fd) {
    char buf[16];
    if (UNLIKELY(readlink_proc_pid_fd(tracee->pid, fd, buf) < 0)) return 0;
    return __builtin_strcmp(buf, "/dev/ashmem") == 0;
}

static ALWAYS_INLINE void handle_fstat_enter(Extension *restrict ext, Tracee *restrict tracee,
                                             int fd, Reg addr_reg) {
    if (UNLIKELY(!is_ashmem(tracee, fd))) return;
    AshmemState *s = (AshmemState *)ext->config;
    s->state = CS_WAIT_STAT;
    s->fd = fd;
    s->st_size_addr = peek_reg(tracee, CURRENT, addr_reg) + offsetof(struct stat, st_size);
    tracee->restart_how = PTRACE_SYSCALL;
}

static ALWAYS_INLINE int handle_memfd_create(Extension *restrict ext, Tracee *restrict tracee,
                                             int from_sigsys) {
    AshmemState *s = (AshmemState *)ext->config;
    if (LIKELY(s->memfd_avail)) return 0;
    word_t flags = peek_reg(tracee, CURRENT, SYSARG_2);
    set_sysnum(tracee, PR_openat);
    poke_reg(tracee, SYSARG_1, AT_FDCWD);
    set_sysarg_data(tracee, "/dev/ashmem", 12, SYSARG_2);
    poke_reg(tracee, SYSARG_3, O_RDWR | ((flags & MFD_CLOEXEC) ? O_CLOEXEC : 0));
    poke_reg(tracee, SYSARG_4, 0);
    if (from_sigsys) {
        restart_syscall_after_seccomp(tracee);
        return 2;
    }
    return 0;
}

static HOT ALWAYS_INLINE void handle_syscall_enter(Extension *restrict ext) {
    Tracee *tracee = TRACEE(ext);
    int num = get_sysnum(tracee, CURRENT);
    switch (num) {
    case PR_memfd_create:
        handle_memfd_create(ext, tracee, 0);
        break;
    case PR_ftruncate:
    case PR_ftruncate64: {
        int fd = peek_reg(tracee, CURRENT, SYSARG_1);
        if (is_ashmem(tracee, fd)) {
            word_t sz = peek_reg(tracee, CURRENT, SYSARG_2);
            set_sysnum(tracee, PR_ioctl);
            poke_reg(tracee, SYSARG_2, ASHMEM_SET_SIZE);
            poke_reg(tracee, SYSARG_3, sz);
        }
        break;
    }
    case PR_fstat:
    case PR_fstat64:
        handle_fstat_enter(ext, tracee, peek_reg(tracee, CURRENT, SYSARG_1), SYSARG_2);
        break;
    case PR_fstatat64: {
        int fd = peek_reg(tracee, CURRENT, SYSARG_1);
        word_t path = peek_reg(tracee, CURRENT, SYSARG_2);
        if (LIKELY(fd >= 0 && path && !peek_int8(tracee, path)))
            handle_fstat_enter(ext, tracee, fd, SYSARG_3);
        break;
    }
    default:
        break;
    }
}

static ALWAYS_INLINE void handle_fstat_exit(Extension *restrict ext) {
    Tracee *tracee = TRACEE(ext);
    AshmemState *s = (AshmemState *)ext->config;
    if (UNLIKELY(peek_reg(tracee, CURRENT, SYSARG_RESULT) != 0)) {
        s->state = CS_IDLE;
        return;
    }
    register_chained_syscall(tracee, PR_ioctl, s->fd, ASHMEM_GET_SIZE, 0, 0, 0, 0);
    s->state = CS_WAIT_IOCTL;
}

static ALWAYS_INLINE void handle_chained_exit(Extension *restrict ext) {
    Tracee *tracee = TRACEE(ext);
    AshmemState *s = (AshmemState *)ext->config;
    if (LIKELY(s->state == CS_WAIT_IOCTL)) {
        word_t sz = peek_reg(tracee, CURRENT, SYSARG_RESULT);
        poke_word(tracee, s->st_size_addr, sz);
        poke_reg(tracee, SYSARG_RESULT, 0);
        s->state = CS_IDLE;
    }
}

HOT
int ashmem_memfd_callback(Extension *ext, ExtensionEvent ev, intptr_t data1, intptr_t data2 UNUSED) {
    if (UNLIKELY(!ext)) return -EINVAL;
    Tracee *tracee = TRACEE(ext);
    switch (ev) {
    case INITIALIZATION: {
        AshmemState *s = talloc(ext, AshmemState);
        if (UNLIKELY(!s)) return -1;
        s->memfd_avail = probe_memfd();
        s->state = CS_IDLE;
        ext->config = s;
        ext->filtered_sysnums = filtered_sysnums;
        return 0;
    }
    case INHERIT_PARENT:
        return 1;
    case INHERIT_CHILD: {
        Extension *parent = (Extension *)data1;
        AshmemState *osp = (AshmemState *)parent->config;
        AshmemState *s = talloc(ext, AshmemState);
        if (UNLIKELY(!s)) return -1;
        s->memfd_avail = osp->memfd_avail;
        s->state = CS_IDLE;
        ext->config = s;
        return 0;
    }
    case SYSCALL_ENTER_END:
        handle_syscall_enter(ext);
        return 0;
    case SYSCALL_EXIT_START: {
        AshmemState *s = (AshmemState *)ext->config;
        if (LIKELY(s->state == CS_WAIT_STAT))
            handle_fstat_exit(ext);
        return 0;
    }
    case SYSCALL_CHAINED_EXIT:
        handle_chained_exit(ext);
        return 0;
    case SIGSYS_OCC:
        if (get_sysnum(tracee, CURRENT) == PR_memfd_create)
            return handle_memfd_create(ext, tracee, 1);
        return 0;
    default:
        return 0;
    }
}