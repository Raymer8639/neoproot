#include <stdint.h>
#include <stdlib.h>
#include <linux/version.h>
#include <assert.h>
#include <sys/utsname.h>
#include <string.h>
#include <talloc.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <errno.h>
#include <linux/auxvec.h>
#include <linux/futex.h>
#include <sys/param.h>

#include "extension/extension.h"
#include "syscall/seccomp.h"
#include "syscall/sysnum.h"
#include "syscall/chain.h"
#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "tracee/abi.h"
#include "tracee/mem.h"
#include "execve/auxv.h"
#include "cli/note.h"
#include "arch.h"
#include "attribute.h"
#include "compat.h"

#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define ALWAYS_INLINE __attribute__((always_inline)) inline
#define HOT __attribute__((hot))

#define MAX_ARG_SHIFT 2
#define NONE {{0, 0, 0}}

typedef struct {
    int expected_release;
    word_t new_sysarg_num;
    struct {
        Reg sysarg;
        size_t nb_args;
        int offset;
    } shifts[MAX_ARG_SHIFT];
} Modif;

typedef struct {
    int actual_release;
    int virtual_release;
    struct utsname utsname;
    word_t hwcap;
} Config;

static ALWAYS_INLINE bool needs_kompat(const Config *restrict config, int expected_release) {
    if (UNLIKELY(!config)) return false;
    return (expected_release > config->actual_release && expected_release <= config->virtual_release);
}

static ALWAYS_INLINE bool modify_syscall(Tracee *restrict tracee, const Config *restrict config,
                                         const Modif *restrict modif) {
    if (UNLIKELY(!tracee || !config || !modif)) return false;
    if (!needs_kompat(config, modif->expected_release)) return false;
    word_t sysnum = detranslate_sysnum(get_abi(tracee), modif->new_sysarg_num);
    if (UNLIKELY(sysnum == SYSCALL_AVOIDER)) return false;
    set_sysnum(tracee, modif->new_sysarg_num);
    for (size_t i = 0; i < MAX_ARG_SHIFT; ++i) {
        Reg sysarg     = modif->shifts[i].sysarg;
        size_t nb_args = modif->shifts[i].nb_args;
        int offset     = modif->shifts[i].offset;
        for (size_t j = 0; j < nb_args; ++j) {
            word_t arg = peek_reg(tracee, CURRENT, sysarg + j);
            poke_reg(tracee, sysarg + j + offset, arg);
        }
    }
    return true;
}

static int parse_kernel_release(const char *release) {
    if (UNLIKELY(!release)) return 0;
    unsigned long major = 0, minor = 0, revision = 0;
    char *cursor = (char *)release;
    major = strtoul(cursor, &cursor, 10);
    if (*cursor == '.') {
        cursor++;
        minor = strtoul(cursor, &cursor, 10);
    }
    if (*cursor == '.') {
        cursor++;
        revision = strtoul(cursor, &cursor, 10);
    }
    return KERNEL_VERSION(major, minor, revision);
}

static ALWAYS_INLINE void discard_fd_flags(Tracee *restrict tracee, const Config *restrict config,
                                           int discarded_flags, int expected_release, Reg sysarg) {
    if (UNLIKELY(!tracee || !config)) return;
    if (!needs_kompat(config, expected_release)) return;
    word_t flags = peek_reg(tracee, CURRENT, sysarg);
    poke_reg(tracee, sysarg, flags & ~discarded_flags);
}

static HOT int handle_sysenter_end(Tracee *restrict tracee, Config *restrict config) {
    if (UNLIKELY(!tracee || !config)) return 0;
    switch (get_sysnum(tracee, ORIGINAL)) {
    case PR_accept4: {
        const Modif modif = { .expected_release = KERNEL_VERSION(2,6,28), .new_sysarg_num = PR_accept, .shifts = NONE };
        modify_syscall(tracee, config, &modif);
        return 0;
    }
    case PR_dup3: {
        const Modif modif = { .expected_release = KERNEL_VERSION(2,6,27), .new_sysarg_num = PR_dup2, .shifts = NONE };
        if (peek_reg(tracee, CURRENT, SYSARG_1) == peek_reg(tracee, CURRENT, SYSARG_2))
            return -EINVAL;
        modify_syscall(tracee, config, &modif);
        return 0;
    }
    case PR_epoll_create1: {
        const Modif modif = { .expected_release = KERNEL_VERSION(2,6,27), .new_sysarg_num = PR_epoll_create, .shifts = NONE };
        bool modified = modify_syscall(tracee, config, &modif);
        if (modified) poke_reg(tracee, SYSARG_1, 1);
        return 0;
    }
    case PR_epoll_pwait: {
        const Modif modif = { .expected_release = KERNEL_VERSION(2,6,19), .new_sysarg_num = PR_epoll_wait, .shifts = NONE };
        modify_syscall(tracee, config, &modif);
        return 0;
    }
    case PR_eventfd2: {
        const Modif modif = { .expected_release = KERNEL_VERSION(2,6,27), .new_sysarg_num = PR_eventfd, .shifts = NONE };
        bool modified = modify_syscall(tracee, config, &modif);
        if (modified) {
            word_t flags = peek_reg(tracee, CURRENT, SYSARG_2);
            if (flags & EFD_SEMAPHORE) return -EINVAL;
        }
        return 0;
    }
    case PR_faccessat: {
        const Modif modif = { .expected_release = KERNEL_VERSION(2,6,16), .new_sysarg_num = PR_access,
            .shifts = { { .sysarg = SYSARG_2, .nb_args = 2, .offset = -1 } } };
        modify_syscall(tracee, config, &modif);
        return 0;
    }
    case PR_fchmodat: {
        const Modif modif = { .expected_release = KERNEL_VERSION(2,6,16), .new_sysarg_num = PR_chmod,
            .shifts = { { .sysarg = SYSARG_2, .nb_args = 2, .offset = -1 } } };
        modify_syscall(tracee, config, &modif);
        return 0;
    }
    case PR_fchownat: {
        word_t flags = peek_reg(tracee, CURRENT, SYSARG_5);
        Modif modif = { .expected_release = KERNEL_VERSION(2,6,16),
            .shifts = { { .sysarg = SYSARG_2, .nb_args = 3, .offset = -1 } } };
        modif.new_sysarg_num = (flags & AT_SYMLINK_NOFOLLOW) ? PR_lchown : PR_chown;
        modify_syscall(tracee, config, &modif);
        return 0;
    }
    case PR_fcntl: {
        if (!needs_kompat(config, KERNEL_VERSION(2,6,24))) return 0;
        word_t command = peek_reg(tracee, ORIGINAL, SYSARG_2);
        if (command == F_DUPFD_CLOEXEC) poke_reg(tracee, SYSARG_2, F_DUPFD);
        return 0;
    }
    case PR_newfstatat:
    case PR_fstatat64: {
        word_t flags = peek_reg(tracee, CURRENT, SYSARG_4);
        if (flags & ~(AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT | AT_EMPTY_PATH | 0x6000))
            return -EINVAL;
        Modif modif = { .expected_release = KERNEL_VERSION(2,6,16),
            .shifts = { { .sysarg = SYSARG_2, .nb_args = 2, .offset = -1 } } };
        modif.new_sysarg_num = (flags & AT_SYMLINK_NOFOLLOW) ? PR_lstat : PR_stat;
        modify_syscall(tracee, config, &modif);
        return 0;
    }
    case PR_futex: {
        static bool warned = false;
        if (!needs_kompat(config, KERNEL_VERSION(2,6,22)) || config->actual_release == 0) return 0;
        word_t operation = peek_reg(tracee, CURRENT, SYSARG_2);
        if ((operation & FUTEX_PRIVATE_FLAG) == 0) return 0;
        if (!warned) {
            warned = true;
            note(tracee, WARNING, USER,
                 "kompat: this kernel doesn't support private futexes "
                 "and neoproot can't emulate them. Expect some troubles...");
        }
        poke_reg(tracee, SYSARG_2, operation & ~FUTEX_PRIVATE_FLAG);
        return 0;
    }
    case PR_futimesat: {
        const Modif modif = { .expected_release = KERNEL_VERSION(2,6,16), .new_sysarg_num = PR_utimes,
            .shifts = { { .sysarg = SYSARG_2, .nb_args = 2, .offset = -1 } } };
        modify_syscall(tracee, config, &modif);
        return 0;
    }
    case PR_inotify_init1: {
        const Modif modif = { .expected_release = KERNEL_VERSION(2,6,27), .new_sysarg_num = PR_inotify_init, .shifts = NONE };
        modify_syscall(tracee, config, &modif);
        return 0;
    }
    case PR_linkat: {
        word_t flags = peek_reg(tracee, CURRENT, SYSARG_5);
        if (flags & ~AT_SYMLINK_FOLLOW) return -EINVAL;
        const Modif modif = { .expected_release = KERNEL_VERSION(2,6,16), .new_sysarg_num = PR_link,
            .shifts = { { .sysarg = SYSARG_2, .nb_args = 1, .offset = -1 },
                        { .sysarg = SYSARG_4, .nb_args = 1, .offset = -2 } } };
        modify_syscall(tracee, config, &modif);
        return 0;
    }
    case PR_mkdirat: {
        const Modif modif = { .expected_release = KERNEL_VERSION(2,6,16), .new_sysarg_num = PR_mkdir,
            .shifts = { { .sysarg = SYSARG_2, .nb_args = 2, .offset = -1 } } };
        modify_syscall(tracee, config, &modif);
        return 0;
    }
    case PR_mknodat: {
        const Modif modif = { .expected_release = KERNEL_VERSION(2,6,16), .new_sysarg_num = PR_mknod,
            .shifts = { { .sysarg = SYSARG_2, .nb_args = 3, .offset = -1 } } };
        modify_syscall(tracee, config, &modif);
        return 0;
    }
    case PR_openat: {
        const Modif modif = { .expected_release = KERNEL_VERSION(2,6,16), .new_sysarg_num = PR_open,
            .shifts = { { .sysarg = SYSARG_2, .nb_args = 3, .offset = -1 } } };
        bool modified = modify_syscall(tracee, config, &modif);
        discard_fd_flags(tracee, config, O_CLOEXEC, KERNEL_VERSION(2,6,23),
                         modified ? SYSARG_2 : SYSARG_3);
        return 0;
    }
    case PR_open:
        discard_fd_flags(tracee, config, O_CLOEXEC, KERNEL_VERSION(2,6,23), SYSARG_2);
        return 0;
    case PR_pipe2: {
        const Modif modif = { .expected_release = KERNEL_VERSION(2,6,27), .new_sysarg_num = PR_pipe, .shifts = NONE };
        modify_syscall(tracee, config, &modif);
        return 0;
    }
    case PR_pselect6: {
        Modif modif = { .expected_release = KERNEL_VERSION(2,6,16), .shifts = NONE };
        modif.new_sysarg_num = PR_select;
        modify_syscall(tracee, config, &modif);
        return 0;
    }
    case PR_readlinkat: {
        const Modif modif = { .expected_release = KERNEL_VERSION(2,6,16), .new_sysarg_num = PR_readlink,
            .shifts = { { .sysarg = SYSARG_2, .nb_args = 3, .offset = -1 } } };
        modify_syscall(tracee, config, &modif);
        return 0;
    }
    case PR_renameat: {
        const Modif modif = { .expected_release = KERNEL_VERSION(2,6,16), .new_sysarg_num = PR_rename,
            .shifts = { { .sysarg = SYSARG_2, .nb_args = 1, .offset = -1 },
                        { .sysarg = SYSARG_4, .nb_args = 1, .offset = -2 } } };
        modify_syscall(tracee, config, &modif);
        return 0;
    }
    case PR_signalfd4: {
        const Modif modif = { .expected_release = KERNEL_VERSION(2,6,27), .new_sysarg_num = PR_signalfd, .shifts = NONE };
        bool modified = modify_syscall(tracee, config, &modif);
        if (modified) poke_reg(tracee, SYSARG_4, 0);
        return 0;
    }
    case PR_socket:
    case PR_socketpair:
    case PR_timerfd_create:
        discard_fd_flags(tracee, config, O_CLOEXEC | O_NONBLOCK, KERNEL_VERSION(2,6,27), SYSARG_2);
        return 0;
    case PR_symlinkat: {
        const Modif modif = { .expected_release = KERNEL_VERSION(2,6,16), .new_sysarg_num = PR_symlink,
            .shifts = { { .sysarg = SYSARG_3, .nb_args = 1, .offset = -1 } } };
        modify_syscall(tracee, config, &modif);
        return 0;
    }
    case PR_unlinkat: {
        word_t flags = peek_reg(tracee, CURRENT, SYSARG_3);
        Modif modif = { .expected_release = KERNEL_VERSION(2,6,16),
            .shifts = { { .sysarg = SYSARG_2, .nb_args = 1, .offset = -1 } } };
        modif.new_sysarg_num = (flags & AT_REMOVEDIR) ? PR_rmdir : PR_unlink;
        modify_syscall(tracee, config, &modif);
        return 0;
    }
    default:
        return 0;
    }
}

static void adjust_elf_auxv(Tracee *restrict tracee, Config *restrict config) {
    if (UNLIKELY(!tracee || !config)) return;
    word_t vectors_address = 0;
    ElfAuxVector *vectors = fetch_elf_aux_vectors(tracee, vectors_address);
    if (UNLIKELY(!vectors)) return;
    for (ElfAuxVector *vector = vectors; vector->type != AT_NULL; ++vector) {
        switch (vector->type) {
        case AT_SYSINFO_EHDR:
        case AT_SYSINFO:
            vector->type = AT_IGNORE;
            vector->value = 0;
            break;
        case AT_HWCAP:
            if (config->hwcap != (word_t)-1)
                vector->value = config->hwcap;
            break;
        default: break;
        }
    }
    push_elf_aux_vectors(tracee, vectors, vectors_address);
}

static ALWAYS_INLINE void emulate_fd_flags(Tracee *restrict tracee, word_t fd, Reg sysarg, int emulated_flags) {
    if (UNLIKELY(!tracee || fd < 0)) return;
    word_t flags = peek_reg(tracee, ORIGINAL, sysarg);
    if (flags == 0) return;
    if ((emulated_flags & flags & O_CLOEXEC) != 0)
        register_chained_syscall(tracee, PR_fcntl, fd, F_SETFD, FD_CLOEXEC, 0, 0, 0);
    if ((emulated_flags & flags & O_NONBLOCK) != 0)
        register_chained_syscall(tracee, PR_fcntl, fd, F_SETFL, O_NONBLOCK, 0, 0, 0);
    force_chain_final_result(tracee, peek_reg(tracee, CURRENT, SYSARG_RESULT));
}

static HOT int handle_sysexit_end(Tracee *restrict tracee, Config *restrict config) {
    if (UNLIKELY(!tracee || !config)) return 0;
    word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
    word_t sysnum = get_sysnum(tracee, ORIGINAL);
    int status = (int)result;
    if (status < 0) return 0;
    switch (sysnum) {
    case PR_uname: {
        word_t address = peek_reg(tracee, ORIGINAL, SYSARG_1);
        status = write_data(tracee, address, &config->utsname, sizeof(config->utsname));
        return status < 0 ? status : 0;
    }
    case PR_setdomainname:
    case PR_sethostname: {
        word_t address = peek_reg(tracee, ORIGINAL, SYSARG_1);
        word_t length = peek_reg(tracee, ORIGINAL, SYSARG_2);
        char *name = (sysnum == PR_setdomainname) ? config->utsname.domainname : config->utsname.nodename;
        if (length > sizeof(config->utsname.domainname) - 1) return -EINVAL;
        status = read_data(tracee, name, address, length);
        if (status < 0) return status;
        name[length] = '\0';
        return 0;
    }
    case PR_accept4:
        if (get_sysnum(tracee, MODIFIED) == PR_accept)
            emulate_fd_flags(tracee, result, SYSARG_4, O_CLOEXEC | O_NONBLOCK);
        return 0;
    case PR_dup3:
        if (get_sysnum(tracee, MODIFIED) == PR_dup2)
            emulate_fd_flags(tracee, peek_reg(tracee, ORIGINAL, SYSARG_2), SYSARG_3, O_CLOEXEC | O_NONBLOCK);
        return 0;
    case PR_epoll_create1:
        if (get_sysnum(tracee, MODIFIED) == PR_epoll_create)
            emulate_fd_flags(tracee, result, SYSARG_1, O_CLOEXEC | O_NONBLOCK);
        return 0;
    case PR_eventfd2:
        if (get_sysnum(tracee, MODIFIED) == PR_eventfd)
            emulate_fd_flags(tracee, result, SYSARG_2, O_CLOEXEC | O_NONBLOCK);
        return 0;
    case PR_fcntl: {
        if (!needs_kompat(config, KERNEL_VERSION(2,6,24))) return 0;
        word_t command = peek_reg(tracee, ORIGINAL, SYSARG_2);
        if (command != F_DUPFD_CLOEXEC) return 0;
        register_chained_syscall(tracee, PR_fcntl, result, F_SETFD, FD_CLOEXEC, 0, 0, 0);
        force_chain_final_result(tracee, peek_reg(tracee, CURRENT, SYSARG_RESULT));
        return 0;
    }
    case PR_inotify_init1:
        if (get_sysnum(tracee, MODIFIED) == PR_inotify_init)
            emulate_fd_flags(tracee, result, SYSARG_1, O_CLOEXEC | O_NONBLOCK);
        return 0;
    case PR_open:
        if (needs_kompat(config, KERNEL_VERSION(2,6,23)))
            emulate_fd_flags(tracee, result, SYSARG_2, O_CLOEXEC);
        return 0;
    case PR_openat:
        if (needs_kompat(config, KERNEL_VERSION(2,6,23)))
            emulate_fd_flags(tracee, result, SYSARG_3, O_CLOEXEC);
        return 0;
    case PR_pipe2: {
        if (get_sysnum(tracee, MODIFIED) != PR_pipe) return 0;
        int fds[2];
        status = read_data(tracee, fds, peek_reg(tracee, MODIFIED, SYSARG_1), sizeof(fds));
        if (status < 0) return 0;
        emulate_fd_flags(tracee, fds[0], SYSARG_2, O_CLOEXEC | O_NONBLOCK);
        emulate_fd_flags(tracee, fds[1], SYSARG_2, O_CLOEXEC | O_NONBLOCK);
        return 0;
    }
    case PR_signalfd4:
        if (get_sysnum(tracee, MODIFIED) == PR_signalfd)
            emulate_fd_flags(tracee, result, SYSARG_4, O_CLOEXEC | O_NONBLOCK);
        return 0;
    case PR_socket:
    case PR_timerfd_create:
        if (needs_kompat(config, KERNEL_VERSION(2,6,27)))
            emulate_fd_flags(tracee, result, SYSARG_2, O_CLOEXEC | O_NONBLOCK);
        return 0;
    case PR_socketpair: {
        if (!needs_kompat(config, KERNEL_VERSION(2,6,27))) return 0;
        int fds[2];
        status = read_data(tracee, fds, peek_reg(tracee, MODIFIED, SYSARG_4), sizeof(fds));
        if (status < 0) return 0;
        emulate_fd_flags(tracee, fds[0], SYSARG_2, O_CLOEXEC | O_NONBLOCK);
        emulate_fd_flags(tracee, fds[1], SYSARG_2, O_CLOEXEC | O_NONBLOCK);
        return 0;
    }
    default:
        return 0;
    }
}

static int parse_utsname(Config *restrict config, const char *string) {
    if (UNLIKELY(!config || !string)) return -1;
    struct utsname utsname;
    int status = uname(&utsname);
    if (status < 0 || getenv("PROOT_FORCE_KOMPAT") != NULL)
        config->actual_release = 0;
    else
        config->actual_release = parse_kernel_release(utsname.release);
    if (string[0] == '\\') {
        const char *start, *end;
        char *end2;
        end = string;
#define PARSE(field) do { \
    size_t length; \
    start = end + 1; \
    end = strchr(start, '\\'); \
    if (!end) { note(NULL, ERROR, USER, "can't find %s field in utsname config", #field); return -1; } \
    length = end - start; \
    length = MIN(length, sizeof(config->utsname.field) - 1); \
    strncpy(config->utsname.field, start, length); \
    config->utsname.field[length] = '\0'; \
} while(0)
        PARSE(sysname);
        PARSE(nodename);
        PARSE(release);
        PARSE(version);
        PARSE(machine);
        PARSE(domainname);
#undef PARSE
        errno = 0;
        config->hwcap = strtol(end + 1, &end2, 16);
        if (errno != 0 || end2[0] != '\\') {
            note(NULL, ERROR, USER, "can't parse hwcap field in utsname config");
            return -1;
        }
    } else {
        memcpy(&config->utsname, &utsname, sizeof(config->utsname));
        size_t length = MIN(strlen(string), sizeof(config->utsname.release) - 1);
        strncpy(config->utsname.release, string, length);
        config->utsname.release[length] = '\0';
        config->hwcap = (word_t)-1;
    }
    config->virtual_release = parse_kernel_release(config->utsname.release);
    return 0;
}

static FilteredSysnum filtered_sysnums[] = {
    { PR_accept4,       FILTER_SYSEXIT },
    { PR_dup3,          FILTER_SYSEXIT },
    { PR_epoll_create1, FILTER_SYSEXIT },
    { PR_epoll_pwait,   0 },
    { PR_eventfd2,      FILTER_SYSEXIT },
    { PR_execve,        FILTER_SYSEXIT },
    { PR_faccessat,     0 },
    { PR_fchmodat,      0 },
    { PR_fchownat,      0 },
    { PR_fcntl,         FILTER_SYSEXIT },
    { PR_fstatat64,     0 },
    { PR_futimesat,     0 },
    { PR_futex,         0 },
    { PR_inotify_init1, FILTER_SYSEXIT },
    { PR_linkat,        0 },
    { PR_mkdirat,       0 },
    { PR_mknodat,       0 },
    { PR_newfstatat,    0 },
    { PR_open,          FILTER_SYSEXIT },
    { PR_openat,        FILTER_SYSEXIT },
    { PR_pipe2,         FILTER_SYSEXIT },
    { PR_pselect6,      0 },
    { PR_readlinkat,    0 },
    { PR_renameat,      0 },
    { PR_setdomainname, FILTER_SYSEXIT },
    { PR_sethostname,   FILTER_SYSEXIT },
    { PR_signalfd4,     FILTER_SYSEXIT },
    { PR_socket,        FILTER_SYSEXIT },
    { PR_socketpair,    FILTER_SYSEXIT },
    { PR_symlinkat,     0 },
    { PR_timerfd_create,FILTER_SYSEXIT },
    { PR_uname,         FILTER_SYSEXIT },
    { PR_unlinkat,      0 },
    FILTERED_SYSNUM_END,
};

int kompat_callback(Extension *extension, ExtensionEvent event, intptr_t data1, intptr_t data2 UNUSED) {
    if (UNLIKELY(!extension)) return -EINVAL;
    switch (event) {
    case INITIALIZATION: {
        Config *config = talloc_zero(extension, Config);
        if (UNLIKELY(!config)) return -1;
        int status = parse_utsname(config, (const char *)data1);
        if (UNLIKELY(status < 0)) return -1;
        extension->config = config;
        extension->filtered_sysnums = filtered_sysnums;
        return 0;
    }
    case SYSCALL_ENTER_END: {
        if ((int)data1 < 0) return 0;
        Tracee *tracee = TRACEE(extension);
        Config *config = talloc_get_type_abort(extension->config, Config);
        return handle_sysenter_end(tracee, config);
    }
    case SYSCALL_EXIT_END: {
        Tracee *tracee = TRACEE(extension);
        Config *config = talloc_get_type_abort(extension->config, Config);
        return handle_sysexit_end(tracee, config);
    }
    case SYSCALL_EXIT_START: {
        Tracee *tracee = TRACEE(extension);
        Config *config = talloc_get_type_abort(extension->config, Config);
        word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
        word_t sysnum = get_sysnum(tracee, ORIGINAL);
        if ((int)result >= 0 && sysnum == PR_execve)
            adjust_elf_auxv(tracee, config);
        return 0;
    }
    default:
        return 0;
    }
}