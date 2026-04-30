#include <cstddef>
#include <cstdint>
#include <cinttypes>
#include <climits>
#include <cstring>
#include <cassert>
#include <cerrno>

#include <sys/types.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/uio.h>

#ifndef NT_PRSTATUS
#define NT_PRSTATUS 1
#endif

#ifndef NT_ARM_SYSTEM_CALL
#define NT_ARM_SYSTEM_CALL 0x400
#endif

#include <linux/elf.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "arch.h"
#include "syscall/sysnum.h"
#include "tracee/reg.h"
#include "tracee/abi.h"
#include "cli/note.h"
#include "compat.h"

#ifdef __cplusplus
}
#endif

#if !defined(ARCH_ARM64)
# error "Only ARM64 architecture is supported"
#endif

#define USER_REGS_OFFSET(reg_name) offsetof(struct user_regs_struct, reg_name)

static constexpr off_t get_reg_offset(Reg reg) noexcept
{
    switch (reg) {
        case SYSARG_NUM:    return USER_REGS_OFFSET(regs[8]);
        case SYSARG_1:      return USER_REGS_OFFSET(regs[0]);
        case SYSARG_2:      return USER_REGS_OFFSET(regs[1]);
        case SYSARG_3:      return USER_REGS_OFFSET(regs[2]);
        case SYSARG_4:      return USER_REGS_OFFSET(regs[3]);
        case SYSARG_5:      return USER_REGS_OFFSET(regs[4]);
        case SYSARG_6:      return USER_REGS_OFFSET(regs[5]);
        case SYSARG_RESULT: return USER_REGS_OFFSET(regs[0]);
        case STACK_POINTER: return USER_REGS_OFFSET(sp);
        case INSTR_POINTER: return USER_REGS_OFFSET(pc);
        case USERARG_1:     return USER_REGS_OFFSET(regs[0]);
        default:            return 0;
    }
}

static inline word_t *get_reg_ptr(Tracee *tracee, RegVersion version, Reg reg)
{
    off_t offset = get_reg_offset(reg);
    return reinterpret_cast<word_t *>(
        reinterpret_cast<uint8_t *>(&tracee->_regs[version]) + offset
    );
}

#define REG(tracee, version, reg) (*get_reg_ptr(tracee, version, reg))

extern "C" word_t peek_reg(const Tracee *tracee, RegVersion version, Reg reg)
{
    assert(version < NB_REG_VERSION);
    return REG(const_cast<Tracee *>(tracee), version, reg);
}

extern "C" void poke_reg(Tracee *tracee, Reg reg, word_t value)
{
    word_t &r = REG(tracee, CURRENT, reg);
    if (r == value)
        return;

    r = value;
    tracee->_regs_were_changed = true;
}

extern "C" void print_current_regs(Tracee *tracee, int verbose_level, const char *message)
{
    if (tracee->verbose < verbose_level || !message)
        return;

    note(tracee, INFO, INTERNAL,
         "vpid %" PRIu64 ": %s: %s(0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx) = 0x%lx [0x%lx, %d]",
         tracee->vpid, message,
         stringify_sysnum(get_sysnum(tracee, CURRENT)),
         peek_reg(tracee, CURRENT, SYSARG_1),
         peek_reg(tracee, CURRENT, SYSARG_2),
         peek_reg(tracee, CURRENT, SYSARG_3),
         peek_reg(tracee, CURRENT, SYSARG_4),
         peek_reg(tracee, CURRENT, SYSARG_5),
         peek_reg(tracee, CURRENT, SYSARG_6),
         peek_reg(tracee, CURRENT, SYSARG_RESULT),
         peek_reg(tracee, CURRENT, STACK_POINTER),
         get_abi(tracee));
}

extern "C" void save_current_regs(Tracee *tracee, RegVersion version)
{
    if (version == ORIGINAL)
        tracee->_regs_were_changed = false;

    memcpy(&tracee->_regs[version],
           &tracee->_regs[CURRENT],
           sizeof(tracee->_regs[CURRENT]));
}

extern "C" int fetch_regs(Tracee *tracee)
{
    struct iovec regs = {
        .iov_base = &tracee->_regs[CURRENT],
        .iov_len  = sizeof(tracee->_regs[CURRENT])
    };

    int status = ptrace(PTRACE_GETREGSET, tracee->pid, NT_PRSTATUS, &regs);
    return status < 0 ? -errno : 0;
}

extern "C" int push_specific_regs(Tracee *tracee, bool including_sysnum)
{
    if (!tracee->_regs_were_changed &&
        !(tracee->restore_original_regs &&
          tracee->restore_original_regs_after_seccomp_event)) {
        return 0;
    }

    if (tracee->restore_original_regs) {
        RegVersion restore_from = ORIGINAL;

        if (tracee->restore_original_regs_after_seccomp_event) {
            restore_from = ORIGINAL_SECCOMP_REWRITE;
            tracee->restore_original_regs_after_seccomp_event = false;
        }

#define RESTORE(r)                                  \
        do {                                        \
            if (get_reg_offset(SYSARG_RESULT) != get_reg_offset(r)) { \
                REG(tracee, CURRENT, r) = REG(tracee, restore_from, r); \
            }                                       \
        } while (0)

        RESTORE(SYSARG_NUM);
        RESTORE(SYSARG_1);
        RESTORE(SYSARG_2);
        RESTORE(SYSARG_3);
        RESTORE(SYSARG_4);
        RESTORE(SYSARG_5);
        RESTORE(SYSARG_6);
        RESTORE(STACK_POINTER);

#undef RESTORE
    }

    int status = 0;

    if (including_sysnum) {
        word_t current_sysnum = REG(tracee, CURRENT, SYSARG_NUM);
        if (current_sysnum != REG(tracee, ORIGINAL, SYSARG_NUM)) {
            struct iovec syscall_regs = {
                .iov_base = &current_sysnum,
                .iov_len  = sizeof(current_sysnum)
            };

            status = ptrace(PTRACE_SETREGSET,
                            tracee->pid,
                            NT_ARM_SYSTEM_CALL,
                            &syscall_regs);
            if (status < 0)
                return -errno;
        }
    }

    struct iovec regs = {
        .iov_base = &tracee->_regs[CURRENT],
        .iov_len  = sizeof(tracee->_regs[CURRENT])
    };

    status = ptrace(PTRACE_SETREGSET, tracee->pid, NT_PRSTATUS, &regs);
    return status < 0 ? -errno : 0;
}

extern "C" int push_regs(Tracee *tracee)
{
    return push_specific_regs(tracee, true);
}

extern "C" word_t get_systrap_size(Tracee *tracee)
{
    (void)tracee;
    return SYSTRAP_SIZE;
}
