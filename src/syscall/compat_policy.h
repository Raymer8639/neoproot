#ifndef NEOPROOT_COMPAT_POLICY_H
#define NEOPROOT_COMPAT_POLICY_H
#include <stdbool.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/prctl.h>
/* compat.h replaces PTRACE_* names with macros, so <sys/ptrace.h> has to be
 * seen first whenever this header is the entry point of a translation unit. */
#include <sys/ptrace.h>
#include "compat.h"
#include "syscall/sysnum.h"   /* Sysnum, word_t */
/* Linux requires unused arguments to be zero for the no_new_privs API. */
static inline bool valid_no_new_privs_request(unsigned long option,
        unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
    return arg3 == 0 && arg4 == 0 && arg5 == 0 &&
        ((option == PR_GET_NO_NEW_PRIVS && arg2 == 0) ||
         (option == PR_SET_NO_NEW_PRIVS && arg2 == 1));
}
/* When the guest's own PR_SET_NO_NEW_PRIVS may be committed to the virtual
 * state neoproot answers PR_GET_NO_NEW_PRIVS from.
 *
 * neoproot sets the *real* flag before the guest program is execve'd (our
 * seccomp filter requires it), so the real flag is always 1 and reading it
 * tells us nothing about what the guest asked for.  The guest's intent is
 * therefore recorded exactly once, after the kernel really accepted the SET:
 *
 *   - entering the syscall only proves the guest *wants* it: a seccomp filter
 *     the guest installed itself can make the real SET fail with EPERM.  If we
 *     committed at syscall entry, PR_GET_NO_NEW_PRIVS would then lie (guest
 *     sees 1 while the real flag is 0) and tools that refuse to run once
 *     no_new_privs is set (sudo-rs and friends) would behave differently.
 *   - a syscall PRoot rewrote or cancelled never reached the kernel, so a 0 in
 *     the result register is not evidence either: MODIFIED must still say
 *     prctl.
 *   - the loader calls SET before the initial execve, which is neoproot's own
 *     doing, not the guest's (seen_execve is still false).
 *
 * Arguments are the guest's original ones, so the option/argument tuple is
 * validated exactly like the kernel validates it (EINVAL otherwise). */
static inline bool no_new_privs_set_committed(unsigned long option,
        unsigned long arg2, unsigned long arg3, unsigned long arg4,
        unsigned long arg5, Sysnum modified_sysnum, word_t syscall_result,
        bool seen_execve)
{
    if (!seen_execve || modified_sysnum != PR_prctl || syscall_result != 0)
        return false;
    return option == PR_SET_NO_NEW_PRIVS
        && valid_no_new_privs_request(option, arg2, arg3, arg4, arg5);
}
/* A NULL pointer must retain its syscall-specific kernel error semantics. */
static inline bool empty_path_uses_guest_cwd(int dirfd, const char *path,
        uintptr_t address, unsigned long flags)
{
    return path[0] == '\0' && address != 0 && dirfd == AT_FDCWD &&
        (flags & AT_EMPTY_PATH) != 0;
}
#endif
