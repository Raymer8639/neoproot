#ifndef NEOPROOT_COMPAT_POLICY_H
#define NEOPROOT_COMPAT_POLICY_H
#include <stdbool.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include "compat.h"
/* Linux requires unused arguments to be zero for the no_new_privs API. */
static inline bool valid_no_new_privs_request(unsigned long option,
        unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
    return arg3 == 0 && arg4 == 0 && arg5 == 0 &&
        ((option == PR_GET_NO_NEW_PRIVS && arg2 == 0) ||
         (option == PR_SET_NO_NEW_PRIVS && arg2 == 1));
}
/* A NULL pointer must retain its syscall-specific kernel error semantics. */
static inline bool empty_path_uses_guest_cwd(int dirfd, const char *path,
        uintptr_t address, unsigned long flags)
{
    return path[0] == '\0' && address != 0 && dirfd == AT_FDCWD &&
        (flags & AT_EMPTY_PATH) != 0;
}
#endif
