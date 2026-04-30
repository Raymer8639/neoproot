#include <stdbool.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "tracee/mem.h"
#include "tracee/abi.h"
#include "cli/note.h"

#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define ALWAYS_INLINE __attribute__((always_inline, flatten))

int translate_setrlimit_exit(const Tracee *restrict tracee, bool is_prlimit) {
    struct rlimit64 proot_stack;
    word_t resource, address;
    rlim_t tracee_stack_limit;
    Reg sysarg;
    int status;

    sysarg = is_prlimit ? SYSARG_2 : SYSARG_1;

    resource = peek_reg(tracee, ORIGINAL, sysarg);
    if (UNLIKELY(resource != RLIMIT_STACK))
        return 0;

    address = peek_reg(tracee, ORIGINAL, sysarg + 1);

    if (is_prlimit) {
        if (UNLIKELY(address == 0))
            return 0;
        tracee_stack_limit = peek_uint64(tracee, address);
    } else {
        // 仅64位，无32位兼容
        tracee_stack_limit = (rlim_t)peek_word(tracee, address);
    }
    if (UNLIKELY(errno != 0))
        return -errno;

    status = prlimit64(0, RLIMIT_STACK, NULL, &proot_stack);
    if (UNLIKELY(status < 0)) {
        VERBOSE(tracee, 1, "can't get stack limit.");
        return 0;
    }

    if (LIKELY(proot_stack.rlim_cur >= tracee_stack_limit))
        return 0;

    proot_stack.rlim_cur = tracee_stack_limit;
    status = prlimit64(0, RLIMIT_STACK, &proot_stack, NULL);
    if (UNLIKELY(status < 0)) {
        VERBOSE(tracee, 1, "can't set stack limit.");
        return 0;
    }

    VERBOSE(tracee, 1, "stack soft limit increased to %llu bytes",
            (unsigned long long)proot_stack.rlim_cur);
    return 0;
}