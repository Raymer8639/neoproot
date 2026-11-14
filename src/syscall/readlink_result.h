#ifndef NEOPROOT_READLINK_RESULT_H
#define NEOPROOT_READLINK_RESULT_H
#include <errno.h>
#include <limits.h>
#include <sys/uio.h>
#include <sys/ptrace.h>
#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "tracee/mem.h"
/* User output must remain subject to the tracee's write protections. Ptrace
 * POKEDATA deliberately bypasses them, so never use its write_data fallback. */
static inline int write_readlink_output(Tracee *tracee, word_t target,
        const void *source, word_t size)
{
    if (size == 0)
        return 0;
    struct iovec local = { .iov_base = (void *)source, .iov_len = size };
    struct iovec remote = { .iov_base = (void *)target, .iov_len = size };
    ssize_t written = process_vm_writev(tracee->pid, &local, 1, &remote, 1, 0);
    return written == (ssize_t)size ? 0 : -EFAULT;
}
/* The kernel must not expose a longer host target in bytes beyond the final
 * guest result. Stage its output below the held stack pointer, then write only
 * the final byte count to the caller. Existing readlink exit stops suffice. */
static inline int prepare_readlink_output(Tracee *tracee, Reg output_reg, Reg size_reg)
{
    word_t size = peek_reg(tracee, CURRENT, size_reg);
    if (size == 0 || peek_reg(tracee, CURRENT, output_reg) == 0)
        return 0;
    if (size > PATH_MAX)
        size = PATH_MAX;
    word_t scratch = alloc_mem(tracee, size);
    if (scratch == 0)
        return -EFAULT;
    poke_reg(tracee, output_reg, scratch);
    poke_reg(tracee, size_reg, size);
    tracee->sysexit_pending = true;
    tracee->restart_how = PTRACE_SYSCALL;
    return 0;
}
static inline int copy_raw_readlink_output(Tracee *tracee, Reg output_reg, word_t size)
{
    char buffer[PATH_MAX];
    word_t original = peek_reg(tracee, ORIGINAL, output_reg);
    word_t scratch = peek_reg(tracee, MODIFIED, output_reg);
    if (original == scratch || size == 0)
        return 0;
    if (size > sizeof(buffer))
        return -EIO;
    int status = read_data(tracee, buffer, scratch, size);
    if (status < 0)
        return status;
    return write_readlink_output(tracee, original, buffer, size);
}
#endif
