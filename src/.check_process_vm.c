#include "check_process_vm.h"
#include "syscall/syscall.h"
#include "tracee/tracee.h"
#include "extension/jit_support/jit_cache.h"
#include <sys/uio.h>

int check_process_vm_readv(Tracee *tracee)
{
    return PASS;
}

int check_process_vm_writev(Tracee *tracee)
{
    unsigned long addr   = tracee->regs.arg[1];
    struct iovec *iov    = (struct iovec *)tracee->regs.arg[2];
    unsigned long iovcnt = tracee->regs.arg[3];

    if (is_jit_supported()) {
        size_t i;
        for (i = 0; i < iovcnt; i++) {
            if (iov[i].iov_base && iov[i].iov_len > 0) {
                jit_cache_insert((void *)addr,
                                 iov[i].iov_base,
                                 iov[i].iov_len);
            }
            addr += iov[i].iov_len;
        }
    }

    return PASS;
}
