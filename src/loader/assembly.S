#if defined(__aarch64__)

.globl pokedata_workaround
.type pokedata_workaround, @function
pokedata_workaround:
        str     x1, [x2]
        // Synchronization barrier + return
        dmb     ish
        ret

// svc #0 + return helper for AArch64 syscall
.globl syscall_aarch64
.type syscall_aarch64, @function
syscall_aarch64:
        svc     #0
        ret

#endif /* __aarch64__ */
