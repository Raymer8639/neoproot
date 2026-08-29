.global _start
.type _start, %function

/*
 * A static ARM64 tracee whose first system call is brk(non-zero).  This
 * exercises the warning path before neoproot has initialized its heap.
 */
_start:
	mov x0, #0x10000
	mov x8, #214                 /* __NR_brk */
	svc #0

	mov x0, #0
	mov x8, #93                  /* __NR_exit */
	svc #0
