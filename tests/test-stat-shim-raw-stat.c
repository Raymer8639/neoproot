/*
 * Direct-syscall stat probe for the --stat-shim raw-syscall regression.
 *
 * Go's runtime (and any program that issues stat syscalls without going
 * through libc) uses a raw svc instruction.  --stat-shim leaves the stat
 * family out of the seccomp filter, so before the fix that raw call was
 * resolved by the host kernel against the *host* namespace and silently
 * returned wrong results (this broke `gh` repository discovery).  The fix
 * routes untagged raw stat syscalls through the tracer's USER_NOTIF channel.
 *
 * This file is compiled -static -nostdlib so no libc wrapper or preload can
 * intervene: every check below is the untagged raw syscall path.
 *
 * The checks look only at the syscall return value.  Both probe paths exist
 * only inside the guest namespace, so an untranslated call (the bug) returns
 * ENOENT while a translated call succeeds.  Reading struct stat is left out
 * on purpose: its layout is kernel-specific and a misread would obscure the
 * regression this test pins down.
 */
#define AT_FDCWD (-100) /* arm64 uses the generic value; no libc header here */
#define NR_newfstatat 79
#define NR_exit 93

static char sbuf[256] __attribute__((aligned(16)));

static long raw_newfstatat(long dirfd, const char *path, long flags)
{
	register long x8 asm("x8") = NR_newfstatat;
	register long x0 asm("x0") = dirfd;
	register long x1 asm("x1") = (long)path;
	register long x2 asm("x2") = (long)sbuf;
	register long x3 asm("x3") = flags;

	asm volatile("svc #0"
		     : "+r"(x0)
		     : "r"(x1), "r"(x2), "r"(x3), "r"(x8)
		     : "memory");
	return x0;
}

static void raw_exit(int code)
{
	register long x8 asm("x8") = NR_exit;
	register long x0 asm("x0") = code;

	asm volatile("svc #0" : : "r"(x0), "r"(x8) : "memory");
	for (;;)
		;
}

/* Exit 1: relative name at AT_FDCWD (guest virtual cwd) not translated.
 * Exit 2: absolute path across a bind not translated. */
void _start(void)
{
	if (raw_newfstatat(AT_FDCWD, "rel-marker", 0) != 0)
		raw_exit(1);
	if (raw_newfstatat(AT_FDCWD, "/bound/inside", 0) != 0)
		raw_exit(2);
	raw_exit(0);
}
