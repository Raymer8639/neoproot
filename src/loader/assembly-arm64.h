#define BRANCH(stack_pointer, destination) do {			\
	asm volatile (						\
		"mov sp, %0\n\t"				\
		"mov x0, #0\n\t"				\
		"br %1\n"					\
		: /* no output */				\
		: "r" (stack_pointer), "r" (destination)	\
		: "memory", "x0");				\
	__builtin_unreachable();				\
} while (0)

#define PREPARE_ARGS_1(arg1_)				\
	register word_t arg1 asm("x0") = arg1_;

#define PREPARE_ARGS_3(arg1_, arg2_, arg3_)		\
	PREPARE_ARGS_1(arg1_)				\
	register word_t arg2 asm("x1") = arg2_;		\
	register word_t arg3 asm("x2") = arg3_;

#define PREPARE_ARGS_4(arg1_, arg2_, arg3_, arg4_)	\
	PREPARE_ARGS_3(arg1_, arg2_, arg3_)		\
	register word_t arg4 asm("x3") = arg4_;

#define PREPARE_ARGS_6(arg1_, arg2_, arg3_, arg4_, arg5_, arg6_)	\
	PREPARE_ARGS_4(arg1_, arg2_, arg3_, arg4_)			\
	register word_t arg5 asm("x4") = arg5_;				\
	register word_t arg6 asm("x5") = arg6_;

#define OUTPUT_CONTRAINTS_1		"r"(arg1)
#define OUTPUT_CONTRAINTS_3		OUTPUT_CONTRAINTS_1, "r"(arg2), "r"(arg3)
#define OUTPUT_CONTRAINTS_4		OUTPUT_CONTRAINTS_3, "r"(arg4)
#define OUTPUT_CONTRAINTS_6		OUTPUT_CONTRAINTS_4, "r"(arg5), "r"(arg6)

#define SYSCALL(number_, nb_args, args...)				\
({									\
	register word_t number asm("x8") = number_;			\
	register word_t result asm("x0");				\
	PREPARE_ARGS_##nb_args(args)					\
	asm volatile (							\
		"svc #0\n"						\
		: "=r"(result)						\
		: "r"(number), OUTPUT_CONTRAINTS_##nb_args		\
		: "memory");						\
	result;								\
})

#define OPENAT		56
#define CLOSE		57
#define MMAP		222
#define EXECVE		221
#define EXIT		93
#define PRCTL		167
#define MPROTECT	226
