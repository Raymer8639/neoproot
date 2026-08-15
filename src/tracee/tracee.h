#ifndef TRACEE_H
#define TRACEE_H

#include <sys/types.h>
#include <sys/user.h>
#include <stdbool.h>
#include <sys/queue.h>
#include <sys/ptrace.h>
#include <talloc.h>
#include <stdint.h>

#include "arch.h"
#include "compat.h"

typedef enum {
	CURRENT  = 0,
	ORIGINAL = 1,
	MODIFIED = 2,
	ORIGINAL_SECCOMP_REWRITE = 3,
	NB_REG_VERSION
} RegVersion;

struct bindings;
struct load_info;
struct extensions;
struct chained_syscalls;

/* File system namespace */
typedef struct {
	struct {
		struct bindings *pending;
		struct bindings *guest;
		struct bindings *host;
	} bindings;
	char *cwd;
} FileSystemNameSpace;

/* Emulated virtual heap */
typedef struct {
	word_t base;
	size_t size;
	bool disabled;
} Heap;

/* Tracee process context (Pure ARM64 version) */
typedef struct tracee {
	/* List link */
	LIST_ENTRY(tracee) link;

	pid_t        pid;
	uint64_t     vpid;
	bool         running;
	bool         terminated;
	bool         killall_on_exit;

	struct tracee *parent;
	bool         clone;

	/* Ptrace: tracer side */
	struct {
		size_t nb_ptracees;
		LIST_HEAD(zombies, tracee) zombies;
		pid_t wait_pid;
		word_t wait_options;
		enum {
			DOESNT_WAIT = 0,
			WAITS_IN_KERNEL,
			WAITS_IN_PROOT
		} waits_in;
	} as_ptracer;

	/* Ptrace: tracee side */
	struct {
		struct tracee *ptracer;
		struct {
			struct { int value; bool pending; } proot;
			struct { int value; bool pending; } ptracer;
		} event4;
		bool tracing_started;
		bool ignore_loader_syscalls;
		bool ignore_syscalls;
		word_t options;
		bool is_zombie;
	} as_ptracee;

	/* 0 = enter, 1 = exit, -errno = error */
	int status;

#define IS_IN_SYSENTER(tracee) ((tracee)->status == 0)
#define IS_IN_SYSEXIT(tracee)  (!IS_IN_SYSENTER(tracee))
#define IS_IN_SYSEXIT2(tracee, nr) \
	(IS_IN_SYSEXIT(tracee) && get_sysnum((tracee), ORIGINAL) == (nr))

	int restart_how;
	int last_restart_how;

	struct user_regs_struct _regs[NB_REG_VERSION];
	bool _regs_were_changed;
	bool restore_original_regs;
	bool restore_original_regs_after_seccomp_event;

	enum {
		SIGSTOP_IGNORED = 0,
		SIGSTOP_ALLOWED,
		SIGSTOP_PENDING
	} sigstop;

	bool skip_next_seccomp_signal;

	/* 上游 cd02c79：外层 seccomp SIGSYS 前若有合成的 sysexit
	 * （translate_syscall）poke 过 SYSARG_RESULT——ARM/ARM64 上
	 * SYSARG_RESULT 与 SYSARG_1 同一寄存器，被拦截 syscall 的首参数
	 * 会被伪结果覆盖，须在模拟/重启前从入口快照恢复。 */
	bool restore_sysarg1_after_sigsys;

	TALLOC_CTX *ctx;
	TALLOC_CTX *life_context;

	mode_t glue_type;

	struct {
		struct tracee *tracee;
		const char *paths;
	} reconf;

	struct {
		struct chained_syscalls *syscalls;
		bool force_final_result;
		word_t final_result;
		enum {
			SYSNUM_WORKAROUND_INACTIVE,
			SYSNUM_WORKAROUND_PROCESS_FAULTY_CALL,
			SYSNUM_WORKAROUND_PROCESS_REPLACED_CALL
		} sysnum_workaround_state;
		int suppressed_signal;
	} chain;

	struct load_info *load_info;

#ifdef HAS_POKEDATA_WORKAROUND
	word_t pokedata_workaround_stub_addr;
	bool pokedata_workaround_cancelled_syscall;
	bool pokedata_workaround_relaunched_syscall;
#endif

	/* Verbosity */
	int verbose;

	enum {
		DISABLED = 0,
		DISABLING,
		ENABLED
	} seccomp;

	bool sysexit_pending;
	bool seccomp_already_handled_enter;

	/* 上游 571a6c0：guest 是否自己请求过 no_new_privs。neoproot 在
	 * execve 前必设真实标志（seccomp 过滤器前提），PR_GET_NO_NEW_PRIVS
	 * 会恒报 1——本字段让 neoproot 按 guest 自身意图回答（sudo-rs
	 * 等工具见标志置位会拒绝运行）。 */
	bool no_new_privs;

	/* 初始 execve 已过 = guest 程序真正在跑。用于忽略 neoproot 自身
	 * 在启动子进程里设的那次 PR_SET_NO_NEW_PRIVS。 */
	bool seen_execve;

	FileSystemNameSpace *fs;
	Heap *heap;

	char *exe;
	char *new_exe;
	char *host_exe;

	char **qemu;
	bool skip_proot_loader;

	const char *glue;
	struct extensions *extensions;

	const char *host_ldso_paths;
	const char *guest_ldso_paths;
	const char *tool_name;
} Tracee;

#define HOST_ROOTFS "/host-rootfs"
#define TRACEE(a) talloc_get_type_abort(talloc_parent(talloc_parent(a)), Tracee)

extern Tracee *get_tracee(const Tracee *tracee, pid_t pid, bool create);
extern Tracee *get_stopped_ptracee(const Tracee *ptracer, pid_t pid,
				bool only_with_pevent, word_t wait_options);
extern bool has_ptracees(const Tracee *ptracer, pid_t pid, word_t wait_options);
extern int new_child(Tracee *parent, word_t clone_flags);
extern Tracee *new_dummy_tracee(TALLOC_CTX *context);
extern void terminate_tracee(Tracee *tracee);
extern void free_terminated_tracees();
extern int swap_config(Tracee *tracee1, Tracee *tracee2);
extern void kill_all_tracees();

typedef LIST_HEAD(tracees, tracee) Tracees;
extern Tracees *get_tracees_list_head();

#endif /* TRACEE_H */
