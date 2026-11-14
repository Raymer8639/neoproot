#include <sched.h>
#include <sys/types.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdbool.h>
#include <sys/queue.h>
#include <talloc.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#include <stdatomic.h>
#include <pthread.h>

#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "tracee/mem.h"
#include "path/binding.h"
#include "syscall/syscall.h"
#include "syscall/sysnum.h"
#include "tracee/event.h"
#include "ptrace/ptrace.h"
#include "ptrace/wait.h"
#include "extension/extension.h"
#include "cli/note.h"
#include "compat.h"

// 定义缺失的宏
#ifndef __W_STOPCODE
#define __W_STOPCODE(s) ((s) << 8 | 0x7f)
#endif

#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define ALWAYS_INLINE __attribute__((always_inline)) inline
#define HOT __attribute__((hot))

// 便捷宏
#define PTRACER (ptracer->as_ptracer)
#define PTRACEE (ptracee->as_ptracee)

// ==================== 原子化全局状态（C23标准，RCPC优化） ====================
// 全局tracee链表头
static Tracees tracees;
// 原子自增vpid，relaxed语义保证唯一性，无额外开销
static _Atomic uint64_t next_vpid = 1;
// 原子化终止标记，acquire-release语义保证多上下文可见性
static _Atomic bool has_terminated_tracees = false;
// 原子自旋锁：仅保护链表结构本身，临界区极短，无阻塞操作
static atomic_flag tracee_list_lock = ATOMIC_FLAG_INIT;
// 信号处理重入保护
static atomic_flag signal_in_progress = ATOMIC_FLAG_INIT;

// ==================== 安全自旋锁操作（临界区极短，无阻塞） ====================
ALWAYS_INLINE
static void tracee_list_lock_acquire(void) {
    while (atomic_flag_test_and_set_explicit(&tracee_list_lock, memory_order_acquire)) {
        __asm__ __volatile__("yield" ::: "memory");
    }
}

ALWAYS_INLINE
static void tracee_list_lock_release(void) {
    atomic_flag_clear_explicit(&tracee_list_lock, memory_order_release);
}

// ==================== 业务逻辑（锁仅保护链表，无阻塞操作） ====================
static int remove_zombie(Tracee *zombie) {
    // 僵尸链表仅单ptracer上下文访问，无并发，无需锁
    LIST_REMOVE(zombie, link);
    return 0;
}

static void clean_life_span_object(const void *pointer, int depth, int max_depth, int is_ref, void *tracee_) {
    [[maybe_unused]] const int unused_depth = depth;
    [[maybe_unused]] const int unused_max_depth = max_depth;
    [[maybe_unused]] const int unused_is_ref = is_ref;
    Tracee *tracee = talloc_get_type_abort(tracee_, Tracee);
    Binding *b = talloc_get_type(pointer, Binding);
    if (b)
        remove_binding_from_all_lists(tracee, b);
}

// 析构函数内链表操作必须加锁，且无阻塞操作
static int remove_tracee(Tracee *tracee) {
    clear_proc_fd_paths(tracee->pid);
    // 1. 先在锁内安全移除链表节点，无任何阻塞操作
    tracee_list_lock_acquire();
    LIST_REMOVE(tracee, link);
    tracee_list_lock_release();

    // 2. 生命周期清理（无链表操作，无锁）
    talloc_report_depth_cb(tracee->life_context, 0, 100, clean_life_span_object, tracee);

    // 3. 先锁内遍历收集需要处理的tracee，锁外执行业务逻辑
    #define MAX_BATCH_TRACEES 256
    Tracee *batch[MAX_BATCH_TRACEES] = {0};
    int batch_count = 0;

    tracee_list_lock_acquire();
    Tracee *iter;
    LIST_FOREACH(iter, &tracees, link) {
        if (batch_count >= MAX_BATCH_TRACEES) break;
        // 仅收集需要处理的tracee，不执行业务逻辑
        if (iter->parent == tracee || iter->as_ptracee.ptracer == tracee) {
            batch[batch_count++] = iter;
        }
    }
    tracee_list_lock_release();

    // 4. 锁外执行业务逻辑（含阻塞ptrace调用，绝对不能在锁内）
    for (int i = 0; i < batch_count; i++) {
        Tracee *t = batch[i];
        if (!t) continue;

        if (t->parent == tracee) {
            t->parent = NULL;
        }
        if (t->as_ptracee.ptracer == tracee) {
            int ev;
            t->as_ptracee.ptracer = NULL;
            if (t->as_ptracee.event4.proot.pending) {
                ev = handle_tracee_event(t, t->as_ptracee.event4.proot.value);
                (void) restart_tracee(t, ev);
            } else if (t->as_ptracee.event4.ptracer.pending) {
                (void) restart_tracee(t, t->as_ptracee.event4.proot.value);
            }
            memset(&t->as_ptracee, 0, sizeof(t->as_ptracee));
        }
    }

    // 5. ptracer相关逻辑（无链表并发操作）
    Tracee *ptracer = tracee->as_ptracee.ptracer;
    if (!ptracer)
        return 0;

    int ev = tracee->as_ptracee.event4.ptracer.value;
    if (tracee->as_ptracee.event4.ptracer.pending && (WIFEXITED(ev) || WIFSIGNALED(ev))) {
        Tracee *z = new_dummy_tracee(ptracer);
        if (z) {
            LIST_INSERT_HEAD(&PTRACER.zombies, z, link);
            talloc_set_destructor(z, remove_zombie);
            z->parent = tracee->parent;
            z->clone = tracee->clone;
            z->pid = tracee->pid;
            detach_from_ptracer(tracee);
            attach_to_ptracer(z, ptracer);
            z->as_ptracee.event4.ptracer.pending = true;
            z->as_ptracee.event4.ptracer.value = ev;
            z->as_ptracee.is_zombie = true;
            return 0;
        }
    }

    detach_from_ptracer(tracee);
    if (PTRACER.nb_ptracees == 0 && PTRACER.wait_pid != 0) {
        poke_reg(ptracer, SYSARG_RESULT, -ECHILD);
        (void) push_regs(ptracer);
        PTRACER.wait_pid = 0;
        (void) restart_tracee(ptracer, 0);
    }
    return 0;
}

[[nodiscard]]
HOT ALWAYS_INLINE
Tracee *new_dummy_tracee(TALLOC_CTX *ctx) {
    Tracee *t = talloc_zero(ctx, Tracee);
    if (UNLIKELY(!t))
        return NULL;
    t->ctx = talloc_new(t);
    t->fs  = talloc_zero(t, FileSystemNameSpace);
    t->heap = talloc_zero(t, Heap);
    if (UNLIKELY(!t->ctx || !t->fs || !t->heap)) {
        TALLOC_FREE(t);
        return NULL;
    }
    return t;
}

[[nodiscard]]
HOT __attribute__((flatten))
static Tracee *new_tracee(pid_t pid) {
    Tracee *t = new_dummy_tracee(NULL);
    if (UNLIKELY(!t))
        return NULL;
    talloc_set_destructor(t, remove_tracee);
    t->pid = pid;
    t->vpid = atomic_fetch_add_explicit(&next_vpid, 1, memory_order_relaxed);

    // 链表插入必须在锁内，临界区仅插入操作，无阻塞
    tracee_list_lock_acquire();
    LIST_INSERT_HEAD(&tracees, t, link);
    tracee_list_lock_release();

    t->life_context = talloc_new(t);
    return t;
}

[[nodiscard]]
static Tracee *get_ptracee(const Tracee *ptracer, pid_t pid, bool stopped, bool pend, word_t opts) {
    // 僵尸链表仅单ptracer访问，无并发
    Tracee *ptracee;
    LIST_FOREACH(ptracee, &PTRACER.zombies, link) {
        if ((pid == -1 || pid == ptracee->pid) && EXPECTED_WAIT_CLONE(opts, ptracee))
            return ptracee;
    }

    // 锁内仅遍历匹配，无业务逻辑，立刻释放锁
    tracee_list_lock_acquire();
    LIST_FOREACH(ptracee, &tracees, link) {
        if (PTRACEE.ptracer != ptracer) continue;
        if (pid != -1 && pid != ptracee->pid) continue;
        if (!EXPECTED_WAIT_CLONE(opts, ptracee)) continue;
        if (!stopped) {
            tracee_list_lock_release();
            return ptracee;
        }
        if (ptracee->running) continue;
        if (PTRACEE.event4.ptracer.pending || !pend) {
            tracee_list_lock_release();
            return ptracee;
        }
        if (pid == ptracee->pid) break;
    }
    tracee_list_lock_release();
    return NULL;
}

[[nodiscard]]
ALWAYS_INLINE
Tracee *get_stopped_ptracee(const Tracee *ptracer, pid_t pid, bool pend, word_t opts) {
    return get_ptracee(ptracer, pid, true, pend, opts);
}

[[nodiscard]]
ALWAYS_INLINE
bool has_ptracees(const Tracee *ptracer, pid_t pid, word_t opts) {
    return get_ptracee(ptracer, pid, false, false, opts) != NULL;
}

[[nodiscard]]
HOT __attribute__((flatten))
ALWAYS_INLINE
Tracee *get_tracee(const Tracee *cur, pid_t pid, bool create) {
    if (cur && cur->pid == pid)
        return (Tracee *)cur;

    // 锁内仅查找匹配，无阻塞操作
    tracee_list_lock_acquire();
    Tracee *t;
    LIST_FOREACH(t, &tracees, link) {
        if (t->pid == pid) {
            /* Only event-loop acquisition starts a new stop context. Pure
             * peer/exec lookups must preserve pending syscall allocations. */
            if (create) {
                TALLOC_FREE(t->ctx);
                t->ctx = talloc_new(t);
            }
            tracee_list_lock_release();
            return t;
        }
    }
    tracee_list_lock_release();

    return create ? new_tracee(pid) : NULL;
}

HOT
void terminate_tracee(Tracee *t) {
    t->terminated = true;
    atomic_store_explicit(&has_terminated_tracees, true, memory_order_release);
    if (t->killall_on_exit) {
        VERBOSE(t, 1, "terminating all tracees on exit");
        kill_all_tracees();
    }
}

HOT __attribute__((flatten))
void free_terminated_tracees(void) {
    if (UNLIKELY(!atomic_load_explicit(&has_terminated_tracees, memory_order_acquire)))
        return;

    // 锁内仅收集待销毁tracee，锁外执行销毁（含阻塞操作）
    #define MAX_FREE_BATCH 256
    Tracee *free_batch[MAX_FREE_BATCH] = {0};
    int free_count = 0;

    tracee_list_lock_acquire();
    Tracee *next, *t;
    for (t = tracees.lh_first; t; t = next) {
        next = t->link.le_next;
        if (t->terminated && free_count < MAX_FREE_BATCH) {
            free_batch[free_count++] = t;
        }
    }
    atomic_store_explicit(&has_terminated_tracees, false, memory_order_release);
    tracee_list_lock_release();

    // 锁外执行销毁（含talloc析构、ptrace操作，无锁）
    for (int i = 0; i < free_count; i++) {
        Tracee *t = free_batch[i];
        if (!t) continue;
        VERBOSE(t, 2, "Cleaning up terminated tracee PID %d", t->pid);
        if (t->as_ptracer.nb_ptracees > 0) {
            // 嵌套收集ptracee，锁外执行
            Tracee *e_batch[MAX_FREE_BATCH] = {0};
            int e_count = 0;

            tracee_list_lock_acquire();
            Tracee *e;
            LIST_FOREACH(e, &tracees, link) {
                if (e->as_ptracee.ptracer == t && e_count < MAX_FREE_BATCH) {
                    e_batch[e_count++] = e;
                }
            }
            tracee_list_lock_release();

            for (int j = 0; j < e_count; j++) {
                Tracee *e = e_batch[j];
                if (!e) continue;
                VERBOSE(e, 3, "Detaching ptracee %d from %d", e->pid, t->pid);
                detach_from_ptracer(e);
            }
        }
        TALLOC_FREE(t);
    }
}

[[nodiscard]]
HOT __attribute__((flatten))
int unshare_file_system_namespace(Tracee *tracee) {
    FileSystemNameSpace *source = tracee->fs;
    FileSystemNameSpace *copy;
    Binding *binding;

    if (source == NULL || source->bindings.guest == NULL)
        return 0;

    copy = talloc_zero(tracee, FileSystemNameSpace);
    if (UNLIKELY(!copy))
        return -ENOMEM;
    copy->cwd = talloc_strdup(copy, source->cwd);
    if (UNLIKELY(!copy->cwd)) {
        TALLOC_FREE(copy);
        return -ENOMEM;
    }
    talloc_set_name_const(copy->cwd, "$cwd");
    if (source->cwd_alias_prefix != NULL)
        copy->cwd_alias_prefix = talloc_strdup(copy, source->cwd_alias_prefix);
    if (source->proc_uid_map != NULL)
        copy->proc_uid_map = talloc_reference(copy, source->proc_uid_map);
    if (source->proc_gid_map != NULL)
        copy->proc_gid_map = talloc_reference(copy, source->proc_gid_map);
    if (source->proc_setgroups != NULL)
        copy->proc_setgroups = talloc_reference(copy, source->proc_setgroups);

    copy->bindings.guest = talloc_zero(copy, Bindings);
    copy->bindings.host = talloc_zero(copy, Bindings);
    if (UNLIKELY(!copy->bindings.guest || !copy->bindings.host)) {
        TALLOC_FREE(copy);
        return -ENOMEM;
    }
    CIRCLEQ_INIT(copy->bindings.guest);
    CIRCLEQ_INIT(copy->bindings.host);

    tracee->fs = copy;
    for (binding = CIRCLEQ_FIRST(source->bindings.guest);
         binding != (void *)source->bindings.guest;
         binding = CIRCLEQ_NEXT(binding, link.guest)) {
        if (copy_binding(tracee, copy, binding, binding->guest.path) == NULL) {
            tracee->fs = source;
            TALLOC_FREE(copy);
            return -ENOMEM;
        }
    }

    TALLOC_FREE(source);
    return 0;
}

/* Called by the event loop before dispatching PTRACE_EVENT_EXEC. The
 * execing thread retains its syscall/loader state under the leader's PID. */
Tracee *get_execve_tracee(Tracee *leader)
{
    unsigned long former_pid = 0;
    Tracee *thread, *relative;

    if (ptrace(PTRACE_GETEVENTMSG, leader->pid, NULL, &former_pid) < 0
        || former_pid == 0 || (pid_t)former_pid == leader->pid)
        return leader;
    thread = get_tracee(leader, (pid_t)former_pid, false);
    if (thread == NULL || thread->terminated)
        return leader;

    VERBOSE(thread, 1, "vpid %" PRIu64 ": execve(2) from thread %d of pid %d",
            thread->vpid, thread->pid, leader->pid);
    tracee_list_lock_acquire();
    LIST_FOREACH(relative, &tracees, link) {
        if (relative->parent == leader)
            relative->parent = thread;
    }
    thread->pid = leader->pid;
    thread->vpid = leader->vpid;
    thread->parent = leader->parent;
    thread->clone = leader->clone;
    thread->killall_on_exit = leader->killall_on_exit;
    tracee_list_lock_release();

    /* The process is still alive: terminate_tracee() could kill it. */
    TALLOC_FREE(leader);
    return thread;
}

/* WNOWAIT leaves all pending events for the event loop. ECHILD means
 * that this child's death was already reported and it must not be tracked. */
static bool is_still_traced(pid_t pid)
{
    siginfo_t info;
    int status = waitid(P_PID, pid, &info,
                        WEXITED | WSTOPPED | WNOHANG | WNOWAIT | __WALL);
    return status == 0 || errno != ECHILD;
}

static int attach_child(Tracee *parent, word_t clone_flags, pid_t pid);

/**
 * Read the Tgid, PPid and TracerPid fields of /proc/@pid/status.  This
 * function returns -1 if they can't all be read, otherwise 0.
 */
static int read_proc_status_ids(pid_t pid, pid_t *tgid, pid_t *ppid, pid_t *tracer)
{
	char path[64];
	char line[128];
	int found = 0;
	FILE *file;

	snprintf(path, sizeof(path), "/proc/%d/status", pid);
	file = fopen(path, "r");
	if (file == NULL)
		return -1;

	while (found != 7 && fgets(line, sizeof(line), file) != NULL) {
		if (sscanf(line, "Tgid: %d", tgid) == 1)
			found |= 1;
		else if (sscanf(line, "PPid: %d", ppid) == 1)
			found |= 2;
		else if (sscanf(line, "TracerPid: %d", tracer) == 1)
			found |= 4;
	}
	fclose(file);

	return (found == 7 ? 0 : -1);
}

/**
 * Return the stack pointer the child of the fork-like syscall @parent
 * is stopped in starts with: the stack the syscall was given, if any,
 * otherwise the stack of @parent itself.
 */
static word_t new_child_stack(Tracee *parent)
{
	word_t stack = 0;

	switch (get_sysnum(parent, CURRENT)) {
	case PR_clone:
		stack = peek_reg(parent, CURRENT, SYSARG_2);
		break;

	case PR_clone3: {
		/* The child starts at the top of the area described
		 * by the "stack" and "stack_size" fields of struct
		 * clone_args, the 6th and 7th 64-bit words.  */
		word_t args = peek_reg(parent, CURRENT, SYSARG_1);
		word_t size;

		errno = 0;
		stack = peek_word(parent, args + 5 * 8);
		size  = peek_word(parent, args + 6 * 8);
		stack = (errno != 0 || stack == 0 ? 0 : stack + size);
		break;
	}

	default:
		break;
	}

	return (stack != 0 ? stack : peek_reg(parent, CURRENT, STACK_POINTER));
}

/**
 * Tell whether @child, stopped but unknown to PRoot yet, was created
 * by the fork-like syscall whose event didn't name the child @parent
 * got (see new_child()).
 */
static bool is_pending_child_of(const Tracee *parent, Tracee *child)
{
	word_t flags = parent->pending_clone_flags;
	pid_t child_tgid, child_ppid, parent_tgid, parent_ppid, tracer;
	bool related;

	if (read_proc_status_ids(child->pid, &child_tgid, &child_ppid, &tracer) < 0
	    || read_proc_status_ids(parent->pid, &parent_tgid, &parent_ppid, &tracer) < 0)
		return false;

	/* A new thread joins the thread group of its creator; a new
	 * process is the child of the process which forked it, unless
	 * it was given the parent of that process.  */
	if ((flags & CLONE_THREAD) != 0)
		related = (child_tgid == parent_tgid);
	else if ((flags & CLONE_PARENT) != 0)
		related = (child_ppid == parent_ppid);
	else
		related = (child_ppid == parent_tgid);

	if (!related)
		return false;

	/* That still can't tell apart the threads of a process forking
	 * at the same time, but their children can: the stack a new
	 * child starts with, untouched until its first stop, is the one
	 * its parent asked for, and no two threads share a stack.  */
	if (fetch_regs(child) < 0)
		return false;

	return (peek_reg(child, CURRENT, STACK_POINTER) == parent->pending_child_sp);
}

/**
 * Register the stopped tracees PRoot doesn't know yet whose parent is
 * blocked in a vfork-like syscall that was reported without the new
 * child's PID (see new_child()).  Such a parent reaches the exit of
 * that syscall only once its child has run, so its child can't wait
 * for it.  Other parents are handled when their syscall exits, where
 * its result names the child exactly (see resolve_pending_child()).
 */
void adopt_held_children(void)
{
	bool vfork_pending = false;
	Tracee *parent;
	Tracee *child;

	LIST_FOREACH(parent, &tracees, link) {
		if (parent->pending_child && (parent->pending_clone_flags & CLONE_VFORK) != 0)
			vfork_pending = true;
	}

	if (!vfork_pending)
		return;

	LIST_FOREACH(child, &tracees, link) {
		if (child->exe != NULL || child->sigstop != SIGSTOP_PENDING || child->terminated)
			continue;

		LIST_FOREACH(parent, &tracees, link) {
			if (!parent->pending_child
			    || (parent->pending_clone_flags & CLONE_VFORK) == 0
			    || parent->exe == NULL
			    || parent->terminated
			    || !is_pending_child_of(parent, child))
				continue;

			parent->pending_child = false;
			(void) attach_child(parent, parent->pending_clone_flags, child->pid);
			break;
		}
	}
}

/**
 * Register the child @parent created with a fork-like syscall that was
 * reported without the new child's PID (see new_child()), now that
 * @parent is at the exit stage of a syscall.  If that syscall is the
 * one which forked, its result is the PID in question.
 */
void resolve_pending_child(Tracee *parent)
{
	pid_t tgid, ppid, tracer;
	Tracee *child;
	pid_t pid;

	switch (get_sysnum(parent, ORIGINAL)) {
	case PR_clone:
	case PR_clone3:
	case PR_fork:
	case PR_vfork:
		break;

	default:
		/* The result of any other syscall isn't a PID: never
		 * mistake it for the child's.  */
		return;
	}

	parent->pending_child = false;

	pid = (pid_t) (int) peek_reg(parent, CURRENT, SYSARG_RESULT);

	/* Already registered by adopt_held_children()?  */
	child = (pid > 0 ? get_tracee(parent, pid, false) : NULL);
	if (child != NULL && child->exe != NULL)
		return;

	/* Make sure that PID designates a process PRoot is tracing
	 * before tracking it (and killing it on exit).  */
	if (pid <= 0
	    || read_proc_status_ids(pid, &tgid, &ppid, &tracer) < 0
	    || tracer != getpid()) {
		note(parent, WARNING, INTERNAL,
			"vpid %" PRIu64 ": can't find the child of a fork reported without its pid",
			parent->vpid);
		parent->clone_stripped_newns = false;
		parent->clone_stripped_newnet = false;
		return;
	}

	(void) attach_child(parent, parent->pending_clone_flags, pid);
}

[[nodiscard]]
HOT __attribute__((flatten))
int new_child(Tracee *parent, word_t clone_flags) {
    unsigned long pid = 0;
    int st;

    st = fetch_regs(parent);
    if (st >= 0) {
        word_t sn = get_sysnum(parent, CURRENT);
        if (sn == PR_clone)
            clone_flags = peek_reg(parent, CURRENT, SYSARG_1);
        else if (sn == PR_clone3)
            clone_flags = peek_word(parent, peek_reg(parent, CURRENT, SYSARG_1));
    }

    if (ptrace(PTRACE_GETEVENTMSG, parent->pid, NULL, &pid) < 0 || !pid) {
        VERBOSE(parent, 1, "vpid %" PRIu64 ": fork event without the child's pid",
                parent->vpid);
        parent->pending_child = true;
        parent->pending_clone_flags = clone_flags;
        parent->pending_child_sp = new_child_stack(parent);
        adopt_held_children();
        return 0;
    }
    return attach_child(parent, clone_flags, (pid_t)pid);
}

static int attach_child(Tracee *parent, word_t clone_flags, pid_t pid)
{
    int opt;
    Tracee *child = get_tracee(parent, pid, false);

    if (child == NULL && !is_still_traced(pid)) {
        VERBOSE(parent, 1, "vpid %" PRIu64 ": child %d is gone already",
                parent->vpid, pid);
        parent->clone_stripped_newns = false;
        parent->clone_stripped_newnet = false;
        return 0;
    }
    /* This PID has just been assigned to a new child. Retire stale state
     * before inserting the replacement at the head of the tracee list. */
    if (child != NULL && child->exe != NULL) {
        VERBOSE(parent, 1, "vpid %" PRIu64 ": pid %d reused, dropping vpid %" PRIu64,
                parent->vpid, pid, child->vpid);
        terminate_tracee(child);
        child = NULL;
    }
    if (child == NULL)
        child = new_tracee(pid);
    if (UNLIKELY(!child))
        return -ENOMEM;

    inherit_proc_fd_paths(parent->pid, child->pid);

    child->verbose    = parent->verbose;
    child->seccomp    = parent->seccomp;
    child->seccomp_notify = parent->seccomp_notify;
    /* Deep copies on the child's own life context: the two strings belong to
     * whichever tracee parsed them and must outlive every get_tracee() ctx
     * reset (and the parent itself). */
    TALLOC_FREE(child->stat_shim_lib);
    TALLOC_FREE(child->rootfs);
    child->stat_shim_lib = parent->stat_shim_lib != NULL
        ? talloc_strdup(child->life_context, parent->stat_shim_lib) : NULL;
    child->rootfs = parent->rootfs != NULL
        ? talloc_strdup(child->life_context, parent->rootfs) : NULL;
    child->sysexit_pending = parent->sysexit_pending;
    child->no_new_privs = parent->no_new_privs;
    child->seen_execve = parent->seen_execve;
    child->execfn_addr = parent->execfn_addr;
    if (child->auxv_host_path != NULL)
        talloc_unlink(child, child->auxv_host_path);
    child->auxv_host_path = parent->auxv_host_path != NULL
        ? talloc_reference(child, parent->auxv_host_path) : NULL;
#ifdef HAS_POKEDATA_WORKAROUND
    child->pokedata_workaround_stub_addr = parent->pokedata_workaround_stub_addr;
#endif

    TALLOC_FREE(child->heap);
    child->heap = (clone_flags & CLONE_VM)
        ? talloc_reference(child, parent->heap)
        : talloc_memdup(child, parent->heap, sizeof(Heap));
    if (UNLIKELY(!child->heap)) return -ENOMEM;

    child->load_info = talloc_reference(child, parent->load_info);
    child->parent = (clone_flags & CLONE_PARENT) ? parent->parent : parent;
    child->clone = !!(clone_flags & CLONE_THREAD);

    opt = (clone_flags == 0 || (clone_flags & 0xFF) == SIGCHLD) ? PTRACE_O_TRACEFORK :
          (clone_flags & CLONE_VFORK) ? PTRACE_O_TRACEVFORK : PTRACE_O_TRACECLONE;

    if (parent->as_ptracee.ptracer) {
        unsigned int m = PTRACE_O_TRACECLONE|PTRACE_O_TRACEEXEC|PTRACE_O_TRACEEXIT
                       |PTRACE_O_TRACEFORK|PTRACE_O_TRACESYSGOOD|PTRACE_O_TRACEVFORK
                       |PTRACE_O_TRACEVFORKDONE;
        if (((opt & parent->as_ptracee.options) != 0) || (clone_flags & CLONE_PTRACE)) {
            attach_to_ptracer(child, parent->as_ptracee.ptracer);
            child->as_ptracee.options |= (parent->as_ptracee.options & m);
        }
    }

    TALLOC_FREE(child->fs);
    if ((clone_flags & CLONE_FS) && !parent->clone_stripped_newns) {
        child->fs = talloc_reference(child, parent->fs);
    } else {
        child->fs = talloc_zero(child, FileSystemNameSpace);
        if (UNLIKELY(!child->fs)) return -ENOMEM;
        child->fs->cwd = talloc_strdup(child->fs, parent->fs->cwd);
        talloc_set_name_const(child->fs->cwd, "$cwd");
        if (parent->fs->cwd_alias_prefix != NULL)
            child->fs->cwd_alias_prefix =
                talloc_strdup(child->fs, parent->fs->cwd_alias_prefix);
        if (parent->fs->proc_uid_map != NULL) {
            child->fs->proc_uid_map =
                talloc_reference(child->fs, parent->fs->proc_uid_map);
            if (UNLIKELY(child->fs->proc_uid_map == NULL)) return -ENOMEM;
        }
        if (parent->fs->proc_gid_map != NULL) {
            child->fs->proc_gid_map =
                talloc_reference(child->fs, parent->fs->proc_gid_map);
            if (UNLIKELY(child->fs->proc_gid_map == NULL)) return -ENOMEM;
        }
        if (parent->fs->proc_setgroups != NULL) {
            child->fs->proc_setgroups =
                talloc_reference(child->fs, parent->fs->proc_setgroups);
            if (UNLIKELY(child->fs->proc_setgroups == NULL)) return -ENOMEM;
        }
        if (parent->clone_stripped_newns
            && parent->fs->bindings.guest != NULL) {
            /* 上游 5c7b2fd：调用方请求了 CLONE_NEWNS（已被剥掉），
             * 给子进程一份独立 binding 树，模拟 mount 不泄漏回父进程。 */
            Binding *iter;

            child->fs->bindings.guest = talloc_zero(child->fs, Bindings);
            child->fs->bindings.host  = talloc_zero(child->fs, Bindings);
            if (   child->fs->bindings.guest == NULL
                || child->fs->bindings.host  == NULL)
                return -ENOMEM;
            CIRCLEQ_INIT(child->fs->bindings.guest);
            CIRCLEQ_INIT(child->fs->bindings.host);

            for (iter = CIRCLEQ_FIRST(parent->fs->bindings.guest);
                 iter != (void *) parent->fs->bindings.guest;
                 iter = CIRCLEQ_NEXT(iter, link.guest))
                (void) copy_binding(child, child->fs, iter, iter->guest.path);
        }
        else {
            /* Bindings are shared across file-system name-spaces since a
             * "mount --bind" made by a process affects all other processes
             * under Linux.  Actually they are copied when a sub
             * reconfiguration occured (nested proot or chroot(2)).  */
            child->fs->bindings.guest = talloc_reference(child->fs, parent->fs->bindings.guest);
            child->fs->bindings.host  = talloc_reference(child->fs, parent->fs->bindings.host);
        }
    }

    /* 上游 6a1f1fe：无论走哪条分支，消费掉 stripped-NEWNS 标记。 */
    parent->clone_stripped_newns = false;

    /* 上游 87af48f：网络命名空间继承与 fd 跟踪复制。 */
    child->fake_netns = parent->fake_netns || parent->clone_stripped_newnet;
    parent->clone_stripped_newnet = false;

    for (int i = 0; i < parent->fake_netlink_fds_count; i++) {
        child->fake_netlink_fds[i].fd = parent->fake_netlink_fds[i].fd;
        child->fake_netlink_fds[i].reply = NULL;
        child->fake_netlink_fds[i].reply_len = 0;
        child->fake_netlink_fds[i].reply_off = 0;
    }
    child->fake_netlink_fds_count = parent->fake_netlink_fds_count;
    memcpy(child->netlink_route_fds, parent->netlink_route_fds,
           sizeof(child->netlink_route_fds));
    child->netlink_route_fds_count = parent->netlink_route_fds_count;

    child->exe     = talloc_reference(child, parent->exe);
    child->qemu    = talloc_reference(child, parent->qemu);
    child->glue    = talloc_reference(child, parent->glue);
    child->host_ldso_paths  = talloc_reference(child, parent->host_ldso_paths);
    child->guest_ldso_paths = talloc_reference(child, parent->guest_ldso_paths);
    child->tool_name = parent->tool_name;

    inherit_extensions(child, parent, clone_flags);

    /* A held child killed meanwhile was already restarted from EXIT. */
    if (child->sigstop == SIGSTOP_PENDING && !child->running) {
        bool keep = false;
        child->sigstop = SIGSTOP_ALLOWED;
        if (child->as_ptracee.ptracer) {
            keep = handle_ptracee_event(child, __W_STOPCODE(SIGSTOP));
            child->as_ptracee.event4.proot.pending = false;
            child->as_ptracee.event4.proot.value   = 0;
        }
        if (!keep)
            (void) restart_tracee(child, 0);
    }

    VERBOSE(child, 1, "vpid %" PRIu64 ": pid %d", child->vpid, child->pid);
    return 0;
}

static void reparent_config(Tracee *dst, Tracee *src) {
    dst->verbose = src->verbose;
#define REP(f) do { talloc_reparent(src, dst, src->f); dst->f = src->f; } while(0)
    REP(fs);
    REP(exe);
    REP(qemu);
    REP(glue);
    REP(extensions);
#undef REP
}

[[nodiscard]]
int swap_config(Tracee *a, Tracee *b) {
    Tracee *tmp = talloc_zero(a->ctx, Tracee);
    if (UNLIKELY(!tmp)) return -ENOMEM;
    reparent_config(tmp, a);
    reparent_config(a, b);
    reparent_config(b, tmp);
    TALLOC_FREE(tmp);
    return 0;
}

// 信号处理安全版，异步信号安全，无死锁
void kill_all_tracees(void) {
    // 信号重入保护，防止嵌套调用死锁
    if (atomic_flag_test_and_set_explicit(&signal_in_progress, memory_order_acquire)) {
        return;
    }

    // 锁内仅收集pid，锁外执行kill（系统调用）
    #define MAX_KILL_BATCH 512
    pid_t pid_batch[MAX_KILL_BATCH] = {0};
    int pid_count = 0;

    tracee_list_lock_acquire();
    Tracee *t;
    LIST_FOREACH(t, &tracees, link) {
        if (pid_count >= MAX_KILL_BATCH) break;
        pid_batch[pid_count++] = t->pid;
    }
    tracee_list_lock_release();

    // 锁外执行kill，无阻塞风险
    for (int i = 0; i < pid_count; i++) {
        if (pid_batch[i] > 0) {
            kill(pid_batch[i], SIGKILL);
        }
    }

    atomic_flag_clear_explicit(&signal_in_progress, memory_order_release);
}

[[nodiscard]]
ALWAYS_INLINE
Tracees *get_tracees_list_head(void) {
    return &tracees;
}
