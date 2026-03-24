#include <sched.h>      /* CLONE_*,  */
#include <sys/types.h>  /* pid_t, size_t, */
#include <stdlib.h>     /* NULL, */
#include <assert.h>     /* assert(3), */
#include <string.h>     /* memset(3), */
#include <stdbool.h>    /* bool, true, false, */
#include <sys/queue.h>  /* LIST_*,  */
#include <talloc.h>     /* talloc_*, */
#include <signal.h>     /* kill(2), SIGKILL, */
#include <sys/ptrace.h> /* ptrace(2), PTRACE_*, */
#include <errno.h>      /* E*, */
#include <inttypes.h>   /* PRI*, */
#include <pthread.h>
#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "tracee/mem.h"
#include "path/binding.h"
#include "syscall/sysnum.h"
#include "tracee/event.h"
#include "ptrace/ptrace.h"
#include "ptrace/wait.h"
#include "extension/extension.h"
#include "cli/note.h"
#include "compat.h"

static Tracees tracees;
static uint64_t next_vpid = 1;

// Fix Bug3: 全局链表锁
static pthread_mutex_t tracee_list_mutex = PTHREAD_MUTEX_INITIALIZER;

static bool has_terminated_tracees = false;

/**
 * Remove @zombie from its parent's list of zombies.  Note: this is a
 * talloc destructor.
 */
__attribute__((cold))
static int remove_zombie(Tracee *zombie)
{
    LIST_REMOVE(zombie, link);
    return 0;
}

/**
 * Perform some specific treatments against @pointer according to its
 * type, before it gets unlinked from @tracee_->life_context.
 */
__attribute__((cold, noinline))
static void clean_life_span_object(const void *pointer, int depth UNUSED,
                                   int max_depth UNUSED, int is_ref UNUSED, void *tracee_)
{
    Binding *binding;
    Tracee *tracee = talloc_get_type_abort(tracee_, Tracee);
    binding = talloc_get_type(pointer, Binding);
    if (binding != NULL)
        remove_binding_from_all_lists(tracee, binding);
}

/**
 * Remove @tracee from the list of tracees and update all of its
 * children & ptracees, and its ptracer.  Note: this is a talloc
 * destructor.
 */
__attribute__((cold))
static int remove_tracee(Tracee *tracee)
{
    Tracee *relative;
    Tracee *ptracer;
    int event;

    LIST_REMOVE(tracee, link);
    talloc_report_depth_cb(tracee->life_context, 0, 100, clean_life_span_object, tracee);

    LIST_FOREACH(relative, &tracees, link) {
        if (relative->parent == tracee)
            relative->parent = NULL;
        if (relative->as_ptracee.ptracer == tracee) {
            relative->as_ptracee.ptracer = NULL;
            if (relative->as_ptracee.event4.proot.pending) {
                event = handle_tracee_event(relative, relative->as_ptracee.event4.proot.value);
                (void) restart_tracee(relative, event);
            }
            else if (relative->as_ptracee.event4.ptracer.pending) {
                event = relative->as_ptracee.event4.proot.value;
                (void) restart_tracee(relative, event);
            }
            memset(&relative->as_ptracee, 0, sizeof(relative->as_ptracee));
        }
    }

    ptracer = tracee->as_ptracee.ptracer;
    if (ptracer == NULL)
        return 0;

    event = tracee->as_ptracee.event4.ptracer.value;
    if (tracee->as_ptracee.event4.ptracer.pending && (WIFEXITED(event) || WIFSIGNALED(event))) {
        Tracee *zombie = new_dummy_tracee(ptracer);
        if (zombie != NULL) {
            LIST_INSERT_HEAD(&PTRACER.zombies, zombie, link);
            talloc_set_destructor(zombie, remove_zombie);
            zombie->parent = tracee->parent;
            zombie->clone = tracee->clone;
            zombie->pid = tracee->pid;
            detach_from_ptracer(tracee);
            attach_to_ptracer(zombie, ptracer);
            zombie->as_ptracee.event4.ptracer.pending = true;
            zombie->as_ptracee.event4.ptracer.value = event;
            zombie->as_ptracee.is_zombie = true;
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

/**
 * Allocate a new entry for a dummy tracee (no pid, no destructor, not
 * in the list of tracees, ...).  The new allocated memory is attached
 * to the given @context.  This function returns NULL if an error
 * occurred (ENOMEM), otherwise it returns the newly allocated
 * structure.
 */
__attribute__((hot, always_inline))
Tracee *new_dummy_tracee(TALLOC_CTX *context)
{
    Tracee *tracee = talloc_zero(context, Tracee);
    if (tracee == NULL)
        return NULL;

    tracee->ctx = talloc_new(tracee);
    if (tracee->ctx == NULL)
        goto no_mem;

    tracee->fs = talloc_zero(tracee, FileSystemNameSpace);
    tracee->heap = talloc_zero(tracee, Heap);
    if (tracee->fs == NULL || tracee->heap == NULL)
        goto no_mem;

    return tracee;

no_mem:
    TALLOC_FREE(tracee);
    return NULL;
}

/**
 * Allocate a new entry for the tracee @pid, then set its destructor
 * and add it to the list of tracees.  This function returns NULL if
 * an error occurred (ENOMEM), otherwise it returns the newly
 * allocated structure.
 */
__attribute__((hot, flatten))
static Tracee *new_tracee(pid_t pid)
{
    Tracee *tracee = new_dummy_tracee(NULL);
    if (tracee == NULL)
        return NULL;

    // 只保留你结构体真实存在的字段，修复 Bug2 内存泄漏
    talloc_set_destructor(tracee, remove_tracee);
    tracee->pid = pid;
    tracee->vpid = next_vpid++;

    pthread_mutex_lock(&tracee_list_mutex);
    LIST_INSERT_HEAD(&tracees, tracee, link);
    pthread_mutex_unlock(&tracee_list_mutex);

    tracee->life_context = talloc_new(tracee);

    return tracee;
}

/**
 * Return the first [stopped?] tracee with the given
 * @pid (-1 for any) which has the given @ptracer, and which has a
 * pending event for its ptracer if @only_with_pevent is true.  See
 * wait(2) manual for the meaning of @wait_options.  This function
 * returns NULL if there's no such ptracee.
 */
__attribute__((hot, flatten, always_inline))
static Tracee *get_ptracee(const Tracee *ptracer, pid_t pid, bool only_stopped,
                           bool only_with_pevent, word_t wait_options)
{
    Tracee *ptracee;

    LIST_FOREACH(ptracee, &PTRACER.zombies, link) {
        if ((pid == ptracee->pid || pid == -1) && EXPECTED_WAIT_CLONE(wait_options, ptracee))
            return ptracee;
    }

    pthread_mutex_lock(&tracee_list_mutex);
    LIST_FOREACH(ptracee, &tracees, link) {
        if (PTRACEE.ptracer != ptracer)
            continue;
        if (pid != ptracee->pid && pid != -1) {
            continue;
        }
        if (!EXPECTED_WAIT_CLONE(wait_options, ptracee)) {
            continue;
        }
        if (!only_stopped) {
            pthread_mutex_unlock(&tracee_list_mutex);
            return ptracee;
        }
        if (ptracee->running) {
            continue;
        }
        if (PTRACEE.event4.ptracer.pending || !only_with_pevent) {
            pthread_mutex_unlock(&tracee_list_mutex);
            return ptracee;
        }
        if (pid == ptracee->pid) {
            break;
        }
    }
    pthread_mutex_unlock(&tracee_list_mutex);

    return NULL;
}

/**
 * Wrapper for get_ptracee(), this ensures only a stopped tracee is
 * returned (or NULL).
 */
__attribute__((always_inline))
Tracee *get_stopped_ptracee(const Tracee *ptracer, pid_t pid,
                            bool only_with_pevent, word_t wait_options)
{
    return get_ptracee(ptracer, pid, true, only_with_pevent, wait_options);
}

/**
 * Wrapper for get_ptracee(), this ensures no running tracee is
 * returned.
 */
__attribute__((always_inline))
bool has_ptracees(const Tracee *ptracer, pid_t pid, word_t wait_options)
{
    return (get_ptracee(ptracer, pid, false, false, wait_options) != NULL);
}

/**
 * Return the entry related to the tracee @pid.  If no entry were
 * found, a new one is created if @create is true, otherwise NULL is
 * returned.
 */
__attribute__((hot, flatten, always_inline))
Tracee *get_tracee(const Tracee *current_tracee, pid_t pid, bool create)
{
    if (current_tracee != NULL && current_tracee->pid == pid)
        return (Tracee *)current_tracee;

    pthread_mutex_lock(&tracee_list_mutex);
    Tracee *tracee;
    LIST_FOREACH(tracee, &tracees, link) {
        if (tracee->pid == pid) {
            TALLOC_FREE(tracee->ctx);
            tracee->ctx = talloc_new(tracee);
            pthread_mutex_unlock(&tracee_list_mutex);
            return tracee;
        }
    }
    pthread_mutex_unlock(&tracee_list_mutex);

    return (create ? new_tracee(pid) : NULL);
}

/**
 * Mark tracee as terminated and optionally take action.
 */
__attribute__((hot))
void terminate_tracee(Tracee *tracee)
{
    tracee->terminated = true;
    has_terminated_tracees = true;

    if (tracee->killall_on_exit) {
        VERBOSE(tracee, 1, "terminating all tracees on exit");
        kill_all_tracees();
    }
}

/**
 * Free all tracees marked as terminated.
 */
__attribute__((hot, flatten))
void free_terminated_tracees()
{
    if (!has_terminated_tracees)
        return;

    pthread_mutex_lock(&tracee_list_mutex);
    Tracee *next = tracees.lh_first;
    while (next != NULL) {
        Tracee *tracee = next;
        next = tracee->link.le_next;

        if (tracee->terminated) {
            VERBOSE(tracee, 2, "Cleaning up terminated tracee PID %d", tracee->pid);

            if (tracee->as_ptracer.nb_ptracees > 0) {
                Tracee *ptracee;
                LIST_FOREACH(ptracee, &tracees, link) {
                    if (ptracee->as_ptracee.ptracer == tracee) {
                        VERBOSE(ptracee, 3, "Detaching ptracee %d from terminated ptracer %d",
                                ptracee->pid, tracee->pid);
                        detach_from_ptracer(ptracee);
                    }
                }
            }

            TALLOC_FREE(tracee);
        }
    }
    pthread_mutex_unlock(&tracee_list_mutex);

    has_terminated_tracees = false;
}

/**
 * Make new @parent's child inherit from it.  Depending on
 * @clone_flags, some information are copied or shared.  This function
 * returns -errno if an error occured, otherwise 0.
 */
__attribute__((hot, flatten))
int new_child(Tracee *parent, word_t clone_flags)
{
    int ptrace_options;
    unsigned long pid;
    Tracee *child;
    int status;

    status = fetch_regs(parent);
    if (status >= 0) {
        word_t sysnum = get_sysnum(parent, CURRENT);
        if (sysnum == PR_clone)
            clone_flags = peek_reg(parent, CURRENT, SYSARG_1);
        else if (sysnum == PR_clone3)
            clone_flags = peek_word(parent, peek_reg(parent, CURRENT, SYSARG_1));
    }

    status = ptrace(PTRACE_GETEVENTMSG, parent->pid, NULL, &pid);
    if (status < 0 || pid == 0) {
        note(parent, WARNING, SYSTEM, "ptrace(GETEVENTMSG)");
        return status;
    }

    child = get_tracee(parent, (pid_t)pid, true);
    if (child == NULL) {
        note(parent, WARNING, SYSTEM, "running out of memory");
        return -ENOMEM;
    }

    assert(child != NULL
           && child->exe == NULL
           && child->fs->cwd == NULL
           && child->fs->bindings.pending == NULL
           && child->fs->bindings.guest == NULL
           && child->fs->bindings.host == NULL
           && child->qemu == NULL
           && child->glue == NULL
           && child->parent == NULL
           && child->as_ptracee.ptracer == NULL);

    child->verbose = parent->verbose;
    child->seccomp = parent->seccomp;
    child->sysexit_pending = parent->sysexit_pending;
#ifdef HAS_POKEDATA_WORKAROUND
    child->pokedata_workaround_stub_addr = parent->pokedata_workaround_stub_addr;
#endif
#ifdef ARCH_ARM64
    child->is_aarch32 = parent->is_aarch32;
#endif

    TALLOC_FREE(child->heap);
    child->heap = ((clone_flags & CLONE_VM) != 0)
                  ? talloc_reference(child, parent->heap)
                  : talloc_memdup(child, parent->heap, sizeof(Heap));
    if (child->heap == NULL)
        return -ENOMEM;
    child->load_info = talloc_reference(child, parent->load_info);

    child->parent = ((clone_flags & CLONE_PARENT) != 0) ? parent->parent : parent;
    child->clone = ((clone_flags & CLONE_THREAD) != 0);

    ptrace_options = (clone_flags == 0			? PTRACE_O_TRACEFORK
                    : (clone_flags & 0xFF) == SIGCHLD	? PTRACE_O_TRACEFORK
                    : (clone_flags & CLONE_VFORK) != 0	? PTRACE_O_TRACEVFORK
                    : 					  PTRACE_O_TRACECLONE);
    if (parent->as_ptracee.ptracer != NULL
        && ((ptrace_options & parent->as_ptracee.options) != 0 || (clone_flags & CLONE_PTRACE) != 0)) {
        attach_to_ptracer(child, parent->as_ptracee.ptracer);
        child->as_ptracee.options |= (parent->as_ptracee.options
                                      & (PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT
                                         | PTRACE_O_TRACEFORK | PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEVFORK
                                         | PTRACE_O_TRACEVFORKDONE));
    }

    TALLOC_FREE(child->fs);
    if ((clone_flags & CLONE_FS) != 0) {
        child->fs = talloc_reference(child, parent->fs);
    }
    else {
        child->fs = talloc_zero(child, FileSystemNameSpace);
        if (child->fs == NULL)
            return -ENOMEM;
        child->fs->cwd = talloc_strdup(child->fs, parent->fs->cwd);
        if (child->fs->cwd == NULL)
            return -ENOMEM;
        talloc_set_name_const(child->fs->cwd, "$cwd");
        child->fs->bindings.guest = talloc_reference(child->fs, parent->fs->bindings.guest);
        child->fs->bindings.host  = talloc_reference(child->fs, parent->fs->bindings.host);
    }

    child->exe = talloc_reference(child, parent->exe);
    child->qemu = talloc_reference(child, parent->qemu);
    child->glue = talloc_reference(child, parent->glue);
    child->host_ldso_paths  = talloc_reference(child, parent->host_ldso_paths);
    child->guest_ldso_paths = talloc_reference(child, parent->guest_ldso_paths);
    child->tool_name = parent->tool_name;
    inherit_extensions(child, parent, clone_flags);

    if (child->sigstop == SIGSTOP_PENDING) {
        bool keep_stopped = false;
        child->sigstop = SIGSTOP_ALLOWED;
        if (child->as_ptracee.ptracer != NULL) {
            assert(!child->as_ptracee.tracing_started);
#ifndef __W_STOPCODE
#define __W_STOPCODE(sig) ((sig) << 8 | 0x7f)
#endif
            keep_stopped = handle_ptracee_event(child, __W_STOPCODE(SIGSTOP));
            child->as_ptracee.event4.proot.pending = false;
            child->as_ptracee.event4.proot.value   = 0;
        }
        if (!keep_stopped)
            (void) restart_tracee(child, 0);
    }

    VERBOSE(child, 1, "vpid %" PRIu64 ": pid %d", child->vpid, child->pid);
    return 0;
}

/**
 * Helper for swap_config().
 */
__attribute__((cold))
static void reparent_config(Tracee *new_parent, Tracee *old_parent)
{
    new_parent->verbose = old_parent->verbose;
#define REPARENT(field) do {							\
		talloc_reparent(old_parent, new_parent, old_parent->field);	\
		new_parent->field = old_parent->field;				\
	} while(0);
    REPARENT(fs);
    REPARENT(exe);
    REPARENT(qemu);
    REPARENT(glue);
    REPARENT(extensions);
#undef REPARENT
}

/**
 * Swap configuration (pointers and parentality) between @tracee1 and @tracee2.
 */
__attribute__((cold, noinline))
int swap_config(Tracee *tracee1, Tracee *tracee2)
{
    Tracee *tmp = talloc_zero(tracee1->ctx, Tracee);
    if (tmp == NULL)
        return -ENOMEM;

    reparent_config(tmp,     tracee1);
    reparent_config(tracee1, tracee2);
    reparent_config(tracee2, tmp);

    TALLOC_FREE(tmp);
    return 0;
}

/* Send the KILL signal to all tracees.  */
__attribute__((cold))
void kill_all_tracees()
{
    pthread_mutex_lock(&tracee_list_mutex);
    Tracee *tracee;
    LIST_FOREACH(tracee, &tracees, link) {
        kill(tracee->pid, SIGKILL);
    }
    pthread_mutex_unlock(&tracee_list_mutex);
}

__attribute__((always_inline))
Tracees *get_tracees_list_head()
{
    return &tracees;
}
