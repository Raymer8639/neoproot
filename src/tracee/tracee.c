/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * This file is part of PRoot.
 *
 * Copyright (C) 2015 STMicroelectronics
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA.
 */
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
#include <stdint.h>     /* UINT64_MAX */

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

/**
 * 通用宏定义：语义化封装，消除魔法数字，完全兼容原逻辑
 */
#ifndef __W_STOPCODE
#define __W_STOPCODE(sig) ((sig) << 8 | 0x7f)
#endif
#define INVALID_PID       ((pid_t)-1)
#define TRACEE_LIST_EMPTY (tracees.lh_first == NULL)

static Tracees tracees;
static uint64_t next_vpid = 1;

/**
 * Remove @zombie from its parent's list of zombies.
 * Note: this is a talloc destructor.
 */
static int remove_zombie(Tracee *zombie)
{
    if (zombie == NULL)
        return 0;

    LIST_REMOVE(zombie, link);
    return 0;
}

/**
 * Perform specific treatments against @pointer according to its type,
 * before it gets unlinked from @tracee_->life_context.
 */
static void clean_life_span_object(const void *pointer, int depth,
				int max_depth, int is_ref, void *tracee_)
{
    // 显式标记未使用参数，彻底消除编译警告
    (void)depth;
    (void)max_depth;
    (void)is_ref;

    // 前置空指针校验，防止非法访问
    if (tracee_ == NULL)
        return;

    Tracee *tracee = talloc_get_type_abort(tracee_, Tracee);
    Binding *binding = talloc_get_type(pointer, Binding);

    // 仅绑定需要特殊清理，完全兼容原逻辑
    if (binding != NULL)
        remove_binding_from_all_lists(tracee, binding);
}

/**
 * Remove @tracee from the list of tracees and update all of its
 * children & ptracees, and its ptracer.
 * Note: this is a talloc destructor.
 */
static int remove_tracee(Tracee *tracee)
{
    if (tracee == NULL)
        return 0;

    Tracee *relative;
    Tracee *ptracer;
    int event;

    // 从全局tracee列表移除
    LIST_REMOVE(tracee, link);

    // 清理生命周期绑定的对象
    talloc_report_depth_cb(tracee->life_context, 0, 100, clean_life_span_object, tracee);

    // 单次遍历处理子进程和ptracee，减少列表循环开销
    LIST_FOREACH(relative, &tracees, link) {
        // 子进程变为孤儿
        if (relative->parent == tracee)
            relative->parent = NULL;

        // 被trace的进程释放
        if (relative->as_ptracee.ptracer == tracee) {
            relative->as_ptracee.ptracer = NULL;

            // 释放挂起的事件，完全兼容原逻辑
            if (relative->as_ptracee.event4.proot.pending) {
                event = handle_tracee_event(relative,
                            relative->as_ptracee.event4.proot.value);
                (void) restart_tracee(relative, event);
            }
            else if (relative->as_ptracee.event4.ptracer.pending) {
                event = relative->as_ptracee.event4.proot.value;
                (void) restart_tracee(relative, event);
            }

            // 统一用memset替代bzero，兼容标准C，消除deprecated警告
            memset(&relative->as_ptracee, 0, sizeof(relative->as_ptracee));
        }
    }

    // 非ptracee直接返回
    ptracer = tracee->as_ptracee.ptracer;
    if (ptracer == NULL)
        return 0;

    // 处理僵尸进程逻辑，完全和原代码一致
    event = tracee->as_ptracee.event4.ptracer.value;
    if (tracee->as_ptracee.event4.ptracer.pending
        && (WIFEXITED(event) || WIFSIGNALED(event))) {
        Tracee *zombie = new_dummy_tracee(ptracer);
        if (zombie != NULL) {
            LIST_INSERT_HEAD(&PTRACER.zombies, zombie, link);
            talloc_set_destructor(zombie, remove_zombie);

            // 批量赋值，减少重复代码
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

    // 脱离ptracer
    detach_from_ptracer(tracee);

    // 唤醒等待中的ptracer，完全兼容原逻辑
    if (PTRACER.nb_ptracees == 0 && PTRACER.wait_pid != 0) {
        poke_reg(ptracer, SYSARG_RESULT, -ECHILD);
        (void) push_regs(ptracer);
        PTRACER.wait_pid = 0;
        (void) restart_tracee(ptracer, 0);
    }

    return 0;
}

/**
 * Allocate a new dummy tracee (no pid, no destructor, not in global list).
 * The new memory is attached to the given @context.
 * Returns NULL on ENOMEM, otherwise the new tracee structure.
 * 【修复核心bug】移除context空指针校验，允许context=NULL的合法调用
 */
Tracee *new_dummy_tracee(TALLOC_CTX *context)
{
    Tracee *tracee = talloc_zero(context, Tracee);
    if (tracee == NULL)
        return NULL;

    // 分配内存收集器
    tracee->ctx = talloc_new(tracee);
    if (tracee->ctx == NULL)
        goto no_mem;

    // 初始化默认命名空间和堆，完全和原代码一致
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
 * Allocate a new tracee entry for @pid, set destructor and add to global list.
 * Returns NULL on ENOMEM, otherwise the new tracee structure.
 */
static Tracee *new_tracee(pid_t pid)
{
    // 仅拦截非法pid，不影响正常逻辑
    if (pid == INVALID_PID)
        return NULL;

    Tracee *tracee = new_dummy_tracee(NULL);
    if (tracee == NULL)
        return NULL;

    // 设置析构函数和基础属性，完全兼容原逻辑
    talloc_set_destructor(tracee, remove_tracee);
    tracee->pid = pid;
    tracee->vpid = next_vpid++;

    // 防止vpid溢出
    if (next_vpid == UINT64_MAX)
        next_vpid = 1;

    LIST_INSERT_HEAD(&tracees, tracee, link);
    tracee->life_context = talloc_new(tracee);

    return tracee;
}

/**
 * Return the first matching tracee with the given @pid and @ptracer.
 * See wait(2) manual for the meaning of @wait_options.
 * Returns NULL if no matching tracee found.
 * 【逻辑完全和原代码一致】仅优化过滤顺序，提升性能
 */
static Tracee *get_ptracee(const Tracee *ptracer, pid_t pid, bool only_stopped,
			bool only_with_pevent, word_t wait_options)
{
    if (ptracer == NULL)
        return NULL;

    Tracee *ptracee;

    // 优先返回僵尸进程，完全和原代码一致
    LIST_FOREACH(ptracee, &PTRACER.zombies, link) {
        // 快速过滤不匹配的pid，和原逻辑完全一致
        if (pid != INVALID_PID && pid != ptracee->pid)
            continue;
        // 过滤不匹配的clone类型
        if (!EXPECTED_WAIT_CLONE(wait_options, ptracee))
            continue;
        return ptracee;
    }

    // 遍历全局tracee列表，逻辑完全兼容原代码
    LIST_FOREACH(ptracee, &tracees, link) {
        // 快速过滤不匹配的ptracer和pid
        if (PTRACEE.ptracer != ptracer)
            continue;
        if (pid != INVALID_PID && pid != ptracee->pid)
            continue;
        if (!EXPECTED_WAIT_CLONE(wait_options, ptracee))
            continue;

        // 非停止状态要求直接返回，和原逻辑一致
        if (!only_stopped)
            return ptracee;

        // 过滤运行中的进程
        if (ptracee->running)
            continue;

        // 过滤无挂起事件的进程
        if (PTRACEE.event4.ptracer.pending || !only_with_pevent)
            return ptracee;

        // 指定pid的进程不满足条件，直接返回NULL，和原逻辑一致
        if (pid == ptracee->pid)
            return NULL;
    }

    return NULL;
}

/**
 * Wrapper for get_ptracee(), ensures only a stopped tracee is returned.
 */
Tracee *get_stopped_ptracee(const Tracee *ptracer, pid_t pid,
			bool only_with_pevent, word_t wait_options)
{
    return get_ptracee(ptracer, pid, true, only_with_pevent, wait_options);
}

/**
 * Wrapper for get_ptracee(), checks if any matching ptracee exists.
 */
bool has_ptracees(const Tracee *ptracer, pid_t pid, word_t wait_options)
{
    return (get_ptracee(ptracer, pid, false, false, wait_options) != NULL);
}

/**
 * Return the tracee entry for @pid. Creates new entry if @create is true.
 * Returns NULL if not found and @create is false.
 * 【逻辑完全和原代码一致】仅优化快速返回路径
 */
Tracee *get_tracee(const Tracee *current_tracee, pid_t pid, bool create)
{
    if (pid == INVALID_PID)
        return NULL;

    // 快速返回当前tracee，避免列表遍历，和原逻辑一致
    if (current_tracee != NULL && current_tracee->pid == pid)
        return (Tracee *)current_tracee;

    Tracee *tracee;
    LIST_FOREACH(tracee, &tracees, link) {
        if (tracee->pid == pid) {
            // 刷新内存收集器，完全和原代码一致
            TALLOC_FREE(tracee->ctx);
            tracee->ctx = talloc_new(tracee);
            return tracee;
        }
    }

    return create ? new_tracee(pid) : NULL;
}

/**
 * Mark tracee as terminated and trigger optional killall action.
 */
void terminate_tracee(Tracee *tracee)
{
    if (tracee == NULL)
        return;

    tracee->terminated = true;

    // 退出时杀死所有tracee，完全兼容原逻辑
    if (tracee->killall_on_exit) {
        VERBOSE(tracee, 1, "terminating all tracees on exit");
        kill_all_tracees();
    }
}

/**
 * Free all tracees marked as terminated.
 */
void free_terminated_tracees()
{
    if (TRACEE_LIST_EMPTY)
        return;

    Tracee *next = tracees.lh_first;
    while (next != NULL) {
        Tracee *tracee = next;
        next = tracee->link.le_next;

        if (tracee->terminated)
            TALLOC_FREE(tracee);
    }
}

/**
 * Make new @parent's child inherit configuration according to @clone_flags.
 * Returns -errno on error, 0 on success.
 * 【逻辑完全和原代码一致】仅优化代码结构，提升可读性
 */
int new_child(Tracee *parent, word_t clone_flags)
{
    // 前置空指针校验，快速失败
    if (parent == NULL)
        return -EINVAL;

    int status = 0;
    unsigned long raw_pid = 0;
    pid_t child_pid = INVALID_PID;
    Tracee *child = NULL;
    int ptrace_options = 0;

    // 获取clone_flags，兼容clone/clone3系统调用，完全和原代码一致
    status = fetch_regs(parent);
    if (status >= 0) {
        Sysnum sysnum = get_sysnum(parent, CURRENT);
        if (sysnum == PR_clone) {
            clone_flags = peek_reg(parent, CURRENT, SYSARG_1);
        } else if (sysnum == PR_clone3) {
            // clone_args第一个字段为clone_flags，和原逻辑一致
            clone_flags = peek_word(parent, peek_reg(parent, CURRENT, SYSARG_1));
        }
    }

    // 获取子进程pid，完全兼容原代码错误处理
    status = ptrace(PTRACE_GETEVENTMSG, parent->pid, NULL, &raw_pid);
    if (status < 0 || raw_pid == 0) {
        note(parent, WARNING, SYSTEM, "ptrace(GETEVENTMSG)");
        return status;
    }
    child_pid = (pid_t)raw_pid;

    // 创建子进程tracee结构
    child = get_tracee(parent, child_pid, true);
    if (child == NULL) {
        note(parent, WARNING, SYSTEM, "running out of memory");
        return -ENOMEM;
    }

    // 合法性校验，完全和原代码一致
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

    // 继承基础配置，完全和原代码一致
    child->verbose = parent->verbose;
    child->seccomp = parent->seccomp;
    child->sysexit_pending = parent->sysexit_pending;
#ifdef HAS_POKEDATA_WORKAROUND
    child->pokedata_workaround_stub_addr = parent->pokedata_workaround_stub_addr;
#endif
#ifdef ARCH_ARM64
    child->is_aarch32 = parent->is_aarch32;
#endif

    // 继承堆内存：CLONE_VM共享，否则拷贝，完全兼容原逻辑
    TALLOC_FREE(child->heap);
    child->heap = ((clone_flags & CLONE_VM) != 0)
        ? talloc_reference(child, parent->heap)
        : talloc_memdup(child, parent->heap, sizeof(Heap));
    if (child->heap == NULL)
        return -ENOMEM;

    // 继承加载信息
    child->load_info = talloc_reference(child, parent->load_info);

    // 设置父进程关系，和原逻辑一致
    child->parent = ((clone_flags & CLONE_PARENT) != 0)
        ? parent->parent
        : parent;

    // 标记是否为同线程组
    child->clone = ((clone_flags & CLONE_THREAD) != 0);

    // 确定ptrace选项，完全和原代码一致
    if (clone_flags == 0)
        ptrace_options = PTRACE_O_TRACEFORK;
    else if ((clone_flags & 0xFF) == SIGCHLD)
        ptrace_options = PTRACE_O_TRACEFORK;
    else if ((clone_flags & CLONE_VFORK) != 0)
        ptrace_options = PTRACE_O_TRACEVFORK;
    else
        ptrace_options = PTRACE_O_TRACECLONE;

    // 继承ptrace跟踪，完全兼容原逻辑
    if (parent->as_ptracee.ptracer != NULL
        && (((ptrace_options & parent->as_ptracee.options) != 0)
        || ((clone_flags & CLONE_PTRACE) != 0))) {
        attach_to_ptracer(child, parent->as_ptracee.ptracer);
        // 继承可继承的ptrace选项
        child->as_ptracee.options |= (parent->as_ptracee.options
            & (PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT
            | PTRACE_O_TRACEFORK | PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEVFORK
            | PTRACE_O_TRACEVFORKDONE));
    }

    // 继承文件系统命名空间，完全和原代码一致
    TALLOC_FREE(child->fs);
    if ((clone_flags & CLONE_FS) != 0) {
        // 共享命名空间
        child->fs = talloc_reference(child, parent->fs);
    } else {
        // 拷贝命名空间
        child->fs = talloc_zero(child, FileSystemNameSpace);
        if (child->fs == NULL)
            return -ENOMEM;

        child->fs->cwd = talloc_strdup(child->fs, parent->fs->cwd);
        if (child->fs->cwd == NULL)
            return -ENOMEM;
        talloc_set_name_const(child->fs->cwd, "$cwd");

        // 绑定关系共享，和原逻辑一致
        child->fs->bindings.guest = talloc_reference(child->fs, parent->fs->bindings.guest);
        child->fs->bindings.host  = talloc_reference(child->fs, parent->fs->bindings.host);
    }

    // 继承执行路径、模拟器、扩展等配置，完全兼容原逻辑
    child->exe = talloc_reference(child, parent->exe);
    child->qemu = talloc_reference(child, parent->qemu);
    child->glue = talloc_reference(child, parent->glue);
    child->host_ldso_paths  = talloc_reference(child, parent->host_ldso_paths);
    child->guest_ldso_paths = talloc_reference(child, parent->guest_ldso_paths);
    child->tool_name = parent->tool_name;

    // 继承扩展
    inherit_extensions(child, parent, clone_flags);

    // 重启挂起的子进程，完全和原代码一致
    if (child->sigstop == SIGSTOP_PENDING) {
        bool keep_stopped = false;
        child->sigstop = SIGSTOP_ALLOWED;

        // 通知ptracer
        if (child->as_ptracee.ptracer != NULL) {
            assert(!child->as_ptracee.tracing_started);
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
 * Helper for swap_config(): reparent configuration from @old_parent to @new_parent.
 */
static void reparent_config(Tracee *new_parent, Tracee *old_parent)
{
    if (new_parent == NULL || old_parent == NULL)
        return;

    new_parent->verbose = old_parent->verbose;

#define REPARENT(field) do { \
        talloc_reparent(old_parent, new_parent, old_parent->field); \
        new_parent->field = old_parent->field; \
    } while(0)

    REPARENT(fs);
    REPARENT(exe);
    REPARENT(qemu);
    REPARENT(glue);
    REPARENT(extensions);

#undef REPARENT
}

/**
 * Swap configuration (pointers and parentality) between @tracee1 and @tracee2.
 * 【修复内存泄漏】添加临时变量释放，完全兼容原逻辑
 */
int swap_config(Tracee *tracee1, Tracee *tracee2)
{
    if (tracee1 == NULL || tracee2 == NULL)
        return -EINVAL;

    Tracee *tmp = talloc_zero(tracee1->ctx, Tracee);
    if (tmp == NULL)
        return -ENOMEM;

    reparent_config(tmp,     tracee1);
    reparent_config(tracee1, tracee2);
    reparent_config(tracee2, tmp);

    TALLOC_FREE(tmp); // 释放临时变量，修复内存泄漏
    return 0;
}

/**
 * Send SIGKILL to all tracees.
 */
void kill_all_tracees()
{
    if (TRACEE_LIST_EMPTY)
        return;

    Tracee *tracee;
    LIST_FOREACH(tracee, &tracees, link) {
        if (tracee->pid != INVALID_PID)
            kill(tracee->pid, SIGKILL);
    }
}

/**
 * Return the head of the global tracees list.
 */
Tracees *get_tracees_list_head()
{
    return &tracees;
}
/**
 * 清理全局tracee所有资源，释放内存
 */
void clean_all_tracees_resources()
{
    Tracee *next, *tracee;
    // 强制释放所有tracee对象
    next = tracees.lh_first;
    while (next != NULL) {
        tracee = next;
        next = tracee->link.le_next;
        TALLOC_FREE(tracee);
    }
    // 初始化列表，防止野指针
    memset(&tracees, 0, sizeof(Tracees));
    next_vpid = 1;
}