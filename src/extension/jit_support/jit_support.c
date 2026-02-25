#include "jit_support.h"
#include "jit_cache.h"

// PRoot核心API头文件（补全缺失的mem.h，解决read_data未声明）
#include "tracee/reg.h"
#include "tracee/mem.h"
#include "syscall/sysnum.h"
#include "cli/note.h"

// 系统库头文件（补全sys/uio.h，解决struct iovec定义）
#include <sys/mman.h>
#include <sys/uio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// 解决宏冲突，直接定义
#ifndef ADDR_NO_RANDOMIZE
#define ADDR_NO_RANDOMIZE 0x0040000
#endif

// 适配PRoot的返回值
#define JIT_HANDLED    1  // 已处理，跳过PRoot原有逻辑
#define JIT_UNHANDLED  0  // 未处理，走PRoot原有逻辑

bool is_jit_supported(void)
{
    static int supported = -1;
    if (supported != -1)
        return supported;

    // 支持用户强制关闭JIT
    const char *disable = getenv("PROOT_DISABLE_JIT");
    if (disable && !strcmp(disable, "1")) {
        supported = 0;
        return false;
    }

    // 核心检测：设备是否支持可执行内存映射
    void *p = mmap(NULL, 4096,
                   PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        supported = 0;
        return false;
    }
    munmap(p, 4096);

    supported = 1;
    return true;
}

// 处理mmap：缓存命中直接返回，跳过重复编译
static int handle_mmap(Tracee *tracee)
{
    word_t prot = peek_reg(tracee, CURRENT, SYSARG_3);
    word_t addr = peek_reg(tracee, CURRENT, SYSARG_2);

    // 仅处理JIT可执行代码页
    if (!(prot & PROT_EXEC))
        return JIT_UNHANDLED;

    // 查缓存，命中直接返回缓存的机器码地址
    JitCacheEntry *e = jit_cache_lookup((void *)addr);
    if (e) {
        poke_reg(tracee, SYSARG_RESULT, (word_t)e->code);
        return JIT_HANDLED;
    }

    return JIT_UNHANDLED;
}

// 处理mprotect：直接放行可执行内存修改
static int handle_mprotect(Tracee *tracee)
{
    word_t prot = peek_reg(tracee, CURRENT, SYSARG_3);
    if (prot & PROT_EXEC)
        return JIT_HANDLED;
    return JIT_UNHANDLED;
}

// 处理personality：直接放行，消除未使用参数警告
static int handle_personality(Tracee *tracee)
{
    (void)tracee; // 标记参数已使用，消除编译警告
    return JIT_HANDLED;
}

// 处理process_vm_writev：写入时缓存JIT机器码
static int handle_process_vm_writev(Tracee *tracee)
{
    word_t target_addr = peek_reg(tracee, CURRENT, SYSARG_2);
    word_t local_iov = peek_reg(tracee, CURRENT, SYSARG_3);
    word_t iov_len = peek_reg(tracee, CURRENT, SYSARG_4);

    // 仅当设备支持JIT时才缓存
    if (!is_jit_supported() || iov_len == 0 || local_iov == 0)
        return JIT_UNHANDLED;

    // 读取iov结构，缓存机器码
    struct iovec {
        void *iov_base;
        size_t iov_len;
    } iov;

    for (size_t i = 0; i < iov_len; i++) {
        read_data(tracee, &iov, local_iov + i * sizeof(iov), sizeof(iov));
        if (iov.iov_base && iov.iov_len > 0) {
            jit_cache_insert((void *)(target_addr + i * iov.iov_len), iov.iov_base, iov.iov_len);
        }
    }

    return JIT_HANDLED;
}

// JIT系统调用入口处理函数（在PRoot的syscall_enter中调用）
int jit_handle_syscall_enter(Tracee *tracee)
{
    // 设备不支持JIT，直接跳过
    if (!is_jit_supported())
        return JIT_UNHANDLED;

    // 获取当前系统调用号
    Sysnum sysnum = get_sysnum(tracee, CURRENT);

    // 分发处理JIT相关系统调用
    switch (sysnum) {
        case PR_mmap:
            return handle_mmap(tracee);
        case PR_mprotect:
            return handle_mprotect(tracee);
        case PR_personality:
            return handle_personality(tracee);
        case PR_process_vm_writev:
            return handle_process_vm_writev(tracee);
        case PR_process_vm_readv:
            return JIT_HANDLED; // 直接放行readv调用，无需处理
        default:
            return JIT_UNHANDLED;
    }
}
