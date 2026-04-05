#include <cstddef>
#include <cstdint>
#include <cinttypes>
#include <climits>
#include <cstring>
#include <cassert>
#include <cerrno>

#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/elf.h>

#ifdef __cplusplus
extern "C" {
#endif
#include "tracee/mem.h"
#include "tracee/abi.h"
#include "syscall/heap.h"
#include "arch.h"
#include "build.h"
#include "cli/note.h"
#include "tracee/reg.h"
#include "syscall/sysnum.h"
#ifdef __cplusplus
}
#endif

// ============================================================================
// 可调参数
// ============================================================================

/// 启用 process_vm_* 快速路径的最小传输大小（字节）
/// 仅当传输数据大于等于此阈值时才尝试使用 process_vm_*，否则走 ptrace 逐字循环。
/// 64KB 是经验值：大块顺序写受益，小块随机读和内存测试不受影响。
static constexpr size_t VM_FAST_THRESHOLD = 64 * 1024;

/// ARM64 红区大小（用于 alloc_mem）
static constexpr size_t ARM64_RED_ZONE = 128;

/// 短字符串阈值：路径名通常不超过 256 字节，直接使用 ptrace 逐字读取
static constexpr size_t SHORT_STRING_MAX = 256;

// ============================================================================
// 修复 unused parameter 警告
// ============================================================================

extern "C" void mem_prepare_after_execve(Tracee *tracee) {
    (void)tracee;
}

extern "C" void mem_prepare_before_first_execve(Tracee *tracee) {
    (void)tracee;
}

// ============================================================================
// 核心读写函数：智能选择路径
// ============================================================================

extern "C" int write_data(Tracee *tracee, word_t dest_tracee, const void *src_tracer, word_t size) {
    if (__builtin_expect(size == 0, 1))
        return 0;

    // 大块数据尝试 process_vm_writev
    if (size >= VM_FAST_THRESHOLD) {
        const struct iovec local = { .iov_base = const_cast<void*>(src_tracer), .iov_len = size };
        const struct iovec remote = { .iov_base = reinterpret_cast<void*>(dest_tracee), .iov_len = size };
        errno = 0;
        long vm_status = syscall(SYS_process_vm_writev, tracee->pid, &local, 1, &remote, 1, 0);
        if (vm_status == (long)size)
            return 0;
        // 失败则回退到 ptrace
    }

    // 小块或回退：逐字操作（原版风格，无额外内存拷贝）
    const word_t *src = reinterpret_cast<const word_t*>(src_tracer);
    const word_t nb_trailing_bytes = size % sizeof(word_t);
    const word_t nb_full_words = (size - nb_trailing_bytes) / sizeof(word_t);

    // 写入所有完整字
    for (word_t i = 0; i < nb_full_words; ++i) {
        if (ptrace(PTRACE_POKEDATA, tracee->pid, dest_tracee + i * sizeof(word_t), src[i]) < 0)
            return -errno;
    }

    // 处理尾部不足一个字的字节
    if (nb_trailing_bytes == 0)
        return 0;

    const word_t tail_addr = dest_tracee + nb_full_words * sizeof(word_t);
    errno = 0;
    word_t tail_word = ptrace(PTRACE_PEEKDATA, tracee->pid, tail_addr, NULL);
    if (errno != 0)
        return -errno;

    uint8_t *last_dest = reinterpret_cast<uint8_t*>(&tail_word);
    const uint8_t *last_src = reinterpret_cast<const uint8_t*>(&src[nb_full_words]);
    for (word_t j = 0; j < nb_trailing_bytes; ++j)
        last_dest[j] = last_src[j];

    if (ptrace(PTRACE_POKEDATA, tracee->pid, tail_addr, tail_word) < 0)
        return -errno;

    return 0;
}

extern "C" int writev_data(Tracee *tracee, word_t dest_tracee, const struct iovec *src_tracer, int src_tracer_count) {
    size_t offset = 0;
    for (int i = 0; i < src_tracer_count; ++i) {
        int ret = write_data(tracee, dest_tracee + offset, src_tracer[i].iov_base, src_tracer[i].iov_len);
        if (ret < 0)
            return ret;
        offset += src_tracer[i].iov_len;
    }
    return 0;
}

extern "C" int read_data(const Tracee *tracee, void *dest_tracer, word_t src_tracee, word_t size) {
    if (__builtin_expect(size == 0, 1))
        return 0;

    // 大块数据尝试 process_vm_readv
    if (size >= VM_FAST_THRESHOLD) {
        const struct iovec local = { .iov_base = dest_tracer, .iov_len = size };
        const struct iovec remote = { .iov_base = reinterpret_cast<void*>(src_tracee), .iov_len = size };
        errno = 0;
        long vm_status = syscall(SYS_process_vm_readv, tracee->pid, &local, 1, &remote, 1, 0);
        if (vm_status == (long)size)
            return 0;
        // 失败则回退
    }

    // 小块或回退：逐字读取（原版风格）
    word_t *dest = reinterpret_cast<word_t*>(dest_tracer);
    const word_t nb_trailing_bytes = size % sizeof(word_t);
    const word_t nb_full_words = (size - nb_trailing_bytes) / sizeof(word_t);

    for (word_t i = 0; i < nb_full_words; ++i) {
        errno = 0;
        word_t word = ptrace(PTRACE_PEEKDATA, tracee->pid, src_tracee + i * sizeof(word_t), NULL);
        if (errno != 0)
            return -errno;
        dest[i] = word;   // 直接赋值
    }

    if (nb_trailing_bytes == 0)
        return 0;

    const word_t tail_addr = src_tracee + nb_full_words * sizeof(word_t);
    errno = 0;
    word_t tail_word = ptrace(PTRACE_PEEKDATA, tracee->pid, tail_addr, NULL);
    if (errno != 0)
        return -errno;

    memcpy(dest + nb_full_words, &tail_word, nb_trailing_bytes);
    return 0;
}

// ============================================================================
// 字符串读取优化：短串走 ptrace，长串走 process_vm 分页
// ============================================================================

extern "C" int read_string(const Tracee *tracee, char *dest_tracer, word_t src_tracee, word_t max_size) {
    if (__builtin_expect(max_size == 0, 1))
        return 0;

    // 短字符串直接使用 ptrace 逐字读取，避免 process_vm 分页循环开销
    if (max_size <= SHORT_STRING_MAX) {
        uint8_t *d = reinterpret_cast<uint8_t*>(dest_tracer);
        const word_t *s = reinterpret_cast<const word_t*>(src_tracee);
        const word_t nb_trailing_bytes = max_size % sizeof(word_t);
        const word_t nb_full_words = (max_size - nb_trailing_bytes) / sizeof(word_t);

        for (word_t i = 0; i < nb_full_words; ++i) {
            errno = 0;
            word_t word = ptrace(PTRACE_PEEKDATA, tracee->pid, s + i, NULL);
            if (errno != 0)
                return -errno;

            memcpy(d + i * sizeof(word_t), &word, sizeof(word_t));

            const uint8_t *bytes = reinterpret_cast<const uint8_t*>(&word);
            for (word_t j = 0; j < sizeof(word_t); ++j) {
                if (bytes[j] == '\0')
                    return i * sizeof(word_t) + j + 1;
            }
        }

        if (nb_trailing_bytes > 0) {
            errno = 0;
            word_t word = ptrace(PTRACE_PEEKDATA, tracee->pid, s + nb_full_words, NULL);
            if (errno != 0)
                return -errno;

            memcpy(d + nb_full_words * sizeof(word_t), &word, nb_trailing_bytes);

            const uint8_t *bytes = reinterpret_cast<const uint8_t*>(&word);
            for (word_t j = 0; j < nb_trailing_bytes; ++j) {
                if (bytes[j] == '\0')
                    return nb_full_words * sizeof(word_t) + j + 1;
            }
        }

        return max_size;
    }

    // 长字符串：使用 process_vm_readv 分页读取
#if defined(HAVE_PROCESS_VM)
    long page_size = sysconf(_SC_PAGE_SIZE);
    if (page_size <= 0) page_size = 4096;
    size_t offset = 0;
    while (offset < max_size) {
        const uintptr_t chunk_base = (src_tracee + offset) & ~(page_size - 1);
        const size_t chunk_remain = page_size - ((src_tracee + offset) - chunk_base);
        const size_t copy_size = (chunk_remain < max_size - offset) ? chunk_remain : (max_size - offset);

        const struct iovec local = { .iov_base = dest_tracer + offset, .iov_len = copy_size };
        const struct iovec remote = { .iov_base = reinterpret_cast<void*>(src_tracee + offset), .iov_len = copy_size };

        errno = 0;
        long vm_status = syscall(SYS_process_vm_readv, tracee->pid, &local, 1, &remote, 1, 0);
        if (vm_status <= 0)
            break; // 回退到 ptrace

        // 检查结束符
        for (size_t i = 0; i < static_cast<size_t>(vm_status); ++i) {
            if (dest_tracer[offset + i] == '\0')
                return offset + i + 1;
        }

        offset += static_cast<size_t>(vm_status);
    }
#endif // HAVE_PROCESS_VM

    // 回退到 ptrace 逐字读取（原版 fallback）
    uint8_t *d = reinterpret_cast<uint8_t*>(dest_tracer);
    const word_t *s = reinterpret_cast<const word_t*>(src_tracee);
    const word_t nb_trailing_bytes = max_size % sizeof(word_t);
    const word_t nb_full_words = (max_size - nb_trailing_bytes) / sizeof(word_t);

    for (word_t i = 0; i < nb_full_words; ++i) {
        errno = 0;
        word_t word = ptrace(PTRACE_PEEKDATA, tracee->pid, s + i, NULL);
        if (errno != 0)
            return -errno;

        memcpy(d + i * sizeof(word_t), &word, sizeof(word_t));

        const uint8_t *bytes = reinterpret_cast<const uint8_t*>(&word);
        for (word_t j = 0; j < sizeof(word_t); ++j) {
            if (bytes[j] == '\0')
                return i * sizeof(word_t) + j + 1;
        }
    }

    if (nb_trailing_bytes > 0) {
        errno = 0;
        word_t word = ptrace(PTRACE_PEEKDATA, tracee->pid, s + nb_full_words, NULL);
        if (errno != 0)
            return -errno;

        memcpy(d + nb_full_words * sizeof(word_t), &word, nb_trailing_bytes);

        const uint8_t *bytes = reinterpret_cast<const uint8_t*>(&word);
        for (word_t j = 0; j < nb_trailing_bytes; ++j) {
            if (bytes[j] == '\0')
                return nb_full_words * sizeof(word_t) + j + 1;
        }
    }

    return max_size;
}

// ============================================================================
// 单字操作（原版风格）
// ============================================================================

extern "C" word_t peek_word(const Tracee *tracee, word_t address) {
    word_t result;

#if defined(HAVE_PROCESS_VM)
    const struct iovec local = { .iov_base = &result, .iov_len = sizeof(word_t) };
    const struct iovec remote = { .iov_base = reinterpret_cast<void*>(address), .iov_len = sizeof(word_t) };
    errno = 0;
    long vm_status = syscall(SYS_process_vm_readv, tracee->pid, &local, 1, &remote, 1, 0);
    if (vm_status == sizeof(word_t))
        goto final_adjust;
#endif

    errno = 0;
    result = static_cast<word_t>(ptrace(PTRACE_PEEKDATA, tracee->pid, reinterpret_cast<void*>(address), NULL));
    if (errno == EIO)
        errno = EFAULT;

final_adjust:
    return is_32on64_mode(tracee) ? (result & 0xFFFFFFFFULL) : result;
}

extern "C" void poke_word(const Tracee *tracee, word_t address, word_t value) {
#if defined(HAVE_PROCESS_VM)
    word_t write_val = is_32on64_mode(tracee) ? (value & 0xFFFFFFFFULL) : value;
    const struct iovec local = { .iov_base = &write_val, .iov_len = sizeof(word_t) };
    const struct iovec remote = { .iov_base = reinterpret_cast<void*>(address), .iov_len = sizeof(word_t) };
    errno = 0;
    long vm_status = syscall(SYS_process_vm_writev, tracee->pid, &local, 1, &remote, 1, 0);
    if (vm_status == sizeof(word_t))
        return;
#endif

    errno = 0;
    ptrace(PTRACE_POKEDATA, tracee->pid, reinterpret_cast<void*>(address), value);
    if (errno == EIO)
        errno = EFAULT;
}

// ============================================================================
// 内存分配与清除（原版逻辑）
// ============================================================================

extern "C" word_t alloc_mem(Tracee *tracee, ssize_t size) {
    assert(IS_IN_SYSENTER(tracee));
    word_t sp = peek_reg(tracee, CURRENT, STACK_POINTER);

    if (sp == peek_reg(tracee, ORIGINAL, STACK_POINTER))
        size += ARM64_RED_ZONE;

    if (__builtin_expect((size > 0 && sp <= static_cast<word_t>(size)) ||
                         (size < 0 && sp >= static_cast<word_t>(ULONG_MAX + size)), 0))
        return 0;

    sp -= size;
    poke_reg(tracee, STACK_POINTER, sp);
    return sp;
}

extern "C" int clear_mem(Tracee *tracee, word_t address, size_t size) {
    if (__builtin_expect(size == 0, 1))
        return 0;

    // 分配零页内存，写入后释放
    void *zeros = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (zeros == MAP_FAILED)
        return -errno;

    int ret = write_data(tracee, address, zeros, size);
    munmap(zeros, size);
    return ret;
}