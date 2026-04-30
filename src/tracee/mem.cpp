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
#include <arm_neon.h>

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
// 可调参数（ARMv8.2 优化阈值）
// ============================================================================

static constexpr size_t VM_FAST_THRESHOLD = 32 * 1024;  // process_vm_* 阈值
static constexpr size_t ARM64_RED_ZONE = 128;           // 栈红区
static constexpr size_t SHORT_STRING_MAX = 256;         // 短字符串阈值
static constexpr size_t NEON_VEC_BYTES = 16;            // NEON 向量宽度

#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define ALWAYS_INLINE __attribute__((always_inline)) inline

static ALWAYS_INLINE void neon_memcpy_fast(void *__restrict dst, const void *__restrict src, size_t len) noexcept {
    if (UNLIKELY(!dst || !src || len == 0)) return;

    uint8_t *__restrict d = static_cast<uint8_t *>(dst);
    const uint8_t *__restrict s = static_cast<const uint8_t *>(src);

    // 对齐到 16 字节
    size_t align = (NEON_VEC_BYTES - (reinterpret_cast<uintptr_t>(d) & (NEON_VEC_BYTES - 1))) & (NEON_VEC_BYTES - 1);
    if (len < align) align = len;
    if (align > 0) {
        __builtin_memcpy(d, s, align);
        d += align;
        s += align;
        len -= align;
    }

    // 64 字节块展开
    while (len >= NEON_VEC_BYTES * 4) {
        uint8x16_t v0 = vld1q_u8(s);
        uint8x16_t v1 = vld1q_u8(s + NEON_VEC_BYTES);
        uint8x16_t v2 = vld1q_u8(s + NEON_VEC_BYTES * 2);
        uint8x16_t v3 = vld1q_u8(s + NEON_VEC_BYTES * 3);
        vst1q_u8(d, v0);
        vst1q_u8(d + NEON_VEC_BYTES, v1);
        vst1q_u8(d + NEON_VEC_BYTES * 2, v2);
        vst1q_u8(d + NEON_VEC_BYTES * 3, v3);
        d += NEON_VEC_BYTES * 4;
        s += NEON_VEC_BYTES * 4;
        len -= NEON_VEC_BYTES * 4;
    }

    while (len >= NEON_VEC_BYTES) {
        uint8x16_t v = vld1q_u8(s);
        vst1q_u8(d, v);
        d += NEON_VEC_BYTES;
        s += NEON_VEC_BYTES;
        len -= NEON_VEC_BYTES;
    }

    if (len > 0) __builtin_memcpy(d, s, len);
}

static ALWAYS_INLINE void neon_memset_zero_fast(void *dst, size_t len) noexcept {
    if (UNLIKELY(!dst || len == 0)) return;

    uint8_t *d = static_cast<uint8_t *>(dst);
    const uint8x16_t zero = vdupq_n_u8(0);

    size_t align = (NEON_VEC_BYTES - (reinterpret_cast<uintptr_t>(d) & (NEON_VEC_BYTES - 1))) & (NEON_VEC_BYTES - 1);
    if (len < align) align = len;
    if (align > 0) {
        __builtin_memset(d, 0, align);
        d += align;
        len -= align;
    }

    while (len >= NEON_VEC_BYTES * 4) {
        vst1q_u8(d, zero);
        vst1q_u8(d + NEON_VEC_BYTES, zero);
        vst1q_u8(d + NEON_VEC_BYTES * 2, zero);
        vst1q_u8(d + NEON_VEC_BYTES * 3, zero);
        d += NEON_VEC_BYTES * 4;
        len -= NEON_VEC_BYTES * 4;
    }

    while (len >= NEON_VEC_BYTES) {
        vst1q_u8(d, zero);
        d += NEON_VEC_BYTES;
        len -= NEON_VEC_BYTES;
    }

    if (len > 0) __builtin_memset(d, 0, len);
}

static ALWAYS_INLINE size_t neon_find_zero_fast(const uint8_t *buf, size_t len) noexcept {
    if (UNLIKELY(!buf || len == 0)) return 0;

    size_t i = 0;
    const uint8x16_t zero = vdupq_n_u8(0);

    size_t align = (NEON_VEC_BYTES - (reinterpret_cast<uintptr_t>(buf) & (NEON_VEC_BYTES - 1))) & (NEON_VEC_BYTES - 1);
    if (len < align) align = len;
    for (; i < align; ++i) if (buf[i] == '\0') return i;

    for (; i + NEON_VEC_BYTES <= len; i += NEON_VEC_BYTES) {
        uint8x16_t v = vld1q_u8(buf + i);
        uint8x16_t eq = vceqq_u8(v, zero);
        if (UNLIKELY(vmaxvq_u8(eq) != 0)) {
            for (size_t j = i; j < i + NEON_VEC_BYTES; ++j)
                if (buf[j] == '\0') return j;
        }
    }

    for (; i < len; ++i) if (buf[i] == '\0') return i;
    return len;
}

// ============================================================================
// 无用的钩子（保持接口兼容）
// ============================================================================

extern "C" void mem_prepare_after_execve(Tracee *tracee) { (void)tracee; }
extern "C" void mem_prepare_before_first_execve(Tracee *tracee) { (void)tracee; }

// ============================================================================
// 核心读写函数
// ============================================================================

extern "C" int write_data(Tracee *tracee, word_t dest_tracee, const void *src_tracer, word_t size) {
    if (LIKELY(size == 0)) return 0;

    if (size >= VM_FAST_THRESHOLD) {
        const struct iovec local = { .iov_base = const_cast<void*>(src_tracer), .iov_len = size };
        const struct iovec remote = { .iov_base = reinterpret_cast<void*>(dest_tracee), .iov_len = size };
        errno = 0;
        long vm_status = syscall(SYS_process_vm_writev, tracee->pid, &local, 1, &remote, 1, 0);
        if (LIKELY(vm_status == (long)size)) return 0;
    }

    const word_t *src = reinterpret_cast<const word_t*>(src_tracer);
    const word_t nb_trailing_bytes = size % sizeof(word_t);
    const word_t nb_full_words = (size - nb_trailing_bytes) / sizeof(word_t);

    for (word_t i = 0; i < nb_full_words; ++i) {
        if (UNLIKELY(ptrace(PTRACE_POKEDATA, tracee->pid, dest_tracee + i * sizeof(word_t), src[i]) < 0))
            return -errno;
    }

    if (nb_trailing_bytes == 0) return 0;

    const word_t tail_addr = dest_tracee + nb_full_words * sizeof(word_t);
    errno = 0;
    word_t tail_word = ptrace(PTRACE_PEEKDATA, tracee->pid, tail_addr, NULL);
    if (UNLIKELY(errno != 0)) return -errno;

    uint8_t *last_dest = reinterpret_cast<uint8_t*>(&tail_word);
    const uint8_t *last_src = reinterpret_cast<const uint8_t*>(&src[nb_full_words]);
    for (word_t j = 0; j < nb_trailing_bytes; ++j) last_dest[j] = last_src[j];

    if (UNLIKELY(ptrace(PTRACE_POKEDATA, tracee->pid, tail_addr, tail_word) < 0))
        return -errno;
    return 0;
}

extern "C" int writev_data(Tracee *tracee, word_t dest_tracee, const struct iovec *src_tracer, int src_tracer_count) {
    size_t offset = 0;
    for (int i = 0; i < src_tracer_count; ++i) {
        int ret = write_data(tracee, dest_tracee + offset, src_tracer[i].iov_base, src_tracer[i].iov_len);
        if (UNLIKELY(ret < 0)) return ret;
        offset += src_tracer[i].iov_len;
    }
    return 0;
}

extern "C" int read_data(const Tracee *tracee, void *dest_tracer, word_t src_tracee, word_t size) {
    if (LIKELY(size == 0)) return 0;

    if (size >= VM_FAST_THRESHOLD) {
        const struct iovec local = { .iov_base = dest_tracer, .iov_len = size };
        const struct iovec remote = { .iov_base = reinterpret_cast<void*>(src_tracee), .iov_len = size };
        errno = 0;
        long vm_status = syscall(SYS_process_vm_readv, tracee->pid, &local, 1, &remote, 1, 0);
        if (LIKELY(vm_status == (long)size)) return 0;
    }

    word_t *dest = reinterpret_cast<word_t*>(dest_tracer);
    const word_t nb_trailing_bytes = size % sizeof(word_t);
    const word_t nb_full_words = (size - nb_trailing_bytes) / sizeof(word_t);

    for (word_t i = 0; i < nb_full_words; ++i) {
        errno = 0;
        word_t word = ptrace(PTRACE_PEEKDATA, tracee->pid, src_tracee + i * sizeof(word_t), NULL);
        if (UNLIKELY(errno != 0)) return -errno;
        dest[i] = word;
    }

    if (nb_trailing_bytes == 0) return 0;

    const word_t tail_addr = src_tracee + nb_full_words * sizeof(word_t);
    errno = 0;
    word_t tail_word = ptrace(PTRACE_PEEKDATA, tracee->pid, tail_addr, NULL);
    if (UNLIKELY(errno != 0)) return -errno;

    neon_memcpy_fast(dest + nb_full_words, &tail_word, nb_trailing_bytes);
    return 0;
}

// ============================================================================
// 字符串读取
// ============================================================================

extern "C" int read_string(const Tracee *tracee, char *dest_tracer, word_t src_tracee, word_t max_size) {
    if (LIKELY(max_size == 0)) return 0;

    if (max_size <= SHORT_STRING_MAX) {
        uint8_t *d = reinterpret_cast<uint8_t*>(dest_tracer);
        const word_t *s = reinterpret_cast<const word_t*>(src_tracee);
        const word_t nb_trailing_bytes = max_size % sizeof(word_t);
        const word_t nb_full_words = (max_size - nb_trailing_bytes) / sizeof(word_t);

        for (word_t i = 0; i < nb_full_words; ++i) {
            errno = 0;
            word_t word = ptrace(PTRACE_PEEKDATA, tracee->pid, s + i, NULL);
            if (UNLIKELY(errno != 0)) return -errno;

            neon_memcpy_fast(d + i * sizeof(word_t), &word, sizeof(word_t));
            size_t zero_off = neon_find_zero_fast(d + i * sizeof(word_t), sizeof(word_t));
            if (LIKELY(zero_off < sizeof(word_t)))
                return static_cast<int>(i * sizeof(word_t) + zero_off + 1);
        }

        if (nb_trailing_bytes > 0) {
            errno = 0;
            word_t word = ptrace(PTRACE_PEEKDATA, tracee->pid, s + nb_full_words, NULL);
            if (UNLIKELY(errno != 0)) return -errno;

            neon_memcpy_fast(d + nb_full_words * sizeof(word_t), &word, nb_trailing_bytes);
            size_t zero_off = neon_find_zero_fast(d + nb_full_words * sizeof(word_t), nb_trailing_bytes);
            if (LIKELY(zero_off < nb_trailing_bytes))
                return static_cast<int>(nb_full_words * sizeof(word_t) + zero_off + 1);
        }
        return static_cast<int>(max_size);
    }

#if defined(HAVE_PROCESS_VM)
    long page_size = sysconf(_SC_PAGE_SIZE);
    if (page_size <= 0) page_size = 4096;
    size_t offset = 0;
    while (offset < max_size) {
        uintptr_t chunk_base = (src_tracee + offset) & ~(static_cast<uintptr_t>(page_size) - 1);
        size_t chunk_remain = static_cast<size_t>(page_size) - ((src_tracee + offset) - chunk_base);
        size_t copy_size = (chunk_remain < max_size - offset) ? chunk_remain : (max_size - offset);

        struct iovec local = { .iov_base = dest_tracer + offset, .iov_len = copy_size };
        struct iovec remote = { .iov_base = reinterpret_cast<void*>(src_tracee + offset), .iov_len = copy_size };
        errno = 0;
        long vm_status = syscall(SYS_process_vm_readv, tracee->pid, &local, 1, &remote, 1, 0);
        if (UNLIKELY(vm_status <= 0)) break;

        size_t zero_off = neon_find_zero_fast(reinterpret_cast<uint8_t*>(dest_tracer + offset),
                                              static_cast<size_t>(vm_status));
        if (LIKELY(zero_off < static_cast<size_t>(vm_status)))
            return static_cast<int>(offset + zero_off + 1);
        offset += static_cast<size_t>(vm_status);
    }
#endif

    // 回退到 ptrace
    uint8_t *d = reinterpret_cast<uint8_t*>(dest_tracer);
    const word_t *s = reinterpret_cast<const word_t*>(src_tracee);
    const word_t nb_trailing_bytes = max_size % sizeof(word_t);
    const word_t nb_full_words = (max_size - nb_trailing_bytes) / sizeof(word_t);

    for (word_t i = 0; i < nb_full_words; ++i) {
        errno = 0;
        word_t word = ptrace(PTRACE_PEEKDATA, tracee->pid, s + i, NULL);
        if (UNLIKELY(errno != 0)) return -errno;
        neon_memcpy_fast(d + i * sizeof(word_t), &word, sizeof(word_t));
        size_t zero_off = neon_find_zero_fast(d + i * sizeof(word_t), sizeof(word_t));
        if (LIKELY(zero_off < sizeof(word_t)))
            return static_cast<int>(i * sizeof(word_t) + zero_off + 1);
    }

    if (nb_trailing_bytes > 0) {
        errno = 0;
        word_t word = ptrace(PTRACE_PEEKDATA, tracee->pid, s + nb_full_words, NULL);
        if (UNLIKELY(errno != 0)) return -errno;
        neon_memcpy_fast(d + nb_full_words * sizeof(word_t), &word, nb_trailing_bytes);
        size_t zero_off = neon_find_zero_fast(d + nb_full_words * sizeof(word_t), nb_trailing_bytes);
        if (LIKELY(zero_off < nb_trailing_bytes))
            return static_cast<int>(nb_full_words * sizeof(word_t) + zero_off + 1);
    }
    return static_cast<int>(max_size);
}

extern "C" word_t peek_word(const Tracee *tracee, word_t address) {
    word_t result;
#if defined(HAVE_PROCESS_VM)
    struct iovec local = { .iov_base = &result, .iov_len = sizeof(word_t) };
    struct iovec remote = { .iov_base = reinterpret_cast<void*>(address), .iov_len = sizeof(word_t) };
    errno = 0;
    long vm_status = syscall(SYS_process_vm_readv, tracee->pid, &local, 1, &remote, 1, 0);
    if (LIKELY(vm_status == sizeof(word_t))) return result;
#endif
    errno = 0;
    result = static_cast<word_t>(ptrace(PTRACE_PEEKDATA, tracee->pid, reinterpret_cast<void*>(address), NULL));
    if (UNLIKELY(errno == EIO)) errno = EFAULT;
    return result;
}

extern "C" void poke_word(const Tracee *tracee, word_t address, word_t value) {
#if defined(HAVE_PROCESS_VM)
    struct iovec local = { .iov_base = &value, .iov_len = sizeof(word_t) };
    struct iovec remote = { .iov_base = reinterpret_cast<void*>(address), .iov_len = sizeof(word_t) };
    errno = 0;
    long vm_status = syscall(SYS_process_vm_writev, tracee->pid, &local, 1, &remote, 1, 0);
    if (LIKELY(vm_status == sizeof(word_t))) return;
#endif
    errno = 0;
    ptrace(PTRACE_POKEDATA, tracee->pid, reinterpret_cast<void*>(address), value);
    if (UNLIKELY(errno == EIO)) errno = EFAULT;
}

// ============================================================================
// 内存分配与清除
// ============================================================================

extern "C" word_t alloc_mem(Tracee *tracee, ssize_t size) {
    assert(IS_IN_SYSENTER(tracee));
    word_t sp = peek_reg(tracee, CURRENT, STACK_POINTER);
    if (LIKELY(sp == peek_reg(tracee, ORIGINAL, STACK_POINTER)))
        size += ARM64_RED_ZONE;
    if (UNLIKELY((size > 0 && sp <= static_cast<word_t>(size)) ||
                 (size < 0 && sp >= static_cast<word_t>(ULONG_MAX + size))))
        return 0;
    sp -= size;
    poke_reg(tracee, STACK_POINTER, sp);
    return sp;
}

extern "C" int clear_mem(Tracee *tracee, word_t address, size_t size) {
    if (LIKELY(size == 0)) return 0;
    if (size <= 4096) {
        uint8_t zero_buf[4096];
        neon_memset_zero_fast(zero_buf, size);
        return write_data(tracee, address, zero_buf, size);
    }
    void *zeros = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (UNLIKELY(zeros == MAP_FAILED)) return -errno;
    int ret = write_data(tracee, address, zeros, size);
    munmap(zeros, size);
    return ret;
}