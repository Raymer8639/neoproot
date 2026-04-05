#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#define NO_LIBC_HEADER
#include "loader/script.h"
#include "compat.h"
#include "arch.h"

// 仅保留aarch64汇编头，彻底删除其他架构分支
#include "loader/assembly-arm64.h"

#if !defined(MMAP_OFFSET_SHIFT)
#    define MMAP_OFFSET_SHIFT 0
#endif

// 安卓aarch64专属定义，替换C++ constexpr，适配编译器
#define FATAL_EXIT_CODE 182
#define UNLIKELY(expr) __builtin_expect(expr, 0)

// 强类型别名，保留编译器优化潜力
typedef word_t WordType;
typedef byte_t ByteType;
typedef LoadStatement* LoadStmtPtr;

/**
 * aarch64专属内存清零：纯C实现，保留对齐优化，编译器自动向量化
 */
static inline void clear(WordType start, WordType end) {
    const size_t WORD_SIZE = sizeof(WordType);
    const WordType start_offset = start % WORD_SIZE;
    const WordType end_offset = end % WORD_SIZE;

    WordType* start_aligned = (WordType*)(start_offset ? start + WORD_SIZE - start_offset : start);
    WordType* end_aligned = (WordType*)(end - end_offset);

    // 清零前置未对齐字节
    uint8_t* start_misaligned = (uint8_t*)start;
    while (start_misaligned < (uint8_t*)start_aligned) {
        *start_misaligned++ = 0;
    }

    // 对齐内存块清零（aarch64 8字节对齐，性能最优）
    while (start_aligned < end_aligned) {
        *start_aligned++ = 0;
    }

    // 清零后置未对齐字节
    uint8_t* end_misaligned = (uint8_t*)end_aligned;
    while (end_misaligned < (uint8_t*)end) {
        *end_misaligned++ = 0;
    }
}

/**
 * 优化版basename：双指针遍历，纯C类型转换，适配aarch64
 */
static inline WordType basename(WordType string_addr) {
    uint8_t* string = (uint8_t*)string_addr;
    if (UNLIKELY(!string || *string == '\0')) {
        return string_addr;
    }

    uint8_t* end = string;
    while (*end != '\0') {
        end++;
    }

    while (end > string && *end != '/') {
        end--;
    }

    return (end != string) ? (WordType)(end + 1) : string_addr;
}

/**
 * 核心加载入口：extern "C" 保证汇编调用兼容，aarch64专属逻辑
 */
extern "C" void _start(void* cursor) {
    bool traced = false;
    bool reset_at_base = true;
    WordType at_base = 0;
    WordType fd = -1;
    WordType status;

    LoadStmtPtr stmt = (LoadStmtPtr)cursor;

    while (true) {
        switch (stmt->action) {
            case LOAD_ACTION_OPEN_NEXT:
                status = SYSCALL(CLOSE, 1, fd);
                if (UNLIKELY((int)status < 0)) {
                    SYSCALL(EXIT, 1, FATAL_EXIT_CODE);
                    __builtin_unreachable();
                }
                // fallthrough

            case LOAD_ACTION_OPEN:
#if defined(OPEN)
                fd = SYSCALL(OPEN, 3, stmt->open.string_address, O_RDONLY, 0);
#else
                fd = SYSCALL(OPENAT, 4, AT_FDCWD, stmt->open.string_address, O_RDONLY, 0);
#endif
                if (UNLIKELY((int)fd < 0)) {
                    SYSCALL(EXIT, 1, FATAL_EXIT_CODE);
                    __builtin_unreachable();
                }
                reset_at_base = true;
                cursor = (void*)((WordType)cursor + LOAD_STATEMENT_SIZE(*stmt, open));
                stmt = (LoadStmtPtr)cursor;
                break;

            case LOAD_ACTION_MMAP_FILE:
                status = SYSCALL(MMAP, 6, stmt->mmap.addr, stmt->mmap.length,
                    stmt->mmap.prot, MAP_PRIVATE | MAP_FIXED, fd,
                    stmt->mmap.offset >> MMAP_OFFSET_SHIFT);
                if (UNLIKELY(status != stmt->mmap.addr)) {
                    SYSCALL(EXIT, 1, FATAL_EXIT_CODE);
                    __builtin_unreachable();
                }

                if (stmt->mmap.clear_length != 0) {
                    clear(stmt->mmap.addr + stmt->mmap.length - stmt->mmap.clear_length,
                        stmt->mmap.addr + stmt->mmap.length);
                }

                if (reset_at_base) {
                    at_base = stmt->mmap.addr;
                    reset_at_base = false;
                }

                cursor = (void*)((WordType)cursor + LOAD_STATEMENT_SIZE(*stmt, mmap));
                stmt = (LoadStmtPtr)cursor;
                break;

            case LOAD_ACTION_MMAP_ANON:
                status = SYSCALL(MMAP, 6, stmt->mmap.addr, stmt->mmap.length,
                    stmt->mmap.prot, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
                if (UNLIKELY(status != stmt->mmap.addr)) {
                    SYSCALL(EXIT, 1, FATAL_EXIT_CODE);
                    __builtin_unreachable();
                }

                cursor = (void*)((WordType)cursor + LOAD_STATEMENT_SIZE(*stmt, mmap));
                stmt = (LoadStmtPtr)cursor;
                break;

            case LOAD_ACTION_MAKE_STACK_EXEC:
                SYSCALL(MPROTECT, 3,
                    stmt->make_stack_exec.start, 1,
                    PROT_READ | PROT_WRITE | PROT_EXEC | PROT_GROWSDOWN);

                cursor = (void*)((WordType)cursor + LOAD_STATEMENT_SIZE(*stmt, make_stack_exec));
                stmt = (LoadStmtPtr)cursor;
                break;

            case LOAD_ACTION_START_TRACED:
                traced = true;
                // fallthrough

            case LOAD_ACTION_START: {
                WordType* cursor2 = (WordType*)stmt->start.stack_pointer;
                const WordType argc = cursor2[0];
                const WordType at_execfn = cursor2[1];
                WordType name;

                status = SYSCALL(CLOSE, 1, fd);
                if (UNLIKELY((int)status < 0)) {
                    SYSCALL(EXIT, 1, FATAL_EXIT_CODE);
                    __builtin_unreachable();
                }

                // 跳过argv[]
                cursor2 += argc + 1;

                // 跳过envp[]
                do { cursor2++; } while (cursor2[0] != 0);
                cursor2++;

                // 调整auxv[]
                do {
                    switch (cursor2[0]) {
                        case AT_PHDR:  cursor2[1] = stmt->start.at_phdr;  break;
                        case AT_PHENT: cursor2[1] = stmt->start.at_phent; break;
                        case AT_PHNUM: cursor2[1] = stmt->start.at_phnum; break;
                        case AT_ENTRY: cursor2[1] = stmt->start.at_entry; break;
                        case AT_BASE:  cursor2[1] = at_base;             break;
                        case AT_EXECFN:cursor2[1] = at_execfn;           break;
                        default: break;
                    }
                    cursor2 += 2;
                } while (cursor2[0] != AT_NULL);

                // 获取程序名，启动执行
                name = basename(stmt->start.at_execfn);
                SYSCALL(PRCTL, 3, PR_SET_NAME, name, 0);

                if (UNLIKELY(traced)) {
                    SYSCALL(EXECVE, 6, 1, stmt->start.stack_pointer, stmt->start.entry_point, 2, 3, 4);
                } else {
                    BRANCH(stmt->start.stack_pointer, stmt->start.entry_point);
                }
                SYSCALL(EXIT, 1, FATAL_EXIT_CODE);
                __builtin_unreachable();
            }

            default:
                SYSCALL(EXIT, 1, FATAL_EXIT_CODE);
                __builtin_unreachable();
        }
    }

    SYSCALL(EXIT, 1, FATAL_EXIT_CODE);
    __builtin_unreachable();
}
