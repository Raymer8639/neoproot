#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#define NO_LIBC_HEADER
#include "loader/script.h"
#include "compat.h"
#include "arch.h"

#include "loader/assembly-arm64.h"

#if !defined(MMAP_OFFSET_SHIFT)
#    define MMAP_OFFSET_SHIFT 0
#endif

#define FATAL_EXIT_CODE 182
#define UNLIKELY(expr) __builtin_expect(!!(expr), 0)
#define LIKELY(expr)  __builtin_expect(!!(expr), 1)

typedef word_t   WordType;
typedef byte_t   ByteType;
typedef LoadStatement *LoadStmtPtr;

static inline void clear(WordType start, WordType end)
{
    const size_t sz = sizeof(WordType);

    // 安全防护：防止越界清空 ld.so 结构体
    if (end <= start || end - start > 2 * 1024 * 1024)
        return;

    uint8_t *p = (uint8_t *)start;
    uint8_t *e = (uint8_t *)end;

    // 未对齐头部
    for (; ((uintptr_t)p & (sz - 1)) && p < e; p++)
        *p = 0;

    // 对齐字循环（AArch64 最优）
    WordType *w = (WordType *)p;
    for (; (uint8_t *)(w + 1) <= e; w++)
        *w = 0;

    // 未对齐尾部
    p = (uint8_t *)w;
    for (; p < e; p++)
        *p = 0;
}

static inline WordType basename(WordType string_addr)
{
    uint8_t *s = (uint8_t *)string_addr;
    if (UNLIKELY(!s || *s == 0))
        return string_addr;

    uint8_t *end = s;
    while (*end)
        end++;

    while (end > s && *(end - 1) != '/')
        end--;

    return (end != s) ? (WordType)(end) : string_addr;
}

extern "C" void _start(void *cursor)
{
    bool     traced       = false;
    bool     reset_at_base = true;
    WordType at_base      = 0;
    WordType fd           = -1;
    WordType status;

    LoadStmtPtr stmt = (LoadStmtPtr)cursor;

    while (LIKELY(1)) {
        switch (stmt->action) {
        case LOAD_ACTION_OPEN_NEXT:
            status = SYSCALL(CLOSE, 1, fd);
            if (UNLIKELY((int)status < 0))
                goto fatal;
            // fallthrough

        case LOAD_ACTION_OPEN:
#if defined(OPEN)
            fd = SYSCALL(OPEN, 3, stmt->open.string_address, O_RDONLY, 0);
#else
            fd = SYSCALL(OPENAT, 4, AT_FDCWD, stmt->open.string_address, O_RDONLY, 0);
#endif
            if (UNLIKELY((int)fd < 0))
                goto fatal;

            reset_at_base = true;
            cursor = (void *)((WordType)cursor + LOAD_STATEMENT_SIZE(*stmt, open));
            stmt = (LoadStmtPtr)cursor;
            break;

        case LOAD_ACTION_MMAP_FILE:
            status = SYSCALL(MMAP, 6,
                stmt->mmap.addr, stmt->mmap.length,
                stmt->mmap.prot, MAP_PRIVATE | MAP_FIXED,
                fd, stmt->mmap.offset >> MMAP_OFFSET_SHIFT);

            if (UNLIKELY(status != stmt->mmap.addr))
                goto fatal;

            if (stmt->mmap.clear_length != 0) {
                clear(stmt->mmap.addr + stmt->mmap.length - stmt->mmap.clear_length,
                      stmt->mmap.addr + stmt->mmap.length);
            }

            if (reset_at_base) {
                at_base = stmt->mmap.addr;
                reset_at_base = false;
            }

            cursor = (void *)((WordType)cursor + LOAD_STATEMENT_SIZE(*stmt, mmap));
            stmt = (LoadStmtPtr)cursor;
            break;

        case LOAD_ACTION_MMAP_ANON:
            status = SYSCALL(MMAP, 6,
                stmt->mmap.addr, stmt->mmap.length,
                stmt->mmap.prot, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);

            if (UNLIKELY(status != stmt->mmap.addr))
                goto fatal;

            cursor = (void *)((WordType)cursor + LOAD_STATEMENT_SIZE(*stmt, mmap));
            stmt = (LoadStmtPtr)cursor;
            break;

        case LOAD_ACTION_MAKE_STACK_EXEC:
            SYSCALL(MPROTECT, 3,
                stmt->make_stack_exec.start, 1,
                PROT_READ | PROT_WRITE | PROT_EXEC | PROT_GROWSDOWN);

            cursor = (void *)((WordType)cursor + LOAD_STATEMENT_SIZE(*stmt, make_stack_exec));
            stmt = (LoadStmtPtr)cursor;
            break;

        case LOAD_ACTION_START_TRACED:
            traced = true;
            // fallthrough

        case LOAD_ACTION_START: {
            WordType *sp = (WordType *)stmt->start.stack_pointer;
            const WordType argc     = sp[0];
            const WordType at_execfn= sp[1];

            status = SYSCALL(CLOSE, 1, fd);
            if (UNLIKELY((int)status < 0))
                goto fatal;

            // 跳过 argv
            sp += argc + 1;

            // 跳过 envp
            do { sp++; } while (sp[0] != 0);
            sp++;

            // 修补 auxv
            do {
                switch (sp[0]) {
                    case AT_PHDR:    sp[1] = stmt->start.at_phdr;    break;
                    case AT_PHENT:   sp[1] = stmt->start.at_phent;   break;
                    case AT_PHNUM:   sp[1] = stmt->start.at_phnum;   break;
                    case AT_ENTRY:   sp[1] = stmt->start.at_entry;   break;
                    case AT_BASE:    sp[1] = at_base;                break;
                    // 2026-08-15：AT_EXECFN 覆写为 argv[0] 指针（= 上方
                    // 捕获的 at_execfn，guest 程序的真实名字）。历史教训：
                    // stmt->start.at_execfn 指向 raw host 路径（addr3），
                    // 会把 host 路径暴露给 guest——必须用栈上 argv[0] 指针。
                    case AT_EXECFN:  sp[1] = at_execfn;              break;
                    default: break;
                }
                sp += 2;
            } while (sp[0] != AT_NULL);

            // 使用栈上原始 at_execfn（argv[0] 指针），不用 stmt->start.at_execfn
            WordType name = basename(at_execfn);
            SYSCALL(PRCTL, 3, PR_SET_NAME, name, 0);

            if (UNLIKELY(traced)) {
                SYSCALL(EXECVE, 6,
                    1, stmt->start.stack_pointer, stmt->start.entry_point,
                    2, 3, 4);
            } else {
                BRANCH(stmt->start.stack_pointer, stmt->start.entry_point);
            }

            goto fatal;
        }

        default:
            goto fatal;
        }
    }

fatal:
    SYSCALL(EXIT, 1, FATAL_EXIT_CODE);
    __builtin_unreachable();
}
