/* Host-only tests of the production auxv and exec-exit helpers. */
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

/* Include the implementation to exercise its private capture/serialization
 * helpers. Unused exec/loader code is discarded by --gc-sections. */
#include "../src/execve/exit.c"

static word_t stack_words[32];
static word_t stack_pointer;
static word_t unreadable;
static word_t syscall_result;
static Binding *current_binding;

word_t peek_reg(const Tracee *tracee, RegVersion version, Reg reg)
{
    (void)tracee;
    (void)version;
    if (reg == SYSARG_RESULT)
        return syscall_result;
    assert(reg == STACK_POINTER);
    return stack_pointer;
}

word_t peek_word(const Tracee *tracee, word_t address)
{
    (void)tracee;
    word_t first = (word_t)stack_words;
    if (address == unreadable || address < first ||
        address - first >= sizeof(stack_words) ||
        (address - first) % sizeof(word_t) != 0) {
        errno = EFAULT;
        return 0;
    }
    errno = 0;
    return stack_words[(address - first) / sizeof(word_t)];
}

Sysnum get_sysnum(const Tracee *tracee, RegVersion version)
{
    (void)tracee;
    (void)version;
    return PR_execve;
}

void poke_reg(Tracee *tracee, Reg reg, word_t value)
{
    (void)tracee; (void)reg; (void)value;
    assert(!"unexpected loader register write in skip-loader test");
}

void save_current_regs(Tracee *tracee, RegVersion version)
{
    (void)tracee; (void)version;
    assert(!"unexpected loader register save in skip-loader test");
}

void set_sysnum(Tracee *tracee, Sysnum number)
{
    (void)tracee; (void)number;
    assert(!"unexpected loader syscall rewrite in skip-loader test");
}

void mem_prepare_after_execve(Tracee *tracee)
{
    (void)tracee;
    assert(!"unexpected loader memory setup in skip-loader test");
}

int write_data(Tracee *tracee, word_t address, const void *data, word_t size)
{
    (void)tracee; (void)address; (void)data; (void)size;
    assert(!"unexpected loader memory write in skip-loader test");
    return -EFAULT;
}

/* Binding insertion is a seam: the real temporary-file destructor and real
 * auxv fetch/serialize code are linked from their production source files. */
Binding *get_binding(const Tracee *tracee, Side side, const char path[PATH_MAX])
{
    (void)tracee;
    assert(side == GUEST);
    (void)path;
    return current_binding;
}

void remove_binding_from_all_lists(const Tracee *tracee, Binding *binding)
{
    (void)tracee;
    assert(binding == current_binding);
    current_binding = NULL;
}

Binding *insort_binding4(const Tracee *tracee, const TALLOC_CTX *context,
                        const char host[PATH_MAX], const char guest[PATH_MAX],
                        BindingMountKind kind)
{
    (void)tracee;
    assert(kind == BINDING_MOUNT_INTERNAL);
    current_binding = talloc_zero(context, Binding);
    assert(current_binding);
    assert(strlen(host) < sizeof(current_binding->host.path));
    assert(strlen(guest) < sizeof(current_binding->guest.path));
    strcpy(current_binding->host.path, host);
    strcpy(current_binding->guest.path, guest);
    return current_binding;
}

void note(const Tracee *tracee, Severity severity, Origin origin,
          const char *message, ...)
{
    (void)tracee;
    (void)severity;
    (void)origin;
    va_list args;
    va_start(args, message);
    vfprintf(stderr, message, args);
    va_end(args);
    abort();
}

static void initialize_stack(void)
{
    memset(stack_words, 0, sizeof(stack_words));
    stack_pointer = (word_t)stack_words;
    unreadable = 0;
    stack_words[0] = 1;             /* argc */
    stack_words[1] = 0x12345678;    /* guest argv[0] */
    stack_words[3] = 0x98765432;    /* envp[0] */
    stack_words[5] = AT_PAGESZ;
    stack_words[6] = 4096;
    stack_words[7] = AT_EXECFN;
    stack_words[8] = 0xdeadbeef;    /* kernel's loader filename */
    stack_words[9] = AT_NULL;
}

static void test_raw_fixup(void)
{
    Tracee tracee = { .execfn_addr = 0xfedcba9876543210UL };
    const word_t vector[] = { AT_PAGESZ, 4096, AT_EXECFN, 7, AT_NULL, 0 };
    unsigned char buffer[sizeof(vector) + 2];
    unsigned char expected[sizeof(buffer)];
    const size_t execfn_end = 4 * sizeof(word_t);

    /* Every possible truncation, including a type without its full value.
     * The byte before/after the unaligned vector must never be touched. */
    for (size_t size = 0; size <= sizeof(vector); size++) {
        memset(buffer, 0xa5, sizeof(buffer));
        memcpy(buffer + 1, vector, sizeof(vector));
        memcpy(expected, buffer, sizeof(buffer));
        bool found = size >= execfn_end;
        if (found)
            memcpy(expected + 1 + 3 * sizeof(word_t),
                   &tracee.execfn_addr, sizeof(word_t));
        assert(fix_up_execfn(&tracee, buffer + 1, size) == found);
        assert(memcmp(buffer, expected, sizeof(buffer)) == 0);
    }

    word_t after_null[] = { AT_NULL, 0, AT_EXECFN, 7 };
    assert(!fix_up_execfn(&tracee, after_null, sizeof(after_null)));
    assert(after_null[3] == 7);
    tracee.execfn_addr = 0;
    assert(!fix_up_execfn(&tracee, after_null + 2, 2 * sizeof(word_t)));
    assert(after_null[3] == 7);
    assert(!fix_up_execfn(NULL, after_null, sizeof(after_null)));
    assert(!fix_up_execfn(&tracee, NULL, 0));
}

static void test_capture(void)
{
    Tracee tracee = { 0 };
    initialize_stack();
    errno = EIO;
    capture_execfn_addr(&tracee);
    assert(tracee.execfn_addr == stack_words[1]);
    stack_words[0] = 5000; /* valid large argv has the same first argument */
    tracee.execfn_addr = 99;
    capture_execfn_addr(&tracee);
    assert(tracee.execfn_addr == stack_words[1]);

    tracee.execfn_addr = 99;
    stack_words[0] = 0;
    capture_execfn_addr(&tracee);
    assert(tracee.execfn_addr == 0);

    initialize_stack();
    tracee.execfn_addr = 99;
    unreadable = stack_pointer;
    capture_execfn_addr(&tracee);
    assert(tracee.execfn_addr == 0);

    initialize_stack();
    tracee.execfn_addr = 99;
    unreadable = stack_pointer + sizeof(word_t);
    capture_execfn_addr(&tracee);
    assert(tracee.execfn_addr == 0);

    tracee.execfn_addr = 99;
    stack_pointer = 0;
    capture_execfn_addr(&tracee);
    assert(tracee.execfn_addr == 0);
}

static void check_file(const char *path, const ElfAuxVector *vectors, size_t count)
{
    FILE *file = fopen(path, "rb");
    assert(file);
    for (size_t i = 0; i < count; i++) {
        ElfAuxVector vector;
        assert(fread(&vector, sizeof(vector), 1, file) == 1);
        assert(vector.type == vectors[i].type);
        assert(vector.value == vectors[i].value);
    }
    assert(fgetc(file) == EOF);
    assert(!ferror(file));
    assert(fclose(file) == 0);
}

static void test_serialization(void)
{
    Tracee tracee = { 0 };
    const char *path = create_temp_file(NULL, "proot-me-auxv-test");
    assert(path);
    /* Cross the writer's internal buffer boundary, including AT_NULL. */
    size_t count = PATH_MAX * 2 / sizeof(ElfAuxVector) + 3;
    ElfAuxVector *vectors = calloc(count, sizeof(*vectors));
    assert(vectors);
    for (size_t i = 0; i + 1 < count; i++) {
        vectors[i].type = AT_PAGESZ;
        vectors[i].value = i;
    }
    assert(fill_file_with_auxv(&tracee, path, vectors) == 0);
    check_file(path, vectors, count);

    const ElfAuxVector shorter[] = { { AT_EXECFN, 0x1234 }, { AT_NULL, 0 } };
    assert(fill_file_with_auxv(&tracee, path, shorter) == 0);
    check_file(path, shorter, 2);
    free(vectors);
    talloc_free((void *)path);
}

static void test_cache_ownership(void)
{
    Tracee *parent = talloc_zero(NULL, Tracee);
    Tracee *child = talloc_zero(NULL, Tracee);
    assert(parent && child);
    parent->ctx = talloc_new(parent);
    parent->life_context = talloc_new(parent);
    parent->pid = getpid();
    parent->status = 1;
    initialize_stack();
    capture_execfn_addr(parent);
    assert(bind_proc_pid_auxv(parent) == 0);
    const ElfAuxVector expected[] = {
        { AT_PAGESZ, 4096 }, { AT_EXECFN, stack_words[1] }, { AT_NULL, 0 }
    };
    check_file(parent->auxv_host_path, expected, 3);

    char *old_path = strdup(parent->auxv_host_path);
    assert(old_path);
    child->auxv_host_path = talloc_reference(child, parent->auxv_host_path);
    assert(child->auxv_host_path);
    assert(talloc_unlink(parent, parent->auxv_host_path) == 0);
    parent->auxv_host_path = NULL;
    assert(bind_proc_pid_auxv(parent) == 0);
    assert(strcmp(old_path, parent->auxv_host_path) != 0);
    assert(access(old_path, F_OK) == 0);
    check_file(child->auxv_host_path, expected, 3);
    talloc_free(child);
    assert(access(old_path, F_OK) == -1 && errno == ENOENT);
    free(old_path);
    talloc_free(parent);
    current_binding = NULL;
}

static void test_exec_lifecycle(void)
{
    Tracee *tracee = talloc_zero(NULL, Tracee);
    Tracee *child = talloc_zero(NULL, Tracee);
    assert(tracee && child);
    const char *path = create_temp_file(tracee, "proot-me-exec-test");
    assert(path);
    tracee->auxv_host_path = (char *)path;
    tracee->execfn_addr = 0x1234;
    tracee->skip_proot_loader = true;
    tracee->restore_original_regs = true;
    child->auxv_host_path = talloc_reference(child, (char *)path);
    assert(child->auxv_host_path);
    char *saved_path = strdup(path);
    assert(saved_path);

    syscall_result = (word_t)-ENOENT;
    translate_execve_exit(tracee);
    assert(tracee->auxv_host_path == path);
    assert(tracee->execfn_addr == 0x1234);
    assert(!tracee->seen_execve);
    assert(tracee->restore_original_regs);

    syscall_result = 0;
    translate_execve_exit(tracee);
    assert(tracee->auxv_host_path == NULL);
    assert(tracee->execfn_addr == 0);
    assert(tracee->seen_execve);
    assert(!tracee->restore_original_regs);
    assert(access(saved_path, F_OK) == 0);
    talloc_free(tracee);
    assert(access(saved_path, F_OK) == 0);
    talloc_free(child);
    assert(access(saved_path, F_OK) == -1 && errno == ENOENT);
    free(saved_path);
}

int main(void)
{
    test_raw_fixup();
    test_capture();
    test_serialization();
    test_cache_ownership();
    test_exec_lifecycle();
    puts("proot-me auxv logic and temporary-file ownership passed");
    return 0;
}
