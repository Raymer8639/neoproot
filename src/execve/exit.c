#include <linux/auxvec.h>
#include <talloc.h>
#include <sys/mman.h>
#include <assert.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include "execve/execve.h"
#include "execve/elf.h"
#include "loader/script.h"
#include "tracee/reg.h"
#include "tracee/abi.h"
#include "tracee/mem.h"
#include "syscall/sysnum.h"
#include "execve/auxv.h"
#include "path/binding.h"
#include "path/temp.h"
#include "cli/note.h"
#include "attribute.h"

static int fill_file_with_auxv(const Tracee *tr, const char *path, const ElfAuxVector *vectors)
{
    const ssize_t word_size = sizeof_word(tr);
    int fd;
    ssize_t ret;
    size_t i, buf_off;
    uint8_t buf[PATH_MAX * 2];

    fd = open(path, O_WRONLY);
    if (fd < 0)
        return -1;

    buf_off = 0;
    for (i = 0; vectors[i].type != AT_NULL; i++) {
        if (buf_off + 2 * word_size > sizeof(buf)) {
            ret = write(fd, buf, buf_off);
            if (ret != (ssize_t)buf_off) {
                close(fd);
                return -1;
            }
            buf_off = 0;
        }
        memcpy(buf + buf_off, &vectors[i].type, word_size);
        buf_off += word_size;
        memcpy(buf + buf_off, &vectors[i].value, word_size);
        buf_off += word_size;
    }

    if (buf_off > 0) {
        ret = write(fd, buf, buf_off);
        if (ret != (ssize_t)buf_off) {
            close(fd);
            return -1;
        }
    }

    close(fd);
    return 0;
}

static int bind_proc_pid_auxv(const Tracee *tr)
{
    word_t vec_addr;
    ElfAuxVector *vectors;
    char *guest_path;
    Binding *binding;
    const char *host_path;

    vec_addr = get_elf_aux_vectors_address(tr);
    if (vec_addr == 0)
        return -1;

    vectors = fetch_elf_aux_vectors(tr, vec_addr);
    if (!vectors)
        return -1;

    guest_path = talloc_asprintf(tr->ctx, "/proc/%d/auxv", tr->pid);
    if (!guest_path)
        return -1;

    binding = get_binding(tr, GUEST, guest_path);
    if (binding && compare_paths(binding->guest.path, guest_path) == PATHS_ARE_EQUAL) {
        remove_binding_from_all_lists((Tracee *)tr, binding);
        TALLOC_FREE(binding);
    }

    host_path = create_temp_file(tr->ctx, "auxv");
    if (!host_path)
        return -1;

    if (fill_file_with_auxv(tr, host_path, vectors) < 0)
        return -1;

    binding = insort_binding3((Tracee *)tr, tr->life_context, host_path, guest_path);
    if (!binding)
        return -1;

    talloc_reparent(tr->ctx, binding, (void *)host_path);
    return 0;
}

static void *transcript_mappings(void *cursor, const Mapping *mappings)
{
    size_t n = talloc_array_length(mappings);
    size_t i;

    for (i = 0; i < n; i++) {
        LoadStatement *st = cursor;
        st->action = (mappings[i].flags & MAP_ANONYMOUS)
            ? LOAD_ACTION_MMAP_ANON
            : LOAD_ACTION_MMAP_FILE;

        st->mmap.addr          = mappings[i].addr;
        st->mmap.length        = mappings[i].length;
        st->mmap.prot          = mappings[i].prot;
        st->mmap.offset        = mappings[i].offset;
        st->mmap.clear_length  = mappings[i].clear_length;

        cursor += LOAD_STATEMENT_SIZE(*st, mmap);
    }
    return cursor;
}

static int transfer_load_script(Tracee *tr)
{
    static word_t page_size, page_mask;
    word_t sp, entry;
    LoadInfo *info;
    size_t align, pad, str1, str2, str3, total_str;
    word_t addr1, addr2, addr3;
    size_t n_main, n_interp, exec_stack, script_sz, buf_sz;
    void *buf, *cursor;
    LoadStatement *st;
    uint8_t *str_buf;
    word_t new_sp;
    int ret;

    if (!page_size) {
        page_size = sysconf(_SC_PAGE_SIZE);
        if (page_size <= 0) page_size = 0x1000;
        page_mask = ~(page_size - 1);
    }

    sp    = peek_reg(tr, CURRENT, STACK_POINTER);
    info  = tr->load_info;

    if (!info->user_path || sp == 0)
        return -EINVAL;

    str1 = strlen(info->user_path) + 1;
    str2 = (info->interp) ? strlen(info->interp->user_path) + 1 : 0;
    str3 = (info->raw_path == info->user_path) ? 0 : strlen(info->raw_path) + 1;

    align     = sizeof_word(tr);
    pad       = (align - ((sp - str1 - str2 - str3) % align)) % align;
    total_str = str1 + str2 + str3 + pad;

    addr1 = sp - total_str;
    addr2 = addr1 + str1;
    addr3 = (str3 == 0) ? addr1 : addr2 + str2;

    n_main     = talloc_array_length(info->mappings);
    n_interp   = (info->interp) ? talloc_array_length(info->interp->mappings) : 0;
    exec_stack = (info->needs_executable_stack || (info->interp && info->interp->needs_executable_stack)) ? 1 : 0;

    script_sz  = LOAD_STATEMENT_SIZE(*st, open);
    script_sz += LOAD_STATEMENT_SIZE(*st, mmap) * n_main;
    if (info->interp) {
        script_sz += LOAD_STATEMENT_SIZE(*st, open);
        script_sz += LOAD_STATEMENT_SIZE(*st, mmap) * n_interp;
    }
    if (exec_stack)
        script_sz += LOAD_STATEMENT_SIZE(*st, make_stack_exec);
    script_sz += LOAD_STATEMENT_SIZE(*st, start);

    buf_sz = script_sz + total_str;
    buf = talloc_zero_size(tr->ctx, buf_sz);
    if (!buf)
        return -ENOMEM;

    cursor = buf;

    st = cursor;
    st->action = LOAD_ACTION_OPEN;
    st->open.string_address = addr1;
    cursor += LOAD_STATEMENT_SIZE(*st, open);

    cursor = transcript_mappings(cursor, info->mappings);
    entry = ELF_FIELD(info->elf_header, entry);

    if (info->interp) {
        st = cursor;
        st->action = LOAD_ACTION_OPEN_NEXT;
        st->open.string_address = addr2;
        cursor += LOAD_STATEMENT_SIZE(*st, open);

        cursor = transcript_mappings(cursor, info->interp->mappings);
        entry = ELF_FIELD(info->interp->elf_header, entry);
    }

    if (exec_stack) {
        st = cursor;
        st->action = LOAD_ACTION_MAKE_STACK_EXEC;
        st->make_stack_exec.start = sp & page_mask;
        cursor += LOAD_STATEMENT_SIZE(*st, make_stack_exec);
    }

    st = cursor;
    st->action = (tr->as_ptracee.ptracer) ? LOAD_ACTION_START_TRACED : LOAD_ACTION_START;
    st->start.stack_pointer = sp;
    st->start.entry_point   = entry;
    st->start.at_phent      = ELF_FIELD(info->elf_header, phentsize);
    st->start.at_phnum      = ELF_FIELD(info->elf_header, phnum);
    st->start.at_entry      = ELF_FIELD(info->elf_header, entry);
    st->start.at_phdr       = ELF_FIELD(info->elf_header, phoff) + info->mappings[0].addr;
    st->start.at_execfn     = addr3;
    cursor += LOAD_STATEMENT_SIZE(*st, start);

    str_buf = cursor;
    memcpy(str_buf, info->user_path, str1);
    str_buf += str1;
    if (str2) {
        memcpy(str_buf, info->interp->user_path, str2);
        str_buf += str2;
    }
    if (str3) {
        memcpy(str_buf, info->raw_path, str3);
        str_buf += str3;
    }

    new_sp = sp - buf_sz;
    poke_reg(tr, STACK_POINTER, new_sp);
    poke_reg(tr, USERARG_1, new_sp);

    ret = write_data(tr, new_sp, buf, buf_sz);
    if (ret < 0)
        return ret;

    save_current_regs(tr, ORIGINAL);
    tr->_regs_were_changed = true;

    return 0;
}

void translate_execve_exit(Tracee *tr)
{
    word_t res;

    if (tr->skip_proot_loader) {
        tr->restore_original_regs = false;
        return;
    }

    if (IS_NOTIFICATION_PTRACED_LOAD_DONE(tr)) {
        word_t orig_sp, orig_ip;

        poke_reg(tr, SYSARG_RESULT, 0);
        set_sysnum(tr, PR_execve);

        orig_sp = peek_reg(tr, ORIGINAL, SYSARG_2);
        orig_ip = peek_reg(tr, ORIGINAL, SYSARG_3);

        poke_reg(tr, STACK_POINTER, orig_sp);
        poke_reg(tr, INSTR_POINTER, orig_ip);
        poke_reg(tr, RTLD_FINI, 0);
        poke_reg(tr, STATE_FLAGS, 0);

        save_current_regs(tr, ORIGINAL);
        tr->_regs_were_changed = true;

        (void)bind_proc_pid_auxv(tr);

        if (!(tr->as_ptracee.options & PTRACE_O_TRACEEXEC))
            kill(tr->pid, SIGTRAP);

        return;
    }

    res = peek_reg(tr, CURRENT, SYSARG_RESULT);
    if ((int)res < 0)
        return;

    if (tr->new_exe) {
        talloc_unlink(tr, tr->exe);
        tr->exe = talloc_reference(tr, tr->new_exe);
        talloc_set_name_const(tr->exe, "$exe");
    }

    if (talloc_reference_count(tr->heap) >= 1) {
        talloc_unlink(tr, tr->heap);
        tr->heap = talloc_zero(tr, Heap);
        if (!tr->heap)
            note(tr, ERROR, INTERNAL, "could not allocate heap");
    } else {
        memset(tr->heap, 0, sizeof(Heap));
    }

    mem_prepare_after_execve(tr);
    (void)transfer_load_script(tr);
}
