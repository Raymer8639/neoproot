/* Exercise production handlers with local register/memory stubs, without
 * ptrace, nested PRoot, user namespaces, or UML. */
#include <assert.h>
#include <stdarg.h>
#include <sys/eventfd.h>
#include <sys/xattr.h>
#include <sys/syscall.h>
#include "tracee/statx.h"
#include "../src/extension/fake_id0/fake_id0.c"
#include "../src/extension/hidden_files/hidden_files.c"
#include "cli/note.h"

static char guest_root[PATH_MAX];
static Tracee *caller;
static Extension *caller_extension;
static Sysnum chained_number;
static unsigned int chained_count, string_reads;
word_t peek_reg(const Tracee *t, RegVersion v, Reg r) { return t->_regs[v].regs[r]; }
void poke_reg(Tracee *t, Reg r, word_t value) { t->_regs[CURRENT].regs[r] = value; }
Sysnum get_sysnum(const Tracee *t, RegVersion v) { return peek_reg(t, v, SYSARG_NUM); }
void set_sysnum(Tracee *t, Sysnum n) { poke_reg(t, SYSARG_NUM, n); }
int read_data(const Tracee *t, void *dest, word_t src, word_t size) {
    (void)t; if (!src) return -EFAULT; memcpy(dest, (void *)src, size); return 0;
}
int write_data(Tracee *t, word_t dest, const void *src, word_t size) {
    (void)t; if (!dest) return -EFAULT; memcpy((void *)dest, src, size); return 0;
}
int read_string(const Tracee *t, char *dest, word_t src, word_t max) {
    (void)t; string_reads++; if (!src) return -EFAULT;
    size_t n = strnlen((char *)src, max); memcpy(dest, (void *)src, n < max ? n + 1 : max);
    return n < max ? (int)n + 1 : (int)max + 1;
}
word_t alloc_mem(Tracee *t, ssize_t size) { return (word_t)talloc_zero_size(t, size); }
word_t peek_word(const Tracee *t, word_t addr) { (void)t; return *(word_t *)addr; }
void poke_word(const Tracee *t, word_t addr, word_t value) { (void)t; *(word_t *)addr = value; }
int translate_path(Tracee *t, char out[PATH_MAX], int fd, const char *path, bool deref) {
    (void)t; (void)fd; (void)deref; snprintf(out, PATH_MAX, "%s", strcmp(path, "/") == 0 ? guest_root : path); return 0;
}
bool belongs_to_guestfs(const Tracee *t, const char *path) {
    (void)t; size_t n = strlen(guest_root);
    return strncmp(path, guest_root, n) == 0 && (path[n] == '/' || path[n] == '\0');
}
int getcwd2(Tracee *t, char out[PATH_MAX]) { (void)t; strcpy(out, guest_root); return 0; }
int readlink_proc_pid_fd(pid_t pid, int fd, char out[PATH_MAX]) {
    char proc[80]; snprintf(proc, sizeof(proc), "/proc/%d/fd/%d", pid, fd);
    ssize_t n = readlink(proc, out, PATH_MAX - 1); if (n < 0) return -errno; out[n] = '\0'; return 0;
}
int register_chained_syscall(Tracee *t, Sysnum n, word_t a, word_t b, word_t c, word_t d, word_t e, word_t f) {
    (void)t; (void)a; (void)b; (void)c; (void)d; (void)e; (void)f; chained_number = n; chained_count++; return 0;
}
Extension *get_extension(Tracee *t, extension_callback_t callback) { return t == caller && callback == fake_id0_callback ? caller_extension : NULL; }
Tracee *get_tracee(const Tracee *t, pid_t pid, bool create) { (void)t; (void)create; return caller && pid == caller->pid ? caller : NULL; }
bool should_skip_file_access_due_to_f2fs_bug(const Tracee *t, const char *p) { (void)t; (void)p; return false; }
word_t get_elf_aux_vectors_address(const Tracee *t) { (void)t; return 0; }
ElfAuxVector *fetch_elf_aux_vectors(const Tracee *t, word_t a) { (void)t; (void)a; return NULL; }
int push_elf_aux_vectors(const Tracee *t, ElfAuxVector *v, word_t a) { (void)t; (void)v; (void)a; return 0; }
Binding *get_binding(const Tracee *t, Side s, const char p[PATH_MAX]) { (void)t; (void)s; (void)p; return NULL; }
Binding *new_binding(Tracee *t, const char *h, const char *g, bool exists) { (void)t; (void)h; (void)g; (void)exists; return NULL; }
int initialize_bindings(Tracee *t) { (void)t; return 0; }
const char *get_root(const Tracee *t) { (void)t; return guest_root; }
Comparison compare_paths(const char *a, const char *b) { return strcmp(a, b) == 0 ? PATHS_ARE_EQUAL : PATHS_ARE_NOT_COMPARABLE; }
int detranslate_path(Tracee *t, char p[PATH_MAX], const char r[PATH_MAX]) { (void)t; (void)p; (void)r; return 0; }
int set_sysarg_data(Tracee *t, const void *data, word_t size, Reg r) { word_t addr = alloc_mem(t, size); if (!addr) return -ENOMEM; memcpy((void *)addr, data, size); poke_reg(t, r, addr); return 0; }
void note(const Tracee *t, Severity s, Origin o, const char *message, ...) { (void)t; (void)s; (void)o; (void)message; }

static void reset_call(Tracee *t, Sysnum n) {
    memset(t->_regs, 0, sizeof(t->_regs)); for (int v = 0; v < NB_REG_VERSION; v++) t->_regs[v].regs[SYSARG_NUM] = n; t->status = 0;
}
static void arg(Tracee *t, Reg r, word_t value) { for (int v = 0; v < NB_REG_VERSION; v++) t->_regs[v].regs[r] = value; }
static void record(char path[PATH_MAX], mode_t mode, uid_t uid, gid_t gid, Config *cfg) {
    char key[PATH_MAX]; assert(get_meta_path(path, key) == 0); assert(write_meta_file(key, mode, uid, gid, false, cfg) == 0);
}
static void expect_record(char path[PATH_MAX], mode_t mode, uid_t uid, gid_t gid, Config *cfg) {
    char key[PATH_MAX]; mode_t m; uid_t u; gid_t g; assert(get_meta_path(path, key) == 0 && path_exists(key) == 0);
    assert(read_meta_file(key, &m, &u, &g, cfg) == 0); assert(m == mode && u == uid && g == gid);
}
static void path_for(char out[PATH_MAX], const char *name) { assert(snprintf(out, PATH_MAX, "%s/%s", guest_root, name) < PATH_MAX); }

int main(int argc, char **argv) {
    assert(argc == 2); assert(realpath(argv[1], guest_root));
    caller = talloc_zero(NULL, Tracee); assert(caller); caller->pid = getpid(); caller->ctx = talloc_new(caller);
    void *extensions = talloc_new(caller); caller_extension = talloc_zero(extensions, Extension); caller_extension->callback = fake_id0_callback;
    Config *cfg = talloc_zero(caller_extension, Config); caller_extension->config = cfg; cfg->umask = 022;
    Tracee *other = talloc_zero(NULL, Tracee); other->pid = getpid(); other->ctx = talloc_new(other);

    /* ARM64 IDs overwrite 32 bits, preserving the adjacent canary. */
    struct { uint32_t id[3]; uint32_t canary; } ids = {{0xFFFF0000, 0xFFFF0000, 0xFFFF0000}, 0xCAFEBABE};
    cfg->ruid = 100001; cfg->euid = 0; cfg->suid = 200002; reset_call(caller, PR_getresuid);
    for (int i = 0; i < 3; i++) arg(caller, SYSARG_1 + i, (word_t)&ids.id[i]);
    assert(handle_getresuid_exit_end(caller, cfg) == 0); assert(ids.id[0] == 100001 && ids.id[1] == 0 && ids.id[2] == 200002 && ids.canary == 0xCAFEBABE);
    cfg->rgid = 300003; cfg->egid = 0; cfg->sgid = 400004;
    assert(handle_getresgid_exit_end(caller, cfg) == 0); assert(ids.id[0] == 300003 && ids.id[1] == 0 && ids.id[2] == 400004 && ids.canary == 0xCAFEBABE);

    char a[PATH_MAX], b[PATH_MAX], key[PATH_MAX], key2[PATH_MAX], proc[PATH_MAX]; path_for(a, "a"); path_for(b, "b");
    int fd = open(a, O_RDWR | O_CREAT, 0600), fd2 = open(b, O_RDWR | O_CREAT, 0600); assert(fd >= 0 && fd2 >= 0);
    record(a, 0600, 111111, 222222, cfg); assert(get_meta_path(a, key) == 0);
    snprintf(proc, sizeof(proc), "%s///", a); assert(get_meta_path(proc, key2) == 0 && strcmp(key, key2) == 0);
    reset_call(caller, PR_chown); arg(caller, SYSARG_1, (word_t)a); arg(caller, SYSARG_2, 333333); arg(caller, SYSARG_3, (uid_t)-1);
    assert(handle_sysenter_end(caller, cfg) == 0); expect_record(a, 0600, 333333, 222222, cfg);

    /* fchmod(O_PATH) fails without changing metadata; successful chmod masks type bits. */
    int pathfd = open(a, O_PATH); assert(pathfd >= 0);
    reset_call(caller, PR_fchmod); arg(caller, SYSARG_1, pathfd); arg(caller, SYSARG_2, S_IFDIR | 04751);
    assert(handle_sysenter_end(caller, cfg) == 0); expect_record(a, 0600, 333333, 222222, cfg);
    assert(fchmod(pathfd, peek_reg(caller, CURRENT, SYSARG_2)) == -1 && errno == EBADF);
    poke_reg(caller, SYSARG_RESULT, -EBADF); assert(handle_sysexit_end(caller, cfg) == 0); expect_record(a, 0600, 333333, 222222, cfg); close(pathfd);
    reset_call(caller, PR_fchmod); arg(caller, SYSARG_1, fd); arg(caller, SYSARG_2, S_IFDIR | 04751);
    assert(handle_sysenter_end(caller, cfg) == 0); assert(peek_reg(caller, CURRENT, SYSARG_2) == 0751);
    assert(fchmod(fd, peek_reg(caller, CURRENT, SYSARG_2)) == 0); poke_reg(caller, SYSARG_RESULT, 0);
    assert(handle_sysexit_end(caller, cfg) == 0); expect_record(a, 04751, 333333, 222222, cfg);

    /* Interleaved tracees sharing Config and ctx cleanup cannot cross pending state. */
    record(b, 0600, 555555, 666666, cfg); reset_call(caller, PR_fchmod); arg(caller, SYSARG_1, fd); arg(caller, SYSARG_2, 0700); assert(handle_sysenter_end(caller, cfg) == 0);
    reset_call(other, PR_fchmod); arg(other, SYSARG_1, fd2); arg(other, SYSARG_2, 0400); assert(handle_sysenter_end(other, cfg) == 0);
    TALLOC_FREE(caller->ctx); caller->ctx = talloc_new(caller);
    poke_reg(caller, SYSARG_RESULT, 0); assert(handle_sysexit_end(caller, cfg) == 0); poke_reg(other, SYSARG_RESULT, 0); assert(handle_sysexit_end(other, cfg) == 0);
    expect_record(a, 0700, 333333, 222222, cfg); expect_record(b, 0400, 555555, 666666, cfg);

    snprintf(proc, sizeof(proc), "/proc/%d/fd/%d", getpid(), fd); reset_call(caller, PR_chmod); arg(caller, SYSARG_1, (word_t)proc); arg(caller, SYSARG_2, 0441);
    assert(handle_sysenter_end(caller, cfg) == 0); assert(peek_reg(caller, CURRENT, SYSARG_2) == 0741); assert(chmod(proc, peek_reg(caller, CURRENT, SYSARG_2)) == 0);
    poke_reg(caller, SYSARG_RESULT, 0); assert(handle_sysexit_end(caller, cfg) == 0); expect_record(a, 0441, 333333, 222222, cfg);
    snprintf(proc, sizeof(proc), "/proc/self/fd/+%d", fd); assert(resolve_proc_fd_path(caller, proc) == -1);
    snprintf(proc, sizeof(proc), "/proc/self/fd/0%d", fd); assert(resolve_proc_fd_path(caller, proc) == -1);
    char empty[] = "";
    for (int success = 0; success < 2; success++) {
        reset_call(caller, PR_fchmodat2); arg(caller, SYSARG_1, fd); arg(caller, SYSARG_2, (word_t)empty); arg(caller, SYSARG_3, 0640); arg(caller, SYSARG_4, AT_EMPTY_PATH);
        assert(handle_sysenter_end(caller, cfg) == 0); poke_reg(caller, SYSARG_RESULT, success ? 0 : -ENOSYS); assert(handle_sysexit_end(caller, cfg) == 0);
        expect_record(a, success ? 0640 : 0441, 333333, 222222, cfg);
    }

    /* ACL-derived mode changes retain recorded set-id bits and the real owner's access. */
    record(a, 04640, 333333, 222222, cfg); char aclname[] = "system.posix_acl_access";
    struct { uint32_t version; struct { uint16_t tag, perm; uint32_t id; } entries[3]; } acl = {2, {{1,0,UINT32_MAX},{4,4,UINT32_MAX},{32,4,UINT32_MAX}}};
    reset_call(caller, PR_fsetxattr); arg(caller, SYSARG_1, fd); arg(caller, SYSARG_2, (word_t)aclname); assert(handle_sysenter_end(caller, cfg) == 0);
    if (fsetxattr(fd, aclname, &acl, sizeof(acl), 0) == 0) {
        poke_reg(caller, SYSARG_RESULT, 0); assert(handle_sysexit_end(caller, cfg) == 0); expect_record(a, 04044, 333333, 222222, cfg);
        struct stat st; assert(fstat(fd, &st) == 0 && (st.st_mode & 07777) == 0644);
    } else {
        assert(errno == ENOTSUP || errno == EOPNOTSUPP); poke_reg(caller, SYSARG_RESULT, -errno); assert(handle_sysexit_end(caller, cfg) == 0); puts("SKIP native ACL filesystem support");
    }
    record(a, 0640, 333333, 222222, cfg); cfg->euid = 123;
    reset_call(caller, PR_fsetxattr); arg(caller, SYSARG_1, fd); arg(caller, SYSARG_2, (word_t)aclname); assert(handle_sysenter_end(caller, cfg) == -EPERM);
    poke_reg(caller, SYSARG_RESULT, -EPERM); assert(handle_sysexit_end(caller, cfg) == 0); expect_record(a, 0640, 333333, 222222, cfg); cfg->euid = 0;

    struct statx_syscall_state sx = {0}; strcpy(sx.host_path, a); sx.statx_buf.stx_mask = STATX_MODE | STATX_UID | STATX_GID; sx.statx_buf.stx_mode = S_IFREG | 0600;
    assert(fake_id0_handle_statx_syscall(caller, cfg, (uintptr_t)&sx) == 0); assert(sx.statx_buf.stx_mode == (S_IFREG | 0640) && sx.statx_buf.stx_uid == 333333 && sx.statx_buf.stx_gid == 222222);
    sx.statx_buf.stx_mask = STATX_TYPE; sx.statx_buf.stx_mode = S_IFLNK | 0777; sx.statx_buf.stx_uid = 42;
    assert(fake_id0_handle_statx_syscall(caller, cfg, (uintptr_t)&sx) == 0 && sx.statx_buf.stx_mode == (S_IFLNK | 0777) && sx.statx_buf.stx_uid == 42);
    struct stat st; assert(fstat(fd, &st) == 0); reset_call(caller, PR_newfstatat); arg(caller, SYSARG_1, fd); arg(caller, SYSARG_2, (word_t)empty); arg(caller, SYSARG_3, (word_t)&st); arg(caller, SYSARG_4, AT_EMPTY_PATH);
    assert(handle_stat_exit_end(caller, cfg, PR_newfstatat) == 0 && st.st_uid == 333333 && (st.st_mode & 0777) == 0640);
    int pipes[2]; assert(pipe(pipes) == 0 && fstat(pipes[0], &st) == 0); arg(caller, SYSARG_1, pipes[0]);
    assert(handle_stat_exit_end(caller, cfg, PR_newfstatat) == 0 && st.st_uid == cfg->suid && st.st_gid == cfg->sgid); close(pipes[0]); close(pipes[1]);
    int anon = eventfd(0, 0); assert(anon >= 0 && fstat(anon, &st) == 0); arg(caller, SYSARG_1, anon);
    uid_t anon_uid = st.st_uid == getuid() ? cfg->suid : st.st_uid;
    gid_t anon_gid = st.st_gid == getgid() ? cfg->sgid : st.st_gid;
    assert(handle_stat_exit_end(caller, cfg, PR_newfstatat) == 0 && st.st_uid == anon_uid && st.st_gid == anon_gid); close(anon);

    /* Chained fstat results must be disguised too, with the original buffer. */
    assert(fstat(fd, &st) == 0); reset_call(caller, PR_fstat);
    arg(caller, SYSARG_1, fd); arg(caller, SYSARG_2, (word_t)&st);
    caller->_regs[CURRENT].regs[SYSARG_NUM] = PR_fstatat64;
    assert(fake_id0_callback(caller_extension, SYSCALL_CHAINED_EXIT, 0, 0) == 0);
    assert(st.st_uid == 333333 && st.st_gid == 222222 && (st.st_mode & 0777) == 0640);

    /* Readlink results have no NUL; nonabsolute/deleted targets replay fstat. */
    char scratch[PATH_MAX]; const char *targets[] = {"socket:[42]", "anon_inode:[eventfd]", "x", "/x (deleted)", a};
    for (size_t i = 0; i < sizeof(targets)/sizeof(targets[0]); i++) {
        size_t n = strlen(targets[i]); memset(scratch, 'A', sizeof(scratch)); memcpy(scratch, targets[i], n);
        reset_call(caller, PR_fstat); arg(caller, SYSARG_1, fd); arg(caller, SYSARG_2, (word_t)&st); caller->_regs[CURRENT].regs[SYSARG_NUM] = PR_readlinkat; caller->_regs[MODIFIED].regs[SYSARG_3] = (word_t)scratch;
        poke_reg(caller, SYSARG_RESULT, n); unsigned int reads = string_reads, chains = chained_count;
        assert(handle_sysexit_end(caller, cfg) == 0 && chained_count == chains + 1 && string_reads == reads); assert(chained_number == (i == 4 ? PR_fstatat64 : PR_fstat));
    }
    assert(chmod(a, 0440) == 0); reset_call(caller, PR_statx); override_permissions(caller, a, true); assert(stat(a, &st) == 0 && (st.st_mode & 0777) == 0440);
    reset_call(caller, PR_fchmodat2); arg(caller, SYSARG_3, 0777); override_permissions(caller, a, true); TALLOC_FREE(caller->ctx); caller->ctx = talloc_new(caller);
    assert(stat(a, &st) == 0 && (st.st_mode & 0777) == 0440);

    /* Failed renameat2 leaves records; successful EXCHANGE swaps and rename replaces. */
    record(a, 0600, 111111, 222222, cfg); record(b, 0644, 555555, 666666, cfg);
    reset_call(caller, PR_renameat2); arg(caller, SYSARG_1, AT_FDCWD); arg(caller, SYSARG_2, (word_t)a); arg(caller, SYSARG_3, AT_FDCWD); arg(caller, SYSARG_4, (word_t)b); arg(caller, SYSARG_5, 1);
    assert(handle_sysenter_end(caller, cfg) == 0); expect_record(a, 0600, 111111, 222222, cfg); poke_reg(caller, SYSARG_RESULT, -EEXIST); assert(handle_sysexit_end(caller, cfg) == 0);
    expect_record(a, 0600, 111111, 222222, cfg); expect_record(b, 0644, 555555, 666666, cfg);
    arg(caller, SYSARG_5, 2); assert(syscall(SYS_renameat2, AT_FDCWD, a, AT_FDCWD, b, 2) == 0); poke_reg(caller, SYSARG_RESULT, 0); assert(handle_sysexit_end(caller, cfg) == 0);
    expect_record(a, 0644, 555555, 666666, cfg); expect_record(b, 0600, 111111, 222222, cfg);
    arg(caller, SYSARG_5, 0); assert(rename(a, b) == 0); assert(handle_sysexit_end(caller, cfg) == 0);
    assert(get_meta_path(a, key) == 0 && path_exists(key) != 0); expect_record(b, 0644, 555555, 666666, cfg);

    /* A same-inode rename is a no-op; unrecorded replacement drops stale metadata. */
    assert(link(b, a) == 0); record(a, 0700, 777777, 888888, cfg);
    /* Model the kernel no-op result directly: an outer PRoot may emulate link(). */
    poke_reg(caller, SYSARG_RESULT, 0); assert(handle_sysexit_end(caller, cfg) == 0);
    expect_record(a, 0700, 777777, 888888, cfg); expect_record(b, 0644, 555555, 666666, cfg);
    assert(unlink(a) == 0); assert(get_meta_path(a, key) == 0); remove_meta_file(key);
    int fresh = open(a, O_RDWR | O_CREAT, 0600); assert(fresh >= 0); close(fresh);
    assert(rename(a, b) == 0); assert(handle_sysexit_end(caller, cfg) == 0);
    assert(get_meta_path(b, key) == 0 && path_exists(key) != 0);

    struct ucred cred = { .pid = 999999, .uid = getuid(), .gid = getgid() };
    reset_call(caller, PR_getsockopt); arg(caller, SYSARG_2, SOL_SOCKET); arg(caller, SYSARG_3, SO_PEERCRED); arg(caller, SYSARG_4, (word_t)&cred);
    assert(handle_getsockopt_exit_end(caller) == 0 && cred.uid == cfg->euid && cred.gid == cfg->egid);
    reset_call(caller, PR_getdents64); poke_reg(caller, SYSARG_RESULT, -EBADF); assert(handle_getdents(caller) == 0 && (long)peek_reg(caller, CURRENT, SYSARG_RESULT) == -EBADF);
    int dirfd = open(guest_root, O_DIRECTORY); assert(dirfd >= 0); unsigned char listing[64] = {0}; unsigned short reclen = 32;
    memcpy(listing + 16, &reclen, 2); strcpy((char *)listing + 19, ".proot-x"); memcpy(listing + 48, &reclen, 2); strcpy((char *)listing + 51, "ok");
    arg(caller, SYSARG_1, dirfd); arg(caller, SYSARG_2, (word_t)listing); arg(caller, SYSARG_3, sizeof(listing)); poke_reg(caller, SYSARG_RESULT, sizeof(listing));
    assert(handle_getdents(caller) == 0 && peek_reg(caller, CURRENT, SYSARG_RESULT) == 32 && strcmp((char *)listing + 19, "ok") == 0);
    memset(listing, 0, sizeof(listing)); poke_reg(caller, SYSARG_RESULT, 32); assert(handle_getdents(caller) == 0 && peek_reg(caller, CURRENT, SYSARG_RESULT) == 32);
    memset(listing, 'X', sizeof(listing)); memcpy(listing + 16, &reclen, 2);
    poke_reg(caller, SYSARG_RESULT, 32); assert(handle_getdents(caller) == 0 && peek_reg(caller, CURRENT, SYSARG_RESULT) == 32);
    memset(listing, 0, sizeof(listing)); memcpy(listing + 16, &reclen, 2); strcpy((char *)listing + 19, ".proot-x");
    unsigned int chains = chained_count; poke_reg(caller, SYSARG_RESULT, 32);
    assert(handle_getdents(caller) == 0 && chained_count == chains + 1 && chained_number == PR_getdents64);
    close(dirfd); close(fd); close(fd2); talloc_free(other); talloc_free(caller);
    puts("PASS actual fake_id0 and hidden_files handlers"); return 0;
}
