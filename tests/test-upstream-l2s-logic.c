/* Real extension code, real filesystem operations, synthetic tracee registers.
 * No ptrace, nested PRoot, rootfs, or UML is needed. */
#include <assert.h>
#include <stdarg.h>
#include "../src/extension/link2symlink/link2symlink.c"

static word_t registers[NB_REG_VERSION][USERARG_1 + 1];
static Sysnum sysnums[NB_REG_VERSION];
static Extension *test_extension;
static unsigned int string_reads, data_writes;
static word_t fail_read_address;

word_t peek_reg(const Tracee *t, RegVersion v, Reg r) { (void)t; return registers[v][r]; }
void poke_reg(Tracee *t, Reg r, word_t n) { (void)t; registers[CURRENT][r] = n; }
Sysnum get_sysnum(const Tracee *t, RegVersion v) { (void)t; return sysnums[v]; }
void set_sysnum(Tracee *t, Sysnum n) { (void)t; sysnums[CURRENT] = n; }
int read_string(const Tracee *t, char *dst, word_t src, word_t max) {
    (void)t; string_reads++;
    if (src == 0 || src == fail_read_address) return -EFAULT;
    size_t n = strnlen((const char *)src, max);
    if (n == max) return max;
    memcpy(dst, (const void *)src, n + 1);
    return n + 1;
}
int read_data(const Tracee *t, void *dst, word_t src, word_t n) {
    (void)t; if (!src) return -EFAULT; memcpy(dst, (void *)src, n); return 0;
}
int write_data(Tracee *t, word_t dst, const void *src, word_t n) {
    (void)t; if (!dst) return -EFAULT; memcpy((void *)dst, src, n); data_writes++; return 0;
}
int substitute_binding(const Tracee *t, Side s, char p[PATH_MAX]) { (void)t; (void)s; (void)p; return 0; }
int detranslate_path(Tracee *t, char p[PATH_MAX], const char ref[PATH_MAX]) { (void)t; (void)p; (void)ref; return 0; }
bool belongs_to_guestfs(const Tracee *t, const char *p) { (void)t; (void)p; return true; }
bool should_skip_file_access_due_to_f2fs_bug(const Tracee *t, const char *p) {
    (void)t; (void)p; return false;
}
Extension *get_extension(Tracee *t, extension_callback_t cb) { (void)t; (void)cb; return test_extension; }
int initialize_extension(Tracee *t, extension_callback_t cb, const char *cli) {
    (void)t; (void)cb; (void)cli; assert(!"unexpected extension initialization"); return -EINVAL;
}
int readlink_proc_pid_fd(pid_t pid, int fd, char path[PATH_MAX]) {
    char proc[80]; snprintf(proc, sizeof(proc), "/proc/%d/fd/%d", pid, fd);
    ssize_t n = readlink(proc, path, PATH_MAX - 1);
    if (n < 0) return -errno;
    path[n] = 0;
    return 0;
}
Comparison compare_paths(const char *a, const char *b) {
    if (!strcmp(a,b)) return PATHS_ARE_EQUAL;
    size_t na = strlen(a), nb = strlen(b);
    if (na < nb && !strncmp(a,b,na) && b[na] == '/') return PATH1_IS_PREFIX;
    if (nb < na && !strncmp(a,b,nb) && a[nb] == '/') return PATH2_IS_PREFIX;
    return PATHS_ARE_NOT_COMPARABLE;
}
void note(const Tracee *t, Severity s, Origin o, const char *fmt, ...) {
    (void)t; (void)s; (void)o; (void)fmt;
}

static void start(Tracee *t, Sysnum n, const char *a, const char *b) {
    memset(registers, 0, sizeof(registers));
    for (int i = 0; i < NB_REG_VERSION; i++) {
        sysnums[i] = n;
        registers[i][SYSARG_1] = (word_t)a;
        registers[i][SYSARG_2] = (word_t)b;
    }
    assert(link2symlink_callback(test_extension, SYSCALL_ENTER_START, 0, 0) == 0);
    (void)t;
}
static void file(const char *p) {
    int fd = open(p, O_WRONLY | O_CREAT | O_EXCL, 0600); assert(fd >= 0);
    assert(write(fd, "data", 4) == 4); assert(close(fd) == 0);
}
static void path(char out[PATH_MAX], const char *root, const char *name) {
    assert(snprintf(out, PATH_MAX, "%s/%s", root, name) < PATH_MAX);
}
static void family(const char *visible, char intermediate[PATH_MAX], char final[PATH_MAX], int count) {
    int actual;
    assert(read_faked_hard_link(visible, intermediate) == 0);
    assert(read_intermediate(intermediate, final) == 0);
    assert(parse_l2s_final_count(final, &actual) && actual == count);
    assert(access(visible, F_OK) == 0);
}
static void link_file(Tracee *t, const char *a, const char *b) {
    start(t, PR_link, a, b);
    assert(link2symlink_callback(test_extension, SYSCALL_ENTER_END, 0, 0) == 0);
    assert(sysnums[CURRENT] == PR_void);
}
static void exit_result(Tracee *t, int result) {
    poke_reg(t, SYSARG_RESULT, (word_t)result);
    assert(link2symlink_callback(test_extension, SYSCALL_EXIT_END, 0, 0) == 0);
}

int main(int argc, char **argv) {
    assert(argc == 2 || argc == 3);
    bool exhaustive = argc == 2;
    const char *store = getenv("PROOT_L2S_DIR");
    if (store == NULL) store = argv[1];
    Tracee *t = talloc_zero(NULL, Tracee); assert(t);
    void *extensions = talloc_new(t); assert(extensions);
    test_extension = talloc_zero(extensions, Extension); assert(test_extension);
    test_extension->callback = link2symlink_callback;
    t->pid = getpid(); t->exe = "test";
    char a[PATH_MAX], b[PATH_MAX], c[PATH_MAX], d[PATH_MAX];
    char intermediate[PATH_MAX], final[PATH_MAX], next[PATH_MAX], text[PATH_MAX];
    struct stat st;
    int count;
    assert(!parse_l2s_final_count("", &count));
    assert(!parse_l2s_final_count(PREFIX "a.0002", &count));
    assert(!parse_l2s_final_count(PREFIX "a0001.0000", &count));
    assert(!parse_l2s_final_count(PREFIX "a0001.10000", &count));
    assert(!parse_l2s_final_count(PREFIX "a000x.0002", &count));
    assert(parse_l2s_final_count(PREFIX "lib.d.ts0001.9999", &count) && count == 9999);

    /* Translation errors must cause no reads, writes or host mutations. */
    start(t, PR_link, (void *)1, (void *)2);
    unsigned int reads = string_reads;
    assert(link2symlink_callback(test_extension, SYSCALL_ENTER_END, -ENOENT, 0) == 0);
    assert(string_reads == reads);

    path(a, argv[1], "a"); path(b, argv[1], "b"); path(c, argv[1], "c");
    file(a); link_file(t, a, b); family(a, intermediate, final, 2);
    /* Failed unlink and a falsely successful kernel result keep the count. */
    start(t, PR_unlink, a, NULL);
    assert(link2symlink_callback(test_extension, SYSCALL_ENTER_END, 0, 0) == 0);
    family(b, intermediate, final, 2); exit_result(t, -EACCES); family(b, intermediate, final, 2);
    start(t, PR_unlink, a, NULL);
    assert(link2symlink_callback(test_extension, SYSCALL_ENTER_END, 0, 0) == 0);
    exit_result(t, 0); family(b, intermediate, final, 2);
    /* Same-family rename must keep both names and counts. */
    start(t, PR_rename, a, b);
    assert(link2symlink_callback(test_extension, SYSCALL_ENTER_END, 0, 0) == 0);
    assert(peek_reg(t, CURRENT, SYSARG_2) == (word_t)a);
    assert(rename(a, (char *)peek_reg(t, CURRENT, SYSARG_2)) == 0);
    exit_result(t, 0); family(a, intermediate, final, 2); assert(access(b, F_OK) == 0);
    start(t, PR_unlink, a, NULL);
    assert(link2symlink_callback(test_extension, SYSCALL_ENTER_END, 0, 0) == 0);
    assert(unlink(a) == 0); exit_result(t, 0); family(b, intermediate, final, 1);

    /* FOLLOW sees a final regular file, but must reuse the existing family.
     * Destination EEXIST and EFAULT must undo the increment via its intermediate. */
    start(t, PR_linkat, NULL, final);
    registers[CURRENT][SYSARG_4] = (word_t)c;
    registers[CURRENT][SYSARG_5] = AT_SYMLINK_FOLLOW;
    assert(move_and_symlink_path(t, SYSARG_2, SYSARG_4) == 0);
    family(b, intermediate, final, 2); family(c, intermediate, next, 2);
    start(t, PR_link, final, b);
    assert(move_and_symlink_path(t, SYSARG_1, SYSARG_2) == -EEXIST);
    family(c, intermediate, final, 2);
    start(t, PR_link, final, NULL); errno = 0;
    assert(move_and_symlink_path(t, SYSARG_1, SYSARG_2) == -EFAULT);
    family(c, intermediate, final, 2);

    /* RENAME_NOREPLACE and EXCHANGE never consume the destination family. */
    for (int flag = RENAME_NOREPLACE; flag <= RENAME_EXCHANGE; flag++) {
        start(t, PR_renameat2, NULL, b);
        registers[CURRENT][SYSARG_4] = (word_t)c;
        registers[CURRENT][SYSARG_5] = flag;
        assert(link2symlink_callback(test_extension, SYSCALL_ENTER_END, 0, 0) == 0);
        assert(get_config(test_extension, false)->removed_link[0] == 0);
        exit_result(t, 0); family(c, intermediate, final, 2);
    }
    /* Rename of an unrelated file consumes only the replaced destination. */
    path(a, argv[1], "replacement"); file(a);
    start(t, PR_rename, a, b);
    assert(link2symlink_callback(test_extension, SYSCALL_ENTER_END, 0, 0) == 0);
    assert(rename(a,b) == 0); exit_result(t, 0); family(c, intermediate, final, 1);

    /* O_NOFOLLOW naming and canonicalized chains report the actual fake hard
     * link, not an ordinary symlink used to reach it or the intermediate. */
    start(t, PR_open, c, NULL);
    strcpy(text, c); translated_path(test_extension, text);
    assert(!strcmp(text, final));
    assert(!strcmp(get_config(test_extension, false)->pending_link, c));
    remember_dereferenced_link(test_extension, intermediate, final);
    assert(!strcmp(get_config(test_extension, false)->dereferenced_link, c));
    remember_dereferenced_link(test_extension, "/ordinary", c);
    assert(!strcmp(get_config(test_extension, false)->dereferenced_link, c));
    char guest[PATH_MAX];
    struct execve_proc_exe_state exe_state = { final, guest, false };
    execve_proc_exe(test_extension, &exe_state);
    assert(exe_state.substituted && !strcmp(guest, c));
    remember_fd(t->pid, 81, c);
    assert(!strcmp(recall_fd(t->pid, 9, final), c)); /* dup2 */
    assert(!strcmp(recall_fd(t->pid + 1, 81, final), c)); /* fork */
    assert(!strcmp(recall_fd(t->pid + 1, 9, final), c)); /* fork + dup: rank 3 */
    strcpy(text,"/stale"); remember_fd(t->pid + 1, 9, text);
    assert(!strcmp(recall_fd(t->pid + 1, 9, final), c)); /* stale exact */
    struct readlink_proc_fd_state fd_state = { t->pid + 1, 9, text, false };
    strcpy(text, final); readlink_proc_fd(&fd_state);
    assert(fd_state.substituted && !strcmp(text,c));

    /* The 9999 limit is independent of the number of occupied suffix slots. */
    snprintf(next, sizeof(next), "%.*s9999", (int)strlen(final) - 4, final);
    assert(rename(final,next) == 0); assert(unlink(intermediate) == 0);
    assert(symlink(next, intermediate) == 0);
    path(d, argv[1], "overlimit"); start(t, PR_link, c, d);
    assert(move_and_symlink_path(t, SYSARG_1, SYSARG_2) == -EMLINK);
    family(c, intermediate, final, 9999); assert(lstat(d,&st) < 0 && errno == ENOENT);

    /* Ordinary symlink contents must stay byte-for-byte intact. */
    path(a, argv[1], "ordinary"); path(b, argv[1], "ordinary-copy");
    assert(symlink("../relative-target", a) == 0); link_file(t,a,b);
    assert(my_readlink(b,text,PATH_MAX) >= 0 && !strcmp(text,"../relative-target"));
    path(a, argv[1], "absolute"); path(b, argv[1], "absolute-copy");
    assert(symlink("/guest-only/target", a) == 0); link_file(t,a,b);
    assert(my_readlink(b,text,PATH_MAX) >= 0 && !strcmp(text,"/guest-only/target"));
    start(t, PR_link, a,b); assert(move_and_symlink_path(t,SYSARG_1,SYSARG_2) == -EEXIST);

    /* Broken and malformed chains preserve a successful kernel lstat, and
     * decrement cannot delete a user file that isn't named with a count. */
    path(a,argv[1],"broken"); path(b,argv[1],PREFIX "missing0001");
    assert(symlink(b,a) == 0);
    struct stat output; memset(&output,0xa5,sizeof(output));
    start(t,PR_lstat,a,(const char *)&output); data_writes = 0;
    assert(handle_sysexit_end(test_extension) == 0 && data_writes == 0);
    strcpy(text,a); translated_path(test_extension,text); assert(!strcmp(text,a));
    path(c,argv[1],"user"); file(c); assert(symlink(c,b) == 0);
    assert(decrement_intermediate_count(t,a,b) == 0 && access(c,F_OK) == 0);
    start(t,PR_link,a,NULL); assert(move_and_symlink_path(t,SYSARG_1,SYSARG_2) == -ENOENT);

    /* Reserve before move: dangling intermediate and orphan final occupy slots. */
    path(a,argv[1],"slot"); path(b,argv[1],"slot-copy"); file(a);
    path(text,store,PREFIX "slot0001"); assert(symlink("missing",text) == 0);
    path(text,store,PREFIX "slot0002.0002"); file(text); link_file(t,a,b);
    family(a,intermediate,final,2); assert(strstr(intermediate,"slot0003"));
    assert(access(text,F_OK) == 0);
    path(a,argv[1],"many"); path(b,argv[1],"many-copy"); file(a);
    for (int i=1;i<=999;i++) {
        snprintf(text,PATH_MAX,"%s/" PREFIX "many%04d",store,i);
        assert(symlink("missing",text) == 0);
    }
    link_file(t,a,b); family(a,intermediate,final,2); assert(strstr(intermediate,"many1000"));
    path(a,argv[1],"full"); path(b,argv[1],"full-copy"); file(a);
    assert(lstat(a,&st) == 0); ino_t inode = st.st_ino;
    if (exhaustive) {
    for(int i=1;i<=9999;i++) {
        snprintf(text,PATH_MAX,"%s/" PREFIX "full%04d",store,i);
        assert(symlink("missing",text) == 0);
    }
    start(t,PR_link,a,b); assert(move_and_symlink_path(t,SYSARG_1,SYSARG_2) == -EMLINK);
    assert(lstat(a,&st) == 0 && S_ISREG(st.st_mode) && st.st_ino == inode);
    }

    /* statx uses the same strict count parser; a user prefix is insufficient. */
    struct statx_syscall_state statx_state = {0};
    statx_state.statx_buf.stx_mask = STATX_NLINK;
    statx_state.statx_buf.stx_nlink = 7;
    strcpy(statx_state.host_path,"/" PREFIX "a.0002");
    link2symlink_handle_statx(&statx_state); assert(statx_state.statx_buf.stx_nlink == 7);
    strcpy(statx_state.host_path,"/" PREFIX "a0001.9999");
    link2symlink_handle_statx(&statx_state); assert(statx_state.statx_buf.stx_nlink == 9999);
#ifdef USERLAND
    /* Only fake_id0's fstatat chain gets the emulated fstat count adjustment. */
    path(a,argv[1],"emulated"); path(b,argv[1],"emulated-copy");
    file(a); link_file(t,a,b); family(b,intermediate,final,2);
    start(t,PR_fstat,NULL,(const char *)&output);
    registers[CURRENT][SYSARG_2] = (word_t)final;
    sysnums[CURRENT] = PR_newfstatat;
    memset(&output,0,sizeof(output)); data_writes = 0;
    assert(link2symlink_callback(test_extension,SYSCALL_CHAINED_EXIT,0,0) == 0);
    assert(data_writes == 1 && output.st_nlink == 2);
    sysnums[CURRENT] = PR_ioctl; data_writes = 0;
    assert(link2symlink_callback(test_extension,SYSCALL_CHAINED_EXIT,0,0) == 0);
    assert(data_writes == 0);
#endif

    /* Copy fallback for a deleted /proc fd must not overwrite a destination. */
    path(a,argv[1],"deleted-source"); path(b,argv[1],"copy-destination");
    file(a); file(b);
    int source_fd = open(a,O_RDONLY); assert(source_fd >= 0 && unlink(a) == 0);
    snprintf(text,PATH_MAX,"/proc/%d/fd/%d",getpid(),source_fd);
    start(t,PR_linkat,NULL,text); registers[CURRENT][SYSARG_4] = (word_t)b;
    assert(handle_linkat_from_proc_fd(t) == -EEXIST);
    assert(lstat(b,&st) == 0 && S_ISREG(st.st_mode) && st.st_size == 4);
    assert(close(source_fd) == 0);

    /* Optional dirent correction must expose the backing type, including FIFOs,
     * and leave ordinary or broken symbolic links alone. */
    path(a,argv[1],"fifo"); path(b,argv[1],"fifo-copy");
    assert(mkfifo(a,0600) == 0); link_file(t,a,b);
    assert(l2s_fake_entry_type(argv[1],"fifo-copy",9) == DT_FIFO);
    assert(l2s_fake_entry_type(argv[1],"many-copy",9) == DT_REG);
    assert(l2s_fake_entry_type(argv[1],"ordinary",8) == DT_LNK);
    assert(l2s_fake_entry_type(argv[1],"broken",6) == DT_LNK);

    /* Default filters keep getdents64 out of the hot path. */
    assert(link2symlink_callback(test_extension,INITIALIZATION,0,0) == 0);
    bool seen = false;
    for (const FilteredSysnum *p=test_extension->filtered_sysnums; p->value != PR_void; p++)
        if (p->value == PR_getdents64) seen = true;
    assert(!seen);
    assert(link2symlink_callback(test_extension,INITIALIZATION,(intptr_t)"dirent",0) == 0);
    assert(get_config(test_extension,false)->dirent_enabled);
    puts("upstream link2symlink real-source logic regressions passed");
    talloc_free(t);
    for(size_t i=0;i<FD_CACHE_SIZE;i++) talloc_free(fd_cache[i].link);
    if(l2s_directory_fd>=0) close(l2s_directory_fd);
    return 0;
}
