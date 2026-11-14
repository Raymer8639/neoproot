/* Production sources, local register/memory stubs, ordinary host filesystem calls.
 * No ptrace, nested neoproot, namespaces, UML, or sidecar implementation. */
#include <assert.h>
#include <dirent.h>
#include <stdlib.h>
#include <sys/syscall.h>

static long fail_after = -1;
static void *meta_calloc(size_t count, size_t size)
{
    if (fail_after == 0)
        return NULL;
    if (fail_after > 0)
        fail_after--;
    return calloc(count, size);
}
#define calloc meta_calloc
#include "../src/extension/fake_id0/helper_functions.c"
#undef calloc

/* An outer tracer may emulate hardlinks with distinct host inodes. Model the
 * kernel's same-inode identity explicitly for that one no-op case. */
static bool same_inode;
static int rename_lstat(const char *path, struct stat *st)
{
    int result = lstat(path, st);
    if (result == 0 && same_inode) {
        st->st_dev = 42;
        st->st_ino = 73;
    }
    return result;
}
#define lstat rename_lstat
#include "../src/extension/fake_id0/rename.c"
#undef lstat

static char root[PATH_MAX];
static Tracee tracee;
static Config config = {.euid = 123, .egid = 456, .umask = 022};
static unsigned int reads, fs_entries;

word_t peek_reg(const Tracee *t, RegVersion version, Reg reg)
{
    return t->_regs[version].regs[reg];
}
int read_string(const Tracee *t, char *out, word_t address, word_t limit)
{
    (void)t;
    reads++;
    if (!address)
        return -EFAULT;
    size_t length = strnlen((const char *)address, limit);
    memcpy(out, (const void *)address, length < limit ? length + 1 : limit);
    return length < limit ? (int)length + 1 : (int)limit + 1;
}
bool belongs_to_guestfs(const Tracee *t, const char *path)
{
    (void)t;
    size_t length = strlen(root);
    return strncmp(path, root, length) == 0
        && (path[length] == '/' || path[length] == '\0');
}
int translate_path(Tracee *t, char out[PATH_MAX], int fd, const char *path, bool deref)
{
    (void)t; (void)fd; (void)deref;
    strcpy(out, path);
    return 0;
}

/* Sanitizer instrumentation may retain these unused helper entry points. */
int getcwd2(Tracee *t, char out[PATH_MAX])
{
    (void)t;
    strcpy(out, root);
    return 0;
}
int readlink_proc_pid_fd(pid_t pid, int fd, char out[PATH_MAX])
{
    (void)pid; (void)fd; (void)out;
    return -ENOSYS;
}

static void host(char out[PATH_MAX], const char *name)
{
    assert(snprintf(out, PATH_MAX, "%s/%s", root, name) < PATH_MAX);
}
static void record(const char *name, unsigned int id)
{
    char path[PATH_MAX], key[PATH_MAX];
    host(path, name);
    assert(get_meta_path(path, key) == 0);
    assert(write_meta_file(key, 0400 + (id & 077), 10000 + id, 20000 + id,
        false, &config) == 0);
}
static void expect(const char *name, unsigned int id)
{
    char path[PATH_MAX], key[PATH_MAX];
    mode_t mode;
    uid_t uid;
    gid_t gid;
    host(path, name);
    assert(get_meta_path(path, key) == 0);
    assert(path_exists(key) == 0);
    assert(read_meta_file(key, &mode, &uid, &gid, &config) == 0);
    assert(mode == 0400 + (id & 077) && uid == 10000 + id && gid == 20000 + id);
}
static void absent(const char *name)
{
    char path[PATH_MAX], key[PATH_MAX];
    mode_t mode;
    uid_t uid;
    gid_t gid;
    host(path, name);
    assert(get_meta_path(path, key) == 0);
    assert(path_exists(key) == -1 && errno == ENOENT);
    assert(read_meta_file(key, &mode, &uid, &gid, &config) == 0);
    assert(mode == 0755 && uid == config.euid && gid == config.egid);
}
static void forget(const char *name)
{
    char path[PATH_MAX], key[PATH_MAX];
    host(path, name);
    assert(get_meta_path(path, key) == 0);
    assert(remove_meta_file(key) == 0);
}
static void clear_records(void)
{
    while (meta_records != NULL) {
        MetaRecord *record = meta_records;
        meta_records = record->next;
        free(record);
    }
}
static void mkdir_name(const char *name)
{
    char path[PATH_MAX];
    host(path, name);
    assert(mkdir(path, 0700) == 0);
    fs_entries++;
}
static void file_name(const char *name)
{
    char path[PATH_MAX];
    host(path, name);
    int fd = open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
    assert(fd >= 0 && close(fd) == 0);
    fs_entries++;
}
static void prepare(const char *old_name, const char *new_name, unsigned int flags,
    long result, int status)
{
    static char old_path[PATH_MAX], new_path[PATH_MAX];
    host(old_path, old_name);
    host(new_path, new_name);
    memset(&tracee, 0, sizeof(tracee));
    tracee.status = status;
    tracee._regs[MODIFIED].regs[SYSARG_1] = (word_t)old_path;
    tracee._regs[MODIFIED].regs[SYSARG_2] = (word_t)new_path;
    tracee._regs[ORIGINAL].regs[SYSARG_3] = flags;
    tracee._regs[CURRENT].regs[SYSARG_RESULT] = result;
}
static void finish(bool has_flags)
{
    assert(handle_rename_exit_end(&tracee, SYSARG_1, SYSARG_2,
        has_flags ? SYSARG_3 : IGNORE_SYSARG, &config) == 0);
}
static void native_rename(const char *old_name, const char *new_name, unsigned int flags)
{
    char old_path[PATH_MAX], new_path[PATH_MAX];
    struct stat st;
    host(old_path, old_name);
    host(new_path, new_name);
    bool replaced = lstat(new_path, &st) == 0;
    if (flags != 0)
        assert(syscall(SYS_renameat2, AT_FDCWD, old_path, AT_FDCWD, new_path, flags) == 0);
    else {
        assert(rename(old_path, new_path) == 0);
        if (replaced)
            fs_entries--;
    }
    prepare(old_name, new_name, flags, 0, 0);
    finish(flags != 0);
}
static unsigned int scan(const char *path)
{
    unsigned int count = 0;
    DIR *dir = opendir(path);
    assert(dir != NULL);
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        assert(strncmp(entry->d_name, ".proot", 6) != 0);
        assert(strncmp(entry->d_name, "@neoproot-meta:", 15) != 0);
        char child[PATH_MAX];
        struct stat st;
        assert(snprintf(child, PATH_MAX, "%s/%s", path, entry->d_name) < PATH_MAX);
        assert(lstat(child, &st) == 0);
        count++;
        if (S_ISDIR(st.st_mode))
            count += scan(child);
    }
    assert(closedir(dir) == 0);
    return count;
}

static void nested_rename(void)
{
    mkdir_name("source"); mkdir_name("source/nested");
    file_name("source/nested/file"); mkdir_name("destination");
    record("source///", 1); record("source/nested/", 2);
    record("source/nested/file", 3);
    record("destination", 4); record("destination/stale/deep", 5);
    record("source-extra/nested/file", 6); record("destination-extra", 7);
    native_rename("source///", "destination///", 0);
    expect("destination", 1); expect("destination/nested", 2);
    expect("destination/nested/file", 3);
    absent("source"); absent("source/nested"); absent("source/nested/file");
    absent("destination/stale/deep");
    expect("source-extra/nested/file", 6); expect("destination-extra", 7);
    /* A second move proves the retained host paths were updated as well as keys.
     * No metadata on the source root must not hide recorded descendants. */
    forget("destination");
    native_rename("destination", "renamed-again-longer", 0);
    absent("renamed-again-longer"); expect("renamed-again-longer/nested", 2);
    expect("renamed-again-longer/nested/file", 3);
    absent("destination/nested/file");
    puts("PASS nested rename, overwrite cleanup, prefix boundaries, trailing slashes, repeated move");
}

static void exchange_trees(void)
{
    clear_records();
    mkdir_name("left"); mkdir_name("right-longer");
    record("left", 10); record("left/nested/file", 11); record("left/only-left/deep", 12);
    record("right-longer", 20); record("right-longer/nested/file", 21);
    record("right-longer/only-right/deep", 22); record("right-longer-extra/nested/file", 23);
    native_rename("left", "right-longer", RENAME_EXCHANGE);
    expect("left", 20); expect("left/nested/file", 21); expect("left/only-right/deep", 22);
    expect("right-longer", 10); expect("right-longer/nested/file", 11);
    expect("right-longer/only-left/deep", 12);
    absent("left/only-left/deep"); absent("right-longer/only-right/deep");
    expect("right-longer-extra/nested/file", 23);
    /* Exchange again with one unrecorded root and different path lengths. */
    forget("left");
    native_rename("left/", "right-longer///", RENAME_EXCHANGE);
    expect("left", 10); expect("left/nested/file", 11); expect("left/only-left/deep", 12);
    absent("right-longer"); expect("right-longer/nested/file", 21);
    expect("right-longer/only-right/deep", 22);
    clear_records();
    /* A completely unrecorded side exchanges absence with a recorded subtree. */
    record("right-longer/deep/record", 24);
    native_rename("left", "right-longer", RENAME_EXCHANGE);
    expect("left/deep/record", 24); absent("right-longer/deep/record");
    puts("PASS simultaneous directory exchange, shared suffixes, asymmetric and unrecorded roots");
}

static void unrecorded_replacement(void)
{
    clear_records();
    mkdir_name("fresh"); mkdir_name("stale");
    record("stale", 30); record("stale/child/grandchild", 31);
    record("stale-extra/child", 32);
    /* Do not call get_meta_path for fresh: the source has no registration. */
    native_rename("fresh", "stale", 0);
    absent("stale"); absent("stale/child/grandchild"); expect("stale-extra/child", 32);
    puts("PASS unregistered source clears complete stale destination subtree");
}

static void failure_and_noop(void)
{
    clear_records();
    mkdir_name("unchanged"); mkdir_name("other");
    record("unchanged", 40); record("unchanged/child/deep", 41);
    record("other", 42); record("other/child/deep", 43);
    unsigned int before = reads;
    prepare("unchanged", "other", RENAME_EXCHANGE, -EINVAL, 0); finish(true);
    prepare("unchanged", "other", 0, 0, -EACCES); finish(false);
    assert(reads == before);
    expect("unchanged/child/deep", 41); expect("other/child/deep", 43);
    native_rename("unchanged", "unchanged///", 0);
    fs_entries++; /* The same-name native rename did not replace an entry. */
    expect("unchanged", 40); expect("unchanged/child/deep", 41);
    /* Model success/no-op on two host names for one inode, for both APIs. */
    file_name("inode-a"); file_name("inode-b");
    record("inode-a", 44); record("inode-b", 45);
    record("inode-a/phantom-child", 46); record("inode-b/phantom-child", 47);
    same_inode = true;
    prepare("inode-a", "inode-b", 0, 0, 0); finish(false);
    prepare("inode-a", "inode-b", RENAME_EXCHANGE, 0, 0); finish(true);
    same_inode = false;
    expect("inode-a", 44); expect("inode-b", 45);
    expect("inode-a/phantom-child", 46); expect("inode-b/phantom-child", 47);
    puts("PASS failed/status-error renames, same-path and same-inode rename/exchange no-ops");
}

static void allocation_atomicity(void)
{
    char from[PATH_MAX], to[PATH_MAX];
    host(from, "allocation-source"); host(to, "allocation-destination");
    for (int exchange = 0; exchange <= 1; exchange++) {
        unsigned int failures = 0;
        bool succeeded = false;
        for (long budget = 0; budget < 10; budget++) {
            clear_records();
            record("allocation-source", 50); record("allocation-source/one", 51);
            record("allocation-source/two/deep", 52);
            record("allocation-destination", 53); record("allocation-destination/old", 54);
            record("allocation-destination-extra/old", 55);
            fail_after = budget;
            int result = rename_meta_tree(from, to, exchange);
            fail_after = -1;
            if (result == 0) {
                succeeded = true;
                expect("allocation-destination", 50); expect("allocation-destination/one", 51);
                expect("allocation-destination/two/deep", 52);
                if (exchange) {
                    expect("allocation-source", 53); expect("allocation-source/old", 54);
                } else {
                    absent("allocation-source"); absent("allocation-source/one");
                }
                expect("allocation-destination-extra/old", 55);
                break;
            }
            assert(result == -ENOMEM);
            failures++;
            expect("allocation-source", 50); expect("allocation-source/one", 51);
            expect("allocation-source/two/deep", 52);
            expect("allocation-destination", 53); expect("allocation-destination/old", 54);
            expect("allocation-destination-extra/old", 55);
        }
        assert(succeeded && failures == (exchange ? 5 : 3));
    }
    /* A failure after kernel success preserves the syscall result and leaves
     * all source/destination metadata intact, including already staged entries. */
    clear_records();
    mkdir_name("oom-exit-from"); mkdir_name("oom-exit-to");
    record("oom-exit-from", 56); record("oom-exit-from/one", 57);
    record("oom-exit-from/two/deep", 58); record("oom-exit-to/stale", 59);
    fail_after = 1;
    native_rename("oom-exit-from", "oom-exit-to", 0);
    fail_after = -1;
    assert(peek_reg(&tracee, CURRENT, SYSARG_RESULT) == 0);
    expect("oom-exit-from", 56); expect("oom-exit-from/one", 57);
    expect("oom-exit-from/two/deep", 58); expect("oom-exit-to/stale", 59);
    /* Registration failure must not leave a false metadata record. */
    char key[PATH_MAX];
    host(from, "registration-failure");
    fail_after = 0;
    assert(get_meta_path(from, key) == -ENOMEM);
    fail_after = -1;
    absent("registration-failure");
    puts("PASS every staged allocation failure leaves both metadata subtrees intact");
}

static void length_and_legacy_api(void)
{
    clear_records();
    char from[PATH_MAX], to[PATH_MAX], child[PATH_MAX], key[PATH_MAX], dest_key[PATH_MAX];
    host(from, "length-source"); host(to, "length-destination");
    size_t prefix = strlen(from);
    memcpy(child, from, prefix);
    child[prefix] = '/';
    memset(child + prefix + 1, 'x', PATH_MAX - prefix - 3);
    child[PATH_MAX - 2] = '\0';
    assert(get_meta_path(child, key) == 0);
    assert(write_meta_file(key, 0671, 81, 82, false, &config) == 0);
    record("length-destination/stale", 60);
    record("length-source/short", 63); /* Staged before the overlong descendant. */
    assert(rename_meta_tree(from, to, false) == -ENAMETOOLONG);
    mode_t mode; uid_t uid; gid_t gid;
    assert(path_exists(key) == 0 && read_meta_file(key, &mode, &uid, &gid, &config) == 0);
    assert(mode == 0671 && uid == 81 && gid == 82);
    expect("length-destination/stale", 60);
    expect("length-source/short", 63);
    absent("length-destination/short");
    clear_records();
    record("legacy-source/child", 61); record("legacy-destination/stale", 62);
    host(from, "legacy-source"); host(to, "legacy-destination");
    assert(get_meta_path(from, key) == 0 && get_meta_path(to, dest_key) == 0);
    assert(rename_meta_file(key, dest_key) == 0);
    expect("legacy-destination/child", 61); absent("legacy-source/child");
    absent("legacy-destination/stale");
    /* Previously returned source keys remain usable after the subtree moves. */
    assert(write_meta_file(key, 0400, 10064, 20064, false, &config) == 0);
    expect("legacy-source", 64);
    assert(remove_meta_file(dest_key) == 0);
    assert(write_meta_file(dest_key, 0600, 83, 84, false, &config) == 0);
    assert(path_exists(dest_key) == 0);
    puts("PASS path-length rollback and existing opaque-key rename/remove/write callers");
}

int main(int argc, char **argv)
{
    assert(argc == 2 && realpath(argv[1], root) != NULL);
    nested_rename(); exchange_trees(); unrecorded_replacement(); failure_and_noop();
    allocation_atomicity(); length_and_legacy_api();
    assert(scan(root) == fs_entries);
    clear_records();
    puts("PASS exact host entry count and no metadata sidecars");
    return 0;
}
