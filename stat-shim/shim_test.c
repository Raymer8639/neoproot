/* Local unit test for shim.c.  No proot needed: it builds a throw-away rootfs
 * with a bind source and points the shim at it through the same environment
 * neoproot sets, then calls the interposed entry points.
 *
 * link2symlink result disguise lives in the tracer (the shim re-issues those
 * calls with NEOPROOT_STAT_SHIM_FLAG and lets USER_NOTIF resolve them), so this
 * test documents the no-fallback behaviour: without NEOPROOT_STATSHIM_NOTIF an
 * L2S link is handed back raw.  The full ON/OFF container A/B covers the
 * flag-gated path.
 *
 * Build:  ./build.sh && ./shim_test        (glibc / guest ABI)
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

/* shim.c provides these */
int fstatat(int dirfd, const char *path, struct stat *st, int flags);
int fstat(int fd, struct stat *st);
int statx(int dirfd, const char *path, int flags, unsigned int mask,
          struct statx *stx);

#define CHECK(cond, msg) do { \
    if (cond) { printf("  ok   %s\n", msg); } \
    else { printf("  FAIL %s\n", msg); fails++; } \
} while (0)

static int fails;

static void mkfile(const char *path) {
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) { perror(path); exit(2); }
    if (write(fd, "x", 1) != 1) { perror("write"); exit(2); }
    close(fd);
}

int main(void) {
    char root[] = "/tmp/shimtest.XXXXXX";
    char p[4096];

    if (mkdtemp(root) == NULL) { perror("mkdtemp"); return 2; }

    snprintf(p, sizeof p, "%s/foo", root);            mkfile(p);
    snprintf(p, sizeof p, "%s/bindsrc", root);        mkdir(p, 0755);
    snprintf(p, sizeof p, "%s/bindsrc/bar", root);    mkfile(p);
    snprintf(p, sizeof p, "%s/dir", root);            mkdir(p, 0755);
    /* L2S chain in production shape: link -> .l2s.link0001 -> .l2s.link0001.0003 */
    snprintf(p, sizeof p, "%s/dir/.l2s.link0001.0003", root); mkfile(p);
    snprintf(p, sizeof p, "%s/dir/.l2s.link0001", root);
    if (symlink(".l2s.link0001.0003", p) != 0) { perror("symlink mid"); return 2; }
    snprintf(p, sizeof p, "%s/dir/link", root);
    if (symlink(".l2s.link0001", p) != 0) { perror("symlink link"); return 2; }
    snprintf(p, sizeof p, "%s/norm", root);
    if (symlink("foo", p) != 0) { perror("symlink norm"); return 2; }

    setenv("NEOPROOT_STATSHIM_ROOTFS", root, 1);
    {
        char binds[8192];
        snprintf(binds, sizeof binds, "/\t%s\n/bind\t%s/bindsrc\n", root, root);
        setenv("NEOPROOT_STATSHIM_BINDS", binds, 1);
    }
    setenv("NEOPROOT_STATSHIM_L2S", "1", 1);
    {
        char v[32];
        snprintf(v, sizeof v, "%lu", (unsigned long)getuid());
        setenv("NEOPROOT_STATSHIM_UID_REAL", v, 1);
        snprintf(v, sizeof v, "%lu", (unsigned long)getgid());
        setenv("NEOPROOT_STATSHIM_GID_REAL", v, 1);
    }
    setenv("NEOPROOT_STATSHIM_UID_FAKE", "4242", 1);
    setenv("NEOPROOT_STATSHIM_GID_FAKE", "4343", 1);
    /* No NEOPROOT_STATSHIM_NOTIF: no tracer resolution channel in this test. */

    printf("rootfs=%s real_uid=%lu\n", root, (unsigned long)getuid());

    {   /* 1. rootfs translation + fake_id0 */
        struct stat st;
        CHECK(lstat("/foo", &st) == 0, "lstat(/foo) via rootfs");
        CHECK(S_ISREG(st.st_mode), "  /foo is a regular file");
        CHECK(st.st_uid == 4242 && st.st_gid == 4343, "  /foo uid/gid disguised");
    }
    {   /* 2. fstat is accelerated when L2S is disabled */
        int fd = open(p, O_RDONLY);
        struct stat st;
        CHECK(fd >= 0, "open regular file for fstat");
        CHECK(fd >= 0 && fstat(fd, &st) == 0, "fstat regular file");
        CHECK(fd >= 0 && st.st_uid == 4242 && st.st_gid == 4343,
              "fstat uid/gid disguised");
        if (fd >= 0) close(fd);
    }
    {   /* 3. bind translation overrides rootfs */
        struct stat st;
        CHECK(stat("/bind/bar", &st) == 0, "stat(/bind/bar) via bind");
        CHECK(S_ISREG(st.st_mode), "  /bind/bar is a regular file");
        CHECK(stat("/bindsrc/bar", &st) == 0, "rootfs path still reachable");
    }
    {   /* 4. without the USER_NOTIF fallback an L2S link stays a symlink */
        struct stat st;
        CHECK(lstat("/dir/link", &st) == 0, "lstat(/dir/link)");
        CHECK(S_ISLNK(st.st_mode), "  no-fallback L2S link stays symlink");
        CHECK(st.st_uid == 4242, "  result still gets fake_id0");
    }
    {   /* 5. L2S storage name is a plain regular file */
        struct stat st;
        CHECK(lstat("/dir/.l2s.link0001.0003", &st) == 0, "lstat(storage name)");
        CHECK(S_ISREG(st.st_mode), "  storage name is a regular file");
    }
    {   /* 6. ordinary symlink untouched */
        struct stat st;
        CHECK(lstat("/norm", &st) == 0, "lstat(/norm)");
        CHECK(S_ISLNK(st.st_mode), "  ordinary symlink stays a symlink");
    }
    {   /* 7. missing file */
        struct stat st;
        CHECK(lstat("/definitely-missing", &st) == -1 && errno == ENOENT,
              "lstat(missing) == ENOENT");
    }
    {   /* 8. relative path through a host dirfd passes through untranslated */
        struct stat st;
        char d[4096];
        int fd;
        snprintf(d, sizeof d, "%s/dir", root);
        fd = open(d, O_RDONLY | O_DIRECTORY);
        CHECK(fd >= 0, "open host dir");
        CHECK(fstatat(fd, ".l2s.link0001.0003", &st, AT_SYMLINK_NOFOLLOW) == 0,
              "relative dirfd fstatat");
        if (fd >= 0) close(fd);
    }

    {   /* 9. the historical glibc *64 entry points hit the shim too.
         *     A program built with -D_FILE_OFFSET_BITS=64 (e.g. i3) resolves
         *     stat()/lstat() to stat64/lstat64, so interposing only the
         *     public stat/lstat names lets that call bypass the shim and
         *     issue an untranslated raw syscall (the "i3 cannot find its
         *     config" regression).  These names are strong symbols in shim.c
         *     and preempt libc's shared-library versions in this binary. */
        struct stat64 s64;
        CHECK(stat64("/bind/bar", &s64) == 0, "stat64(/bind/bar) via bind");
        CHECK(S_ISREG(s64.st_mode), "  stat64 sees a regular file");
        CHECK(lstat64("/foo", &s64) == 0, "lstat64(/foo) via rootfs");
        CHECK(s64.st_uid == 4242 && s64.st_gid == 4343,
              "  stat64/lstat64 uid/gid disguised");
    }

    printf("%s (%d failure%s)\n", fails == 0 ? "PASS" : "FAIL",
           fails, fails == 1 ? "" : "s");
    return fails == 0 ? 0 : 1;
}
