/* stat-shim: in-process path-stat for neoproot --stat-shim.
 *
 * neoproot injects this .so via LD_PRELOAD and removes newfstatat/fstatat64/
 * statx from its seccomp filter, so the wrappers below issue raw syscalls the
 * tracer never sees.  In-process they reproduce the two stat-result transforms
 * that need no tracer state:
 *
 *   - guest -> host path translation from the binding map neoproot exports in
 *     NEOPROOT_STATSHIM_BINDS ("guest<TAB>host" newline-separated), with
 *     NEOPROOT_STATSHIM_ROOTFS as fallback;
 *   - fake_id0 ownership disguise (NEOPROOT_STATSHIM_UID_REAL/UID_FAKE and
 *     NEOPROOT_STATSHIM_GID_REAL/GID_FAKE).
 *
 * link2symlink (L2S) result disguise needs the real symlink chain, which the
 * tracer also intercepts, so it cannot be reproduced here.  Instead the seccomp
 * filter keeps those stat syscalls routed to USER_NOTIF *only* when the caller
 * ORs NEOPROOT_STAT_SHIM_FLAG into its flags argument (NEOPROOT_STATSHIM_NOTIF
 * tells the shim that channel exists).  Whenever a raw result is a symlink or an
 * L2S-internal name the wrappers re-issue the call with that sentinel and let
 * the tracer do the full L2S emulation.  Regular-file stats never pay that
 * round trip.
 *
 * Keep in sync with:
 *   src/syscall/seccomp.c                      set_seccomp_filters
 *   src/syscall/seccomp_notify.c               emulate_notif_fstatat/statx
 *   src/extension/fake_id0/stat.c              fake_id0_disguise_stat
 *   src/extension/link2symlink/link2symlink.c  link2symlink_disguise_stat
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define L2S_PREFIX     ".l2s."
#define L2S_PREFIX_LEN (sizeof(L2S_PREFIX) - 1)

/* Sentinel ORed into the flags argument to ask the tracer for one
 * USER_NOTIF-serviced stat.  Must match src/syscall/seccomp.h. */
#define NEOPROOT_STAT_SHIM_FLAG 0x40000000u
#define NEOPROOT_STAT_SHIM_RAW_TAG 0x4e50524ful

#define MAX_BINDS    512
#define BIND_ENTRY   '\n'
#define BIND_KV      '\t'

typedef struct {
    char   guest[PATH_MAX];
    size_t glen;
    char   host[PATH_MAX];
    size_t hlen;
} Bind;

static const char *g_rootfs;
static size_t      g_rootfs_len;
static int         g_debug;
static int         g_use_l2s;
static int         g_have_notif;

static int   g_have_ids;
static uid_t g_uid_real, g_uid_fake;
static gid_t g_gid_real, g_gid_fake;

static Bind *g_binds;
static int   g_nbinds;
/* Most scans stay under one mount/bind. Keep the last hit out of the linear
 * longest-prefix search; this is process-local and the table is immutable. */
static _Thread_local int    g_last_bind = -1;
static _Thread_local size_t g_last_bind_len;
static int   g_inited;

/* ---- raw syscalls: never recurse into our own interposers ----
 *
 * Programs that issue the stat syscalls themselves -- libuv's statx path is
 * one -- never reach the interposers below, and --stat-shim removes those
 * syscalls from the tracer filter, so their guest paths would be resolved by
 * the host kernel.  syscall() (defined at the end of this file) catches that
 * entry point, which makes every raw call here go through libc directly. */

typedef long (*syscall_fn)(long, ...);
static syscall_fn g_real_syscall;

__attribute__((constructor))
static void shim_bind_real_syscall(void) {
    g_real_syscall = (syscall_fn)dlsym(RTLD_NEXT, "syscall");
}

static long raw_syscall6(long number, long a1, long a2, long a3,
                         long a4, long a5, long a6) {
    if (g_real_syscall == NULL)
        g_real_syscall = (syscall_fn)dlsym(RTLD_NEXT, "syscall");
    if (g_real_syscall == NULL) {
        errno = ENOSYS;
        return -1;
    }
    /* Distinguish translated host-path calls from direct guest syscalls in BPF.
     * The kernel takes flags as int, so these upper bits never reach AT_* flags. */
    if (number == SYS_newfstatat && ((unsigned long)a4 & NEOPROOT_STAT_SHIM_FLAG) == 0)
        a4 |= NEOPROOT_STAT_SHIM_RAW_TAG << 32;
#ifdef SYS_statx
    if (number == SYS_statx && ((unsigned long)a3 & NEOPROOT_STAT_SHIM_FLAG) == 0)
        a3 |= NEOPROOT_STAT_SHIM_RAW_TAG << 32;
#endif
    return g_real_syscall(number, a1, a2, a3, a4, a5, a6);
}

static int raw_lstat(const char *path, struct stat *st) {
    return (int)raw_syscall6(SYS_newfstatat, AT_FDCWD, (long)path, (long)st,
                             AT_SYMLINK_NOFOLLOW, 0, 0);
}

/* L2S links are only detectable through the nofollow view of the same path.
 * Absolute guest paths are probed on their translated host path; dirfd-relative
 * names must go through the same dirfd (a real host descriptor). */
static int probe_is_symlink(int dirfd, const char *path, const char *host) {
    struct stat probe;
    int r;

    if (path == NULL)
        return 0;
    if (path[0] == '/')
        r = raw_lstat(host, &probe);
    else
        r = (int)raw_syscall6(SYS_newfstatat, dirfd, (long)path, (long)&probe,
                              AT_SYMLINK_NOFOLLOW, 0, 0);
    return r == 0 && S_ISLNK(probe.st_mode);
}

/* ---- binding map ---- */

static void parse_binds(const char *s) {
    const char *p = s;

    if (s == NULL || s[0] == '\0')
        return;
    g_binds = calloc(MAX_BINDS, sizeof(*g_binds));
    if (g_binds == NULL)
        return;

    while (*p != '\0' && g_nbinds < MAX_BINDS) {
        const char *nl = strchr(p, BIND_ENTRY);
        size_t len = nl != NULL ? (size_t)(nl - p) : strlen(p);
        const char *tab = memchr(p, BIND_KV, len);

        if (tab != NULL) {
            size_t glen = (size_t)(tab - p);
            size_t hlen = len - glen - 1;
            if (glen > 0 && hlen > 0
                && glen < PATH_MAX && hlen < PATH_MAX) {
                Bind *b = &g_binds[g_nbinds++];
                memcpy(b->guest, p, glen);
                b->guest[glen] = '\0';
                b->glen = glen;
                memcpy(b->host, tab + 1, hlen);
                b->host[hlen] = '\0';
                b->hlen = hlen;
            }
        }
        if (nl == NULL)
            break;
        p = nl + 1;
    }
}

static void shim_init(void) {
    const char *ur, *uf, *gr, *gf;

    if (g_inited)
        return;
    g_inited = 1;

    g_rootfs = getenv("NEOPROOT_STATSHIM_ROOTFS");
    if (g_rootfs == NULL)
        g_rootfs = "";
    g_rootfs_len = strlen(g_rootfs);
    g_debug = getenv("NEOPROOT_STATSHIM_DEBUG") != NULL;
    g_use_l2s = getenv("NEOPROOT_STATSHIM_L2S") != NULL;
    g_have_notif = getenv("NEOPROOT_STATSHIM_NOTIF") != NULL;
    if (g_debug)
        fprintf(stderr, "[stat-shim] init rootfs='%s' notif=%d l2s=%d\n",
                g_rootfs, g_have_notif, g_use_l2s);

    ur = getenv("NEOPROOT_STATSHIM_UID_REAL");
    uf = getenv("NEOPROOT_STATSHIM_UID_FAKE");
    gr = getenv("NEOPROOT_STATSHIM_GID_REAL");
    gf = getenv("NEOPROOT_STATSHIM_GID_FAKE");
    if (ur != NULL && uf != NULL && gr != NULL && gf != NULL) {
        g_uid_real = (uid_t)strtoul(ur, NULL, 10);
        g_uid_fake = (uid_t)strtoul(uf, NULL, 10);
        g_gid_real = (gid_t)strtoul(gr, NULL, 10);
        g_gid_fake = (gid_t)strtoul(gf, NULL, 10);
        g_have_ids = 1;
    }

    parse_binds(getenv("NEOPROOT_STATSHIM_BINDS"));
}

/* Does @path fall under binding guest prefix @b (boundary aware)? */
static int prefix_match(const char *path, const Bind *b) {
    if (b->glen == 1 && b->guest[0] == '/')
        return 1;
    if (strncmp(path, b->guest, b->glen) != 0)
        return 0;
    return path[b->glen] == '\0' || path[b->glen] == '/';
}

/* Translate a guest absolute path to its host path.  Absolute paths are the
 * only ones this can serve: a relative path at AT_FDCWD belongs to the
 * tracee's virtual cwd, which the tracer owns (see relative_to_host). */
static const char *to_host(const char *path, char *buf, size_t bufsz) {
    const Bind *best = NULL;
    const char *rest;
    int i;

    shim_init();
    if (path == NULL || path[0] != '/')
        return path;

    if (g_last_bind >= 0 && g_last_bind < g_nbinds
        && g_last_bind_len > 1
        && prefix_match(path, &g_binds[g_last_bind])) {
        best = &g_binds[g_last_bind];
    } else {
        for (i = 0; i < g_nbinds; i++) {
            const Bind *b = &g_binds[i];
            if (prefix_match(path, b) && (best == NULL || b->glen > best->glen))
                best = b;
        }
        if (best != NULL) {
            g_last_bind = (int)(best - g_binds);
            g_last_bind_len = best->glen;
        } else {
            g_last_bind = -1;
            g_last_bind_len = 0;
        }
    }

    if (best != NULL) {
        rest = path + best->glen;
        if (best->glen == 1 && best->guest[0] == '/')
            rest = path + 1;
        if (rest[0] == '/')
            rest++;
        {
            size_t rlen = strlen(rest);
            int slash = best->hlen > 0 && best->host[best->hlen - 1] == '/';
            size_t need = best->hlen + (slash ? 0 : 1) + rlen + 1;
            if (need >= bufsz) {
                errno = ENAMETOOLONG;
                return path;
            }
            {
                size_t hlen = best->hlen;
                memcpy(buf, best->host, hlen);
                if (!slash)
                    buf[hlen++] = '/';
                memcpy(buf + hlen, rest, rlen + 1);
            }
        }
        return buf;
    }

    if (g_rootfs[0] != '\0') {
        size_t rlen = strlen(path);
        size_t hlen = g_rootfs_len;
        if (hlen + rlen + 1 >= bufsz) {
            errno = ENAMETOOLONG;
            return path;
        }
        memcpy(buf, g_rootfs, hlen);
        memcpy(buf + hlen, path, rlen + 1);
        return buf;
    }
    return path;
}

/* Host path of a relative name at AT_FDCWD when no USER_NOTIF channel is
 * available.  PR_getcwd is emulated by the tracer, so it reports the guest cwd
 * even though the tracee's real cwd is a host path; translating the joined
 * guest path keeps the bind table authoritative.  Callers with a channel must
 * prefer tracer_fstatat()/tracer_statx(): only the tracer reproduces ".."
 * across a bind boundary and the L2S result disguise. */
static const char *relative_to_host(const char *path, char *buf, size_t bufsz) {
    char cwd[PATH_MAX];
    char guest[PATH_MAX];
    const char *host;
    size_t clen;
    size_t glen;
    int n;

    if (getcwd(cwd, sizeof cwd) == NULL)
        return path;
    clen = strlen(cwd);
    n = snprintf(guest, sizeof guest, "%s%s%s", cwd,
                 (clen > 1 && cwd[clen - 1] == '/') ? "" : "/", path);
    if (n < 0 || (size_t)n >= sizeof guest) {
        errno = ENAMETOOLONG;
        return path;
    }
    host = to_host(guest, buf, bufsz);
    if (host != guest)
        return host;
    /* to_host() echoes its argument when no binding or rootfs applies; the
     * guest buffer is local to this frame, so hand back a stable copy. */
    glen = strlen(guest) + 1;
    if (glen > bufsz) {
        errno = ENAMETOOLONG;
        return path;
    }
    memmove(buf, guest, glen);
    return buf;
}

/* ---- fake_id0 ---- */

static void disguise_ids_stat(struct stat *st) {
    if (!g_have_ids || st == NULL)
        return;
    if (st->st_uid == g_uid_real)
        st->st_uid = g_uid_fake;
    if (st->st_gid == g_gid_real)
        st->st_gid = g_gid_fake;
}

static void disguise_ids_statx(struct statx *stx) {
    if (!g_have_ids || stx == NULL)
        return;
    if ((stx->stx_mask & STATX_UID) && stx->stx_uid == g_uid_real)
        stx->stx_uid = g_uid_fake;
    if ((stx->stx_mask & STATX_GID) && stx->stx_gid == g_gid_real)
        stx->stx_gid = g_gid_fake;
}

/* ---- link2symlink delegation ---- */

static const char *base_name(const char *path) {
    const char *s = strrchr(path, '/');
    return s != NULL ? s + 1 : path;
}

/* Only symlinks and .l2s.* storage names can need the tracer's L2S disguise. */
static int l2s_ambiguous(const char *guest, const char *host, int is_link) {
    if (is_link)
        return 1;
    if (guest != NULL && *guest != '\0'
        && strncmp(base_name(guest), L2S_PREFIX, L2S_PREFIX_LEN) == 0)
        return 1;
    if (host != NULL && *host != '\0'
        && strncmp(base_name(host), L2S_PREFIX, L2S_PREFIX_LEN) == 0)
        return 1;
    return 0;
}

/* Re-issue through the tracer.  @path must stay the guest path so the tracer
 * translates it; the caller already owns a raw result to fall back on. */
static int tracer_fstatat(int dirfd, const char *path, struct stat *st, int flags) {
    if (!g_have_notif || path == NULL)
        return 0;
    return raw_syscall6(SYS_newfstatat, dirfd, (long)path, (long)st,
                        (int)((unsigned int)flags | NEOPROOT_STAT_SHIM_FLAG),
                        0, 0) == 0;
}

static int tracer_statx(int dirfd, const char *path, int flags, unsigned int mask,
                        struct statx *stx) {
    if (!g_have_notif || path == NULL)
        return 0;
    return raw_syscall6(SYS_statx, dirfd, (long)path,
                        (int)((unsigned int)flags | NEOPROOT_STAT_SHIM_FLAG),
                        mask, (long)stx, 0) == 0;
}

/* ---- interposed entry points ---- */

int fstatat(int dirfd, const char *path, struct stat *st, int flags) {
    char buf[PATH_MAX];
    const char *host;
    int is_link = 0;

    shim_init();
    /* A relative name at AT_FDCWD resolves against the tracee's *virtual*
     * cwd, which differs from the real one (--cwd is applied virtually and a
     * bind source is a host path).  Only the tracer can translate that, so
     * re-issue through its USER_NOTIF channel: exactly the emulation used
     * when --stat-shim is off.  Without that channel fall back to the guest
     * cwd the tracer reports for getcwd(). */
    if (dirfd == AT_FDCWD && path != NULL && path[0] != '/') {
        if (g_have_notif) {
            if (tracer_fstatat(dirfd, path, st, flags))
                return 0;
            return -1;
        }
        host = relative_to_host(path, buf, sizeof(buf));
    } else {
        host = to_host(path, buf, sizeof(buf));
    }
    if (g_debug)
        fprintf(stderr, "[stat-shim] fstatat(%d,'%s')->'%s' flags=%#x\n",
                dirfd, path != NULL ? path : "", host != NULL ? host : "", flags);
    if (raw_syscall6(SYS_newfstatat, dirfd, (long)host, (long)st, flags, 0, 0) < 0) {
        int raw_errno = errno;
        if (g_debug)
            fprintf(stderr, "[stat-shim]   RAW FAIL errno=%d\n", raw_errno);
        /* A raw failure is not conclusive.  The host kernel resolves the
         * translated path by itself, and the guest filesystem stores
         * symlinks whose targets are guest absolute paths (fnm's
         * multishell link -> /home/..., a library alias foo.so -> foo.so.1).
         * Those targets do not exist in the host namespace, so only the
         * tracer can resolve the guest path.  Retry through USER_NOTIF; it
         * is also the side that owns the binding map. */
        if (g_have_notif) {
            int fb = tracer_fstatat(dirfd, path, st, flags);
            if (g_debug)
                fprintf(stderr, "[stat-shim]   FALLBACK fstatat %s errno=%d '%s'\n",
                        fb ? "ok" : "fail", fb ? 0 : errno,
                        path != NULL ? path : "");
            if (fb)
                return 0;
            return -1;
        }
        errno = raw_errno;
        return -1;
    }
    if (g_debug)
        fprintf(stderr, "[stat-shim]   RAW ok mode=%o nlink=%u\n",
                (unsigned)st->st_mode, (unsigned)st->st_nlink);

    if (g_use_l2s && g_have_notif) {
        if ((flags & AT_SYMLINK_NOFOLLOW) != 0) {
            is_link = S_ISLNK(st->st_mode);
        } else {
            is_link = probe_is_symlink(dirfd, path, host);
        }
        if (l2s_ambiguous(path, host, is_link)) {
            if (g_debug)
                fprintf(stderr, "[stat-shim]   fallback is_link=%d\n", is_link);
            if (tracer_fstatat(dirfd, path, st, flags))
                return 0;
            if (g_debug)
                fprintf(stderr, "[stat-shim]   fallback FAILED errno=%d\n", errno);
        }
    }

    disguise_ids_stat(st);
    return 0;
}

int statx(int dirfd, const char *path, int flags, unsigned int mask,
          struct statx *stx) {
    char buf[PATH_MAX];
    const char *host;
    int is_link = 0;

    shim_init();
    /* Same virtual-cwd rule as fstatat(). */
    if (dirfd == AT_FDCWD && path != NULL && path[0] != '/') {
        if (g_have_notif) {
            if (tracer_statx(dirfd, path, flags, mask, stx))
                return 0;
            return -1;
        }
        host = relative_to_host(path, buf, sizeof(buf));
    } else {
        host = to_host(path, buf, sizeof(buf));
    }
    if (g_debug)
        fprintf(stderr, "[stat-shim] statx(%d,'%s')->'%s' flags=%#x mask=%#x\n",
                dirfd, path != NULL ? path : "", host != NULL ? host : "", flags, mask);
    if (raw_syscall6(SYS_statx, dirfd, (long)host, flags, mask, (long)stx, 0) < 0) {
        int raw_errno = errno;
        if (g_debug)
            fprintf(stderr, "[stat-shim]   statx RAW FAIL errno=%d\n", raw_errno);
        /* Same guest-absolute-symlink reasoning as fstatat(). */
        if (g_have_notif) {
            if (tracer_statx(dirfd, path, flags, mask, stx))
                return 0;
            return -1;
        }
        errno = raw_errno;
        return -1;
    }
    if (g_debug)
        fprintf(stderr, "[stat-shim]   statx RAW ok mode=%o nlink=%u\n",
                (unsigned)stx->stx_mode, (unsigned)stx->stx_nlink);

    if (g_use_l2s && g_have_notif) {
        if ((flags & AT_SYMLINK_NOFOLLOW) != 0) {
            is_link = (stx->stx_mode & S_IFMT) == S_IFLNK;
        } else {
            is_link = probe_is_symlink(dirfd, path, host);
        }
        if (l2s_ambiguous(path, host, is_link)) {
            if (g_debug)
                fprintf(stderr, "[stat-shim]   statx fallback is_link=%d\n", is_link);
            if (tracer_statx(dirfd, path, flags, mask, stx))
                return 0;
            if (g_debug)
                fprintf(stderr, "[stat-shim]   statx fallback FAILED errno=%d\n", errno);
        }
    }

    disguise_ids_statx(stx);
    return 0;
}

int fstat(int fd, struct stat *st) {
    int r;

    shim_init();
    /* neoproot removes fstat from the filter only when link2symlink is off.
     * Under L2S this same raw call remains traced, preserving fd/path state. */
#ifdef SYS_fstat
    r = (int)raw_syscall6(SYS_fstat, fd, (long)st, 0, 0, 0, 0);
#else
    r = (int)raw_syscall6(SYS_newfstatat, fd, (long)"", (long)st,
                          AT_EMPTY_PATH, 0, 0);
#endif
    if (r == 0)
        disguise_ids_stat(st);
    return r;
}

int stat(const char *path, struct stat *st) {
    return fstatat(AT_FDCWD, path, st, 0);
}

int lstat(const char *path, struct stat *st) {
    return fstatat(AT_FDCWD, path, st, AT_SYMLINK_NOFOLLOW);
}

/* glibc implements eaccess() on top of an *internal* stat() call: a direct
 * intra-libc branch to stat@@GLIBC_2.33, not a PLT call, so LD_PRELOAD cannot
 * interpose that stat().  Under --stat-shim the path-stat syscalls are removed
 * from the tracer's seccomp filter and a non-sentinel stat is ALLOWed, i.e.
 * executed by the kernel directly.  glibc's internal stat() therefore runs
 * against the *host* namespace with the untranslated guest path and wrongly
 * returns ENOENT for a guest-absolute name.  GNU make 4.4 calls
 * eaccess(program, X_OK) before posix_spawn(), so a recursive $(MAKE)
 * recipe aborts with 127 "No such file or directory" without ever cloning.
 *
 * The two halves need opposite path forms (stat() wants the host path because
 * it is ALLOWed kernel-direct; access() wants the guest path because it is
 * still traced and translated), so glibc's eaccess() cannot work under the
 * shim no matter which form the caller passes.
 *
 * Fix: interpose the public eaccess() symbol and implement it as a single
 * faccessat2(AT_FDCWD, path, mode, AT_EACCESS) on the untouched guest path.
 * The access family is never removed from the tracer's filter, so neoproot
 * translates that one syscall correctly for absolute and relative names alike. */
int eaccess(const char *path, int mode) {
    shim_init();

    /* faccessat2(AT_FDCWD, path, mode, AT_EACCESS) is exactly eaccess() and,
     * unlike glibc's stat()+access() pair, it is a single syscall that the
     * tracer still translates in shim mode (the access family is never removed
     * from the filter).  Hand it the *guest* path untouched and let neoproot
     * resolve it against the virtual cwd / bindings -- correct for both
     * absolute and relative names.  raw_syscall6() reaches libc's syscall()
     * via RTLD_NEXT, so it does not recurse into this preload's syscall(). */
#ifdef SYS_faccessat2
    {
        long r = raw_syscall6(SYS_faccessat2, AT_FDCWD, (long)path, mode,
                              AT_EACCESS, 0, 0);
        if (r == 0 || errno != ENOSYS)
            return (int)r;
    }
#endif

    /* faccessat2 is required for correct eaccess semantics in shim mode. */
    errno = ENOSYS;
    return -1;
}

/* glibc still uses the historical 64-bit symbol names from some internal
 * filesystem/configuration code (notably i3 on a 64-bit guest).  Keep these
 * entry points in the preload as well; otherwise that call can bypass the
 * shim while the corresponding raw syscall is no longer tracer-translated. */
int fstatat64(int dirfd, const char *path, struct stat64 *st, int flags) {
    return fstatat(dirfd, path, (struct stat *)st, flags);
}

int stat64(const char *path, struct stat64 *st) {
    return stat(path, (struct stat *)st);
}

int lstat64(const char *path, struct stat64 *st) {
    return lstat(path, (struct stat *)st);
}

int fstat64(int fd, struct stat64 *st) {
    return fstat(fd, (struct stat *)st);
}

/* Versioned glibc filesystem entry points.  Some applications call these
 * symbols directly instead of the public stat/stat64 wrappers. */
int __xstat(int version, const char *path, struct stat *st) {
    (void)version;
    return stat(path, st);
}

int __lxstat(int version, const char *path, struct stat *st) {
    (void)version;
    return lstat(path, st);
}

int __fxstat(int version, int fd, struct stat *st) {
    (void)version;
    return fstat(fd, st);
}

int __fxstatat(int version, int dirfd, const char *path,
               struct stat *st, int flags) {
    (void)version;
    return fstatat(dirfd, path, st, flags);
}

int __xstat64(int version, const char *path, struct stat64 *st) {
    (void)version;
    return stat64(path, st);
}

int __lxstat64(int version, const char *path, struct stat64 *st) {
    (void)version;
    return lstat64(path, st);
}

int __fxstat64(int version, int fd, struct stat64 *st) {
    (void)version;
    return fstat64(fd, st);
}

int __fxstatat64(int version, int dirfd, const char *path,
                 struct stat64 *st, int flags) {
    (void)version;
    return fstatat64(dirfd, path, st, flags);
}

/* libc's variadic syscall() entry point.  Code that issues the stat syscalls
 * itself (libuv's statx path, for instance) never reaches the wrappers above,
 * and with --stat-shim the tracer does not see those syscalls either, so the
 * kernel would resolve a guest path in the host namespace.  Route the stat
 * family through the same translation and forward everything else verbatim. */
long syscall(long number, ...) {
    va_list ap;
    long a1, a2, a3, a4, a5, a6;

    va_start(ap, number);
    a1 = va_arg(ap, long);
    a2 = va_arg(ap, long);
    a3 = va_arg(ap, long);
    a4 = va_arg(ap, long);
    a5 = va_arg(ap, long);
    a6 = va_arg(ap, long);
    va_end(ap);

    switch (number) {
#ifdef SYS_newfstatat
    case SYS_newfstatat:
        return (long)fstatat((int)a1, (const char *)a2, (struct stat *)a3,
                             (int)a4);
#endif
#ifdef SYS_fstatat64
    case SYS_fstatat64:
        return (long)fstatat64((int)a1, (const char *)a2, (struct stat64 *)a3,
                               (int)a4);
#endif
#ifdef SYS_statx
    case SYS_statx:
        return (long)statx((int)a1, (const char *)a2, (int)a3,
                           (unsigned int)a4, (struct statx *)a5);
#endif
    default:
        break;
    }
    return raw_syscall6(number, a1, a2, a3, a4, a5, a6);
}
