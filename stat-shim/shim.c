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
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
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

/* ---- raw syscalls: never recurse into our own interposers ---- */

static int raw_lstat(const char *path, struct stat *st) {
    return (int)syscall(SYS_newfstatat, AT_FDCWD, path, st, AT_SYMLINK_NOFOLLOW);
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
        r = (int)syscall(SYS_newfstatat, dirfd, path, &probe, AT_SYMLINK_NOFOLLOW);
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

/* Translate a guest absolute path to its host path.  Relative paths and
 * dirfd-relative names are already host-rooted (the kernel dirfd/cwd is a real
 * host fd), so they pass through untouched. */
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
    return syscall(SYS_newfstatat, dirfd, path, st,
                   (int)((unsigned int)flags | NEOPROOT_STAT_SHIM_FLAG)) == 0;
}

static int tracer_statx(int dirfd, const char *path, int flags, unsigned int mask,
                        struct statx *stx) {
    if (!g_have_notif || path == NULL)
        return 0;
    return syscall(SYS_statx, dirfd, path,
                   (int)((unsigned int)flags | NEOPROOT_STAT_SHIM_FLAG),
                   mask, stx) == 0;
}

/* ---- interposed entry points ---- */

int fstatat(int dirfd, const char *path, struct stat *st, int flags) {
    char buf[PATH_MAX];
    const char *host;
    int is_link = 0;

    shim_init();
    host = to_host(path, buf, sizeof(buf));
    if (g_debug)
        fprintf(stderr, "[stat-shim] fstatat(%d,'%s')->'%s' flags=%#x\n",
                dirfd, path != NULL ? path : "", host != NULL ? host : "", flags);
    if (syscall(SYS_newfstatat, dirfd, host, st, flags) < 0) {
        if (g_debug)
            fprintf(stderr, "[stat-shim]   RAW FAIL errno=%d\n", errno);
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
    host = to_host(path, buf, sizeof(buf));
    if (g_debug)
        fprintf(stderr, "[stat-shim] statx(%d,'%s')->'%s' flags=%#x mask=%#x\n",
                dirfd, path != NULL ? path : "", host != NULL ? host : "", flags, mask);
    if (syscall(SYS_statx, dirfd, host, flags, mask, stx) < 0) {
        if (g_debug)
            fprintf(stderr, "[stat-shim]   statx RAW FAIL errno=%d\n", errno);
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
    r = (int)syscall(SYS_fstat, fd, st);
#else
    r = (int)syscall(SYS_newfstatat, fd, "", st, AT_EMPTY_PATH);
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
