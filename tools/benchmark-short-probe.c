/* Short old/new regression probe: one ELF that runs unchanged inside the guest
 * rootfs, so both Neoproot builds execute the same bytes and the same ABI.
 *
 * Protocol v1, stdout only:
 *   1. exactly one complete line holding the marker argument;
 *   2. exactly one line of JSON:
 *      {"protocol":1,"marker":...,"workload":...,
 *       "status":"ok"|"error"|"unsupported","operations":N,"checksum":C,
 *       "duration_ns":D,"errno":E,"stage":S}
 *
 * Exit codes: 0 ok, 1 error, 2 bad invocation, 77 unsupported capability.
 * A failed operation is never reported as a fast sample: every operation that
 * is counted has been verified (stat size, link nlink/content, exec status,
 * received payload bytes).
 *
 * Every sample that touches the filesystem gets its own mkdtemp(3) directory
 * and chdir(2) into it. Setup runs before the clock starts and cleanup after
 * it stops; only the workload loop is timed.
 *
 * Build with the *guest* toolchain (glibc in the Arch/Alpine rootfs), never
 * with the Termux bionic compiler: a bionic ELF or .so would not load in the
 * guest and would silently measure something else.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define FILES 64u
#define FILE_SIZE 17u
#define PAYLOAD 64u
#define BATCH 4u

enum family { F_STARTUP, F_STAT_ABS, F_STAT_REL, F_L2S, F_FORK, F_UNIX };
enum method { M_SENDTO, M_SENDMSG, M_SENDMMSG };

struct plan {
    const char *name;
    enum family family;
    int translated;   /* unix-*: send to a bound pathname instead of a socketpair */
    enum method method;
};

static const struct plan plans[] = {
    {"startup", F_STARTUP, 0, M_SENDTO},
    {"stat-absolute", F_STAT_ABS, 0, M_SENDTO},
    {"stat-relative", F_STAT_REL, 0, M_SENDTO},
    {"l2s", F_L2S, 0, M_SENDTO},
    {"fork-exec", F_FORK, 0, M_SENDTO},
    {"unix-connected-sendto", F_UNIX, 0, M_SENDTO},
    {"unix-connected-sendmsg", F_UNIX, 0, M_SENDMSG},
    {"unix-connected-sendmmsg", F_UNIX, 0, M_SENDMMSG},
    {"unix-translated-sendto", F_UNIX, 1, M_SENDTO},
    {"unix-translated-sendmsg", F_UNIX, 1, M_SENDMSG},
    {"unix-translated-sendmmsg", F_UNIX, 1, M_SENDMMSG},
};

/* 17 bytes: "0123456789abcdef\n" */
static const char payload16[] = "0123456789abcdef\n";

static struct {
    uint64_t operations;
    uint64_t checksum;
    int err;            /* errno of the first failure, 0 while healthy */
    int unsupported;    /* capability gap, not a regression */
    const char *stage;  /* failure location, "complete" on success */
} run = {0, 0, 0, 0, "complete"};

static char work[PATH_MAX];   /* per-sample mkdtemp directory */
static int prepared;          /* atexit cleanup armed */

static int write_all(int fd, const char *data, size_t length)
{
    while (length > 0) {
        ssize_t written = write(fd, data, length);
        if (written < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (written == 0) { errno = EIO; return -1; }
        data += (size_t)written;
        length -= (size_t)written;
    }
    return 0;
}

static uint64_t now_ns(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) {
        /* Losing the clock after the marker would break the protocol; the
         * runner rejects a marker without JSON, so it stays a hard error. */
        run.err = errno ? errno : EIO;
        run.stage = "clock";
        return 0;
    }
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}

/* Record a failure at *stage* and classify it. ENOSYS/EOPNOTSUPP mean the
 * feature does not exist here; that is "unsupported", never a fast success. */
static int fail(const char *stage)
{
    run.err = errno ? errno : EIO;
    run.stage = stage;
    run.unsupported = (run.err == ENOSYS || run.err == EOPNOTSUPP);
    return -1;
}

static void cleanup(void)
{
    if (!prepared || !work[0]) return;
    (void)unlink("peer");
    (void)unlink("linked");
    for (unsigned i = 0; i < FILES; ++i) {
        char name[24];
        snprintf(name, sizeof(name), "f%02u", i);
        (void)unlink(name);
    }
    (void)chdir("/");
    (void)rmdir(work);
}

static int make_files(void)
{
    for (unsigned i = 0; i < FILES; ++i) {
        char name[24];
        snprintf(name, sizeof(name), "f%02u", i);
        int fd = open(name, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd < 0) return fail("create");
        ssize_t count = write(fd, payload16, FILE_SIZE);
        int saved = errno;
        (void)close(fd);
        errno = saved;
        if (count != (ssize_t)FILE_SIZE) return fail("write");
    }
    return 0;
}

/* Workloads. Each returns 0 or -1 with run.stage/run.err set. */

static int scan(int absolute, unsigned iterations)
{
    for (unsigned i = 0; i < iterations; ++i) {
        struct stat st;
        char name[24];
        snprintf(name, sizeof(name), "f%02u", i % FILES);
        int status;
        if (absolute) {
            char path[PATH_MAX];
            if (snprintf(path, sizeof(path), "%s/%s", work, name) >= (int)sizeof(path)) {
                errno = ENAMETOOLONG;
                return fail("stat-path");
            }
            status = stat(path, &st);
        } else {
            /* Plain cwd-relative path: this is what exercises the guest's
             * relative resolution, unlike fstatat(dirfd, ...) which would
             * skip the cwd translation entirely. */
            status = stat(name, &st);
        }
        if (status < 0) return fail("stat");
        if (!S_ISREG(st.st_mode) || st.st_size != (off_t)FILE_SIZE) {
            errno = EIO;
            return fail("stat-data");
        }
        ++run.operations;
        run.checksum += (uint64_t)st.st_size;
    }
    return 0;
}

/* Read COUNT bytes and compare them with the probe payload. */
static int payload_ok(const char *path)
{
    char data[FILE_SIZE];
    int fd = open(path, O_RDONLY);
    if (fd < 0) return fail("l2s-open");
    ssize_t count = read(fd, data, sizeof(data));
    int saved = errno;
    (void)close(fd);
    errno = saved;
    if (count != (ssize_t)FILE_SIZE) {
        if (count >= 0) errno = EIO;
        return fail("l2s-read");
    }
    if (memcmp(data, payload16, FILE_SIZE) != 0) {
        errno = EIO;
        return fail("l2s-content");
    }
    return 0;
}

/* link(2) under --link2symlink is an emulation: the second name may become a
 * symlink and st_nlink accounting is faked inconsistently between stat(2) and
 * lstat(2) on different backends. So the invariant checked here is semantic,
 * not an inode counter: the alias must expose the same bytes, removing the
 * alias must make the name disappear, and the original must survive with its
 * content intact. That is exactly the failure mode that costs user data. */
static int links(unsigned iterations)
{
    for (unsigned i = 0; i < iterations; ++i) {
        struct stat source, alias, alias_lstat;
        if (link("f00", "linked") < 0) return fail("l2s-link");
        if (stat("f00", &source) < 0) return fail("l2s-stat-source");
        if (stat("linked", &alias) < 0) return fail("l2s-stat-alias");
        if (source.st_size != (off_t)FILE_SIZE) { errno = EIO; return fail("l2s-source-size"); }
        if (lstat("linked", &alias_lstat) < 0) return fail("l2s-lstat-alias");
        if (payload_ok("linked") < 0) return -1;
        if (!S_ISLNK(alias_lstat.st_mode) && S_ISREG(alias_lstat.st_mode) &&
            alias_lstat.st_nlink < 2 && alias.st_nlink < 2) {
            errno = EIO;
            return fail("l2s-alias-link-count");
        }
        if (unlink("linked") < 0) return fail("l2s-unlink");
        if (stat("linked", &alias) == 0) {
            errno = EEXIST;
            return fail("l2s-unlink-visible");
        }
        if (errno != ENOENT) return fail("l2s-unlink-stat");
        if (stat("f00", &source) < 0) return fail("l2s-survivor-stat");
        if (payload_ok("f00") < 0) return -1;
        ++run.operations;
        run.checksum += FILE_SIZE;
    }
    return 0;
}

static int children(const char *self, unsigned iterations)
{
    for (unsigned i = 0; i < iterations; ++i) {
        pid_t child = fork();
        if (child < 0) return fail("fork");
        if (child == 0) {
            execl(self, self, "--child", (char *)NULL);
            _exit(127);
        }
        int status = 0;
        pid_t reaped;
        do {
            reaped = waitpid(child, &status, 0);
        } while (reaped < 0 && errno == EINTR);
        if (reaped != child) return fail("wait");
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            errno = ECHILD;
            return fail("exec-status");
        }
        ++run.operations;
        run.checksum += 1;
    }
    return 0;
}

static int sockets(const struct plan *plan, unsigned iterations)
{
    int fds[2] = {-1, -1};
    struct sockaddr_un address;
    socklen_t address_len = 0;
    memset(&address, 0, sizeof(address));

    if (plan->translated) {
        if (snprintf(address.sun_path, sizeof(address.sun_path), "%s/peer", work)
                >= (int)sizeof(address.sun_path)) {
            errno = ENAMETOOLONG;
            return fail("socket-path");
        }
        address.sun_family = AF_UNIX;
        address_len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
                                  strlen(address.sun_path) + 1);
        fds[0] = socket(AF_UNIX, SOCK_DGRAM, 0);
        fds[1] = socket(AF_UNIX, SOCK_DGRAM, 0);
        if (fds[0] < 0 || fds[1] < 0) return fail("socket");
        if (bind(fds[1], (struct sockaddr *)&address, address_len) < 0) return fail("bind");
    } else if (socketpair(AF_UNIX, SOCK_DGRAM, 0, fds) < 0) {
        return fail("socketpair");
    }

    for (unsigned i = 0; i < iterations;) {
        unsigned batch = plan->method == M_SENDMMSG ? (iterations - i < BATCH ? iterations - i : BATCH) : 1;
        char payload[BATCH][PAYLOAD];
        char received[PAYLOAD];
        struct iovec iov[BATCH];
        struct mmsghdr messages[BATCH];
        memset(messages, 0, sizeof(messages));

        for (unsigned j = 0; j < batch; ++j) {
            memset(payload[j], (int)((i + j) % 251 + 1), sizeof(payload[j]));
            iov[j].iov_base = payload[j];
            iov[j].iov_len = sizeof(payload[j]);
            messages[j].msg_hdr.msg_iov = &iov[j];
            messages[j].msg_hdr.msg_iovlen = 1;
            if (plan->translated) {
                messages[j].msg_hdr.msg_name = &address;
                messages[j].msg_hdr.msg_namelen = address_len;
            }
        }

        int sent;
        if (plan->method == M_SENDMMSG) {
            sent = sendmmsg(fds[0], messages, batch, 0);
        } else {
            ssize_t bytes;
            if (plan->method == M_SENDTO) {
                bytes = sendto(fds[0], payload[0], PAYLOAD, 0,
                               plan->translated ? (struct sockaddr *)&address : NULL,
                               address_len);
            } else {
                bytes = sendmsg(fds[0], &messages[0].msg_hdr, 0);
            }
            if (bytes >= 0 && bytes != (ssize_t)PAYLOAD) { errno = EIO; bytes = -1; }
            sent = bytes < 0 ? -1 : 1;
        }
        if (sent < 0) {
            int saved = errno;
            /* A translated destination that the guest cannot resolve shows up
             * as ENOENT/EAFNOSUPPORT after a successful bind: an old-version
             * capability gap, not a timing. Never count it as success. */
            if (plan->translated && (saved == ENOENT || saved == EAFNOSUPPORT)) {
                errno = saved;
                run.unsupported = 1;
                run.err = saved;
                run.stage = "destination-send";
                if (fds[0] >= 0) (void)close(fds[0]);
                if (fds[1] >= 0) (void)close(fds[1]);
                (void)unlink("peer");
                return -1;
            }
            errno = saved;
            if (fds[0] >= 0) (void)close(fds[0]);
            if (fds[1] >= 0) (void)close(fds[1]);
            (void)unlink("peer");
            return fail("destination-send");
        }
        if ((unsigned)sent != batch) {
            errno = EIO;
            (void)close(fds[0]);
            (void)close(fds[1]);
            (void)unlink("peer");
            return fail("send-count");
        }
        for (unsigned j = 0; j < batch; ++j) {
            if (plan->method == M_SENDMMSG && messages[j].msg_len != PAYLOAD) {
                errno = EIO;
                (void)close(fds[0]);
                (void)close(fds[1]);
                (void)unlink("peer");
                return fail("message-length");
            }
            ssize_t got = recv(fds[1], received, sizeof(received), MSG_TRUNC);
            if (got != (ssize_t)PAYLOAD || memcmp(received, payload[j], PAYLOAD) != 0) {
                errno = got < 0 ? errno : EIO;
                (void)close(fds[0]);
                (void)close(fds[1]);
                (void)unlink("peer");
                return fail("receive");
            }
            ++run.operations;
            run.checksum += PAYLOAD;
        }
        i += batch;
    }
    (void)close(fds[0]);
    (void)close(fds[1]);
    (void)unlink("peer");
    return 0;
}

static int report_string(const char *marker, const char *workload, uint64_t duration)
{
    const char *status = run.err ? (run.unsupported ? "unsupported" : "error") : "ok";
    char line[512];
    int length = snprintf(line, sizeof(line),
        "{\"protocol\":1,\"marker\":\"%s\",\"workload\":\"%s\",\"status\":\"%s\","
        "\"operations\":%" PRIu64 ",\"checksum\":%" PRIu64 ",\"duration_ns\":%" PRIu64 ","
        "\"errno\":%d,\"stage\":\"%s\"}\n",
        marker, workload, status, run.operations, run.checksum, duration,
        run.err, run.err ? run.stage : "complete");
    if (length < 0 || (size_t)length >= sizeof(line)) return -1;
    return write_all(STDOUT_FILENO, line, (size_t)length) < 0 ? -1 : 0;
}

static int usage(const char *why)
{
    fprintf(stderr, "short-probe: %s\n"
            "usage: short-probe WORKLOAD ITERATIONS MARKER DATA_DIR\n"
            "workloads: startup stat-absolute stat-relative l2s fork-exec "
            "unix-{connected,translated}-{sendto,sendmsg,sendmmsg}\n", why);
    return 2;
}

static int marker_ok(const char *marker)
{
    size_t length = strlen(marker);
    if (length == 0 || length > 128) return 0;
    for (size_t i = 0; i < length; ++i) {
        char c = marker[i];
        int alpha = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
        int digit = c >= '0' && c <= '9';
        if (!alpha && !digit && c != '_') return 0;
    }
    return 1;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--child") == 0) return 0;
    if (argc != 5) return usage("expected four arguments");
    if (argv[1][0] == 0 || argv[3][0] == 0 || argv[4][0] != '/')
        return usage("data directory must be an absolute path");
    if (!marker_ok(argv[3])) return usage("marker must be 1..128 of [A-Za-z0-9_]");

    errno = 0;
    char *end = NULL;
    unsigned long amount = strtoul(argv[2], &end, 10);
    if (errno != 0 || end == argv[2] || *end != 0 || amount < 1 || amount > 10000000)
        return usage("iterations must be 1..10000000");

    const struct plan *plan = NULL;
    for (unsigned i = 0; i < sizeof(plans) / sizeof(plans[0]); ++i) {
        if (strcmp(argv[1], plans[i].name) == 0) { plan = &plans[i]; break; }
    }
    if (plan == NULL) return usage("unknown workload");

    signal(SIGPIPE, SIG_IGN);
    /* The marker goes out before any setup so that launcher startup can be
     * measured, and it is a single complete line by construction. */
    if (write_all(STDOUT_FILENO, argv[3], strlen(argv[3])) < 0 ||
        write_all(STDOUT_FILENO, "\n", 1) < 0) {
        fprintf(stderr, "short-probe: cannot write marker: %s\n", strerror(errno));
        return 1;
    }

    unsigned iterations = (unsigned)amount;
    if (plan->family != F_STARTUP) {
        if (snprintf(work, sizeof(work), "%s/short-XXXXXX", argv[4]) >= (int)sizeof(work)) {
            errno = ENAMETOOLONG;
            fail("data-dir-path");
        } else if (mkdtemp(work) == NULL) {
            work[0] = 0;
            fail("mkdtemp");
        } else if (chdir(work) < 0) {
            int saved = errno;
            (void)rmdir(work);
            work[0] = 0;
            errno = saved;
            fail("chdir");
        } else {
            prepared = 1;
            atexit(cleanup);
            if ((plan->family == F_STAT_ABS || plan->family == F_STAT_REL || plan->family == F_L2S) &&
                make_files() < 0) {
                /* make_files already recorded the stage */
            }
        }
    }

    char self[PATH_MAX];
    self[0] = 0;
    if (plan->family == F_FORK) {
        if (argv[0][0] == '/') {
            snprintf(self, sizeof(self), "%s", argv[0]);
        } else {
            ssize_t length = readlink("/proc/self/exe", self, sizeof(self) - 1);
            if (length <= 0) {
                errno = ENOENT;
                fail("self-path");
            } else {
                self[length] = 0;
            }
        }
    }

    uint64_t started = now_ns();
    if (run.err == 0) {
        switch (plan->family) {
        case F_STARTUP:
            run.operations = iterations;
            run.checksum = iterations;
            break;
        case F_STAT_ABS: (void)scan(1, iterations); break;
        case F_STAT_REL: (void)scan(0, iterations); break;
        case F_L2S: (void)links(iterations); break;
        case F_FORK: (void)children(self, iterations); break;
        case F_UNIX: (void)sockets(plan, iterations); break;
        }
    }
    uint64_t duration = now_ns() - started;

    if (report_string(argv[3], argv[1], duration) < 0) {
        fprintf(stderr, "short-probe: cannot write result: %s\n", strerror(errno));
        return 1;
    }
    if (run.err == 0) return 0;
    return run.unsupported ? 77 : 1;
}
