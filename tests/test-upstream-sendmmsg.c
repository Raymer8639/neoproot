#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include "syscall/socket.h"
#include "syscall/chain.h"
#include "tracee/mem.h"
#include "tracee/reg.h"
#include "path/path.h"

/* The socket implementation is linked unchanged.  Only register/chain and
 * pathname plumbing is mocked; all sends and protected reads/stores use the
 * real host kernel.  The syscall wrapper injects unavailable VM operations. */
struct test_tracee {
    Tracee tracee;
    word_t regs[USERARG_1 + 1];
    Sysnum sysnum;
    bool queued;
    word_t args[6];
    unsigned allocations, queued_count;
    size_t scratch_size;
    word_t scratch;
    int queue_error;
    unsigned queue_fail_after;
};
static char host_target[PATH_MAX];
static int read_error, write_error;
static unsigned vm_reads, vm_writes, forbidden_accesses;
static char last_received[2048];
static long page_size;
static const unsigned sentinel = 0x8a8b8c8d;

extern long __real_syscall(long number, ...);
long __wrap_syscall(long number, ...)
{
    va_list ap;
    va_start(ap, number);
    assert(number == __NR_process_vm_readv || number == __NR_process_vm_writev);
    pid_t pid = va_arg(ap, pid_t);
    struct iovec *local = va_arg(ap, struct iovec *);
    int local_count = va_arg(ap, int);
    struct iovec *remote = va_arg(ap, struct iovec *);
    int remote_count = va_arg(ap, int);
    int flags = va_arg(ap, int);
    va_end(ap);
    int error;
    if (number == __NR_process_vm_readv) { vm_reads++; error = read_error; }
    else { vm_writes++; error = write_error; }
    if (error) { errno = error; return -1; }
    return __real_syscall(number, pid, local, local_count, remote, remote_count, flags);
}

static struct test_tracee *mock(const Tracee *tracee) { return (void *)tracee; }
word_t peek_reg(const Tracee *tracee, RegVersion version, Reg reg)
{ (void)version; return mock(tracee)->regs[reg]; }
void poke_reg(Tracee *tracee, Reg reg, word_t value) { mock(tracee)->regs[reg] = value; }
void set_sysnum(Tracee *tracee, Sysnum number) { mock(tracee)->sysnum = number; }
int register_chained_syscall(Tracee *tracee, Sysnum number, word_t a, word_t b,
                            word_t c, word_t d, word_t e, word_t f)
{
    struct test_tracee *t = mock(tracee);
    assert(number == PR_sendmsg && !t->queued);
    if (t->queue_error && t->queued_count >= t->queue_fail_after) return -t->queue_error;
    t->queued = true; t->queued_count++;
    t->args[0] = a; t->args[1] = b; t->args[2] = c;
    t->args[3] = d; t->args[4] = e; t->args[5] = f;
    assert(b == t->scratch);
    return 0;
}
void force_chain_final_result(Tracee *tracee, word_t result)
{ tracee->chain.force_final_result = true; tracee->chain.final_result = result; }
word_t alloc_mem(Tracee *tracee, ssize_t size)
{
    struct test_tracee *t = mock(tracee);
    assert(IS_IN_SYSENTER(tracee) && size > 0);
    t->allocations++; t->scratch_size += size;
    t->scratch = (word_t)talloc_size(tracee, size);
    return t->scratch;
}
int read_data(const Tracee *tracee, void *out, word_t from, word_t size)
{
    (void)tracee; (void)out; (void)from; (void)size;
    /* Controlled sendmmsg must never read protected inputs through ptrace. */
    forbidden_accesses++; return -EFAULT;
}
int write_data(Tracee *tracee, word_t to, const void *in, word_t size)
{
    struct test_tracee *t = mock(tracee);
    /* Original headers and msg_len must never use write_data. */
    assert(to >= t->scratch && to + size <= t->scratch + t->scratch_size);
    memcpy((void *)to, in, size); return 0;
}
int translate_path(Tracee *tracee, char out[PATH_MAX], int fd, const char *path, bool follow)
{
    (void)tracee; (void)fd; (void)follow;
    if (!strcmp(path, "/guest") || !strcmp(path, "guest")) {
        strcpy(out, host_target); return 0;
    }
    if (!strcmp(path, "denied")) return -EACCES;
    return -ENOENT;
}

static struct test_tracee *new_tracee(int fd, struct mmsghdr *vector, unsigned count)
{
    struct test_tracee *t = talloc_zero(NULL, struct test_tracee);
    assert(t);
    t->tracee.pid = getpid();
    t->tracee.ctx = talloc_new(t);
    t->regs[SYSARG_1] = fd; t->regs[SYSARG_2] = (word_t)vector;
    t->regs[SYSARG_3] = count; t->regs[SYSARG_4] = MSG_DONTWAIT | MSG_NOSIGNAL;
    t->sysnum = PR_sendmmsg;
    return t;
}
static struct sockaddr_un socket_address(const char *path)
{
    struct sockaddr_un result = { .sun_family = AF_UNIX };
    assert(strlen(path) < sizeof(result.sun_path));
    strcpy(result.sun_path, path); return result;
}
static unsigned receive_all(int fd)
{
    unsigned count = 0;
    char buffer[8];
    for (;;) {
        ssize_t size = recv(fd, buffer, sizeof(buffer), MSG_DONTWAIT);
        if (size < 0) { assert(errno == EAGAIN || errno == EWOULDBLOCK); break; }
        assert(size == 0 || (size == 1 && buffer[0] >= 'x' && buffer[0] <= 'z'));
        assert(count < sizeof(last_received));
        last_received[count++] = size ? buffer[0] : '\0';
    }
    return count;
}
static long native_send(int fd, struct mmsghdr *vector, unsigned count)
{
    int result = sendmmsg(fd, vector, count, MSG_DONTWAIT | MSG_NOSIGNAL);
    return result < 0 ? -errno : result;
}
static long lowered_send(struct test_tracee *t, struct mmsghdr *vector, unsigned count,
                         bool expected_lowering, int drain_fd, unsigned *drained)
{
    int status = translate_sendmmsg_start(&t->tracee, (word_t)vector, count);
    if (status < 0) return status;
    assert((status == 1) == expected_lowering);
    if (!status) {
        assert(t->sysnum == PR_sendmmsg && !t->allocations);
        assert(t->regs[SYSARG_2] == (word_t)vector && t->regs[SYSARG_3] == count);
        return native_send((int)t->regs[SYSARG_1], vector, count);
    }
    bool first = true;
    do {
        if (!first) {
            assert(t->queued); t->queued = false;
            for (unsigned i = 0; i < 6; i++) t->regs[SYSARG_1 + i] = t->args[i];
        }
        assert(t->sysnum == PR_sendmsg && t->regs[SYSARG_2] == t->scratch);
        assert(t->regs[SYSARG_3] == (MSG_DONTWAIT | MSG_NOSIGNAL));
        ssize_t result = sendmsg((int)t->regs[SYSARG_1], (void *)t->regs[SYSARG_2],
                                 (int)t->regs[SYSARG_3]);
        t->regs[SYSARG_RESULT] = result < 0 ? (word_t)-errno : (word_t)result;
        if (drain_fd >= 0) *drained += receive_all(drain_fd);
        t->tracee.status = 1;
        /* This is what the event loop does between syscall stops. */
        talloc_free(t->tracee.ctx); t->tracee.ctx = talloc_new(t);
        if (first) assert(translate_sendmmsg_finish(&t->tracee));
        else translate_sendmmsg_chained_exit(&t->tracee);
        first = false;
    } while (t->queued);
    if (t->tracee.chain.force_final_result)
        t->regs[SYSARG_RESULT] = t->tracee.chain.final_result;
    assert(t->allocations == 1 && t->scratch_size == sizeof(struct msghdr) + sizeof(struct sockaddr_un));
    assert(!translate_sendmmsg_finish(&t->tracee));
    translate_sendmmsg_chained_exit(&t->tracee);
    return (long)t->regs[SYSARG_RESULT];
}

enum scenario { WRITABLE, READONLY_VECTOR, SECOND_READONLY, LATER_NONE,
                LATER_STRADDLE, LENGTH_NONE, LENGTH_READONLY, BAD_IOV_FIRST,
                BAD_IOV_SECOND, BAD_NAME_SECOND, MISSING_SECOND, EMPTY_FIRST,
                NATIVE_FAST, NATIVE_LATER_NONE, NATIVE_READONLY, LATE_TRANSLATION,
                LATE_TRANSLATION_READONLY, THIRD_READONLY, THIRD_SEND_ERROR };
struct outcome { long result; unsigned received; unsigned lengths[3]; unsigned allocations; char datagrams[3]; };

static struct outcome exercise(enum scenario scenario, bool lowering, int sender, int receiver)
{
    char *pages = mmap(NULL, 3 * page_size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(pages != MAP_FAILED);
    struct mmsghdr *vector = (void *)pages;
    unsigned count = 3;
    size_t readable_bytes = 3 * sizeof(*vector);
    if (scenario == READONLY_VECTOR || scenario == NATIVE_READONLY) count = 2;
    if (scenario == THIRD_READONLY)
        vector = (void *)(pages + page_size - 2 * sizeof(*vector));
    if (scenario == SECOND_READONLY || scenario == LATER_NONE || scenario == NATIVE_LATER_NONE)
        vector = (void *)(pages + page_size - sizeof(*vector));
    if (scenario == LATER_STRADDLE)
        vector = (void *)(pages + page_size - sizeof(*vector) - (sizeof(struct msghdr) - sizeof(word_t)));
    if (scenario == LENGTH_NONE || scenario == LENGTH_READONLY)
        vector = (void *)(pages + page_size - sizeof(struct msghdr));
    if (scenario == LATER_NONE || scenario == NATIVE_LATER_NONE) {
        count = 2; readable_bytes = sizeof(*vector);
    } else if (scenario == LATER_STRADDLE) {
        count = 2; readable_bytes = sizeof(*vector) + sizeof(struct msghdr) - sizeof(word_t);
    } else if (scenario == LENGTH_NONE) {
        count = 2; readable_bytes = sizeof(struct msghdr);
    } else readable_bytes = count * sizeof(*vector);
    struct sockaddr_un host = socket_address(host_target), guest = socket_address("/guest");
    struct sockaddr_un absent = socket_address(lowering ? "missing" : "/tmp/neoproot-sendmmsg-absent/socket");
    char payloads[] = { 'x', 'y', 'z' };
    struct iovec iov[3];
    for (unsigned i = 0; i < 3; i++) iov[i] = (struct iovec){ .iov_base = payloads + i, .iov_len = 1 };
    bool fast = scenario == NATIVE_FAST || scenario == NATIVE_LATER_NONE || scenario == NATIVE_READONLY;
    for (unsigned i = 0; i < count; i++)
        vector[i] = (struct mmsghdr){ .msg_hdr = { .msg_name = lowering && !fast ? &guest : &host,
            .msg_namelen = sizeof(host), .msg_iov = iov + i, .msg_iovlen = 1, .msg_flags = 73 },
            .msg_len = sentinel };
    if (scenario == LATE_TRANSLATION || scenario == LATE_TRANSLATION_READONLY)
        vector[0].msg_hdr.msg_name = &host;
    if (scenario == THIRD_SEND_ERROR) vector[2].msg_hdr.msg_iov = (void *)1;
    if (scenario == BAD_IOV_FIRST) vector[0].msg_hdr.msg_iov = (void *)1;
    if (scenario == BAD_IOV_SECOND) vector[1].msg_hdr.msg_iov = (void *)1;
    if (scenario == BAD_NAME_SECOND) vector[1].msg_hdr.msg_name = (void *)1;
    if (scenario == MISSING_SECOND) vector[1].msg_hdr.msg_name = &absent;
    if (scenario == EMPTY_FIRST) vector[0].msg_hdr.msg_iovlen = 0;
    uint8_t original[3 * sizeof(*vector)];
    memcpy(original, vector, readable_bytes);
    if (scenario == READONLY_VECTOR || scenario == NATIVE_READONLY || scenario == LATE_TRANSLATION_READONLY)
        assert(!mprotect(pages, page_size, PROT_READ));
    if (scenario == SECOND_READONLY || scenario == LENGTH_READONLY || scenario == THIRD_READONLY)
        assert(!mprotect(pages + page_size, page_size, PROT_READ));
    if (scenario == LATER_NONE || scenario == LATER_STRADDLE || scenario == LENGTH_NONE || scenario == NATIVE_LATER_NONE)
        assert(!mprotect(pages + page_size, page_size, PROT_NONE));
    assert(!receive_all(receiver));
    struct test_tracee *t = lowering ? new_tracee(sender, vector, count) : NULL;
    struct outcome outcome = { .result = lowering ? lowered_send(t, vector, count, !fast, -1, NULL)
                                                  : native_send(sender, vector, count) };
    outcome.received = receive_all(receiver);
    assert(outcome.received <= sizeof(outcome.datagrams));
    memcpy(outcome.datagrams, last_received, outcome.received);
    if (t) { outcome.allocations = t->allocations; talloc_free(t); }
    for (unsigned i = 0; i < count; i++) {
        size_t offset = i * sizeof(*vector), length_offset = offset + offsetof(struct mmsghdr, msg_len);
        if (offset + sizeof(struct msghdr) <= readable_bytes)
            assert(!memcmp((char *)vector + offset, original + offset, sizeof(struct msghdr)));
        if (length_offset + sizeof(unsigned) <= readable_bytes)
            memcpy(&outcome.lengths[i], (char *)vector + length_offset, sizeof(unsigned));
    }
    assert(!strcmp(guest.sun_path, "/guest") && !strcmp(host.sun_path, host_target));
    assert(!munmap(pages, 3 * page_size));
    return outcome;
}

static void compare_scenarios(int sender, int receiver)
{
    const char *names[] = { "writable", "readonly vector", "readonly later msg_len",
        "later inaccessible header", "later partial header", "inaccessible first msg_len",
        "readonly first msg_len", "first send error", "later send error", "later bad name",
        "later translation error", "zero byte message", "native fast path",
        "native later inaccessible header", "native readonly vector", "translation after native prefix",
        "readonly native prefix before translation", "readonly third msg_len", "third send error" };
    for (unsigned i = 0; i < sizeof(names) / sizeof(*names); i++) {
        struct outcome native = exercise(i, false, sender, receiver);
        struct outcome lowered = exercise(i, true, sender, receiver);
        if (native.result != lowered.result || native.received != lowered.received ||
            memcmp(native.lengths, lowered.lengths, sizeof(native.lengths)) ||
            memcmp(native.datagrams, lowered.datagrams, sizeof(native.datagrams))) {
            fprintf(stderr, "%s: native result=%ld sends=%u, lowered result=%ld sends=%u\n",
                names[i], native.result, native.received, lowered.result, lowered.received);
            abort();
        }
        if (i == READONLY_VECTOR || i == LENGTH_NONE || i == LENGTH_READONLY || i == LATE_TRANSLATION_READONLY) {
            assert(native.result == -EFAULT && native.received == 1);
            assert(lowered.allocations == 1);
        }
        if (i == SECOND_READONLY) assert(native.result == 1 && native.received == 2);
        if (i == THIRD_READONLY) assert(native.result == 2 && native.received == 3);
        if (i == THIRD_SEND_ERROR) assert(native.result == 2 && native.received == 2);
        if (i == LATER_NONE || i == LATER_STRADDLE || i == BAD_IOV_SECOND || i == BAD_NAME_SECOND || i == MISSING_SECOND)
            assert(native.result == 1 && native.received == 1);
        printf("PASS native comparison: %s (result=%ld, datagrams=%u)\n", names[i], native.result, native.received);
    }
}

static void stress_scratch(int sender, int receiver)
{
    struct sockaddr_un guest = socket_address("/guest");
    struct iovec iov = { .iov_base = (void *)"x", .iov_len = 1 };
    struct mmsghdr *vector = calloc(1025, sizeof(*vector));
    assert(vector);
    for (unsigned i = 0; i < 1024; i++) vector[i].msg_hdr = (struct msghdr){
        .msg_name = &guest, .msg_namelen = sizeof(guest), .msg_iov = &iov, .msg_iovlen = 1 };
    vector[1024].msg_hdr.msg_name = (void *)1;
    struct test_tracee *t = new_tracee(sender, vector, 1025);
    unsigned drained = 0;
    assert(lowered_send(t, vector, 1025, true, receiver, &drained) == 1024);
    assert(drained == 1024 && t->queued_count == 1023 && t->allocations == 1);
    for (unsigned i = 0; i < 1024; i++) assert(vector[i].msg_len == 1 && vector[i].msg_hdr.msg_name == &guest);
    assert(vector[1024].msg_len == 0);
    talloc_free(t); free(vector);
    puts("PASS 1024 messages: one fixed scratch, count clamp, event-context destruction");
}

static void failure_and_lifetime_tests(int sender, int receiver)
{
    struct sockaddr_un guest = socket_address("/guest");
    struct iovec iov = { .iov_base = (void *)"x", .iov_len = 1 };
    struct mmsghdr vector[3];
    for (unsigned i = 0; i < 3; i++) vector[i] = (struct mmsghdr){ .msg_hdr = {
        .msg_name = &guest, .msg_namelen = sizeof(guest), .msg_iov = &iov, .msg_iovlen = 1 }, .msg_len = sentinel };
    struct test_tracee *t = new_tracee(sender, vector, 3);
    read_error = ENOSYS;
    assert(lowered_send(t, vector, 3, true, -1, NULL) == -ENOSYS && !receive_all(receiver));
    read_error = 0; talloc_free(t);
    const int errors[] = { ENOSYS, EPERM };
    for (unsigned i = 0; i < sizeof(errors) / sizeof(*errors); i++) {
        t = new_tracee(sender, vector, 3); write_error = errors[i];
        assert(lowered_send(t, vector, 3, true, -1, NULL) == -errors[i]);
        assert(receive_all(receiver) == 1 && !t->queued_count && vector[0].msg_len == sentinel);
        write_error = 0; talloc_free(t);
    }
    t = new_tracee(sender, vector, 3); t->queue_error = ENOMEM;
    assert(lowered_send(t, vector, 3, true, -1, NULL) == 1);
    assert(receive_all(receiver) == 1 && !t->queued_count && vector[0].msg_len == 1);
    talloc_free(t);
    t = new_tracee(sender, vector, 3); t->queue_error = ENOMEM; t->queue_fail_after = 1;
    assert(lowered_send(t, vector, 3, true, -1, NULL) == 2);
    assert(receive_all(receiver) == 2 && t->queued_count == 1);
    talloc_free(t);
    t = new_tracee(-1, vector, 3);
    assert(lowered_send(t, vector, 3, true, -1, NULL) == -EBADF && !receive_all(receiver));
    talloc_free(t);
    /* Free an owner with an unfinished batch.  Its destructor must unlink
     * pending state so the next lookup cannot walk freed allocations. */
    t = new_tracee(sender, vector, 3);
    assert(translate_sendmmsg_start(&t->tracee, (word_t)vector, 3) == 1);
    talloc_free(t);
    t = new_tracee(sender, vector, 3);
    assert(lowered_send(t, vector, 3, true, -1, NULL) == 3 && receive_all(receiver) == 3);
    talloc_free(t);
    t = new_tracee(sender, (void *)1, 2);
    assert(lowered_send(t, (void *)1, 2, false, -1, NULL) == -EFAULT && !receive_all(receiver));
    talloc_free(t);
    t = new_tracee(sender, vector, 0);
    assert(lowered_send(t, vector, 0, false, -1, NULL) == 0 && !receive_all(receiver));
    talloc_free(t);
    assert(!forbidden_accesses && vm_reads && vm_writes);
    puts("PASS unavailable process_vm, queue failure, EBADF, and Tracee cleanup");
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    page_size = sysconf(_SC_PAGESIZE); assert(page_size > 0);
    assert(sizeof(struct msghdr) == 7 * sizeof(word_t) && sizeof(struct mmsghdr) == 8 * sizeof(word_t));
    char directory[] = "/tmp/neoproot-sendmmsg.XXXXXX";
    assert(mkdtemp(directory));
    int directory_fd = open(".", O_RDONLY | O_DIRECTORY);
    assert(directory_fd >= 0 && !chdir(directory));
    int socket_directory_fd = open(".", O_RDONLY | O_DIRECTORY);
    assert(socket_directory_fd >= 0);
    snprintf(host_target, sizeof(host_target), "/proc/self/fd/%d/socket", socket_directory_fd);
    int receiver = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    int sender = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    assert(receiver >= 0 && sender >= 0);
    struct sockaddr_un address = socket_address(host_target);
    assert(!bind(receiver, (void *)&address, sizeof(address)));
    compare_scenarios(sender, receiver);
    stress_scratch(sender, receiver);
    failure_and_lifetime_tests(sender, receiver);
    close(sender); close(receiver); assert(!unlink(host_target));
    close(socket_directory_fd);
    assert(!fchdir(directory_fd)); close(directory_fd); assert(!rmdir(directory));
    puts("PASS actual-source ordered sendmmsg regressions; no neoproot/UML execution");
    return 0;
}
