/* Host kernel integration for the actual raw-auxv correction helper.
 * This probe never starts neoproot, PRoot, QEMU, or UML. */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/auxvec.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>
#include "execve/auxv.h"

#ifndef PR_GET_AUXV
#define PR_GET_AUXV 0x41555856
#endif

static const char guest_name[] = "/guest/program";

static size_t execfn_offset(const unsigned char *buffer, size_t size)
{
    for (size_t offset = 0; offset + 2 * sizeof(word_t) <= size;
         offset += 2 * sizeof(word_t)) {
        word_t type;
        memcpy(&type, buffer + offset, sizeof(type));
        if (type == AT_NULL)
            break;
        if (type == AT_EXECFN)
            return offset;
    }
    assert(!"AT_EXECFN missing from the host kernel auxiliary vector");
    return 0;
}

static void check_copy(const unsigned char *source, size_t size, size_t offset)
{
    unsigned char buffer[4098], expected[4098];
    assert(size <= sizeof(buffer) - 2);
    Tracee tracee = { .execfn_addr = (word_t)guest_name };
    memset(buffer, 0xa5, sizeof(buffer));
    memcpy(buffer + 1, source, size);
    memcpy(expected, buffer, sizeof(buffer));
    bool complete = size >= offset + 2 * sizeof(word_t);
    if (complete)
        memcpy(expected + 1 + offset + sizeof(word_t),
               &tracee.execfn_addr, sizeof(word_t));
    assert(fix_up_execfn(&tracee, buffer + 1, size) == complete);
    assert(memcmp(buffer, expected, sizeof(buffer)) == 0);
    if (complete) {
        word_t value;
        memcpy(&value, buffer + 1 + offset + sizeof(word_t), sizeof(value));
        assert(strcmp((const char *)value, guest_name) == 0);
    }
}

static void check_proc(void)
{
    unsigned char vector[4096];
    size_t total = 0;
    int fd = open("/proc/self/auxv", O_RDONLY);
    assert(fd >= 0);
    for (;;) {
        ssize_t size = read(fd, vector + total, sizeof(vector) - total);
        if (size < 0 && errno == EINTR)
            continue;
        assert(size >= 0);
        if (size == 0)
            break;
        total += (size_t)size;
        assert(total < sizeof(vector));
    }
    assert(close(fd) == 0);
    size_t offset = execfn_offset(vector, total);
    word_t value;
    memcpy(&value, vector + offset + sizeof(word_t), sizeof(value));
    /* An existing outer tracer may expose its saved loader vector after
     * fork.  The correction must work for that input too; do not require
     * the host procfs copy to equal libc's already-corrected stack vector. */
    assert(value != 0);
    assert(getauxval(AT_EXECFN) != 0);
    for (size_t size = 0; size <= total; size++)
        check_copy(vector, size, offset);
}

static void check_prctl(void)
{
    unsigned char vector[4096];
    errno = 0;
    int total = prctl(PR_GET_AUXV, vector, sizeof(vector), 0UL, 0UL);
    if (total < 0 && errno == EINVAL) {
        puts("SKIP: host kernel does not support PR_GET_AUXV");
        return;
    }
    assert(total > 0 && (size_t)total < sizeof(vector));
    size_t offset = execfn_offset(vector, (size_t)total);
    for (size_t size = 0; size <= (size_t)total; size++) {
        memset(vector, 0xa5, sizeof(vector));
        int result = prctl(PR_GET_AUXV, vector, size, 0UL, 0UL);
        assert(result == total); /* The result is not the copied byte count. */
        check_copy(vector, size, offset);
    }
    puts("proot-me host PR_GET_AUXV integration passed");
}

int main(void)
{
    check_proc();
    check_prctl();
    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        check_proc();
        _exit(0);
    }
    int status;
    assert(waitpid(pid, &status, 0) == pid);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    puts("proot-me host procfs and fork integration passed");
    return 0;
}
