/* Compile the actual Android allocator with an ashmem header shim and inject
 * syscall failures. The successful memfd allocation uses the running kernel. */
#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
static bool fail_create, fail_resize, fail_ashmem, fail_ioctl;
static int ashmem_opens, closed_fds, ioctls;
static long test_syscall(long nr, ...) {
    assert(nr == SYS_memfd_create);
    va_list ap; va_start(ap, nr); const char *name = va_arg(ap, const char *); int flags = va_arg(ap, int); va_end(ap);
    assert(strcmp(name, "sysvshm_0x2A") == 0 && flags == 0);
    if (fail_create) { errno = ENOSYS; return -1; }
    return syscall(nr, name, flags);
}
static int test_ftruncate(int fd, off_t size) {
    if (fail_resize) { errno = EINVAL; return -1; }
    return ftruncate(fd, size);
}
static int test_open(const char *name, int flags, ...) {
    assert(strcmp(name, "/dev/ashmem") == 0 && flags == O_RDWR); ashmem_opens++;
    if (fail_ashmem) { errno = EACCES; return -1; }
    return open("/dev/null", O_RDWR);
}
static int test_close(int fd) { closed_fds++; return close(fd); }
static int test_ioctl(int fd, unsigned long request, ...) {
    (void)fd; (void)request; ioctls++;
    if (fail_ioctl) { errno = EINVAL; return -1; }
    return 0;
}
#define __ANDROID__ 1
#define syscall test_syscall
#define ftruncate test_ftruncate
#define open test_open
#define close test_close
#define ioctl test_ioctl
#include "../src/extension/sysvipc/sysvipc_shm.c"
#undef syscall
#undef ftruncate
#undef open
#undef close
#undef ioctl

static void reset_faults(void) { fail_create = fail_resize = fail_ashmem = fail_ioctl = false; ashmem_opens = closed_fds = ioctls = 0; }
int main(void) {
    int fd; struct stat st;
    reset_faults(); fd = sysvipc_shm_do_allocate(8192, 42);
    assert(fd >= 0 && fstat(fd, &st) == 0 && st.st_size == 8192 && ashmem_opens == 0); close(fd);
    reset_faults(); fail_create = true; fd = sysvipc_shm_do_allocate(8192, 42);
    assert(fd >= 0 && ashmem_opens == 1 && ioctls == 2 && closed_fds == 0); close(fd);
    reset_faults(); fail_resize = true; fd = sysvipc_shm_do_allocate(8192, 42);
    assert(fd >= 0 && ashmem_opens == 1 && ioctls == 2 && closed_fds == 1); close(fd);
    reset_faults(); fail_create = fail_ashmem = true;
    assert(sysvipc_shm_do_allocate(8192, 42) == -ENOSPC && ashmem_opens == 1);
    reset_faults(); fail_create = fail_ioctl = true;
    assert(sysvipc_shm_do_allocate(8192, 42) == -ENOSPC && closed_fds == 1);
    puts("PASS Android SysV shm memfd and ashmem fallback branches");
    return 0;
}
