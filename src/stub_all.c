#include <sys/types.h>
#include <stddef.h>
#include <errno.h>

// 实现__assert2，解决未定义引用
void __assert2(const char *file, int line, const char *func, const char *expr) {}

// 实现__errno，映射到标准errno
int *__errno(void) { static int e; return &e; }

// Android loader符号缺失
const char _binary_loader_exe_start[] = {};
const char _binary_loader_exe_end[] = {};

// pokedata_workaround符号缺失
const ssize_t offset_to_pokedata_workaround = 0;

// ashmem_memfd回调缺失
void ashmem_memfd_callback(void) {}
