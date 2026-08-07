#include <linux/limits.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>

#include "arch.h"
#include "tracee/tracee.h"
#include "tracee/mem.h"
#include "tracee/abi.h"
#include "build.h"

#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define LIKELY(x)  __builtin_expect(!!(x), 1)

static inline char *native_strdup(const char *s)
{
    size_t l = strlen(s) + 1;
    char *d = talloc_size(NULL, l);
    if (LIKELY(d))
        memcpy(d, s, l);
    return d;
}

struct mixed_pointer {
    word_t remote;
    void  *local;
};

#include "execve/aoxp.h"

int read_xpointee_as_object(ArrayOfXPointers *array, size_t index, void **local_pointer)
{
    if (UNLIKELY(index >= array->length))
        return -ERANGE;

    *local_pointer = array->_xpointers[index].local;
    if (LIKELY(*local_pointer))
        return 0;

    word_t raddr = array->_xpointers[index].remote;
    if (UNLIKELY(!raddr))
        return 0;

    int size = sizeof_xpointee(array, index);
    if (UNLIKELY(size < 0))
        return size;

    void *buf = talloc_size(array, size);
    if (UNLIKELY(!buf))
        return -ENOMEM;

    int st = read_data(TRACEE(array), buf, raddr, size);
    if (UNLIKELY(st < 0)) {
        talloc_free(buf);
        return st;
    }

    array->_xpointers[index].local = *local_pointer = buf;
    return 0;
}

int read_xpointee_as_string(ArrayOfXPointers *array, size_t index, char **local_pointer)
{
    if (UNLIKELY(index >= array->length))
        return -ERANGE;

    *local_pointer = array->_xpointers[index].local;
    if (LIKELY(*local_pointer))
        return 0;

    word_t raddr = array->_xpointers[index].remote;
    if (UNLIKELY(!raddr))
        return 0;

    char tmp[ARG_MAX];
    int st = read_string(TRACEE(array), tmp, raddr, ARG_MAX);
    if (UNLIKELY(st < 0))
        return st;
    if (UNLIKELY(st >= ARG_MAX))
        return -ENAMETOOLONG;

    char *s = native_strdup(tmp);
    if (UNLIKELY(!s))
        return -ENOMEM;

    array->_xpointers[index].local = *local_pointer = s;
    return 0;
}

int sizeof_xpointee_as_string(ArrayOfXPointers *array, size_t index)
{
    char *s;
    int ret = read_xpointee_as_string(array, index, &s);
    if (UNLIKELY(ret < 0))
        return ret;
    return s ? (int)(strlen(s) + 1) : 0;
}

int compare_xpointee_generic(ArrayOfXPointers *array, size_t index, const void *ref)
{
    if (UNLIKELY(index >= array->length))
        return -ERANGE;

    void *obj;
    int ret = read_xpointee(array, index, &obj);
    if (UNLIKELY(ret < 0))
        return ret;

    if (!obj && !ref) return 1;
    if (!obj || !ref) return 0;

    ssize_t sz = sizeof_xpointee(array, index);
    if (UNLIKELY(sz < 0))
        return sz;

    return memcmp(obj, ref, sz) == 0;
}

int find_xpointee(ArrayOfXPointers *array, const void *ref)
{
    for (size_t i = 0; LIKELY(i < array->length); i++) {
        int r = compare_xpointee(array, i, ref);
        if (UNLIKELY(r < 0))
            return r;
        if (r)
            return i;
    }
    return -ENOENT;
}

int write_xpointee_as_string(ArrayOfXPointers *array, size_t index, const char *s)
{
    if (UNLIKELY(index >= array->length))
        return -ERANGE;

    char *dup = native_strdup(s);
    if (UNLIKELY(!dup))
        return -ENOMEM;

    array->_xpointers[index].local = dup;
    return 0;
}

int write_xpointees(ArrayOfXPointers *array, size_t index, size_t n, ...)
{
    va_list ap;
    va_start(ap, n);

    int ret = 0;
    for (size_t i = 0; LIKELY(i < n); i++) {
        const char *s = va_arg(ap, const char *);
        ret = write_xpointee(array, index + i, s);
        if (UNLIKELY(ret < 0))
            break;
    }

    va_end(ap);
    return ret;
}

int resize_array_of_xpointers(ArrayOfXPointers *array, size_t index, ssize_t delta)
{
    if (delta == 0)
        return 0;

    size_t old_len = array->length;
    if (index > old_len)
        index = old_len;

    size_t new_len = old_len + delta;
    size_t move    = old_len - index;

    XPointer *tmp = talloc_realloc(array, array->_xpointers, XPointer, new_len);
    if (UNLIKELY(!tmp))
        return -ENOMEM;
    array->_xpointers = tmp;

    if (delta > 0) {
        memmove(tmp + index + delta, tmp + index, move * sizeof(XPointer));
        memset(tmp + index, 0, delta * sizeof(XPointer));
    } else {
        memmove(tmp + index + delta, tmp + index, move * sizeof(XPointer));
    }

    array->length = new_len;
    return 0;
}

int fetch_array_of_xpointers(Tracee *tracee, ArrayOfXPointers **out, Reg reg, size_t limit)
{
    if (UNLIKELY(!out))
        return -EINVAL;

    ArrayOfXPointers *a = talloc_zero(tracee->ctx, ArrayOfXPointers);
    if (UNLIKELY(!a))
        return -ENOMEM;
    *out = a;

    word_t addr = peek_reg(tracee, CURRENT, reg);
    size_t i = 0;
    word_t ptr;

    do {
        XPointer *tmp = talloc_realloc(a, a->_xpointers, XPointer, i+1);
        if (UNLIKELY(!tmp))
            return -ENOMEM;
        a->_xpointers = tmp;

        ptr = peek_word(tracee, addr + i * sizeof(word_t));
        if (UNLIKELY(errno))
            return -errno;

        a->_xpointers[i].remote = ptr;
        a->_xpointers[i].local  = NULL;
        i++;
    } while ((limit && i < limit) || (!limit && ptr));

    a->length = i;

    a->read_xpointee    = (read_xpointee_t)read_xpointee_as_string;
    a->sizeof_xpointee  = sizeof_xpointee_as_string;
    a->write_xpointee   = (write_xpointee_t)write_xpointee_as_string;
    a->compare_xpointee = compare_xpointee_generic;

    return 0;
}

int push_array_of_xpointers(ArrayOfXPointers *a, Reg reg)
{
    if (UNLIKELY(!a))
        return 0;

    Tracee *tracee = TRACEE(a);
    size_t nr_ptr = a->length;
    size_t word_sz = sizeof(word_t);

    word_t *pod = talloc_zero_size(tracee->ctx, word_sz * nr_ptr);
    if (UNLIKELY(!pod))
        return -ENOMEM;

    struct iovec *vec = talloc_zero_array(tracee->ctx, struct iovec, nr_ptr + 1);
    if (UNLIKELY(!vec))
        return -ENOMEM;

    size_t total = word_sz * nr_ptr;
    vec[0].iov_base = pod;
    vec[0].iov_len  = total;
    size_t cnt = 1;

    for (size_t i = 0; LIKELY(i < nr_ptr); i++) {
        void *loc = a->_xpointers[i].local;
        if (UNLIKELY(!loc))
            continue;

        ssize_t sz = sizeof_xpointee(a, i);
        if (UNLIKELY(sz < 0))
            return sz;

        vec[cnt].iov_base = loc;
        vec[cnt].iov_len  = sz;
        total += sz;
        cnt++;
    }

    if (cnt == 1)
        return 0;

    word_t base = alloc_mem(tracee, total);
    if (UNLIKELY(!base))
        return -E2BIG;

    /* 每个 local 字符串在 base 中的实际偏移是"pod 区 + 前面所有字符串长度"
     * 的累加；旧代码固定指向最后一个字符串（total - vec[cnt-1].iov_len），
     * 导致 argv 所有指针都指向同一字符串（shebang 展开后 argv 全变成脚本
     * 路径，env/node 的 ld.so 误判 argv[0] 为脚本而反复 exec，死循环）。 */
    word_t off = word_sz * nr_ptr;
    for (size_t i = 0; LIKELY(i < nr_ptr); i++) {
        if (a->_xpointers[i].local) {
            a->_xpointers[i].remote = base + off;
            off += sizeof_xpointee(a, i);
        }
        pod[i] = a->_xpointers[i].remote;
    }

    int ret = writev_data(tracee, base, vec, cnt);
    if (UNLIKELY(ret < 0))
        return ret;

    poke_reg(tracee, reg, base);
    return 0;
}
