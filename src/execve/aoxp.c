#include <linux/limits.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <talloc.h>

#include "arch.h"
#include "tracee/tracee.h"
#include "tracee/mem.h"
#include "tracee/abi.h"
#include "build.h"

struct mixed_pointer {
	word_t remote;
	void  *local;
};

#include "execve/aoxp.h"

int read_xpointee_as_object(ArrayOfXPointers *array, size_t index, void **local_pointer)
{
	int status;
	int size;

	if (index >= array->length) {
		*local_pointer = NULL;
		return -ERANGE;
	}

	if (array->_xpointers[index].local != NULL)
		goto end;

	if (array->_xpointers[index].remote == 0) {
		array->_xpointers[index].local = NULL;
		goto end;
	}

	size = sizeof_xpointee(array, index);
	if (size < 0)
		return size;

	array->_xpointers[index].local = talloc_size(array, size);
	if (!array->_xpointers[index].local)
		return -ENOMEM;

	status = read_data(TRACEE(array),
		array->_xpointers[index].local,
		array->_xpointers[index].remote,
		size);
	if (status < 0) {
		array->_xpointers[index].local = NULL;
		return status;
	}

end:
	*local_pointer = array->_xpointers[index].local;
	return 0;
}

int read_xpointee_as_string(ArrayOfXPointers *array, size_t index, char **local_pointer)
{
	char tmp[ARG_MAX];
	int status;

	if (index >= array->length) {
		*local_pointer = NULL;
		return -ERANGE;
	}

	if (array->_xpointers[index].local != NULL)
		goto end;

	if (array->_xpointers[index].remote == 0) {
		array->_xpointers[index].local = NULL;
		goto end;
	}

	status = read_string(TRACEE(array), tmp, array->_xpointers[index].remote, ARG_MAX);
	if (status < 0)
		return status;
	if (status >= ARG_MAX)
		return -ENAMETOOLONG;

	array->_xpointers[index].local = talloc_strdup(array, tmp);
	if (!array->_xpointers[index].local)
		return -ENOMEM;

end:
	*local_pointer = array->_xpointers[index].local;
	return 0;
}

int sizeof_xpointee_as_string(ArrayOfXPointers *array, size_t index)
{
	char *s;
	int ret;

	if (index >= array->length)
		return -ERANGE;

	ret = read_xpointee_as_string(array, index, &s);
	if (ret < 0)
		return ret;

	return s ? strlen(s) + 1 : 0;
}

int compare_xpointee_generic(ArrayOfXPointers *array, size_t index, const void *ref)
{
	void *obj;
	int ret;
	ssize_t sz;

	if (index >= array->length)
		return -ERANGE;

	ret = read_xpointee(array, index, &obj);
	if (ret < 0)
		return ret;

	if (obj == NULL && ref == NULL) return 1;
	if (obj == NULL || ref == NULL) return 0;

	sz = sizeof_xpointee(array, index);
	if (sz < 0) return sz;

	return memcmp(obj, ref, sz) == 0 ? 1 : 0;
}

int find_xpointee(ArrayOfXPointers *array, const void *ref)
{
	size_t i;

	for (i = 0; i < array->length; i++) {
		int ret = compare_xpointee(array, i, ref);
		if (ret < 0) return ret;
		if (ret != 0) return i;
	}

	return -ENOENT;
}

int write_xpointee_as_string(ArrayOfXPointers *array, size_t index, const char *s)
{
	if (index >= array->length)
		return -ERANGE;

	array->_xpointers[index].local = talloc_strdup(array, s);
	return array->_xpointers[index].local ? 0 : -ENOMEM;
}

int write_xpointees(ArrayOfXPointers *array, size_t index, size_t n, ...)
{
	va_list ap;
	int ret = 0;
	size_t i;

	va_start(ap, n);
	for (i = 0; i < n; i++) {
		const char *s = va_arg(ap, const char*);
		ret = write_xpointee(array, index + i, s);
		if (ret < 0) break;
	}
	va_end(ap);

	return ret;
}

int resize_array_of_xpointers(ArrayOfXPointers *array, size_t index, ssize_t delta)
{
	size_t new_len;
	size_t move;
	void *tmp;

	if (delta == 0) return 0;
	if (index > array->length) index = array->length;

	new_len = array->length + delta;
	move    = array->length - index;

	if (delta > 0) {
		tmp = talloc_realloc(array, array->_xpointers, XPointer, new_len);
		if (!tmp) return -ENOMEM;
		array->_xpointers = tmp;

		memmove(array->_xpointers + index + delta,
			array->_xpointers + index,
			move * sizeof(XPointer));
		memset(array->_xpointers + index, 0, delta * sizeof(XPointer));
	} else {
		if (index >= array->length) return -ERANGE;

		memmove(array->_xpointers + index + delta,
			array->_xpointers + index,
			move * sizeof(XPointer));

		tmp = talloc_realloc(array, array->_xpointers, XPointer, new_len);
		if (!tmp) return -ENOMEM;
		array->_xpointers = tmp;
	}

	array->length = new_len;
	return 0;
}

int fetch_array_of_xpointers(Tracee *tracee, ArrayOfXPointers **out, Reg reg, size_t limit)
{
	word_t addr;
	word_t ptr = 1;
	size_t i;
	ArrayOfXPointers *a;

	if (!out) return -EINVAL;

	*out = talloc_zero(tracee->ctx, ArrayOfXPointers);
	if (!*out) return -ENOMEM;
	a = *out;

	addr = peek_reg(tracee, CURRENT, reg);

	for (i = 0; (limit && i < limit) || (!limit && ptr); i++) {
		void *tmp = talloc_realloc(a, a->_xpointers, XPointer, i + 1);
		if (!tmp) return -ENOMEM;
		a->_xpointers = tmp;

		ptr = peek_word(tracee, addr + i * sizeof_word(tracee));
		if (errno) return -errno;

		a->_xpointers[i].remote = ptr;
		a->_xpointers[i].local  = NULL;
	}

	a->length = i;

	a->read_xpointee    = (read_xpointee_t)read_xpointee_as_string;
	a->sizeof_xpointee  = sizeof_xpointee_as_string;
	a->write_xpointee   = (write_xpointee_t)write_xpointee_as_string;
	a->compare_xpointee = compare_xpointee_generic;

	return 0;
}

int push_array_of_xpointers(ArrayOfXPointers *a, Reg reg)
{
	Tracee *tracee;
	struct iovec *vec;
	size_t cnt;
	size_t total;
	word_t *pod;
	word_t ptr;
	int ret;
	size_t i;

	if (!a) return 0;
	tracee = TRACEE(a);

	pod = talloc_zero_size(tracee->ctx, a->length * sizeof_word(tracee));
	if (!pod) return -ENOMEM;

	vec = talloc_zero_array(tracee->ctx, struct iovec, a->length + 1);
	if (!vec) return -ENOMEM;

	total = a->length * sizeof_word(tracee);
	vec[0].iov_base = pod;
	vec[0].iov_len  = total;
	cnt = 1;

	for (i = 0; i < a->length; i++) {
		ssize_t sz;

		if (!a->_xpointers[i].local) continue;

		a->_xpointers[i].remote = total;
		sz = sizeof_xpointee(a, i);
		if (sz < 0) return sz;

		total += sz;
		vec[cnt].iov_base = a->_xpointers[i].local;
		vec[cnt].iov_len  = sz;
		cnt++;
	}

	if (cnt == 1) return 0;

	ptr = alloc_mem(tracee, total);
	if (!ptr) return -E2BIG;

	for (i = 0; i < a->length; i++) {
		if (a->_xpointers[i].local)
			a->_xpointers[i].remote += ptr;

		if (is_32on64_mode(tracee))
			((uint32_t*)pod)[i] = a->_xpointers[i].remote;
		else
			pod[i] = a->_xpointers[i].remote;
	}

	ret = writev_data(tracee, ptr, vec, cnt);
	if (ret < 0) return ret;

	poke_reg(tracee, reg, ptr);
	return 0;
}
