#ifndef AOXP_H
#define AOXP_H

#include <stdbool.h>

#include "tracee/reg.h"
#include "arch.h"

typedef struct array_of_xpointers ArrayOfXPointers;
typedef int (*read_xpointee_t)(ArrayOfXPointers *array, size_t index, void **object);
typedef int (*write_xpointee_t)(ArrayOfXPointers *array, size_t index, const void *object);
typedef int (*compare_xpointee_t)(ArrayOfXPointers *array, size_t index, const void *reference);
typedef int (*sizeof_xpointee_t)(ArrayOfXPointers *array, size_t index);

typedef struct mixed_pointer XPointer;
struct array_of_xpointers {
	XPointer *_xpointers;
	size_t length;

	read_xpointee_t    read_xpointee;
	write_xpointee_t   write_xpointee;
	compare_xpointee_t compare_xpointee;
	sizeof_xpointee_t  sizeof_xpointee;
};

static inline int read_xpointee(ArrayOfXPointers *array, size_t index, void **object)
{
	return array->read_xpointee(array, index, object);
}

static inline int write_xpointee(ArrayOfXPointers *array, size_t index, const void *object)
{
	return array->write_xpointee(array, index, object);
}

static inline int compare_xpointee(ArrayOfXPointers *array, size_t index, const void *reference)
{
	return array->compare_xpointee(array, index, reference);
}

static inline int sizeof_xpointee(ArrayOfXPointers *array, size_t index)
{
	return array->sizeof_xpointee(array, index);
}

extern int find_xpointee(ArrayOfXPointers *array, const void *reference);
extern int resize_array_of_xpointers(ArrayOfXPointers *array, size_t index, ssize_t nb_delta_entries);
extern int fetch_array_of_xpointers(Tracee *tracee, ArrayOfXPointers **array, Reg reg, size_t nb_entries);
extern int push_array_of_xpointers(ArrayOfXPointers *array, Reg reg);

extern int read_xpointee_as_object(ArrayOfXPointers *array, size_t index, void **object);
extern int read_xpointee_as_string(ArrayOfXPointers *array, size_t index, char **string);
extern int write_xpointee_as_string(ArrayOfXPointers *array, size_t index, const char *string);
extern int write_xpointees(ArrayOfXPointers *array, size_t index, size_t nb_xpointees, ...);
extern int compare_xpointee_generic(ArrayOfXPointers *array, size_t index, const void *reference);
extern int sizeof_xpointee_as_string(ArrayOfXPointers *array, size_t index);

#endif /* AOXP_H */
