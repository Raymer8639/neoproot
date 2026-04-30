#ifndef RLIMIT_H
#define RLIMIT_H

#include <stdbool.h>
#include "tracee/tracee.h"

extern int translate_setrlimit_exit(const Tracee *tracee, bool is_prlimit);

#endif /* RLIMIT_H */
