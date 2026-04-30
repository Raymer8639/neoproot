#ifndef NOTE_H
#define NOTE_H

#include "tracee/tracee.h"
#include "attribute.h"

/* Origin of a notice */
typedef enum {
    SYSTEM,
    INTERNAL,
    USER,
    TALLOC,
} Origin;

/* Severity of a notice */
typedef enum {
    ERROR,
    WARNING,
    INFO,
} Severity;

/* Verbose macro (unchanged) */
#define VERBOSE(tracee, level, message, args...) do {          \
        if (tracee == NULL || tracee->verbose >= (level))      \
            note(tracee, INFO, INTERNAL, (message), ## args);  \
    } while (0)

extern void note(const Tracee *tracee, Severity severity, Origin origin,
                 const char *message, ...) FORMAT(printf, 4, 5);

extern int global_verbose_level;
extern const char *global_tool_name;

#endif /* NOTE_H */