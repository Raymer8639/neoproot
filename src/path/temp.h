#ifndef TEMP_H
#define TEMP_H

#include <talloc.h>

extern char *create_temp_name(TALLOC_CTX *context, const char *prefix);
extern const char *create_temp_directory(TALLOC_CTX *context, const char *prefix);
extern const char *create_temp_file(TALLOC_CTX *context, const char *prefix);
extern FILE* open_temp_file(TALLOC_CTX *context, const char *prefix);
extern const char *get_temp_directory();

#endif /* TEMP_H */
