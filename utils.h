#ifndef _UTILS_H_
#define _UTILS_H_

#include <stddef.h>

ssize_t get_file_size(const char* path);
int is_file_exit(const char* path);
char* get_file_data(const char* path);

#endif