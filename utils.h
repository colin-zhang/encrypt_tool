#ifndef _UTILS_H_
#define _UTILS_H_

#include <stddef.h>
#include <stdint.h>

uint16_t htobe_16(uint16_t v);
uint32_t htobe_32(uint32_t v);
uint64_t htobe_64(uint64_t v);
uint16_t betoh_16(uint16_t v);
uint32_t betoh_32(uint32_t v);
uint64_t betoh_64(uint64_t v);

ssize_t get_file_size(const char* path);
int  is_file_exit(const char* path);
char* get_file_data(const char* path);


#endif