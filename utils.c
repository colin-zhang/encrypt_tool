#include <stdio.h>  
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "utils.h"

static const int kLittleEndian = (__BYTE_ORDER == __LITTLE_ENDIAN);

uint16_t htobe_16(uint16_t v) {
    if (kLittleEndian) {
        unsigned char* pv = (unsigned char*)&v;
        return uint16_t(pv[0])<<8 | uint16_t(pv[1]);
    }
    return v;
}

uint32_t htobe_32(uint32_t v) {
    if (kLittleEndian) {
        unsigned char* pv = (unsigned char*)&v;
        return uint32_t(pv[0])<<24 | uint32_t(pv[1])<<16 | uint32_t(pv[2])<<8 | uint32_t(pv[3]);
    }
    return v;
}

uint64_t htobe_64(uint64_t v) {
    if (kLittleEndian) {
        unsigned char* pv = (unsigned char*)&v;
        return uint64_t(pv[0])<<56 | uint64_t(pv[1])<<48 | uint64_t(pv[2])<<40 | uint64_t(pv[3])<<32
                | uint64_t(pv[4])<<24 | uint64_t(pv[5])<<16 | uint64_t(pv[6])<<8 | uint64_t(pv[7]);
    }
    return v;
}

uint16_t betoh_16(uint16_t v) {
    if (kLittleEndian) {
        return htobe_16(v);
    }
    return v;
}

uint32_t betoh_32(uint32_t v) {
    if (kLittleEndian) {
        return htobe_32(v);
    }
    return v;
}

uint64_t betoh_64(uint64_t v) {
    if (kLittleEndian) {
        return htobe_64(v);
    }
    return v;
}

ssize_t get_file_size(const char* path)
{
    ssize_t    file_size = -1;
    struct stat statbuff;

    if (stat(path, &statbuff) < 0) {
        return file_size;
    } else {
        file_size = statbuff.st_size;
        return file_size;
    }
}

int is_file_exit(const char* path)
{
    if (access(path, F_OK) < 0) {
        return 0;
    }
    return 1;
}

char* get_file_data(const char* path) 
{
    char* data = NULL;
    ssize_t data_len = get_file_size(path);
    if (data_len < 0) {
        return NULL;
    }
    FILE* fp = fopen(path, "rb");
    if (NULL == fp) {
        return NULL;
    }
    data = (char*)calloc(1, data_len + 1);
    fread(data, 1, data_len, fp);
    return data;
}
