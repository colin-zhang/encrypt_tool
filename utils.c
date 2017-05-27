#include <stdio.h>  
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "utils.h"

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