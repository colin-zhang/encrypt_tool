#ifndef _LIB_ENCRYTPT_FILE_H_
#define _LIB_ENCRYTPT_FILE_H_

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

static const uint16_t kEncryptFileHeaderLen=512;
static const uint32_t kEncryptFileStamp=0x6d6e7363;
static const uint8_t  kEncryptFileVer=0x01;

struct encypt_file_header
{
    uint32_t stamp;
    uint16_t ver;
    uint64_t origin_len;
    uint8_t  compressed_type;
    uint8_t  encrypt_type;
    uint8_t  md5sum[16];
    uint16_t key_len;
    uint8_t  key[300];
} __attribute__((__packed__));

int decrypt_key(const unsigned char* encrypted, const char *PrivKey, const char *passwd, unsigned char** decrypted, int* decrypted_len);
int decrypt_file(const char* encrypt_file_path, unsigned char** output, size_t* data_len);

#ifdef __cplusplus
}
#endif

#endif //end of _LIB_ENCRYTPT_FILE_H_