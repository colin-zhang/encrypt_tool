#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "openssl/pem.h"
#include "openssl/err.h"
#include "openssl/aes.h"
#include "openssl/rand.h"
#include "openssl/md5.h"

#include "encrypt_file.h"
#include "utils.h"

static void phex(uint8_t* str)
{
    unsigned char i;
    for(i = 0; i < 16; ++i)
        printf("%.2x", str[i]);
    printf("\n");
}

int decrypt_key(const unsigned char* encrypted, const char *PrivKey, const char *passwd, unsigned char** decrypted, int* decrypted_len)
{
    BIO* bp = NULL;
    unsigned char* dedata = NULL;
    int encrylen = 256;
    if ((bp = BIO_new_mem_buf((void*)PrivKey, -1)) == NULL) {     
        fprintf(stderr, "%s\n", "BIO_new_mem_buf failed!\n");
        return -1;
    }

    OpenSSL_add_all_ciphers();
    RSA *rsa2 = PEM_read_bio_RSAPrivateKey(bp, NULL, 0, (char *)passwd);
    if (rsa2 == NULL) {
        fprintf(stderr, "unable to read private key!\n");
        BIO_free_all(bp);
        EVP_cleanup();
        return -1;
    }
    BIO_free_all(bp);
    EVP_cleanup();

    dedata = (unsigned char*)malloc(encrylen);
    if (NULL == dedata) {
        RSA_free(rsa2);
        return -1;
    }
    memset(dedata, 0, encrylen);

    // use private key to decrypt encrypted data
    int decrylen = RSA_private_decrypt(encrylen, encrypted, dedata, rsa2, RSA_PKCS1_PADDING);
    if (decrylen == -1) {
        free(dedata);
        RSA_free(rsa2);
        fprintf(stderr, "failed to decrypt!\n");
        return -1;
    }

    RSA_free(rsa2);
    *decrypted = dedata;
    *decrypted_len = decrylen;

    return 0;
}

int decrypt_file(const char* encrypt_file_path, const char *PrivKey, const char *passwd, unsigned char** output, size_t* data_len)
{
    ssize_t ofile_size;
    struct encypt_file_header header = {0};
    unsigned char plaintext[256];
    unsigned char ciphertext[256];

    ofile_size = get_file_size(encrypt_file_path);
    if (ofile_size < 0) {
        fprintf(stderr, "Fail to get file size, %s\n", strerror(errno));
        return -1;
    }
    if (ofile_size <= kEncryptFileHeaderLen) {
        fprintf(stderr, "%s\n", "not the right file");
        return -1;
    }

    FILE* enfp = fopen(encrypt_file_path, "r");

    if (NULL == enfp) {
        fprintf(stderr, "Faile to open [%s]\n", encrypt_file_path);
        return -1;
    }

    unsigned char iv[16] = {0};
    uint8_t* dekey = NULL;
    int dekey_len = 0;
    size_t plaintext_size = 0;
    size_t block_len = 0;
    AES_KEY key;
    MD5_CTX md5_ctx;

    MD5_Init(&md5_ctx);
    fread((char*)&header, 1, sizeof(header), enfp);
    header.stamp = betoh_32(header.stamp);
    header.ver = betoh_16(header.ver);
    header.origin_len = betoh_64(header.origin_len);
    header.key_len = betoh_16(header.key_len);

    if (decrypt_key(header.key, PrivKey, passwd, &dekey, &dekey_len) < 0) {
        fprintf(stderr, "Fail to decrypt key ");
        fclose(enfp);
        return -1;
    }

#if 0
    printf("stamp =  %08x\n", header.stamp);
    printf("ver =  %02x\n", header.ver);
    printf("origin_len =  %lu\n", header.origin_len);
    printf("key_len =  %u \n", header.key_len);
    phex(dekey);
    printf("dekey_len = %d\n", dekey_len);
#endif

    if (header.stamp != kEncryptFileStamp) {
        fprintf(stdout, "header.stamp error !\n");
        free(dekey);
        fclose(enfp);
        return -1;
    }

    if (header.ver != kEncryptFileVer) {
        fprintf(stdout, "do not support ver %02x\n", header.ver);
        free(dekey);
        fclose(enfp);
        return -1;
    }

    if (header.compressed_type != 0 || header.encrypt_type != 0) {
        fprintf(stdout, "do not support compressed_type=%02x, encrypt_type=%02x\n", header.compressed_type, header.encrypt_type);
        free(dekey);
        fclose(enfp);
        return -1;
    }

    unsigned char* origin_data = (unsigned char*)malloc(header.origin_len + 1);
    memset(origin_data, 0, header.origin_len);

    AES_set_decrypt_key(dekey, 128, &key);  
    
    fseek(enfp, 512, SEEK_SET);
    while (!feof(enfp)) {
        size_t n = fread(ciphertext, 1, 16, enfp); 
        if (n == 0) {
            break;
        }
        memset(plaintext, 0, sizeof(plaintext));
        AES_cbc_encrypt(ciphertext, plaintext, 16, &key, iv, AES_DECRYPT);

        if (plaintext_size + 16 > header.origin_len) {
            block_len = header.origin_len - plaintext_size;
        } else {    
            block_len = 16;
        }
        MD5_Update(&md5_ctx, plaintext, block_len);

        memcpy(origin_data + plaintext_size, plaintext, block_len);
        plaintext_size += block_len;
    }
    uint8_t MD5result[32] = {0};
    MD5_Final(MD5result, &md5_ctx);

    printf("md5sum:");
    phex(MD5result);

    if (memcmp(MD5result, header.md5sum, 16) != 0) {
        fprintf(stdout, "md5 do not compare !\n");
        free(dekey);
        fclose(enfp);
        return -1;
    }

    free(dekey);
    fclose(enfp);
    *output = origin_data;
    *data_len = plaintext_size;
    return 0;
}

int main(int argc, char const *argv[])
{
    char* key = (char*)".private.pem";
    if (argc != 2 && argc != 3) {
        exit(0);
    }   
    if (argc == 3) {
        key = (char*)argv[2];
    }

    if (!is_file_exit(argv[1])) {
        fprintf(stderr, "File %s is not exist\n", argv[1]);
        exit(-1);
    }

    char decyptFile[1024] = {0};

    snprintf(decyptFile, sizeof(decyptFile), "%s.decrypt", argv[1]);
    
    unsigned char* output = NULL;
    size_t data_len = 0;

    char* privKey = get_file_data(key);
    if (NULL == privKey) {
        fprintf(stderr, "can not find %s\n", key);
        exit(-1);
    } 
    char* passwd = getpass("Input passwd:");

    int rc = decrypt_file(argv[1], privKey, passwd, &output, &data_len);
    if (rc < 0) {
        fprintf(stderr, "Fail to encrypt %s\n", argv[1]);
        return -1;
    }

    FILE* dfp = fopen(decyptFile, "wb");
    fwrite(output, 1, data_len, dfp);
    free(output);

    return 0;
}
