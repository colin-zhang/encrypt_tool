#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

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

static int encrypt_key(const unsigned char* plain, int plain_len, const char* PubKey, unsigned char** encrypted, int* encrypted_len)
{
    BIO* bp = NULL;
    RSA* pPubKey_ = NULL;
    unsigned char* endata = NULL;
    int encrylen = 0;

    if ((bp = BIO_new_mem_buf((void*)PubKey, -1)) == NULL) {     
        fprintf(stderr, "%s\n", "BIO_new_mem_buf failed!\n");
        return -1;
    }

    pPubKey_ = PEM_read_bio_RSA_PUBKEY(bp, NULL, NULL, NULL);
    if (NULL == pPubKey_) {
        ERR_load_crypto_strings();
        char errBuf[512];
        ERR_error_string_n(ERR_get_error(), errBuf, sizeof(errBuf));
        fprintf(stderr, "load public key failed[%s]\n", errBuf);
        BIO_free_all(bp);
        return -1;
    }
    BIO_free_all(bp);

    endata = (unsigned char*)malloc(256);
    if (NULL == endata) {
        return -1;
    }
    memset(endata, 0, 256);

    encrylen = RSA_public_encrypt(plain_len, plain, endata, pPubKey_, RSA_PKCS1_PADDING);
    if (encrylen == -1) {
        free(endata);
        fprintf(stderr, "RSA_public_encrypt error \n");
        return -1;
    }

    *encrypted = endata;
    *encrypted_len = encrylen;

#if 1
    FILE* f = fopen(".enkey", "w");
    fwrite(endata, 1, encrylen, f);
    fclose(f);
#endif
    return 0;
}

static int write_file_header(struct encypt_file_header* header, FILE* fp)
{
    fseek(fp, 0L, SEEK_SET);
    fwrite((char*)header, 1, sizeof(*header), fp);
    return 0;
}

static int fill_file_header(FILE* fp)
{
    char buf[kEncryptFileHeaderLen];
    fseek(fp, 0L, SEEK_SET);
    memset(buf, 0x20, sizeof(buf));
    fwrite(buf, 1, sizeof(buf), fp);
    return 0;
}


static int encrypt_file(const char* file_path, const char* encrypt_file_path, const char* PubKey)
{
    ssize_t ofile_size;
    struct encypt_file_header header = {0, };
    unsigned char plaintext[256];
    unsigned char ciphertext[256];

    ofile_size = get_file_size(file_path);
    if (ofile_size < 0) {
        fprintf(stderr, "Fail to get file size, %s\n", strerror(errno));
        return -1;
    }

    FILE* ofp = fopen(file_path, "r");
    if (NULL == ofp) {
        fprintf(stderr, "failed to open(r) [%s], %s\n", file_path, strerror(errno));
        return -1;
    }

    FILE* dfp = fopen(encrypt_file_path, "w");
    if (NULL == dfp) {
        fclose(ofp);
        fprintf(stderr, "failed to open(w) [%s], %s\n", file_path, strerror(errno));
        return -1;
    } 
    unsigned char rkey[16] = {0};
    unsigned char iv[16] = {0};  
    AES_KEY key;
    MD5_CTX md5_ctx;
    uint8_t* enkey = NULL;
    int enkey_len = 0;

    RAND_pseudo_bytes(rkey, sizeof rkey);//memcpy(rkey, "1234567812345678", 16);
    AES_set_encrypt_key(rkey, 8*sizeof(rkey), &key); 
    MD5_Init(&md5_ctx);

    fill_file_header(dfp);
    while (!feof(ofp)) {
        size_t n = fread(plaintext, 1, 16, ofp);
        if (0 == n) {
            break;
        }
        MD5_Update(&md5_ctx, plaintext, n);
        AES_cbc_encrypt(plaintext, ciphertext, n, &key, iv, AES_ENCRYPT);
        fwrite(ciphertext, 1, 16, dfp);
    }  

    if (encrypt_key(rkey, sizeof(rkey), PubKey, &enkey, &enkey_len) < 0) {
        fclose(ofp);
        fclose(dfp);
        fprintf(stderr, "Fail to encrypt_key \n");
        return -1;
    }

    header.stamp = kEncryptFileStamp;
    header.ver = kEncryptFileVer;
    header.origin_len = ofile_size;
    header.compressed_type = 0;
    header.encrypt_type = 0;
    header.key_len = enkey_len;
    memcpy(header.key, enkey, enkey_len);
    MD5_Final(header.md5sum, &md5_ctx); 

    printf("md5sum:");
    phex(header.md5sum);

    write_file_header(&header, dfp);

    free(enkey);
    fclose(ofp);
    fclose(dfp);

    return 0;
}

static void help()
{
    printf( "encrypt_tool\n"
            "\tuse ./encrypt_tool \"file to be encrypted\" \n"
        );
}


int main(int argc, char const *argv[])
{
    if (argc != 2) {
        help();
        exit(0);
    }   
    if (!is_file_exit(argv[1])) {
        fprintf(stderr, "File %s is not exist\n", argv[1]);
        exit(-1);
    }

    char encyptFile[1024] = {0};

    snprintf(encyptFile, sizeof(encyptFile), "%s.encrypt", argv[1]);
    
    char* privKey = get_file_data("public.pem");
    int rc = encrypt_file(argv[1], encyptFile, privKey);
    if (rc < 0) {
        fprintf(stderr, "Fail to encrypt %s\n", argv[1]);
        return -1;
    }
    return 0;
}
