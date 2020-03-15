#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/aes.h>

#include "crypt.h"
#ifdef USE_MODP_B64
#include "modp_b64/modp_b64.h"
#else
#include "base64.h"
#endif
#include "modp_b64/modp_b64.h"

const char* A = "dde4b1f8a9e6b81a";
const char* B = "dde4b1f8a9e6b81b";

static int EncryptCBC(unsigned char* in, int inl, unsigned char* out,
                      int* outlen, const char* key, const unsigned char* iv,
                      int ivLen) {
  if (ivLen != 16 || iv == nullptr) {  // 16 iv len
    return -10;
  }
  EVP_CIPHER_CTX* ctx;
  if (!(ctx = EVP_CIPHER_CTX_new())) {
    printf("EVP_CIPHER_CTX_new err");
    return -1;
  }
  if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr,
                          (const unsigned char*)key, iv)) {
    printf("EVP_DecryptInit_ex err");
    EVP_CIPHER_CTX_free(ctx);
    return -2;
  }
  if (outlen == nullptr || out == nullptr) {
    printf("outlen is null or out is null");
    EVP_CIPHER_CTX_free(ctx);
    return -3;
  }
  int len = 0;
  int outl = 0;
  if (!EVP_EncryptUpdate(ctx, out + len, &outl, in, inl)) {
    printf("EVP_DecryptUpdate err");
    EVP_CIPHER_CTX_free(ctx);
    return -4;
  }
  len += outl;
  if (!EVP_EncryptFinal_ex(ctx, out + len, &outl)) {
    printf("EVP_DecryptFinal_ex err");
    EVP_CIPHER_CTX_free(ctx);
    return -5;
  }
  len += outl;
  *outlen = len;
  EVP_CIPHER_CTX_free(ctx);
  return 0;
}

static int DecryptCBC(unsigned char* in, int inl, unsigned char* out,
                      int* outlen, const char* key, const unsigned char* iv,
                      int ivLen) {

  if (ivLen != 16 || iv == nullptr) {  // 16 iv len
    return -10;
  }
  EVP_CIPHER_CTX* ctx;
  if (!(ctx = EVP_CIPHER_CTX_new())) {
    printf("EVP_CIPHER_CTX_new err");
    return -1;
  }
  if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr,
                          (const unsigned char*)key, iv)) {
    printf("EVP_DecryptInit_ex err");
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }

  int len = 0;
  int outl = 0;
  if (!EVP_DecryptUpdate(ctx, out + len, &outl, in, inl)) {
    printf("EVP_EncryptUpdate err");
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  len += outl;
  if (!EVP_DecryptFinal_ex(ctx, out + len, &outl)) {
    printf("EVP_DecryptFinal_ex err");
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  len += outl;
  *outlen = len;
  EVP_CIPHER_CTX_free(ctx);
  return 0;
}

void FillS(std::string& out, const std::string& key) {
  if (key.size() > 0) {
    out = key.substr(0, 16);
    if (out.size() < 16) {
        out.append(16 - out.size(), '*');
    }
  }
}

// default base64 with paddig '='
int EncryptStr(const std::string& key, const std::string& iv,
               const std::string& str, std::string& out_str) {
  std::string real_key = std::string(A);
  std::string real_iv = std::string(B);

  FillS(real_key, key);
  FillS(real_iv, iv);

  unsigned char* out = new unsigned char[str.size() + 256];
  int outlen;
  int ret =
      EncryptCBC((unsigned char*)str.c_str(), (int)str.size(), out, &outlen,
                 real_key.c_str(), (unsigned char*)real_iv.c_str(), 16);

  if (ret != 0) {
    delete[] out;
    return -1;
  }

// minimum block is 16
#ifdef USE_MODP_B64
  char* outbase64 = new char[modp_b64_encode_len(str.size()) + 16];
  ret = (int)modp_b64_encode(outbase64, (const char*)out, outlen);
#else
  int outbase64_len = (str.size() + 16) << 1;
  unsigned char* outbase64 = new unsigned char[outbase64_len];
  ret = Base64Encode(out, outlen, outbase64, outbase64_len);
#endif
  if (ret <= 0) {
    delete[] out;
    delete[] outbase64;
    return -1;
  }
  out_str = std::string((char*)outbase64, ret);

  delete[] out;
  delete[] outbase64;
  return 0;
}

int DecryptStr(const std::string& key, const std::string& iv,
               const std::string& str, std::string& out_str) {
#ifdef USE_MODP_B64
  size_t en_len = modp_b64_decode_len(str.size()) + 4;
  char* en = new char[en_len];
  int ret = (int)modp_b64_decode(en, str.c_str(), str.size());
#else
  int en_len = str.size();
  unsigned char* en = new unsigned char[en_len];
  int ret = Base64Decode((uint8_t*)str.c_str(), (int)str.size(), en, en_len);
#endif
  en_len = ret;
  if (ret <= 0) {
    delete[] en;
    return -1;
  }

  std::string real_key = std::string(A);
  std::string real_iv = std::string(B);
  FillS(real_key, key);
  FillS(real_iv, iv);

  int outlen = en_len + 16;
  unsigned char* out = new unsigned char[outlen];
  ret = DecryptCBC((unsigned char*)en, en_len, out, &outlen, real_key.c_str(),
                   (unsigned char*)real_iv.c_str(), 16);
  if (ret < 0) {
    delete[] en;
    delete[] out;
    return -1;
  }
  out_str = std::string((char*)out, outlen);

  delete[] en;
  delete[] out;
  return 0;
}
