#include <stdint.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

static int Base64OP(uint8_t* in, int in_len, uint8_t* out, int out_len,
                    int op) {
  int ret = 0;
  BIO* b64 = BIO_new(BIO_f_base64());
  BIO* bio = BIO_new(BIO_s_mem());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  BIO_push(b64, bio);
  // encode
  if (op == 0) {
    ret = BIO_write(b64, in, in_len);
    BIO_flush(b64);
    if (ret > 0) {
      ret = BIO_read(bio, out, out_len);
    }
  } else {
    ret = BIO_write(bio, in, in_len);
    BIO_flush(bio);
    if (ret) {
      ret = BIO_read(b64, out, out_len);
    }
  }
  BIO_free(b64);
  return ret;
}

int Base64Encode(uint8_t* in, int in_len, uint8_t* out, int out_len) {
  return Base64OP(in, in_len, out, out_len, 0);
}

int Base64Decode(uint8_t* in, int in_len, uint8_t* out, int out_len) {
  return Base64OP(in, in_len, out, out_len, 1);
}
