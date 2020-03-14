#ifndef BASE64_H_
#define BASE64_H_
#include <stdint.h>
int Base64Encode(uint8_t* in, int in_len, uint8_t* out, int out_len);
int Base64Decode(uint8_t* in, int in_len, uint8_t* out, int out_len);

#endif
