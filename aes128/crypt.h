#ifndef CRYPT_H_
#define CRYPT_H_

#include <string>

int EncryptStr(const std::string& key, const std::string& iv, 
                const std::string& str, std::string& out);

int DecryptStr(const std::string& key, const std::string& iv, 
                const std::string& str, std::string& out);
#endif
