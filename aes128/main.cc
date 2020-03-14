#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string>
#include <iostream>

#include "crypt.h"

void Encrypt(const std::string& key, const std::string& iv, 
                const std::string& str) {
    std::string out;
    EncryptStr(key, iv, str, out);

    std::cout << "" 
              << out
              << std::endl;
}

void Decrypt(const std::string& key, const std::string& iv, 
                const std::string& str) {
    std::string out;
    DecryptStr(key, iv, str, out);

    std::cout << ""
              << out
              << std::endl;
}

void Prompt(int f) {
    std::string key;
    std::string iv;
    std::string str;

    std::cout << "请输入密钥（敲回车使用默认值）:";
    getline(std::cin, key, '\n');
    std::cout << "请输入初始向量（敲回车使用默认值）:";
    getline(std::cin, iv, '\n');
    
    if (f == 'e') {
        std::cout << "请输入加密字符串:";
        getline(std::cin, str, '\n');
        Encrypt(key, iv, str);
    } else {
        std::cout << "请输入解密字符串:";
        getline(std::cin, str, '\n');
        Decrypt(key, iv, str);
    }
}

void Help() {
   std::cout << "说明: \n"
        << " -e/encrypt: 加密 \n"    
        << " -d/decrypt: 解密 \n";
}

int main(int argc, char* argv[])
{
    struct option long_opt[] = {
        {"encrypt", no_argument, 0, 'e'},
        {"decrypt", no_argument, 0, 'd'},
    };

    int opt_index = 0;
    int opt = 0;

    if (argc == 1)  {
        Help();
        exit(0);
    }

    while ((opt = getopt_long(argc, argv, "ed", long_opt, &opt_index)) != -1) {
        switch (opt) {
            case 'e':
                Prompt(opt);
                break;
            case 'd':
                Prompt(opt);
                break;
            default:
                Help();
                exit(0);
        }

    }
    return 0;
}
