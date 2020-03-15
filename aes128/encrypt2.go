package main

import (
    "bufio"
    "bytes"
    "crypto/aes"
    "crypto/cipher"
    "encoding/base64"
    "flag"
    "fmt"
    "io/ioutil"
    "log"
    "os"
    "strings"
)

const (
    sKey        = "dde4b1f8a9e6b81a"
    ivParameter = "dde4b1f8a9e6b81b"
)

var (
    IsDecrypt = false
)

//加密
func PswEncrypt(src string, keyIn string, ivIn string) string {
    key := []byte(sKey)
    iv := []byte(ivParameter)
    if len(keyIn) > 0 {
        key = []byte(keyIn)
    }
    if len(ivIn) > 0 {
        iv = []byte(ivIn)
    }

    result, err := Aes128Encrypt([]byte(src), key, iv)
    if err != nil {
        panic(err)
    }

    ioutil.WriteFile("x0.dat", result, 0777)
    return base64.StdEncoding.WithPadding(base64.StdPadding).EncodeToString(result)
}

//解密
func PswDecrypt(src string, keyIn string, ivIn string) string {
    key := []byte(sKey)
    iv := []byte(ivParameter)
    var result []byte
    var err error

    if len(keyIn) > 0 {
        key = []byte(keyIn)
    }
    if len(ivIn) > 0 {
        iv = []byte(ivIn)
    }

    result, err = base64.StdEncoding.WithPadding(base64.StdPadding).DecodeString(src)
    if err != nil {
        panic(err)
    }
    ioutil.WriteFile("x.dat", result, 0777)
    origData, err := Aes128Decrypt(result, key, iv)
    if err != nil {
        panic(err)
    }
    return string(origData)
}
func Aes128Encrypt(origData, key []byte, IV []byte) ([]byte, error) {
    if key == nil || len(key) != 16 {
        return nil, nil
    }
    if IV != nil && len(IV) != 16 {
        return nil, nil
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    blockSize := block.BlockSize()
    origData = PKCS5Padding(origData, blockSize)
    blockMode := cipher.NewCBCEncrypter(block, IV[:blockSize])
    encrypted := make([]byte, len(origData))
    // 根据CryptBlocks方法的说明，如下方式初始化crypted也可以
    blockMode.CryptBlocks(encrypted, origData)
    return encrypted, nil
}

func Aes128Decrypt(encrypted, key []byte, IV []byte) ([]byte, error) {
    if key == nil || len(key) != 16 {
        return nil, nil
    }
    if IV != nil && len(IV) != 16 {
        return nil, nil
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    blockSize := block.BlockSize()
    blockMode := cipher.NewCBCDecrypter(block, IV[:blockSize])
    origData := make([]byte, len(encrypted))
    blockMode.CryptBlocks(origData, encrypted)
    origData = PKCS5UnPadding(origData)
    return origData, nil
}

func PKCS5Padding(cipherText []byte, blockSize int) []byte {
    padding := blockSize - len(cipherText)%blockSize
    padtext := bytes.Repeat([]byte{byte(padding)}, padding)
    return append(cipherText, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
    length := len(origData)
    // 去掉最后一个字节 unpadding 次
    unpadding := int(origData[length-1])
    return origData[:(length - unpadding)]
}

func PaddingKeyIv(key, iv string) (string, string)  {
    paddingFun := func(s string) string {
        if len(s) == 0 {
            return ""
        } else if len(s) >= 16 {
            return s[0:16]
        } else {
            return s + strings.Repeat("*", 16 - len(s))
        }
    }
    return paddingFun(key), paddingFun(iv)
}

func main() {
    flag.BoolVar(&IsDecrypt, "d", false, "is decrypt or not")
    flag.Parse()

    if IsDecrypt {
        fmt.Println("请输入要解密的字符串:")
    } else {
        fmt.Println("请输入要加密的字符串:")
    }
    stdinReader := bufio.NewReader(os.Stdin)
    input, err := stdinReader.ReadString('\n')
    if err != nil {
        log.Fatal("输入发生错误！")
    }

    fmt.Println("请输入加密密钥（默认按回车）：")
    key, err := stdinReader.ReadString('\n')
    if err != nil {
        log.Fatal("输入发生错误！")
    }
    fmt.Println("请输入初始向量（默认按回车）：")
    iv, err := stdinReader.ReadString('\n')
    if err != nil {
        log.Fatal("输入发生错误！")
    }

    input = strings.Trim(input, "\r\n")
    key = strings.Trim(key, "\r\n")
    iv = strings.Trim(iv, "\r\n")
    key, iv = PaddingKeyIv(key, iv)
    
    if IsDecrypt {
        decodingString := PswDecrypt(input, key, iv)
        fmt.Println("解密后：", decodingString)
    } else {
        encodingString := PswEncrypt(input, key, iv)
        fmt.Println("加密后：", encodingString)
    }
}
