/usr/include/openssl/rsa.h

```bash
openssl genrsa -des -out .private.pem 2048
openssl rsa -in .private.pem -pubout -out .public.pem

openssl rsautl -encrypt -in test.txt -inkey .public.pem -pubin -out test.txt.en
openssl rsautl -decrypt -in .enkey -inkey .private.pem -out key
```

1. 系统中缺少openssl, 安装openssl
```bash
yum erase openssl-static
yum install openssl-static
```
