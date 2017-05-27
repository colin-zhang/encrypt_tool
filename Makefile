all:encrypt_tool decrypt_tool

encrypt_tool: encrypt_tool.o utils.o
	$(CXX) -o $@ $^ -Wl,-dn -lcrypto -lz -Wl,-dy -ldl
	
decrypt_tool: decrypt_tool.o utils.o
	$(CXX) -o $@ $^ -Wl,-dn -lcrypto -lz -Wl,-dy -ldl

.c.o:
	$(CXX) $(CFLAGS) -c $< -o $@ -Wall

install:
	install encrypt_tool -D /usr/local/bin

clean:
	rm -rf encrypt_tool decrypt_tool *.o
