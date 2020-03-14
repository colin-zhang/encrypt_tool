TARGET = encrypt2

SOURCE = $(wildcard *.cc)
SOURCE2= $(wildcard modp_b64/*.cc)
OBJS = $(patsubst %.cc,%.o,$(SOURCE))
OBJS += $(patsubst %.cc,%.o,$(SOURCE2))



CFLAGS = -DUSE_MODP_B64 -Wall -O1 -std=c++11 -g
LDFLAGS = -lcrypto

$(TARGET):$(OBJS)
	$(CXX) $(OBJS) $(LDFLAGS) -o $@

%.o:%.cc
	echo Compiling $< ...
	$(CXX) -c $(CFLAGS)  $< -o $*.o

.PHONY: clean

clean:
	rm  *.o -rf $(TARGET) modp_b64/*.o
