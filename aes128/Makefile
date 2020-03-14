TARGET = encrypt2

SOURCE = $(wildcard *.cc)
OBJS = $(patsubst %.cc,%.o,$(SOURCE))

CFLAGS = -Wall -O1 -std=c++11 -g
LDFLAGS = -lcrypto

$(TARGET):$(OBJS)
	$(CXX) $(OBJS) $(LDFLAGS) -o $@

%.o:%.cc
	echo Compiling $< ...
	$(CXX) -c $(CFLAGS)  $< -o $*.o

.PHONY: clean

clean:
	rm  *.o -rf $(TARGET)
