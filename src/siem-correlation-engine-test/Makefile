GEN_SRC := $(wildcard *.cpp)
GEN_OBJ := $(patsubst %.cpp,%.o, $(GEN_SRC))

THRIFT_DIR := /usr/local/include/thrift
PROTOBUF_DIR := /home/siem/include/

INC := -I$(THRIFT_DIR) -I$(PROTOBUF_DIR)

.PHONY: all clean

all: test_thrift

%.o: %.cpp
	$(CXX) -g -Wall -DHAVE_INTTYPES_H -DHAVE_NETINET_IN_H $(INC) -c $< -o $@

test_thrift: ThriftClientTest.o $(GEN_OBJ)
	$(CXX) $^  -g -o $@ -L/usr/local/lib -lthrift -lthriftnb -levent -lprotobuf-lite -L/home/sdk/lib -lzmq
clean:
	$(RM) *.o test_thrift
