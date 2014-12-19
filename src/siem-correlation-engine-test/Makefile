GEN_THRIFT_SRC := SIEMMessage_constants.cpp SIEMMessage_types.cpp SIEMThrift.cpp
GEN_THRIFT_OBJ := $(patsubst %.cpp,%.o, $(GEN_THRIFT_SRC))

GEN_ZMQ_SRC := SIEMMessage.pb.cpp
GEN_ZMQ_OBJ := $(patsubst %.cpp,%.o, $(GEN_ZMQ_SRC))

THRIFT_DIR := /usr/local/include/thrift
PROTOBUF_DIR := /home/siem/include/

INC := -I$(THRIFT_DIR) -I$(PROTOBUF_DIR)

.PHONY: all clean

all: test_thrift test_zmq

%.o: %.cpp
	$(CXX) -g -Wall -DHAVE_INTTYPES_H -DHAVE_NETINET_IN_H $(INC) -c $< -o $@

test_thrift: ThriftClientTest.o $(GEN_THRIFT_OBJ)
	$(CXX) $^  -g -o $@ -L/usr/local/lib -lthrift -lthriftnb -levent -lprotobuf-lite -L/home/sdk/lib -lzmq

test_zmq: ZmqClientTest.o $(GEN_ZMQ_OBJ)
	$(CXX) $^  -g -o $@ -L/usr/local/lib -lprotobuf-lite -L/home/sdk/lib -lzmq

clean:
	$(RM) *.o test_thrift test_zmq
