GEN_SRC := $(wildcard ../src/siem-correlation-engine/*.cpp)
GEN_OBJ := $(patsubst %.cpp,%.o, $(GEN_SRC))

THRIFT_DIR := /usr/local/include/thrift
PROTOBUF_DIR := /home/siem/include/

INC := -I$(THRIFT_DIR) -I$(PROTOBUF_DIR)

.PHONY: all clean

all: siem_server

%.o: %.cpp
	$(CXX) -g -Wall -DHAVE_INTTYPES_H -DHAVE_NETINET_IN_H $(INC) -c $< -o $@

siem_server: ../src/siem-correlation-engine/AppMain.o $(GEN_OBJ)
	$(CXX) $^  -g -o $@ -L/usr/local/lib -lthrift -lthriftnb -levent -lprotobuf-lite -L/home/sdk/lib -lzmq -lPocoFoundation -lPocoUtil -lPocoNet -lPocoXML
	mv siem_server ../bin/
clean:
	$(RM) ../src/siem-correlation-engine/*.o ../bin/*
