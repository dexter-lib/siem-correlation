#ifndef THRIFTRECEIVESERVER_H_
#define THRIFTRECEIVESERVER_H_

#include "SIEMThrift.h"

#include <vector>

#include "IReceiveServer.h"

namespace SIEM
{

typedef struct stRingCache
{
    uint64_t                 nRead;
    uint64_t                 nWrite;
    std::vector<std::string> vctCache;
    stRingCache():nRead(0), nWrite(0)
    {}
} RingCache;

typedef boost::shared_ptr<RingCache> RingCachePtr;

class CThriftReceiveServer : virtual public ::SIEM::thrift::SIEMThriftIf, virtual public SIEM::IReceiveServer
{
public:
    CThriftReceiveServer();
    ~CThriftReceiveServer();
public:
    bool Recv(const std::string& strEvent);
    bool Handle(const ::SIEM::thrift::SIEMThriftEvent& tEvent);
    bool Start();
    bool Initialize();
private:
    static void *ThreadFunc(void *p);
public:
    std::string  m_strBind;
    uint16_t     m_nPort;
    uint8_t      m_nThreadNum;
    uint32_t     m_nCacheNum;
    RingCachePtr m_RingCachePtr;

};
}
#endif //THRIFTRECEIVESERVER_H_
