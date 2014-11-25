#ifndef THRIFTRECEIVESERVER_H_
#define THRIFTRECEIVESERVER_H_

#include "SIEMThrift.h"

#include <vector>

#include "IReceiveServer.h"
#include "SIEMPublic.h"

namespace SIEM
{

typedef boost::shared_ptr<stCacheItem<std::string> > RingCachePtr;

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
    static void *ThreadThrift(void *p);
    static void *ThreadHandle(void *p);
public:
    std::string  m_strBind;
    uint16_t     m_nPort;
    uint8_t      m_nThreadNum;
    uint32_t     m_nCacheNum;
    RingCachePtr m_CachePtr;
private:
    pthread_t    m_pthHandleID;

};
}
#endif //THRIFTRECEIVESERVER_H_
