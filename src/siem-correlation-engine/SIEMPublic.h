/**
 *   @file   SIEMPublic.h
 *   @brief  brief
 *
 *   detail
 *
 *   @internal www.captech.net.cn
 *   author:    Zhang peng
 *   mail:      zhangpeng@captech.net.cn,Developer.Zhang.Peng@gmail.com
 *   Created:   Nov 25, 2014
 *   Revision:  1.0.0
 *   Compiler:  gcc/g++
 *   Company:   Captech Co., Ltd.
 *   Copyright: Copyright (c) 2008, Captech Co., Ltd.
 *
 * =====================================================================================
 */

#ifndef SIEMPUBLIC_H_
#define SIEMPUBLIC_H_

#include <string>
#include <vector>

#include <boost/shared_ptr.hpp>

#include <stdint.h>

namespace SIEM
{

//use this item please override assign and operater =

template<typename T = std::string>
struct stCacheItem
{
    std::vector<T> Cache;
    uint32_t       nRead;
    uint32_t       nWrite;
    stCacheItem():nRead(0), nWrite(0)
    {}
};

typedef enum stProtocolType
{
    SIEM_PROTOCOL_NONE = -1,
    SIEM_PROTOCOL_ICMP = 1,
    SIEM_PROTOCOL_TCP = 6,
    SIEM_PROTOCOL_UDP = 17,
    SIEM_PROTOCOL_ARP_EVENT = 134,
    SIEM_PROTOCOL_OS_EVENT = 135,
    SIEM_PROTOCOL_SERVER_EVENT = 136
} SIEM_PROTOCOL_TYPE;

typedef enum stSIEMEventType
{
      SIEM_EVENT_NONE = -1,
      SIEM_EVENT_DETECTOR = 1,
      SIEM_EVENT_MONITOR = 2,
      SIEM_EVENT_BACKLOG = 3
} SIEM_EVENT_TYPE;

typedef struct stSIEMEvent
{
    SIEM_EVENT_TYPE    enEventType;
    SIEM_PROTOCOL_TYPE enEventProtoType;
    time_t             tmDate;
    time_t             tmFDate;
    u_int32_t          nPluginID;
    u_int32_t          nPluginSID;
    u_int32_t          nSnortSID;
    u_int32_t          nSnortCID;
    u_int32_t          nSensor;
    std::string        strInterface;
    std::string        strUsername;
    std::string        strPassword;
    std::string        strFilename;
    std::string        strUserdata1;
    std::string        strUserdata2;
    std::string        strUserdata3;
    std::string        strUserdata4;
    std::string        strUserdata5;
    std::string        strUserdata6;
    std::string        strUserdata7;
    std::string        strUserdata8;
    std::string        strUserdata9;
    std::string        strCtx;
    std::string        strSensorID;
    std::string        strEventID;
    std::string        strTimezone;
    std::string        strBinaryData;
    u_int32_t          nPrority;
    u_int32_t          nDeviceIP;
    u_int32_t          nSrcIP;
    u_int32_t          nDstIP;
    u_int32_t          nOccurrence;
    u_int16_t          nSrcPort;
    u_int16_t          nDstPort;
    std::string        strLog;
} SIEMEvent;

typedef boost::shared_ptr<SIEMEvent> SIEMEventPtr;
typedef boost::shared_ptr<std::vector<SIEMEventPtr> > SIEMEventVctPtr;

} /* namespace SIEM */
#endif /* SIEMPUBLIC_H_ */
