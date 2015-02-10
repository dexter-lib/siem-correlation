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
#include <set>

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
    SIEM_PROTOCOL_ANY = 0,
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

typedef enum
{
    RULE_TYPE_DETECTOR,
    RULE_TYPE_MONITOR,
    RULE_TYPE_NULL
}RULE_TYPE;

typedef enum
{
    IP_TYPE_SRC_IP = 0,
    IP_TYPE_DST_IP,
    IP_TYPE_HOME_NET,
    IP_TYPE_ANY,
    IP_TYPE_NULL
}IP_TYPE;

typedef enum
{
    PORT_TYPE_SRC_PORT = 0,
    PORT_TYPE_DST_PORT,
    PORT_TYPE_ANY,
    PORT_TYPE_NULL
}PORT_TYPE;

typedef struct stIPVar
{
    IP_TYPE eIPType;
    int     nLevel;
    stIPVar():
        eIPType(IP_TYPE_NULL),
        nLevel(1)
    {
    }

    bool operator < (const stIPVar& ip) const
    {
        if(this->eIPType < ip.eIPType)
            return true;
        else
            return false;
    }
}IPVar;

typedef struct stPortVar
{
    PORT_TYPE ePortType;
    int       nLevel;
    stPortVar():
        ePortType(PORT_TYPE_NULL),
        nLevel(1)
    {
    }

    stPortVar& operator= (const stPortVar& port)
    {
        this->ePortType = port.ePortType;
        this->nLevel    = port.nLevel;
        return *this;
    }

    bool operator< (const stPortVar& port) const
    {
        if(this->ePortType < port.ePortType)
            return true;
        else
            return false;
    }
}PortVar;

typedef struct stSIEM_IP
{
    std::set<IPVar>       varSet;
    std::set<IPVar>       varNotSet;
    std::set<std::string> ipSet;
    std::set<std::string> ipNotSet;
    bool                  bAny;

    stSIEM_IP& operator=(const stSIEM_IP& ip)
    {
        this->ipSet.insert(ip.ipSet.begin(), ip.ipSet.end());
        this->ipNotSet.insert(ip.ipNotSet.begin(), \
                ip.ipNotSet.end());
        this->varNotSet.insert(ip.varNotSet.begin(), ip.varNotSet.end());
        this->varSet.insert(ip.varSet.begin(), ip.varSet.end());
        this->bAny = ip.bAny;
        return *this;
    }

    stSIEM_IP():bAny(false){}

    stSIEM_IP(const stSIEM_IP& ip)
    :bAny(false)
    {
        if(!ip.varSet.empty())
            varSet.insert(ip.varSet.begin(), ip.varSet.end());
        if(!ip.varNotSet.empty())
            varNotSet.insert(ip.varNotSet.begin(), ip.varNotSet.end());
        if(!ip.ipSet.empty())
            ipNotSet.insert(ip.ipSet.begin(), ip.ipSet.end());
        if(!ip.ipNotSet.empty())
            ipNotSet.insert(ip.ipNotSet.begin(), ip.ipNotSet.end());
        bAny = ip.bAny;
    }
}SIEM_IP;

typedef struct stSIEM_PORT
{
    std::set<PortVar>  varSet;
    std::set<PortVar>  varNotSet;
    std::set<uint16_t> portSet;
    std::set<uint16_t> portNotSet;
    bool               bAny;

    stSIEM_PORT& operator=(const stSIEM_PORT& port)
    {
        this->portSet.insert(port.portSet.begin(), port.portSet.end());
        this->portNotSet.insert(port.portNotSet.begin(), \
                port.portNotSet.end());
        this->varNotSet.insert(port.varNotSet.begin(), port.varNotSet.end());
        this->varSet.insert(port.varSet.begin(), port.varSet.end());
        this->bAny = port.bAny;
        return *this;
    }

    stSIEM_PORT():bAny(false){}

    stSIEM_PORT(const stSIEM_PORT& port)
    :bAny(false)
    {
        if(!port.varSet.empty())
            varSet.insert(port.varSet.begin(), port.varSet.end());
        if(!port.varNotSet.empty())
            varNotSet.insert(port.varNotSet.begin(), port.varNotSet.end());
        if(!port.portSet.empty())
            portSet.insert(port.portSet.begin(), port.portSet.end());
        if(!port.portNotSet.empty())
            portNotSet.insert(port.portNotSet.begin(), port.portNotSet.end());
        bAny = port.bAny;
    }
}SIEM_PORT;

typedef struct stRule
{
    std::set<uint32_t> setPluginID;
    std::set<uint32_t> setPluginSID;
    std::string        strName;
    uint16_t           nReliability;
    uint16_t           nOccurrence;
    uint32_t           nTimeout;
    RULE_TYPE          eRuleType;
    SIEM_PROTOCOL_TYPE eProtocolType;
    SIEM_IP            srcIP;
    SIEM_IP            dstIP;
    SIEM_PORT          srcPort;
    SIEM_PORT          dstPort;

    stRule():
        strName(""), nReliability(0), nOccurrence(0),
        nTimeout(0), eRuleType(RULE_TYPE_NULL),
        eProtocolType(SIEM_PROTOCOL_ANY)
    {
    }

    stRule(const stRule& rule):
        strName(""), nReliability(0), nOccurrence(0),
        nTimeout(0), eRuleType(RULE_TYPE_NULL),
        eProtocolType(SIEM_PROTOCOL_ANY)
    {
        if(!setPluginID.empty())
            setPluginID.insert(rule.setPluginID.begin(), \
                rule.setPluginID.end());
        if(!setPluginSID.empty())
            setPluginSID.insert(rule.setPluginSID.begin(), \
                rule.setPluginSID.end());

        strName       = rule.strName;
        nReliability  = rule.nReliability;
        nOccurrence   = rule.nOccurrence;
        nTimeout      = rule.nTimeout;
        eRuleType     = rule.eRuleType;
        eProtocolType = rule.eProtocolType;
        srcIP         = rule.srcIP;
        dstIP         = rule.dstIP;
        srcPort       = rule.srcPort;
        dstPort       = rule.dstPort;
    }

    stRule(stRule& rule):
        strName(""), nReliability(0), nOccurrence(0),
        nTimeout(0), eRuleType(RULE_TYPE_NULL),
        eProtocolType(SIEM_PROTOCOL_ANY)
    {
        if(!setPluginID.empty())
            setPluginID.insert(rule.setPluginID.begin(), \
                rule.setPluginID.end());
        if(!setPluginSID.empty())
            setPluginSID.insert(rule.setPluginSID.begin(), \
                rule.setPluginSID.end());

        strName       = rule.strName;
        nReliability  = rule.nReliability;
        nOccurrence   = rule.nOccurrence;
        nTimeout      = rule.nTimeout;
        eRuleType     = rule.eRuleType;
        eProtocolType = rule.eProtocolType;
        srcIP         = rule.srcIP;
        dstIP         = rule.dstIP;
        srcPort       = rule.srcPort;
        dstPort       = rule.dstPort;
    }

    stRule& operator= (const stRule& rule)
    {
        if(!setPluginID.empty())
            this->setPluginID.insert(rule.setPluginID.begin(), \
                rule.setPluginID.end());
        if(!setPluginSID.empty())
            this->setPluginSID.insert(rule.setPluginSID.begin(), \
                rule.setPluginSID.end());

        this->strName       = rule.strName;
        this->nReliability  = rule.nReliability;
        this->nOccurrence   = rule.nOccurrence;
        this->nTimeout      = rule.nTimeout;
        this->eRuleType     = rule.eRuleType;
        this->eProtocolType = rule.eProtocolType;
        this->srcIP         = rule.srcIP;
        this->dstIP         = rule.dstIP;
        this->srcPort       = rule.srcPort;
        this->dstPort       = rule.dstPort;
        return *this;
    }
} SIEMRule;

} /* namespace SIEM */
#endif /* SIEMPUBLIC_H_ */
