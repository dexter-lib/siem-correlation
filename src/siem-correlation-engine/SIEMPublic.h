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
    PROTOCOL_TYPE_ANY = 0,
    PROTOCOL_TYPE_TCP,
    PROTOCOL_TYPE_UDP,
}PROTOCOL_TYPE;

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
    PORT_TYPE_HOME_NET,
    PORT_TYPE_ANY,
    PORT_TYPE_NULL
}PORT_TYPE;

typedef struct stIPStruct
{
    bool     bIsNot;
    uint32_t nIPV4;
    stIPStruct():
        bIsNot(false),
        nIPV4(0)
    {
    }

    stIPStruct& operator=(const stIPStruct& ipStruct)
    {
        this->bIsNot = ipStruct.bIsNot;
        this->nIPV4  = ipStruct.nIPV4;
        return *this;
    }

    bool operator < (const stIPStruct& ipStruct) const
    {
        if(this->bIsNot == ipStruct.bIsNot)
            return this->nIPV4 < ipStruct.nIPV4;
        else if(this->bIsNot)
            return false;
        else
            return true;
    }
}IP_STRUCT;

typedef struct stPortStruct
{
    bool     bIsNot;
    uint16_t nPort;
    stPortStruct():
        bIsNot(false),
        nPort(0)
    {
    }

    stPortStruct& operator=(const stPortStruct& portStruct)
    {
        this->bIsNot = portStruct.bIsNot;
        this->nPort  = portStruct.nPort;
        return *this;
    }

    bool operator < (const stPortStruct& portStruct) const
    {
        if(this->bIsNot == portStruct.bIsNot)
            return this->nPort < portStruct.nPort;
        else if(this->bIsNot)
            return false;
        else
            return true;
    }
}PORT_STRUCT;

typedef struct stIPType
{
    std::set<IP_STRUCT> setIPV4;
    IP_TYPE             eIPType;
    bool                bIsSection;
    IP_STRUCT           beginIP;
    IP_STRUCT           endIP;
    stIPType():
        eIPType(IP_TYPE_NULL),
        bIsSection(false)
    {
    }

    stIPType(const stIPType& ipType):
        eIPType(IP_TYPE_NULL),
        bIsSection(false)
    {
        if(!ipType.setIPV4.empty())
            setIPV4.insert(ipType.setIPV4.begin(), \
                    ipType.setIPV4.end());

        eIPType    = ipType.eIPType;
        bIsSection = ipType.bIsSection;
        beginIP    = ipType.beginIP;
        endIP      = ipType.endIP;
    }

    stIPType(stIPType& ipType):
        eIPType(IP_TYPE_NULL),
        bIsSection(false)
    {
        if(!ipType.setIPV4.empty())
            setIPV4.insert(ipType.setIPV4.begin(), \
                    ipType.setIPV4.end());

        eIPType    = ipType.eIPType;
        bIsSection = ipType.bIsSection;
        beginIP    = ipType.beginIP;
        endIP      = ipType.endIP;
    }

    stIPType& operator= (const stIPType& ipType)
    {
        if(!ipType.setIPV4.empty())
            this->setIPV4.insert(ipType.setIPV4.begin(), \
                    ipType.setIPV4.end());

        this->eIPType    = ipType.eIPType;
        this->bIsSection = ipType.bIsSection;
        this->beginIP    = ipType.beginIP;
        this->endIP      = ipType.endIP;
        return *this;
    }


}SIEM_IP_TYPE;

typedef struct stPortType
{
    std::set<PORT_STRUCT> setPort;
    PORT_TYPE             ePortType;
    bool                bIsSection;
    IP_STRUCT           beginPort;
    IP_STRUCT           endPort;
    stPortType():
        ePortType(PORT_TYPE_NULL),
        bIsSection(false)
    {
    }

    stPortType(const stPortType& portType):
        ePortType(PORT_TYPE_NULL),
        bIsSection(false)
    {
        if(!portType.setPort.empty())
            setPort.insert(portType.setPort.begin(), \
                    portType.setPort.end());

        ePortType  = portType.ePortType;
        bIsSection = portType.bIsSection;
        beginPort  = portType.beginPort;
        endPort    = portType.endPort;
    }

    stPortType(stPortType& portType):
        ePortType(PORT_TYPE_NULL),
        bIsSection(false)
    {
        if(!portType.setPort.empty())
            setPort.insert(portType.setPort.begin(), \
                    portType.setPort.end());

        ePortType  = portType.ePortType;
        bIsSection = portType.bIsSection;
        beginPort  = portType.beginPort;
        endPort    = portType.endPort;
    }

    stPortType& operator= (const stPortType& portType)
    {
        if(!portType.setPort.empty())
        {
            this->setPort.insert(portType.setPort.begin(), \
                    portType.setPort.end());
        }

        this->ePortType  = portType.ePortType;
        this->bIsSection = portType.bIsSection;
        this->beginPort  = portType.beginPort;
        this->endPort    = portType.endPort;
        return *this;
    }
}SIEM_PORT_TYPE;

typedef struct stRule
{
    std::set<uint32_t> setPluginID;
    std::set<uint32_t> setPluginSID;
    std::string        strName;
    uint16_t           nReliability;
    uint16_t           nOccurrence;
    uint32_t           nTimeout;
    RULE_TYPE          eRuleType;
    PROTOCOL_TYPE      eProtocolType;
    SIEM_IP_TYPE       srcIP;
    SIEM_IP_TYPE       dstIP;
    SIEM_PORT_TYPE     srcPort;
    SIEM_PORT_TYPE     dstPort;

    stRule():
        strName(""), nReliability(0), nOccurrence(0),
        nTimeout(0), eRuleType(RULE_TYPE_NULL),
        eProtocolType(PROTOCOL_TYPE_ANY)
    {
    }

    stRule(const stRule& rule):
        strName(""), nReliability(0), nOccurrence(0),
        nTimeout(0), eRuleType(RULE_TYPE_NULL),
        eProtocolType(PROTOCOL_TYPE_ANY)
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
        eProtocolType(PROTOCOL_TYPE_ANY)
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
