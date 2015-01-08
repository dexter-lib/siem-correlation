/**
 *   @file   SIEMUtil.hpp
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

#ifndef SIEMUTIL_HPP_
#define SIEMUTIL_HPP_

#include <thrift/protocol/TBinaryProtocol.h>
#include <thrift/transport/TServerSocket.h>
#include <thrift/transport/TBufferTransports.h>

#include <boost/foreach.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/split.hpp>

#include <pthread.h>
#include <arpa/inet.h>

#include "SIEMPublic.h"

#ifdef __GNUC__
#    define __UTIL_UNUSED__ __attribute__ ((unused))
#else
#    define __UTIL_UNUSED__
#endif

namespace SIEM
{
namespace Util
{

//thrift serialize
template<typename ThriftStruct>
static bool StringToThrift(const std::string& buff, \
        ThriftStruct* ts)
{
    using namespace apache::thrift::transport;
    using namespace apache::thrift::protocol;
    TMemoryBuffer* buffer = new TMemoryBuffer;
    buffer->write((const uint8_t*)buff.data(), buff.size());
    boost::shared_ptr<TTransport> trans(buffer);
    TBinaryProtocol protocol(trans);
    ts->read(&protocol);
    return true;
}

//thrift deserialize
template<typename ThriftStruct>
static std::string  ThriftToString(const ThriftStruct& ts)
{
    using namespace apache::thrift::transport;
    using namespace apache::thrift::protocol;
    TMemoryBuffer* buffer = new TMemoryBuffer;
    boost::shared_ptr<TTransport> trans(buffer);
    TBinaryProtocol protocol(trans);
    ts.write(&protocol);
    uint8_t* buf;
    uint32_t size;
    buffer->getBuffer(&buf, &size);
    return std::string((char*)buf, (unsigned int)size);
}

__UTIL_UNUSED__
static bool SetThreadCPU(pthread_t pthID, u_int32_t nCPUNum)
{
    cpu_set_t mask;
    cpu_set_t get;

    CPU_ZERO(&mask);
    CPU_SET(nCPUNum, &mask);
    if (pthread_setaffinity_np(pthID, sizeof(mask), &mask) < 0) return false;

    CPU_ZERO(&get);
    if (pthread_getaffinity_np(pthID, sizeof(get), &get) < 0) return false;
    if (CPU_ISSET(nCPUNum, &get)) return true;

    return false;
}

template<typename T>
static void ParseString(std::string& strSource, std::set<T> *pSet)
{
    std::vector<std::string> vecStr;
    boost::algorithm::split(vecStr, strSource, boost::algorithm::is_any_of(","));
    BOOST_FOREACH(std::string& strValue, vecStr)
    {
        try
        {
            boost::trim(strValue);
            T nValue = boost::lexical_cast<T, std::string>(strValue);
            pSet->insert(nValue);
        }
        catch (boost::bad_lexical_cast& e)
        {
            continue;
        }
    }
}

//this code so ugly
__UTIL_UNUSED__
static bool ParseIPStr(std::string& strIP, SIEM_IP_TYPE *pIP)
{
    if(strcmp(strIP.c_str(), "ANY") == 0)
    {
        pIP->eIPType = IP_TYPE_ANY;
        return true;
    }
    else if(strIP.find("HOME_NET") != strIP.npos)
    {
        if(strIP[0] == '!') pIP->bIsNot = true;
        pIP->eIPType = IP_TYPE_HOME_NET;
        return true;
    }
    else if(strIP.find("SRC_IP") != strIP.npos)
    {
        if(strIP[0] == '!') pIP->bIsNot = true;
        pIP->eIPType = IP_TYPE_SRC_IP;
        return true;
    }
    else if(strIP.find("DST_IP") != strIP.npos)
    {
        if(strIP[0] == '!') pIP->bIsNot = true;
        pIP->eIPType = IP_TYPE_DST_IP;
        return true;
    }
    else if(strIP.find("-") != strIP.npos)
    {
        pIP->bIsSection = true;
        std::vector<std::string> vctStr;
        boost::algorithm::split(vctStr, strIP, boost::algorithm::is_any_of("-"));
        BOOST_FOREACH(std::string str, vctStr)
        {
            boost::algorithm::trim(str);
        }

        if(vctStr.size() != 2)
            return false;
        pIP->beginIP.nIPV4 = ntohl(inet_addr(vctStr[0].c_str()));
        pIP->endIP.nIPV4   = ntohl(inet_addr(vctStr[1].c_str()));
        return true;
    }
    else
    {
        std::set<std::string> ips;
        ParseString(strIP, &ips);
        BOOST_FOREACH(std::string strIP, ips)
        {
            if(strIP.empty() || strIP.length() <= 1)
                continue;
            IP_STRUCT ip;
            if(strIP[0] == '!')
            {
                ip.bIsNot = true;
                strIP.assign(strIP.begin() + 1, strIP.end());
            }
            ip.nIPV4 = ntohl(inet_addr(strIP.c_str()));
            pIP->setIPV4.insert(ip);
        }
        return true;
    }
}

__UTIL_UNUSED__
static bool ParsePortStr(std::string& strPort, SIEM_PORT_TYPE *pPort)
{
    if(strcmp(strPort.c_str(), "ANY") == 0)
    {
        pPort->ePortType = PORT_TYPE_ANY;
        return true;
    }
    else if(strPort.find("SRC_PORT") != strPort.npos)
    {
        if(strPort[0] == '!') pPort->bIsNot = true;
        pPort->ePortType = PORT_TYPE_SRC_PORT;
        return true;
    }
    else if(strPort.find("DST_PORT") != strPort.npos)
    {
        if(strPort[0] == '!') pPort->bIsNot = true;
        pPort->ePortType = PORT_TYPE_DST_PORT;
        return true;
    }
    else if(strPort.find("-") != strPort.npos)
    {
        pPort->bIsSection = true;
        std::vector<std::string> vctStr;
        boost::algorithm::split(vctStr, strPort, boost::algorithm::is_any_of("-"));
        BOOST_FOREACH(std::string str, vctStr)
        {
            boost::algorithm::trim(str);
        }

        if(vctStr.size() != 2)
            return false;

        pPort->beginPort.nPort = boost::lexical_cast<uint16_t>(vctStr[0]);
        pPort->endPort.nPort   = boost::lexical_cast<uint16_t>(vctStr[1]);
        return true;
    }
    else
    {
        std::set<std::string> setPort;
        ParseString(strPort, &setPort);
        BOOST_FOREACH(std::string strPort, setPort)
        {
            if(strPort.empty() || strPort.length() <= 1)
                continue;
            PORT_STRUCT port;
            if(strPort[0] == '!')
            {
                port.bIsNot = true;
                strPort.assign(strPort.begin() + 1, strPort.end());
            }
            port.nPort = boost::lexical_cast<uint16_t>(strPort);
            pPort->setPort.insert(port);
        }
        return true;
    }
}

__UTIL_UNUSED__
static bool IsHomeNet(uint32_t nIP)
{
    if((nIP > 167772160 && nIP < 184549375) || \
            (nIP > 2886729728 && nIP < 2886737919) || \
            (nIP > 3232235520 && nIP < 3232301055))
        return true;
    return false;
}
} /* namespace Util */
} /* namespace SIEM */
#endif /* SIEMUTIL_HPP_ */
