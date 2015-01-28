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

#include <Poco/Util/Application.h>
#include <Poco/Logger.h>

#include <pthread.h>
#include <arpa/inet.h>

#include "SIEMPublic.h"
#include "SIEMConst.h"

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
static void ParseString(std::string& strSource, std::set<T> *pSet, \
        const std::string& strSplit = ",")
{
    std::vector<std::string> vecStr;
    boost::algorithm::split(vecStr, strSource, boost::algorithm::is_any_of(strSplit));
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

__UTIL_UNUSED__
static bool IsIPV4Format(std::string strIP)
{
    std::set<uint16_t> s;
    const std::string split = ",";
    ParseString(strIP, &s, split);

    if(s.size() != 4)
        return false;

    BOOST_FOREACH(uint16_t b, s)
    {
        if(b >= 255)
            return false;
    }

    return true;
}

__UTIL_UNUSED__
static bool IsIPV6Format(std::string& strIP)
{
    static char addr[39];
    memset(addr, 0, sizeof(addr));

    int v = inet_pton(AF_INET6, strIP.c_str(), (void *)addr);

    if(!v)
        return false;

    return true;
}

template <typename T>
static bool StringToInt(const char *pszValue, T& value)
{
    if(!pszValue)
        return false;

    try
    {
        std::string str(pszValue);
        value = boost::lexical_cast<T>(str);
    }
    catch (boost::bad_lexical_cast &e)
    {
        return false;
    }
    catch(...)
    {
        return false;
    }

    return true;
}

//this code so ugly
__UTIL_UNUSED__
static bool ParseIPStr(std::string& strIP, SIEM_IP *pIP)
{
    Poco::Logger & logger = Poco::Util::Application::instance().logger();

    if(strIP.empty())
    {
        logger.error("IP string is empty", __FILE__, __LINE__);
        return false;
    }

    if(!pIP)
    {
        logger.error("IP struct is empty", __FILE__, __LINE__);
        return false;
    }

    std::vector<std::string> vctStr;
    boost::algorithm::split(vctStr, strIP, \
            boost::algorithm::is_any_of(SIEM_DELIMITER_LIST));

    BOOST_FOREACH(std::string str, vctStr)
    {
        boost::algorithm::trim(str);

        bool bIPNeg = false;
        if(str[0] == SIEM_DELIMITER_NOT)
        {
            bIPNeg = true;
            str.assign(str.begin() + 1, str.end());
        }

        IPVar ipVar;
        size_t nIndex;
        if((nIndex = str.find(SIEM_DELIMITER_LEVEL)) != str.npos && \
                (str.find(SIEM_SRC_IP_CONST) != str.npos ||\
                 str.find(SIEM_DST_IP_CONST) != str.npos))
        {
            if(StringToInt(str.substr(0, nIndex).c_str(),ipVar.nLevel))
            {
                logger.error("ip level lexcast error", __FILE__, __LINE__);
                continue;
            }
            str.assign(str.begin() + nIndex + 1, str.end());
            if(str == SIEM_SRC_IP_CONST)
            {
                ipVar.eIPType = IP_TYPE_SRC_IP;
            }
            else if(str == SIEM_DST_IP_CONST)
            {
                ipVar.eIPType = IP_TYPE_DST_IP;
            }
            else
            {
                logger.debug(Poco::format("A IP type is not recognized:%s",\
                        str), __FILE__, __LINE__);
                continue;
            }

            if(bIPNeg)
                pIP->varNotSet.insert(ipVar);
            else
                pIP->varSet.insert(ipVar);
        }
        else if(str == SIEM_HOME_NET_CONST)
        {
            ipVar.eIPType = IP_TYPE_HOME_NET;
            if(bIPNeg)
                pIP->varNotSet.insert(ipVar);
            else
                pIP->varSet.insert(ipVar);
        }
        else if(str == SIEM_WILDCARD_ANY)
        {
            if(!bIPNeg)
            {
                pIP->bAny = true;
                return true;
            }
            else
            {
                logger.error("\"ANY\" type can not be opposite");
                return false;
            }
        }
        else
        {
            if(!IsIPV4Format(str) && !IsIPV6Format(str))
            {
                logger.error(Poco::format("IP type is wrong:%s",\
                        str), __FILE__, __LINE__);
                continue;
            }

            if(bIPNeg)
                pIP->ipSet.insert(str);
            else
                pIP->ipNotSet.insert(str);
        }
    }

    return true;
}

__UTIL_UNUSED__
static bool ParsePortStr(std::string& strPort, SIEM_PORT *pPort)
{
    Poco::Logger & logger = Poco::Util::Application::instance().logger();

    if(strPort.empty())
    {
        logger.error("Port string is empty", __FILE__, __LINE__);
        return false;
    }

    if(!pPort)
    {
        logger.error("Port struct is empty", __FILE__, __LINE__);
        return false;
    }

    std::vector<std::string> vctStr;
    boost::algorithm::split(vctStr, strPort, \
            boost::algorithm::is_any_of(SIEM_DELIMITER_LIST));
    BOOST_FOREACH(std::string str, vctStr)
    {
        boost::algorithm::trim(str);

        bool bPortNeg = false;
        if(str[0] == SIEM_DELIMITER_NOT)
        {
            bPortNeg = true;
            str.assign(str.begin() + 1, str.end());
        }

        PortVar portVar;
        size_t nIndex;
        if((nIndex = str.find(SIEM_DELIMITER_LEVEL)) != str.npos && \
                (str.find(SIEM_SRC_PORT_CONST) != str.npos ||\
                 str.find(SIEM_DST_PORT_CONST) != str.npos))
        {
            if(StringToInt(str.substr(0, nIndex).c_str(), portVar.nLevel))
            {
                logger.error("port Level lexcast error");
                continue;
            }
            str.assign(str.begin() + nIndex + 1, str.end());
            if(str == SIEM_SRC_PORT_CONST)
            {
                portVar.ePortType = PORT_TYPE_SRC_PORT;
            }
            else if(str == SIEM_DST_PORT_CONST)
            {
                portVar.ePortType = PORT_TYPE_DST_PORT;
            }
            else
            {
                logger.debug(Poco::format("A port type is not recognized:%s",\
                        str), __FILE__, __LINE__);
                continue;
            }

            if(bPortNeg)
                pPort->varNotSet.insert(portVar);
            else
                pPort->varSet.insert(portVar);
        }
        else if((nIndex = str.find(SIEM_DELIMITER_RANGE)) != str.npos)
        {
            uint16_t nPortBegin = 0, nPortEnd = 0;
            if(!StringToInt(str.substr(0, nIndex).c_str(), nPortBegin))
            {
                logger.error("from port lexcast error", __FILE__, __LINE__);
                continue;
            }

            if(!StringToInt(str.substr(nIndex + 1, str.length() - nIndex -1).c_str(), \
                    nPortEnd))
            {
                logger.error("To port lexcast error", __FILE__, __LINE__);
                continue;
            }

            if(nPortBegin > nPortEnd)
            {
                logger.debug("Port Range error", __FILE__, __LINE__);
                continue;
            }

            std::set<uint16_t> *pPortSet = NULL;
            if(bPortNeg)
                pPortSet = &(pPort->portNotSet);
            else
                pPortSet = &(pPort->portSet);

            for(uint16_t i = 0; i <= nPortEnd; i++)
                pPortSet->insert(i);
        }
        else if((nIndex = str.find(SIEM_WILDCARD_ANY)) != str.npos)
        {
            if(!bPortNeg)
            {
                pPort->bAny = true;
                return true;
            }
            else
            {
                logger.error("\"ANY\" type can not be opposite");
                return false;
            }
        }
        else
        {
            uint16_t nPort = 0;
            if(StringToInt(str.c_str(), nPort))
            {
                logger.debug(Poco::format("Port lexcast error:%s",\
                        str), __FILE__, __LINE__);
                continue;
            }

            if(bPortNeg)
                pPort->portNotSet.insert(nPort);
            else
                pPort->portSet.insert(nPort);
        }
    }

    return true;
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
