/**
 *   @file   SIEMRuleHandle.cpp
 *   @brief  brief
 *
 *   detail
 *
 *   @internal www.captech.net.cn
 *   author:    root
 *   mail:      zhangpeng@captech.net.cn,developer.zhang.peng@gmail.com
 *   Created:   Dec 28, 2014
 *   Revision:  1.0.0
 *   Compiler:  gcc/g++
 *   Company:   Captech Co., Ltd.
 *   Copyright: Copyright (c) 2014, Captech Co., Ltd.
 *
 * =====================================================================================
 */

#include "SIEMRuleHandle.h"
#include "SIEMTreeContainer.hpp"
#include "SIEMUtil.hpp"

#include <Poco/Logger.h>
#include <Poco/Util/Application.h>

#include <boost/algorithm/string/trim.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/split.hpp>

#include <list>

namespace SIEM
{

void CSIEMRuleHandle::ParseRule(Element<SIEMRule> *pElement, xmlNodePtr pXMLNode)
{
    if(pElement == NULL || pXMLNode == NULL || \
            xmlStrcmp(pXMLNode->name, BAD_CAST"rule"))
        return;

    if(pElement->pData == NULL)
    {
        pElement->pData = new SIEMRule();
        ParseRuleProperties(pElement->pData, pXMLNode);
    }

    xmlNodePtr pNode = pXMLNode->children;

    if(pNode == NULL || pNode->next != NULL || \
            xmlStrcmp(pNode->name, BAD_CAST"rules"))
        return;

    pNode = pNode->children;

    if(pNode != NULL)
    {
        pElement->pChild = new std::list<Element<SIEMRule> *>();

        while(pNode!= NULL)
        {
            Element<SIEMRule> *pChildren = new Element<SIEMRule>();
            pElement->pChild->push_back(pChildren);
            ParseRule(pChildren, pNode);
            pNode = pNode->next;
        }
    }
    else
    {
        return;
    }
}

void CSIEMRuleHandle::ParseRuleProperties(SIEMRule *pRule, xmlNodePtr pXMLNode)
{
    Poco::Logger & logger = Poco::Util::Application::instance().logger();

    xmlChar *pszValue = NULL;

    try
    {
        pszValue = xmlGetProp(pXMLNode, BAD_CAST"name");
        if(pszValue)
        {
            pRule->strName = (char *)pszValue;
            xmlFree(pszValue);
            pszValue = NULL;
        }

        pszValue = xmlGetProp(pXMLNode, BAD_CAST"type");
        if(pszValue)
        {
            if(strcmp("detector", (char *)pszValue) == 0)
            {
                pRule->eRuleType = RULE_TYPE_DETECTOR;
            }
            else if(strcmp("monitor", (char *)pszValue) == 0)
            {
                pRule->eRuleType = RULE_TYPE_MONITOR;
            }
            else
            {
                pRule->eRuleType = RULE_TYPE_NULL;
            }
            xmlFree(pszValue);
            pszValue = NULL;
        }
        else
        {
            pRule->eRuleType = RULE_TYPE_NULL;
        }

        pszValue = xmlGetProp(pXMLNode, BAD_CAST"protocol");
        if(pszValue)
        {
            if(strcasecmp("TCP", (char *)pszValue) == 0)
            {
                pRule->eProtocolType = SIEM_PROTOCOL_TCP;
            }
            else if(strcasecmp("UDP", (char *)pszValue) == 0)
            {
                pRule->eProtocolType = SIEM_PROTOCOL_UDP;
            }
            else
            {
                pRule->eProtocolType = SIEM_PROTOCOL_ANY;
            }
            xmlFree(pszValue);
            pszValue = NULL;
        }
        else
        {
            pRule->eProtocolType = SIEM_PROTOCOL_ANY;
        }

        pszValue = xmlGetProp(pXMLNode, BAD_CAST"reliability");
        if(pszValue)
        {
            pRule->nReliability = boost::lexical_cast<uint32_t>((char *)pszValue);
            xmlFree(pszValue);
            pszValue = NULL;
        }

        pszValue = xmlGetProp(pXMLNode, BAD_CAST"occurrence");
        if(pszValue)
        {
            pRule->nOccurrence = boost::lexical_cast<uint32_t>((char *)pszValue);
            xmlFree(pszValue);
            pszValue = NULL;
        }

        pszValue = xmlGetProp(pXMLNode, BAD_CAST"time_out");
        if(pszValue)
        {
            pRule->nTimeout = boost::lexical_cast<uint32_t>((char *)pszValue);
            xmlFree(pszValue);
            pszValue = NULL;
        }

        pszValue = xmlGetProp(pXMLNode, BAD_CAST"plugin_id");
        if(pszValue)
        {
            std::string strPluginID((char *)pszValue);
            SIEM::Util::ParseString(strPluginID, &pRule->setPluginID);
            xmlFree(pszValue);
            pszValue = NULL;
        }

        pszValue = xmlGetProp(pXMLNode, BAD_CAST"plugin_sid");
        if(pszValue)
        {
            std::string strPluginSID((char *)pszValue);
            SIEM::Util::ParseString(strPluginSID, &pRule->setPluginSID);
            xmlFree(pszValue);
            pszValue = NULL;
        }

        pszValue = xmlGetProp(pXMLNode, BAD_CAST"from");
        if(pszValue)
        {
            std::string strSrcIP((char *)pszValue);
            SIEM::Util::ParseIPStr(strSrcIP, &pRule->srcIP);
            xmlFree(pszValue);
            pszValue = NULL;
        }

        pszValue = xmlGetProp(pXMLNode, BAD_CAST"to");
        if(pszValue)
        {
            std::string strDstIP((char *)pszValue);
            SIEM::Util::ParseIPStr(strDstIP, &pRule->dstIP);
            xmlFree(pszValue);
            pszValue = NULL;
        }

        pszValue = xmlGetProp(pXMLNode, BAD_CAST"port_from");
        if(pszValue)
        {
            std::string strSrcPort((char *)pszValue);
            SIEM::Util::ParsePortStr(strSrcPort, &pRule->srcPort);
            xmlFree(pszValue);
            pszValue = NULL;
        }

        pszValue = xmlGetProp(pXMLNode, BAD_CAST"port_to");
        if(pszValue)
        {
            std::string strDstPort((char *)pszValue);
            SIEM::Util::ParsePortStr(strDstPort, &pRule->dstPort);
            xmlFree(pszValue);
            pszValue = NULL;
        }
    }
    catch (boost::bad_lexical_cast &e)
    {
        logger.error("bad_lexical_cast error", __FILE__, __LINE__);
    }

    return;
}

CSIEMRuleHandle::CSIEMRuleHandle()
{
    // TODO Auto-generated constructor stub

}

CSIEMRuleHandle::~CSIEMRuleHandle()
{
    // TODO Auto-generated destructor stub
}

} /* namespace SIEM */
