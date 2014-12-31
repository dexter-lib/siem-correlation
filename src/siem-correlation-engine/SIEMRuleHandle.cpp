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

#include <Poco/Logger.h>
#include <Poco/Util/Application.h>

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
    xmlChar *pszValue = NULL;
    pszValue = xmlGetProp(pXMLNode, BAD_CAST"name");

    if(pszValue)
    {
        pRule->strName = (char *)pszValue;
        xmlFree(pszValue);
        pszValue = NULL;
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
