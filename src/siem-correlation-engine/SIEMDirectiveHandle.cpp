/**
 *   @file   SIEMDirectiveHandle.cpp
 *   @brief  brief
 *
 *   detail
 *
 *   @internal www.captech.net.cn
 *   author:    root
 *   mail:      zhangpeng@captech.net.cn,developer.zhang.peng@gmail.com
 *   Created:   Dec 7, 2014
 *   Revision:  1.0.0
 *   Compiler:  gcc/g++
 *   Company:   Captech Co., Ltd.
 *   Copyright: Copyright (c) 2014, Captech Co., Ltd.
 *
 * =====================================================================================
 */

#include "SIEMDirectiveHandle.h"
#include "SIEMRuleHandle.h"
#include "SIEMEventHandle.h"
#include "SIEMTreeContainer.hpp"
#include "SIEMPublic.h"

#include <Poco/Path.h>
#include <Poco/Logger.h>
#include <Poco/Util/Application.h>

#include <boost/lexical_cast.hpp>

#include <string.h>

namespace SIEM
{

bool CSIEMDirectiveHandle::LoadDirectives(const std::string& strPath)
{
    Poco::Logger& logger = Poco::Util::Application::instance().logger();

    xmlSchemaParserCtxtPtr pParserCtxt;
    xmlSchemaPtr pSchema;
    xmlSchemaValidCtxtPtr pValidCtxt;
    xmlDocPtr pDoc;
    xmlParserCtxtPtr pCtx;
    xmlNodePtr root = NULL;
    xmlNodePtr pNode = NULL;


    //Default return value:true
    bool bRt = true;

    if(strPath.size() == 0) return false;

    Poco::Path pathDirective (strPath);

    std::string strValidPath = strPath + pathDirective.separator() + "dt.xsd";
    std::string strDirPath = strPath + pathDirective.separator() + "directives.xml";

    pCtx = xmlNewParserCtxt();

    pParserCtxt = xmlSchemaNewParserCtxt(strValidPath.c_str());
    if(pParserCtxt == NULL)
    {
        bRt = false;
        goto XML_VALIDATE_ERROR;
    }

    pSchema = xmlSchemaParse(pParserCtxt);
    if(pSchema == NULL)
    {
        bRt = false;
        goto XML_VALIDATE_ERROR;
    }

    pValidCtxt = xmlSchemaNewValidCtxt(pSchema);
    if(pValidCtxt == NULL)
    {
        bRt = false;
        goto XML_VALIDATE_ERROR;
    }

    pDoc = xmlCtxtReadFile(pCtx,
                strDirPath.c_str(),\
                NULL,\
                XML_PARSE_DTDVALID | XML_PARSE_NOENT | XML_PARSE_RECOVER \
                | XML_PARSE_NOERROR | XML_PARSE_NOWARNING | XML_PARSE_NOBLANKS \
                | XML_PARSE_DTDATTR);

    if(pDoc == NULL)
    {
        bRt = false;
        goto XML_VALIDATE_ERROR;
    }

    if(xmlSchemaValidateDoc(pValidCtxt, pDoc) != 0)
    {
        logger.error("validate error", __FILE__, __LINE__);
        bRt = false;
        goto XML_VALIDATE_ERROR;
    }

    root = xmlDocGetRootElement(pDoc);
    if(root == NULL || (xmlStrcmp(root->name, BAD_CAST"directives") != 0))
    {
        bRt = false;
        goto XML_VALIDATE_ERROR;
    }

    pNode = root->xmlChildrenNode;
    while(pNode)
    {
        bRt = ParseDirectives(pNode);
        if(!bRt)
            goto XML_VALIDATE_ERROR;
        pNode = pNode->next;
    }

    logger.debug(Poco::format("Directive number is %u", \
            (uint32_t)CSIEMEventHandle::Instance()->m_pvctDirective->size()));

XML_VALIDATE_ERROR:
    xmlSchemaFree(pSchema);
    xmlFreeDoc(pDoc);
    xmlFreeParserCtxt(pCtx);
    xmlSchemaFreeValidCtxt(pValidCtxt);
    return bRt;
}

bool CSIEMDirectiveHandle::ParseDirectives(xmlNodePtr pXMLNode)
{
    Poco::Logger& logger = Poco::Util::Application::instance().logger();

    bool bParseRes = true;
    CSIEMTreeContainer<SIEMRule> *pDirective = NULL;
    xmlChar *pszValue = NULL;
    xmlNodePtr pXMLChildren = NULL;
    Element<SIEMRule> *pElement = NULL;
    CSIEMRuleHandle ruleHandle;

    xmlKeepBlanksDefault(1);

    if(pXMLNode == NULL)
    {
        logger.error("XML node is NULL", __FILE__, __LINE__);
        bParseRes = false;
        goto XML_PARSE_ERROR;
    }

    //Removal of commit and text node
    if(xmlStrcmp(pXMLNode->name, BAD_CAST"text") == 0 || \
            xmlStrcmp(pXMLNode->name, BAD_CAST"comment") == 0)
    {
        return true;
    }

    if(xmlStrcmp(pXMLNode->name, BAD_CAST"directive") != 0)
    {
        logger.error("XML type is invalid", __FILE__, __LINE__);
        printf("pxmlNode->name %s\n", pXMLNode->name);
        bParseRes = false;
        goto XML_PARSE_ERROR;
    }

    pDirective = new CSIEMTreeContainer<SIEMRule>();

    pszValue = xmlGetProp(pXMLNode, BAD_CAST"name");
    if(pszValue != NULL)
    {
        pDirective->m_strName = (char *)pszValue;
        xmlFree(pszValue);
        pszValue = NULL;
    }
    else goto XML_PARSE_ERROR;

    pszValue = xmlGetProp(pXMLNode, BAD_CAST"id");
    if(pszValue != NULL)
    {
        pDirective->m_nID = boost::lexical_cast<uint32_t>((char *)pszValue);
        xmlFree(pszValue);
        pszValue = NULL;
    }
    else goto XML_PARSE_ERROR;

    pszValue = xmlGetProp(pXMLNode, BAD_CAST"priority");
    if(pszValue != NULL)
    {
        pDirective->m_nPriority = boost::lexical_cast<uint32_t>((char *)pszValue);
        xmlFree(pszValue);
        pszValue = NULL;
    }
    else goto XML_PARSE_ERROR;

    //parse root rule ,only one
    pXMLChildren = pXMLNode->children;
    if(xmlStrcmp(pXMLChildren->name, BAD_CAST"rule") != 0 || pXMLChildren->next != NULL)
        goto XML_PARSE_ERROR;

    pElement = new Element<SIEMRule>();
    pDirective->SetCurrentElement(pElement);
    pDirective->SetRootElement(pElement);

    ruleHandle.ParseRule(pElement, pXMLChildren);
    //for test
    if(pElement)
    {
        CSIEMEventHandle::Instance()->m_pvctDirective->push_back(pDirective);
        pDirective->TreeTraversing(pElement);
    }

XML_PARSE_ERROR:
    xmlCleanupParser();
    if(pDirective != NULL && !bParseRes)
    {
        delete pDirective;
        pDirective = NULL;
    }

    if(pElement != NULL && !bParseRes)
    {
        delete pElement;
        pElement = NULL;
    }
    return bParseRes;
}

CSIEMDirectiveHandle::CSIEMDirectiveHandle()
{
}

CSIEMDirectiveHandle::~CSIEMDirectiveHandle()
{
}

} /* namespace SIEM */
