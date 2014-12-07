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

namespace SIEM
{

CSIEMDirectiveHandle* CSIEMDirectiveHandle::m_pDirectiveHandle = NULL;

bool CSIEMDirectiveHandle::LoadDirectives(const std::string& strPath)
{
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
                | XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
    if(pDoc == NULL)
    {
        bRt = false;
        goto XML_VALIDATE_ERROR;
    }

    if(xmlSchemaValidateDoc(pValidCtxt, pDoc) != 0)
    {
        std::cout << "validate error" <<std::endl;
        bRt = false;
        goto XML_VALIDATE_ERROR;
    }

    root = xmlDocGetRootElement(pDoc);
    if(root == NULL || (strcmp((char *)root->name, "directives") != 0))
    {
        bRt = false;
        goto XML_VALIDATE_ERROR;
    }

    pNode = root->xmlChildrenNode;
    while(pNode)
    {
        bRt = ParseDirectives(pNode);
        pNode = pNode->next;
    }

XML_VALIDATE_ERROR:
    xmlSchemaFree(pSchema);
    xmlFreeDoc(pDoc);
    xmlFreeParserCtxt(pCtx);
    xmlSchemaFreeValidCtxt(pValidCtxt);
    return bRt;
}

bool CSIEMDirectiveHandle::ParseDirectives(xmlNodePtr pXMLNode)
{
    return true;
}

CSIEMDirectiveHandle::CSIEMDirectiveHandle()
{
}

CSIEMDirectiveHandle::~CSIEMDirectiveHandle()
{
    if(m_pDirectiveHandle)
    {
        delete m_pDirectiveHandle;
        m_pDirectiveHandle = NULL;
    }
}

} /* namespace SIEM */
