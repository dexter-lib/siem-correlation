/**
 *   @file   SIEMRuleHandle.h
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

#ifndef SRC_SIEM_CORRELATION_ENGINE_SIEMRULEHANDLE_H_
#define SRC_SIEM_CORRELATION_ENGINE_SIEMRULEHANDLE_H_

#include <libxml/xmlreader.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/tree.h>

#include "SIEMTreeContainer.hpp"
#include "SIEMPublic.h"

namespace SIEM
{

class CSIEMRuleHandle
{
public:
    CSIEMRuleHandle();
    virtual ~CSIEMRuleHandle();
public:
    void ParseRule(Element<SIEMRule> *pElement, xmlNodePtr pXMLNode);
    void ParseRuleProperties(SIEMRule *pRule, xmlNodePtr pXMLNode);
};

} /* namespace SIEM */

#endif /* SRC_SIEM_CORRELATION_ENGINE_SIEMRULEHANDLE_H_ */
