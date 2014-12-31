/**
 *   @file   SIEMDirectiveHandle.h
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

#ifndef SRC_SIEM_CORRELATION_ENGINE_SIEMDIRECTIVEHANDLE_H_
#define SRC_SIEM_CORRELATION_ENGINE_SIEMDIRECTIVEHANDLE_H_

#include <boost/noncopyable.hpp>

#include <stddef.h>
#include <libxml/xmlreader.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/tree.h>

#include <string>

namespace SIEM
{

class CSIEMDirectiveHandle
{
public:
    CSIEMDirectiveHandle();
    virtual ~CSIEMDirectiveHandle();
public:
    bool LoadDirectives(const std::string& strPath);
private:
    bool ParseDirectives(xmlNodePtr pXMLNode);
};

} /* namespace SIEM */

#endif /* SRC_SIEM_CORRELATION_ENGINE_SIEMDIRECTIVEHANDLE_H_ */
