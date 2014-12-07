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

static CSIEMDirectiveHandle* CSIEMDirectiveHandle::m_pDirectiveHandle = NULL;

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
