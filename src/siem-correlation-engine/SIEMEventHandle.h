/**
 *   @file   SIEMEventHandle.h
 *   @brief  brief
 *
 *   detail
 *
 *   @internal www.captech.net.cn
 *   author:    Zhang peng
 *   mail:      zhangpeng@captech.net.cn,Developer.Zhang.Peng@gmail.com
 *   Created:   Dec 3, 2014
 *   Revision:  1.0.0
 *   Compiler:  gcc/g++
 *   Company:   Captech Co., Ltd.
 *   Copyright: Copyright (c) 2008, Captech Co., Ltd.
 *
 * =====================================================================================
 */

#ifndef SIEMEVENTHANDLE_H_
#define SIEMEVENTHANDLE_H_

#include <pthread.h>

namespace SIEM
{

class CSIEMEventHandle
{
public:
    CSIEMEventHandle();
    virtual ~CSIEMEventHandle();
public:
    bool Start();
    bool Join ();
private:
    pthread_t m_pthHandle;
private:
    static void *EventHandle(void *p);
};

} /* namespace SIEM */
#endif /* SIEMEVENTHANDLE_H_ */
