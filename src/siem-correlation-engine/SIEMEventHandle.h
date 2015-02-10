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

#include <list>
#include <vector>

#include "SIEMPublic.h"
#include "SIEMTreeContainer.hpp"

typedef ::SIEM::CSIEMTreeContainer< ::SIEM::SIEMRule > Directive;
typedef ::SIEM::CSIEMTreeContainer< ::SIEM::SIEMRule > Backlog;

namespace SIEM
{

class CSIEMEventHandle
{
    friend class CSIEMDirectiveHandle;
public:
    CSIEMEventHandle();
    virtual ~CSIEMEventHandle();
public:
    bool                     Start();
    bool                     Join ();
    bool                     Release();
    bool                     MatchDirective(::SIEM::SIEMEvent *pEvent);
    bool                     MatchBacklog(::SIEM::SIEMEvent *pEvent);
    static CSIEMEventHandle *Instance();
private:
    pthread_t m_pthHandle;
    std::vector<Directive *> *m_pvctDirective;
    std::list<Backlog *>     *m_plstBacklog;
private:
    static void *EventHandle(void *p);
    static CSIEMEventHandle *m_pSIEMEventHandle;
    bool MatchIP(uint32_t nSrcIP, SIEM_IP *pRuleIP);
    bool MatchPort(uint16_t nPort, SIEM_PORT *pRulePort);
};

inline CSIEMEventHandle* CSIEMEventHandle::Instance()
{
    if(m_pSIEMEventHandle == NULL)
    {
        m_pSIEMEventHandle = new CSIEMEventHandle();
    }
    return m_pSIEMEventHandle;
}

} /* namespace SIEM */
#endif /* SIEMEVENTHANDLE_H_ */
