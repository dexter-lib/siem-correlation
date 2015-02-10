/**
 *   @file   SIEMEventHandle.cpp
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

#include "SIEMEventHandle.h"
#include "SIEMPublic.h"
#include "SIEMUtil.hpp"

#include <Poco/Util/Application.h>
#include <Poco/Logger.h>

#include <boost/foreach.hpp>

#include <sched.h>

extern ::SIEM::SIEMEventVctPtr g_vctSIEMEventPtr;
extern pthread_mutex_t         g_mutEvent;

namespace SIEM
{

CSIEMEventHandle * CSIEMEventHandle::m_pSIEMEventHandle = NULL;

bool CSIEMEventHandle::Start()
{
    Poco::Logger & logger = Poco::Util::Application::instance().logger();

    pthread_attr_t thread_attr;
    struct sched_param thread_param;
    int thread_policy, status, fifo_min_priority, fifo_max_priority;

    pthread_attr_init(&thread_attr);

#if defined(_POSIX_THREAD_PRIORITY_SCHEDULING)
    pthread_attr_getschedpolicy(&thread_attr, &thread_policy);
    pthread_attr_getschedparam(&thread_attr, &thread_param);
    status = pthread_attr_setschedpolicy(&thread_attr, SCHED_FIFO);
    if(status != 0)
    {
        logger.debug("Unable to set schedpolicy");
    }
    else
    {
        fifo_min_priority = sched_get_priority_min(SCHED_FIFO);
        if(fifo_min_priority == -1)
        {
            logger.debug("Get SCHED_RR min priority");
            goto THREAD_START;
        }
        fifo_max_priority = sched_get_priority_max(SCHED_FIFO);
        if(fifo_max_priority == -1)
        {
            logger.debug("Get SCHED_RR max priority");
            goto THREAD_START;
        }
        thread_param.__sched_priority = (fifo_max_priority + fifo_min_priority)/2;
        pthread_attr_setschedparam(&thread_attr, &thread_param);
        pthread_attr_setinheritsched(&thread_attr, PTHREAD_EXPLICIT_SCHED);
    }
#else
    logger.debug("Priority setting not supports\n");
#endif

THREAD_START:
    if(pthread_create(&m_pthHandle, &thread_attr, EventHandle, NULL))
    {
        logger.error("Create SIEMEvent handle error!", __FILE__, __LINE__);
        return false;
    }

    int nCPUNum = sysconf(_SC_NPROCESSORS_ONLN);
    //CPU core number greater than 2 then set affinity
    if(nCPUNum >= 2)
    {
        //The thread bound to a final CPU core
        if(!::SIEM::Util::SetThreadCPU(m_pthHandle, nCPUNum - 1))
        {
            logger.debug("Set cpu affinity false");
        }
    }
    else
    {
        logger.debug("CPU core number less than 2");
    }
    return true;
}

bool CSIEMEventHandle::MatchDirective(::SIEM::SIEMEvent *pEvent)
{
    Poco::Logger & logger = Poco::Util::Application::instance().logger();

    if(pEvent == NULL)
    {
        logger.debug("Event is NULL");
        return false;
    }

    if(m_pvctDirective == NULL || m_pvctDirective->empty())
    {
        logger.debug("Directive is NULL");
        return false;
    }

    BOOST_FOREACH(Directive *pDirective, *m_pvctDirective)
    {
        Element<SIEMRule> *pRoot = pDirective->GetRootElement();

        SIEMRule *pRule = pRoot->pData;

        if(pRule->eProtocolType != pEvent->enEventProtoType)
            continue;
        if(pRule->setPluginID.find(pEvent->nPluginID  ) == \
                pRule->setPluginID.end())
            continue;
        if(pRule->setPluginSID.find(pEvent->nPluginSID) == \
                pRule->setPluginSID.end())
            continue;
        if(!MatchIP(pEvent->nSrcIP, &pRule->srcIP))
            continue;
        if(!MatchIP(pEvent->nDstIP, &pRule->dstIP))
            continue;
        if(!MatchPort(pEvent->nSrcPort, &pRule->srcPort))
            continue;
        if(!MatchPort(pEvent->nDstPort, &pRule->dstPort))
            continue;
    }

    return true;
}

bool CSIEMEventHandle::MatchIP(uint32_t nIP, SIEM_IP *pRuleIP)
{

    if(NULL == pRuleIP) return false;
    if(pRuleIP->bAny) return true;

    in_addr addr;
    addr.s_addr = nIP;
    std::string strIP = inet_ntoa(addr);

    if(!pRuleIP->ipNotSet.empty() && \
            pRuleIP->ipNotSet.find(strIP) != pRuleIP->ipNotSet.end())
        return false;
    if(!pRuleIP->ipSet.empty() && \
            pRuleIP->ipSet.find(strIP) == pRuleIP->ipSet.end())
        return false;

    return true;
}

bool CSIEMEventHandle::MatchPort(uint16_t nPort, SIEM_PORT *pRulePort)
{
    if(pRulePort == NULL) return false;

    if(pRulePort->bAny) return true;

    if(!pRulePort->portNotSet.empty() && \
            pRulePort->portNotSet.find(nPort) != pRulePort->portSet.end())
        return false;
    if(!pRulePort->portSet.empty() && \
            pRulePort->portSet.find(nPort) == pRulePort->portSet.end())
        return false;

    return true;
}

void* CSIEMEventHandle::EventHandle(void *p)
{
    Poco::Logger & logger = Poco::Util::Application::instance().logger();

    //Init empty vector for swap
    SIEMEventVctPtr vct_ptr(new std::vector<SIEMEventPtr>());
    vct_ptr->clear();

    while(true)
    {
        pthread_testcancel();
        pthread_mutex_lock(&g_mutEvent);
        if(g_vctSIEMEventPtr->empty())
        {
            pthread_mutex_unlock(&g_mutEvent);
            sleep(5);
            logger.debug("No event data container");
            continue;
        }

        g_vctSIEMEventPtr->swap(*vct_ptr);
        pthread_mutex_unlock(&g_mutEvent);

        //for
        BOOST_FOREACH(::SIEM::SIEMEventPtr event, *vct_ptr)
        {
        }
        //clear handled events
        vct_ptr->clear();
    }
    return (void *)0;
}

bool CSIEMEventHandle::Join()
{
    Poco::Logger & logger = Poco::Util::Application::instance().logger();

    void *pRet;
    if(!pthread_join(m_pthHandle, &pRet))
    {
        logger.error("Join SIEMEvent handle thread error", __FILE__, __LINE__);
        return false;
    }
    return true;
}

bool CSIEMEventHandle::Release()
{
    Poco::Logger & logger = Poco::Util::Application::instance().logger();

    if(m_pvctDirective != NULL)
    {
        if(m_pvctDirective->size() > 0)
        {
            BOOST_FOREACH(Directive *p, *m_pvctDirective)
            {
                delete p;
                p = NULL;
            }
            m_pvctDirective->clear();
        }
        delete m_pvctDirective;
        m_pvctDirective = NULL;
    }

    if(m_plstBacklog != NULL)
    {
        if(m_plstBacklog->size() > 0)
        {
            BOOST_FOREACH(Backlog *p, *m_plstBacklog)
            {
                delete p;
                p = NULL;
            }
            m_plstBacklog->clear();
        }
        delete m_plstBacklog;
        m_plstBacklog = NULL;
    }

    if(!pthread_cancel(m_pthHandle))
    {
        logger.error("Exit event handle thread failure", __FILE__, __LINE__);
        return false;
    }
    return true;
}

CSIEMEventHandle::CSIEMEventHandle()
:m_pvctDirective(new std::vector<Directive *>()),
 m_plstBacklog  (new std::list  <Backlog *>())
{
    // TODO Auto-generated constructor stub
}

CSIEMEventHandle::~CSIEMEventHandle()
{
}

} /* namespace SIEM */
