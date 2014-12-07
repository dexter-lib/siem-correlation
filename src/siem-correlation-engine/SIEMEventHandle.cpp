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

bool CSIEMEventHandle::Start()
{
    Poco::Logger & logger = Poco::Util::Application::instance().logger();

    pthread_attr_t thread_attr;
    struct sched_param thread_param;
    int thread_policy, status, rr_min_priority, rr_max_priority;

    pthread_attr_init(&thread_attr);

#if defined(_POSIX_THREAD_PRIORITY_SCHEDULING)
    pthread_attr_getschedpolicy(&thread_attr, &thread_policy);
    pthread_attr_getschedparam(&thread_attr, &thread_param);
    status = pthread_attr_setschedpolicy(&thread_attr, SCHED_RR);
    if(status != 0)
    {
        logger.debug("Unable to set schedpolicy");
    }
    else
    {
        rr_min_priority = sched_get_priority_min(SCHED_RR);
        if(rr_min_priority == -1)
        {
            logger.debug("Get SCHED_RR min priority");
            goto THREAD_START;
        }
        rr_max_priority = sched_get_priority_max(SCHED_RR);
        if(rr_max_priority == -1)
        {
            logger.debug("Get SCHED_RR max priority");
            goto THREAD_START;
        }
        thread_param.__sched_priority = (rr_max_priority + rr_min_priority)/2;
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

CSIEMEventHandle::CSIEMEventHandle()
{
    // TODO Auto-generated constructor stub

}

CSIEMEventHandle::~CSIEMEventHandle()
{
    // TODO Auto-generated destructor stub
}

} /* namespace SIEM */
