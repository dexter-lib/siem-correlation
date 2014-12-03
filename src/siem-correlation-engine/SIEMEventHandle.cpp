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

#include <Poco/Util/Application.h>
#include <Poco/Logger.h>

#include <boost/foreach.hpp>

extern ::SIEM::SIEMEventVctPtr g_vctSIEMEventPtr;
extern pthread_mutex_t         g_mutEvent;

namespace SIEM
{

bool CSIEMEventHandle::Start()
{
    Poco::Logger & logger = Poco::Util::Application::instance().logger();

    if(pthread_create(&m_pthHandle, NULL, EventHandle, NULL))
    {
        logger.error("Create SIEMEvent handle error!", __FILE__, __LINE__);
        return false;
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
