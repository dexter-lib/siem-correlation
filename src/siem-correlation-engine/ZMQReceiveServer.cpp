/**
 *   @file   ZMQReceiveServer.cpp
 *   @brief  brief
 *
 *   detail
 *
 *   @internal www.captech.net.cn
 *   author:    Zhang peng
 *   mail:      zhangpeng@captech.net.cn,Developer.Zhang.Peng@gmail.com
 *   Created:   Nov 17, 2014
 *   Revision:  1.0.0
 *   Compiler:  gcc/g++
 *   Company:   Captech Co., Ltd.
 *   Copyright: Copyright (c) 2008, Captech Co., Ltd.
 *
 * =====================================================================================
 */

#include "ZMQReceiveServer.h"

#include <Poco/Util/LayeredConfiguration.h>
#include <Poco/Logger.h>

#include <zmq.h>

#include <stdint.h>

namespace SIEM
{

void * CZMQReceiveServer::ThreadFunc(void *p)
{

}

bool CZMQReceiveServer::Start()
{
    pthread_create(&m_ThreadID, NULL, ThreadFunc,(void *)this);
    return true;
}

bool CZMQReceiveServer::Initialize()
{
    //Read zmq config items from config file.
    Poco::Util::LayeredConfiguration & config = Poco::Util::Application::instance().config();
    Poco::Logger & logger = Poco::Util::Application::instance().logger();

    logger.debug("Read zmq config from config file");

    m_nHwm     = config.getInt("sqlevent.zmq.hwm", 200000);
    m_nTimeout = config.getInt("sqlevent.zmq.timeout", 2000000);
    m_strIPC   = config.getString("sqlevent.zmq.bind", "ipc:///tmp/siem-correlation");

    logger.debug(Poco::format("Hwm is %u, timeout is %u ipc address is %s", m_nHwm, m_nTimeout, m_strIPC.c_str()));
    return true;
}

CZMQReceiveServer::CZMQReceiveServer():
 m_nHwm(200000),
 m_strIPC("ipc:///tmp/siem-correlation"),
 m_nTimeout(2000000)
{
    // TODO Auto-generated constructor stub

}

CZMQReceiveServer::~CZMQReceiveServer()
{
    // TODO Auto-generated destructor stub
}

} /* namespace SIEM */
