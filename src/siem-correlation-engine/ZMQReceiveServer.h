/**
 *   @file   ZMQReceiveServer.h
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

#ifndef ZMQRECEIVESERVER_H_
#define ZMQRECEIVESERVER_H_

#include "IReceiveServer.h"

namespace SIEM
{

class CZMQReceiveServer: public SIEM::IReceiveServer
{
public:
    CZMQReceiveServer();
    virtual ~CZMQReceiveServer();
public:
    bool Start();
    bool Initialize();
    bool Handle(char * pszMsg, size_t size);
private:
    static void *ThreadFunc(void *p);
public:
    uint64_t     m_nHwm;
    std::string  m_strIPC;
    uint32_t     m_nTimeout;
};

} /* namespace SIEM */
#endif /* ZMQRECEIVESERVER_H_ */
