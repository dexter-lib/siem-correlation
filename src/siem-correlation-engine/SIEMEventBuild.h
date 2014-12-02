/**
 *   @file   SIEMEventBuild.h
 *   @brief  brief
 *
 *   detail
 *
 *   @internal www.captech.net.cn
 *   author:    dexter
 *   mail:      zhangpeng@captech.net.cn,developer.zhang.peng@gmail.com
 *   Created:   Nov 30, 2014
 *   Revision:  1.0.0
 *   Compiler:  gcc/g++
 *   Company:   Captech Co., Ltd.
 *   Copyright: Copyright (c) 2014, Captech Co., Ltd.
 *
 * =====================================================================================
 */

#ifndef SIEMEVENTBUILD_H_
#define SIEMEVENTBUILD_H_

#include <pthread.h>

#include "SIEMMessage.pb.h"
#include "SIEMMessage_types.h"
#include "SIEMPublic.h"

namespace SIEM
{

class CSIEMEventBuild
{
public:
    CSIEMEventBuild();
    virtual ~CSIEMEventBuild();
public:
    bool ZMQEventBuild(::SIEM::SIEMEvent& event, ::SIEM::SIEMPbMessage& pbMsg);
    bool ThriftEventBuild(::SIEM::SIEMEvent& event, const ::SIEM::thrift::SIEMThriftEvent& tEvent);
};

} /* namespace SIEM */

#endif /* SIEMEVENTBUILD_H_ */
