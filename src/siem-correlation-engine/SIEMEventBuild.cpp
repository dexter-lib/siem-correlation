/**
 *   @file   SIEMEventBuild.cpp
 *   @brief  brief
 *
 *   detail
 *
 *   @internal www.captech.net.cn
 *   author:    root
 *   mail:      zhangpeng@captech.net.cn,developer.zhang.peng@gmail.com
 *   Created:   Nov 30, 2014
 *   Revision:  1.0.0
 *   Compiler:  gcc/g++
 *   Company:   Captech Co., Ltd.
 *   Copyright: Copyright (c) 2014, Captech Co., Ltd.
 *
 * =====================================================================================
 */

#include "SIEMEventBuild.h"

#include <Poco/Logger.h>
#include <Poco/Util/Application.h>

namespace SIEM
{

bool CSIEMEventBuild::ZMQEventBuild(::SIEM::SIEMEvent& event, ::SIEM::SIEMPbMessage& pbMsg)
{
    ::SIEM::SIEMPbMessage_SIEMPbEvent *pPbEvent = NULL;
    pPbEvent = pbMsg.mutable_siem_event();

    Poco::Logger& logger = Poco::Util::Application().instance().logger();

    if(pPbEvent->has_plugin_id_uint32())
    {
        event.nPluginID = pPbEvent->plugin_id_uint32();
    }
    else
    {
        logger.error("event plugin_id is null");
        goto DEFAULT_VALUE_ERROR;
    }

    if(pPbEvent->has_plugin_sid_uint32())
    {
        event.nPluginSID = pPbEvent->plugin_sid_uint32();
    }
    else
    {
        logger.error("event plugin_sid is null");
        goto DEFAULT_VALUE_ERROR;
    }

    if(pPbEvent->has_data_uint32())
    {
        event.tmDate = pPbEvent->data_uint32();
    }
    else
    {
        logger.error("event date is null");
        goto DEFAULT_VALUE_ERROR;
    }

    if(pPbEvent->has_fdata_uint32())
    {
        event.tmFDate = pPbEvent->fdata_uint32();
    }
    else
    {
        logger.error("event fdate is null");
        goto DEFAULT_VALUE_ERROR;
    }

    if(pPbEvent->has_event_type_enum())
    {
        event.enEventType = pPbEvent->event_type_enum();
    }
    else
    {
        logger.error("event type is null");
        goto DEFAULT_VALUE_ERROR;
    }

    if(pPbEvent->has_src_ipv4_uint32())
    {
        event.nSrcIP = pPbEvent->src_ipv4_uint32();
    }
    else
    {
        logger.error("event src IP is null");
        goto DEFAULT_VALUE_ERROR;
    }

    if(pPbEvent->has_dst_ipv4_uint32())
    {
        event.nDstIP = pPbEvent->dst_ipv4_uint32();
    }
    else
    {
        logger.error("event dst IP is null");
        goto DEFAULT_VALUE_ERROR;
    }

    if(pPbEvent->has_device_ipv4_uint32())
    {
        event.nDeviceIP = pPbEvent->device_ipv4_uint32();
    }
    else
    {
        logger.error("event device IP is null");
        goto DEFAULT_VALUE_ERROR;
    }

    if(pPbEvent->has_interface_str())
    {
        event.strInterface = pPbEvent->interface_str();
    }
    else
    {
        logger.error("event interface IP is null");
        goto DEFAULT_VALUE_ERROR;
    }

    if(pPbEvent->has_log_str())
    {
        event.strLog = pPbEvent->log_str();
    }
    else
    {
        logger.error("event log is null");
        goto DEFAULT_VALUE_ERROR;
    }

    if(pPbEvent->has_event_id_str())
    {
        event.strEventID = pPbEvent->event_id_str();
    }
    else
    {
        logger.error("event ID is null");
        goto DEFAULT_VALUE_ERROR;
    }

    if(pPbEvent->has_protocol_type_enum())
    {
        event.enEventProtoType = pPbEvent->protocol_type_enum();
    }

    if(pPbEvent->has_src_port_uint32())
    {
        event.nSrcPort = pPbEvent->src_port_uint32();
    }

    if(pPbEvent->has_dst_port_uint32())
    {
        event.nDstPort = pPbEvent->dst_port_uint32();
    }

    if(pPbEvent->has_snort_sid_uint32())
    {
        event.nSnortSID = pPbEvent->snort_sid_uint32();
    }

    if(pPbEvent->has_snort_cid_uint32())
    {
        event.nSnortCID = pPbEvent->snort_cid_uint32();
    }

    if(pPbEvent->has_priority_uint32())
    {
        event.nPrority = pPbEvent->priority_uint32();
    }

    if(pPbEvent->has_occurrences_uint32())
    {
        event.nOccurrence = pPbEvent->occurrences_uint32();
    }

    if(pPbEvent->has_ctx_str())
    {
        event.strCtx = pPbEvent->ctx_str();
    }

    if(pPbEvent->has_username_str())
    {
        event.strUsername = pPbEvent->username_str();
    }

    if(pPbEvent->has_password_str())
    {
        event.strPassword = pPbEvent->password_str();
    }

    if(pPbEvent->has_filename_str())
    {
        event.strFilename = pPbEvent->filename_str();
    }

    if(pPbEvent->has_userdata1_str())
    {
        event.strUserdata1 = pPbEvent->userdata1_str();
    }

    if(pPbEvent->has_userdata2_str())
    {
        event.strUserdata2 = pPbEvent->userdata2_str();
    }

    if(pPbEvent->has_userdata3_str())
    {
        event.strUserdata3 = pPbEvent->userdata3_str();
    }

    if(pPbEvent->has_userdata4_str())
    {
        event.strUserdata4 = pPbEvent->userdata4_str();
    }

    if(pPbEvent->has_userdata5_str())
    {
        event.strUserdata5 = pPbEvent->userdata5_str();
    }

    if(pPbEvent->has_userdata6_str())
    {
        event.strUserdata6 = pPbEvent->userdata6_str();
    }

    if(pPbEvent->has_userdata7_str())
    {
        event.strUserdata7 = pPbEvent->userdata7_str();
    }

    if(pPbEvent->has_userdata8_str())
    {
        event.strUserdata8 = pPbEvent->userdata8_str();
    }

    if(pPbEvent->has_userdata9_str())
    {
        event.strUserdata9 = pPbEvent->userdata9_str();
    }

    if(pPbEvent->has_sensor_id_str())
    {
        event.strSensorID = pPbEvent->sensor_id_str();
    }

    if(pPbEvent->has_binary_data_str())
    {
        event.strBinaryData = pPbEvent->binary_data_str();
    }

    return true;

DEFAULT_VALUE_ERROR:
        return false;
}

bool CSIEMEventBuild::ThriftEventBuild(::SIEM::SIEMEvent& event, ::SIEM::thrift::SIEMThriftEvent& tEvent)
{

    return true;
}

CSIEMEventBuild::CSIEMEventBuild()
{
    // TODO Auto-generated constructor stub

}

CSIEMEventBuild::~CSIEMEventBuild()
{
    // TODO Auto-generated destructor stub
}

} /* namespace SIEM */
