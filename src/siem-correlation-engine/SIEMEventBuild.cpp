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
    Poco::Logger& logger = Poco::Util::Application().instance().logger();

     if(tEvent.plugin_id_int32 > 0)
     {
         event.nPluginID = tEvent.plugin_id_int32;
     }
     else
     {
         logger.error("event plugin_id is null");
         goto DEFAULT_VALUE_ERROR;
     }

     if(tEvent.plugin_sid_int32 > 0)
     {
         event.nPluginSID = tEvent.plugin_sid_int32;
     }
     else
     {
         logger.error("event plugin_sid is null");
         goto DEFAULT_VALUE_ERROR;
     }

     if(tEvent.data_int32 > 0)
     {
         event.tmDate = tEvent.data_int32;
     }
     else
     {
         logger.error("event date is null");
         goto DEFAULT_VALUE_ERROR;
     }

     if(tEvent.fdata_int32 > 0)
     {
         event.tmFDate = tEvent.fdata_int32;
     }
     else
     {
         logger.error("event fdate is null");
         goto DEFAULT_VALUE_ERROR;
     }

     if(tEvent.event_type_enum >= ::SIEM::thrift::SIEMEventType::SIEM_EVENT_NONE)
     {
         event.enEventType = tEvent.event_type_enum;
     }
     else
     {
         logger.error("event type is null");
         goto DEFAULT_VALUE_ERROR;
     }

     if(tEvent.src_ipv4_int32 > 0)
     {
         event.nSrcIP = tEvent.src_ipv4_int32;
     }
     else
     {
         logger.error("event src IP is null");
         goto DEFAULT_VALUE_ERROR;
     }

     if(tEvent.dst_ipv4_int32 > 0)
     {
         event.nDstIP = tEvent.dst_ipv4_int32;
     }
     else
     {
         logger.error("event dst IP is null");
         goto DEFAULT_VALUE_ERROR;
     }

     if(tEvent.device_ipv4_int32 > 0)
     {
         event.nDeviceIP = tEvent.device_ipv4_int32;
     }
     else
     {
         logger.error("event device IP is null");
         goto DEFAULT_VALUE_ERROR;
     }

     if(!tEvent.interface_str.empty())
     {
         event.strInterface = tEvent.interface_str;
     }
     else
     {
         logger.error("event interface IP is null");
         goto DEFAULT_VALUE_ERROR;
     }

     if(!tEvent.log_str.empty())
     {
         event.strLog = tEvent.log_str;
     }
     else
     {
         logger.error("event log is null");
         goto DEFAULT_VALUE_ERROR;
     }

     if(!tEvent.event_id_str.empty())
     {
         event.strEventID = tEvent.event_id_str;
     }
     else
     {
         logger.error("event ID is null");
         goto DEFAULT_VALUE_ERROR;
     }

     if(tEvent.protocol_type_enum >= ::SIEM::thrift::SIEMProtocolType::SIEM_PROTOCOL_NONE)
     {
         event.enEventProtoType = tEvent.protocol_type_enum;
     }

     if(tEvent.src_port_int32 >= 0 && tEvent.src_port_int32 <= 65535)
     {
         event.nSrcPort = (uint16_t)tEvent.src_port_int32;
     }

     if(tEvent.dst_port_int32 >= 0 && tEvent.dst_port_int32 <= 65535)
     {
         event.nDstPort = (uint16_t)tEvent.dst_port_int32;
     }

     if(tEvent.snort_sid_int32 > 0)
     {
         event.nSnortSID = tEvent.snort_sid_int32;
     }

     if(tEvent.snort_cid_int32 > 0)
     {
         event.nSnortCID = tEvent.snort_cid_int32;
     }

     if(tEvent.priority_int32 > 0)
     {
         event.nPrority = (uint32_t)tEvent.priority_int32;
     }

     if(tEvent.occurrences_int32 > 0)
     {
         event.nOccurrence = (uint32_t)tEvent.occurrences_int32;
     }

     if(!tEvent.ctx_str.empty())
     {
         event.strCtx = tEvent.ctx_str;
     }

     if(!tEvent.username_str.empty())
     {
         event.strUsername = tEvent.username_str;
     }

     if(!tEvent.password_str.empty())
     {
         event.strPassword = tEvent.password_str;
     }

     if(!tEvent.filename_str.empty())
     {
         event.strFilename = tEvent.filename_str;
     }

     if(!tEvent.userdata1_str.empty())
     {
         event.strUserdata1 = tEvent.userdata1_str;
     }

     if(!tEvent.userdata2_str.empty())
     {
         event.strUserdata2 = tEvent.userdata2_str;
     }

     if(!tEvent.userdata3_str.empty())
     {
         event.strUserdata3 = tEvent.userdata3_str;
     }

     if(!tEvent.userdata4_str.empty())
     {
         event.strUserdata4 = tEvent.userdata4_str;
     }

     if(!tEvent.userdata5_str.empty())
     {
         event.strUserdata5 = tEvent.userdata5_str;
     }

     if(!tEvent.userdata6_str.empty())
     {
         event.strUserdata6 = tEvent.userdata6_str;
     }

     if(!tEvent.userdata7_str.empty())
     {
         event.strUserdata7 = tEvent.userdata7_str;
     }

     if(!tEvent.userdata8_str.empty())
     {
         event.strUserdata8 = tEvent.userdata8_str;
     }

     if(!tEvent.userdata9_str.empty())
     {
         event.strUserdata9 = tEvent.userdata9_str;
     }

     if(!tEvent.sensor_id_str.empty())
     {
         event.strSensorID = tEvent.sensor_id_str;
     }

     if(!tEvent.binary_data_str.empty())
     {
         event.strBinaryData = tEvent.binary_data_str;
     }

     return true;

 DEFAULT_VALUE_ERROR:
         return false;
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
