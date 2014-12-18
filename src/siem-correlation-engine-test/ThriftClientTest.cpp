/**
 *   @file   AppMain.cpp
 *   @brief  brief
 *
 *   detail: Test for thrift handle
 *
 *   @internal www.captech.net.cn
 *   author:    zhangpeng
 *   mail:      zhangpeng@captech.net.cn,developer.zhang.peng@gmail.com
 *   Created:   Jul 5, 2014
 *   Revision:  1.0.0
 *   Compiler:  gcc/g++
 *   Company:   Captech Co., Ltd.
 *   Copyright: Copyright (c) 2008, Captech Co., Ltd.
 *
 * =====================================================================================
 */

#include "SIEMThrift.h"
#include "../siem-correlation-engine/SIEMUtil.hpp"
#include "../siem-correlation-engine/Base64.h"

#include <thrift/transport/TSocket.h>
#include <thrift/transport/TBufferTransports.h>
#include <thrift/protocol/TBinaryProtocol.h>
#include <thrift/transport/TTransportUtils.h>

#include <string>
#include <vector>

using namespace apache::thrift;
using namespace apache::thrift::protocol;
using namespace apache::thrift::transport;

using std::string;
using std::vector;

 using namespace ::SIEM::thrift;

int main(int argc, char **argv)
{
   boost::shared_ptr<TSocket> socket(new TSocket("127.0.0.1", 9999));
   boost::shared_ptr<TTransport> transport(new TFramedTransport(socket));
   boost::shared_ptr<TProtocol> protocol(new TBinaryProtocol(transport));

   SIEMThriftClient client(protocol);
   transport->open();

   SIEMThriftEvent event;
   std::string strEventSerialize;

   for(int i = 0; i < 10; i++)
   {
       // construct event log
       event.plugin_id_int32  = 12;
       event.plugin_sid_int32 = 22;
       std::string strEventID = "bdf8cb60bdf8cb60";
       event.event_id_str = SIEM::Util::Base64Encode(
               reinterpret_cast<const unsigned char *>(strEventID.c_str()),
               strEventID.length());
       std::string strEventLog = "sql injection attack";
       event.log_str = SIEM::Util::Base64Encode(
               reinterpret_cast<const unsigned char *>(strEventLog.c_str()),
               strEventLog.length());
       std::string strInterface = "eth0";
       event.interface_str = SIEM::Util::Base64Encode(
               reinterpret_cast<const unsigned char *>(strInterface.c_str()),
               strInterface.length());
       event.src_ipv4_int32 = 1;
       event.src_port_int32 = 1433;
       event.__isset.src_port_int32 = true;
       event.__isset.dst_port_int32 = true;
       event.dst_ipv4_int32 = 1;
       event.dst_port_int32 = 6445;
       event.device_ipv4_int32 = 0;
       event.event_type_enum    = SIEMEventType::SIEM_EVENT_DETECTOR;
       event.protocol_type_enum = SIEMProtocolType::SIEM_PROTOCOL_TCP;
       event.data_int32 = 0;
       event.fdata_int32 = 0;
       event.ctx_str = "zhangpeng";
       event.__isset.ctx_str = true;
       strEventSerialize = SIEM::Util::ThriftToString(event);
       client.Recv(strEventSerialize);
   }

   transport->close();

   return 0;
 }
