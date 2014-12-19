#include <zmq/zmq.hpp>

#include "SIEMMessage.pb.h"
#include "../siem-correlation-engine/Base64.h"

#include <iostream>
#include <string>


using namespace ::google::protobuf;

const static int SIEM_ZMQ_SEND_IO_TRD = 1;

int main(int argc, char **argv)
{
    std::string strAddr = "ipc:///tmp/siem-correlation-server";
    uint64_t ulZmqHwm = 100000ul;
    zmq::context_t zmqCtxt(SIEM_ZMQ_SEND_IO_TRD);
    zmq::socket_t zmqSckt(zmqCtxt, ZMQ_PUSH);

    try
    {
        zmqSckt.setsockopt(ZMQ_HWM, &ulZmqHwm, sizeof(uint64_t));
        zmqSckt.connect(strAddr.c_str());

        for(int i = 0; i < 20; i++)
        {
            ::SIEM::SIEMPbMessage siemMsg;
            ::SIEM::SIEMPbMessage_SIEMPbEvent *pEvent = siemMsg.mutable_siem_event();

            pEvent->set_data_uint32(1418957927);
            pEvent->set_fdata_uint32(1418957927);
            pEvent->set_src_ipv4_uint32(3232243478);
            pEvent->set_dst_ipv4_uint32(3232243578);
            pEvent->set_device_ipv4_uint32(3232243578);
            pEvent->set_src_port_uint32(1433);
            pEvent->set_dst_port_uint32(6557);
            pEvent->set_plugin_id_uint32(12);
            pEvent->set_plugin_sid_uint32(32);
            std::string strInterface = "eth0";
            pEvent->set_interface_str(std::string(::SIEM::Util::Base64Encode(
                    reinterpret_cast<const unsigned char *>(strInterface.c_str()), strInterface.size())));
            std::string strEventID = "yuzhiqiang";
            pEvent->set_event_id_str(std::string(::SIEM::Util::Base64Encode(
                    reinterpret_cast<const unsigned char *>(strEventID.c_str()), strEventID.size())));

            std::string strCtx = "liangbo";
            pEvent->set_ctx_str(std::string(::SIEM::Util::Base64Encode(
                    reinterpret_cast<const unsigned char *>(strCtx.c_str()), strCtx.size())));

            std::string strLog = "sql injection attack";
            pEvent->set_log_str(std::string(::SIEM::Util::Base64Encode(
                    reinterpret_cast<const unsigned char *>(strLog.c_str()), strLog.size())));

            pEvent->set_event_type_enum(::SIEM::SIEMPbMessage_SIEMEventType_SIEM_EVENT_BACKLOG);
            pEvent->set_protocol_type_enum(::SIEM::SIEMPbMessage_SIEMProtocolType_SIEM_PROTOCOL_TCP);

            size_t nSize = siemMsg.ByteSize();

            char szMsg[nSize + 1];
            siemMsg.SerializeToArray(szMsg, nSize);
            zmq::message_t msg(nSize);
            memcpy(msg.data(), szMsg, nSize);
            zmqSckt.send(msg, ZMQ_NOBLOCK);
        }
        zmqSckt.close();
    }
    catch (zmq::error_t& err)
    {
        std::cout << "zmq error:" << err.what() << std::endl;
    }
    catch (...)
    {
        std::cout << "zmq error:" << std::endl;
    }
    return 0;
}
