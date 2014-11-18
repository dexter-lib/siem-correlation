namespace cpp SIEM.thrift

enum SIEMProtocolType
{
	SIEM_PROTOCOL_NONE         = 0,
	SIEM_PROTOCOL_ICMP         = 1,
	SIEM_PROTOCOL_TCP          = 6,
	SIEM_PROTOCOL_UDP          = 17,
	SIEM_PROTOCOL_ARP_EVENT    = 134,
	SIEM_PROTOCOL_OS_EVENT     = 135,
	SIEM_PROTOCOL_SERVER_EVENT = 136,
}

enum SIEMEventType
{
	SIEM_EVENT_NONE             = 0,
	SIEM_EVENT_DETECTOR         = 1,
	SIEM_EVENT_MONITOR          = 2,
	SIEM_EVENT_BACKLOG          = 3,
}

struct SIEMThriftEvent
{
	1:required i32   plugin_id_int32                                ;
	2:required i32   plugin_sid_int32                               ;
	3:required i32   data_int32                                     ;
	4:required i32   fdata_int32                                    ;
	5:required SIEMEventType    event_type_enum = SIEMEventType.SIEM_EVENT_NONE;
	6:required i32   src_ipv4_int32                                 ;
	7:required i32   dst_ipv4_int32                                 ;
	8:required i32   device_ipv4_int32                              ;
	9:required string   interface_str                                   ;
	10:required string   log_str                                         ;
	11:required string   event_id_str                                    ;
	12:SIEMProtocolType protocol_type_enum = SIEMProtocolType.SIEM_PROTOCOL_NONE  ;
	13:optional i32   src_port_int32                                 ;
	14:optional i32   dst_port_int32                                 ;
	15:optional i32   snort_sid_int32                                ;
	16:optional i32   snort_cid_int32                                ;
	17:optional i32   priority_int32                                 ;
	18:optional i32   occurrences_int32                              ;
	19:optional string   ctx_str                                         ;
	20:optional string   username_str                                    ;
	21:optional string   password_str                                    ;
	22:optional string   filename_str                                    ;
	23:optional string   userdata1_str                                   ;
	24:optional string   userdata2_str                                   ;
	25:optional string   userdata3_str                                   ;
	26:optional string   userdata4_str                                   ;
	27:optional string   userdata5_str                                   ;
	28:optional string   userdata6_str                                   ;
	29:optional string   userdata7_str                                   ;
	30:optional string   userdata8_str                                    ;
	31:optional string   userdata9_str                                    ;
	32:optional string   sensor_id_str                                    ;
	33:optional string   binary_data_str                                  ;
}

service SIEMThrift
{
	bool Recv(1:string strEvent);
	bool Handle(1:SIEMThriftEvent tEvent);
}
