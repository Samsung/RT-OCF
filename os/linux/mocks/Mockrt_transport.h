/* AUTOGENERATED FILE. DO NOT EDIT. */
#ifndef _MOCKRT_TRANSPORT_H
#define _MOCKRT_TRANSPORT_H

#include "rt_transport.h"

/* Ignore the following warnings, since we are copying code */
#if defined(__GNUC__) && !defined(__ICC) && !defined(__TMS470__)
#if !defined(__clang__)
#pragma GCC diagnostic ignored "-Wpragmas"
#endif
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
#pragma GCC diagnostic ignored "-Wduplicate-decl-specifier"
#endif

void Mockrt_transport_Init(void);
void Mockrt_transport_Destroy(void);
void Mockrt_transport_Verify(void);




#define msg_initialize_transport_IgnoreAndReturn(cmock_retval) msg_initialize_transport_CMockIgnoreAndReturn(__LINE__, cmock_retval)
void msg_initialize_transport_CMockIgnoreAndReturn(UNITY_LINE_TYPE cmock_line, int cmock_to_return);
#define msg_initialize_transport_ExpectAnyArgsAndReturn(cmock_retval) msg_initialize_transport_CMockExpectAnyArgsAndReturn(__LINE__, cmock_retval)
void msg_initialize_transport_CMockExpectAnyArgsAndReturn(UNITY_LINE_TYPE cmock_line, int cmock_to_return);
#define msg_initialize_transport_ExpectAndReturn(cmock_retval) msg_initialize_transport_CMockExpectAndReturn(__LINE__, cmock_retval)
void msg_initialize_transport_CMockExpectAndReturn(UNITY_LINE_TYPE cmock_line, int cmock_to_return);
typedef int (* CMOCK_msg_initialize_transport_CALLBACK)(int cmock_num_calls);
void msg_initialize_transport_StubWithCallback(CMOCK_msg_initialize_transport_CALLBACK Callback);
#define msg_terminate_transport_Ignore() msg_terminate_transport_CMockIgnore()
void msg_terminate_transport_CMockIgnore(void);
#define msg_terminate_transport_ExpectAnyArgs() msg_terminate_transport_CMockExpectAnyArgs(__LINE__)
void msg_terminate_transport_CMockExpectAnyArgs(UNITY_LINE_TYPE cmock_line);
#define msg_terminate_transport_Expect() msg_terminate_transport_CMockExpect(__LINE__)
void msg_terminate_transport_CMockExpect(UNITY_LINE_TYPE cmock_line);
typedef void (* CMOCK_msg_terminate_transport_CALLBACK)(int cmock_num_calls);
void msg_terminate_transport_StubWithCallback(CMOCK_msg_terminate_transport_CALLBACK Callback);
#define msg_send_unicast_packet_Ignore() msg_send_unicast_packet_CMockIgnore()
void msg_send_unicast_packet_CMockIgnore(void);
#define msg_send_unicast_packet_ExpectAnyArgs() msg_send_unicast_packet_CMockExpectAnyArgs(__LINE__)
void msg_send_unicast_packet_CMockExpectAnyArgs(UNITY_LINE_TYPE cmock_line);
#define msg_send_unicast_packet_Expect(packet, len, endpoint) msg_send_unicast_packet_CMockExpect(__LINE__, packet, len, endpoint)
void msg_send_unicast_packet_CMockExpect(UNITY_LINE_TYPE cmock_line, const uint8_t* packet, uint16_t len, const ocf_endpoint_s* endpoint);
typedef void (* CMOCK_msg_send_unicast_packet_CALLBACK)(const uint8_t* packet, uint16_t len, const ocf_endpoint_s* endpoint, int cmock_num_calls);
void msg_send_unicast_packet_StubWithCallback(CMOCK_msg_send_unicast_packet_CALLBACK Callback);
#define msg_send_unicast_packet_IgnoreArg_packet() msg_send_unicast_packet_CMockIgnoreArg_packet(__LINE__)
void msg_send_unicast_packet_CMockIgnoreArg_packet(UNITY_LINE_TYPE cmock_line);
#define msg_send_unicast_packet_IgnoreArg_len() msg_send_unicast_packet_CMockIgnoreArg_len(__LINE__)
void msg_send_unicast_packet_CMockIgnoreArg_len(UNITY_LINE_TYPE cmock_line);
#define msg_send_unicast_packet_IgnoreArg_endpoint() msg_send_unicast_packet_CMockIgnoreArg_endpoint(__LINE__)
void msg_send_unicast_packet_CMockIgnoreArg_endpoint(UNITY_LINE_TYPE cmock_line);
#define msg_send_multicast_packet_Ignore() msg_send_multicast_packet_CMockIgnore()
void msg_send_multicast_packet_CMockIgnore(void);
#define msg_send_multicast_packet_ExpectAnyArgs() msg_send_multicast_packet_CMockExpectAnyArgs(__LINE__)
void msg_send_multicast_packet_CMockExpectAnyArgs(UNITY_LINE_TYPE cmock_line);
#define msg_send_multicast_packet_Expect(packet, len) msg_send_multicast_packet_CMockExpect(__LINE__, packet, len)
void msg_send_multicast_packet_CMockExpect(UNITY_LINE_TYPE cmock_line, const uint8_t* packet, uint16_t len);
typedef void (* CMOCK_msg_send_multicast_packet_CALLBACK)(const uint8_t* packet, uint16_t len, int cmock_num_calls);
void msg_send_multicast_packet_StubWithCallback(CMOCK_msg_send_multicast_packet_CALLBACK Callback);
#define msg_send_multicast_packet_IgnoreArg_packet() msg_send_multicast_packet_CMockIgnoreArg_packet(__LINE__)
void msg_send_multicast_packet_CMockIgnoreArg_packet(UNITY_LINE_TYPE cmock_line);
#define msg_send_multicast_packet_IgnoreArg_len() msg_send_multicast_packet_CMockIgnoreArg_len(__LINE__)
void msg_send_multicast_packet_CMockIgnoreArg_len(UNITY_LINE_TYPE cmock_line);
#define msg_set_receive_handler_IgnoreAndReturn(cmock_retval) msg_set_receive_handler_CMockIgnoreAndReturn(__LINE__, cmock_retval)
void msg_set_receive_handler_CMockIgnoreAndReturn(UNITY_LINE_TYPE cmock_line, int cmock_to_return);
#define msg_set_receive_handler_ExpectAnyArgsAndReturn(cmock_retval) msg_set_receive_handler_CMockExpectAnyArgsAndReturn(__LINE__, cmock_retval)
void msg_set_receive_handler_CMockExpectAnyArgsAndReturn(UNITY_LINE_TYPE cmock_line, int cmock_to_return);
#define msg_set_receive_handler_ExpectAndReturn(recv_handler, cmock_retval) msg_set_receive_handler_CMockExpectAndReturn(__LINE__, recv_handler, cmock_retval)
void msg_set_receive_handler_CMockExpectAndReturn(UNITY_LINE_TYPE cmock_line, msg_receive_handler recv_handler, int cmock_to_return);
typedef int (* CMOCK_msg_set_receive_handler_CALLBACK)(msg_receive_handler recv_handler, int cmock_num_calls);
void msg_set_receive_handler_StubWithCallback(CMOCK_msg_set_receive_handler_CALLBACK Callback);
#define msg_set_receive_handler_IgnoreArg_recv_handler() msg_set_receive_handler_CMockIgnoreArg_recv_handler(__LINE__)
void msg_set_receive_handler_CMockIgnoreArg_recv_handler(UNITY_LINE_TYPE cmock_line);
#define msg_unset_receive_handler_IgnoreAndReturn(cmock_retval) msg_unset_receive_handler_CMockIgnoreAndReturn(__LINE__, cmock_retval)
void msg_unset_receive_handler_CMockIgnoreAndReturn(UNITY_LINE_TYPE cmock_line, int cmock_to_return);
#define msg_unset_receive_handler_ExpectAnyArgsAndReturn(cmock_retval) msg_unset_receive_handler_CMockExpectAnyArgsAndReturn(__LINE__, cmock_retval)
void msg_unset_receive_handler_CMockExpectAnyArgsAndReturn(UNITY_LINE_TYPE cmock_line, int cmock_to_return);
#define msg_unset_receive_handler_ExpectAndReturn(cmock_retval) msg_unset_receive_handler_CMockExpectAndReturn(__LINE__, cmock_retval)
void msg_unset_receive_handler_CMockExpectAndReturn(UNITY_LINE_TYPE cmock_line, int cmock_to_return);
typedef int (* CMOCK_msg_unset_receive_handler_CALLBACK)(int cmock_num_calls);
void msg_unset_receive_handler_StubWithCallback(CMOCK_msg_unset_receive_handler_CALLBACK Callback);

#endif
