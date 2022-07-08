/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * API for generating ICMP PDUs.
 *
 * @author Alexander Kukuta <Alexander.Kukuta@oktetlabs.ru>
 *
 * $Id$
 */

#ifndef __ICMP_SEND_H_
#define __ICMP_SEND_H_

#include <stdint.h>

#include "asn_impl.h"
#include "ndn_internal.h"
#include "ndn_eth.h"


#define ICMPV4_CODES                            \
    {"ICMP_NET_UNREACH", ICMP_NET_UNREACH},     \
    {"ICMP_HOST_UNREACH", ICMP_HOST_UNREACH},   \
    {"ICMP_PROT_UNREACH", ICMP_PROT_UNREACH},   \
    {"ICMP_PORT_UNREACH", ICMP_PORT_UNREACH}

#define ICMPV6_CODES                                    \
    {"ICMPV6_NOROUTE", ICMPV6_NOROUTE},                 \
    {"ICMPV6_ADM_PROHIBITED", ICMPV6_ADM_PROHIBITED},   \
    {"ICMPV6_NOT_NEIGHBOUR", ICMPV6_NOT_NEIGHBOUR},     \
    {"ICMPV6_ADDR_UNREACH", ICMPV6_ADDR_UNREACH},       \
    {"ICMPV6_PORT_UNREACH", ICMPV6_PORT_UNREACH},       \
    {"ICMPV6_POLICY_FAIL", ICMPV6_POLICY_FAIL},         \
    {"ICMPV6_REJECT_ROUTE", ICMPV6_REJECT_ROUTE}

/**
 * Create ICMP packet, calculate checksum for payload
 *
 * @param type      ICMP error message type
 * @param code      ICMP error message code
 * @param unused    Length of unused data in ICMP message
 * @param data      payload data of ICMP message
 * @param data_len  payload data length
 * @param buf       output buffer for composed ICMP message
 * @param buf_len   output buffer length
 *
 * @return N/A
 */
extern void create_icmp(uint8_t type, uint8_t code, uint32_t unused,
                        uint8_t *data, int data_len,
                        uint8_t *buf, int *buf_len);
    
/**
 * Create UDP datagram, (TODO: calculate checksum for payload)
 *
 * @param s_port    Source port field of UDP datagram header
 * @param d_port    Destination port field of UDP datagram header
 * @param data      payload data of UDP datagram
 * @param data_len  payload data length
 * @param buf       output buffer for composed UDP datagram
 * @param buf_len   output buffer length
 *
 * @return N/A
 */
extern void create_udp(uint16_t s_port, uint16_t d_port,
                       uint8_t *data, int data_len,
                       uint8_t *buf, int *buf_len);

/**
 * Create TCP packet, (TODO: calculate checksum for payload)
 *
 * @param s_port    Source port field of TCP packet header
 * @param d_port    Destination port field of TCP packet header
 * @param sn        Sequence Number field of TCP packet header
 * @param ack       ACK Number field of TCP packet header
 * @param data      payload data of TCP packet
 * @param data_len  payload data length
 * @param buf       output buffer for composed TCP packet
 * @param buf_len   output buffer length
 *
 * @return N/A
 */
extern void create_tcp(uint16_t s_port, uint16_t d_port,
                       uint32_t sn, uint32_t ack,
                       uint8_t *data, int data_len,
                       uint8_t *buf, int *buf_len);

/**
 * Create IPv4 packet, calculate checksum for IP header
 *
 * @param src       Source address field of IPv4 packet header
 * @param dst       Destination address field of IPv4 packet header
 * @param proto     Payload protocol type
 * @param data      payload data of IPv4 packet
 * @param data_len  payload data length
 * @param buf       output buffer for composed IPv4 packet
 * @param buf_len   output buffer length
 *
 * @return N/A
 */
extern void create_ip(uint8_t *src, uint8_t *dst, uint8_t proto,
                      uint8_t *data, int data_len,
                      uint8_t *buf, int *buf_len);

/**
 * Prepare packet template for sending via Ethernet CSAP
 *
 * @param src       Source MAC address  field of IPv4 packet header
 * @param dst       Destination address field of IPv4 packet header
 * @param proto     Payload protocol type
 * @param data      payload data of IPv4 packet
 * @param data_len  payload data length
 * @param templ     output buffer for composed IPv4 packet
 *
 * @return 0 on success or -1 in the case of failure
 */
extern int test_prepare_template(const uint8_t *src, const uint8_t *dst,
                                 uint8_t *data, int data_len,
                                 asn_value **templ);

/**
 * Prepare ICMP packet template for sending via Ethernet CSAP
 *
 * @param eth_src   Source (Local) MAC address for Eth header field
 * @param eth_dst   Destination (Remote) address for Eth header field
 * @param ip_src    Source (Local) IPv4 address for IPv4 header field,
 *                  and Destination (Remote) IPv4 address for IPv4 header
 *                  nested into the ICMP message
 * @param ip_dst    Destination (Remote) IPv4 address for IPv4 header field
 *                  and Source (Local) IPv4 address for IPv4 header
 *                  nested into the ICMP message
 * @param type      ICMP error message type
 * @param code      ICMP error message code
 * @param proto     Payload protocol type
 * @param src_port  Source (Local) TCP header nested into the ICMP message
 * @param dst_port  Destination (Remote) TCP header nested into the
 *                  ICMP message
 * @param templ     output buffer for composed ICMP PDU
 *
 * @return 0 on success or -1 in the case of failure
 */
extern int
create_icmp_error_msg_tmpl(const uint8_t *eth_src,
                           const uint8_t *eth_dst,
                           uint8_t *ip_src, uint8_t *ip_dst,
                           uint8_t icmp_type, uint8_t icmp_code,
                           uint32_t icmp_unused,
                           uint8_t proto, 
                           uint16_t src_port, uint16_t dst_port,
                           asn_value **templ);

/**
 * Prepare ICMP packet template for sending via complex
 * UDP/TCP-IPv4-ICMP-IPv4-Ethernet CSAP
 *
 * @param eth_src       Source (Local) MAC address for Eth header field
 * @param eth_dst       Destination (Remote) address for Eth header field
 * @param ip4_src       Source (Local) IPv4 address for IPv4 header field,
 * @param ip4_dst       Destination (Remote) IPv4 address for IPv4 header field
 * @param icmp_type     ICMP error message type
 * @param icmp_code     ICMP error message code
 * @param msg_ip4_src   Source (Local) IPv4 address for IPv4 header
 *                      nested into the ICMP message
 * @param msg_ip4_dst   Destination (Remote) IPv4 address for IPv4 header
 *                      nested into the ICMP message
 * @param msg_ip_proto  Payload protocol type
 * @param msg_src_port  Source (Local) TCP header nested into the ICMP message
 * @param msg_dst_port  Destination (Remote) TCP header nested into the
 *                      ICMP message
 * @param data          Payload data
 * @param data_len      Payload data length
 * @param templ         output buffer for composed ICMP PDU
 *
 * @return Status code
 */
extern te_errno
tapi_icmp4_error_msg_pdu(const uint8_t *eth_src,
                         const uint8_t *eth_dst,
                         uint8_t *ip4_src, uint8_t *ip4_dst,
                         uint8_t icmp_type, uint8_t icmp_code,
                         uint8_t *msg_ip4_src, uint8_t *msg_ip4_dst,
                         uint8_t  msg_ip_proto,
                         int msg_src_port, int msg_dst_port,
                         uint8_t *data, int data_len,
                         asn_value **templ);

/**
 * Prepare ICMPv6 packet template for sending via complex
 * UDP/TCP-IPv6-ICMP-IPv6-Ethernet CSAP
 *
 * @param eth_src       Source (Local) MAC address for Eth header field
 * @param eth_dst       Destination (Remote) address for Eth header field
 * @param ip6_src       Source (Local) IPv6 address for IPv6 header field,
 * @param ip6_dst       Destination (Remote) IPv6 address for IPv6 header field
 * @param icmp_type     ICMP error message type
 * @param icmp_code     ICMP error message code
 * @param msg_src_addr  Source (Local) IPv6 address/port for IPv6/TCP header
 *                      nested into the ICMP message
 * @param msg_dst_addr  Destination (Remote) IPv6 address/port for IPv6/TCP
                        header nested into the ICMP message
 * @param msg_ip_proto  Payload protocol type
 * @param data          Payload data
 * @param data_len      Payload data length
 * @param templ         Output buffer for composed ICMP PDU
 *
 * @return Status code
 */
extern te_errno tapi_icmp6_error_msg_pdu(const uint8_t              *eth_src,
                                         const uint8_t              *eth_dst,
                                         uint8_t                    *ip6_src,
                                         uint8_t                    *ip6_dst,
                                         uint8_t                     icmp_type,
                                         uint8_t                     icmp_code,
                                         const struct sockaddr_in6  *msg_src_addr,
                                         const struct sockaddr_in6  *msg_dst_addr,
                                         uint8_t                     msg_ip_proto,
                                         uint8_t                    *data,
                                         int                         data_len,
                                         asn_value                 **templ);


/**
 * Prepare ICMP packet template for sending via complex
 * UDP/TCP-IP-ICMP-IP-Ethernet CSAP. IP version depends on the @p af.
 *
 * @param eth_src       Source (Local) MAC address for Eth header field
 * @param eth_dst       Destination (Remote) address for Eth header field
 * @param src_addr      Source (Local) IP address for IP header field,
 * @param dst_addr      Destination (Remote) IP address for IP header field
 * @param icmp_type     ICMP error message type
 * @param icmp_code     ICMP error message code
 * @param msg_src_addr  Source (Local) IP address/port for IP/TCP header
 *                      nested into the ICMP message
 * @param msg_dst_addr  Destination (Remote) IP address/port for IP/TCP
                        header nested into the ICMP message
 * @param msg_ip_proto  Payload protocol type
 * @param data          Payload data
 * @param data_len      Payload data length
 * @param af            Address family
 * @param templ         Output buffer for composed ICMP PDU (OUT)
 *
 * @return Status code
 */
extern te_errno tapi_icmp_error_msg_pdu(const uint8_t          *eth_src,
                                        const uint8_t          *eth_dst,
                                        const struct sockaddr  *src_addr,
                                        const struct sockaddr  *dst_addr,
                                        uint8_t                 icmp_type,
                                        uint8_t                 icmp_code,
                                        const struct sockaddr  *msg_src_addr,
                                        const struct sockaddr  *msg_dst_addr,
                                        uint8_t                 msg_ip_proto,
                                        uint8_t                *data,
                                        int                     data_len,
                                        int                     af,
                                        asn_value             **templ);
#endif
