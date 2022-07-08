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

#include "te_config.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

#include "icmp_send.h"
#include "te_errno.h"
#include "logger_api.h"

#include "tapi_tcp.h"
#include "tapi_udp.h"
#include "tapi_icmp4.h"
#include "tapi_icmp6.h"
#include "tapi_ip4.h"
#include "tapi_eth.h"


/**
 * Accumulate a partial checksum for a memory region.
 * [sum] and the returned value are 16+ bit partial checksums.
 *
 * @param sum       initial checksum value
 * @param in_buf    buffer to calculate partial checksum for
 * @param bytes     buffer length
 *
 * @return Calculated checksum
 */
static inline unsigned
ip_csum_partial(unsigned sum, const void* in_buf, unsigned int bytes)
{
  const uint16_t *buf = (const uint16_t *)in_buf;

  assert(in_buf || bytes == 0);

  while (bytes > 1)
  {
    sum += *buf++;
    bytes -= 2;
  }

  sum += bytes ? *(uint8_t *) buf : 0;

  return sum;
}

/**
 * Finish IP header checksum calculation
 *
 * @param sum       Calculated IP header checksum value
 *
 * @return Calculated checksum
 */
static inline unsigned int
ip_hdr_csum_finish(unsigned int sum) {
  sum =  (sum >> 16u) + (sum & 0xffff);
  sum += (sum >> 16u);
  return ~sum & 0xffff;
}

/**
 * Finish ICMP checksum calculation
 *
 * @param sum       Calculated ICMP checksum value
 *
 * @return Calculated checksum
 */
static inline unsigned int
icmp_csum_finish(unsigned int sum) {
  sum =  (sum >> 16u) + (sum & 0xffff);
  sum += (sum >> 16u);
  sum = ~sum & 0xffff;
  return sum;
}


/**
 * Create ICMP packet, calculate checksum for payload
 *
 * @param type      ICMP error message type
 * @param code      ICMP error message code
 * @param unused    Reserved 'unused' field of ICMP message
 * @param data      payload data of ICMP message
 * @param data_len  payload data length
 * @param buf       output buffer for composed ICMP message
 * @param buf_len   output buffer length
 *
 * @return N/A
 */
void
create_icmp(uint8_t type, uint8_t code, uint32_t unused, 
            uint8_t *data, int data_len,
            uint8_t *buf, int *buf_len)
{
    unsigned csum;

    if ((data_len + 8) > *buf_len)
        assert(0);
    
    buf[0] = type;
    buf[1] = code;
    buf[2] = 0;
    buf[3] = 0;
    unused = htonl(unused);
    memcpy(buf + 4, &unused, 4); /* Unused field */
        
    memcpy(buf + 8, data, data_len);
    *buf_len = data_len + 8;

    csum = ip_csum_partial(0, buf, *buf_len);
    *((uint16_t *)(buf + 2)) = icmp_csum_finish(csum);
}

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
void create_udp(uint16_t s_port, uint16_t d_port, uint8_t *data, int data_len,
                uint8_t *buf, int *buf_len)
{
    uint16_t port;
    uint16_t len;

    if (data_len + 8 > *buf_len)
        assert(0);

    *buf_len = 8 + data_len;
     
    port = s_port;
    memcpy(buf, &port, sizeof(port));
    port = d_port;
    memcpy(buf + 2, &port, sizeof(port));
    len = htons(8 + data_len);
    memcpy(buf + 4, &len, 2);
    memset(buf + 6, 0, 2);
    /** @todo Calculate CHCKSUM in UDP header */
    memcpy(buf + 8, data, data_len);
}

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
void
create_tcp(uint16_t s_port, uint16_t d_port, uint32_t sn, uint32_t ack,
           uint8_t *data, int data_len, uint8_t *buf, int *buf_len)
{
    uint16_t port;

    if (data_len + 20 > *buf_len)
        assert(0);

    *buf_len = 20 + data_len;

    memset(buf, 0, 20);
    
    port = s_port;
    memcpy(buf, &port, sizeof(port));
    port = d_port;
    memcpy(buf + 2, &port, sizeof(port));

    sn = htonl(sn);
    ack = htonl(ack);
    memcpy(buf + 4, &sn, sizeof(sn));
    memcpy(buf + 4, &ack, sizeof(ack));
    
    /* Offset, flags, wnd, chsum, urg ptr = 0*/
    
    memcpy(buf + 20, data, data_len);
}


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
void
create_ip(uint8_t *src, uint8_t *dst, uint8_t proto,
          uint8_t *data, int data_len, uint8_t *buf, int *buf_len)
{
    uint16_t len = 5 * 4 + data_len;
    uint16_t csum;

    assert(buf_len);    
    if (*buf_len < len)
        assert(0);
    *buf_len = len;

    memset(buf, 0, 5 * 4);
    buf[0] = 0x45;
    buf[1] = 0;
    len = htons(len);
    memcpy(buf + 2, &len , sizeof(len));
    buf[8] = 100; /* TTL */
    buf[9] = proto;
    /* 2 bytes checksum */
    memcpy(buf + 12, src, 4); /* source address */
    memcpy(buf + 16, dst, 4);/* dst address */

    csum = ip_hdr_csum_finish(ip_csum_partial(0, buf, 20));

    memcpy(buf + 10, &csum, 2);
    memcpy(buf + 20, data, data_len);

    return;
}

/**
 * Prepare packet template for sending via Ethernet CSAP
 * with binary payload
 *
 * @param src       Source MAC address  field of IPv4 packet header
 * @param dst       Destination address field of IPv4 packet header
 * @param data      payload data of IPv4 packet
 * @param data_len  payload data length
 * @param templ     output buffer for composed IPv4 packet
 *
 * @return 0 on success or -1 in the case of failure
 */
int
test_prepare_template(const uint8_t *src, const uint8_t *dst,
                      uint8_t *data, int data_len, asn_value **templ)
{
    asn_value *traffic_templ;
    asn_value *asn_eth_hdr;
    asn_value *asn_pdus, *asn_pdu;
    int        rc = 0;
    ndn_eth_header_plain  header;

    if (data == NULL || templ == NULL)
    {
        assert(0);
        return TE_EINVAL;
    }

    traffic_templ = asn_init_value(ndn_traffic_template);
    asn_pdus = asn_init_value(ndn_generic_pdu_sequence);
    asn_pdu = asn_init_value(ndn_generic_pdu);

#if 0
    asn_eth_hdr = asn_init_value(ndn_eth_header);
#else
    memcpy(header.src_addr, src, 6);
    memcpy(header.dst_addr, dst, 6);
    header.len_type = 0x0800;
    header.is_tagged = 0;
    asn_eth_hdr = ndn_eth_plain_to_packet(&header);
#endif

    rc = asn_write_component_value(asn_pdu, asn_eth_hdr, "#eth");

    if (rc == 0)
        rc = asn_insert_indexed(asn_pdus, asn_pdu, -1, "");

    if (rc == 0)
        rc = asn_write_component_value(traffic_templ, asn_pdus, "pdus");

    if (rc == 0)
    {
        rc = asn_write_value_field(traffic_templ, data, data_len,
                                   "payload.#bytes");
    }

    if (rc != 0)
    {
        VERB("Cannot create traffic template %x\n", rc);
        return rc;
    }

    *templ = traffic_templ;
    return 0;
}

/**
 * Prepare ICMP packet template for sending via Ethernet CSAP
 *
 * @param eth_src       Source (Local) MAC address for Eth header field
 * @param eth_dst       Destination (Remote) address for Eth header field
 * @param ip_src        Source (Local) IPv4 address for IPv4 header field,
 *                      and Destination (Remote) IPv4 address for IPv4
 *                      header nested into the ICMP message
 * @param ip_dst        Destination (Remote) IPv4 address for IPv4 header
 *                      field and Source (Local) IPv4 address for IPv4
 *                      header nested into the ICMP message
 * @param icmp_type     ICMP error message type
 * @param icmp_code     ICMP error message code
 * @param icmp_unused   Reserved 'unused' field of ICMP message
 * @param proto         Payload protocol type
 * @param src_port      Source (Local) TCP header nested into the ICMP message
 * @param dst_port      Destination (Remote) TCP header nested into the
 *                      ICMP message
 * @param templ         output buffer for composed ICMP PDU
 *
 * @return 0 on success or -1 in the case of failure
 */
int
create_icmp_error_msg_tmpl(const uint8_t *eth_src,
                           const uint8_t *eth_dst,
                           uint8_t *ip_src, uint8_t *ip_dst,
                           uint8_t icmp_type, uint8_t icmp_code,
                           uint32_t icmp_unused, uint8_t proto, 
                           uint16_t src_port, uint16_t dst_port,
                           asn_value **templ)
{
    uint8_t        transp_proto_data[10];
    uint8_t        ip_data[1024];
    int            ip_data_len = sizeof(ip_data);
    uint8_t        icmp_data[1024];
    int            icmp_data_len = sizeof(icmp_data);
    uint8_t        ip_out_data[1024];
    int            ip_out_data_len = sizeof(ip_data);
    uint8_t        eth_data[1024];
    int            eth_data_len = sizeof(eth_data);

    if (proto == IPPROTO_UDP)
    {
        /* 1. create UDP datagram */
        create_udp(src_port, dst_port,
                   transp_proto_data, sizeof(transp_proto_data),
                   ip_data, &ip_data_len);
    }
    else if (proto == IPPROTO_TCP)
    {
        create_tcp(src_port, dst_port, 10, 10,
                   transp_proto_data, sizeof(transp_proto_data),
                   ip_data, &ip_data_len);
    }
    else
    {
        assert(0);
    }
    
    /* 2. IP packet to be reported in ICMP message (DST -> SRC) */
    create_ip(ip_dst, ip_src, proto, ip_data, ip_data_len,
              icmp_data, &icmp_data_len);
    /* 3. Wrap the IP packet to ICMP message */
    create_icmp(icmp_type, icmp_code, icmp_unused,
                icmp_data, icmp_data_len, ip_out_data, &ip_out_data_len);
    /* 4. IP packet from SRC to DST */
    create_ip(ip_src, ip_dst, IPPROTO_ICMP,
              ip_out_data, ip_out_data_len,
              eth_data, &eth_data_len);

    /* Prepare ETH traffic template */
    if (test_prepare_template(eth_src, eth_dst,
                              eth_data, eth_data_len, templ) != 0)
    {
        assert(0);
    }

    return 0;
}

/**
 * Create traffic template and add UDP/TCP PDU with payload
 *
 * @param src_port  Source port
 * @param dst_port  Destination port
 * @param ip_proto  IPPROTO_UDP or IPPROTO_TCP
 * @param data      Payload data (or NULL)
 * @param data_len  Payload data length (ignored if @p data is NULL)
 * @param templ     Location for pointer to ASN value (OUT)
 *
 * @return Status code
 */
static te_errno
tapi_create_udp_tcp_proto_pdu(uint16_t src_port, uint16_t dst_port,
                              uint8_t ip_proto, uint8_t *data,
                              size_t data_len, asn_value **templ)
{
    te_errno        rc;
    int             syms;

    asn_value      *traffic_templ = NULL;
    asn_value      *tcp_pdu = NULL;
    uint32_t        msg_tcp_seqn = 10;
    uint32_t        msg_tcp_ackn = 10;
    te_bool         msg_tcp_syn_flag = FALSE;
    te_bool         msg_tcp_ack_flag = FALSE;

    traffic_templ = asn_init_value(ndn_traffic_template);

    rc = asn_parse_value_text("{ pdus { } }", ndn_traffic_template,
                              &traffic_templ, &syms);
    if (rc != 0)
    {
        ERROR("%s(): asn_parse_value_text returned unexpected error: %r",
               __FUNCTION__, rc);
        goto cleanup;
    }

    if (ip_proto == IPPROTO_UDP)
    {
        rc = tapi_udp_add_pdu(&traffic_templ, NULL, FALSE, src_port, dst_port);
        if (rc != 0)
        {
            ERROR("%s(): add udp pdu error: %r", __FUNCTION__, rc);
            goto cleanup;
        }
    }
    else if (ip_proto == IPPROTO_TCP)
    {
        rc = tapi_tcp_pdu(src_port, dst_port, msg_tcp_seqn, msg_tcp_ackn,
                          msg_tcp_syn_flag, msg_tcp_ack_flag, &tcp_pdu);
        if (rc != 0)
        {
            ERROR("%s(): create tcp pdu error: %r", __FUNCTION__, rc);
            goto cleanup;
        }

        rc = asn_insert_indexed(traffic_templ, tcp_pdu, 0, "pdus");
        if (rc != 0)
        {
            ERROR("%s(): insert tcp pdu error: %r", __FUNCTION__, rc);
            goto cleanup;
        }
    }
    else
    {
        ERROR("%s(): wrong value of ip_proto: %u", __FUNCTION__,
              ip_proto);
        rc = TE_EINVAL;
        goto cleanup;
    }

    if (data != NULL)
    {
        rc = asn_write_value_field(traffic_templ, data, data_len,
                                   "payload.#bytes");
        if (rc != 0)
        {
            ERROR("%s(): cannot write payload data: %r", __FUNCTION__, rc);
            goto cleanup;
        }
    }

    *templ = traffic_templ;
    return 0;

cleanup:
    asn_free_value(traffic_templ);
    asn_free_value(tcp_pdu);
    return rc;
}

/* See description in icmp_send.h */
te_errno
tapi_icmp4_error_msg_pdu(const uint8_t *eth_src,
                         const uint8_t *eth_dst,
                         uint8_t *ip4_src, uint8_t *ip4_dst,
                         uint8_t icmp_type, uint8_t icmp_code,
                         uint8_t *msg_ip4_src, uint8_t *msg_ip4_dst,
                         uint8_t  msg_ip_proto,
                         int msg_src_port, int msg_dst_port,
                         uint8_t *data, int data_len,
                         asn_value **templ)
{
    te_errno    rc;

    asn_value  *traffic_templ = NULL;

    uint8_t     msg_ip4_ttl = 128;
    uint8_t     msg_ip4_tos = 0;
    uint8_t     ip4_ttl = 128;
    uint8_t     ip4_tos = 0;
    uint16_t    eth_type = ETHERTYPE_IP; /* IPv4 */

    /* 1. Create UDP/TCP PDU with payload */
    rc = tapi_create_udp_tcp_proto_pdu(msg_src_port, msg_dst_port, msg_ip_proto,
                                       data, data_len, &traffic_templ);
    if (rc != 0)
        return rc;

    /* 2. IPv4 packet to be reported in ICMP message (DST -> SRC) */
    rc = tapi_ip4_add_pdu(&traffic_templ, NULL, FALSE,
                          *(in_addr_t *)msg_ip4_src,
                          *(in_addr_t *)msg_ip4_dst,
                          msg_ip_proto, msg_ip4_ttl, msg_ip4_tos);
    if (rc != 0)
    {
        ERROR("%s(): add outer ipv4 pdu error: %r", __FUNCTION__, rc);
        goto cleanup;
    }

    /* 3. Wrap the IPv4 packet to ICMP message */
    rc = tapi_icmp4_add_pdu(&traffic_templ, NULL, FALSE,
                            icmp_type, icmp_code);
    if (rc != 0)
    {
        ERROR("%s(): add icmp4 pdu error: %r", __FUNCTION__, rc);
        goto cleanup;
    }

    /* 4. Add IPv4 packet header (use ip4_src and ip4_dst) */
    rc = tapi_ip4_add_pdu(&traffic_templ, NULL, FALSE,
                          *(in_addr_t *)ip4_src,
                          *(in_addr_t *)ip4_dst,
                          IPPROTO_ICMP, ip4_ttl, ip4_tos);
    if (rc != 0)
    {
        ERROR("%s(): add inner ipv4 pdu error: %r", __FUNCTION__, rc);
        goto cleanup;
    }

    /* 5. Add Ethernet header */
    rc = tapi_eth_add_pdu(&traffic_templ, NULL, FALSE,
                          eth_dst, eth_src, &eth_type,
                          TE_BOOL3_FALSE, TE_BOOL3_FALSE);
    if (rc != 0)
    {
        ERROR("%s(): add eth pdu error: %r", __FUNCTION__, rc);
        goto cleanup;
    }

    *templ = traffic_templ;
    return 0;

cleanup:
    asn_free_value(traffic_templ);
    return rc;
}


/* See description in icmp_send.h */
te_errno
tapi_icmp6_error_msg_pdu(const uint8_t              *eth_src,
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
                         asn_value                 **templ)
{
    te_errno        rc = 0;
    asn_value      *traffic_templ = NULL;
    icmp6_msg_body  msg_body = {0};
    uint8_t         msg_ip6_hop_limit = 128;
    uint8_t         ip6_hop_limit = 128;
    uint16_t        eth_type = ETHERTYPE_IPV6;

    /* 1. Create UDP/TCP PDU with payload */
    rc = tapi_create_udp_tcp_proto_pdu(msg_src_addr->sin6_port,
                                       msg_dst_addr->sin6_port,
                                       msg_ip_proto, data, data_len,
                                       &traffic_templ);
    if (rc != 0)
        return rc;

    /* 2. IPv6 packet to be reported in ICMP message (DST -> SRC) */
    rc = tapi_ip6_add_pdu(&traffic_templ, NULL, FALSE,
                          (uint8_t *)&msg_src_addr->sin6_addr,
                          (uint8_t *)&msg_dst_addr->sin6_addr,
                          msg_ip_proto, msg_ip6_hop_limit);
    if (rc != 0)
    {
        ERROR("%s(): add outer ipv6 pdu error: %r", __FUNCTION__, rc);
        goto cleanup;
    }

    /* 3. Wrap the IPv6 packet to ICMP message */
    msg_body.msg_type = icmp_type;
    rc = tapi_icmp6_add_pdu(&traffic_templ, NULL, FALSE,
                            icmp_type, icmp_code, &msg_body, NULL);
    if (rc != 0)
    {
        ERROR("%s(): add icmp6 pdu error: %r", __FUNCTION__, rc);
        goto cleanup;
    }

    /* 4. Add IPv6 packet header (use ip6_src and ip6_dst) */
    rc = tapi_ip6_add_pdu(&traffic_templ, NULL, FALSE,
                          ip6_src, ip6_dst,
                          IPPROTO_ICMPV6, ip6_hop_limit);
    if (rc != 0)
    {
        ERROR("%s(): add inner ip6 pdu error: %r", __FUNCTION__, rc);
        goto cleanup;
    }

    /* 5. Add Ethernet header */
    rc = tapi_eth_add_pdu(&traffic_templ, NULL, FALSE,
                          eth_dst, eth_src, &eth_type,
                          TE_BOOL3_FALSE, TE_BOOL3_FALSE);
    if (rc != 0)
    {
        ERROR("%s(): add eth pdu error: %r", __FUNCTION__, rc);
        goto cleanup;
    }

    *templ = traffic_templ;
    return 0;

cleanup:
    asn_free_value(traffic_templ);
    return rc;
}

/* See description in icmp_send.h */
te_errno
tapi_icmp_error_msg_pdu(const uint8_t          *eth_src,
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
                        asn_value             **templ)
{
    if (af == AF_INET)
    {

        return tapi_icmp4_error_msg_pdu(eth_src, eth_dst,
                                    (uint8_t *)&(SIN(src_addr)->sin_addr),
                                    (uint8_t *)&(SIN(dst_addr)->sin_addr),
                                    icmp_type, icmp_code,
                                    (uint8_t *)&(SIN(msg_src_addr)->sin_addr),
                                    (uint8_t *)&(SIN(msg_dst_addr)->sin_addr),
                                    msg_ip_proto,
                                    SIN(msg_src_addr)->sin_port,
                                    SIN(msg_dst_addr)->sin_port,
                                    data, data_len, templ);
    }
    else if (af == AF_INET6)
    {
        return tapi_icmp6_error_msg_pdu(eth_src, eth_dst,
                                    (uint8_t *)&(SIN6(src_addr)->sin6_addr),
                                    (uint8_t *)&(SIN6(dst_addr)->sin6_addr),
                                    icmp_type, icmp_code,
                                    SIN6(msg_src_addr), SIN6(msg_dst_addr),
                                    msg_ip_proto,
                                    data, data_len, templ);
    }
    else
    {
        ERROR("%s(): invalid ip address family: %d", __FUNCTION__, af);
        return TE_EINVAL;
    }
}
