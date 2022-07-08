/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Test attacks/icmp/tcp_break  
 * Break TCP connection using ICMP errors
 */

/** @page icmp-tcp_break  Break TCP connection using ICMP errors
 *
 * @objective Check that sending of ICMP errors cannot break established
 *            connection.
 *
 * @reference CERT VU#222750 http://www.kb.cert.org/vuls/id/222750
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_peer2peer
 * @param type      ICMP Type (in couples with @p code):
 *                  - 3: Destination Unreachable
 *                  - 3: Destination Unreachable
 *                  - 3: Destination Unreachable
 *                  - 3: Destination Unreachable
 *                  - 3: Destination Unreachable
 *                  - 3: Destination Unreachable
 *                  - 11: Time Exceeded
 *                  - 11: Time Exceeded
 *                  - 12: Parameter Problem
 * @param code      ICMP Code:
 *                  - 0: Net Unreachable
 *                  - 1: Host Unreachable
 *                  - 2: Protocol Unreachable
 *                  - 3: Port Unreachable
 *                  - 4: Fragmentation Needed and Don't Fragment was Set
 *                  - 5: Source Route Failed
 *                  - 0: Net Unreachable
 *                  - 1: Host Unreachable
 *                  - 0: Net Unreachable
 *
 * @par Scenario
 * -# Establish TCP connection between @p pco_tst and @p pco_iut.
 * -# Send data via the connection.
 * -# Sniff TCP packet with data.
 * -# Create the ICMP error message using the sniffed TCP packet.
 *    In the case of Parameter Problem the pointer should be assigned
 *    to ToS offset.
 * -# Send the ICMP error.
 * -# Send/receive data via connection.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "attacks/icmp/tcp_break"

#include "sockapi-test.h"

#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#endif

#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif

#ifdef HAVE_NETINET_IP_ICMP_H
#include <netinet/ip_icmp.h>
#endif

#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif

#include "tapi_tad.h"
#include "tapi_ip4.h"
#include "tapi_tcp.h"
#include "tapi_ip4.h"
#include "tapi_eth.h"
#include "tapi_arp.h"
#include "tapi_cfg_base.h"
#include "ndn.h"

/** Number of packets for flooding */
#define IP_HDR_LEN       20  /**< Length of IP header in bytes */
#define ICMP_HDR_LEN     8   /**< Length of ICMP header in bytes */
#define ICMP_PLD_LEN     28  /**< Original packet length in ICMP error */
#define TIMEOUT          (5 * 1000)  /**< 5 seconds for packet catching */

/** Auxiliary buffer */
static char buf[1024];

static char tcp_pkt[ICMP_PLD_LEN];

static const struct sockaddr *iut_addr;
static const struct sockaddr *tst_addr;

/** Callback for catching row TCP and UDP packets */
static void
callback(const asn_value *packet, int layer,
         const ndn_eth_header_plain *header,
         const uint8_t *payload, uint16_t plen, void *userdata)
{
    uint16_t *tcp_hdr = (uint16_t *)(payload + IP_HDR_LEN);

    UNUSED(packet);
    UNUSED(layer);
    UNUSED(userdata);
    UNUSED(header);
    UNUSED(plen);

    if (((struct iphdr *)payload)->protocol != IPPROTO_TCP ||
        *tcp_hdr != SIN(iut_addr)->sin_port ||
        *(tcp_hdr + 1) != SIN(tst_addr)->sin_port ||
        (*((uint8_t *)tcp_hdr + 13) & TCP_PSH_FLAG) == 0)
    {
        return;
    }

    memcpy(tcp_pkt, payload, ICMP_PLD_LEN);
}

/** Construct ICMP packet */
static asn_value *
construct_icmp(uint8_t type, uint8_t code)
{
    asn_value *pkt;
    int        len = ICMP_PLD_LEN + ICMP_HDR_LEN;
    int        num;
    
    CHECK_RC(asn_parse_value_text("{ pdus { ip4:{}, eth:{} } }",
                                  ndn_traffic_template, &pkt, &num));
    
    /* Fill ICMP packet */
    memset(buf, 0, ICMP_HDR_LEN);
    buf[0] = type;
    buf[1] = code;
    memcpy(buf + 8, tcp_pkt, sizeof(tcp_pkt));
    switch (type)
    {
        case ICMP_DEST_UNREACH:
            if (code == ICMP_FRAG_NEEDED)
                *(uint16_t *)(buf + 6) = htonl(68);
            break;
            
        case ICMP_PARAMETERPROB:
            buf[4] = 1; /* Point to IP ToS */
            break;
        
        case ICMP_TIME_EXCEEDED:
            break;
            
        default:
            WARN("Unexpected ICMP type is provided in the test parameters");
            break;
    }
    *(uint16_t *)(buf + 2) = ~calculate_checksum(buf, len);
    CHECK_RC(asn_write_value_field(pkt, buf, len, "payload.#bytes"));
    
    return pkt;
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct if_nameindex *iut_if;
    const struct if_nameindex *tst_if;
    
    int type, code;
    
    unsigned int num;

    int iut_s = -1;
    int tst_s = -1;

    uint8_t mac_iut[ETHER_ADDR_LEN];
    uint8_t mac_tst[ETHER_ADDR_LEN];
    
    char oid[RCF_MAX_ID];

    csap_handle_t              csap = CSAP_INVALID_HANDLE;
    csap_handle_t              csap_eth = CSAP_INVALID_HANDLE;
    int                        sid;
    asn_value                 *pkt = NULL;
    
    uint16_t ethertype = ETHERTYPE_IP;
    int      error;
    
    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_INT_PARAM(type);
    TEST_GET_INT_PARAM(code);
    
    sprintf(oid, "/agent:%s/interface:%s", pco_iut->ta, iut_if->if_name);
    if (tapi_cfg_base_if_get_mac(oid, mac_iut) != 0)
        TEST_STOP;

    sprintf(oid, "/agent:%s/interface:%s", pco_tst->ta, tst_if->if_name);
    if (tapi_cfg_base_if_get_mac(oid, mac_tst) != 0)
        TEST_STOP;

    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_IPPROTO_TCP,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    /* Create CSAP */

    CHECK_RC(rcf_ta_create_session(pco_tst->ta, &sid));

    CHECK_RC(tapi_ip4_eth_csap_create(pco_tst->ta, sid,
                                      tst_if->if_name,
                                      (TAD_ETH_RECV_DEF &
                                       ~TAD_ETH_RECV_OTHER) |
                                      TAD_ETH_RECV_NO_PROMISC,
                                      mac_tst, mac_iut,
                                      SIN(tst_addr)->sin_addr.s_addr,
                                      SIN(iut_addr)->sin_addr.s_addr,
                                      IPPROTO_ICMP, &csap));

    CHECK_RC(tapi_eth_csap_create(pco_tst->ta, sid,
                                  tst_if->if_name,
                                  TAD_ETH_RECV_DEF |
                                  TAD_ETH_RECV_NO_PROMISC,
                                  mac_tst, mac_iut, NULL, &csap_eth));

    /* Catch row TCP and UDP packets */
    CHECK_RC(tapi_eth_add_pdu(&pkt, NULL, TRUE, mac_tst, mac_iut, &ethertype,
                              TE_BOOL3_ANY /* tagged/untagged */,
                              TE_BOOL3_ANY /* Ethernet2/LLC */));
    
    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, sid, csap_eth, pkt,
                                   TIMEOUT, 10, RCF_TRRECV_PACKETS));
    /* Provoke the traffic */
    sockts_test_connection(pco_iut, iut_s, pco_tst, tst_s); 
    rpc_getsockopt(pco_iut, iut_s, RPC_SO_ERROR, &error);
    if (error != 0)
        TEST_FAIL("ICMP is not ignored: SO_ERROR value is set");
    
    CHECK_RC(tapi_tad_trrecv_stop(pco_tst->ta, sid, csap_eth,
                                  tapi_eth_trrecv_cb_data(callback, NULL), 
                                  &num));

    if (tcp_pkt[0] == 0)
        TEST_FAIL("Failed to catch row TCP packet");
        
    asn_free_value(pkt);
    pkt = NULL;

    pkt = construct_icmp(type, code);
    CHECK_RC(tapi_tad_trsend_start(pco_tst->ta, sid, csap, 
                                   pkt, RCF_MODE_BLOCKING));

    /* Check usability of existing connections */
    sockts_test_connection(pco_iut, iut_s, pco_tst, tst_s); 
    rpc_getsockopt(pco_iut, iut_s, RPC_SO_ERROR, &error);
    if (error != 0)
        TEST_FAIL("ICMP is not ignored: SO_ERROR value is set");
    
    TEST_SUCCESS;

cleanup:
    if (csap_eth != CSAP_INVALID_HANDLE)
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0, csap_eth));

    if (csap != CSAP_INVALID_HANDLE)
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0, csap));

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    asn_free_value(pkt);
    
    TEST_END;
}
