/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Test attacks/icmp/icmp_flood
 * Flood of ICMP packets
 */

/** @page icmp-icmp_flood  Flood of ICMP packets
 *
 * @objective Check that flood of ICMP packets does not lead to denial
 *            of service.
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_peer2peer
 * @param only_echo Send only @c ICMP_ECHO if @c TRUE, else send also ICMP
 *                  errors.
 *
 * @par Scenario
 * -# Create stream and datagram connections between @p pco_iut and
 *    @p pco_tst.
 * -# Start the task on @p pco_tst, which performs flood ping of
 *    @p pco_iut host.
 * -# Start the task on the @p pco_tst, which sends flood random ICMP error
 *    messages with TCP packets inside (corresponding to existing
 *    and non-existing connections).
 * -# Check that existing connections may be used to send/receive data.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "attacks/icmp/icmp_flood"

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
#define PKT_NUM         (1024 * 256)

#define IP_HDR_LEN       20  /**< Length of IP header in bytes */
#define ICMP_HDR_LEN     8   /**< Length of ICMP header in bytes */
#define ICMP_PLD_LEN     28  /**< Original packet length in ICMP error */
#define TIMEOUT          (5 * 1000)  /**< 5 seconds for packet catching */

/** Maximum attempts to transmit datagrams. */
#define UDP_MAX_ATTEMPTS_NUM    5

/** Datagrams number which is sent in a bunch. */
#define UDP_BUNCH               10

static rcf_rpc_server *pco_iut = NULL;
static rcf_rpc_server *pco_tst = NULL;

static const struct if_nameindex *iut_if;
static const struct if_nameindex *tst_if;
static const struct sockaddr     *iut_addr;
static const struct sockaddr     *tst_addr;

static te_bool only_echo;

static uint8_t mac_iut[ETHER_ADDR_LEN];
static uint8_t mac_tst[ETHER_ADDR_LEN];

/** Maximum number of ICMP CSAPs in the test */
#define MAX_CSAP        32

static int        sid[MAX_CSAP];     /**< SIDs ICMP CSAPs */
static asn_value *pkt[MAX_CSAP];     /**< Templates */

static csap_handle_t    csap[MAX_CSAP];    /**< ICMP CSAPs */

/** Auxiliary buffer */
static char buf[1024];

static char tcp_pkt[ICMP_PLD_LEN];
static char udp_pkt[ICMP_PLD_LEN];

/** Callback for catching row TCP and UDP packets */
static void
callback(const asn_value *packet, int layer,
         const ndn_eth_header_plain *header,
         const uint8_t *payload, uint16_t plen, void *userdata)
{
    UNUSED(packet);
    UNUSED(layer);
    UNUSED(header);
    UNUSED(userdata);
    
    switch (((struct iphdr *)payload)->protocol)
    {
        case IPPROTO_UDP:
            memcpy(udp_pkt, payload, 
                   plen > ICMP_PLD_LEN ? ICMP_PLD_LEN : plen);
            break;

        case IPPROTO_TCP:
            if ((*(payload + IP_HDR_LEN + 13) & TCP_PSH_FLAG) == 0)
                return;
            memcpy(tcp_pkt, payload, 
                   plen > ICMP_PLD_LEN ? ICMP_PLD_LEN : plen);
            break;
    }
}

/** Construct ICMP message */
static asn_value *
construct_icmp(uint8_t type, uint8_t code, char *dgram)
{
    asn_value *res;
    int        len = ICMP_PLD_LEN + ICMP_HDR_LEN;
    int        num;
    
    sprintf(buf, 
             "{ arg-sets { simple-for:{begin 1,end %u} }, "
             "  pdus  { ip4:{protocol plain:%u}, eth:{}}} ",
             PKT_NUM, IPPROTO_ICMP);

    CHECK_RC(asn_parse_value_text(buf, ndn_traffic_template, &res, &num));
    
    /* Fill ICMP packet */
    memset(buf, 0, ICMP_HDR_LEN);
    buf[0] = type;
    buf[1] = code;
    if (dgram != NULL)
        memcpy(buf + 8, dgram, ICMP_PLD_LEN);
    else
    {
        memcpy(buf + 8, udp_pkt, ICMP_PLD_LEN);
        te_fill_buf(buf + 8, 4); /* Random ports */
    }
    
    if (type == ICMP_DEST_UNREACH && code == ICMP_FRAG_NEEDED)
            *(uint16_t *)(buf + 6) = htonl(68);
    else if (type == ICMP_ECHO)
    {  
        *(uint16_t *)(buf + 4) = htons(1);  /* Identifier */
        *(uint16_t *)(buf + 6) = htons(1);  /* Sequence Number */
    }
        
    *(uint16_t *)(buf + 2) = ~calculate_checksum(buf, len);
    CHECK_RC(asn_write_value_field(res, buf, len, "payload.#bytes"));
    
    return res;
}

static void
start_traffic()
{
    int i;
    int n = 0;
    
#define CONSTRUCT_ERROR(type, code) \
    do {                                                \
        pkt[n++] = construct_icmp(type, code, tcp_pkt); \
        pkt[n++] = construct_icmp(type, code, udp_pkt); \
        pkt[n++] = construct_icmp(type, code, NULL);    \
    } while (0)
    
    /* Construct errors */
    if (!only_echo)
    {
        CONSTRUCT_ERROR(ICMP_DEST_UNREACH, ICMP_NET_UNREACH);
        CONSTRUCT_ERROR(ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
        CONSTRUCT_ERROR(ICMP_DEST_UNREACH, ICMP_PROT_UNREACH);
        CONSTRUCT_ERROR(ICMP_DEST_UNREACH, ICMP_PORT_UNREACH);
        CONSTRUCT_ERROR(ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED);
        CONSTRUCT_ERROR(ICMP_DEST_UNREACH, ICMP_SR_FAILED);
        
        CONSTRUCT_ERROR(ICMP_TIME_EXCEEDED, ICMP_EXC_TTL);
        CONSTRUCT_ERROR(ICMP_TIME_EXCEEDED, ICMP_EXC_FRAGTIME);
        
        CONSTRUCT_ERROR(ICMP_PARAMETERPROB, 0);
    }

    pkt[n++] = construct_icmp(ICMP_ECHO, 0, NULL);
    
    for (i = 0; i < n; i++)
    {
        CHECK_RC(rcf_ta_create_session(pco_tst->ta, sid + i));

        CHECK_RC(tapi_ip4_eth_csap_create(pco_tst->ta, sid[i],
                                          tst_if->if_name,
                                          (TAD_ETH_RECV_DEF &
                                           ~TAD_ETH_RECV_OTHER) |
                                          TAD_ETH_RECV_NO_PROMISC,
                                          mac_tst, mac_iut,
                                          SIN(tst_addr)->sin_addr.s_addr,
                                          SIN(iut_addr)->sin_addr.s_addr,
                                          IPPROTO_ICMP, csap + i));

        CHECK_RC(tapi_tad_trsend_start(pco_tst->ta, sid[i], csap[i],
                                       pkt[i], RCF_MODE_NONBLOCKING));
    }
#undef CONSTRUCT_ERROR
}

/** Check datagrams transmission.
 *
 * @param rpcs1     Sending RPC server
 * @param s1        Sending socket
 * @param rpcs2     Receiving RPC server
 * @param s2        Receiving socket
 */
static void
test_connection_udp(rcf_rpc_server *rpcs1, int s1,
                    rcf_rpc_server *rpcs2, int s2)
{
    char   *rx_buf;
    char   *tx_buf;
    size_t  tx_buflen;
    te_bool is_readable;

    int count = 0;
    int rc;
    int i;
    int b;

    rx_buf = te_make_buf_by_len(SOCKTS_MSG_DGRAM_MAX);

    for (i = 0; i < UDP_MAX_ATTEMPTS_NUM; i++)
    {
        tx_buf = sockts_make_buf_dgram(&tx_buflen);
        for (b = 0; b < UDP_BUNCH; b++)
            rpc_send(rpcs1, s1, tx_buf, tx_buflen, 0);

        do {
            RPC_GET_READABILITY(is_readable, rpcs2, s2,
                                TAPI_WAIT_NETWORK_DELAY);
            if (is_readable)
            {
                rc = rpc_recv(rpcs2, s2, rx_buf, SOCKTS_MSG_DGRAM_MAX, 0);
                SOCKTS_CHECK_RECV(rpcs2, tx_buf, rx_buf, tx_buflen, rc);
                count++;
            }
        } while(is_readable);

        if (count > 0)
            break;
    }

    if (count == 0)
        TEST_VERDICT("No datagrams was received");
}

int
main(int argc, char *argv[])
{
    int num;
    int i;
    int iut_s_udp = -1;
    int tst_s_udp = -1;
    int iut_s_tcp = -1;
    int tst_s_tcp = -1;
    int iut_s_udp_snd = -1;

    char oid[RCF_MAX_ID];

    csap_handle_t              csap_eth = CSAP_INVALID_HANDLE;
    int                        sid_eth;
    asn_value                 *pkt_eth = NULL;

    uint16_t ethertype = ETHERTYPE_IP;

    TEST_START;

    for (i = 0; i < MAX_CSAP; i++)
        csap[i] = CSAP_INVALID_HANDLE;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_BOOL_PARAM(only_echo);

    sprintf(oid, "/agent:%s/interface:%s", pco_iut->ta, iut_if->if_name);
    if (tapi_cfg_base_if_get_mac(oid, mac_iut) != 0)
        TEST_STOP;

    sprintf(oid, "/agent:%s/interface:%s", pco_tst->ta, tst_if->if_name);
    if (tapi_cfg_base_if_get_mac(oid, mac_tst) != 0)
        TEST_STOP;

    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_DGRAM, RPC_IPPROTO_UDP,
                   iut_addr, tst_addr, &iut_s_udp, &tst_s_udp);

    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_IPPROTO_TCP,
                   iut_addr, tst_addr, &iut_s_tcp, &tst_s_tcp);

    iut_s_udp_snd = rpc_socket(pco_iut, RPC_PF_INET, RPC_SOCK_DGRAM,
                               RPC_IPPROTO_UDP);

    /* Create CSAP */

    CHECK_RC(rcf_ta_create_session(pco_tst->ta, &sid_eth));

    CHECK_RC(tapi_eth_csap_create(pco_tst->ta, sid_eth,
                                  tst_if->if_name,
                                  TAD_ETH_RECV_DEF |
                                  TAD_ETH_RECV_NO_PROMISC,
                                  mac_tst, mac_iut, NULL, &csap_eth));

    /* Catch row TCP and UDP packets */
    CHECK_RC(tapi_eth_add_pdu(&pkt_eth, NULL, TRUE, mac_tst, mac_iut,
                              &ethertype, TE_BOOL3_ANY /* tagged/untagged */,
                              TE_BOOL3_ANY /* Ethernet2/LLC */));

    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, sid_eth, csap_eth, pkt_eth,
                                   TIMEOUT, 100, RCF_TRRECV_PACKETS));
    /* Provoke the traffic */
    te_fill_buf(buf, sizeof(buf));
    rpc_sendto(pco_iut, iut_s_udp_snd, buf, sizeof(buf), 0, tst_addr);
    sockts_test_connection(pco_iut, iut_s_tcp, pco_tst, tst_s_tcp);

    CHECK_RC(tapi_tad_trrecv_stop(pco_tst->ta, sid_eth, csap_eth,
                                  tapi_eth_trrecv_cb_data(callback, NULL),
                                  (unsigned int *)&num));

    if (tcp_pkt[0] == 0)
        TEST_FAIL("Failed to catch row TCP packet");

    if (udp_pkt[0] == 0)
        TEST_FAIL("Failed to catch row UDP packet");

    start_traffic();
    SLEEP(2);

    /* Check usability of existing connections */
    test_connection_udp(pco_iut, iut_s_udp, pco_tst, tst_s_udp);
    test_connection_udp(pco_tst, tst_s_udp, pco_iut, iut_s_udp);
    sockts_test_connection(pco_iut, iut_s_tcp, pco_tst, tst_s_tcp);

    TEST_SUCCESS;

cleanup:
    for (i = 0; i < MAX_CSAP; i++)
    {
        if (csap[i] != CSAP_INVALID_HANDLE)
        {
#if 0
            RING("not send_stop on agt %s, csap %d", pco_tst->ta, csap[i]);
            MSLEEP(10);
#endif
            rcf_ta_trsend_stop(pco_tst->ta, sid[i], csap[i],
                               &num);
            CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0, csap[i]));
        }
        asn_free_value(pkt[i]);
    }

    if (csap_eth != CSAP_INVALID_HANDLE)
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0, csap_eth));

    CLEANUP_RPC_CLOSE(pco_iut, iut_s_udp);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s_udp);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s_tcp);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s_tcp);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s_udp_snd);

    asn_free_value(pkt_eth);

    TEST_END;
}
