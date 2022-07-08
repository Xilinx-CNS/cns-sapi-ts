/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Test attacks/ethernet/zero_src_mac
 * Zero source MAC address
 */

/** @page ethernet-zero_src_mac  Zero source MAC address
 *
 * @objective The test checks that sending of Ethernet frames with zero
 *            MAC address does not lead to system crash.
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_peer2peer
 *
 * @par Scenario
 * -# Create stream and datagram connections between @p pco_iut
 *    and @p pco_tst and check that traffic flows between them; catch
 *    TCP and UDP packets sent from IUT.
 * -# Create listening TCP socket @p iut_s.
 * -# Send flood of frames with zero source MAC address:
 *   -# UDP datagrams with destination port corresponding to existing UDP
 *      connection and different source ports.
 *   -# TCP SYN packets with @p iut_s destination port and different
 *      source ports. 
 *   -# TCP data packets corresponding to existing TCP connection.
 *   -# ARP requests for @p pco_iut IP address.
 *   -# ICMP Destination Unreachable packets with code Port Unreachable 
 *      and catched UDP packets inside.
 *   -# ICMP Destination Unreachable packets with code Fragmentation Needed
 *      and DF set and catched normal TCP data packets inside.
 *   -# ICMP Echo packets.
 * -# Check that data may be sent/received via connections created on the
 *    step 1.
 * -# Check that connection TCP and UDP is usable.
 * -# Close all sockets created during the test.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "attacks/ethernet/zero_src_mac"

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

#include "tapi_tad.h"
#include "tapi_ip4.h"
#include "tapi_udp.h"
#include "tapi_tcp.h"
#include "tapi_ip4.h"
#include "tapi_eth.h"
#include "tapi_arp.h"
#include "tapi_cfg.h"
#include "tapi_cfg_base.h"
#include "ndn.h"

/** Number of packets for flooding */
#define PKT_NUM          64
#define ICMP_HDR_LEN     8   /**< Length of ICMP header in bytes */
#define ICMP_PLD_LEN     28  /**< Original packet length in ICMP error */
#define TIMEOUT          (5 * 1000)  /**< 5 seconds for packet catching */
#define IP_HDR_LEN       20          /**< IP header length in bytes */


/** Auxiliary buffer */
static char buf[1024 * 16];

static char tcp_pkt[ICMP_PLD_LEN];
static char udp_pkt[ICMP_PLD_LEN];

static uint32_t seqn;

/** Callback to catch TCP ACK to find out next SEQN */
static void 
ack_callback(asn_value *pkt, void *userdata)
{
    size_t len = sizeof(uint32_t);
    int    rc;
    
    UNUSED(userdata);
    
    if ((rc = asn_read_value_field(pkt, &seqn, &len, 
                                   "pdus.0.#tcp.ackn.#plain")) != 0)
        ERROR("Cannot read seqn: %r", rc);
}

/** Callback for catching row TCP and UDP packets */
static void
eth_callback(const asn_value *packet, int layer,
             const ndn_eth_header_plain *header,
             const uint8_t *payload, uint16_t plen, void *userdata)
{
    UNUSED(packet);
    UNUSED(layer);
    UNUSED(userdata);
    UNUSED(header);
    
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

/** Construct ICMP packet */
static asn_value *
construct_icmp(uint8_t type, uint8_t code)
{
    asn_value *pkt;
    int        len = ICMP_PLD_LEN + ICMP_HDR_LEN;;
    int        num;
    
    sprintf(buf, 
             "{ arg-sets { simple-for:{begin 1,end %u} }, "
             "  pdus  { ip4:{protocol plain:%u}, eth:{}}} ",
             PKT_NUM, IPPROTO_ICMP);

    CHECK_RC(asn_parse_value_text(buf, ndn_traffic_template, &pkt, &num));
    
    /* Fill ICMP packet */
    te_fill_buf(buf, len);
    buf[0] = type;
    buf[1] = code;
    memset(buf + 2, 0, 6);
    if (type == ICMP_DEST_UNREACH)
    {
        if (code == ICMP_FRAG_NEEDED)
        {
            *(uint16_t *)(buf + 6) = htonl(68);
            memcpy(buf + 8, tcp_pkt, sizeof(tcp_pkt));
        }
        else
            memcpy(buf + 8, udp_pkt, sizeof(udp_pkt));
    }
    else
    {  
        /* Echo */
        *(uint16_t *)(buf + 4) = htons(1);  /* Identifier */
        *(uint16_t *)(buf + 6) = htons(1);  /* Sequence Number */
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
    const struct sockaddr     *iut_addr = NULL;
    const struct sockaddr     *tst_addr = NULL;
    
    struct sockaddr_in         addr;
    ndn_arp_header_plain      *arp_hdr = (ndn_arp_header_plain *)buf;
    
    int num;
    int iut_s_tcp = -1;
    int iut_s_udp = -1;
    int tst_s_tcp = -1;
    int tst_s_udp = -1;
    int iut_srv = -1;
    int iut_acc = -1;
    int tst_clnt = -1;

    uint8_t mac_iut[ETHER_ADDR_LEN];
    uint8_t mac_tst[ETHER_ADDR_LEN];
    uint8_t mac_fake[ETHER_ADDR_LEN] = { 0, };
    
    char oid[RCF_MAX_ID];

    enum {
       IND_UDP,
       IND_TCP_DATA,
       IND_TCP_SYN,
       IND_ICMP_PORT,
       IND_ICMP_DF,
       IND_ICMP_ECHO,
       IND_ARP,
       IND_MAX
    } ind;

    csap_handle_t csap[IND_MAX];
    int           sid[IND_MAX];
    asn_value    *pkt[IND_MAX];
    
    uint16_t type = ETHERTYPE_IP;
    
    for (ind = 0; ind < IND_MAX; ind++)
    {
        csap[ind] = CSAP_INVALID_HANDLE;
        pkt[ind] = NULL;
    }
    
    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    
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

    addr = *SIN(iut_addr);
    TAPI_SET_NEW_PORT(pco_iut, &addr);
    iut_srv = rpc_socket(pco_iut, RPC_PF_INET, RPC_SOCK_STREAM, 
                         RPC_PROTO_DEF);
    tst_clnt = rpc_socket(pco_tst, RPC_PF_INET, RPC_SOCK_STREAM, 
                          RPC_PROTO_DEF);
    rpc_bind(pco_iut, iut_srv, (struct sockaddr *)&addr);
    rpc_listen(pco_iut, iut_srv, SOCKTS_BACKLOG_DEF);
    
    /* Create all CSAPs */

    for (ind = 0; ind < IND_MAX; ind++)
        CHECK_RC(rcf_ta_create_session(pco_tst->ta, sid + ind));

    CHECK_RC(tapi_udp_ip4_eth_csap_create(pco_tst->ta, sid[IND_UDP],
                                          tst_if->if_name,
                                          TAD_ETH_RECV_DEF |
                                          TAD_ETH_RECV_NO_PROMISC,
                                          mac_fake, mac_iut,
                                          SIN(tst_addr)->sin_addr.s_addr,
                                          SIN(iut_addr)->sin_addr.s_addr,
                                          SIN(tst_addr)->sin_port,
                                          SIN(iut_addr)->sin_port,
                                          csap + IND_UDP));

    CHECK_RC(tapi_tcp_ip4_eth_csap_create(pco_tst->ta, sid[IND_TCP_DATA],
                                          tst_if->if_name,
                                          TAD_ETH_RECV_DEF |
                                          TAD_ETH_RECV_NO_PROMISC,
                                          mac_tst, mac_iut,
                                          SIN(tst_addr)->sin_addr.s_addr,
                                          SIN(iut_addr)->sin_addr.s_addr,
                                          SIN(tst_addr)->sin_port,
                                          SIN(iut_addr)->sin_port,
                                          csap + IND_TCP_DATA));

    CHECK_RC(tapi_tcp_ip4_eth_csap_create(pco_tst->ta, sid[IND_TCP_SYN],
                                          tst_if->if_name,
                                          TAD_ETH_RECV_DEF |
                                          TAD_ETH_RECV_NO_PROMISC,
                                          mac_fake, mac_iut,
                                          SIN(tst_addr)->sin_addr.s_addr,
                                          SIN(iut_addr)->sin_addr.s_addr,
                                          -1, addr.sin_port,
                                          csap + IND_TCP_SYN));

    for (ind = IND_ICMP_PORT; ind <= IND_ICMP_ECHO; ind++)
        CHECK_RC(tapi_ip4_eth_csap_create(pco_tst->ta, sid[ind],
                                          tst_if->if_name,
                                          TAD_ETH_RECV_DEF |
                                          TAD_ETH_RECV_NO_PROMISC,
                                          mac_fake, mac_iut,
                                          SIN(tst_addr)->sin_addr.s_addr,
                                          SIN(iut_addr)->sin_addr.s_addr,
                                          -1, csap + ind));

    CHECK_RC(tapi_eth_csap_create(pco_tst->ta, sid[IND_ARP],
                                  tst_if->if_name,
                                  TAD_ETH_RECV_DEF |
                                  TAD_ETH_RECV_NO_PROMISC,
                                  mac_fake, mac_iut, NULL, csap + IND_ARP));

    /* Catch TCP ACK packets */
    CHECK_RC(tapi_tcp_ip4_eth_recv_start(pco_tst->ta, sid[IND_TCP_DATA], 
                                         csap[IND_TCP_DATA], 
                                         SIN(iut_addr)->sin_addr.s_addr,
                                         SIN(tst_addr)->sin_addr.s_addr,
                                         SIN(iut_addr)->sin_port,
                                         SIN(tst_addr)->sin_port,
                                         TIMEOUT, 10, RCF_TRRECV_PACKETS));

    /* Catch row TCP and UDP packets */
    CHECK_RC(tapi_eth_add_pdu(pkt, NULL, TRUE, mac_tst, mac_iut, &type,
                              TE_BOOL3_ANY /* tagged/untagged */,
                              TE_BOOL3_ANY /* Ethernet2/LLC */));
    
    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, sid[IND_ARP], csap[IND_ARP],
                                   pkt[0], TIMEOUT, 10, RCF_TRRECV_PACKETS));
  
    /* Provoke the traffic */
    sockts_test_connection(pco_iut, iut_s_tcp, pco_tst, tst_s_tcp); 
    sockts_test_connection(pco_iut, iut_s_udp, pco_tst, tst_s_udp); 
    
    CHECK_RC(tapi_tad_trrecv_stop(pco_tst->ta, sid[IND_TCP_DATA], 
                                  csap[IND_TCP_DATA],
                                  tapi_tad_trrecv_make_cb_data(ack_callback,
                                                               NULL),
                                  (unsigned int *)&num));

    CHECK_RC(tapi_tad_trrecv_stop(pco_tst->ta, sid[IND_ARP], 
                                  csap[IND_ARP],
                                  tapi_eth_trrecv_cb_data(eth_callback,
                                                          NULL), 
                                  (unsigned int *)&num)); 
                                
    if (seqn == 0)
        TEST_FAIL("Cannot find out SEQN for TCP data packets");
        
    if (udp_pkt[0] == 0)
        TEST_FAIL("Failed to catch row UDP packet");

    if (tcp_pkt[0] == 0)
        TEST_FAIL("Failed to catch row TCP packet");
        
    asn_free_value(pkt[0]);
    pkt[0] = NULL;

    /* Construct patterns */
    sprintf(buf, 
             "{ arg-sets { simple-for:{begin 1,end %u} }, "
             "  pdus  { udp:{}, ip4:{}, eth:{}},          "
             "  payload length:100 }                      ",
             PKT_NUM);

    CHECK_RC(asn_parse_value_text(buf, ndn_traffic_template, 
                                  pkt + IND_UDP, &num));

    sprintf(buf, 
             "{ arg-sets { simple-for:{begin 1,end %u} },     "
             "  pdus  { tcp:{flags plain:8, seqn plain:%u},   " 
             "          ip4:{},                               "
             "          eth:{src-addr plain:'0 0 0 0 0 0'H}}, "
             "  payload length:100 }                          ",
             PKT_NUM, seqn);

    CHECK_RC(asn_parse_value_text(buf, ndn_traffic_template, 
                                  pkt + IND_TCP_DATA, &num));

    sprintf(buf, 
             "{ arg-sets { simple-for:{begin 1,end %u} },       "
             "  pdus  {                                         "
             "      tcp:{ src-port script:\"expr:(5000+$0)\",   "
             "            flags plain:2,                        "
             "            seqn plain:666 },                     "
             "      ip4:{},  eth:{}}}                           ",
             PKT_NUM);

    CHECK_RC(asn_parse_value_text(buf, ndn_traffic_template, 
                                  pkt + IND_TCP_SYN, &num));

    pkt[IND_ICMP_PORT] = construct_icmp(ICMP_DEST_UNREACH, 
                                        ICMP_PORT_UNREACH);
    pkt[IND_ICMP_DF] = construct_icmp(ICMP_DEST_UNREACH, 
                                      ICMP_FRAG_NEEDED);
    pkt[IND_ICMP_ECHO] = construct_icmp(ICMP_ECHO, 0);

    sprintf(buf, 
             "{ arg-sets { simple-for:{begin 1,end %u} },       "
             "  pdus  { eth:{length-type plain:%u,              "
             "          dst-addr plain:'FF FF FF FF FF FF'H}}}  ",
             PKT_NUM, ETHERTYPE_ARP);
    CHECK_RC(asn_parse_value_text(buf, ndn_traffic_template, 
                                  pkt + IND_ARP, &num));

    te_fill_buf(buf, sizeof(buf));
    memset(arp_hdr, 0, sizeof(*arp_hdr));
    arp_hdr->hw_type = htons(ARPHRD_ETHER);
    arp_hdr->proto_type = htons(ETHERTYPE_IP);
    arp_hdr->hw_size = ETHER_ADDR_LEN; 
    arp_hdr->proto_size = sizeof(struct in_addr); 
    arp_hdr->opcode = htons(ARPOP_REQUEST);
    memcpy(arp_hdr->snd_hw_addr, mac_fake, ETHER_ADDR_LEN);
    *(struct in_addr *)(arp_hdr->snd_proto_addr) = SIN(tst_addr)->sin_addr;
    *(struct in_addr *)(arp_hdr->tgt_proto_addr) = SIN(iut_addr)->sin_addr;

    CHECK_RC(asn_write_value_field(pkt[IND_ARP], arp_hdr, sizeof(*arp_hdr), 
                                   "payload.#bytes"));
             
    /* Start flooding */
    for (ind = 0; ind < IND_MAX; ind++)
        CHECK_RC(tapi_tad_trsend_start(pco_tst->ta, sid[ind], csap[ind], 
                                       pkt[ind], RCF_MODE_NONBLOCKING));

    SLEEP(1);

    for (ind = 0; ind < IND_MAX; ind++)
        rcf_ta_trsend_stop(pco_tst->ta, sid[ind], csap[ind], &num);

    /* 
     * ARP entry with invalid MAC be added because of flood, don't
     * wait to fail because of this invalid ARP entry.
     */
    CHECK_RC(tapi_cfg_del_neigh_entry(pco_iut->ta, iut_if->if_name,
                                      tst_addr));
    CFG_WAIT_CHANGES;

    /* Check that connection may be established and used */
    pco_tst->timeout = 60000;
    rpc_connect(pco_tst, tst_clnt, SA(&addr));
    iut_acc = rpc_accept(pco_iut, iut_srv, NULL, NULL);
    sockts_test_connection(pco_iut, iut_acc, pco_tst, tst_clnt);

    /* Check usability of UDP */
    
    /* Re-open socket to avoid send failures due ICMP errors */
    RPC_CLOSE(pco_iut, iut_s_udp);
    iut_s_udp = rpc_socket(pco_iut, RPC_PF_INET, 
                           RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);
    rpc_bind(pco_iut, iut_s_udp, iut_addr);
    rpc_connect(pco_iut, iut_s_udp, tst_addr);
    sockts_test_connection(pco_iut, iut_s_udp, pco_tst, tst_s_udp);
    
    TEST_SUCCESS;

cleanup:
    for (ind = 0; ind < IND_MAX; ind++)
    {
        asn_free_value(pkt[ind]);
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0, csap[ind]));
    }

    CLEANUP_RPC_CLOSE(pco_iut, iut_s_udp);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s_udp);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s_tcp);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s_tcp);
    CLEANUP_RPC_CLOSE(pco_tst, tst_clnt);
    CLEANUP_RPC_CLOSE(pco_iut, iut_srv);
    CLEANUP_RPC_CLOSE(pco_iut, iut_acc);

    TEST_END;
}
