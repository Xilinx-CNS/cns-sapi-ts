/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Test attacks/icmp/icmp_forged_seqnum
 * 
 */

/** @page icmp-icmp_forged_seqnum Send ICMP packet with forged sequence number
 *
 * @objective Check that port unreachable ICMP packets with forged sequence 
 *            number does not lead to denial of service.
 *
 * @param env   Private testing environment which includes three hosts and use
 *              Onload accelerated and not accelerated IUT interfaces.
 *
 * @par Scenario
 * -# Start sniffing interface of @p pco_tst1, wait for SYN packet from 
 *    @p pco_iut.
 * -# Send a SYN packet (i.e. try to  connect) from @p pco_iut
 *    to @p pco_tst1. 
 * -# Send forged ICMP message with incorrect sequence number to @p pco_iut.
 * -# Check that @p pco_iut behaves correctly, i.e. drops this ACK and
 *    repeat SYN to @p pco_tst1.
 * -# Check that next connection will be established.
 *
 * @author Igor Muzhichenko <Igor.Muzhichenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "attacks/icmp/icmp_forged_seqnum"

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

#include "te_ethernet.h"
#include "tapi_cfg_base.h"
#include "tapi_cfg.h"
#include "tapi_tad.h"
#include "tapi_eth.h"
#include "tapi_tcp.h"
#include "tapi_route_gw.h"
#include "ndn.h"

#define TIMEOUT         (1000 * 5)
#define ICMP_HDR_LEN     8   /**< Length of ICMP header in bytes */

/** User data for syn_rcv_callback() */
struct icmp_forged_seqnum_cb_flag {
    te_bool    syn_received;    /**< SYN packet reception flag */
    uint8_t    payload[1024];   /**< IP payload data */
    uint16_t   pld_len;         /**< Payload length */
} icmp_forged_seqnum_cb_flag;

/** Callback for catching TCP packets */
static void
syn_rcv_callback(const tapi_ip4_packet_t *pkt, void *userdata)
{
    struct icmp_forged_seqnum_cb_flag *ud = userdata;
    
    if (ud == NULL)
        return;

    if (pkt->ip_proto == IPPROTO_TCP)
    {
        if (((struct tcphdr *)pkt->payload)->syn == 1)
        {
            ud->syn_received = TRUE;
            ud->pld_len = pkt->pld_len;
            memcpy(ud->payload, pkt->payload, pkt->pld_len);
        }
    }
}

static asn_value*
construct_icmp(uint8_t *payload, uint16_t pld_len)
{
    char       buf[1024];    
    int        num = 1;
    asn_value *pkt;

    sprintf(buf, "{ arg-sets { simple-for:{begin 1,end 1} }, "
                 "  pdus { ip4:{protocol plain:%u}, eth:{}}} ", 
                 IPPROTO_ICMP);
                 
    CHECK_RC(asn_parse_value_text(buf, ndn_traffic_template, &pkt, &num));
    
    /* Fill ICMP packet */
    memset(buf, 0, ICMP_HDR_LEN + pld_len);
    memcpy(buf + ICMP_HDR_LEN, payload, pld_len);
    ((struct icmphdr *)buf)->type = ICMP_DEST_UNREACH;
    ((struct icmphdr *)buf)->code = ICMP_PORT_UNREACH;
    ((struct tcphdr *)(buf + ICMP_HDR_LEN))->seq = 0xabcd;

    ((struct icmphdr *)buf)->checksum = 0;
    ((struct icmphdr *)buf)->checksum = ~calculate_checksum(buf, pld_len);
    asn_write_value_field(pkt, buf, pld_len, "payload.#bytes");
    return pkt;
}

int 
main(int argc, char **argv)
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst1 = NULL;
    
    const struct if_nameindex *iut_if;
    const struct if_nameindex *tst1_if;    
    const struct sockaddr *iut_addr;
    const struct sockaddr *tst1_addr;

    asn_value     *pkt;
    csap_handle_t  tst1_csap = CSAP_INVALID_HANDLE;    
    csap_handle_t  tst1_csap_send = CSAP_INVALID_HANDLE;
     
    int iut_s_tcp = -1;
    int tst1_s_tcp = -1;
    int tst1_sid = -1;
    int tst1_sid_send = -1;

    char    oid[RCF_MAX_ID];
    uint8_t iut_mac[ETHER_ADDR_LEN];
    uint8_t tst1_mac[ETHER_ADDR_LEN];

    unsigned int num = 1;    
    int opt_val = 1;

    unsigned int addrlen = sizeof(struct sockaddr);
    
    struct icmp_forged_seqnum_cb_flag ud;
    struct sockaddr_in iut_taddr;
    struct sockaddr_in tst1_taddr;
    
    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst1_if);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst1, tst1_addr);
    
    /* Get MAC addresses */
    sprintf(oid, "/agent:%s/interface:%s", pco_iut->ta, iut_if->if_name);
    if (tapi_cfg_base_if_get_mac(oid, iut_mac) != 0)
    {
        TEST_FAIL("%s(): Can't get IUT ethernet address.", __FUNCTION__);
    }

    sprintf(oid, "/agent:%s/interface:%s", pco_tst1->ta, tst1_if->if_name);
    if (tapi_cfg_base_if_get_mac(oid, tst1_mac) != 0)
    {
        TEST_FAIL("%s(): Can't get TST1 ethernet address.", __FUNCTION__);
    }
    
    memset(&iut_taddr, 0, sizeof(iut_taddr));
    iut_taddr.sin_family = SIN(iut_addr)->sin_family;
    iut_taddr.sin_addr.s_addr = SIN(iut_addr)->sin_addr.s_addr;
    TAPI_SET_NEW_PORT(pco_iut, &iut_taddr);

    memset(&tst1_taddr, 0, sizeof(tst1_taddr));    
    tst1_taddr.sin_family = SIN(tst1_addr)->sin_family;
    tst1_taddr.sin_addr.s_addr = SIN(tst1_addr)->sin_addr.s_addr;
    TAPI_SET_NEW_PORT(pco_tst1, &tst1_taddr);

    /* Add static ARP entry with fake MAC to prevent connection establishment */
    sprintf(oid, "\x06\x05\x04\x03\x02\x01");
    CHECK_RC(tapi_update_arp(pco_iut->ta, iut_if->if_name, NULL, NULL,
                             SA(&tst1_taddr), oid, TRUE));

    /* Receiving CSAP */
    CHECK_RC(rcf_ta_create_session(pco_tst1->ta, &tst1_sid));
    CHECK_RC(tapi_ip4_eth_csap_create(pco_tst1->ta, tst1_sid, tst1_if->if_name, 
                                      TAD_ETH_RECV_DEF,
                                      (uint8_t *)oid, iut_mac,
                                      tst1_taddr.sin_addr.s_addr,
                                      iut_taddr.sin_addr.s_addr, 
                                      -1, &tst1_csap));
         
    CHECK_RC(tapi_tad_trrecv_start(pco_tst1->ta, tst1_sid, tst1_csap, 
                                   NULL, TIMEOUT, num, RCF_TRRECV_PACKETS));

    iut_s_tcp = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                           RPC_SOCK_STREAM, RPC_PF_INET);
    tst1_s_tcp = rpc_socket(pco_tst1, rpc_socket_domain_by_addr(tst1_addr),
                            RPC_SOCK_STREAM, RPC_PF_INET);
                            
    rpc_bind(pco_tst1, tst1_s_tcp, SA(&tst1_taddr));
    rpc_listen(pco_tst1, tst1_s_tcp, 1);

    rpc_ioctl(pco_iut, iut_s_tcp, RPC_FIONBIO, &opt_val);
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rpc_connect(pco_iut, iut_s_tcp, SA(&tst1_taddr));

    memset(&ud, 0, sizeof(ud));
    CHECK_RC(tapi_tad_trrecv_stop(pco_tst1->ta, tst1_sid, tst1_csap,
                         tapi_ip4_eth_trrecv_cb_data(syn_rcv_callback, &ud), 
                         &num));

    if (ud.syn_received)
    {
        CHECK_RC(rcf_ta_create_session(pco_tst1->ta, &tst1_sid_send));
        CHECK_RC(tapi_ip4_eth_csap_create(pco_tst1->ta, tst1_sid_send, 
                                          tst1_if->if_name,
                                          TAD_ETH_RECV_DEF &
                                          ~TAD_ETH_RECV_OTHER,
                                          tst1_mac, iut_mac,
                                          tst1_taddr.sin_addr.s_addr, 
                                          iut_taddr.sin_addr.s_addr,
                                          -1, &tst1_csap_send));
                                          
        pkt = construct_icmp(ud.payload, ud.pld_len);
        CHECK_RC(tapi_tad_trsend_start(pco_tst1->ta, tst1_sid_send, 
                                       tst1_csap_send, pkt, 
                                       RCF_MODE_NONBLOCKING));
    }
    
    CHECK_RC(tapi_cfg_del_neigh_entry(pco_iut->ta, iut_if->if_name, 
                                      SA(&tst1_taddr)));
    if (rpc_accept(pco_tst1, tst1_s_tcp, SA(&iut_taddr), &addrlen) == -1) 
    {
        TEST_FAIL("Can't accept connection from IUT.");
    }

    TEST_SUCCESS;

cleanup:
    if (ud.syn_received)
    {
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst1->ta, 0, tst1_csap_send));
    }
    
    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst1->ta, 0, tst1_csap));
    CLEANUP_RPC_CLOSE(pco_tst1, tst1_s_tcp);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s_tcp);

    if (pco_iut != NULL && rcf_rpc_server_restart(pco_iut) != 0)
    {
        WARN("It seems that icmp_forged_seqnum made TA crasy");
        rcf_ta_call(pco_iut->ta, 0, "die", &rc, 0, TRUE);
    }
                            
    TEST_END;
}
