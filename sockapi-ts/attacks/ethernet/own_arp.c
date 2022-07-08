/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Test attacks/ethernet/own_arp  
 * ARP packets for host MAC address
 */

/** @page ethernet-own_arp ARP packets for host MAC address
 *
 * @objective Check that ARP requests with IUT IP address and
 * non-IUT MAC address do not lead to IUT MAC address corruptiion.
 *
 * @reference CERT VU#399355: http://www.kb.cert.org/vuls/id/399355
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_peer2peer
 * @param reply     ARP reply from @p pco_iut should be received if @c TRUE
 *
 * @par Scenario
 * -# Send UDP datagram from @p pco_iut to @p pco_tst to guarantee
 *    that ARP entry for @p pco_tst host exists in the ARP table of the 
 *    @p pco_iut host.
 * -# Retrieve IP address @p iut_addr of the interface @p iut_if.
 * -# Retrieve MAC address @p iut_mac of the interface @p iut_if.
 * -# Choose IP address @p req_addr from the subnet which @p iut_addr
 *    belongs to.
 * -# If @p reply is @b TRUE, add @p req_addr to the interface @p iut_if.
 * -# Send ARP request for address @p req_addr, source IP address 
 *    @p iut_addr and MAC address, which is not equal to @p iut_mac.
 * -# Send UDP datagram from @p pco_iut to @p pco_tst and check that
 *    source MAC address in the Ethernet frame is @p iut_mac.
 * -# Remove ARP entry for @p pco_tst host from the ARP table of the
 *    @p pco_iut host.
 * -# Send UDP datagram from @p pco_iut to @p pco_tst and check that
 *    source MAC address in the Ethernet frame is @p iut_mac.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "attacks/ethernet/own_arp"

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
#include "tapi_cfg.h"
#include "tapi_ip4.h"
#include "tapi_eth.h"
#include "tapi_arp.h"
#include "tapi_cfg_base.h"
#include "ndn.h"

#define TIMEOUT          (5 * 1000)  /**< 5 seconds for packet catching */

/** Auxiliary buffer */
static char buf[1024 * 16];

/** MAC address of the IUT host */
static uint8_t mac_iut[ETHER_ADDR_LEN];

static te_bool mac_ok = FALSE;
static te_bool catched = FALSE;

/** Callback for catching row TCP and UDP packets */
static void
callback(const asn_value *packet, int layer,
         const ndn_eth_header_plain *header,
         const uint8_t *payload, uint16_t plen, void *userdata)
{
    UNUSED(packet);
    UNUSED(layer);
    UNUSED(userdata);
    UNUSED(header);
    UNUSED(plen);
    
    if (((struct iphdr *)payload)->protocol != IPPROTO_UDP)
        return;
        
    catched = TRUE;
        
    if (memcmp(header->src_addr, mac_iut, sizeof(mac_iut)) == 0)
        mac_ok = TRUE;
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
    const struct sockaddr     *tst_fake_addr = NULL;
    te_bool                    reply;
    tapi_env_net              *net;
    
    ndn_arp_header_plain      *arp_hdr = (ndn_arp_header_plain *)buf;
    
    unsigned int num;

    int iut_s = -1;
    int tst_s = -1;

    uint8_t mac_tst[ETHER_ADDR_LEN];
    uint8_t mac_fake[ETHER_ADDR_LEN];
    
    char oid[RCF_MAX_ID];
    
    cfg_handle handle = CFG_HANDLE_INVALID;

    csap_handle_t csap = CSAP_INVALID_HANDLE;
    int           sid;
    asn_value    *pkt = NULL;
    
    uint16_t type = ETHERTYPE_IP;
    
    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_tst, tst_fake_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_BOOL_PARAM(reply);
    TEST_GET_NET(net);
    
    sprintf(oid, "/agent:%s/interface:%s", pco_iut->ta, iut_if->if_name);
    if (tapi_cfg_base_if_get_mac(oid, mac_iut) != 0)
        TEST_STOP;

    sprintf(oid, "/agent:%s/interface:%s", pco_tst->ta, tst_if->if_name);
    if (tapi_cfg_base_if_get_mac(oid, mac_tst) != 0)
        TEST_STOP;

    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_DGRAM, 
                   RPC_IPPROTO_UDP,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    sockts_test_connection(pco_iut, iut_s, pco_tst, tst_s);

    if (reply)
    {
        CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_iut->ta, 
                     iut_if->if_name, tst_fake_addr,
                     net->ip4pfx, FALSE, &handle));
    }
                   
    /* Create CSAP */

    CHECK_RC(rcf_ta_create_session(pco_tst->ta, &sid));

    te_fill_buf(mac_fake, sizeof(mac_fake));

    CHECK_RC(tapi_eth_csap_create(pco_tst->ta, sid,
                                  tst_if->if_name,
                                  TAD_ETH_RECV_DEF |
                                  TAD_ETH_RECV_NO_PROMISC,
                                  NULL, NULL, NULL, &csap));

    /* Send ARP request */
    sprintf(buf, 
             "{ pdus { eth:{length-type plain:%u,                  "
             "              dst-addr plain:'FF FF FF FF FF FF'H,   "
             "              src-addr plain:'%02X %02X %02X %02X %02X %02X'H }}}",
             ETHERTYPE_ARP, mac_fake[0], mac_fake[1], mac_fake[2],
             mac_fake[3], mac_fake[4], mac_fake[5]);

    if ((rc = asn_parse_value_text(buf, ndn_traffic_template, 
                                   &pkt, (int *)&num)) != 0)
    {
        TEST_FAIL("asn_parse_value_text falied with rc %r; template\n%s",
                  rc, buf);
    }

    te_fill_buf(buf, sizeof(buf));
    memset(arp_hdr, 0, sizeof(*arp_hdr));
    arp_hdr->hw_type = htons(ARPHRD_ETHER);
    arp_hdr->proto_type = htons(ETHERTYPE_IP);
    arp_hdr->hw_size = ETHER_ADDR_LEN; 
    arp_hdr->proto_size = sizeof(struct in_addr); 
    arp_hdr->opcode = htons(ARPOP_REQUEST);
    memcpy(arp_hdr->snd_hw_addr, mac_fake, ETHER_ADDR_LEN);
    *(struct in_addr *)(arp_hdr->snd_proto_addr) = 
        SIN(iut_addr)->sin_addr;
    *(struct in_addr *)(arp_hdr->tgt_proto_addr) = 
        SIN(tst_fake_addr)->sin_addr;

    CHECK_RC(asn_write_value_field(pkt, buf, sizeof(*arp_hdr), 
                                   "payload.#bytes"));

    CHECK_RC(tapi_tad_trsend_start(pco_tst->ta, sid, csap, pkt, 
                                   RCF_MODE_BLOCKING));
    
    asn_free_value(pkt); pkt = NULL;
                    
    /* Send and catch UDP packet */
    CHECK_RC(tapi_eth_add_pdu(&pkt, NULL, TRUE, mac_tst, NULL, &type,
                              TE_BOOL3_ANY /* tagged/untagged */, 
                              TE_BOOL3_ANY /* Ethernet2/LLC */));
    
    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, sid, csap, pkt,
                                   TIMEOUT, 10, RCF_TRRECV_PACKETS));
    rpc_send(pco_iut, iut_s, "Hello", sizeof("Hello"), 0);
    CHECK_RC(tapi_tad_trrecv_stop(pco_tst->ta, sid, csap,
                                  tapi_eth_trrecv_cb_data(callback, NULL), 
                                  &num));
                                
    if (!catched)
        TEST_FAIL("UDP datagram is not catched");
        
    if (!mac_ok)
        TEST_FAIL("IUT uses incorrect source MAC address");

    /* Cleanup ARP table */
    CHECK_RC(tapi_cfg_del_neigh_dynamic(pco_iut->ta, iut_if->if_name));

    /* Send and catch UDP packet */
    catched = mac_ok = FALSE;
    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, sid, csap, pkt,
                                   TIMEOUT, 10, RCF_TRRECV_PACKETS));
    rpc_send(pco_iut, iut_s, "Hello", sizeof("Hello"), 0);
    SLEEP(1); /* needs time to ARP request/responce */
    CHECK_RC(tapi_tad_trrecv_stop(pco_tst->ta, sid, csap,
                                  tapi_eth_trrecv_cb_data(callback, NULL), 
                                  &num));
    
    if (!catched)
        TEST_FAIL("UDP datagram is not catched");
        
    if (!mac_ok)
        TEST_FAIL("IUT uses incorrect source MAC address");

    TEST_SUCCESS;

cleanup:
    if (csap != CSAP_INVALID_HANDLE)
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0, csap));

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    
    if (handle != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(cfg_del_instance(handle, FALSE));
        
    asn_free_value(pkt);
    
    TEST_END;
}
