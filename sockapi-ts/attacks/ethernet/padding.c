/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Test attacks/ethernet/padding
 * Padding of short frames
 */

/** @page ethernet-padding  Padding of short frames
 *
 * @objective Check that short frames are padded with zero bytes.
 *
 * @reference CERT VU#412115 http://www.kb.cert.org/vuls/id/412115
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_peer2peer
 * @param sock_type Socket type:
 *                  - SOCK_DGRAM
 *                  - SOCK_STREAM
 *
 * @par Scenario
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "attacks/ethernet/padding"

#include "sockapi-test.h"

#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#endif

#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif

#include "tapi_eth.h"
#include "tapi_arp.h"
#include "tapi_cfg.h"
#include "tapi_cfg_base.h"
#include "tapi_route_gw.h"

#define TIMEOUT          (5 * 1000)  /**< 5 seconds for packet catching */

/** Minimum Ethernet frame payload length */
#define ETH_MIN_PLD_LEN  (ETHER_MIN_LEN - ETHER_CRC_LEN - ETHER_HDR_LEN)


static void
callback(const asn_value *packet, int layer,
         const ndn_eth_header_plain *header,
         const uint8_t *payload, uint16_t plen, void *userdata)
{
    int len = (header->len_type == ETHERTYPE_ARP) ?
                  sizeof(ndn_arp_header_plain) :
                  ntohs(((struct iphdr *)payload)->tot_len);
    int i;

    UNUSED(packet);
    UNUSED(layer);
    UNUSED(header);
    UNUSED(userdata);

    if (plen < ETH_MIN_PLD_LEN)
        TEST_VERDICT("%s Ethernet frame is too short",
                     header->len_type == ETHERTYPE_ARP ? "ARP" : "IP");

    for (i = len; i < ETH_MIN_PLD_LEN; i++)
    {
        if (payload[i] != 0)
            TEST_VERDICT("Short %s frame is not padded by zeros",
                         header->len_type == ETHERTYPE_ARP ? "ARP" : "IP");
    }
}

int
main(int argc, char *argv[])
{
    const struct if_nameindex *iut_if;
    const struct if_nameindex *tst_if;
    rcf_rpc_server            *pco_iut = NULL;
    rcf_rpc_server            *pco_tst = NULL;
    int                        iut_s = -1;
    int                        tst_s = -1;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;
    struct sockaddr        *new_addr = NULL;
    cfg_handle              new_addr_handle = CFG_HANDLE_INVALID;
    tapi_env_net           *net = NULL;
    rpc_socket_type         sock_type;

    csap_handle_t              csap = CSAP_INVALID_HANDLE;
    asn_value                 *pkt = NULL;
    int                        sid;

    uint8_t         buf = 0;

    uint8_t mac_iut[ETHER_ADDR_LEN];
    uint8_t mac_tst[ETHER_ADDR_LEN];

    te_bool iut_arp_entry_added = FALSE;

    char oid[RCF_MAX_ID];

    unsigned int    num;

    uint16_t    type;


    /*
     * Test preambule.
     */
    TEST_START;

    TEST_GET_NET(net);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);

    sprintf(oid, "/agent:%s/interface:%s", pco_iut->ta, iut_if->if_name);
    if (tapi_cfg_base_if_get_mac(oid, mac_iut) != 0)
        TEST_STOP;

    sprintf(oid, "/agent:%s/interface:%s", pco_tst->ta, tst_if->if_name);
    if (tapi_cfg_base_if_get_mac(oid, mac_tst) != 0)
        TEST_STOP;

    CHECK_RC(tapi_update_arp(pco_tst->ta, tst_if->if_name, NULL, NULL,
                             iut_addr, mac_iut, TRUE));
    iut_arp_entry_added = TRUE;

    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);
    TEST_STEP("Send some data via @p iut_s and @p tst_s and "
              "receive them via @p tst_s and @p iut_s.");
    sockts_test_connection(pco_iut, iut_s, pco_tst, tst_s);

    CHECK_RC(rcf_ta_create_session(pco_tst->ta, &sid));

    CHECK_RC(tapi_eth_csap_create(pco_tst->ta, sid, tst_if->if_name,
                                  TAD_ETH_RECV_DEF |
                                  TAD_ETH_RECV_NO_PROMISC,
                                  NULL, NULL, NULL, &csap));

    type = ETHERTYPE_IP;
    CHECK_RC(tapi_eth_add_pdu(&pkt, NULL, TRUE, mac_tst, mac_iut, &type,
                              TE_BOOL3_ANY /* tagged/untagged */,
                              TE_BOOL3_ANY /* Ethernet2/LLC */));
    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, sid, csap, pkt,
                                   TIMEOUT, 10, RCF_TRRECV_PACKETS));
    TAPI_WAIT_NETWORK;

    TEST_STEP("Send Ethernet frame with IP packet with payload "
              " @c 1 byte length.");
    rpc_send(pco_iut, iut_s, "A", 1, 0);

    rpc_recv(pco_tst, tst_s, &buf, 1, 0);
    TEST_STEP("Check that Ethernet frame with the data is padded "
              "by zero bytes.");
    CHECK_RC(tapi_tad_trrecv_stop(pco_tst->ta, sid, csap,
                                  tapi_eth_trrecv_cb_data(callback, NULL), 
                                  &num));
    if (num == 0)
        TEST_FAIL("No IP packets are catched");


    TEST_STEP("Allocate a new IP address @b new_addr from the same network "
              "as @p tst_addr, choosing it so that there is no neighbor "
              "entry on IUT for it yet.");
    CHECK_RC(tapi_env_allocate_addr(net, AF_INET, &new_addr, NULL));
    CHECK_RC(tapi_allocate_set_port(pco_tst, new_addr));
    rc = tapi_cfg_get_neigh_entry(pco_iut->ta, iut_if->if_name, new_addr,
                                  NULL, NULL, NULL);
    if (rc != TE_RC(TE_CS, TE_ENOENT))
    {
      TEST_FAIL("Fail to allocate new IP address without neighbor "
                "entry on IUT");
    }

    TEST_STEP("Add @b new_addr on @p tst_if interface on Tester.");
    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_tst->ta, tst_if->if_name,
                                           new_addr, net->ip4pfx,
                                           TRUE, &new_addr_handle));
    CFG_WAIT_CHANGES;

    type = ETHERTYPE_ARP;
    asn_free_value(pkt); pkt = NULL;
    CHECK_RC(tapi_eth_add_pdu(&pkt, NULL, TRUE, NULL, mac_iut, &type,
                              TE_BOOL3_ANY /* tagged/untagged */,
                              TE_BOOL3_ANY /* Ethernet2/LLC */));
    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, sid, csap, pkt,
                                   TIMEOUT, 10, RCF_TRRECV_PACKETS));
    TAPI_WAIT_NETWORK;

    TEST_STEP("Send data with payload @c 1 byte length");
    RPC_CLOSE(pco_iut, iut_s);
    RPC_CLOSE(pco_tst, tst_s);

    TAPI_SET_NEW_PORT(pco_iut, iut_addr);
    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, new_addr, &iut_s, &tst_s);

    if (sock_type == RPC_SOCK_DGRAM)
    {
        rpc_send(pco_iut, iut_s, "B", 1, 0);
        rpc_recv(pco_tst, tst_s, &buf, 1, 0);
    }

    TAPI_WAIT_NETWORK;

    TEST_STEP("Catch ARP packet and check that Ethernet frame "
              "with the data is padded by zero bytes.");
    CHECK_RC(tapi_tad_trrecv_stop(pco_tst->ta, sid, csap,
                                  tapi_eth_trrecv_cb_data(callback, NULL),
                                  &num));

    if (num == 0)
        TEST_FAIL("No ARP packets are catched");

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    asn_free_value(pkt);
    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0, csap));

    CLEANUP_CHECK_RC(cfg_del_instance(new_addr_handle, FALSE));
    CLEANUP_CHECK_RC(tapi_cfg_del_neigh_entry(pco_iut->ta, iut_if->if_name,
                                              new_addr));
    free(new_addr);

    if (iut_arp_entry_added)
    {
        CLEANUP_CHECK_RC(tapi_cfg_del_neigh_entry(pco_tst->ta,
                                                  tst_if->if_name,
                                                  iut_addr));
    }

    TEST_END;
}
