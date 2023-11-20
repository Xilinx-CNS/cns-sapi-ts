/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * ARP table
 *
 * $Id$
 */

/** @page arp-permanent_entry_untouched_by_request Permanent ARP entry remains untouched by receiving ARP request
 *
 * @objective Check that permanent ARP entry remains untouched by
 *            receiving ARP request
 *
 * @type conformance
 *
 * @reference @ref COMER, chapter 5
 *
 * @param pco_iut           PCO on IUT
 * @param pco_tst           PCO on TESTER
 * @param iut_addr          Network address on IUT
 * @param tst_addr          Network address on Tester
 * @param iut_lladdr        Ethernet address on IUT
 * @param tst_lladdr        Ethernet address on Tester
 * @param alien_link_addr   Alien link address
 * @param iut_if            Network interface on IUT
 * @param tst_if            Network interface on Tester
 * @param sock_type         Socket type
 *
 * @par Test sequence:
 *
 * @author Renata Sayakhova <Renata.Sayakhova@oktetlabs.ru>
 */
#define TE_TEST_NAME "arp/permanent_entry_untouched_by_request"

#include "sockapi-test.h"
#include "arp_test_macros.h"
#include "arp_send_recv.h"
#include "tapi_route_gw.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    const struct sockaddr  *iut_lladdr = NULL;
    const struct sockaddr  *tst_lladdr = NULL;
    const struct sockaddr  *alien_link_addr = NULL;

    const struct if_nameindex  *iut_if = NULL;
    const struct if_nameindex  *tst_if = NULL;

    csap_handle_t eth_filter_handle1 = CSAP_INVALID_HANDLE;
    csap_handle_t eth_filter_handle2 = CSAP_INVALID_HANDLE;
    csap_handle_t arp_filter_handle = CSAP_INVALID_HANDLE;
    unsigned int  received1 = 0;
    unsigned int  received2 = 0;
    unsigned int  received3 = 0;

    uint8_t                 ether_buf[ETHER_ADDR_LEN];
    te_bool                 is_static;
    cs_neigh_entry_state    state;

    int iut_s = -1;
    int tst_s = -1;

    void   *tx_buf = NULL;
    size_t  buf_len;

    sockts_socket_type sock_type;

    /* Preambule */
    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    TEST_GET_LINK_ADDR(iut_lladdr);
    TEST_GET_LINK_ADDR(tst_lladdr);
    TEST_GET_LINK_ADDR(alien_link_addr);

    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);

    SOCKTS_GET_SOCK_TYPE(sock_type);

    /* Scenario */

    TEST_STEP("Create a pair of sockets on IUT and Tester, "
              "connect them if required according to @p sock_type.");
    SOCKTS_CONNECTION(pco_iut, pco_tst, iut_addr, tst_addr,
                      sock_type, &iut_s, &tst_s, NULL);

    TEST_STEP("If there is a Tester ARP entry in IUT ARP table, delete it.");
    CHECK_RC(tapi_cfg_del_neigh_entry(pco_iut->ta, iut_if->if_name, tst_addr));

    TEST_STEP("If there is a IUT ARP entry in Tester ARP table, delete it.");
    CHECK_RC(tapi_cfg_del_neigh_entry(pco_tst->ta, tst_if->if_name, iut_addr));

    TEST_STEP("Add permanent ARP entry for @p tst_addr with "
              "incorrect @p alien_link_addr on IUT.");
    CHECK_RC(tapi_update_arp(pco_iut->ta, iut_if->if_name, NULL, NULL,
                             tst_addr, CVT_HW_ADDR(alien_link_addr),
                             TRUE));

    CFG_WAIT_CHANGES;

    START_ARP_FILTER_WITH_HDR(pco_tst->ta, tst_if->if_name,
                              CVT_HW_ADDR(iut_lladdr), NULL,
                              ARPOP_REQUEST,
                              TAD_ETH_RECV_DEF,
                              NULL, NULL,
                              CVT_PROTO_ADDR(tst_addr),
                              NULL, 0, arp_filter_handle);

    TEST_STEP("Send some data from Tester socket. It should result in ARP "
              "request for @p iut_addr from Tester.");
    CHECK_NOT_NULL((tx_buf = sockts_make_buf_dgram(&buf_len)));
    RPC_SEND(rc, pco_tst, tst_s, tx_buf, buf_len, 0);
    TAPI_WAIT_NETWORK;

    START_ETH_FILTER(pco_tst->ta, tst_if->if_name,
                     TAD_ETH_RECV_DEF,
                     CVT_HW_ADDR(iut_lladdr),
                     CVT_HW_ADDR(alien_link_addr),
                     ETHERTYPE_IP,
                     0,
                     eth_filter_handle1);

    START_ETH_FILTER(pco_tst->ta, tst_if->if_name,
                     TAD_ETH_RECV_DEF,
                     CVT_HW_ADDR(iut_lladdr),
                     CVT_HW_ADDR(tst_lladdr),
                     ETHERTYPE_IP,
                     0,
                     eth_filter_handle2);

    TAPI_WAIT_NETWORK;

    TEST_STEP("Send some data from IUT socket.");
    if (sock_type == SOCKTS_SOCK_UDP_NOTCONN)
        RPC_SENDTO(rc, pco_iut, iut_s, tx_buf, buf_len, 0, tst_addr);
    else
        RPC_SEND(rc, pco_iut, iut_s, tx_buf, buf_len, 0);

    TAPI_WAIT_NETWORK;

    TEST_STEP("Check that permanent ARP entry for @p tst_addr was not "
              "changed on IUT.");
    CHECK_RC(tapi_cfg_get_neigh_entry(pco_iut->ta, iut_if->if_name,
                                      tst_addr, ether_buf,
                                      &is_static, &state));
    if ((memcmp(ether_buf, CVT_HW_ADDR(alien_link_addr),
                ETHER_ADDR_LEN) != 0)
        || !is_static)
    {
        TEST_VERDICT("Static ARP updated by received ARP request: "
                     "HW address was %s, %s, state is %s",
                     (memcmp(ether_buf, CVT_HW_ADDR(alien_link_addr),
                             ETHER_ADDR_LEN) != 0) ?
                         "updated" : "not touched",
                     is_static ?  "remains static" : "became dynamic",
                     cs_neigh_entry_state2str(state));
    }

    TEST_STEP("Check that a packet with incorrect @p alien_link_addr MAC "
              "address was sent from IUT.");

    STOP_ETH_FILTER(pco_tst->ta, eth_filter_handle1, received1);
    STOP_ETH_FILTER(pco_tst->ta, eth_filter_handle2, received2);

    if (received2 != 0)
        TEST_VERDICT("Some packets from IUT had unexpected MAC address");
    else if (received1 == 0)
        TEST_VERDICT("No packets from IUT were caught");
    else if (received1 > 1 && /* Retransmits are expected only for TCP. */
             sock_type_sockts2rpc(sock_type) == RPC_SOCK_DGRAM)
        TEST_VERDICT("More than one packet was catched from IUT "
                     "for UDP socket");

    TEST_STEP("Check that no ARP requests were sent from IUT.");

    STOP_ETH_FILTER(pco_tst->ta, arp_filter_handle, received3);
    if (received3 > 0)
        TEST_VERDICT("ARP requests from IUT were detected");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_CHECK_RC(tapi_cfg_del_neigh_entry(pco_iut->ta, iut_if->if_name,
                     tst_addr));

    if (eth_filter_handle1 != CSAP_INVALID_HANDLE)
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0,
                                               eth_filter_handle1));

    if (eth_filter_handle2 != CSAP_INVALID_HANDLE)
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0,
                                               eth_filter_handle2));

    if (arp_filter_handle != CSAP_INVALID_HANDLE)
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0,
                                               arp_filter_handle));

    free(tx_buf);

    TEST_END;
}
