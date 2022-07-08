/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * ARP table
 *
 * $Id$
 */

/** @page arp-gateway_addr ARP resolution and gateway
 *
 * @objective Check that if there is a route to a given IP
 *            address via gateway, then a packet sent to that
 *            IP address has destination MAC address of the gateway.
 *
 * @type conformance
 *
 * @reference @ref COMER chapter 5
 *
 * @param pco_iut         PCO on IUT
 * @param pco_tst         PCO on TESTER
 * @param pco_gw          PCO on Gateway
 * @param iut_if          Network interface on IUT
 * @param gw_iut_if       Network interface on Gateway
 *                        connected to IUT
 * @param iut_addr        Network address on IUT
 * @param tst_addr        Network address on Tester
 * @param iut_lladdr      Ethernet address on IUT
 * @param gw_iut_lladdr   Ethernet address on @p gw_iut_if
 * @param sock_type       Socket type
 *
 * @par Test sequence:
 *
 * @author Renata Sayakhova <Renata.Sayakhova@oktetlabs.ru>
 */

#define TE_TEST_NAME    "arp/gateway_addr"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "tapi_ip4.h"
#include "arp_test_macros.h"
#include "arp_send_recv.h"
#include "tapi_route_gw.h"

int
main(int argc, char *argv[])
{
    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;
    tapi_route_gateway gateway;

    csap_handle_t          handle = CSAP_INVALID_HANDLE;
    int                    sid;

    const struct sockaddr *gw_iut_lladdr = NULL;
    const struct sockaddr *iut_lladdr = NULL;

    int iut_s = -1;
    int tst_s = -1;
    int iut_s_listener = -1;
    int tst_s_listener = -1;

    unsigned int           received_frames;

    sockts_socket_type  sock_type;
    te_dbuf             iut_sent = TE_DBUF_INIT(0);

    TEST_START;

    TAPI_GET_ROUTE_GATEWAY_PARAMS;

    TEST_GET_LINK_ADDR(iut_lladdr);
    TEST_GET_LINK_ADDR(gw_iut_lladdr);

    SOCKTS_GET_SOCK_TYPE(sock_type);

    TEST_STEP("Configure routes between IUT and Tester "
              "via Gateway.");

    TAPI_INIT_ROUTE_GATEWAY(gateway);
    tapi_route_gateway_configure(&gateway);
    CFG_WAIT_CHANGES;

    TEST_STEP("Remove ARP entry for @p tst_addr on IUT if it is present.");
    CHECK_RC(tapi_cfg_del_neigh_entry(pco_iut->ta, iut_if->if_name,
                                      tst_addr));

    TEST_STEP("Launch Ethernet sniffer on Gateway looking for packets "
              "destined to Tester.");

    CHECK_RC(rcf_ta_create_session(pco_gw->ta, &sid));
    CHECK_RC(tapi_ip4_eth_csap_create(
                        pco_gw->ta, sid,
                        gw_iut_if->if_name,
                        TAD_ETH_RECV_DEF |
                        TAD_ETH_RECV_NO_PROMISC,
                        CVT_HW_ADDR(gw_iut_lladdr),
                        CVT_HW_ADDR(iut_lladdr),
                        SIN(tst_addr)->sin_addr.s_addr,
                        SIN(iut_addr)->sin_addr.s_addr,
                        (sock_type_sockts2rpc(sock_type) == RPC_SOCK_DGRAM ?
                            IPPROTO_UDP : IPPROTO_TCP),
                        &handle));
    CHECK_RC(tapi_tad_trrecv_start(pco_gw->ta, sid, handle, NULL,
                                   TAD_TIMEOUT_INF, 0, RCF_TRRECV_COUNT));

    TEST_STEP("Create a pair of sockets on IUT and Tester according "
              "to @p sock_type. In case of TCP start nonblocking connection "
              "establishment; in case of UDP call @b send() or @b sendto() "
              "on IUT.");
    sockts_connection_begin(pco_iut, pco_tst, iut_addr, tst_addr,
                            sock_type, &iut_s, &iut_s_listener,
                            &tst_s, &tst_s_listener, &iut_sent);

    TEST_STEP("In case of TCP, finish connection establishment. In case of UDP, "
              "receive a packet on Tester.");
    sockts_connection_end(pco_iut, pco_tst, iut_addr, tst_addr,
                          sock_type, &iut_s, &iut_s_listener,
                          &tst_s, &tst_s_listener, &iut_sent);

    TEST_STEP("Stop Ethernet sniffer, check that a packet was received "
              "with destination IP address @p tst_addr and destination "
              "Ethernet address @p gw_iut_lladdr.");

    TAPI_WAIT_NETWORK;
    STOP_ETH_FILTER(pco_gw->ta, handle, received_frames);

    if (received_frames == 0)
        TEST_VERDICT("Ethernet filter have not caught any frames");

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_gw->ta, 0, handle));
    te_dbuf_free(&iut_sent);

    TEST_END;
}
