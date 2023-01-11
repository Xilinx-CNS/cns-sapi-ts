/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * TCP
 * 
 * $Id$
 */

/** @page tcp-initial_rto Compair SYN-ACK and SYN initial RTO
 *
 * @objective  Compair delays between initial SYN-ACK and SYN retransmits
 *
 * @type conformance
 *
 * @param pco_iut  PCO on IUT
 * @param pco_tst  PCO on TESTER
 * 
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "tcp/initial_rto"

#include "sockapi-test.h"
#include "tcp_test_macros.h"
#include "tapi_tcp.h"
#include "tapi_route_gw.h"

#include "ndn_ipstack.h"
#include "ndn_eth.h"

/** Comparison precision. */
#define RTO_PRECISION 0.5

/** Auxiliary comparison precision in milliseconds. */
#define RTO_PRECISION_ABS 500

/** How long to wait for initial packet, in milliseconds. */
#define INITIAL_TIMEOUT 500

/** Maximum waiting time to get the retransmit, in milliseconds. */
#define RTO_TIMEOUT 10000

int
main(int argc, char *argv[])
{
    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;

    tapi_route_gateway gateway;

    struct sockaddr_storage iut_addr2;

    uint8_t     gw_tst_link_addr[IFHWADDRLEN];
    size_t      link_addr_len;

    int                 iut_s = -1;
    tapi_tcp_handler_t  csap_tst_s = -1;

    struct timeval      tv1;
    struct timeval      tv2;
    long unsigned int   rto_act;
    long unsigned int   rto_pass;

    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;

    TEST_STEP("Configure connection between IUT and Tester "
              "through gateway host.");

    TAPI_INIT_ROUTE_GATEWAY(gateway);
    tapi_route_gateway_configure(&gateway);
    /*
     * This is done because Linux should consider packets from IUT
     * as addressed to another host, otherwise it will send RST
     * interfering with TCP socket emulation.
     */
    CHECK_RC(tapi_update_arp(pco_gw->ta, gw_tst_if->if_name, NULL, NULL,
                             tst_addr, CVT_HW_ADDR(alien_link_addr), TRUE));
    CFG_WAIT_CHANGES;

    link_addr_len = sizeof(gw_tst_link_addr);
    CHECK_RC(tapi_cfg_get_hwaddr(pco_gw->ta, gw_tst_if->if_name,
                                 gw_tst_link_addr, &link_addr_len));


    TEST_STEP("Create listener socket on IUT.");
    iut_s = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_STREAM,
                                       RPC_PROTO_DEF, FALSE, FALSE,
                                       iut_addr);
    rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);

    TEST_STEP("Create TCP socket emulation on Tester, send SYN to IUT.");
    CHECK_RC(tapi_tcp_init_connection(pco_tst->ta, TAPI_TCP_CLIENT,
                                      tst_addr, iut_addr,
                                      tst_if->if_name,
                                      (uint8_t *)alien_link_addr->sa_data,
                                      gw_tst_link_addr,
                                      0, &csap_tst_s));

    TEST_STEP("Receive the first SYN-ACK from IUT.");
    if (tapi_tcp_wait_packet(csap_tst_s, INITIAL_TIMEOUT) != 0)
        TEST_VERDICT("SYN-ACK was not received on tester");
    gettimeofday(&tv1, NULL);

    TEST_STEP("Wait for the SYN-ACK retransmit.");
    CHECK_RC(tapi_tcp_wait_packet(csap_tst_s, RTO_TIMEOUT));
    gettimeofday(&tv2, NULL);
    rto_pass = TE_US2MS(TIMEVAL_SUB(tv2, tv1));
    RING("Initial SYN-ACK rto %lu", rto_pass);

    TEST_STEP("Close IUT socket, destroy TCP socket emulation "
              "on Tester.");

    RPC_CLOSE(pco_iut, iut_s);
    CHECK_RC(tapi_tcp_destroy_connection(csap_tst_s));
    csap_tst_s = -1;

    TEST_STEP("Create listener TCP socket emulation on Tester, "
              "create socket on IUT and call nonblocking @b connect() on it.");

    CHECK_RC(tapi_sockaddr_clone(pco_iut, iut_addr, &iut_addr2));

    CHECK_RC(tapi_tcp_init_connection(pco_tst->ta, TAPI_TCP_SERVER,
                                      tst_addr, SA(&iut_addr2),
                                      tst_if->if_name,
                                      (uint8_t *)alien_link_addr->sa_data,
                                      gw_tst_link_addr,
                                      0, &csap_tst_s));
    /*
     * Enabling promiscuous mode can take some time on virtual hosts,
     * see ST-2675.
     */
    VSLEEP(1, "Wait for promiscuous mode to turn on");

    iut_s = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_STREAM,
                                       RPC_PROTO_DEF, FALSE, FALSE,
                                       SA(&iut_addr2));

    pco_iut->op = RCF_RPC_CALL;
    rpc_connect(pco_iut, iut_s, tst_addr);

    TEST_STEP("Receive the first SYN on Tester.");
    if (tapi_tcp_wait_packet(csap_tst_s, INITIAL_TIMEOUT) != 0)
        TEST_VERDICT("SYN was not received on tester");
    gettimeofday(&tv1, NULL);

    TEST_STEP("Wait for the SYN retransmit.");
    CHECK_RC(tapi_tcp_wait_packet(csap_tst_s, RTO_TIMEOUT));
    gettimeofday(&tv2, NULL);
    rto_act = TE_US2MS(TIMEVAL_SUB(tv2, tv1));
    RING("Initial SYN rto %lu", rto_act);

    TEST_STEP("Compare the gathered RTO delays.");
    if (rto_pass < rto_act - rto_act * RTO_PRECISION - RTO_PRECISION_ABS ||
        rto_pass > rto_act + rto_act * RTO_PRECISION + RTO_PRECISION_ABS)
        TEST_VERDICT("SYN and SYN-ACK retransmission timeouts differ too "
                     "much");

    TEST_STEP("Finish connection establishment.");
    CHECK_RC(tapi_tcp_wait_open(csap_tst_s, RTO_TIMEOUT));
    rpc_connect(pco_iut, iut_s, tst_addr);

    TEST_SUCCESS;

cleanup:
    if (csap_tst_s >= 0)
        CLEANUP_CHECK_RC(tapi_tcp_destroy_connection(csap_tst_s));

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
