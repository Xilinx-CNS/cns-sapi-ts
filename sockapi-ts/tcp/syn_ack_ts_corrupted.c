/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * TCP
 */

/** @page tcp-syn_ack_ts_corrupted Timestamp in sent SYN-ACK is lost
 *
 * @objective Check what happens if timestamp is lost in sent SYN-ACK due
 *            to packet corruption.
 *
 * @type usecase
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_peer2peer_gw
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "tcp/syn_ack_ts_corrupted"

#include "sockapi-test.h"
#include "tcp_test_macros.h"
#include "tapi_route_gw.h"
#include "tapi_tcp.h"

int
main(int argc, char *argv[])
{
    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;

    const struct sockaddr *gw_tst_lladdr = NULL;
    const struct sockaddr *tst_fake_addr = NULL;

    int                 iut_s_listener = -1;
    int                 iut_s = -1;
    tapi_tcp_handler_t  csap_tst_s = -1;
    te_bool             readable = FALSE;

    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;
    TEST_GET_ADDR(pco_tst, tst_fake_addr);
    TEST_GET_LINK_ADDR(gw_tst_lladdr);

    CHECK_RC(tapi_update_arp(pco_gw->ta, gw_tst_if->if_name, NULL, NULL,
                             tst_fake_addr, CVT_HW_ADDR(alien_link_addr),
                             TRUE));
    CFG_WAIT_CHANGES;

    TEST_STEP("Create TCP socket on IUT, bind it to @p iut_addr, call "
              "@b listen() on it. It is assumed that TCP timestamps are already "
              "enabled in prologue.");

    iut_s_listener = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_STREAM,
                                                RPC_PROTO_DEF, FALSE,
                                                FALSE, iut_addr);
    rpc_listen(pco_iut, iut_s_listener, SOCKTS_BACKLOG_DEF);

    TEST_STEP("Create CSAP TCP socket emulation on Tester, enable timestamps "
              "for it. Call @b tapi_tcp_start_conn() which will send SYN with "
              "timestamp. On receiving it IUT should think that timestamps are "
              "enabled on the peer.");

    CHECK_RC(tapi_tcp_create_conn(
                          pco_tst->ta,
                          tst_fake_addr, iut_addr, tst_if->if_name,
                          (const uint8_t *)alien_link_addr->sa_data,
                          (const uint8_t *)gw_tst_lladdr->sa_data,
                          TAPI_TCP_DEF_WINDOW, &csap_tst_s));

    CHECK_RC(tapi_tcp_conn_enable_ts(csap_tst_s, TRUE,
                                     rand_range(0, INT_MAX)));

    CHECK_RC(tapi_tcp_start_conn(csap_tst_s, TAPI_TCP_CLIENT));

    TEST_STEP("Now disable timestamps on CSAP TCP socket emulation to imitate "
              "receiving SYN-ACK without timestamp, and call "
              "@b tapi_tcp_wait_open() to receive SYN-ACK from IUT and send ACK "
              "without timestamp in response.");

    CHECK_RC(tapi_tcp_conn_enable_ts(csap_tst_s, FALSE, 0));
    CHECK_RC(tapi_tcp_wait_open(csap_tst_s, TAPI_WAIT_NETWORK_DELAY));

    TEST_STEP("Check that IUT listener considers such ACK as valid and "
              "becomes readable.");

    RPC_GET_READABILITY(readable, pco_iut, iut_s_listener,
                        TAPI_WAIT_NETWORK_DELAY);

    if (!readable)
    {
        TEST_VERDICT("After receiving ACK without timestamp IUT listener "
                     "is not readable");
    }

    TEST_STEP("@b accept() connected IUT socket. Check that data can be sent "
              "in both directions over established connection.");

    iut_s = rpc_accept(pco_iut, iut_s_listener, NULL, NULL);

    CHECK_RC(sockts_check_tcp_conn_csap(pco_iut, iut_s, csap_tst_s));

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s_listener);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_CHECK_RC(tapi_tcp_destroy_connection(csap_tst_s));

    TEST_END;
}
