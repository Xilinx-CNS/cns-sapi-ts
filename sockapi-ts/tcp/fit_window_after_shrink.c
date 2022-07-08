/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * TCP tests
 */

/** @page tcp-fit_window_after_shrink Handling of shrinking to the window that fits already received data
 *
 * @objective Check that data fits into recently shrinked window.
 *
 * @type conformance
 *
 * @param env            Testing environment:
 *                       - @ref arg_types_env_peer2peer_gw
 *                       - @ref arg_types_env_peer2peer_gw_ipv6
 * @param active         Passive or active open
 * @param cache_socket   If @c TRUE, create cached socket to be reused.
 * @param packets_num    Number of packets that should be sent from IUT
 *                       with ACKs from Tester
 * @param packets_wo_ack Number of packets that should be sent from IUT
 *                       without ACKs from Tester
 *
 * @par Scenario:
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "tcp/fit_window_after_shrink"

#include "sockapi-test.h"
#include "tcp_test_macros.h"
#include "tapi_route_gw.h"

/* Length of packets that should be sent from IUT with ACKs from Tester */
#define SEND_LEN        1000
/* Length of packets that should be sent from IUT without ACKs
 * from Tester
 */
#define SEND_LEN_WO_ACK 100
/* Length of buffer that can accommodate all data from each sent buffer */
#define BUF_LEN         (SEND_LEN * BIG_BUF_MULT * 2)
/* Big packet scale */
#define BIG_BUF_MULT    3
/* 1 second in milliseconds */
#define SLEEP_SEC       1000

int
main(int argc, char *argv[])
{
    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;

    tsa_session         ss = TSA_SESSION_INITIALIZER;
    tapi_tcp_handler_t  csap_tst_s;

    int     iut_s = -1;
    te_bool active = FALSE;
    te_bool cache_socket = FALSE;

    uint8_t send_buf[BUF_LEN];
    uint8_t recv_buf[BUF_LEN];
    size_t  recv_len = BUF_LEN;
    size_t  total_len;
    te_dbuf recv_dbuf = TE_DBUF_INIT(0);

    int          packets_num = 0;
    int          packets_wo_ack = 0;
    int          old_ackn;
    int          prev_window;
    int          new_window;

    int i;

    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;
    TEST_GET_BOOL_PARAM(active);
    TEST_GET_BOOL_PARAM(cache_socket);
    TEST_GET_INT_PARAM(packets_num);
    TEST_GET_INT_PARAM(packets_wo_ack);

    te_fill_buf(send_buf, BUF_LEN);
    TEST_STEP("Use GW CSAP to control traffic from Tester side.");

    if (tsa_state_init(&ss, TSA_TST_GW_CSAP) != 0)
        TEST_FAIL("Unable to initialize TSA");

    CHECK_RC(tsa_iut_set(&ss, pco_iut, iut_if, iut_addr));
    CHECK_RC(tsa_tst_set(&ss, pco_tst, tst_if, tst_addr, NULL));
    tsa_gw_preconf(&ss, TRUE);
    CHECK_RC(tsa_gw_set(&ss, pco_gw, gw_iut_addr, gw_tst_addr,
                        gw_iut_if, gw_tst_if,
                        alien_link_addr->sa_data));
    CFG_WAIT_CHANGES;

    TEST_STEP("If @p cache_socket is @c TRUE and @p active is @c TRUE - "
              "create cached socket.");
    if (active && cache_socket)
    {
        sockts_create_cached_socket(pco_iut, pco_gw, iut_addr, gw_iut_addr,
                                    -1, TRUE, cache_socket);
    }

    TEST_STEP("Create a tcp socket on IUT and CSAP on tester.");
    CHECK_RC(tsa_create_session(&ss, 0));
    TAPI_WAIT_NETWORK;

    TEST_STEP("Move IUT socket and the CSAP to @c ESTABLISHED TCP state.");
    tcp_move_to_state(&ss, RPC_TCP_ESTABLISHED,
                      active ? OL_ACTIVE : OL_PASSIVE_OPEN,
                      active ? FALSE : cache_socket);
    iut_s = ss.state.iut_s;

    csap_tst_s = tsa_tst_sock(&ss);
    TEST_STEP("Send some data from IUT to TST to open congestion window.");
    for (i = 0; i < packets_num; i++)
    {
        rpc_send(pco_iut, iut_s, send_buf, SEND_LEN, 0);
        CHECK_RC(tapi_tcp_recv_data(csap_tst_s, TAPI_WAIT_NETWORK_DELAY,
                                    TAPI_TCP_AUTO, &recv_dbuf));
        if (recv_dbuf.len != SEND_LEN ||
            memcmp(send_buf, recv_dbuf.ptr, SEND_LEN) != 0)
        {
            TEST_VERDICT("Received data does not match data sent "
                         "from IUT");
        }
        te_dbuf_free(&recv_dbuf);
    }

    TEST_STEP("Send some data from IUT and do not acknowledge it "
              "from TST.");
    for (i = 0; i < packets_wo_ack; i++)
    {
        rpc_send(pco_iut, iut_s, send_buf, SEND_LEN_WO_ACK, 0);
        CHECK_RC(tapi_tcp_recv_data(csap_tst_s, TAPI_WAIT_NETWORK_DELAY,
                                    TAPI_TCP_QUIET, &recv_dbuf));
        te_dbuf_free(&recv_dbuf);
    }

    TEST_STEP("From TST to IUT: send an ACK with the same old ACK "
              "value and smaller window (so that all the already-sent"
              "data fits in)");
    old_ackn = tapi_tcp_last_ackn_sent(csap_tst_s);
    prev_window = tapi_tcp_get_window(csap_tst_s);
    /* Window should be a little bit bigger than already sent from
     * IUT data without ACK from Tester.
     */
    new_window = SEND_LEN_WO_ACK * (packets_wo_ack + 2);
    if (prev_window < new_window)
        TEST_FAIL("Default window is too small.");
    CHECK_RC(tapi_tcp_set_window(csap_tst_s, new_window));
    CHECK_RC(tapi_tcp_send_ack(csap_tst_s, old_ackn));

    TAPI_WAIT_NETWORK;
    TEST_STEP("Acknowledge and receive all data.");
    CHECK_RC(tapi_tcp_ack_all(csap_tst_s));
    TAPI_WAIT_NETWORK;
    CHECK_RC(tapi_tcp_recv_data(csap_tst_s, TAPI_WAIT_NETWORK_DELAY,
                                TAPI_TCP_AUTO, &recv_dbuf));
    te_dbuf_free(&recv_dbuf);
    TAPI_WAIT_NETWORK;

    TEST_STEP("On IUT, send() a lot of data. Check that all the data "
              "on the wire fits into the shrunk window.");
    for (i = 0; i < packets_num; i++)
    {
        rpc_send(pco_iut, iut_s, send_buf, SEND_LEN * BIG_BUF_MULT, 0);
        total_len = 0;
        while (total_len < SEND_LEN * BIG_BUF_MULT)
        {
            tapi_tcp_recv_msg(csap_tst_s, SLEEP_SEC, TAPI_TCP_AUTO,
                              recv_buf, &recv_len, NULL, NULL, 0);

            if (recv_len > (size_t)new_window ||
                memcmp(&send_buf[total_len], recv_buf, recv_len) != 0)
            {
                TEST_VERDICT("Received data does not match data sent "
                             "from IUT after reducing the window.");
            }
            total_len += recv_len;
            recv_len = BUF_LEN;
        }
    }

    TEST_STEP("Increase the window back.");
    CHECK_RC(tapi_tcp_set_window(csap_tst_s, prev_window));
    CHECK_RC(tapi_tcp_ack_all(csap_tst_s));
    TAPI_WAIT_NETWORK;

    TEST_STEP("Send more data from IUT, receive it all on TST.");
    for (i = 0; i < packets_num; i++)
    {
        rpc_send(pco_iut, iut_s, send_buf, SEND_LEN, 0);
        CHECK_RC(tapi_tcp_recv_data(csap_tst_s, TAPI_WAIT_NETWORK_DELAY,
                                    TAPI_TCP_AUTO, &recv_dbuf));
        if (recv_dbuf.len != SEND_LEN ||
            memcmp(send_buf, recv_dbuf.ptr, SEND_LEN) != 0)
        {
            TEST_VERDICT("Received data does not match data sent "
                         "from IUT after increasing window back again.");
        }
        te_dbuf_free(&recv_dbuf);
    }

    TEST_SUCCESS;

cleanup:
    if (iut_s >= 0)
        CLEANUP_CHECK_RC(tsa_destroy_session(&ss));
    te_dbuf_free(&recv_dbuf);

    TEST_END;
}
