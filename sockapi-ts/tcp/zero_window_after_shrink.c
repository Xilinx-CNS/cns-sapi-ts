/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * TCP tests
 */

/** @page tcp-zero_window_after_shrink Handling of shrinking to zero window
 *
 * @objective Check that data is retransmitted when window becomes
 *            non-zero after shrink.
 *
 * @type conformance
 *
 * @param env            Testing environment:
 *                       - @ref arg_types_env_peer2peer_gw
 *                       - @ref arg_types_env_peer2peer_gw_ipv6
 * @param active         Passive or active open
 * @param cache_socket   If @c TRUE, create cached socket to be reused.
 * @param packets_before Number of packets that should be sent before main
 *                       part of the test
 * @param set_zero       If @c TRUE, set window to zero, otherwise set it
 *                       to some small but non-zero value
 * @param close_iut_s    If @c TRUE, close socket on IUT just after
 *                       acknowledging some data
 *
 * @par Scenario:
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "tcp/zero_window_after_shrink"

#include "sockapi-test.h"
#include "tcp_test_macros.h"
#include "tapi_route_gw.h"

#define SEND_LEN     1000
#define BUF_LEN      (SEND_LEN * BIG_BUF_MULT * 2)
#define BIG_BUF_MULT 5
#define SLEEP_SEC    1000

int
main(int argc, char *argv[])
{
    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;

    tsa_session         ss = TSA_SESSION_INITIALIZER;
    tapi_tcp_handler_t  csap_tst_s;

    int     iut_s = -1;
    te_bool active = FALSE;
    te_bool cache_socket = FALSE;
    te_bool set_zero = FALSE;
    te_bool close_iut_s = FALSE;

    uint8_t send_buf[BUF_LEN];
    uint8_t recv_buf[BUF_LEN];
    size_t  recv_len = BUF_LEN;
    te_dbuf recv_dbuf = TE_DBUF_INIT(0);

    int          packets_before = 0;
    int          old_ackn;
    int          next_ackn;
    int          prev_window;
    int          acked_data_len;
    unsigned int recv_seqn;

    int i;

    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;
    TEST_GET_BOOL_PARAM(active);
    TEST_GET_BOOL_PARAM(set_zero);
    TEST_GET_BOOL_PARAM(close_iut_s);
    TEST_GET_BOOL_PARAM(cache_socket);
    TEST_GET_INT_PARAM(packets_before);

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
    for (i = 0; i < packets_before; i++)
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
    rpc_send(pco_iut, iut_s, send_buf, SEND_LEN * BIG_BUF_MULT, 0);
    CHECK_RC(tapi_tcp_recv_data(csap_tst_s, TAPI_WAIT_NETWORK_DELAY,
                                TAPI_TCP_QUIET, &recv_dbuf));

    TEST_STEP("From Tester send an ACK with the same old ACK value and "
              "very small window (smaller than already-sent data) "
              "according to @p set_zero parameter");
    old_ackn = tapi_tcp_last_ackn_sent(csap_tst_s);
    prev_window = tapi_tcp_get_window(csap_tst_s);
    acked_data_len = SEND_LEN * (BIG_BUF_MULT / 2 + 1);
    CHECK_RC(tapi_tcp_set_window(csap_tst_s,
                                 set_zero ? 0 : acked_data_len));
    CHECK_RC(tapi_tcp_send_ack(csap_tst_s, old_ackn));

    TEST_STEP("Wait a bit and capture all packets during this time");
    SLEEP(5);
    CHECK_RC(tapi_tcp_recv_data(csap_tst_s, TAPI_WAIT_NETWORK_DELAY,
                                TAPI_TCP_QUIET, &recv_dbuf));
    if (!set_zero &&
        ((int)recv_dbuf.len < acked_data_len ||
         memcmp(send_buf, recv_dbuf.ptr, acked_data_len) != 0))
    {
        if ((int)recv_dbuf.len < acked_data_len)
        {
            ERROR("recv_dbuf.len (%d) unexpectedly less than acked_data_len "
                  "(%d)", (int)recv_dbuf.len, acked_data_len);
        }
        else
        {
            ERROR("recv_dbuf.len (%d) expectedly greater than or equal to "
                  "acked_data_len (%d), but send_buf does not match recv_buf",
                  (int)recv_dbuf.len, acked_data_len);
        }
        TEST_VERDICT("Received data does not match data sent "
                     "from IUT after window shrink");
    }
    te_dbuf_free(&recv_dbuf);

    TEST_STEP("If @p set_zero is @c FALSE acknowledge all in-window data."
              "If @p set_zero is @c TRUE acknowledge some part of sent "
              "from IUT data.");
    next_ackn = old_ackn + acked_data_len;
    CHECK_RC(tapi_tcp_send_ack(csap_tst_s, next_ackn));
    TEST_STEP("If @p close_iut_s is @c TRUE close IUT socket "
              "and end the test.");
    if (close_iut_s)
    {
        RPC_CLOSE(pco_iut, iut_s);
        TEST_SUCCESS;
    }

    TEST_STEP("Check that IUT transmits data when set_zero is @c FALSE");
    if (!set_zero)
    {
        CHECK_RC(tapi_tcp_recv_msg(csap_tst_s, SLEEP_SEC, TAPI_TCP_QUIET,
                                   recv_buf, &recv_len, &recv_seqn,
                                   NULL, 0));
        if ((int)recv_seqn + recv_len - 1 <= old_ackn + acked_data_len ||
            (int)recv_seqn > old_ackn + acked_data_len)
        {
            RING("Retransmit message info: seq %u, len %d;"
                 " previous ACKN: %d, window size: %d",
                 recv_seqn, recv_len, old_ackn, acked_data_len);
            TEST_VERDICT("Incorrect seqn in retransmit packet");
        }
        if (memcmp(&send_buf[recv_seqn - old_ackn], recv_buf,
                   recv_len) != 0)
        {
            TEST_VERDICT("Received data does not match data sent "
                         "from IUT after shrinking window and "
                         "acknowledging received data");
        }
    }

    TEST_STEP("Increase the window back.");
    CHECK_RC(tapi_tcp_set_window(csap_tst_s, prev_window));
    CHECK_RC(tapi_tcp_ack_all(csap_tst_s));

    TEST_STEP("Send more data from IUT, receive it all on TST.");
    for (i = 0; i < packets_before; i++)
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
