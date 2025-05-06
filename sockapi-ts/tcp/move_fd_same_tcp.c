/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Advanced Micro Devices, Inc. */
/*
 * Socket API Test Suite
 * TCP protocol special cases
 */

/**
 * @page tcp-move_fd_same_tcp Check onload_move_fd() moving TCP socket to the same stack
 *
 * @objective Check that onload_move_fd(), moving TCP socket on IUT to the same
 *            stack, does the right thing. Namely, check that onload_move_fd()
 *            returns success, the socket remains in the same stack and functions
 *            normally.
 *
 * @param env       Testing environment:
 *      - @ref arg_types_env_peer2peer_gw
 *      - @ref arg_types_env_peer2peer_gw_ipv6
 * @param tcp_state TCP state to be tested
 * @param active    Active/passive connection opening:
 *      - @c FALSE (passive opening)
 *      - @c TRUE (active opening)
 *
 * @par Scenario:
 *
 * @author Nikolai Kosovskii <Nikolai.Kosovskii@arknetworks.am>
 */

#define TE_TEST_NAME "tcp/move_fd_same_tcp"

#include "sockapi-test.h"
#include "tapi_route_gw.h"
#include "tapi_tad.h"
#include "ndn_ipstack.h"

#include "../level5/ext_stackname/move_fd_helpers.h"
#include "tcp_test_macros.h"

/* Length of data to send. */
#define BUF_LEN 10000

void
send_data_and_check(rcf_rpc_server *pco_iut, tsa_session *ss)
{
    int data_sent = 0;
    char rx_buf[1024];
    int data_chunk = sizeof(rx_buf);
    uint8_t *buf =  te_make_buf_by_len(BUF_LEN);
    te_dbuf recv_data = TE_DBUF_INIT(0);

    /* Send data from IUT to Tester */
    rpc_send(pco_iut, tsa_iut_sock(ss), buf, BUF_LEN, 0);
    tapi_tcp_recv_data(tsa_tst_sock(ss), TAPI_WAIT_NETWORK_DELAY,
                       TAPI_TCP_AUTO, &recv_data);

    /* Send data from Tester to IUT */
    while (data_sent < BUF_LEN)
    {
        if (BUF_LEN - data_sent < data_chunk)
            data_chunk = BUF_LEN - data_sent;

        CHECK_RC(tapi_tcp_send_msg(tsa_tst_sock(ss),
                                   buf + data_sent,
                                   data_chunk,
                                   TAPI_TCP_AUTO, 0,
                                   TAPI_TCP_AUTO, 0,
                                   NULL, 0));
        TAPI_WAIT_NETWORK;
        data_sent += rpc_recv(pco_iut, tsa_iut_sock(ss),
                              rx_buf, sizeof(rx_buf), 0);
    }

    SOCKTS_CHECK_RECV(pco_iut, buf, recv_data.ptr, BUF_LEN, recv_data.len);

    free(buf);
    te_dbuf_free(&recv_data);
}

int
main(int argc, char *argv[])
{
    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;

    te_bool active;
    tsa_session ss = TSA_SESSION_INITIALIZER;
    uint32_t flags = 0;
    rpc_tcp_state tcp_state;
    tarpc_onload_stat ostat_before;
    te_string tcp_states_path=TE_STRING_INIT;
    te_bool set_established = FALSE;

    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;
    TEST_GET_TCP_STATE(tcp_state);
    TEST_GET_BOOL_PARAM(active);

    TEST_STEP("Initialize TSA session.");
    CHECK_RC(tsa_state_init(&ss, TSA_TST_GW_CSAP));
    CHECK_RC(tsa_iut_set(&ss, pco_iut, iut_if, iut_addr));
    CHECK_RC(tsa_tst_set(&ss, pco_tst, tst_if, tst_addr,
                         ((struct sockaddr *)alien_link_addr)->sa_data));
    tsa_gw_preconf(&ss, TRUE);
    CHECK_RC(tsa_gw_set(&ss, pco_gw, gw_iut_addr, gw_tst_addr, gw_iut_if,
                        gw_tst_if, alien_link_addr->sa_data));
    CFG_WAIT_CHANGES;

    if ((tcp_state == RPC_TCP_SYN_SENT && !active) ||
        (tcp_state == RPC_TCP_SYN_RECV && active) ||
        (tcp_state == RPC_TCP_LISTEN && active))
    {
        TEST_SKIP("TCP state %s is not suitable for %s opening in the test",
                  tcp_state_rpc2str(tcp_state),
                  active ? "active" : "passive");
    }

    TEST_STEP("Move IUT socket to @p tcp_state state. Active/passive "
              "connection establishment depends on a @p active parameter.");
    if (!active)
        flags |= TSA_ESTABLISH_PASSIVE | TSA_MOVE_IGNORE_START_ERR;

    CHECK_RC(tsa_create_session(&ss, flags));
    tcp_move_to_state(&ss, tcp_state, active ? OL_ACTIVE : OL_PASSIVE_OPEN,
                      FALSE);

    if (tsa_state_cur(&ss) != tcp_state)
    {
        if (tsa_state_cur(&ss) == RPC_TCP_CLOSE &&
          tcp_state == RPC_TCP_TIME_WAIT)
        {
            WARN("TCP state should be %s but tsa_state_cur is %s. "
                 "It is a known bug of getsockopt().",
                 tcp_state_rpc2str(tcp_state),
                 tcp_state_rpc2str(tsa_state_cur(&ss)));
        }
        else if
          (tsa_state_cur(&ss) == RPC_TCP_LISTEN &&
          tcp_state == RPC_TCP_SYN_RECV)
        {
            WARN("TCP state should be %s but tsa_state_cur is %s. "
                 "It is a known issue of getsockopt().",
                 tcp_state_rpc2str(tcp_state),
                 tcp_state_rpc2str(tsa_state_cur(&ss)));
        }
        else
        {
            TEST_VERDICT("TCP state should be %s but tsa_state_cur is %s",
                          tcp_state_rpc2str(tcp_state),
                          tcp_state_rpc2str(tsa_state_cur(&ss)));
        }
    }

    TEST_STEP("Call @b rpc_onload_fd_stat() on @p iut_s. Check that socket "
              "is accelerated.");
    rc = rpc_onload_fd_stat(pco_iut, tsa_iut_sock(&ss), &ostat_before);
    if (rc != 1)
    {
        TEST_VERDICT("Failed to create accelerated socket on IUT");
    }

    TEST_STEP("Call @b onload_move_fd(): move the socket @p iut_s to the same "
              "stack.");
    tapi_rpc_onload_move_fd_check(pco_iut, tsa_iut_sock(&ss),
                                  TAPI_MOVE_FD_SUCCESS_EXPECTED,
                                  ostat_before.stack_name,
                                  "Call onload_move_fd()");

    /* Set path to TCP_ESTABLISHED or to TCP_CLOSE */
    switch (tcp_state)
    {
        case RPC_TCP_LISTEN:
            te_string_append(&tcp_states_path,
                            "TCP_SYN_RECV->TCP_ESTABLISHED");
            set_established = TRUE;
            break;

        case RPC_TCP_SYN_SENT:
        case RPC_TCP_SYN_RECV:
            te_string_append(&tcp_states_path, "TCP_ESTABLISHED");
            set_established = TRUE;
            break;

        case RPC_TCP_ESTABLISHED:
            if (active)
            {
                te_string_append(&tcp_states_path,
                    "TCP_FIN_WAIT1->TCP_FIN_WAIT2->TCP_TIME_WAIT->TCP_CLOSE");
            }
            else
            {
                te_string_append(&tcp_states_path,
                    "TCP_CLOSE_WAIT->TCP_LAST_ACK->TCP_CLOSE");
            }
            break;

        case RPC_TCP_FIN_WAIT1:
            te_string_append(&tcp_states_path,
                             "TCP_FIN_WAIT2->TCP_TIME_WAIT->TCP_CLOSE");
            break;

        case RPC_TCP_FIN_WAIT2:
        case RPC_TCP_CLOSING:
            te_string_append(&tcp_states_path, "TCP_TIME_WAIT->TCP_CLOSE");
            break;

        case RPC_TCP_TIME_WAIT:
            te_string_append(&tcp_states_path, "TCP_CLOSE");
            break;

        case RPC_TCP_CLOSE_WAIT:
        case RPC_TCP_LAST_ACK:
            te_string_append(&tcp_states_path, "TCP_LAST_ACK->TCP_CLOSE");
            break;

        case RPC_TCP_CLOSE:
            break;

        default:
            assert(0);
    }

    if (set_established || tcp_state == RPC_TCP_ESTABLISHED)
    {
        TEST_STEP("Move IUT socket to TCP_ESTABLISHED state");
        if (tcp_state != RPC_TCP_ESTABLISHED)
        {
            rc = tsa_do_moves_str(&ss, tcp_state, RPC_TCP_UNKNOWN,
                                  flags, tcp_states_path.ptr);
            if (rc != 0)
            {
                TEST_VERDICT("TCP_ESTABLISHED state is not achieved");
            }
            else if (tsa_state_cur(&ss) != RPC_TCP_ESTABLISHED)
            {
                TEST_VERDICT("Final TCP state should be TCP_ESTABLISHED but "
                              "tsa_state_cur is %s",
                              tcp_state_rpc2str(tsa_state_cur(&ss)));
            }
        }

        TEST_STEP("Pass traffic");
        send_data_and_check(pco_iut, &ss);

    }

    if (!set_established)
    {
        TEST_STEP("Move IUT socket to TCP_CLOSE state.");
        rc = tsa_do_moves_str(&ss, tcp_state, RPC_TCP_UNKNOWN,
                              flags, tcp_states_path.ptr);
        if (rc != 0)
        {
            TEST_VERDICT("There were some problems "
                          "when going with the path %s",
                          tcp_states_path.ptr);
        }
        if (tsa_state_cur(&ss) != RPC_TCP_CLOSE)
        {
            TEST_VERDICT("Final TCP state should be TCP_CLOSE but "
                          "tsa_state_cur is %s",
                          tcp_state_rpc2str(tsa_state_cur(&ss)));
        }
    }

    TEST_SUCCESS;

cleanup:
    te_string_free(&tcp_states_path);
    CLEANUP_CHECK_RC(tsa_destroy_session(&ss));
    TEST_END;
}
