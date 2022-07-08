/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 */

/** @page sockopts-linger_listening_close Usage of SO_LINGER socket option for listening socket
 *
 * @objective Check influence of @c SO_LINGER socket option set for
 *            listening socket.
 *
 * @type conformance
 *
 * @reference @ref STEVENS, section 7.5
 *
 * @param env           Testing environment.
 *                      - @ref arg_types_env_peer2peer
 *                      - @ref arg_types_env_peer2peer_tst
 *                      - @ref arg_types_env_peer2peer_lo
 * @param zero_linger   If @c TRUE, set zero linger timeout;
 *                      if @c FALSE, set non zero linger timeout
 * @param acceptq       Close with not empty accept queue
 *
 * @par Test sequence:
 *
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/linger_listening_close"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             iut_s = -1;
    int             tst_s = -1;

    te_bool                 zero_linger;
    te_bool                 acceptq;
    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;
    tarpc_linger            opt_val;

    rpc_tcp_info  tcp_info;
    rpc_tcp_state tcp_state;
    te_bool       found = FALSE;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(zero_linger);
    TEST_GET_BOOL_PARAM(acceptq);

    TEST_STEP("Create listener TCP socket on IUT, binding it to "
              "@p iut_addr.");
    iut_s = rpc_stream_server(pco_iut, RPC_PROTO_DEF, FALSE, iut_addr);

    TEST_STEP("Enable @c SO_LINGER on the listener, setting zero or "
              "nonzero linger value according to @p zero_linger.");
    opt_val.l_onoff  = 1;
    opt_val.l_linger = (zero_linger) ? 0 : rand_range(10, 20);
    rpc_setsockopt(pco_iut, iut_s, RPC_SO_LINGER, &opt_val);

    if (acceptq)
    {
        TEST_STEP("If @p acceptq is @c TRUE, create a TCP socket on "
                  "Tester, @b connect() it to @p iut_addr, but do not "
                  "call @b accept() on IUT.");
        tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                           RPC_SOCK_STREAM, RPC_PROTO_DEF);
        rpc_bind(pco_tst, tst_s, tst_addr);
        rpc_connect(pco_tst, tst_s, iut_addr);
    }

    TEST_STEP("Close IUT listener.");
    RPC_CLOSE(pco_iut, iut_s);

    TEST_STEP("Check that close() returned immediately.");
    CHECK_CALL_DURATION_INT(pco_iut->duration, TST_TIME_INACCURACY,
                            TST_TIME_INACCURACY_MULTIPLIER, 0, 0);

    TEST_STEP("If @p acceptq is @c TRUE, check that socket on Tester is "
              "now in @c TCP_CLOSE state, and accepted socket on IUT "
              "is not observable with netstat/onload_netstat.");
    if (acceptq)
    {
        TAPI_WAIT_NETWORK;

        rpc_getsockopt(pco_tst, tst_s, RPC_TCP_INFO, &tcp_info);
        if (tcp_info.tcpi_state != RPC_TCP_CLOSE)
        {
            ERROR_VERDICT("After closing listener with not accepted "
                          "socket the peer on Tester is in %s instead of "
                          "TCP_CLOSE",
                          tcp_state_rpc2str(tcp_info.tcpi_state));
        }

        rpc_get_tcp_socket_state(pco_iut, iut_addr, tst_addr,
                                 &tcp_state, &found);
        if (found)
        {
            ERROR_VERDICT("After closing listener accepted socket "
                          "still hangs in %s state",
                          tcp_state_rpc2str(tcp_state));
        }
    }

    TEST_STEP("Check that a new TCP socket created on IUT can be "
              "bound to @p iut_addr.");
    if (is_addr_inuse(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                      RPC_SOCK_STREAM, iut_addr))
        TEST_VERDICT("Address on IUT was not released");

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
