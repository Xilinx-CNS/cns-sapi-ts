/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * TCP
 * 
 * $Id$
 */

/** @page tcp-listener_closing_states  Closing listener socket when the accepted one is in different states
 *
 * @objective  Check that closing listener socket does not violate accepted
 *             socket behavior independently on its state.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TESTER
 * @param tcp_state     TCP state to be tested
 * @param cache_socket  Create cached socket to be reused
 * 
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "tcp/listener_closing_states"

#include "sockapi-test.h"
#include "tcp_test_macros.h"
#include "onload.h"
#include "tapi_route_gw.h"

#define RETRIES_NUM 4

int
main(int argc, char *argv[])
{
    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;

    rcf_rpc_server   *pco_iut2 = NULL;
    const char       *tcp_state = NULL;
    te_bool           cache_socket;

    tsa_session ss = TSA_SESSION_INITIALIZER;

    rpc_tcp_state state_to;
    te_bool reuse;
    int iut_s = -1;;
    int opt_val  = 0;

    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;
    TEST_GET_PCO(pco_iut2);
    TEST_GET_IF(iut_if);
    TEST_GET_STRING_PARAM(tcp_state);
    TEST_GET_BOOL_PARAM(cache_socket);

    state_to = tcp_state_str2rpc(tcp_state);

    CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, RETRIES_NUM, NULL,
                                     "net/ipv4/tcp_retries2"));
    CHECK_RC(rcf_rpc_server_restart(pco_iut));

    if (tsa_state_init(&ss, TSA_TST_GW_CSAP) != 0)
        TEST_FAIL("Unable to initialize TSA");

    CHECK_RC(tsa_iut_set(&ss, pco_iut, iut_if, iut_addr));
    CHECK_RC(tsa_tst_set(&ss, pco_tst, tst_if, tst_addr, NULL));
    CHECK_RC(tsa_gw_set(&ss, pco_gw, gw_iut_addr, gw_tst_addr,
                        gw_iut_if, gw_tst_if,
             ((struct sockaddr *)alien_link_addr)->sa_data));
    CFG_WAIT_CHANGES;

    TEST_STEP("Create TCP socket on IUT and CSAPs on tester.");
    tsa_create_session(&ss, 0);

    iut_s = tsa_iut_sock(&ss);

    TEST_STEP("Tweak TCP timeouts to get the socket closed in the determined "
              "time.");
    /**
     * Set low keepalive timeouts for states, which can't wait any
     * packets. There are some TCP socket states, in which socket doesn't
     * send any pakets and doesn't wait ACK, or if it sends a packet its
     * state will be changed. Since socket does not wait any packets, it
     * doesn't retransmit anything. But it sends keep-alive probes when
     * keepalive timeout is expired. So the socket will restransmit
     * keep-alive probes when doesn't receive ACKs of the probes.
     */
    if (state_to == RPC_TCP_CLOSE_WAIT || state_to == RPC_TCP_FIN_WAIT2)
    {
        opt_val = 1;
        rpc_setsockopt(pco_iut, iut_s, RPC_SO_KEEPALIVE, &opt_val);
        opt_val = RETRIES_NUM;
        rpc_setsockopt(pco_iut, iut_s, RPC_TCP_KEEPCNT, &opt_val);
        opt_val = 10;
        rpc_setsockopt(pco_iut, iut_s, RPC_TCP_KEEPIDLE, &opt_val);
        opt_val = 2;
        rpc_setsockopt(pco_iut, iut_s, RPC_TCP_KEEPINTVL, &opt_val);
    }

    TEST_STEP("Perform action to move the TCP connection to the required state.");
    tcp_move_to_state(&ss, state_to, OL_PASSIVE_END, cache_socket);
    iut_s = tsa_iut_sock(&ss);

    if (state_to != tsa_state_cur(&ss))
        TEST_VERDICT("%s was not achieved",
                     tcp_state_rpc2str(tsa_state_to(&ss)));

    TEST_STEP("Close the listener socket.");
    RPC_CLOSE(pco_iut, ss.state.iut_s_aux);

    tcp_test_wait_for_tcp_close(&ss, MSEC_BEFORE_NEXT_ATTEMPT,
                                TCP_MAX_ATTEMPTS);

    TEST_STEP("Check that the accepted socket will be closed by timeout.");
    rpc_getsockopt(pco_iut, iut_s, RPC_SO_ERROR, &opt_val);
    if (opt_val != RPC_ETIMEDOUT)
        TEST_VERDICT("IUT socket has unexpected error %s after closing "
                     "connection, it must be ETIMEDOUT",
                     errno_rpc2str(opt_val));

    TEST_STEP("Check that there is not any cached sockets now.");
    if (tapi_onload_run() &&
        (tapi_onload_get_free_cache(pco_iut2, FALSE, &reuse) > 0 || reuse))
        TEST_VERDICT("All sockets must be uncached");

    TEST_SUCCESS;

cleanup:
    if (tsa_destroy_session(&ss) != 0)
        CLEANUP_TEST_FAIL("Closing working session with TSA failed");

    TEST_END;
}
