/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * TCP
 */

/** @page tcp-default_tcp_orphan_retries Default FIN-ACK retransmit number
 *
 * @objective  Check that default FIN-ACK retransmit number in Onload is
 *             equal to linux number.
 *
 * @type conformance
 *
 * @param env           Testing environment.
 *                      - @ref arg_types_env_peer2peer
 *                      - @ref arg_types_env_peer2peer_ipv6
 * @param tcp_state     TCP state to be tested:
 *                      - @c TCP_FIN_WAIT1
 *                      - @c TCP_CLOSING
 * @param opening       How to establish connection:
 *                      - @c active - open actively from IUT
 *                      - @c passive_open - open passively from IUT,
 *                        close listener after accepting
 *                      - @c passive_close - open passively from IUT,
 *                        close listener after closing accepted
 *                        socket
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "tcp/default_tcp_orphan_retries"

#include "sockapi-test.h"
#include "tcp_test_macros.h"
#include "tapi_tcp.h"
#include "tapi_proc.h"
#include "onload.h"

/** Maxmim waiting time in seconds */
#define TIME_LIMIT 300

static int
get_fin_ack_num(rcf_rpc_server *pco_iut, rcf_rpc_server *pco_iut_aux,
                rcf_rpc_server *pco_tst,
                const struct sockaddr *iut_addr,
                const struct sockaddr *tst_fake_addr,
                const struct if_nameindex *iut_if,
                const struct if_nameindex *tst_if,
                const void *alien_link_addr, int opening,
                csap_handle_t csap, rpc_tcp_state state, te_bool onload)
{
    tsa_session         ss = TSA_SESSION_INITIALIZER;
    tapi_tcp_handler_t  csap_tst_s;
    int                 iut_s = -1;
    int                 i = 0;
    tsa_packets_counter ctx;
    int                 rc;

    if (tsa_state_init(&ss, TSA_TST_CSAP) != 0)
        TEST_FAIL("Unable to initialize TSA");

    tsa_iut_set(&ss, pco_iut, iut_if, iut_addr);
    tsa_tst_set(&ss, pco_tst, tst_if, tst_fake_addr,
                ((struct sockaddr *)alien_link_addr)->sa_data);

    /* Create a TCP socket on IUT and CSAP socket emulation on Tester */
    tsa_create_session(&ss, 0);
    iut_s = tsa_iut_sock(&ss);

    /*
     * Without such a delay this test fails on nali/narvi
     * (Ubuntu 20.04.1, 5.4.0-47-generic), see ST-1603.
     * Probably some time is required before an interface
     * becomes promiscuous.
     * Note - moving this delay after tapi_tad_trrecv_start()
     * does not work for unknown reason. TSA library makes
     * interface promiscuous before this delay.
     */
    SLEEP(5);

    /* Move IUT socket to ESTABLISHED TCP state */
    tcp_move_to_state(&ss, RPC_TCP_ESTABLISHED, opening, FALSE);

    iut_s = tsa_iut_sock(&ss);
    csap_tst_s = tsa_tst_sock(&ss);

    /* Start CSAP sniffer to track transmitted packets */
    memset(&ctx, 0, sizeof(ctx));
    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, 0, csap, NULL,
                                   TAD_TIMEOUT_INF, 0, RCF_TRRECV_PACKETS));

    /* Close IUT socket, moving it to target TCP state */
    RPC_CLOSE(pco_iut, iut_s);

    switch (state)
    {
        case RPC_TCP_FIN_WAIT1:
            break;

        case RPC_TCP_CLOSING:
            CHECK_RC(tapi_tcp_wait_packet(ss.state.csap.csap_tst_s, 1000));
            CHECK_RC(tapi_tcp_send_fin(csap_tst_s, 1000));
            break;

        default:
            TEST_FAIL("Unexpected socket state is requested");
    }

    /*
     * Wait until IUT socket disappears from netstat/onload_netstat
     * output, counting FIN-ACK retransmits
     */

    if (opening == OL_PASSIVE_CLOSE)
    {
        /*
         * Listener is not closed, we wait for connected socket to
         * disappear first
         */
        sockts_wait_socket_closing_spec(pco_iut_aux, iut_addr, tst_fake_addr,
                                        TIME_LIMIT, onload, FALSE);
        RPC_CLOSE(pco_iut, ss.state.iut_s_aux);

        iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                           RPC_SOCK_STREAM, RPC_PROTO_DEF);
        ss.state.iut_s = iut_s;

        RPC_AWAIT_ERROR(pco_iut);
        rc = rpc_bind(pco_iut, iut_s, iut_addr);
        if (rc < 0)
        {
            TEST_VERDICT("Trying to bind a new TCP socket to the same "
                         "address/port failed with %r",
                         RPC_ERRNO(pco_iut));
        }
    }
    else
    {
        iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                           RPC_SOCK_STREAM, RPC_PROTO_DEF);
        ss.state.iut_s = iut_s;

        do {
            RPC_AWAIT_IUT_ERROR(pco_iut);
            rc = rpc_bind(pco_iut, iut_s, iut_addr);
            if (rc < 0)
            {
                if (RPC_ERRNO(pco_iut) != RPC_EADDRINUSE)
                    TEST_FAIL("Bind failed with unexpected errno %s",
                              strerror(RPC_ERRNO(pco_iut)));
                SLEEP(1);
            }
            else
                break;

            i++;
        } while (i < TIME_LIMIT);

        if (i == TIME_LIMIT)
            TEST_VERDICT("The TCP connection was not closed by timeout");
    }

    rcf_ta_trrecv_stop(pco_tst->ta, 0, csap, tsa_packet_handler, &ctx, NULL);
    tsa_print_packet_stats(&ctx);
    tsa_destroy_session(&ss);

    return ctx.fin_ack;
}

int
main(int argc, char *argv[])
{
    const struct if_nameindex *tst_if = NULL;
    const struct if_nameindex *iut_if = NULL;
    const struct sockaddr     *iut_addr;
    const struct sockaddr     *tst_fake_addr;
    const void                *alien_link_addr = NULL;

    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_iut_aux = NULL;
    rcf_rpc_server *pco_tst = NULL;
    const char     *tcp_state;
    int             rt1;
    int             rt2;

    csap_handle_t csap = CSAP_INVALID_HANDLE;
    rpc_tcp_state state;
    int           opening;
    te_bool       is_enabled_acc = TRUE;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_fake_addr);
    TEST_GET_LINK_ADDR(alien_link_addr);
    TEST_GET_IF(tst_if);
    TEST_GET_IF(iut_if);
    TEST_GET_STRING_PARAM(tcp_state);
    TEST_GET_ENUM_PARAM(opening, OPENING_LISTENER);

    /*
     * Auxiliary RPC server is required to run system("onload_stackdump")
     * from it. If it is done from pco_iut instead, forking will result
     * in dropping the current default Onload stack if all the sockets
     * in it are closed, so that the stack will become "zombie".
     * See
     * https://bugzilla.solarflarecom.com/bugzilla/show_bug.cgi?id=87520#c15
     */
    CHECK_RC(rcf_rpc_server_create(pco_iut->ta, "pco_iut_aux",
                                   &pco_iut_aux));

    state = tcp_state_str2rpc(tcp_state);

    TEST_STEP("Create CSAP on Tester to capture FIN-ACK retransmits "
              "from IUT.");

    CHECK_RC(tapi_tcp_ip_eth_csap_create(
                                  pco_tst->ta, 0, tst_if->if_name,
                                  TAD_ETH_RECV_DEF,
                                  NULL, NULL,
                                  iut_addr->sa_family,
                                  TAD_SA2ARGS(tst_fake_addr, iut_addr),
                                  &csap));

    TEST_STEP("Establish TCP connection according to @p opening. Move IUT "
              "socket to @p tcp_state. Call @b close() on IUT socket. Wait "
              "until it is no longer observable with @b onload_netstat, "
              "counting FIN-ACK retransmits.");

    rt1 = get_fin_ack_num(pco_iut, pco_iut_aux, pco_tst,
                          iut_addr, tst_fake_addr, iut_if, tst_if,
                          alien_link_addr, opening, csap, state,
                          TRUE);

    TEST_STEP("Disable Onload acceleration.");
    CHECK_RC(tapi_onload_acc(pco_iut, FALSE));
    is_enabled_acc = FALSE;

    TEST_STEP("Establish TCP connection according to @p opening. Move IUT "
              "socket to @p tcp_state. Call @b close() on IUT socket. Wait "
              "until it is no longer observable with @b netstat, counting "
              "FIN-ACK retransmits.");
    rt2 = get_fin_ack_num(pco_iut, pco_iut_aux, pco_tst,
                          iut_addr, tst_fake_addr, iut_if, tst_if,
                          alien_link_addr, opening, csap, state,
                          FALSE);

    TEST_STEP("Check that the same number of FIN-ACK retransmits was done "
              "for both connections.");
    if (rt1 != rt2)
    {
        ERROR("%d FIN-ACK retransmits on Onload vs %d on Linux", rt1, rt2);
        TEST_VERDICT("Default FIN-ACK retransmit number on Onload "
                     "is %s than on Linux", (rt1 < rt2 ? "less" : "more"));
    }

    TEST_SUCCESS;

cleanup:
    tapi_tad_csap_destroy(pco_tst->ta, 0, csap);

    if (!is_enabled_acc)
        tapi_onload_acc(pco_iut, TRUE);

    CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_iut_aux));

    TEST_END;
}

