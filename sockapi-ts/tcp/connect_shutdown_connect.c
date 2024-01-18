/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Tests
 *
 * This test package contains tests for special cases of TCP protocol,
 * such as ICMP and routing table handling, small and zero window,
 * fragmentation of TCP packets, etc.
 */

/**
 * @page tcp-connect_shutdown_connect Re-connect after aborted attempt
 *
 * @objective Abort connection attemt using shutdown(wr) while it is
 *            in progress, then connect the same socket to the peer.
 *
 * @param first_nonblock    If @c TRUE, use non-blocking connect when
 *                          trying to establish a connection the first
 *                          time.
 * @param second_nonblock   If @c TRUE use non-blocking connect when
 *                          establishing a new connection after the failed
 *                          attempt.
 * @param rst               If @c TRUE deliver the first SYN packet to
 *                          tester.
 * @param cache_socket      If @c TRUE, create cached socket to be reused.
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#include <linux/ethtool.h>
#define TE_TEST_NAME "tcp/connect_shutdown_connect"

#include "sockapi-test.h"

#include "tapi_proc.h"
#include "tapi_route_gw.h"
#include "tcp_test_macros.h"
#include "tapi_sockets.h"

/** How long to wait for RST, in seconds. */
#define RST_TIMEOUT 5

int
main(int argc, char *argv[])
{
    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;
    tapi_route_gateway gateway;

    rcf_rpc_server *pco_iut_aux = NULL;

    int iut_s = -1;
    int tst_s_listener = -1;
    int tst_s = -1;
    int fdflags;
    int i;

    csap_handle_t   csap = CSAP_INVALID_HANDLE;

    te_bool first_nonblock;
    te_bool second_nonblock;
    te_bool rst;
    te_bool test_fail = FALSE;
    te_bool cache_socket;
    te_bool shut_busy = FALSE;

    tsa_packets_counter     ctx;

    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;
    TEST_GET_BOOL_PARAM(first_nonblock);
    TEST_GET_BOOL_PARAM(second_nonblock);
    TEST_GET_BOOL_PARAM(rst);
    TEST_GET_BOOL_PARAM(cache_socket);

    TEST_STEP("Connect IUT and Tester via gateway host.");
    TAPI_INIT_ROUTE_GATEWAY(gateway);
    tapi_route_gateway_configure(&gateway);

    TEST_STEP("If @p cache_socket is @c TRUE - create cached socket.");
    sockts_create_cached_socket(pco_iut, pco_tst, iut_addr, tst_addr, -1,
                                TRUE, cache_socket);

    TEST_STEP("If @p rst is @c TRUE, break connection Tester->IUT, "
              "else break connection IUT->Tester.");
    if (rst)
        tapi_route_gateway_break_tst_gw(&gateway);
    else
        tapi_route_gateway_break_gw_tst(&gateway);

    CFG_WAIT_CHANGES;

    TEST_STEP("If @p rst is TRUE, create CSAP to check that RST "
              "is really sent.");
    if (rst)
    {
        CHECK_RC(tapi_tcp_ip_eth_csap_create(
                    pco_gw->ta, 0,
                    gw_tst_if->if_name,
                    TAD_ETH_RECV_ALL, NULL, NULL,
                    tst_addr->sa_family,
                    TAD_SA2ARGS(tst_addr, iut_addr), &csap));

        CHECK_RC(tapi_tad_trrecv_start(pco_gw->ta, 0, csap, NULL,
                                       TAD_TIMEOUT_INF, 0,
                                       RCF_TRRECV_PACKETS));
    }

    TEST_STEP("Create and bind TCP socket on IUT.");
    iut_s = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_STREAM,
                                       RPC_PROTO_DEF, FALSE, FALSE,
                                       iut_addr);

    TEST_STEP("Create listener socket on Tester.");
    tst_s_listener = rpc_create_and_bind_socket(
                                       pco_tst, RPC_SOCK_STREAM,
                                       RPC_PROTO_DEF, FALSE, FALSE,
                                       tst_addr);
    rpc_listen(pco_tst, tst_s_listener, SOCKTS_BACKLOG_DEF);

    if (first_nonblock)
    {
        TEST_STEP("If @p first_nonblock, set IUT socket as non-blocking.");
        fdflags = rpc_fcntl(pco_iut, iut_s, RPC_F_GETFL, 0);
        rpc_fcntl(pco_iut, iut_s, RPC_F_SETFL,
                  fdflags | RPC_O_NONBLOCK);
        pco_iut_aux = pco_iut;
    }
    else
    {
        TEST_STEP("Else create a thread on IUT in which to call blocking "
                  "connect().");
        CHECK_RC(rcf_rpc_server_thread_create(pco_iut, "iut_connect_thread",
                                              &pco_iut_aux));
        pco_iut_aux->op = RCF_RPC_CALL;
    }

    TEST_STEP("Call connect() on IUT according to @p first_nonblock.");
    RPC_AWAIT_ERROR(pco_iut_aux);
    rc = rpc_connect(pco_iut_aux, iut_s, tst_addr);
    if (first_nonblock)
    {
        if (rc >= 0)
            TEST_VERDICT("The first connect() succeeded unexpectedly");
        else if (RPC_ERRNO(pco_iut_aux) != RPC_EINPROGRESS)
            TEST_VERDICT("The first connect() returned unexpected errno %r",
                         RPC_ERRNO(pco_iut_aux));
    }
    else
    {
        if (rc < 0)
            TEST_VERDICT("The first connect() failed with errno %r when "
                         "called with RCF_RPC_CALL",
                         RPC_ERRNO(pco_iut_aux));
    }

    TAPI_WAIT_NETWORK;

    TEST_STEP("Call shutdown(WR) on IUT socket.");
    RPC_AWAIT_ERROR(pco_iut);
    rc = rpc_shutdown(pco_iut, iut_s, RPC_SHUT_WR);
    if (rc < 0)
    {
        CHECK_RPC_ERRNO_NOEXIT(pco_iut, RPC_EBUSY, test_fail,
                               "shutdown(WR) returned -1");
        if (!test_fail)
        {
            if (first_nonblock)
            {
                RING_VERDICT("shutdown() unexpectedly returned -1 with EBUSY");
                test_fail = TRUE;
            }
            else
            {
                shut_busy = TRUE;
                RING_VERDICT("shutdown() returned -1 with EBUSY, while "
                             "connect() is hanging in another thread.");
            }
        }
    }

    TEST_STEP("Repair network connection.");
    if (rst)
        tapi_route_gateway_repair_tst_gw(&gateway);
    else
        tapi_route_gateway_repair_gw_tst(&gateway);
    CFG_WAIT_CHANGES;

    TEST_STEP("If @p rst is @c TRUE, check that IUT sends RST "
              "in response to SYN-ACK from Tester.");
    if (rst)
    {
        for (i = 0; i < RST_TIMEOUT; i++)
        {
            memset(&ctx, 0, sizeof(ctx));
            CHECK_RC(rcf_ta_trrecv_get(pco_gw->ta, 0, csap,
                                       tsa_packet_handler, &ctx, NULL));
            tsa_print_packet_stats(&ctx);

            if (ctx.rst > 0 || ctx.rst_ack > 0)
                break;

            SLEEP(1);
        }

        if (ctx.rst == 0 && ctx.rst_ack == 0)
            RING_VERDICT("RST was not sent from IUT");
    }
    else
    {
        TAPI_WAIT_NETWORK;
    }

    if (first_nonblock)
    {
        rpc_tcp_state tcp_state;

        TEST_STEP("If @p first_nonblock is @c TRUE, check that IUT socket "
                  "is in TCP_CLOSE state.");

        tcp_state = tapi_get_tcp_sock_state(pco_iut, iut_s);
        if (tcp_state != RPC_TCP_CLOSE)
            TEST_VERDICT("TCP socket is in state %s after "
                         "shutdown()", tcp_state_rpc2str(iut_s));
    }
    else
    {
        TEST_STEP("If @p first_nonblock is @c FALSE, check that connect() was "
                  "unblocked and failed with ECONNRESET.");

        RPC_AWAIT_ERROR(pco_iut_aux);
        rc = rpc_connect(pco_iut_aux, iut_s, tst_addr);
        if (rc >= 0)
        {
            if (!shut_busy)
            {
                TEST_VERDICT("The first connect() succeeded unexpectedly "
                             "after calling shutdown()");
            }
        }
        else if (RPC_ERRNO(pco_iut_aux) != RPC_ECONNRESET)
        {
            TEST_VERDICT("The first connect() returned unexpected errno %r "
                         "after calling shutdown()",
                         RPC_ERRNO(pco_iut_aux));
        }
    }

    TEST_STEP("If @p second_nonblock is @c TRUE, make IUT socket non-blocking; "
              "otherwise make it blocking.");
    fdflags = rpc_fcntl(pco_iut, iut_s, RPC_F_GETFL, 0);
    if (second_nonblock)
    {
        rpc_fcntl(pco_iut, iut_s, RPC_F_SETFL,
                  (fdflags | RPC_O_NONBLOCK));
    }
    else
    {
        rpc_fcntl(pco_iut, iut_s, RPC_F_SETFL,
                  (fdflags & ~(RPC_O_NONBLOCK | RPC_O_NDELAY)));
    }

    if (second_nonblock)
    {
        TEST_STEP("If @p second_nonblock is @c TRUE, call connect() on IUT and "
                  "check that it fails with @c EINPROGRESS or @c EISCONN if "
                  "first @b shutdown() returned @c EBUSY. Wait for a while to "
                  "let connection be established.");

        RPC_AWAIT_ERROR(pco_iut);
        rc = rpc_connect(pco_iut, iut_s, tst_addr);
        if (rc >= 0)
        {
            TEST_VERDICT("The second connect() succeeded unexpectedly");
        }
        else
        {
            if ((RPC_ERRNO(pco_iut) != RPC_EINPROGRESS && !shut_busy) ||
                (RPC_ERRNO(pco_iut) != RPC_EISCONN && shut_busy))
            {
                TEST_VERDICT("The second connect() returned unexpected "
                             "errno %r",
                             RPC_ERRNO(pco_iut));
            }
        }

        TAPI_WAIT_NETWORK;
    }

    if (!second_nonblock || !shut_busy)
    {
        TEST_STEP("Call connect() on IUT again, check that it succeeds.");
        RPC_AWAIT_ERROR(pco_iut);
        rc = rpc_connect(pco_iut, iut_s, tst_addr);
        if (rc < 0)
        {
            if (shut_busy)
            {
                CHECK_RPC_ERRNO(pco_iut, RPC_EISCONN,
                                "connect() returend -1");
            }
            else
            {
                TEST_VERDICT("The final connect() failed with errno %r",
                             RPC_ERRNO(pco_iut));
            }
        }
    }

    TEST_STEP("Accept the connection on Tester.");
    tst_s = rpc_accept(pco_tst, tst_s_listener, NULL, NULL);

    TEST_STEP("Check data transmission in both directions.");
    sockts_test_connection(pco_iut, iut_s, pco_tst, tst_s);

    if (test_fail)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s_listener);

    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_gw->ta, 0, csap));

    if (pco_iut_aux != pco_iut && pco_iut_aux != NULL)
        rcf_rpc_server_destroy(pco_iut_aux);

    TEST_END;
}
