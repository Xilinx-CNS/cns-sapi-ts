/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * TCP
 *
 * $Id$
 */

/** @page tcp-peer_large_window Peer declares large window and goes away
 *
 * @objective  Check that declared large window with unacknowledged data
 *             does not make harm for the send queue.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TESTER
 * @param sndbuf        Send buffer size to set on IUT, value @c -1 is used
 *                      to use default size of the buffer (@b SO_SNDBUF is
 *                      not set).
 * @param rcvbuf        Receive buffer size to set on tester
 * @param sndbuf_mode   Value to set env EF_TCP_SNDBUF_MODE
 * @param ack           Allow tester to send acknowledges if @c TRUE
 * @param cache_socket  If @c TRUE, create cached socket to be reused.
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "tcp/peer_large_window"

#include "sockapi-test.h"
#include "tcp_test_macros.h"
#include "tapi_tcp.h"
#include "iomux.h"
#include "onload.h"
#include "tapi_route_gw.h"

/* Value @c -1 is used to avoid setting option @b SO_SNDBUF. */
#define DO_NOT_SET_SO_SNDBUF -1

/*
 * Minimum number of bytes which can be (possibly) written to socket,
 * even if SO_SNDBUF value is small.
 */
#define MIN_SEND_SIZE 150000

/*
 * Acceptable difference between estimated maximum number of bytes
 * which can be written to a socket and observed number,
 * as fraction of SO_SNDBUF value.
 */
#define SNDBUF_ACCURACY 0.25

int
main(int argc, char *argv[])
{
    tapi_route_gateway gw;
    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;
    const struct sockaddr      *tst_alien_addr = NULL;

    int     iut_s = -1;
    int     tst_s = -1;
    int     tst_s_listener = -1;
    int     sndbuf;
    int     sndbuf_set;
    int     rcvbuf;
    te_bool ack;
    te_bool cache_socket;

    int           sndbuf_mode = -1;
    uint64_t      send_limit = 0;
    uint64_t      sent = 0;
    uint64_t      received = 0;

    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;
    TEST_GET_ADDR(pco_tst, tst_alien_addr);
    TEST_GET_INT_PARAM(rcvbuf);
    TEST_GET_INT_PARAM(sndbuf);
    TEST_GET_INT_PARAM(sndbuf_mode);
    TEST_GET_BOOL_PARAM(ack);
    TEST_GET_BOOL_PARAM(cache_socket);

    TAPI_INIT_ROUTE_GATEWAY(gw);

    if (sndbuf_mode >= 0)
        CHECK_RC(tapi_sh_env_save_set_int(pco_iut, "EF_TCP_SNDBUF_MODE",
                                          sndbuf_mode, TRUE, NULL, NULL));
    else
        CHECK_RC(tapi_sh_env_unset(pco_iut, "EF_TCP_SNDBUF_MODE",
                                   TRUE, TRUE));

    TEST_STEP("Configure gateway.");
    CHECK_RC(tapi_route_gateway_configure(&gw));
    CFG_WAIT_CHANGES;

    TEST_STEP("If @p cache_socket is @c TRUE - create cached socket.");
    sockts_create_cached_socket(pco_iut, pco_tst, iut_addr, tst_addr, -1, TRUE,
                                cache_socket);

    iut_s = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_STREAM,
                                       RPC_PROTO_DEF, FALSE, FALSE,
                                       iut_addr);

    tst_s_listener = rpc_create_and_bind_socket(pco_tst, RPC_SOCK_STREAM,
                                                RPC_PROTO_DEF, FALSE, FALSE,
                                                tst_addr);

    TEST_STEP("Set IUT SNDBUF and tester RCVBUF in accordance to the parameters.");
    rpc_setsockopt_int(pco_tst, tst_s_listener, RPC_SO_RCVBUFFORCE, rcvbuf);
    rpc_getsockopt(pco_tst, tst_s_listener, RPC_SO_RCVBUF, &rcvbuf);

    if (sndbuf != DO_NOT_SET_SO_SNDBUF)
        rpc_setsockopt_int(pco_iut, iut_s, RPC_SO_SNDBUF, sndbuf);

    rpc_listen(pco_tst, tst_s_listener, SOCKTS_BACKLOG_DEF);
    rpc_connect(pco_iut, iut_s, tst_addr);
    tst_s = rpc_accept(pco_tst, tst_s_listener, NULL, NULL);

    if (sndbuf == DO_NOT_SET_SO_SNDBUF)
    {
        uint64_t total_filled;
        uint64_t total_received;
        int      rcvbuf_filled;

        rpc_overfill_buffers(pco_iut, iut_s, &total_filled);
        rpc_ioctl(pco_tst, tst_s, RPC_FIONREAD, &rcvbuf_filled);
        sndbuf_set = total_filled - rcvbuf_filled;

        rpc_drain_fd_simple(pco_tst, tst_s, &total_received);
        if (total_received != total_filled)
            TEST_FAIL("rpc_drain_fd_simple() read unexpected number "
                      "of bytes");
    }
    else
    {
        rpc_getsockopt(pco_iut, iut_s, RPC_SO_SNDBUF, &sndbuf_set);
    }

    TEST_STEP("Send data from IUT and receive it on Tester repeatedly to "
              "increase IUT congestion window to the maximum possible.");
    sockts_extend_cong_window(pco_iut, iut_s, pco_tst, tst_s);
    {
        rpc_tcp_info  tcp_info;

        rc = rpc_getsockopt(pco_iut, iut_s, RPC_TCP_INFO, &tcp_info);
        send_limit = MIN(tcp_info.tcpi_snd_cwnd * tcp_info.tcpi_snd_mss +
                         sndbuf_set * (1.0 + SNDBUF_ACCURACY),
                         sndbuf_set * 3);
    }

    TEST_STEP("Prevent ACKs receiving by IUT if @p ack is @c FALSE.");
    if (!ack)
    {
        CHECK_RC(tapi_route_gateway_break_gw_tst(&gw));
        CFG_WAIT_CHANGES;

    }

    TEST_STEP("Send data packets from IUT until the send buffer is overfilled.");

    rpc_overfill_buffers(pco_iut, iut_s, &sent);

    TEST_STEP("Read all data on Tester.");

    rpc_drain_fd_simple(pco_tst, tst_s, &received);

    RING("Sent %" TE_PRINTF_64 "u bytes, "
         "received %" TE_PRINTF_64 "u bytes, "
         "send buffer size %d", sent, received, sndbuf_set);

    TEST_STEP("Check that not less than half of @c SO_SNDBUF value was passed "
              "to send().");

    if (sent < (uint64_t)sndbuf_set / 2)
        TEST_VERDICT("Less data was sent than half of SO_SNDBUF value");

    if (ack)
    {
        TEST_STEP("If @p ack is @c TRUE, check that all the data was received by "
                  "peer.");

        if (received != sent)
            TEST_VERDICT("Size of data received does not match "
                         "size of data sent");
    }
    else
    {
        TEST_STEP("If @p ack is @c FALSE, check that no more than "
                  "MIN(<TCP send window size> + "
                  "<@c SO_SNDBUF value> * (1.0 + @c SNDBUF_ACCURACY), "
                  "<@c SO_SNDBUF value> * 3) "
                  "was written to IUT socket.");

        if (sent > send_limit)
            TEST_VERDICT("Too much data was successfully "
                         "written to socket");
    }

    TEST_SUCCESS;

cleanup:

    if (!ack)
    {
        CLEANUP_CHECK_RC(tapi_cfg_del_neigh_entry(pco_tst->ta,
                                                  tst_if->if_name,
                                                  gw_tst_addr));
        CFG_WAIT_CHANGES;
    }

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s_listener);

    TEST_END;
}
