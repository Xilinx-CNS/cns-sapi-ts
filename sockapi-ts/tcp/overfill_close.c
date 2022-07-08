/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Tests
 * This test package contains tests for special cases of TCP protocol,
 * such as ICMP and routing table handling, small and zero window,
 * fragmentation of TCP packets, etc.
 *
 * $Id$
 */

/**
 * @page tcp-overfill_close Close TCP socket while buffers are overfilled
 *
 * @objective Overfill send or receive buffer and close the socket.
 *
 * @param shutdown     Call @c shutdown(WR) if @c TRUE.
 * @param fill_rcv     How much to send from Tester:
 *                     - empty (nothing);
 *                     - packet (one packet);
 *                     - full (overfill IUT receive buffer).
 * @param fill_snd     Overfill send buffer if @c TRUE.
 * @param peer_close   Close socket on tester if @c TRUE.
 * @param cache_socket Create cached socket to be reused.
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "tcp/overfill_close"

#include "sockapi-test.h"
#include "tcp_test_macros.h"

/** Length of data packet to be used in the test. */
#define PKT_LEN 1024

/** Ways to fill receive buffer. */
typedef enum {
    FILL_BUF_EMPTY,   /**< Do not fill. */
    FILL_BUF_PACKET,  /**< Send a single packet from peer. */
    FILL_BUF_FULL,    /**< Overfill. */
} buf_fill_type;

/**
 * Enumberation of buffer fill types to be passed to
 * TEST_GET_ENUM_PARAM() macro.
 */
#define BUF_FILL_TYPES \
    { "empty",      FILL_BUF_EMPTY },     \
    { "packet",     FILL_BUF_PACKET },    \
    { "full",       FILL_BUF_FULL }

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;

    const struct if_nameindex *tst_if = NULL;
    const struct if_nameindex *iut_if = NULL;

    int iut_s = -1;
    int tst_s = -1;

    te_bool         shutdown = FALSE;
    buf_fill_type   fill_rcv;
    te_bool         fill_snd = FALSE;
    te_bool         peer_close = FALSE;
    te_bool         cache_socket;

    char data[PKT_LEN];

    csap_handle_t           csap = CSAP_INVALID_HANDLE;
    tsa_packets_counter     ctx;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(tst_if);
    TEST_GET_IF(iut_if);
    TEST_GET_BOOL_PARAM(shutdown);
    TEST_GET_ENUM_PARAM(fill_rcv, BUF_FILL_TYPES);
    TEST_GET_BOOL_PARAM(fill_snd);
    TEST_GET_BOOL_PARAM(peer_close);
    TEST_GET_BOOL_PARAM(cache_socket);

    TEST_STEP("If @p cache_socket is @c TRUE - create cached socket.");
    sockts_create_cached_socket(pco_iut, pco_tst, iut_addr, tst_addr, -1,
                                TRUE, cache_socket);

    TEST_STEP("Establish TCP connection.");
    GEN_CONNECTION(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   tst_addr, iut_addr, &tst_s, &iut_s);

    te_fill_buf(data, PKT_LEN);

    TEST_STEP("Send a data packet from IUT.");
    rpc_send(pco_iut, iut_s, data, PKT_LEN, 0);

    TEST_STEP("If @p fill_rcv is @c 'full', overfill RX buffer of the socket. "
              "If @p fill_rcv is @c 'packet', send a single packet from Tester.");
    if (fill_rcv == FILL_BUF_FULL)
        rpc_overfill_buffers(pco_tst, tst_s, NULL);
    else if (fill_rcv == FILL_BUF_PACKET)
        rpc_send(pco_tst, tst_s, data, PKT_LEN, 0);

    TEST_STEP("If @p fill_snd is @c TRUE, overfill TX buffer of the socket.");
    if (fill_snd)
        rpc_overfill_buffers(pco_iut, iut_s, NULL);

    TEST_STEP("Add CSAP on tester to count incoming packets.");
    CHECK_RC(tapi_tcp_ip_eth_csap_create(
        pco_tst->ta, 0, tst_if->if_name, TAD_ETH_RECV_DEF,
        NULL, NULL, tst_addr->sa_family, TAD_SA2ARGS(NULL, NULL), &csap));

    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, 0, csap, NULL,
                                   TAD_TIMEOUT_INF, 0, RCF_TRRECV_PACKETS));

    TEST_STEP("If @p shutdown is @c TRUE: "
              "- call @b shutdown(WR) on IUT socket; "
              "- check that FIN-ACK packet is sent from IUT "
              "if @p fill_snd is @c FALSE.");
    if (shutdown)
    {
        RPC_AWAIT_ERROR(pco_iut);
        rc = rpc_shutdown(pco_iut, iut_s, RPC_SHUT_WR);
        if (rc < 0)
            TEST_VERDICT("shutdown() unexpectedly failed with errno %r",
                         RPC_ERRNO(pco_iut));
        TAPI_WAIT_NETWORK;

        memset(&ctx, 0, sizeof(ctx));
        CHECK_RC(rcf_ta_trrecv_get(pco_tst->ta, 0, csap,
                                   tsa_packet_handler, &ctx, NULL));
        tsa_print_packet_stats(&ctx);

        if (fill_snd)
        {
            if (ctx.fin_ack != 0)
                TEST_VERDICT("FIN-ACK was received "
                             "unexpectedly after shutdown()");
        }
        else
        {
            if (ctx.fin_ack == 0)
                TEST_VERDICT("FIN-ACK was not received after shutdown()");
        }
    }

    TEST_STEP("Close the socket on Tester if @p peer_close is @c TRUE.");
    if (peer_close)
    {
        RPC_CLOSE(pco_tst, tst_s);
        TAPI_WAIT_NETWORK;
    }

    TEST_STEP("Close the IUT socket.");
    RPC_CLOSE(pco_iut, iut_s);
    TAPI_WAIT_NETWORK;

    TEST_STEP("Check that RST-ACK is received from IUT if some "
              "data is in IUT receive buffer and @p peer_close is "
              "@c FALSE.");

    memset(&ctx, 0, sizeof(ctx));
    CHECK_RC(rcf_ta_trrecv_stop(pco_tst->ta, 0, csap,
                                tsa_packet_handler, &ctx, NULL));
    tsa_print_packet_stats(&ctx);

    if (peer_close)
    {
        if (ctx.rst_ack != 0)
            TEST_VERDICT("RST-ACK was unexpectedly received from IUT "
                         "after closing IUT socket");
    }
    else
    {
        if (ctx.rst_ack == 0 && fill_rcv != FILL_BUF_EMPTY)
            TEST_VERDICT("RST-ACK was not received from IUT "
                         "after closing IUT socket");
    }

    if (!peer_close)
    {
        /*
         * If @p peer_close is @c FALSE, receive all data on
         * Tester and check what the last @b recv() returns.
         */

        do {
            RPC_AWAIT_ERROR(pco_tst);
            pco_tst->silent = TRUE;
            rc = rpc_recv(pco_tst, tst_s, data, PKT_LEN, 0);
        } while (rc > 0);

        if (fill_rcv != FILL_BUF_EMPTY && (!shutdown || fill_snd))
        {
            if (rc >= 0)
                TEST_VERDICT("Last recv() on Tester unexpectedly succeeded "
                             "instead of failing with ECONNRESET");
            else if (RPC_ERRNO(pco_tst) != RPC_ECONNRESET)
                TEST_VERDICT("Last recv() on Tester failed with unexpected "
                             "errno %r", RPC_ERRNO(pco_tst));
        }
        else
        {
            if (rc < 0)
                TEST_VERDICT("Last recv() on Tester unexpectedly failed "
                             "with errno %r", RPC_ERRNO(pco_tst));
        }
    }

    TEST_SUCCESS;

cleanup:
    tapi_tad_csap_destroy(pco_tst->ta, 0, csap);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
