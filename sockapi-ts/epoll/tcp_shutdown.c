/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Tests
 * Test suite on reliability of the @b epoll functions.
 *
 * $Id$
 */

/**
 * @page epoll-tcp_shutdown epoll behavior after shutdown(WR)
 *
 * @objective Check @b epoll behavior after @b shutdown(WR) on TCP socket.
 *
 * @param evts            Epoll events to be provoked and/or passed
 *                        to @b epoll_ctl():
 *                        - in;
 *                        - out;
 *                        - inout.
 * @param event_before    If @c TRUE provoke an event before @b shutdown().
 * @param close_peer      If @c TRUE, close peer socket after calling
 *                        @b shutdown().
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "epoll/tcp_shutdown"

#include "sockapi-test.h"

#include "iomux.h"
#include "epoll_common.h"

/** Packet length used in this test. */
#define PKT_LEN 1024

/** Epoll timeout. */
#define EPOLL_TIMEOUT 500

/** Delay between read calls to make data reading slower, milliseconds. */
#define READING_DELAY 50

/**
 * Timeout for @b rpc_iomux_flooder() call which is used to read
 * data on peer from overfilled IUT TX buffer (seconds).
 */
#define FLOODER_TIMEOUT 1

int
main(int argc, char *argv[])
{
    rcf_rpc_server             *pco_iut = NULL;
    rcf_rpc_server             *pco_tst = NULL;
    const struct sockaddr      *iut_addr = NULL;
    const struct sockaddr      *tst_addr = NULL;

    const struct if_nameindex  *tst_if = NULL;

    struct rpc_epoll_event  event;
    uint32_t                events;
    uint32_t                exp_events;

    int tst_s = -1;
    int iut_s = -1;
    int epfd = -1;

    const char   *evts = NULL;
    te_bool       event_before = FALSE;
    te_bool       close_peer = FALSE;

    char send_data[PKT_LEN];
    char recv_data[PKT_LEN];

    csap_handle_t           csap = CSAP_INVALID_HANDLE;

    tsa_packets_counter     ctx;

    uint64_t tx_stat = 0;
    uint64_t rx_stat = 0;
    te_bool  failed = FALSE;
    rpc_ptr  rpcbuf = RPC_NULL;
    int      rpcbuf_len;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(tst_if);
    TEST_GET_STRING_PARAM(evts);
    TEST_GET_BOOL_PARAM(event_before);
    TEST_GET_BOOL_PARAM(close_peer);

    te_fill_buf(send_data, PKT_LEN);

    PARSE_EVTS(evts, events, events);

    CHECK_RC(tapi_tcp_ip_eth_csap_create(pco_tst->ta, 0,
                                         tst_if->if_name,
                                         TAD_ETH_RECV_DEF, NULL, NULL,
                                         tst_addr->sa_family,
                                         TAD_SA2ARGS(tst_addr, iut_addr),
                                         &csap));

    /* Do not print out packets captured by CSAP. */
    rcf_tr_op_log(FALSE);

    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, 0, csap, NULL,
                                   TAD_TIMEOUT_INF, 0, RCF_TRRECV_PACKETS));

    TEST_STEP("Establish TCP connection to get TCP socket on IUT.");
    GEN_CONNECTION(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   tst_addr, iut_addr, &tst_s, &iut_s);

    TEST_STEP("If @p evts is @c 'out' or @c 'inout', overfill TX buffer "
              "for IUT socket, so that later we can provoke @c EPOLLOUT by "
              "reading data on Tester.");
    if (events & RPC_EPOLLOUT)
        rpc_overfill_buffers(pco_iut, iut_s, &tx_stat);

    TEST_STEP("Create a epoll set and add the socket to it with events "
              "defined by @p evts; use edge-triggered mode.");
    epfd = rpc_epoll_create(pco_iut, 1);

    rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_ADD, iut_s,
                         events | RPC_EPOLLHUP |
                         RPC_EPOLLERR | RPC_EPOLLET);

    TEST_STEP("If @p event_before is @c TRUE, provoke events defined by "
              "@p evts.");
    if (event_before)
    {
        if (events & RPC_EPOLLIN)
            RPC_SEND(rc, pco_tst, tst_s, send_data, PKT_LEN, 0);

        if (events & RPC_EPOLLOUT)
        {
            rpc_iomux_flooder(pco_tst, NULL, 0, &tst_s, 1,
                              PKT_LEN, FLOODER_TIMEOUT, FLOODER_TIMEOUT,
                              FUNC_DEFAULT_IOMUX,
                              NULL, &rx_stat);

            if (rx_stat != tx_stat)
            {
                ERROR_VERDICT("%s data was received than sent from IUT",
                              (rx_stat > tx_stat ? "More" : "Less"));
                failed = TRUE;
            }
        }

        TAPI_WAIT_NETWORK;
    }

    TEST_STEP("Call @b shutdown(WR) on IUT socket.");
    RPC_AWAIT_ERROR(pco_iut);
    rc = rpc_shutdown(pco_iut, iut_s, RPC_SHUT_WR);
    if (rc < 0)
        TEST_VERDICT("shutdown() unexpectedly failed with errno %r",
                     RPC_ERRNO(pco_iut));
    TAPI_WAIT_NETWORK;

    TEST_STEP("Check that @b shutdown(WR) sent FIN to the peer.");
    memset(&ctx, 0, sizeof(ctx));
    CHECK_RC(rcf_ta_trrecv_get(pco_tst->ta, 0, csap,
                               tsa_packet_handler, &ctx, NULL));
    tsa_print_packet_stats(&ctx);

    if ((events & RPC_EPOLLOUT) && !event_before)
    {
        if (ctx.fin_ack > 0 || ctx.push_fin_ack > 0)
        {
            ERROR_VERDICT("shutdown() sent FIN to peer "
                          "despite overfilled send buffer");
            failed = TRUE;
        }
    }
    else
    {
        if (ctx.fin_ack <= 0 && ctx.push_fin_ack <= 0)
        {
            ERROR_VERDICT("shutdown() did not send FIN to peer");
            failed = TRUE;
        }
    }

    TEST_STEP("If @p close_peer, close peer socket on Tester.");
    if (close_peer)
    {
        RPC_CLOSE(pco_tst, tst_s);
        TAPI_WAIT_NETWORK;
    }

    TEST_STEP("Call @b epoll_wait() and check its result.");

    exp_events = 0;
    if (events & RPC_EPOLLOUT)
        exp_events = exp_events | RPC_EPOLLOUT;
    if ((events & RPC_EPOLLIN) && (event_before || close_peer))
        exp_events = exp_events | RPC_EPOLLIN;
    if (close_peer)
        exp_events = exp_events | RPC_EPOLLHUP;
    if (close_peer && !event_before && (events & RPC_EPOLLOUT))
        exp_events = exp_events | RPC_EPOLLERR;

    RPC_AWAIT_ERROR(pco_iut);
    rc = rpc_epoll_wait(pco_iut, epfd, &event, 1, EPOLL_TIMEOUT);
    epoll_check_single_event(pco_iut, IC_EPOLL, rc, &event,
                             (exp_events > 0 ? 1 : 0),
                             RPC_EOK, iut_s, exp_events,
                             "The first call");

    TEST_STEP("Receive and check data on IUT socket if required.");
    if (event_before)
    {
        if (events & RPC_EPOLLIN)
        {
            rc = rpc_recv(pco_iut, iut_s, recv_data, PKT_LEN, 0);
            SOCKTS_CHECK_RECV(pco_iut, recv_data, send_data, PKT_LEN, rc);
        }
    }
    else
    {
        TEST_STEP("If Tester socket is not closed by now and IUT socket send "
                  "buffer is overfilled, free overfilled buffer.");
        if (!close_peer && (events & RPC_EPOLLOUT))
        {
            rpcbuf_len = tx_stat / 10;
            rpcbuf = rpc_malloc(pco_tst, rpcbuf_len);
            rx_stat = 0;
            do {
                rc = rpc_readbuf(pco_tst, tst_s, rpcbuf, rpcbuf_len);
                rx_stat += rc;

                /* Make data reading a bit slower to give time to CSAP to
                 * process all packets. */
                if (rc != 0)
                    MSLEEP(READING_DELAY);
            } while (rc != 0);

            if (rx_stat != tx_stat)
            {
                ERROR_VERDICT("%s data was received than sent from IUT",
                              (rx_stat > tx_stat ? "More" : "Less"));
                failed = TRUE;
            }
        }
    }

    TEST_STEP("If IUT socket send buffer was overfilled when @b shutdown() was "
              "called and released after @b shutdown() call, check that FIN was "
              "sent eventually from IUT.");

    memset(&ctx, 0, sizeof(ctx));
    CHECK_RC(rcf_ta_trrecv_stop(pco_tst->ta, 0, csap,
                                tsa_packet_handler, &ctx, NULL));
    tsa_print_packet_stats(&ctx);

    if ((events & RPC_EPOLLOUT) && !event_before && !close_peer)
    {
        if (ctx.fin_ack <= 0 && ctx.push_fin_ack <= 0)
        {
            ERROR_VERDICT("FIN was not received on Tester after "
                          "freeing overfilled send buffer on IUT");
            failed = TRUE;
        }
    }

    if (!close_peer)
    {
        RPC_AWAIT_ERROR(pco_tst);
        rc = rpc_recv(pco_tst, tst_s, recv_data, PKT_LEN,
                      RPC_MSG_DONTWAIT);
        if (rc != 0)
        {
            ERROR_VERDICT("recv() does not return 0 "
                          "after shutdown(WR) on peer");
            failed = TRUE;
        }
    }

    TEST_STEP("If @p evts contain @c EPOLLIN event and peer socket "
              "was not closed before, send a packet from Tester and "
              "check that @b epoll_wait() returns @c EPOLLIN after that.");

    if ((events & RPC_EPOLLIN) && !close_peer)
    {
        RPC_SEND(rc, pco_tst, tst_s, send_data, PKT_LEN, 0);

        exp_events = RPC_EPOLLIN;
        if (events & RPC_EPOLLOUT)
        {
            exp_events = exp_events | RPC_EPOLLOUT;
            TAPI_WAIT_NETWORK;
        }

        RPC_AWAIT_ERROR(pco_iut);
        rc = rpc_epoll_wait(pco_iut, epfd, &event, 1, EPOLL_TIMEOUT);
        epoll_check_single_event(pco_iut, IC_EPOLL, rc, &event,
                                 1, RPC_EOK, iut_s, exp_events,
                                 "The second call");

        rc = rpc_recv(pco_iut, iut_s, recv_data, PKT_LEN, 0);
        SOCKTS_CHECK_RECV(pco_iut, recv_data, send_data, PKT_LEN, rc);
    }

    if (failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    if (csap != CSAP_INVALID_HANDLE)
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0, csap));

    CLEANUP_RPC_CLOSE(pco_iut, epfd);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    CLEANUP_RPC_FREE(pco_tst, rpcbuf);

    TEST_END;
}
