/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Tests
 * Test suite on reliability of the @b epoll functions.
 *
 * $Id$
 */

/**
 * @page epoll-tcp_ack_no_event No event for TCP ACKs.
 *
 * @objective Check that no events is reported for TCP ACK packets.
 *
 * @param ack_type    ACK packet type:
 *                    - ack (ACK packet in answer to sent data packet);
 *                    - keepalive (keepalive probe);
 *                    - zero_window (zero window probe).
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "epoll/tcp_ack_no_event"

#include "sockapi-test.h"
#include "tapi_route_gw.h"

/** Methods to get ACK from Tester. */
typedef enum {
    TAPI_ACK_TYPE_ACK = 0,      /**< Tester sends ACK in response
                                     to packet. */
    TAPI_ACK_TYPE_KEEPALIVE,    /**< Tester sends ACK as keepalive
                                     probe. */
    TAPI_ACK_TYPE_ZERO_WINDOW,  /**< Tester sends ACK as zero window
                                     probe. */
} tapi_ack_type;

/** List of ACK generation methods, to be used for test
 * parameter parsing. */
#define TAPI_ACK_TYPE \
    { "ack",          TAPI_ACK_TYPE_ACK }, \
    { "keepalive",    TAPI_ACK_TYPE_KEEPALIVE }, \
    { "zero_window",  TAPI_ACK_TYPE_ZERO_WINDOW }

/** Packet length to be used in test. */
#define PKT_LEN 1000

/** Default epoll timeout */
#define DEF_TIMEOUT 5000

/** Epoll timeout used for zero window probe testing. */
#define ZERO_WINDOW_TIMEOUT 60000

/** Number of keepalive probes before giving up. */
#define KEEPALIVE_PROBES 100

int
main(int argc, char *argv[])
{
    tapi_route_gateway          gw;

    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;

    char send_data[PKT_LEN];
    char recv_data[PKT_LEN];

    int tst_s = -1;
    int iut_s = -1;
    int epfd = -1;
    int epoll_rc = -1;

    unsigned int epoll_timeout = 0;

    struct rpc_epoll_event  event;

    csap_handle_t           csap = CSAP_INVALID_HANDLE;
    tsa_packets_counter     ctx;

    tapi_ack_type ack_type;

    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;
    TEST_GET_ENUM_PARAM(ack_type, TAPI_ACK_TYPE);

    TAPI_INIT_ROUTE_GATEWAY(gw);

    te_fill_buf(send_data, PKT_LEN);

    TEST_STEP("Create CSAP to check whether ACK was actually sent "
              "from Tester.");

    CHECK_RC(tapi_tcp_ip_eth_csap_create(pco_gw->ta, 0,
                                         gw_iut_if->if_name,
                                         TAD_ETH_RECV_ALL, NULL, NULL,
                                         iut_addr->sa_family,
                                         TAD_SA2ARGS(iut_addr, tst_addr),
                                         &csap));

    TEST_STEP("Configure gateway connecting Tester and IUT.");

    CHECK_RC(tapi_route_gateway_configure(&gw));
    CFG_WAIT_CHANGES;

    if (ack_type == TAPI_ACK_TYPE_KEEPALIVE)
    {
        TEST_STEP("If @p ack_type is @c keepalive "
                  "- tune keepalive timeout on the Tester.");
        CHECK_RC(tapi_cfg_sys_ns_set_int(pco_tst->ta, KEEPALIVE_PROBES, NULL,
                                         "net/ipv4/tcp_keepalive_probes"));
        CHECK_RC(tapi_cfg_sys_ns_set_int(pco_tst->ta, 1, NULL,
                                         "net/ipv4/tcp_keepalive_intvl"));
        CHECK_RC(tapi_cfg_sys_ns_set_int(pco_tst->ta, 1, NULL,
                                         "net/ipv4/tcp_keepalive_time"));
        rcf_rpc_server_restart(pco_tst);
    }

    TEST_STEP("Establish TCP connection.");
    GEN_CONNECTION(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   tst_addr, iut_addr, &tst_s, &iut_s);

    if (ack_type == TAPI_ACK_TYPE_ZERO_WINDOW)
    {
        TEST_STEP("If @p ack_type is @c zero_window "
                  "- overfill IUT RX buffer, to force the tester to "
                  "send zero window probe.");
        rpc_overfill_buffers(pco_tst, tst_s, NULL);
    }

    TEST_STEP("Create a epoll set and add the socket with @b EPOLLIN to it "
              "- use the edge-triggered mode.");
    epfd = rpc_epoll_create(pco_iut, 1);
    rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_ADD,
                         iut_s, RPC_EPOLLIN | RPC_EPOLLET);

    if (ack_type == TAPI_ACK_TYPE_ZERO_WINDOW)
    {
        TEST_STEP("If @p ack_type is @c zero_window, call @b epoll_wait() "
                  "to get rid of @c EPOLLIN event produced by overfilling RX buffer.");
        rc = rpc_epoll_wait(pco_iut, epfd, &event, 1, 0);
        if (rc != 1 || event.events != RPC_EPOLLIN)
            TEST_VERDICT("epoll_wait() did not return EPOLLIN after "
                         "overfilling RX buffer");

        rc = rpc_epoll_wait(pco_iut, epfd, &event, 1, 1);
        if (rc > 0)
        {
            rc = rpc_epoll_wait(pco_iut, epfd, &event, 1, 1);
            if( rc > 0 )
                TEST_VERDICT("epoll_wait() returns events the third time");
            RING_VERDICT("epoll_wait() returns events the second time "
                         "for overfilled RX buffer");
        }
    }

    if (ack_type == TAPI_ACK_TYPE_ACK)
    {
        TEST_STEP("If @p ack_type is @c ack "
                  "- break connection with the peer using a gateway; "
                  "- send a data packet from the socket.");
        CHECK_RC(tapi_route_gateway_break_tst_gw(&gw));
        CFG_WAIT_CHANGES;
        rpc_send(pco_iut, iut_s, send_data, PKT_LEN, 0);
    }

    if (ack_type == TAPI_ACK_TYPE_ZERO_WINDOW)
        epoll_timeout = ZERO_WINDOW_TIMEOUT;
    else
        epoll_timeout = DEF_TIMEOUT;

    if (pco_iut->timeout < 2 * epoll_timeout)
        pco_iut->timeout = 2 * epoll_timeout;

    TEST_STEP("Call @c epoll_wait() with a timeout which is enough to get "
              "the expected ACK.");
    pco_iut->op = RCF_RPC_CALL;
    rpc_epoll_wait(pco_iut, epfd, &event, 1, epoll_timeout);

    if (ack_type == TAPI_ACK_TYPE_KEEPALIVE)
    {
        TEST_STEP("If @p ack_type is @c keepalive, enable @c SO_KEEPALIVE for "
                  "Tester socket.");
        rpc_setsockopt_int(pco_tst, tst_s, RPC_SO_KEEPALIVE, 1);
    }

    CHECK_RC(tapi_tad_trrecv_start(pco_gw->ta, 0, csap, NULL,
                                   TAD_TIMEOUT_INF, 0, RCF_TRRECV_PACKETS));

    if (ack_type == TAPI_ACK_TYPE_ACK)
    {
        TEST_STEP("if @p ack_type is @c ack "
                  "- repair the connection.");
        CHECK_RC(tapi_route_gateway_repair_tst_gw(&gw));
        CFG_WAIT_CHANGES;
    }

    TEST_STEP("Check that ACK is received but no events is returned.");

    epoll_rc = rpc_epoll_wait(pco_iut, epfd, &event, 1, epoll_timeout);

    memset(&ctx, 0, sizeof(ctx));
    CHECK_RC(rcf_ta_trrecv_stop(pco_gw->ta, 0, csap,
                                tsa_packet_handler, &ctx, NULL));
    tsa_print_packet_stats(&ctx);

    if (epoll_rc > 0)
        TEST_VERDICT("epoll_wait() unexpectedly returns events '%s'",
                     epoll_event_rpc2str(event.events));

    if (ctx.ack == 0)
        TEST_VERDICT("ACK was not sent to IUT");

    if (ack_type == TAPI_ACK_TYPE_ACK)
    {
        TEST_STEP("Read and check data if it was sent before.");
        rc = rpc_recv(pco_tst, tst_s, recv_data, PKT_LEN, 0);
        if (rc != PKT_LEN ||
            memcmp(send_data, recv_data, PKT_LEN) != 0)
            TEST_VERDICT("Received data does not match sent data");
    }

    TEST_SUCCESS;

cleanup:

    tapi_tad_csap_destroy(pco_gw->ta, 0, csap);

    CLEANUP_RPC_CLOSE(pco_iut, epfd);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
