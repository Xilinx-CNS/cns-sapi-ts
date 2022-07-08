/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 *
 * $Id$
 */

/** @page tcp-syn_recv_fin_wait1 TCP_SYN_RECV -> TCP_FIN_WAIT1 transition
 *
 * @objective Check that when we close (or call @b shutdown(RD)) on
 *            a listening socket just received SYN it will send
 *            TCP FIN or RST to a peer.
 *
 * @type conformance
 *
 * @param pco_iut          PCO on IUT
 * @param pco_tst          PCO on TESTER
 * @param pco_gw           PCO on host in the tested network
 *                         that is able to forward incoming packets
 *                         (gateway)
 * @param iut_if           Network interface on @p pco_iut
 * @param tst_if           Network interface on @p pco_tst
 * @param iut_addr         Network address on @p pco_iut
 * @param tst_addr         Network address on @p pco_tst
 * @param gw_iut_addr      Gateway address on @p pco_iut
 * @param gw_tst_addr      Gateway address on @p pco_tst
 * @param alien_link_addr  Invalid ethernet address
 * @param use_shutdown     Whether to call @b shutdown(RD) or
 *                         @b close() on listening socket
 * @param so_reuseaddr     Set SO_REUSEADDR socket option
 *
 * @par Test sequence:
 * -# Configure routing to use gateway @p pco_gw.
 * -# Add incorrect arp entry on @p pco_iut to block traffic from
 *    @p pco_iut to @p pco_tst.
 * -# Create @p iut_s socket on @p pco_iut, @b bind() it to
 *    @p iut_addr address, make it listening.
 * -# Create @p tst_s socket on @p pco_tst, @b bind() it to
 *    @p tst_addr, make it nonblocking, call @b connect() on it.
 * -# Call function defined by @p use_shutdown on @p iut_s socket.
 * -# Delete incorrect arp entry to make data traffic from @p pco_iut
 *    to @p pco_tst possible.
 * -# Check that @b connect() call returns errno @c EALREADY, wait untill
 *    @p tst_s socket will move from @c TCP_SYN_SENT to some other
 *    TCP state.
 * -# Check whether messages with FIN or RST flags set was received on
 *    @p pco_tst.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "tcp/syn_recv_fin_wait1"

#include "sockapi-test.h"
#include "tapi_tcp.h"
#include "tapi_sockets.h"
#include "tapi_route_gw.h"

static te_bool rst_got = FALSE;
static te_bool fin_got = FALSE;

static void
user_pkt_handler(const tcp_message_t *pkt, void *userdata)
{
    UNUSED(userdata);

    if (pkt->flags & TCP_RST_FLAG)
        rst_got = TRUE;

    if (pkt->flags & TCP_FIN_FLAG)
        fin_got = TRUE;
}

int
main(int argc, char *argv[])
{
    tapi_route_gateway gw;
    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;

    int             sid;
    csap_handle_t   csap = CSAP_INVALID_HANDLE;

    int             iut_s = -1;
    int             tst_s = -1;

    rpc_socket_addr_family family;

    te_bool     use_shutdown = FALSE;
    te_bool     so_reuseaddr = FALSE;
    te_bool     iut_tst_broken = FALSE;

    rpc_tcp_state   tcp_state;
    unsigned int    recv_num = 0;
    int             fdflags;
    int             change_tcp_state_attempts = 0;

    /* Preambule */
    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;
    TEST_GET_BOOL_PARAM(use_shutdown);

    if (rcf_ta_create_session(pco_tst->ta, &sid) != 0)
        TEST_FAIL("rcf_ta_create_session failed");

    family = sockts_domain2family(rpc_socket_domain_by_addr(iut_addr));

    /* Configure CSAP */
    CHECK_RC(tapi_tcp_ip_eth_csap_create(
        pco_tst->ta, sid, tst_if->if_name,
        TAD_ETH_RECV_DEF | TAD_ETH_RECV_NO_PROMISC,
        NULL, NULL, tst_addr->sa_family,
        TAD_SA2ARGS(tst_addr, iut_addr), &csap));

    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, sid, csap, NULL,
                                   TAD_TIMEOUT_INF, 100,
                                   RCF_TRRECV_PACKETS));

    /* Configure gateway */
    TAPI_INIT_ROUTE_GATEWAY(gw);
    tapi_route_gateway_configure(&gw);

    /* Break connection from iut to gateway */
    tapi_route_gateway_break_iut_gw(&gw);
    iut_tst_broken = TRUE;

    CFG_WAIT_CHANGES;

    iut_s = rpc_socket(pco_iut, family, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_iut, iut_s, iut_addr);
    rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);

    if (so_reuseaddr)
        rpc_setsockopt_int(pco_iut, iut_s, RPC_SO_REUSEADDR, 1);

    tst_s = rpc_socket(pco_tst, family, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr);
    fdflags = rpc_fcntl(pco_tst, tst_s, RPC_F_GETFL, RPC_O_NONBLOCK);
    fdflags |= RPC_O_NONBLOCK;
    fdflags = rpc_fcntl(pco_tst, tst_s, RPC_F_SETFL, fdflags);

    RPC_AWAIT_IUT_ERROR(pco_tst);
    rc = rpc_connect(pco_tst, tst_s, iut_addr);

    if (rc >= 0)
        TEST_VERDICT("connect() call unexpectedly successeed after "
                     "incorrect arp entry was added");
    else if (RPC_ERRNO(pco_tst) != RPC_EINPROGRESS)
        TEST_VERDICT("nonblocking connect() call returned unexpected "
                     "errno %s", errno_rpc2str(RPC_ERRNO(pco_tst)));

    TAPI_WAIT_NETWORK;
    if (use_shutdown)
        rpc_shutdown(pco_iut, iut_s, RPC_SHUT_RD);
    else
        rpc_close(pco_iut, iut_s);

    TAPI_WAIT_NETWORK;

    CHECK_RC(tapi_route_gateway_repair_iut_gw(&gw));
    iut_tst_broken = FALSE;

    CFG_WAIT_CHANGES;

    RPC_AWAIT_IUT_ERROR(pco_tst);
    rc = rpc_connect(pco_tst, tst_s, iut_addr);
    while (rc == -1 && RPC_ERRNO(pco_tst) == RPC_EALREADY)
    {
        TAPI_WAIT_NETWORK;
        RPC_AWAIT_IUT_ERROR(pco_tst);
        rc = rpc_connect(pco_tst, tst_s, iut_addr);
    } 

    if (rc == -1)
        RING_VERDICT("connect() call returned errno %s",
                     errno_rpc2str(RPC_ERRNO(pco_tst)));
    else
        RING_VERDICT("connect() call successed");

    tcp_state = tapi_get_tcp_sock_state(pco_tst, tst_s);
    while (tcp_state == RPC_TCP_SYN_SENT)
    {
        TAPI_WAIT_NETWORK;
        tcp_state = tapi_get_tcp_sock_state(pco_tst, tst_s);
        if (++change_tcp_state_attempts > 20)
            TEST_VERDICT("Socket is not moved from TCP_SYN_SENT");
    }

    RING("TCP state of tst_s socket is %s", tcp_state_rpc2str(tcp_state));

    CHECK_RC(tapi_tad_trrecv_get(pco_tst->ta, sid, csap,
                                 tapi_tcp_ip_eth_trrecv_cb_data(
                                        user_pkt_handler, NULL),
                                 &recv_num));
    if (fin_got)
        RING_VERDICT("Message with FIN flag set was received");
    if (rst_got)
        RING_VERDICT("Message with RST flag set was received");

    TEST_SUCCESS;

cleanup:
    if (pco_tst != NULL && csap != CSAP_INVALID_HANDLE &&
        rcf_ta_trrecv_stop(pco_tst->ta, sid, csap, NULL, NULL,
                           &recv_num))
    {
        TEST_FAIL("Failed to stop receiving packets");
    }

    if (pco_tst != NULL && csap != CSAP_INVALID_HANDLE &&
        tapi_tad_csap_destroy(pco_tst->ta, sid, csap))
    {
        ERROR("Failed to destroy CSAP");
    }

    if (use_shutdown)
        CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    if (iut_tst_broken)
        tapi_route_gateway_repair_iut_gw(&gw);

    TEST_END;
}
