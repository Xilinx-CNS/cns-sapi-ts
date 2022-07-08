/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Tests
 * Routing table
 */

/**
 * @page route-retransmit_change_route Change route to peer during retransmission
 *
 * @objective Check what happens if, while IUT is trying to retransmit
 *            an unaknowledged packet, route to the peer is changed to go
 *            over a different interface.
 *
 * @note This test is intended to reproduce assertion from SF bug 88812.
 *
 * @param env               Testing environment:
 *                          - @ref arg_types_env_triangle_iut_tst
 *                          - @ref arg_types_env_triangle_iut_tst_ipv6
 * @param sock_type         Socket type:
 *                          - @c tcp_active
 *                          - @c tcp_passive
 * @param data_retransmit   If @c TRUE, check data packet retransmission;
 *                          otherwise check @c SYN (if @p sock_type is
 *                          @c tcp_active) or @c SYN-ACK (if @p sock_type is
 *                          @c tcp_passive) retransmission.
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "route/retransmit_change_route"

#include "sockapi-test.h"

#include "ts_route.h"
#include "tapi_route_gw.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_gw = NULL;
    rcf_rpc_server        *pco_tst = NULL;

    const struct if_nameindex *iut1_if = NULL;
    const struct if_nameindex *iut2_if = NULL;
    const struct if_nameindex *tst2_if = NULL;
    const struct if_nameindex *gwb_if = NULL;

    const struct sockaddr *iut1_addr = NULL;
    const struct sockaddr *iut2_addr = NULL;
    const struct sockaddr *tst1_addr = NULL;
    const struct sockaddr *tst2_addr = NULL;
    const struct sockaddr *gwa_addr = NULL;
    const struct sockaddr *gwb_addr = NULL;
    const struct sockaddr *alien_link_addr = NULL;

    sockts_socket_type     sock_type;
    te_bool                data_retransmit;

    int                    af;
    int                    iut_l = -1;
    int                    iut_s = -1;
    int                    tst_s = -1;
    te_bool                readable = FALSE;
    char                   sndbuf[SOCKTS_MSG_STREAM_MAX];
    size_t                 sndlen;
    char                   rcvbuf[SOCKTS_MSG_STREAM_MAX];

    rcf_rpc_server        *pco_srv = NULL;
    rcf_rpc_server        *pco_clnt = NULL;
    int                   *srv_s = NULL;
    int                   *clnt_s = NULL;
    int                    srv_s_aux = -1;
    const struct sockaddr *srv_addr = NULL;

    cfg_handle             iut_rt = CFG_HANDLE_INVALID;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_gw);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut1_if);
    TEST_GET_IF(iut2_if);
    TEST_GET_IF(tst2_if);
    TEST_GET_IF(gwb_if);
    TEST_GET_ADDR(pco_iut, iut1_addr);
    TEST_GET_ADDR(pco_iut, iut2_addr);
    TEST_GET_ADDR(pco_tst, tst1_addr);
    TEST_GET_ADDR(pco_tst, tst2_addr);
    TEST_GET_ADDR_NO_PORT(gwa_addr);
    TEST_GET_ADDR_NO_PORT(gwb_addr);
    TEST_GET_LINK_ADDR(alien_link_addr);
    SOCKTS_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(data_retransmit);

    if (data_retransmit || sock_type == SOCKTS_SOCK_TCP_ACTIVE)
    {
        pco_clnt = pco_iut;
        pco_srv = pco_tst;
        clnt_s = &iut_s;
        srv_s = &tst_s;
        srv_addr = tst1_addr;
    }
    else
    {
        pco_clnt = pco_tst;
        pco_srv = pco_iut;
        clnt_s = &tst_s;
        srv_s = &iut_s;
        srv_addr = iut1_addr;
    }

    af = iut1_addr->sa_family;

    TEST_STEP("Enable forwarding on gateway host.");
    if (af == AF_INET)
        CHECK_RC(tapi_cfg_base_ipv4_fw(pco_gw->ta, TRUE));
    else
        CHECK_RC(tapi_cfg_base_ipv6_fw(pco_gw->ta, TRUE));

    TEST_STEP("If IPv4 is checked, set @c rp_filter to @c 2 on @p iut1_if "
              "and @p tst2_if interfaces; otherwise incoming packets may "
              "be dropped when they come from an interface which differs "
              "from outgoing interface to the same destination.");
    if (af == AF_INET)
    {
        CHECK_RC(tapi_cfg_sys_set_int(pco_iut->ta, 2, NULL,
                                      "net/ipv4/conf:%s/rp_filter",
                                      iut1_if->if_name));
        CHECK_RC(tapi_cfg_sys_set_int(pco_tst->ta, 2, NULL,
                                      "net/ipv4/conf:%s/rp_filter",
                                      tst2_if->if_name));
    }

    TEST_STEP("On IUT configure a route to @p tst1_addr over @p iut1_if "
              "via gateway @p gwa_addr.");
    CHECK_RC(tapi_cfg_add_route(pco_iut->ta, af,
                                te_sockaddr_get_netaddr(tst1_addr),
                                te_netaddr_get_bitsize(af),
                                te_sockaddr_get_netaddr(gwa_addr),
                                iut1_if->if_name, NULL, 0, 0, 0,
                                0, 0, 0, &iut_rt));

    TEST_STEP("On Tester configure a route to @p iut1_addr via gateway "
              "@p gwb_addr, so that packets will be received via "
              "@p iut1_if on IUT.");
    CHECK_RC(tapi_cfg_add_route_via_gw(
                pco_tst->ta, af, te_sockaddr_get_netaddr(iut1_addr),
                te_netaddr_get_bitsize(af),
                te_sockaddr_get_netaddr(gwb_addr)));

    if (data_retransmit)
    {
        TEST_STEP("If @p data_retransmit is @c TRUE, establish TCP "
                  "connection according to @p sock_type, binding IUT "
                  "socket to @b iut1_addr and Tester socket to "
                  "@b tst1_addr.");
        CFG_WAIT_CHANGES;
        SOCKTS_CONNECTION(pco_iut, pco_tst, iut1_addr, tst1_addr,
                          sock_type, &iut_s, &tst_s, &iut_l);
    }
    else
    {
        TEST_STEP("If @p data_retransmit is @c FALSE, create "
                  "TCP sockets on IUT and Tester, binding IUT socket to "
                  "@p iut1_addr and Tester socket to @p tst1_addr.");

        iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut1_addr),
                           RPC_SOCK_STREAM, RPC_PROTO_DEF);
        rpc_bind(pco_iut, iut_s, iut1_addr);

        tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst1_addr),
                           RPC_SOCK_STREAM, RPC_PROTO_DEF);
        rpc_bind(pco_tst, tst_s, tst1_addr);
    }

    TEST_STEP("On @p pco_gw add an incorrect neighbor entry for "
              "@p tst1_addr on @p gwb_if, so that packets sent from "
              "IUT over @p iut1_if via the gateway will not reach "
              "Tester.");
    CHECK_RC(tapi_update_arp(pco_gw->ta, gwb_if->if_name, NULL, NULL,
                             tst1_addr, alien_link_addr->sa_data, TRUE));

    CFG_WAIT_CHANGES;

    if (data_retransmit)
    {
        TEST_STEP("If @p data_retransmit is @c TRUE, send some data from "
                  "the IUT socket. It should not reach Tester, so that IUT "
                  "is expected to start retransmitting it.");

        sndlen = rand_range(1, sizeof(sndbuf));
        te_fill_buf(sndbuf, sndlen);

        RPC_AWAIT_ERROR(pco_iut);
        rc = rpc_send(pco_iut, iut_s, sndbuf, sndlen, 0);
        if (rc < 0)
        {
            TEST_VERDICT("After breaking connectivity to Tester, "
                         "send() on IUT failed with errno %r",
                         RPC_ERRNO(pco_iut));
        }
        else if (rc != (int)sndlen)
        {
            TEST_VERDICT("After breaking connectivity to Tester, "
                         "send() on IUT returned unexpected value");
        }
    }
    else
    {
        TEST_STEP("If @p data_retransmit is @c FALSE, make one "
                  "of the sockets listener according to @p sock_type, "
                  "and call nonblocking @b connect() from the peer, "
                  "checking that it reports errno @c EINPROGRESS.");

        rpc_listen(pco_srv, *srv_s, SOCKTS_BACKLOG_DEF);

        rpc_fcntl(pco_clnt, *clnt_s, RPC_F_SETFL, RPC_O_NONBLOCK);
        RPC_AWAIT_ERROR(pco_clnt);
        rc = rpc_connect(pco_clnt, *clnt_s, srv_addr);
        if (rc >= 0)
        {
            TEST_VERDICT("Nonblocking connect() succeeded unexpectedly");
        }
        else if (RPC_ERRNO(pco_clnt) != RPC_EINPROGRESS)
        {
            TEST_VERDICT("Nonblocking connect() failed with "
                         "unexpected errno %r", RPC_ERRNO(pco_clnt));
        }
    }

    TEST_STEP("Wait for a while to ensure that IUT started retransmitting "
              "@c SYN, @c SYN-ACK or data packet, since @c ACK does not "
              "arrive from Tester. Check that the socket which is "
              "expected to receive data or accept connection request does "
              "not become readable.");
    RPC_GET_READABILITY(readable, pco_srv, *srv_s, TAPI_WAIT_NETWORK_DELAY);
    if (readable)
        TEST_VERDICT("Peer became readable before changing route");

    TEST_STEP("Modify the route to @p tst1_addr on IUT to go via "
              "gateway @p tst2_addr over @p iut2_if.");
    CHECK_RC(tapi_cfg_modify_route(pco_iut->ta, af,
                                   te_sockaddr_get_netaddr(tst1_addr),
                                   te_netaddr_get_bitsize(af),
                                   te_sockaddr_get_netaddr(tst2_addr),
                                   iut2_if->if_name, NULL, 0, 0, 0,
                                   0, 0, 0, &iut_rt));

    CFG_WAIT_CHANGES;

    TEST_STEP("Check that now the socket which should receive data "
              "or accept connection request is readable.");

    RPC_GET_READABILITY(readable, pco_srv, *srv_s, TAPI_WAIT_NETWORK_DELAY);
    if (!readable)
        TEST_VERDICT("Peer did not become readable after changing route");

    if (data_retransmit)
    {
        TEST_STEP("If @p data_retransmit is @c TRUE, receive and check "
                  "data on Tester.");
        rc = rpc_recv(pco_tst, tst_s, rcvbuf, sizeof(rcvbuf), 0);
        if (rc < 0)
        {
            TEST_VERDICT("After changing route recv() on Tester failed "
                         "with %r", RPC_ERRNO(pco_tst));
        }
        else if (rc != (int)sndlen || memcmp(sndbuf, rcvbuf, sndlen) != 0)
        {
            TEST_VERDICT("After changing route recv() on Tester returned "
                         "unexpected data");
        }
    }
    else
    {
        TEST_STEP("If @p data_retransmit is @c FALSE, call "
                  "@b accept() on listener socket.");
        srv_s_aux = *srv_s;
        *srv_s = rpc_accept(pco_srv, *srv_s, NULL, NULL);
        rpc_fcntl(pco_clnt, *clnt_s, RPC_F_SETFL, 0);
    }

    TEST_STEP("Check that data can be transmitted in both "
              "directions over the established connection.");
    sockts_test_connection(pco_clnt, *clnt_s, pco_srv, *srv_s);

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_l);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_srv, srv_s_aux);

    TEST_END;
}
