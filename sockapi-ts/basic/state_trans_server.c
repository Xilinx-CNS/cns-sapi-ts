/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-state_trans_server State transitions for TCP server socket type
 *
 * @objective Check legal socket state transitions for server-oriented socket
 *            and behaviour of system calls in attempts for inappropriate 
 *            usage.
 *
 * @type Conformance, compatibility
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 *
 * @par Scenario:
 *
 * -# Create the @c SOCK_STREAM socket @p srv_s on @p pco_iut.
 * -# @b bind() @p srv_s with zero address and port.
 * -# Call @b listen() for @p srv_s.
 * -# Perform #sockts_get_socket_state routine for @p srv_s.
 * -# Check that obtained state of @p srv_s is the @c STATE_LISTENING.
 * -# Create socket @p clnt_s on @p pco_tst of the @c SOCK_STREAM type.
 * -# @b connect() @p clnt_s to the @p srv_s.
 * -# Call @b accept() on @p srv_s to get @p acc_s socket.
 * -# Perform #sockts_get_socket_state routine for @p acc_s.
 * -# Check that obtained state of @p acc_s is the @c STATE_CONNECTED.
 * -# Close all sockets.
 * -# Perform routine #sockts_get_socket_state for @p srv_s.
 * -# Check that obtained state of @p srv_s is the @c STATE_CLOSED.
 * -# Perform #sockts_get_socket_state routine for @p acc_s.
 * -# Check that obtained state of @p acc_s is the @c STATE_CONNECTED.
 * -# Perform routine #sockts_get_socket_state for @p acc_s.
 * -# Check that obtained state of @p acc_s is the @c STATE_CLOSED.
 *
 * @author Konstantin Abramenko <Konstantin.Abramenko@oktetlabs.ru>
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/state_trans_server"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server             *pco_iut;
    rcf_rpc_server             *pco_tst;

    const struct sockaddr      *iut_addr;
    const struct sockaddr      *tst_addr;

    int                         srv_s = -1;
    int                         clnt_s = -1;
    int                         acc_s = -1;
    int                         closed_s;

    struct sockaddr_storage     wild_addr;
    struct sockaddr_storage     listen_addr;
    socklen_t                   listen_addrlen;


    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    memset(&wild_addr, 0, sizeof(wild_addr));
    SA(&wild_addr)->sa_family = iut_addr->sa_family;

    srv_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM, RPC_IPPROTO_TCP);

    rpc_bind(pco_iut, srv_s, SA(&wild_addr));

    listen_addrlen = sizeof(listen_addr);
    rpc_getsockname(pco_iut, srv_s, SA(&listen_addr), &listen_addrlen);
    CHECK_RC(te_sockaddr_set_netaddr(SA(&listen_addr),
                                     te_sockaddr_get_netaddr(iut_addr)));

    rpc_listen(pco_iut, srv_s, SOCKTS_BACKLOG_DEF);

    CHECK_SOCKET_STATE(pco_iut, srv_s, NULL, -1, STATE_LISTENING);

    clnt_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(iut_addr),
                        RPC_SOCK_STREAM, RPC_IPPROTO_TCP);

    rpc_connect(pco_tst, clnt_s, SA(&listen_addr));

    acc_s = rpc_accept(pco_iut, srv_s, NULL, NULL);

    CHECK_SOCKET_STATE(pco_iut, acc_s, pco_tst, clnt_s, STATE_CONNECTED);

    closed_s = srv_s;
    rpc_closesocket(pco_iut, srv_s);
    srv_s = -1;

    CHECK_SOCKET_STATE(pco_iut, closed_s, NULL, -1, STATE_CLOSED);

    CHECK_SOCKET_STATE(pco_iut, acc_s, pco_tst, clnt_s, STATE_CONNECTED);

    closed_s = acc_s;
    rpc_closesocket(pco_iut, acc_s);
    acc_s = -1;

    CHECK_SOCKET_STATE(pco_iut, closed_s, NULL, -1, STATE_CLOSED);


    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_tst, clnt_s);
    CLEANUP_RPC_CLOSE(pco_iut, srv_s);
    CLEANUP_RPC_CLOSE(pco_iut, acc_s);

    TEST_END;
}
