/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-state_trans_client State transitions for TCP client socket type
 *
 * @objective Check legal socket state transitions for TCP client stream socket
 *
 * @type Conformance, compatibility
 *
 * @param env       Testing environment:
 *                  - Private environment similar to
 *                    @ref arg_types_env_peer2peer but wildcard address is
 *                    issued on IUT
 *                  - Private environment similar to
 *                    @ref arg_types_env_peer2peer_ipv6 but wildcard address is
 *                    issued on IUT
 *                  - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 *
 * @par Scenario:
 *
 * -# Create socket @p iut_s on @p pco_iut of the @c SOCK_STREAM type.
 * -# Perform routine #sockts_get_socket_state for @p iut_s.
 * -# Check that obtained state of @p iut_s is the @c STATE_CLEAR.
 * -# @b bind() @p iut_s to the wildcard IP address and zero port.
 * -# Perform routine #sockts_get_socket_state for @p iut_s.
 * -# Check that obtained state of @p iut_s is the @c STATE_BOUND.
 * -# Create socket @p srv_s on @p pco_tst of the @c SOCK_STREAM type.
 * -# Call @b listen() for @p srv_s.
 * -# Call @b connect() to connect @p iut_s to the @p srv_s.
 * -# Call @b accept() on @p srv_s to return @p acc_s socket.
 * -# Perform routine #sockts_get_socket_state for @p iut_s.
 * -# Check that obtained state of @p iut_s is the @c STATE_CONNECTED.
 * -# Close all sockets.
 * -# Perform routine #sockts_get_socket_state for @p iut_s.
 * -# Check that obtained state of @p iut_s is the @c STATE_CLOSED.
 *
 * @author Konstantin Abramenko <Konstantin.Abramenko@oktetlabs.ru>
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/state_trans_client"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut;
    rcf_rpc_server         *pco_tst;

    const struct sockaddr  *tst_addr;

    int                     iut_s = -1;
    int                     srv_s = -1;
    int                     acc_s = -1;

    struct sockaddr_storage wild_addr;


    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_tst, tst_addr);

    memset(&wild_addr, 0, sizeof(wild_addr));
    SA(&wild_addr)->sa_family = tst_addr->sa_family;

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_STREAM, RPC_IPPROTO_TCP);

    CHECK_SOCKET_STATE(pco_iut, iut_s, NULL, -1, STATE_CLEAR);

    rpc_bind(pco_iut, iut_s, SA(&wild_addr));

    CHECK_SOCKET_STATE(pco_iut, iut_s, NULL, -1, STATE_BOUND);

    srv_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_STREAM, RPC_IPPROTO_TCP);

    rpc_bind(pco_tst, srv_s, tst_addr);

    rpc_listen(pco_tst, srv_s, SOCKTS_BACKLOG_DEF);

    rpc_connect(pco_iut, iut_s, tst_addr);

    acc_s = rpc_accept(pco_tst, srv_s, NULL, NULL);

    CHECK_SOCKET_STATE(pco_iut, iut_s, pco_tst, acc_s, STATE_CONNECTED);

    TEST_SUCCESS;

cleanup:

    if (iut_s != -1)
    {
        rpc_closesocket(pco_iut, iut_s);
        CHECK_SOCKET_STATE(pco_iut, iut_s, NULL, -1, STATE_CLOSED);
    }

    CLEANUP_RPC_CLOSE(pco_tst, srv_s);
    CLEANUP_RPC_CLOSE(pco_tst, acc_s);

    TEST_END;
}
