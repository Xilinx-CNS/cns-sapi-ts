/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-state_trans_udp State transitions for datagram socket
 *
 * @objective Check legal socket state transitions for datagram socket
 *
 * @type Conformance, compatibility
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 *
 * @par Scenario:
 *
 * -# Create socket @p iut_s on @p pco_iut of the @c SOCK_DGRAM type.
 * -# @b bind() @p iut_s to @p iut_addr.
 * -# Perform routine #sockts_get_socket_state for @p iut_s.
 * -# Check that obtained state of @p iut_s is the @c STATE_BOUND.
 * -# Call @b connect() to connect @p iut_s to @p tst_addr.
 * -# Perform routine #sockts_get_socket_state for @p iut_s.
 * -# Check that obtained state of @p iut_s is the @c STATE_CONNECTED.
 * -# Close all sockets.
 * -# Perform routine #sockts_get_socket_state for @p iut_s.
 * -# Check that obtained state of @p iut_s is the @c STATE_CLOSED.
 *
 * @author Konstantin Abramenko <Konstantin.Abramenko@oktetlabs.ru>
 * @author Igor.Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/state_trans_udp"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server             *pco_iut;
    rcf_rpc_server             *pco_tst;

    const struct sockaddr      *iut_addr;
    const struct sockaddr      *tst_addr;
    struct sockaddr_storage     wildcard_addr;

    int                         iut_s = -1;
    int                         tst_s = -1;


    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);

    CHECK_SOCKET_STATE(pco_iut, iut_s, NULL, -1, STATE_CLEAR);

    assert(sizeof(wildcard_addr) >= te_sockaddr_get_size(iut_addr));
    memcpy(&wildcard_addr, iut_addr, te_sockaddr_get_size(iut_addr));
    te_sockaddr_set_wildcard(SA(&wildcard_addr));
    rpc_bind(pco_iut, iut_s, SA(&wildcard_addr));

    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    rpc_bind(pco_tst, tst_s, tst_addr);

    rpc_connect(pco_tst, tst_s, iut_addr);

    CHECK_SOCKET_STATE(pco_iut, iut_s, pco_tst, tst_s, STATE_BOUND);

    rpc_connect(pco_iut, iut_s, tst_addr);

    CHECK_SOCKET_STATE(pco_iut, iut_s, pco_tst, tst_s, STATE_CONNECTED); 

    rpc_closesocket(pco_iut, iut_s);
    iut_s = -1;

    CHECK_SOCKET_STATE(pco_iut, iut_s, NULL, -1, STATE_CLOSED);

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
