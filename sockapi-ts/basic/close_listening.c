/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-close_listening Close listening socket
 *
 * @objective Check that listening socket can be successfully closed.
 *
 * @type Conformance, compatibility
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_iut_wild
 *              - @ref arg_types_env_iut_wild_ipv6
 *
 * @par Scenario:
 *
 * -# Create sockets @p iut_s on @p pco_iut of the @c SOCK_STREAM type.
 * -# @b bind() @p iut_s with parameters: wildcard IP address and zero port.
 * -# Call @b listen() on @p iut_s.
 * -# Perform routine #sockts_get_socket_state on @p iut_s.
 * -# Check that obtained state of @p iut_s is the @c STATE_LISTENING.
 * -# @b close() @p iut_s.
 * -# Perform routine #sockts_get_socket_state on @p iut_s.
 * -# Check that obtained state of @p iut_s is the @c STATE_CLOSED.
 *
 * @author Konstantin Abramenko <Konstantin.Abramenko@oktetlabs.ru>
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/close_listening"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server             *pco_iut;

    const struct sockaddr      *iut_addr;

    int                         iut_s = -1;
    int                         closed_s;


    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);
    
    
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM, RPC_IPPROTO_TCP);

    /* FIXME */
    te_sockaddr_set_port(SA(iut_addr), 0);
    rpc_bind(pco_iut, iut_s, iut_addr);

    rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);

    CHECK_SOCKET_STATE(pco_iut, iut_s, NULL, -1, STATE_LISTENING);

    closed_s = iut_s;
    rpc_closesocket(pco_iut, iut_s);
    iut_s = -1;
    
    CHECK_SOCKET_STATE(pco_iut, closed_s, NULL, -1, STATE_CLOSED);


    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
