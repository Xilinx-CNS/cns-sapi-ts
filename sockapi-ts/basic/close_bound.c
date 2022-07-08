/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-close_bound Close bound socket
 *
 * @objective Check that bound socket can be successfully closed.
 *
 * @type Conformance, compatibility
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_iut_ucast
 *                  - @ref arg_types_env_iut_wild
 *                  - @ref arg_types_env_iut_ucast_ipv6
 *                  - @ref arg_types_env_iut_wild_ipv6
 * @param sock_type Socket type:
 *                  - SOCK_STREAM
 *                  - SOCK_DGRAM
 * @param port_wildcard Boolean flag, meaining whether binding port should be
 *                      wildcard or user-specified.
 *
 * @par Scenario:
 *
 * -# Create sockets @p iut_s on @p pco_iut of the @p sock_type.
 * -# Perform routine #sockts_get_socket_state on @p iut_s.
 * -# Check that obtained state of @p iut_s is the @c STATE_CLEAR.
 * -# @b bind() @p iut_s @p iut_addr, depending on @p port_wildcard.
 * -# Perform routine #sockts_get_socket_state on @p iut_s.
 * -# Check that obtained state of @p iut_s is the @c STATE_BOUND.
 * -# @b close() @p iut_s.
 * -# Perform routine #sockts_get_socket_state on @p iut_s.
 * -# Check that obtained state of @p iut_s is the @c STATE_CLOSED.
 *
 * @author Konstantin Abramenko <Konstantin.Abramenko@oktetlabs.ru>
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/close_bound"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rpc_socket_type             sock_type;
    te_bool                     port_wildcard;

    rcf_rpc_server             *pco_iut;

    const struct sockaddr      *iut_addr;

    struct sockaddr            *iut_addr_tmp;
    struct sockaddr_storage     iut_addr_stor;

    int                         iut_s = -1;
    int                         iut_s_aux = -1;
    int                         closed_s;


    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(port_wildcard);

    iut_addr_tmp = SA(&iut_addr_stor);
    memcpy(iut_addr_tmp, iut_addr, te_sockaddr_get_size(iut_addr));

    if (port_wildcard)
        te_sockaddr_clear_port(iut_addr_tmp);
    
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                       sock_type, RPC_PROTO_DEF);
    CHECK_SOCKET_STATE(pco_iut, iut_s, NULL, -1, STATE_CLEAR);

    rpc_bind(pco_iut, iut_s, iut_addr_tmp);

    CHECK_SOCKET_STATE(pco_iut, iut_s, NULL, -1, STATE_BOUND);

    closed_s = iut_s;
    rpc_closesocket(pco_iut, iut_s);
    iut_s = -1;

    CHECK_SOCKET_STATE(pco_iut, closed_s, NULL, -1, STATE_CLOSED);

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s_aux);

    TEST_END;
}
