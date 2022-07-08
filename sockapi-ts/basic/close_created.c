/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-close_created Close just created socket
 *
 * @objective Check that just created socket can be successfully closed.
 *
 * @type Conformance, compatibility
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_iut_only
 * @param domain    Network address domain:
 *                      - PF_INET
 *                      - PF_INET6
 * @param sock_type Socket type:
 *                  - SOCK_STREAM
 *                  - SOCK_DGRAM
 *
 * @par Scenario:
 *
 * -# Create socket @p iut_s on @p pco_iut of the @p sock_type type.
 * -# Perform routine #sockts_get_socket_state on @p iut_s.
 * -# Check that obtained state of the @p iut_s is the @c STATE_CLEAR.
 * -# @b close() @p iut_s.
 * -# Perform routine #sockts_get_socket_state on @p iut_s.
 * -# Check that obtained state of @p iut_s is the @c STATE_CLOSED.
 *
 * @author Konstantin Abramenko <Konstantin.Abramenko@oktetlabs.ru>
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/close_created"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rpc_socket_type     sock_type;
    rcf_rpc_server     *pco_iut;

    int                 iut_s = -1;
    int                 closed_s;
    rpc_socket_domain   domain;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_DOMAIN(domain);

    iut_s = rpc_socket(pco_iut, domain, sock_type, RPC_PROTO_DEF);

    CHECK_SOCKET_STATE(pco_iut, iut_s, NULL, -1, STATE_CLEAR);

    closed_s = iut_s;
    rpc_closesocket(pco_iut, iut_s);
    iut_s = -1;

    CHECK_SOCKET_STATE(pco_iut, closed_s, NULL, -1, STATE_CLOSED);

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
