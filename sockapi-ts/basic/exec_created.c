/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-exec_created Exec robustness for just created socket
 *
 * @objective Check that created socket is inherited during @b execve() call.
 *
 * @type Conformance, compatibility
 *
 * @reference @ref STEVENS Section 4.7
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_iut_only
 * @param sock_type Socket type:
 *                  - SOCK_STREAM
 *                  - SOCK_DGRAM
 * @param domain    Protocol domain to be used for socket creation:
 *                  - PF_INET
 *                  - PF_INET6
 *
 * @par Scenario:
 *
 * -# Create socket @p iut_s on @p pco_iut of desired type. 
 * -# Change image of process @p pco_iut by @b execve() call.
 * -# Perform #sockts_get_socket_state routine for @p iut_s on @p pco_iut.
 * -# Check that obtained state of @p iut_s is @c STATE_CLEAR. 
 * -# @b close() @p iut_s on @b pco_iut;
 *
 * @author Konstantin Abramenko <Konstantin.Abramenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/exec_created"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rpc_socket_type     sock_type; 
    rcf_rpc_server     *pco_iut;
    rpc_socket_domain   domain;
    int                 iut_s  = -1; 

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_DOMAIN(domain);

    iut_s = rpc_socket(pco_iut, domain, sock_type, RPC_PROTO_DEF); 

    CHECK_RC(rcf_rpc_server_exec(pco_iut));

    CHECK_SOCKET_STATE(pco_iut, iut_s, NULL, -1, STATE_CLEAR);

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s); 

    TEST_END;
}
