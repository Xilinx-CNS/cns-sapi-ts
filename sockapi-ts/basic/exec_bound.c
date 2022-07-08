/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-exec_bound Exec robustness for bound socket
 *
 * @objective Check that bound socket is inherited during
 *            @b exec() call and has the same state.
 * 
 * @type Conformance, compatibility
 *
 * @reference @ref STEVENS Section 4.7
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_iut_ucast
 *              - @ref arg_types_env_iut_ucast_ipv6
 * @param sock_type Socket type:
 *                  - SOCK_STREAM
 *                  - SOCK_DGRAM
 *
 * @par Scenario:
 *
 * -# Create socket @p sock on @p pco_iut of @p sock_type type. 
 * -# @b bind() it @p pco_iut local address.
 * -# Change image of process @p pco_iut by @b execve() call.
 * -# Perform #sockts_get_socket_state routine for @p sock on @p pco_iut.
 * -# Check that obtained state of @p sock is @c STATE_BOUND. 
 * -# @b close() @p sock on @b pco_iut.
 *
 * @author Konstantin Abramenko <Konstantin.Abramenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/exec_bound"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut;
    int                     sock  = -1;

    const struct sockaddr  *iut_addr;

    rpc_socket_type         sock_type; 

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_SOCK_TYPE(sock_type);

    sock = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                      sock_type, RPC_PROTO_DEF); 

    rpc_bind(pco_iut, sock, iut_addr);

    CHECK_SOCKET_STATE(pco_iut, sock, NULL, -1, STATE_BOUND); 

    CHECK_RC(rcf_rpc_server_exec(pco_iut));

    CHECK_SOCKET_STATE(pco_iut, sock, NULL, -1, STATE_BOUND); 

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, sock); 

    TEST_END;
}


