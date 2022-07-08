/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-exec_listening Exec robustness for listening sockets
 *
 * @objective Check that TCP listening server socket is inherited
 *            during @b execve() call and connection establishing
 *            operations work correctly.
 *
 * @type Conformance, compatibility
 *
 * @reference @ref STEVENS Section 4.7
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 *
 * @par Scenario:
 *
 * -# Create socket stream @p iut_s of @c SOCK_STREAM type on @p pco_iut.
 * -# @b bind() @p iut_s to @p pco_iut socket address.  
 * -# Call @b listen() for @p iut_s.
 * -# Change image of process @p pco_iut by @b execve() call.
 * -# Perform #sockts_get_socket_state routine for @p pco_iut, @p iut_s.
 * -# Check that obtained state of @p iut_s is @c STATE_LISTENING.
 * -# Create socket @p tst_s of @c SOCK_STREAM type on @p pco_tst.
 * -# @b connect() socket @p tst_s to @p iut_s. 
 * -# Check that @p iut_s is readable on @p pco_iut.
 * -# Change image of process @p pco_iut by @b execve() call.
 * -# Check that @p iut_s is readable on @p pco_iut.
 * -# Call @b accept() on @p iut_s to get @p acc_s socket.  
 * -# Perform #sockts_get_socket_state routine for @p pco_iut, @p iut_s.
 * -# Check that obtained state of @p iut_s is @c STATE_LISTENING.
 * -# Close all sockets.
 *
 * @author Konstantin Abramenko <Konstantin.Abramenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/exec_listening"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    void                   *tx_buf = NULL;
    size_t                  buf_len;

    rcf_rpc_server         *pco_iut;
    rcf_rpc_server         *pco_tst;
    int                     iut_s = -1;
    int                     tst_s = -1;
    int                     acc_s = -1;

    const struct sockaddr  *iut_addr;

    struct sockaddr_storage acc_addr;
    socklen_t               acc_addrlen; 

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);

    CHECK_NOT_NULL((tx_buf = sockts_make_buf_dgram(&buf_len)));

    iut_s = rpc_stream_server(pco_iut, RPC_PROTO_DEF, TRUE, iut_addr);

    CHECK_RC(rcf_rpc_server_exec(pco_iut));
    CHECK_SOCKET_STATE(pco_iut, iut_s, NULL, -1, STATE_LISTENING);

    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(iut_addr), 
                       RPC_SOCK_STREAM, RPC_PROTO_DEF); 

    rpc_connect(pco_tst, tst_s, iut_addr);
    TAPI_WAIT_NETWORK;

    RPC_CHECK_READABILITY(pco_iut, iut_s, TRUE); 

    CHECK_RC(rcf_rpc_server_exec(pco_iut));
    RPC_CHECK_READABILITY(pco_iut, iut_s, TRUE); 

    acc_addrlen = sizeof(acc_addr);
    acc_s = rpc_accept(pco_iut, iut_s, SA(&acc_addr), &acc_addrlen); 

    RPC_CHECK_READABILITY(pco_iut, iut_s, FALSE); 

    CHECK_SOCKET_STATE(pco_iut, iut_s, NULL, -1, STATE_LISTENING);

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s); 
    CLEANUP_RPC_CLOSE(pco_iut, acc_s); 
    CLEANUP_RPC_CLOSE(pco_tst, tst_s); 

    TEST_END;
}
