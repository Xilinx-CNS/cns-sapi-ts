/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-shutdown_peer Check behaviour after shutdown() on peer of connected TCP socket
 *
 * @objective Check behaviour of TCP connected socket when shutdown
 *            was performed on the other side of connection.
 *
 * @type Conformance, compatibility
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 *
 * @par Scenario:
 *
 * -# Create sockets @p srvr_s and @p clnt_s on @p pco_iut and @p pco_tst 
 *    respectively.
 * -# Call @b listen() for @p srvr_s.
 * -# @b connect() @p clnt_s to the @p srvr_s.
 * -# Call @b accept() on @p srvr_s for get @p acc_s socket.
 * -# Perform routine #sockts_get_socket_state for @p acc_s. 
 * -# Check that obtained state of @p acc_s is @c STATE_CONNECTED. 
 * -# @b shutdown() @p clnt_s for reading.
 * -# Perform routine #sockts_get_socket_state for @p acc_s. 
 * -# Check that obtained state of @p acc_s is @c STATE_CONNECTED. 
 * -# Call @b send() on @p acc_s with prepared buffer.
 * -# Check that @b send() returned length of passed buffer.
 * -# Call @b send() on @p clnt_s with prepared buffer.
 * -# Call @b recv() on @p acc_s. 
 * -# Check that @p acc_s received data sent from @p clnt_s.
 * -# @b shutdown() @p clnt_s for writing.
 * -# Perform routine #sockts_get_socket_state for @p acc_s. 
 * -# Check that obtained state of @p acc_s is @c STATE_SHUT_RD. 
 * -# Call @b recv() on @p acc_s.
 * -# Check that @b recv() call immediately returns zero.
 * -# Close all sockets 
 *
 * @author Konstantin Abramenko <Konstantin.Abramenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/shutdown_peer"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    void                   *tx_buf = NULL;
    void                   *rx_buf = NULL;
    size_t                  buf_len;

    rcf_rpc_server         *pco_iut;
    rcf_rpc_server         *pco_tst;
    int                     srvr_s = -1;
    int                     clnt_s = -1;
    int                     acc_s = -1;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;
    struct sockaddr_storage acc_addr;
    socklen_t               acc_addrlen;


    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    CHECK_NOT_NULL((tx_buf = sockts_make_buf_dgram(&buf_len)));
    rx_buf = te_make_buf_by_len(buf_len);

    srvr_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                        RPC_SOCK_STREAM, RPC_PROTO_DEF); 

    clnt_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr), 
                        RPC_SOCK_STREAM, RPC_PROTO_DEF); 

    rpc_bind(pco_iut, srvr_s, iut_addr);

    rpc_bind(pco_tst, clnt_s, tst_addr);

    rpc_listen(pco_iut, srvr_s, SOCKTS_BACKLOG_DEF);

    rpc_connect(pco_tst, clnt_s, iut_addr); 

    acc_addrlen = sizeof(acc_addr);
    acc_s = rpc_accept(pco_iut, srvr_s, SA(&acc_addr), &acc_addrlen);

    CHECK_SOCKET_STATE(pco_iut, acc_s, pco_tst, clnt_s, STATE_CONNECTED);

    rpc_shutdown(pco_tst, clnt_s, RPC_SHUT_RD);

    CHECK_SOCKET_STATE(pco_iut, acc_s, pco_tst, clnt_s, STATE_CONNECTED); 

    RPC_SEND(rc, pco_iut, acc_s, tx_buf, buf_len, 0);

    if ((unsigned)rc != buf_len)
    {
        TEST_FAIL("Send on acc_s after RD shutdown on peer returns"
                  "differ then expected");
    } 

    RPC_SEND(rc, pco_tst, clnt_s, tx_buf, buf_len, 0);

    rc = rpc_recv(pco_iut, acc_s, rx_buf, buf_len, 0); 

    if ((unsigned)rc != buf_len)
    { 
        TEST_FAIL("Recv on acc_s after RD shutdown on peer returns"
                  "differ then expected");
    }

    rpc_shutdown(pco_tst, clnt_s, RPC_SHUT_WR);

    CHECK_SOCKET_STATE(pco_iut, acc_s, pco_tst, clnt_s, STATE_SHUT_RD); 

    rc = rpc_recv(pco_iut, acc_s, rx_buf, buf_len, 0); 

    if (rc > 0)
    { 
        TEST_FAIL("Recv on acc_s after WR shutdown on peer "
                  "returns non-zero");
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, srvr_s); 
    CLEANUP_RPC_CLOSE(pco_tst, clnt_s); 
    CLEANUP_RPC_CLOSE(pco_iut, acc_s); 

    TEST_END;
}

