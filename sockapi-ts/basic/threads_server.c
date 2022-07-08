/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-threads_server Stream server socket in multiple threads
 *
 * @objective Check that the same stream server socket may be accessed
 *            from different threads and action in any thread changes
 *            state of socket for other thread.
 *
 * @type Conformance, compatibility
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_twothr2peer
 *                  - @ref arg_types_env_twothr2peer_ipv6
 *
 * @par Scenario:
 *
 * -# Create socket @p iut_s on @p pco_iut1 of the @c SOCK_STREAM type.
 * -# @b bind() @p iut_s to the local address/port.
 * -# Perform routine #sockts_get_socket_state on @p pco_iut2 for @p iut_s.
 * -# Check that obtained state of @p iut_s is the @c STATE_BOUND.
 * -# Create socket @p tst_s on @p pco_tst of the @c SOCK_STREAM type.
 * -# Call @b listen() on @p iut_s on @p pco_iut1.
 * -# Perform routine #sockts_get_socket_state for @p iut_s on @p pco_iut1.
 * -# Perform routine #sockts_get_socket_state for @p iut_s on @p pco_iut2.
 * -# Check that both obtained states from both threads are the
 *    @c STATE_LISTENING.
 * -# Check by means of @b getsockname()
 *    that local address/port of @p iut_s on both threads is the same.
 * -# @b connect() @p tst_s to the @p iut_s.
 * -# Call @b accept() on @p iut_s on @p pco_iut2 to get @p acc_s
 *    socket descriptor,
 * -# Perform routine #sockts_get_socket_state for @p acc_s on @p pco_iut1.
 * -# Perform routine #sockts_get_socket_state for @p acc_s on @p pco_iut2.
 * -# Check that both obtained states from both threads 
 *    are the @c STATE_CONNECTED.
 * -# Check that local and remote socket address of @p acc_s is the same
 *  in the cases of getting from @p pco_iut1 and from @p pco_iut2.
 * -# @b shutdown() @p iut_s for reading on @p pco_iut1.
 * -# Perform routine #sockts_get_socket_state for @p acc_s on @p pco_iut2.
 * -# Check that obtained state of @p acc_s is the @c STATE_SHUT_RD.
 * -# Close all sockets.
 *
 * @author Konstantin Abramenko <Konstantin.Abramenko@oktetlabs.ru>
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/threads_server"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server             *pco_iut1;
    rcf_rpc_server             *pco_iut2;
    rcf_rpc_server             *pco_tst;

    const struct sockaddr      *iut_addr;
    const struct sockaddr      *tst_addr;

    int                         iut_s  = -1;
    int                         tst_s = -1;
    int                         acc_s = -1;

    struct sockaddr_storage     ret_addr;
    socklen_t                   ret_addrlen;

    TEST_START;
    TEST_GET_PCO(pco_iut1);
    TEST_GET_PCO(pco_iut2);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut1, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);


    iut_s = rpc_socket(pco_iut1, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM, RPC_IPPROTO_TCP);

    rpc_bind(pco_iut1, iut_s, iut_addr);
    
    CHECK_SOCKET_STATE(pco_iut2, iut_s, NULL, -1, STATE_BOUND);


    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_STREAM, RPC_IPPROTO_TCP);


    rpc_listen(pco_iut1, iut_s, SOCKTS_BACKLOG_DEF);
    
    CHECK_SOCKET_STATE(pco_iut1, iut_s, pco_tst, tst_s, STATE_LISTENING);
    CHECK_SOCKET_STATE(pco_iut2, iut_s, pco_tst, tst_s, STATE_LISTENING);


    ret_addrlen = sizeof(ret_addr);
    rpc_getsockname(pco_iut1, iut_s, SA(&ret_addr), &ret_addrlen);

    CHECK_NAME(SA(&ret_addr), ret_addrlen);

    rc = te_sockaddrcmp(SA(&ret_addr), ret_addrlen,
                        iut_addr, te_sockaddr_get_size(iut_addr));
    if(rc != 0)
    {
        TEST_FAIL("unexpected socket address/port returned by getsockname() "
                  "on iut_s (pco_iut1)");
    }

    ret_addrlen = sizeof(ret_addr);
    rpc_getsockname(pco_iut2, iut_s, SA(&ret_addr), &ret_addrlen);

    CHECK_NAME(SA(&ret_addr), ret_addrlen);

    rc = te_sockaddrcmp(SA(&ret_addr), ret_addrlen,
                        iut_addr, te_sockaddr_get_size(iut_addr));
    if(rc != 0)
    {
        TEST_FAIL("unexpected socket address/port returned by getsockname() "
                  "on iut_s (pco_iut2)");
    }

    rpc_bind(pco_tst, tst_s, tst_addr);

    rpc_connect(pco_tst, tst_s, iut_addr);

    acc_s = rpc_accept(pco_iut2, iut_s, NULL, NULL);

    CHECK_SOCKET_STATE(pco_iut1, acc_s, pco_tst, tst_s, STATE_CONNECTED);
    CHECK_SOCKET_STATE(pco_iut2, acc_s, pco_tst, tst_s, STATE_CONNECTED);

    ret_addrlen = sizeof(ret_addr);
    rpc_getsockname(pco_iut1, acc_s, SA(&ret_addr), &ret_addrlen);

    rc = te_sockaddrcmp(SA(&ret_addr), ret_addrlen,
                        iut_addr, te_sockaddr_get_size(iut_addr));
    if(rc != 0)
    {
        TEST_FAIL("unexpected socket address/port returned by "
                  "getsockname() on acc_s (pco_iut1)");
    }

    ret_addrlen = sizeof(ret_addr);
    rpc_getsockname(pco_iut2, acc_s, SA(&ret_addr), &ret_addrlen);

    rc = te_sockaddrcmp(SA(&ret_addr), ret_addrlen,
                        iut_addr, te_sockaddr_get_size(iut_addr));
    if (rc != 0)
    {
        TEST_FAIL("unexpected socket address/port returned by "
                  "getsockname() on acc_s (pco_iut2)");
    }

    ret_addrlen = sizeof(ret_addr);
    rpc_getpeername(pco_iut1, acc_s, SA(&ret_addr), &ret_addrlen);

    rc = te_sockaddrcmp(SA(&ret_addr), ret_addrlen,
                        tst_addr, te_sockaddr_get_size(tst_addr));
    if (rc != 0)
    {
        TEST_FAIL("unexpected socket address/port returned by "
                 "getpeername() on acc_s (pco_iut1)");
    }

    ret_addrlen = sizeof(ret_addr);
    rpc_getpeername(pco_iut2, acc_s, SA(&ret_addr), &ret_addrlen);

    rc = te_sockaddrcmp(SA(&ret_addr), ret_addrlen,
                        tst_addr, te_sockaddr_get_size(tst_addr));
    if (rc != 0)
    {
        TEST_FAIL("unexpected socket address/port returned by "
                  "getpeername() on acc_s (pco_iut2)");
    }

    rpc_shutdown(pco_iut1, acc_s, RPC_SHUT_RD);

    CHECK_SOCKET_STATE(pco_iut2, acc_s, pco_tst, tst_s, STATE_SHUT_RD);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut1, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut1, acc_s);

    TEST_END;
}
