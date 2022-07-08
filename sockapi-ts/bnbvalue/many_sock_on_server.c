/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */


/** @page bnbvalue-many_sock_on_server Many sockets on server
 *
 * @objective Check that when we have created the largest number of sockets
 *            and after that @c close() one socket we can call function @c
 *            accept().
 *
 * @type conformance
 *
 * @reference @ref STEVENS section 13.3
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_peer2peer
 *                  - @ref arg_types_env_peer2peer_ipv6
 *@param close_one  If @c TRUE, close one of sockets and check that new
 *                  connection can be accepted.
 *
 * -# Create @p iut_s socket on @p pco_iut and @c bind() this socket
 *    to @p iut_addr.
 * -# Call @c listen on @p iut_s socket.
 * -# Create @p tst_s socket on @b pco_tst and @c bind() this socket
 *    to @p tst_addr.
 * -# Create as many sockets on @p pco_iut as possible.
 * -# Call @c connect() on @p tst_s socket to connect to @p iut_s.
 * -# @c close() one socket on @p pco_iut.
 * -# Call @c accept() function on @p pco_iut.
 * -# Check that @c accept return @p accepted_socket without any errors.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME "bnbvalue/many_sock_on_server"

#include "sockapi-test.h"

#define SOCK_DESK_MAX 10000

int
main(int argc, char *argv[])
{

    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    int                     iut_socket = -1;
    int                     tst_socket = -1;
    int                     accepted_socket = -1;

    int                     iut_sockets[SOCK_DESK_MAX];
    unsigned int            num_sock = 0;

    te_bool                 close_one;


    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(close_one);


    iut_socket = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                            RPC_SOCK_STREAM, RPC_PROTO_DEF);

    rpc_bind(pco_iut, iut_socket, iut_addr);

    rpc_listen(pco_iut, iut_socket, SOCKTS_BACKLOG_DEF);


    tst_socket = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr), 
                            RPC_SOCK_STREAM, RPC_PROTO_DEF);

    rpc_bind(pco_tst, tst_socket, tst_addr);


    do {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        iut_sockets[num_sock] = rpc_socket(pco_iut, 
                                           rpc_socket_domain_by_addr(iut_addr),
                                           RPC_SOCK_STREAM, RPC_PROTO_DEF);
        if (iut_sockets[num_sock] == -1)
        {
            CHECK_RPC_ERRNO(pco_iut, RPC_EMFILE,
                            "Error in socket creation");
            break;
        }
        if (++num_sock == SOCK_DESK_MAX)
            TEST_FAIL("Socket array overflowed, %d", num_sock);
    } while (1);


    rpc_connect(pco_tst, tst_socket, iut_addr);

    if (close_one)
    {
        num_sock--;
        RPC_CLOSE(pco_iut, iut_sockets[num_sock]);
    }
    else
        RPC_AWAIT_IUT_ERROR(pco_iut);

    accepted_socket = rpc_accept(pco_iut, iut_socket, NULL, NULL);

    if (!close_one)
    {
        if (accepted_socket != -1)
            TEST_VERDICT("accept() returns success after socket "
                         "returns -1 with EMFILE");
        else
            CHECK_RPC_ERRNO(pco_iut, RPC_EMFILE,
                            "accept() fails");
    }


    TEST_SUCCESS;

cleanup:
    while (num_sock-- > 0)
        CLEANUP_RPC_CLOSE(pco_iut, iut_sockets[num_sock]);

    CLEANUP_RPC_CLOSE(pco_iut, iut_socket);
    CLEANUP_RPC_CLOSE(pco_tst, tst_socket);
    CLEANUP_RPC_CLOSE(pco_iut, accepted_socket);

    TEST_END;
}
