/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-default_bind_listen Default binding during listen()
 *
 * @objective Check that @b listen call for stream nonnamed socket 
 *            implicitly performs @b bind() for it automatically to 
 *            system-chosen unused port.
 *
 * @type Conformance, compatibility
 *
 * @note
 *   This feature is not documented anywhere, but it works for IPv4/TCP 
 *   sockets on Linux and BSD socket API implementations.
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 *
 * @par Scenario:
 *
 * -# Create @p sock_iut of type @c SOCK_STREAM on @p pco_iut.
 * -# Call @b listen() for @p sock_iut.
 * -# Call @b getsockname() for @p sock_iut and check that there is valid port. 
 * -# Perform routine #sockts_get_socket_state for @p pco_iut.
 * -# Check that obtained state of @p accepted is @c STATE_LISTENING. 
 * -# Create @p sock_tst of type @c SOCK_STREAM on @p pco_tst.
 * -# @b connect() @p sock_tst to IP address of @p pco_iut and auto-bound port 
 *    of @p sock_iut. 
 * -# Close all sockets.
 *
 * @author Konstantin Abramenko <Konstantin.Abramenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/default_bind_listen"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut;
    rcf_rpc_server         *pco_tst;
    int                     sock_iut = -1;
    int                     sock_tst = -1;

    const struct sockaddr  *iut_addr;

    struct sockaddr_storage retr_addr;
    socklen_t               retr_addrlen;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);

    sock_iut = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                          RPC_SOCK_STREAM, RPC_PROTO_DEF); 

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_listen(pco_iut, sock_iut, SOCKTS_BACKLOG_DEF);
    if (rc == -1)
    {
        TEST_VERDICT("listen() returns (%d) and errno is set to %s",
                     rc, errno_rpc2str(RPC_ERRNO(pco_iut)));
    }
    

    retr_addrlen = sizeof(retr_addr);
    rpc_getsockname(pco_iut, sock_iut, SA(&retr_addr), &retr_addrlen);

    if (te_sockaddr_get_port(SA(&retr_addr)) == 0)
    {
        TEST_FAIL("Null port got from socket");
    }

    if (te_sockaddr_set_netaddr(SA(&retr_addr),
                                te_sockaddr_get_netaddr(iut_addr)) != 0)
    {
        TEST_FAIL("Failed to prepare IUT address to connect to");
    }

    CHECK_SOCKET_STATE(pco_iut, sock_iut, NULL, -1, STATE_LISTENING); 

    sock_tst = rpc_socket(pco_tst, rpc_socket_domain_by_addr(iut_addr), 
                          RPC_SOCK_STREAM, RPC_PROTO_DEF); 

    rpc_connect(pco_tst, sock_tst, SA(&retr_addr));

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, sock_iut); 
    CLEANUP_RPC_CLOSE(pco_tst, sock_tst);

    TEST_END;
}

