/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-accept_order Accepting connections order
 *
 * @objective Check that accept() returns connections in the same order
 * as they appeared.
 *
 * @type Conformance.
 *
 * @param env   Private set of environments where @p pco_srv is IUT RPC server
 *              with listener socket and iterate (each environment is iterated
 *              with IPv4/IPv6 addresses):
 *              - both @p pco_cli1, @p pco_cli2 on tester host;
 *              - @p pco_cli1 on IUT (not Onload accelerated) and @p pco_cli2
 *              on tester host;
 *              - @p pco_cli1 on IUT (accelerated) and @p pco_cli2
 *              on tester host;
 *              - @p pco_cli2 on IUT (not accelerated) and @p pco_cli1
 *              on tester host;
 *              - @p pco_cli2 on IUT (accelerated) and @p pco_cli1
 *              on tester host;
 *              - both @p pco_cli1 (not accelerated) and
 *                @p pco_cli2 (not accelerated) on IUT host;
 *              - both @p pco_cli1 (accelerated) and
 *                @p pco_cli2 (not accelerated) on IUT host;
 *              - both @p pco_cli1 (not accelerated) and
 *                @p pco_cli2 (accelerated) on IUT host;
 *              - both @p pco_cli1 (accelerated) and
 *                @p pco_cli2 (accelerated) on IUT host;
 *
 * @par Scenario:
 *
 * -# Create a stream socket @p srv_s on @p pco_srv.
 * -# Create stream sockets @p cli1_s on @p pco_cli1
 *                      and @p cli2_s on @p pco_cli2.
 * -# Call listen() for @p srv_s.
 * -# Call connect() for @p cli1_s to @p srv_s.
 * -# Call connect() for @p cli2_s to @p srv_s.
 * -# Call accept() for @p srv_s.
 * -# Check that it returns address and port of @p cli1_s.
 * -# Call accept() for @p srv_s again.
 * -# Check that it returns address and port of @p cli2_s.
 *
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 * @author Ivan Soloducha <Ivan.Soloducha@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/accept_order"

#include "sockapi-test.h"
#include "tapi_ip4.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server              *pco_srv = NULL;
    const struct sockaddr       *srv_addr = NULL;
    rcf_rpc_server              *pco_cli1 = NULL;
    struct sockaddr_storage      cli1_addr;
    socklen_t                    cli1_addrlen;
    rcf_rpc_server              *pco_cli2 = NULL;
    struct sockaddr_storage      cli2_addr;
    socklen_t                    cli2_addrlen;
    int                          srv_s = -1;
    int                          acc1_s = -1;
    int                          acc2_s = -1;
    int                          cli1_s = -1;
    int                          cli2_s = -1;
    struct sockaddr_storage      accepted_addr;
    socklen_t                    accepted_addrlen;
    rpc_socket_domain            domain;


    TEST_START;
    TEST_GET_PCO(pco_srv);
    TEST_GET_PCO(pco_cli1);
    TEST_GET_PCO(pco_cli2);
    TEST_GET_ADDR(pco_srv, srv_addr);

    domain = rpc_socket_domain_by_addr(srv_addr);

    srv_s = rpc_socket(pco_srv, domain, RPC_SOCK_STREAM, RPC_IPPROTO_TCP);
    cli1_s = rpc_socket(pco_cli1, domain, RPC_SOCK_STREAM, RPC_IPPROTO_TCP);
    cli2_s = rpc_socket(pco_cli2, domain, RPC_SOCK_STREAM, RPC_IPPROTO_TCP);

    rpc_bind(pco_srv, srv_s, SA(srv_addr));
    rpc_listen(pco_srv, srv_s, 10);

    rpc_connect(pco_cli1, cli1_s, srv_addr);
    TAPI_WAIT_NETWORK;

    accepted_addrlen = cli1_addrlen = cli2_addrlen =
        te_sockaddr_get_size(srv_addr);
    rpc_getsockname(pco_cli1, cli1_s, SA(&cli1_addr), &cli1_addrlen);

    rpc_connect(pco_cli2, cli2_s, srv_addr);
    TAPI_WAIT_NETWORK;
    rpc_getsockname(pco_cli2, cli2_s, SA(&cli2_addr), &cli2_addrlen);

    acc1_s = rpc_accept(pco_srv, srv_s, SA(&accepted_addr), &accepted_addrlen);
    if (te_sockaddrcmp(SA(&accepted_addr), accepted_addrlen,
                       SA(&cli2_addr), cli2_addrlen) == 0)
    {
        TEST_VERDICT("The 1st accept() returned address of 2nd client");
    }
    else
    {
        if (te_sockaddrcmp(SA(&accepted_addr), accepted_addrlen,
                           SA(&cli1_addr), cli1_addrlen) == -1)
        {
            TEST_VERDICT("The 1st accept() returned unknown address");
        }
    }

    acc2_s = rpc_accept(pco_srv, srv_s, SA(&accepted_addr), &accepted_addrlen);
    if (te_sockaddrcmp(SA(&accepted_addr), accepted_addrlen,
                       SA(&cli1_addr), cli1_addrlen) == 0)
    {
        TEST_VERDICT("The 2nd accept() returned address of 1st client");
    }
    else
    {
        if (te_sockaddrcmp(SA(&accepted_addr), accepted_addrlen,
                           SA(&cli2_addr), cli2_addrlen) == -1)
        {
            TEST_VERDICT("The 2nd accept() returned unknown address");
        }
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_srv, acc1_s);
    CLEANUP_RPC_CLOSE(pco_srv, acc2_s);
    CLEANUP_RPC_CLOSE(pco_srv, srv_s);
    CLEANUP_RPC_CLOSE(pco_cli1, cli1_s);
    CLEANUP_RPC_CLOSE(pco_cli2, cli2_s);
    TEST_END;
}
