/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-bind_reuse Bind to a busy port
 *
 * @objective Check @b bind() behaviour at attempt to bind to already used port.
 *
 * @type Conformance, compatibility
 *
 * @param env       Private environments set where:
 *                  - iterate using unicast and wildcard IPv4 addresses:
 *                      - @p pco_aux and @p pco_iut are two threads on IUT;
 *                      - @p pco_aux and @p pco_iut are two processes on IUT.
 *                  - iterate using unicast and wildcard IPv6 addresses:
 *                      - @p pco_aux and @p pco_iut are two threads on IUT;
 *                      - @p pco_aux and @p pco_iut are two processes on IUT.
 * @param sock_type Socket type:
 *                  - SOCK_STREAM
 *                  - SOCK_DGRAM
 *
 * @par Scenario:
 *
 * -# Create sockets @p sock_iut and @p sock_tst of type @p sock_type
 *    on @p pco_iut and @p pco_aux respectively.
 * -# @b bind() socket @b sock_tst to local socket address of @p pco_iut. 
 * -# Call @b bind() on socket @b sock_iut to local IP address of of @p pco_iut
 *  and same port as @p sock_tst was bound.
 * -# Check that @b bind() of @p sock_iut fails whit @b errno @c EADDRINUSE.
 * -# Close all sockets. 
 *
 * Behaviour of the IUT must match behaviour of the reference
 * implementation.
 *
 * @author Konstantin Abramenko <Konstantin.Abramenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/bind_reuse"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rpc_socket_type         sock_type; 
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_aux = NULL;
    int                     sock_iut = -1;
    int                     sock_tst = -1;

    const struct sockaddr  *iut_addr;

    struct sockaddr_storage loc_addr;


    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_aux);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_SOCK_TYPE(sock_type);

    sock_iut = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                          sock_type, RPC_PROTO_DEF); 

    sock_tst = rpc_socket(pco_aux, rpc_socket_domain_by_addr(iut_addr), 
                          sock_type, RPC_PROTO_DEF); 

    rpc_bind(pco_aux, sock_tst, iut_addr);


    memcpy(&loc_addr, iut_addr, te_sockaddr_get_size(iut_addr));
    te_sockaddr_set_port(SA(&loc_addr), te_sockaddr_get_port(iut_addr));

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_bind(pco_iut, sock_iut, SA(&loc_addr)); 
    if (rc != -1)
    {
        TEST_FAIL("Unexpected return code %d from bind of sock_iut "
                  "to used port", rc);
    } 
    else
    {
        CHECK_RPC_ERRNO(pco_iut, RPC_EADDRINUSE,
                        "Unexpected errno from bind() to used "
                        "address/port");
    } 

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, sock_iut); 
    CLEANUP_RPC_CLOSE(pco_aux, sock_tst); 

    TEST_END;
}
