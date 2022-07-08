/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_bind_twice Usage bind() function more than once on the same socket
 *
 * @objective Check that @b bind() forbids binding more than once.
 *
 * @type conformance, robustness
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param sock_type     Socket type used in the test (@c SOCK_STREAM or
 *                      @c SOCK_DGRAM)
 * @param pco_iut       PCO on IUT
 * @param bind1_addr    Address to bind to
 * @param bind2_addr    Address to bind to
 * @param port1         @c specified - port is specified in the first address;
 *                      @c unspecified - port is zero in the first address
 * @param port2         @c unspecified - port is zero in the second address;
 *                      @c same - the second address has the same port
 *                      as the first one; @c other - the second address
 *                      has port which is not zero and differs from port
 *                      in the first address
 *
 * @par Scenario:
 * -# Create @p pco_iut socket of type @c sock_type on @b pco_iut.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b bind() on @p pco_iut socket specifying @p bind1_addr
 *    address and port in accordance with @p port1 parameter;
 * -# Check that the function returns @c 0.
 * -# Once again call @b bind() on @p pco_iut socket specifying 
 *    @p bind2_addr address and port in accordance with @p port2
 *    parameter;
 * -# Check that the function returns @c -1 and sets @b errno to @c EINVAL.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Close @p pco_iut socket.
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_bind_twice"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;         /* pointer to POC on UIT */

    rpc_socket_type   sock_type;

    const struct sockaddr *bind1_addr;
    const struct sockaddr *bind2_addr;
    const char            *port1 = NULL;
    const char            *port2 = NULL;
    int                    iut_socket = -1;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, bind1_addr);
    TEST_GET_ADDR(pco_iut, bind2_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_STRING_PARAM(port1);
    TEST_GET_STRING_PARAM(port2);

    iut_socket = rpc_socket(pco_iut, rpc_socket_domain_by_addr(bind1_addr), 
                            sock_type, RPC_PROTO_DEF);

    if (strcmp(port1, "unspecified") == 0)
    {
        te_sockaddr_set_port(SA(bind1_addr), 0);
    }
    else if (strcmp(port1, "specified") == 0)
    {
        /* Do not touch port set by environment */
    }
    else
    {
        TEST_FAIL("Invalid 'port1' parameter: %s", port1);
    }
    rpc_bind(pco_iut, iut_socket, bind1_addr);

    if (strcmp(port2, "unspecified") == 0)
    {
        te_sockaddr_set_port(SA(bind2_addr), 0);
    }
    else if (strcmp(port2, "same") == 0)
    {
        te_sockaddr_set_port(SA(bind2_addr),
                             te_sockaddr_get_port(bind1_addr));
    }
    else if (strcmp(port2, "other") == 0)
    {
        /* Do not touch port set by environment */
    }
    else
    {
        TEST_FAIL("Invalid 'port2' parameter: %s", port2);
    }
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_bind(pco_iut, iut_socket, bind2_addr);
    if (rc != -1)
    {
        TEST_VERDICT("bind() called twice on the same socket on IUT "
                     "returns %d istead of -1", rc);
    }

    CHECK_RPC_ERRNO(pco_iut, RPC_EINVAL, "bind() called twice on the "
                    "same socket on IUT returns -1");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_socket);

    TEST_END;
}
