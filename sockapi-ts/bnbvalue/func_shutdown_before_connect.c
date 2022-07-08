/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_shutdown_before_connect Using shutdown() function with not connected sockets
 *
 * @objective Check that @b shutdown() function reports an error while
 *            using for not connected sockets.
 *
 * @type conformance, robustness
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param env Testing environment
 *            - @ref arg_types_env_iut_ucast
 *            - @ref arg_types_env_iut_ucast_ipv6
 *
 * @param sock_type Type of socket used in the test
 *
 * @param bind_to   Type of address to bind
 *      - @c none
 *      - @c wild
 *      - @c lo
 *      - @c iut
 *
 * @param shut_how
 *      - @c SHUT_RD
 *      - @c SHUT_WR
 *      - @c SHUT_RDWR
 *      - @c SHUT_NONE
 *
 * @par Scenario:
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_shutdown_before_connect"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rpc_socket_type    sock_type;
    rpc_shut_how       shut_how;

    rcf_rpc_server            *pco_iut = NULL;
    int                        iut_s = -1;
    const struct sockaddr     *iut_addr = NULL;


    te_bool how_is_correct;
    te_bool bind_is_none = FALSE;

    const char             *bind_to;
    struct sockaddr_storage iut_addr_bind;

    TEST_START;

    /* Preambule */
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_SHUT_HOW(shut_how);
    TEST_GET_STRING_PARAM(bind_to);

    tapi_sockaddr_clone_exact(iut_addr, &iut_addr_bind);

    if (strcmp(bind_to, "none") == 0)
        bind_is_none = TRUE;
    else if (strcmp(bind_to, "wild") == 0)
        te_sockaddr_set_wildcard(SA(&iut_addr_bind));
    else if (strcmp(bind_to, "lo") == 0)
        te_sockaddr_set_loopback(SA(&iut_addr_bind));

    switch (shut_how)
    {
        case RPC_SHUT_NONE:
        case RPC_SHUT_UNKNOWN:
            how_is_correct = FALSE;
            break;

        case RPC_SHUT_RD:
        case RPC_SHUT_WR:
        case RPC_SHUT_RDWR:
            how_is_correct = TRUE;
            break;

        default:
            TEST_FAIL("'shut_how'=%d is not supported by the test",
                      shut_how);
    }

    TEST_STEP("Create @p pco_iut socket from @p domain domain of type "
              "@p type on @p pco_iut;");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       sock_type, RPC_PROTO_DEF);

    TEST_STEP("Bind socket @b iut_s to @b ius_addr_bind in dependence "
               "on @p bind_to");
    if (!bind_is_none)
        rpc_bind(pco_iut, iut_s, SA(&iut_addr_bind));

    TEST_STEP("Call @b shutdown() on @p pco_iut socket specifying @c SHUT_RD, "
              "@c SHUT_WR, and @c SHUT_RDWR as the value of @a how parameter");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_shutdown(pco_iut, iut_s, shut_how);

    TEST_STEP("Check that the function returns @c -1 and sets @b errno to "
              "@c ENOTCONN or @c EINVAL;");
    if (rc != -1)
    {
         TEST_FAIL("shutdown() called on IUT "
                   "returns %d instead of -1", rc);
    }

    if (!how_is_correct)
    {
        CHECK_RPC_ERRNO(pco_iut, RPC_EINVAL,
                        "shutdown() called on IUT returns -1");
    }
    else
    {
        CHECK_RPC_ERRNO(pco_iut, RPC_ENOTCONN,
                        "shutdown() called on IUT returns -1");
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
