/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_connect_addr_null Using NULL pointer as address in connect() function
 *
 * @objective Check that @b connect() function correctly handles
 *            situation with passing @c NULL as the value of
 *            @a address parameter.
 *
 * @type conformance, robustness
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_iut_ucast
 *                  - @ref arg_types_env_iut_ucast_ipv6
 * @param sock_type Socket type:
 *                  - SOCK_STREAM
 *                  - SOCK_DGRAM
 *
 * @par Scenario:
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 * @author Dmitrij Komoltsev <Dmitrij.Komoltsev@oktetlabs.ru> (@b ConnectEx())
 */

#define TE_TEST_NAME  "bnbvalue/func_connect_addr_null"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rpc_socket_type         sock_type;
    rcf_rpc_server         *pco_iut = NULL;
    const struct sockaddr  *iut_addr;

    struct sockaddr        *addr = NULL;
    tarpc_sa               *rpc_sa = NULL;

    int                     iut_socket = -1;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_SOCK_TYPE(sock_type);

    TEST_STEP("Create socket of type @p sock_type on @p pco_iut.");
    iut_socket = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                            sock_type, RPC_PROTO_DEF);

    CHECK_NOT_NULL(addr = sockaddr_to_te_af(iut_addr, &rpc_sa));
    rpc_sa->flags &= ~TARPC_SA_NOT_NULL;

    TEST_STEP("Call @b connect() on the socket passing @c NULL as "
              "the value of @a address parameter.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_connect(pco_iut, iut_socket, addr);

    TEST_STEP("Check that the function immediately returns @c -1 and sets"
              "@b errno to @c EFAULT.");
    if (rc != -1)
    {
        TEST_FAIL("connect() called with NULL value of adress parameter "
                      "returned %d instead of -1", rc);
    }

    CHECK_RPC_ERRNO(pco_iut, RPC_EFAULT,
                     "connect() called with NULL value of adress parameter "
                     "returned -1");

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_socket);

    free(addr);

    TEST_END;
}
