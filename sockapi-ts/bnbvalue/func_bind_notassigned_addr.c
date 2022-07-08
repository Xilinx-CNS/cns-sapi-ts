/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_bind_notassigned_addr Usage bind() function with network address not assigned to the system
 *
 * @objective Check that @b bind() rejects bindings to network addresses
 *            not assigned to the system.
 *
 * @type conformance, robustness
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param sock_type             Socket type used in the test
 *                              (@c SOCK_STREAM or @c SOCK_DGRAM)
 * @param env                   Test environment
 *                               - @ref arg_types_env_peer2peer
 *                               - @ref arg_types_env_peer2peer_ipv6
 *
 * @par Scenario:
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_bind_notassigned_addr"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;

    rpc_socket_type   sock_type;

    const struct sockaddr *alien_addr;
    int                    iut_socket = -1;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, alien_addr);
    TEST_GET_SOCK_TYPE(sock_type);

    TEST_STEP("Create @b iut_s socket of type @p sock_type on @b pco_iut;");
    iut_socket = rpc_socket(pco_iut,
                            rpc_socket_domain_by_addr(alien_addr),
                            sock_type, RPC_PROTO_DEF);

    TEST_STEP("Call @b bind() on @b iut_s socket specifying @p alien_addr "
              "as the value of @a address parameter;");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_bind(pco_iut, iut_socket, alien_addr);

    TEST_STEP("Check that the function returns @c -1 and sets @b errno to "
              "@c EADDRNOTAVAIL;");
    if (rc != -1)
    {
        TEST_FAIL("bind() called with not assigned adress returns %d "
                  "istead of -1", rc);
    }

    CHECK_RPC_ERRNO(pco_iut, RPC_EADDRNOTAVAIL, "bind() called with not "
                    "assigned adress returns -1");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_socket);

    TEST_END;
}
