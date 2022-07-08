/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-addr_family_inapprop_connect Using inappropriate address family while passing address structure in connect() function
 *
 * @objective Check that @b connect() function checks address family
 *            field of @a address parameter and reports an error when
 *            it contains not supported by protocol family socket
 *            created with.
 *
 * @type conformance, robustness
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param sock_type             Socket type used in the test
 *                              (@c SOCK_STREAM or @c SOCK_DGRAM)
 * @param unsupported_family    Unsupported address family
 * @param pco_iut               PCO on IUT
 *
 * @par Scenario:
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/addr_family_inapprop_connect"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rpc_socket_type         sock_type;
    const struct sockaddr  *iut_addr = NULL;

    struct sockaddr        *addr = NULL;
    tarpc_sa               *rpc_sa = NULL;
    int                     iut_socket = -1;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_SOCK_TYPE(sock_type);

    TEST_STEP("Create @b iut_s socket of type @c sock_type on @b pco_iut.");
    iut_socket = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                            sock_type, RPC_PROTO_DEF);

    CHECK_NOT_NULL(addr = sockaddr_to_te_af(iut_addr, &rpc_sa));
    rpc_sa->sa_family = RPC_AF_UNKNOWN;

    TEST_STEP("Call @b connect() on @b iut_s socket passing @a address "
              "parameter whose @a family member equals to "
              "@p unsupported_family.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_connect(pco_iut, iut_socket, addr);

    TEST_STEP("Check that function returns @c -1 and sets @b errno to "
              "@c EAFNOSUPPORT.");
    if (rc != -1)
    {
        TEST_FAIL("connect() called with unsupported address family address"
                  "returns %d instead of -1", rc);
    }

    CHECK_RPC_ERRNO(pco_iut, RPC_EAFNOSUPPORT,
                    "connect() called with unsupported address family address "
                    "returns -1");

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_socket);

    free(addr);

    TEST_END;
}
