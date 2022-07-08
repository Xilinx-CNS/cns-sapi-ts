/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-addr_family_inapprop_bind Using inappropriate address family while passing address structure in bind() function
 *
 * @objective Check that @b bind() function checks address family field
 *            of @a address parameter and reports an error when it
 *            contains not supported by protocol family socket created with.
 *
 * @type conformance, robustness
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param sock_type         Socket type used in the test (@c SOCK_STREAM or
 *                          @c SOCK_DGRAM)
 * @param env               Test environment
 *                            - @ref arg_types_env_iut_ucast
 *                            - @ref arg_types_env_iut_ucast_ipv6
 * @param domain            @c PF_INET or @c PF_INET6
 * @param family_unknown    If it is @c TRUE use @c AF_UNKNOWN value for family
 *                          address field
 *
 * @note
 * -# @anchor bnbvalue-addr_family_inapprop_bind_1
 *    This step is based on @ref XNS5 and FreeBSD, but Linux ignores
 *    family specified in address and tries to @b bind().
 *
 * @par Scenario:
 *
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/addr_family_inapprop_bind"

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
    rpc_socket_domain       domain;
    te_bool                 family_unknown = FALSE;
    rpc_errno               expected_errno;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_DOMAIN(domain);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(family_unknown);

    if ((iut_addr->sa_family == AF_INET) && (domain == RPC_PF_INET6))
        expected_errno = RPC_EINVAL;
    else
        expected_errno = RPC_EAFNOSUPPORT;

    TEST_STEP("Create @b iut_s socket of type @p sock_type and using "
              "@p domain on @b pco_iut.");
    iut_socket = rpc_socket(pco_iut, domain, sock_type, RPC_PROTO_DEF);
    CHECK_NOT_NULL(addr = sockaddr_to_te_af(iut_addr, &rpc_sa));

    TEST_STEP("Prepare an address with @a sa_family set to either a known "
              "family not matching socket domain (@c AF_INET6 for @c PF_INET, "
              "@c AF_INET for @c PF_INET6), or to AF_UNKNOWN if "
              "@p family_unknown is @c TRUE.");
    if (family_unknown)
        rpc_sa->sa_family = RPC_AF_UNKNOWN;
    else if (domain == RPC_PF_INET)
        rpc_sa->sa_family = RPC_AF_INET6;
    else
        rpc_sa->sa_family = RPC_AF_INET;

    TEST_STEP("@b bind() @b iut_s socket to the prepared address.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_bind(pco_iut, iut_socket, addr);

    TEST_STEP("Check that function returns @c -1 and sets @b errno to "
              "@c EINVAL for @c AF_INET address and @c PF_INET6 sockets "
              "and @c -1 with @c EAFNOSUPPORT for other cases."
              "See @ref bnbvalue-addr_family_inapprop_bind_1 \"note 1\".");
    if (rc != -1)
    {
        TEST_FAIL("bind() called with incorrect address family address "
                  "returns %d instead of -1", rc);
    }

    CHECK_RPC_ERRNO(pco_iut, expected_errno,
                    "bind() called with incorrect address family address "
                    "returns -1");

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_socket);

    free(addr);

    TEST_END;
}
