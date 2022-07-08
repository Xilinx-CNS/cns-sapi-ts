/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_bind_addr_null Using NULL pointer as address in bind() function
 *
 * @objective Check that @b bind() function correctly handles situation
 *            with passing @c NULL pointer as the value of @a address
 *            parameter.
 *
 * @type conformance, robustness
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_iut_only
 * @param sock_type Socket type:
 *                  - SOCK_STREAM
 *                  - SOCK_DGRAM
 *
 * @par Scenario:
 * -# Create @p iut_s socket from @p domain domain of type @p sock_type
 *    on @p pco_iut;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b bind() on @p iut_s socket passing @c NULL as the value of
 *    @a address parameter and zero value as @a address_length
 *    parameter;
 * -# Check that the function immediately returns @c -1 and sets @b errno
 *    to @c EDESTADDRREQ. See @ref bnbvalue_func_bind_addr_null_1 "note 1";
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b bind() on @p iut_s socket passing @c NULL as the value of
 *    @a address parameter and some non zero value as @a address_length
 *    parameter;
 * -# Check that the function immediately returns @c -1 and sets @b errno
 *    to @c EDESTADDRREQ. See @ref bnbvalue_func_bind_addr_null_2 "note 2";
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Close @p iut_s socket.
 *
 * @note
 * -# @anchor bnbvalue_func_bind_addr_null_1
 *    This step is based on @ref XNS5, but on Linux and FreeBSD @b errno
 *    is set to @c EINVAL;
 * -# @anchor bnbvalue_func_bind_addr_null_2
 *    This step is based on @ref XNS5, but on Linux and FreeBSD @b errno
 *    is set to @c EFAULT.
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_bind_addr_null"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rpc_socket_domain  domain;
    rpc_socket_type    sock_type;
    rcf_rpc_server    *pco_iut = NULL;

    int                iut_s = -1;
    int                err;
    te_bool            step_fail = FALSE;

    struct sockaddr   *addr = NULL;
    tarpc_sa          *rpc_sa = NULL;

    int                expected_errno;
    

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_DOMAIN(domain);

    expected_errno = RPC_EDESTADDRREQ;

    iut_s = rpc_socket(pco_iut, domain, sock_type, RPC_PROTO_DEF);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_bind(pco_iut, iut_s, NULL);
    if (rc != -1)
    {
        TEST_FAIL("bind(s, NULL, 0) returns %d instead of -1", rc);
    }
    err = RPC_ERRNO(pco_iut);
    if (err != expected_errno)
    {
        ERROR("bind(s, NULL, 0) returns -1 but sets errno to %s, "
              "instead of %s", errno_rpc2str(err),
              errno_rpc2str(expected_errno));
        step_fail = TRUE;
    }

    CHECK_NOT_NULL(addr = sockaddr_to_te_af(NULL, &rpc_sa));
    rpc_sa->len = rpc_get_sizeof(pco_iut,
        addr_family_sockaddr_str(sockts_domain2family(domain)));

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_bind(pco_iut, iut_s, addr);
    if (rc != -1)
    {
        TEST_FAIL("bind(s, NULL, 1) returns %d instead of -1", rc);
    }
    err = RPC_ERRNO(pco_iut);
    if (err != expected_errno)
    {
        ERROR("bind(s, NULL, 1) returns -1 but sets errno to %s, "
              "instead of %s", errno_rpc2str(err),
              errno_rpc2str(expected_errno));
        step_fail = TRUE;
    }

    if (!step_fail)
        TEST_SUCCESS;
    else
        TEST_STOP;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    free(addr);

    TEST_END;
}
