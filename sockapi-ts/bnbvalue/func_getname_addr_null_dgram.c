/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_getname_addr_null_dgram Using NULL pointer as address and its length in getpeername() and getsockname() functions with SOCK_DGRAM sockets
 *
 * @objective Check that @b getpeername() and @b getsockname() functions
 *            correctly handle situation with passing @c NULL as the value
 *            of @a address or @a address_len parameters.
 *
 * @type conformance, robustness
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_iut_ucast
 *                  - @ref arg_types_env_iut_ucast_ipv6
 *
 * @par Scenario:
 * -# Create @p pco_iut socket of type @c SOCK_DGRAM on @p pco_iut.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b getpeername() on @p pco_iut socket passing @c NULL as the
 *    value of @a address parameter and size of an appropriate sockaddr
 *    structure as the value of @a address_len parameter.
 * -# Check that the function immediately returns @c -1 and sets 
 *    @b errno to @c ENOTCONN.
 *    See @ref bnbvalue_func_getname_addr_null_dgram_1 "note 1".
 * -# Call @b getpeername() on @p pco_iut socket passing @c NULL as the 
 *    value of @a address_len parameter and some not @c NULL pointer as
 *    the value of @a address parameter.
 * -# Check that the function immediately returns @c -1 and sets 
 *    @b errno to @c ENOTCONN.
 *    See @ref bnbvalue_func_getname_addr_null_dgram_1 "note 1".
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b getsockname() on @p pco_iut socket passing @c NULL as the
 *    value of @a address parameter and size of an appropriate sockaddr
 *    structure as the value of @a address_len parameter.
 * -# Check that the function immediately returns @c -1 and sets 
 *    @b errno to @c EFAULT.
 * -# Call @b getsockname() on @p pco_iut socket passing @c NULL as the 
 *    value of @a address_len value and some not @c NULL pointer as the
 *    value of @a address parameter.
 * -# Check that the function immediately returns @c -1 and sets 
 *    @b errno to @c EFAULT.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b connect() on @p pco_iut socket specifying a valid peer address.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b getpeername() on @p pco_iut socket passing @c NULL as the 
 *    value of @a address parameter and size of an appropriate sockaddr
 *    structure as the value of @a address_len parameter.
 * -# Check that the function immediately returns @c -1 and sets 
 *    @b errno to @c EFAULT.
 * -# Call @b getpeername() on @p pco_iut socket passing @c NULL as the 
 *    value of @a address_len parameter and some not @c NULL pointer as
 *    the value of @a address parameter.
 * -# Check that the function immediately returns @c -1 and sets 
 *    @b errno to @c EFAULT.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b getsockname() on @p pco_iut socket passing @c NULL as the 
 *    value of @a address parameter and size of an appropriate sockaddr
 *    structure as the value of @a address_len parameter.
 * -# Check that the function immediately returns @c -1 and sets
 *    @b errno to @c EFAULT.
 * -# Call @b getsockname() on @p pco_iut socket passing @c NULL as the
 *    value of @a address_len value and some not @c NULL pointer as the
 *    value of @a address parameter.
 * -# Check that the function immediately returns @c -1 and sets 
 *    @b errno to @c EFAULT.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Close @p pco_iut and @p pco_tst sockets.
 *
 * @note
 * -# @anchor bnbvalue_func_getname_addr_null_dgram_1
 *    This step is oriented on FreeBSD and Linux behaviour, but it is
 *    not obvious what should be checked first whether state of the
 *    connection point (connected or not) or validity of the parameters;
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_getname_addr_null_dgram"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server          *pco_iut = NULL;
    const struct sockaddr   *iut_addr = NULL;

    struct sockaddr_storage  addr;
    socklen_t                addrlen;
    int                      iut_socket = -1;
    
    int expected_errno;


    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);

    iut_socket = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                            RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    addrlen = sizeof(addr);
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_getpeername(pco_iut, iut_socket, NULL, &addrlen);

    if (rc != -1)
    {
        TEST_FAIL("getpeername() called on IUT with NULL as the value "
                  "of adress parameter and correct addr_length "
                  "returned %d instead of -1", rc);
    }

    if (addrlen != sizeof(addr))
    {
        TEST_FAIL("getpeername() called on IUT with NULL as the value "
                  "of address parameter and correct addr_lenth "
                  "returned -1 but changed the addr_length", rc);

    }
    
    if (RPC_ERRNO(pco_iut) == RPC_ENOTCONN ||
        RPC_ERRNO(pco_iut) == RPC_EFAULT)
    {
        RING_VERDICT("getpeername() called on not connected datagram "
                     "socket with NULL as the value of address "
                     "parameter and positive address length failed "
                     "with errno %s", errno_rpc2str(RPC_ERRNO(pco_iut)));
    }
    else
    {
        TEST_VERDICT("getpeername() called on not connected datagram "
                     "socket with NULL as the value of address "
                     "parameter and positive address length failed "
                     "with unexpected errno %s",
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    /*
     * It's necessary to use '_gen' function here in order to get RPC
     * support know real size of address.
     */
    addrlen = sizeof(addr);
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_getpeername_gen(pco_iut, iut_socket, SA(&addr), NULL, addrlen);

    if (rc != -1)
    {
        TEST_FAIL("getpeername() called on IUT with some as the value "
                  "of adress parameter and NULL addr_length"
                  " returned %d instead of -1", rc);
    }
    
    if (RPC_ERRNO(pco_iut) == RPC_ENOTCONN ||
        RPC_ERRNO(pco_iut) == RPC_EFAULT)
    {
        RING_VERDICT("getpeername() called on not connected datagram "
                     "socket with not NULL as the value of address "
                     "parameter and NULL address length location failed "
                     "with errno %s", errno_rpc2str(RPC_ERRNO(pco_iut)));
    }
    else
    {
        TEST_VERDICT("getpeername() called on not connected datagram "
                     "socket with NULL as the value of address "
                     "parameter and positive address length failed "
                     "with unexpected errno %s",
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    expected_errno = RPC_EFAULT;

    addrlen = sizeof(addr);
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_getsockname(pco_iut, iut_socket, NULL, &addrlen);

    if (rc != -1)
    {
        TEST_FAIL("getsockname() called on IUT with NULL as the value "
                  "of adress parameter and correct addr_length"
                  " returned %d instead of -1", rc);
    }
    if (addrlen != sizeof(addr))
    {
        TEST_FAIL("getsockname() called on IUT with NULL as the value "
                  "of adress parameter and correct addr_lenth "
                  "returned -1 but changed the addr_length", rc);

    }


    CHECK_RPC_ERRNO(pco_iut, expected_errno,
                    "getsockname() called on IUT with NULL as the value"
                    " of adress parameter and correct addr_length "
                    "returned -1");

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_getsockname(pco_iut, iut_socket, NULL, NULL);

    if (rc != -1)
    {
        TEST_FAIL("getsockname() called on IUT with NULL as the value "
                  "of adress parameter and NULL addr_lenth"
                  " returned %d instead of -1", rc);
    }

    CHECK_RPC_ERRNO(pco_iut, expected_errno,
                    "getsockname() called on IUT with NULL as the value"
                    " of adress parameter and NULL addr_length "
                    "returned -1");

    rpc_bind(pco_iut, iut_socket, iut_addr);
    rpc_connect(pco_iut, iut_socket, iut_addr);

    addrlen = sizeof(addr);
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_getpeername(pco_iut, iut_socket, NULL, &addrlen);

    if (rc != -1)
    {
        TEST_FAIL("getpeername() called on IUT with NULL as the value "
                  "of adress parameter and correct addr_length "
                  "returned %d instead of -1", rc);
    }

    if (addrlen != sizeof(addr))
    {
        TEST_FAIL("getpeername() called on IUT with NULL as the value "
                  "of adress parameter and correct addr_lenth "
                  "returned -1 but changed the addr_length", rc);

    }

    CHECK_RPC_ERRNO(pco_iut, RPC_EFAULT,
                    "getpeername() called on IUT with NULL as the value"
                    " of adress parameter and correct addr_length "
                    "returned -1");

    /*
     * It's necessary to use '_gen' function here in order to get RPC
     * support know real size of address.
     */
    addrlen = sizeof(addr);
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_getpeername_gen(pco_iut, iut_socket, SA(&addr), NULL, addrlen);

    if (rc != -1)
    {
        TEST_FAIL("getpeername() called on IUT with some as the value "
                  "of adress parameter and NULL addr_length"
                  " returned %d instead of -1", rc);
    }

    CHECK_RPC_ERRNO(pco_iut, RPC_EFAULT,
                    "getpeername() called on IUT with some as the value"
                    " of adress parameter and NULL addr_length "
                    "returned -1");

    addrlen = sizeof(addr);
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_getsockname(pco_iut, iut_socket, NULL, &addrlen);

    if (rc != -1)
    {
        TEST_FAIL("getsockname() called on IUT with NULL as the value "
                  "of adress parameter and correct addr_length"
                  " returned %d instead of -1", rc);
    }
    if (addrlen != sizeof(addr))
    {
        TEST_FAIL("getsockname() called on IUT with NULL as the value "
                  "of adress parameter and correct addr_lenth "
                  "returned -1 but changed the addr_length", rc);

    }


    CHECK_RPC_ERRNO(pco_iut, RPC_EFAULT,
                    "getsockname() called on IUT with NULL as the value"
                    " of adress parameter and correct addr_length "
                    "returned -1");

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_getsockname(pco_iut, iut_socket, NULL, NULL);

    if (rc != -1)
    {
        TEST_FAIL("getsockname() called on IUT with NULL as the value "
                  "of adress parameter and NULL addr_lenth "
                  "returned %d instead of -1", rc);
    }

    CHECK_RPC_ERRNO(pco_iut, RPC_EFAULT,
                    "getsockname() called on IUT with NULL as the value"
                    " of adress parameter and NULL addr_length "
                    "returned -1");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_socket);

    TEST_END;
}
