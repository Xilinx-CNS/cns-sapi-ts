/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_sendto_addr_null_dgram  Using NULL pointer as address in sendto() function with SOCK_DGRAM sockets
 *
 * @objective Check that @b sendto() function correctly handles situation
 *            with passing @c NULL pointer as an address structure with
 *            @c SOCK_DGRAM sockets.
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
 * -# Create @p pco_iut socket of type @c SOCK_DGRAM on @b pco_iut.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b sendto() on @p pco_iut socket passing @c NULL as the
 *    value of @a address parameter and zero as the value of
 *    @a address_len parameter.
 * -# Check that the function immediately returns @c -1 and sets 
 *    @b errno to @c EDESTADDRREQ.
 *    See @ref bnbvalue_func_sendto_addr_null_dgram_1 "note 1".
 * -# Call @b sendto() on @p pco_iut socket passing @c NULL as the
 *    value of @a address parameter and size of an appropriate sockaddr
 *    structure as the value of @a address_len parameter.
 * -# Check that the function immediately returns @c -1 and sets
 *    @b errno to @c EDESTADDRREQ.
 *    See @ref bnbvalue_func_sendto_addr_null_dgram_1 "note 1".
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Close @p pco_iut socket.
 *
 * @note
 * -# @anchor bnbvalue_func_sendto_addr_null_dgram_1
 *    This step is oriented on @ref XNS5 and FreeBSD behaviour, because on
 *    Linux the function sets @b errno to @c ENOTCONN;
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_sendto_addr_null_dgram"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;     
    const struct sockaddr  *iut_addr;
    int                     iut_socket = -1;

    struct sockaddr    *addr = NULL;
    tarpc_sa           *rpc_sa = NULL;

    char   buffer[] = "Test";
    size_t buffer_size = sizeof(buffer);
    
    int expected_errno;
    
    rpc_socket_domain domain;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);
    
    domain = rpc_socket_domain_by_addr(iut_addr);
    
    expected_errno = RPC_EDESTADDRREQ;

    iut_socket = rpc_socket(pco_iut, domain, RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    RPC_AWAIT_IUT_ERROR(pco_iut);
    
    te_fill_buf(buffer, buffer_size);
    
    rc = rpc_sendto(pco_iut, iut_socket, buffer, buffer_size, 0, NULL); 
    
    if (rc != -1)
    {
        TEST_FAIL("sendto(..., NULL, 0) called on not connected SOCK_DGRAM"
                  " sockets returned %d instead of -1", rc);
    }

    CHECK_RPC_ERRNO(pco_iut, expected_errno,
                    "sendto(..., NULL, 0) called on not connected SOCK_DGRAM "
                    "sockets returned -1");


    CHECK_NOT_NULL(addr = sockaddr_to_te_af(NULL, &rpc_sa));
    rpc_sa->len = rpc_get_sizeof(pco_iut,
        addr_family_sockaddr_str(addr_family_h2rpc(iut_addr->sa_family)));

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_sendto(pco_iut, iut_socket, buffer, buffer_size, 0, addr);

    if (rc != -1)
    {
        TEST_FAIL("sendto(..., NULL, address length) called on not connected "
                  "SOCK_DGRAM sockets returned %d instead of -1", rc);
    }

    CHECK_RPC_ERRNO(pco_iut, expected_errno,
                    "sendto(..., NULL, address length) called on not "
                    "connected SOCK_DGRAM sockets returned -1");

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_socket);

    free(addr);

    TEST_END;
}
