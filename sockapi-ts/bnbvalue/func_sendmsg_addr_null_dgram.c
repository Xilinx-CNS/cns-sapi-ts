/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_sendmsg_addr_null_dgram  Using NULL pointer as address in sendmsg() or sendmmsg() function with SOCK_DGRAM sockets
 *
 * @objective Check that @b sendmsg() or @b sendmmsg() functions correctly
 *            handle situation with passing @c NULL pointer as an address
 *            structure with not connected @c SOCK_DGRAM sockets.
 *
 * @type conformance, robustness
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_iut_ucast
 *                  - @ref arg_types_env_iut_ucast_ipv6
 * @param func      Tested function:
 *                  - sendmsg
 *                  - sendmmsg
 *
 * @par Scenario:
 * -# Create @p pco_iut socket of type @c SOCK_DGRAM on @b pco_iut.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call tested function on @p pco_iut socket passing @c NULL as
 *    the value of @a msg_name field of @a message parameter and
 *    zero as the value of @a msg_namelen field.
 * -# Check that the function immediately returns @c -1 and sets
 *    @b errno to @c EDESTADDRREQ.
 *    See @ref bnbvalue_func_sendmsg_addr_null_dgram_1 "note 1".
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call tested function on @p pco_iut socket passing @c NULL as
 *    the value of @a msg_name field of @a message parameter and size
 *    of an appropriate @c sockaddr structure as the value of
 *    @a msg_namelen field.
 * -# Check that the function immediately returns @c -1 and sets
 *    @b errno to @c EDESTADDRREQ.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Close @p pco_iut socket.
 *
 * @note
 * -# @anchor bnbvalue_func_sendmsg_addr_null_dgram_1
 *    This step is oriented on @ref XNS5. On FreeBSD it sets @b errno 
 *    to @c EINVAL, but it is not fit in the way @b errno is updated
 *    by @b sendto() function in the same conditions,
 *    see @ref bnbvalue-func_sendto_addr_null_dgram.
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_sendmsg_addr_null_dgram"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    const struct sockaddr  *iut_addr;
    const char             *func = NULL;

    struct sockaddr    *addr = NULL;
    tarpc_sa           *rpc_sa = NULL;
    
    rpc_socket_domain  domain;

    struct rpc_msghdr *msg = NULL;
    ssize_t            msg_datalen;

    int iut_socket = -1;

    int expected_errno;


    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_STRING_PARAM(func);
    
    if (!(strcmp(func, "sendmsg") == 0 ||
          strcmp(func, "sendmmsg") == 0))
        TEST_FAIL("Wrong function name");

    domain = rpc_socket_domain_by_addr(iut_addr);

    expected_errno = RPC_EDESTADDRREQ;

    msg_datalen = -1;
    CHECK_NOT_NULL(msg = sockts_make_msghdr(0, -1, &msg_datalen, 0));

    
    iut_socket = rpc_socket(pco_iut, domain, RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    msg->msg_name = NULL;
    msg->msg_namelen = 0;
    RPC_AWAIT_IUT_ERROR(pco_iut);
    if (strcmp(func, "sendmsg") == 0)
        rc = rpc_sendmsg(pco_iut, iut_socket, msg, 0);
    else
        rc = rpc_sendmmsg_as_sendmsg(pco_iut, iut_socket, msg, 0);

    if (rc != -1)
    {
        TEST_FAIL("%s() called on not connected SOCK_STREAM "
                  "sockets with msg_namelen = 0  returned %d instead of -1",
                  func, rc);
    }

    CHECK_RPC_ERRNO(pco_iut, expected_errno,
                    "%s() called on not connected SOCK_DGRAM "
                    "sockets with msg_namelen = 0 returned -1", func);

    CHECK_NOT_NULL(msg->msg_name = addr = sockaddr_to_te_af(NULL, &rpc_sa));
    rpc_sa->len = rpc_get_sizeof(pco_iut,
        addr_family_sockaddr_str(addr_family_h2rpc(iut_addr->sa_family)));

    RPC_AWAIT_IUT_ERROR(pco_iut);
    if (strcmp(func, "sendmsg") == 0)
        rc = rpc_sendmsg(pco_iut, iut_socket, msg, 0);
    else
        rc = rpc_sendmmsg_as_sendmsg(pco_iut, iut_socket, msg, 0);

    if (rc != -1)
    {
        TEST_FAIL("%s() called on not connected "
                  "SOCK_DGRAM sockets with msg_namelen != 0 returned "
                  "%d instead of -1", func, rc);
    }

    CHECK_RPC_ERRNO(pco_iut, expected_errno,
                    "%s() called on not connected SOCK_DGRAM "
                    "sockets with msg_namelen != 0 returned -1", func);

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_socket);

    free(addr);

    TEST_END;
}
