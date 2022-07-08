/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * IOCTL Requests
 * 
 * $Id$
 */

/** @page sockopts-type Usage of SO_TYPE socket option
 *
 * @objective Check that @c SO_TYPE socket option correctly works.
 *
 * @type conformance
 *
 * @reference @ref XNS5 section 8.1, @ref STEVENS
 *
 * @param domain        Domain to be used for socket creation
 * @param sock_type     Socket type
 * @param pco_iut       PCO on IUT
 * 
 * @par Test sequence:
 * -# Create @p iut_s socket from @p domain domain of type @p type on
 *    @p pco_iut;
 * -# Call @b getsockopt() with @c SO_TYPE socket option on @p iut_s socket;
 * -# Check that the function returns @c 0 and updates @a option_value
 *    parameter with @p type;
 * -# Call @b setsockopt() with @p SO_TYPE socket option on @p iut_s socket;
 * -# Check that the function returns @c -1 and sets @c errno to 
 *    @c ENOPROTOOPT, because it is read-only option;
 * -# Close @p iut_s socket.
 * 
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/type"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    int             iut_s = -1;

    rpc_socket_type        sock_type;
    rpc_sockopt            opt_name = RPC_SO_TYPE;
    int                    opt_val;
    
    rpc_socket_domain domain;

    TEST_START;
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_PCO(pco_iut);
    TEST_GET_DOMAIN(domain);
    
    iut_s = rpc_socket(pco_iut, domain, sock_type, RPC_PROTO_DEF);
   
    rpc_getsockopt(pco_iut, iut_s, opt_name, &opt_val);
    
    if ((rpc_socket_type)opt_val != sock_type)
    {
        TEST_FAIL("Value of %s socket option is %s on socket of type %s",
                  sockopt_rpc2str(opt_name), proto_rpc2str(opt_val),
                  proto_rpc2str(sock_type));
    }

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_setsockopt(pco_iut, iut_s, opt_name, &opt_val);
    if (rc != -1)
    {
        TEST_FAIL("setsockopt() on %s socket option returns %d, "
                  "but it is expected to return -1",
                  sockopt_rpc2str(opt_name), rc);
    }
    CHECK_RPC_ERRNO(pco_iut, RPC_ENOPROTOOPT, "setsockopt(%s) returns -1, but",
                    sockopt_rpc2str(opt_name));

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}

