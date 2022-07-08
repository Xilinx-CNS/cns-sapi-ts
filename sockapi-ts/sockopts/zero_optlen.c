/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * IOCTL Requests
 * 
 * $Id$
 */

/** @page sockopts-zero_optlen Zero length of option value.
 *
 * @objective Check which options of @c SOL_SOCKET level
 *            accept zero length of value.
 *
 * @type conformance
 *
 * @param domain                Domain to be used for socket creation
 * @param sock_type             Socket type
 * @param pco_iut               PCO on IUT
 * @param option                Socket option.
 * @param expected_errno        Expected result.
 * 
 * @par Test sequence:
 * -# Create @p iut_s socket from @p domain domain of type @p type on
 *    @p pco_iut;
 * -# Evaluate expected errno by @p option name and @p sock_type.
 * -# Call @b setsockopt() with @p option socket option,
 *    a large buffer as optval and zero optlen on @p pco_iut;
 * -# Check that it returns expected result.
 * -# Close @p iut_s socket.
 * 
 * @author Ivan Soloducha <Ivan.Soloducha@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/zero_optlen"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rpc_socket_domain domain;
    rcf_rpc_server *pco_iut = NULL;
    int             iut_s = -1;

    rpc_socket_type     sock_type;
    rpc_sockopt         opt_name;
    int                 opt_val = 0;
    te_errno            expected_errno;

    TEST_START;
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_PCO(pco_iut);
    TEST_GET_DOMAIN(domain);
    TEST_GET_SOCKOPT(opt_name);
    
    iut_s = rpc_socket(pco_iut, domain, sock_type, RPC_PROTO_DEF);

    switch(opt_name)
    {
        case RPC_SO_DEBUG:
        case RPC_SO_REUSEADDR:
        case RPC_SO_OOBINLINE:
        case RPC_SO_BROADCAST:
        case RPC_SO_TIMESTAMP:
        case RPC_SO_TIMESTAMPNS:
        case RPC_SO_TIMESTAMPING:
        case RPC_SO_ACCEPTCONN:
        case RPC_SO_ERROR:
        case RPC_SO_TYPE:
        case RPC_SO_DONTROUTE:
        case RPC_SO_PRIORITY:
        case RPC_SO_RCVBUF:
        case RPC_SO_RCVBUFFORCE:
        case RPC_SO_RCVLOWAT:
        case RPC_SO_RCVTIMEO:
        case RPC_SO_SNDBUF:
        case RPC_SO_SNDBUFFORCE:
        case RPC_SO_SNDTIMEO:
        case RPC_SO_KEEPALIVE:
        case RPC_SO_LINGER:
            expected_errno = RPC_EINVAL;
            break;

        case RPC_SO_BINDTODEVICE:
            expected_errno = 0;
            break;

        default:
            TEST_VERDICT("Cannot determine expected errno for option %s",
                         sockopt_rpc2str(opt_name));
    }
            
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_setsockopt_gen(pco_iut, iut_s,
                            rpc_sockopt2level(opt_name), opt_name,
                            NULL, &opt_val, 0, sizeof(opt_val));

    if (expected_errno == 0)
    {
        if (rc != 0)
        {
            TEST_VERDICT("setsockopt(%s, %s) with zero length "
                         "unexpectedly failed",
                         socklevel_rpc2str(RPC_SOL_SOCKET),
                         sockopt_rpc2str(opt_name));
        }
    }
    else if (rc != -1)
    {
        TEST_VERDICT("setsockopt(%s, %s) with zero length unexpectedly "
                     "passed", socklevel_rpc2str(RPC_SOL_SOCKET),
                     sockopt_rpc2str(opt_name));
    }
    else
    {
        CHECK_RPC_ERRNO(pco_iut, expected_errno,
                        "setsockopt(%s, %s) with zero length failed",
                        socklevel_rpc2str(RPC_SOL_SOCKET),
                        sockopt_rpc2str(opt_name));
    }   

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}

