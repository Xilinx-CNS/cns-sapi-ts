/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 *
 * $Id$
 */

/** @page sockopts-get_supported Checking for support of the @b getsockopt operation
 *
 * @objective Check that @b getsockopt() of the option level/name is
 *            supported in expected way for specified type of socket.
 *            Do not explore option semantic.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param domain        Domain to be used for socket creation
 * @param sock_type     @c SOCK_DGRAM or @c SOCK_STREAM
 * @param opt_level     Level where option can be used
 * @param opt_name      Option to be tested
 * @param is_pipe       Whether to test pipe fd instead of socket
 * @param write_end     If @p is_pipe, whether to test write or
 *                      read end
 *
 * @par Test sequence:
 * -# Create a socket @p iut_fd from @p domain, @p sock_type type
 *    on @p pco_iut if @p is_pipe is @c FALSE; otherwise
 *    create pipe and let @p iut_fd be equal to fd of its end selected
 *    according to @p write_end.
 * -# Call @b getsockopt() with appropriate @p opt_name and @p opt_level
 * -# Check that @b getsockopt() returns success.
 * -# Close @p iut_fd.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/get_supported"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server     *pco_iut = NULL;
    rpc_socket_domain   domain;  
    rpc_socket_type     sock_type;
    rpc_socklevel       opt_level;
    rpc_sockopt         opt_name;
    te_bool             is_pipe;
    te_bool             write_end;

    int                 ret;
    int                 iut_fd = -1;
    int                 pipefds[2] = {-1, -1};
    uint8_t             opt_val_buf[128];
    socklen_t           opt_len;


    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_SOCKOPT(opt_name);
    TEST_GET_BOOL_PARAM(is_pipe);
    if (!is_pipe)
    {
        TEST_GET_DOMAIN(domain);
        TEST_GET_SOCK_TYPE(sock_type);
    }
    else
        TEST_GET_BOOL_PARAM(write_end);

    opt_level = rpc_sockopt2level(opt_name);

    if (!is_pipe)
        iut_fd = rpc_socket(pco_iut, domain, sock_type,
                            RPC_PROTO_DEF);
    else
    {
        rpc_pipe(pco_iut, pipefds);
        iut_fd = write_end ? pipefds[1] : pipefds[0];
    }

    memset(opt_val_buf, 0, sizeof(opt_val_buf));

    switch(opt_name)
    {
        case RPC_IP_ADD_MEMBERSHIP:
        case RPC_IP_DROP_MEMBERSHIP:
        case RPC_IP_MULTICAST_IF:
            ((rpc_sockopt_value *)opt_val_buf)->v_mreqn.type = OPT_MREQN;
            break;

        case RPC_IP_ADD_SOURCE_MEMBERSHIP:
        case RPC_IP_DROP_SOURCE_MEMBERSHIP:
        case RPC_IP_BLOCK_SOURCE:
        case RPC_IP_UNBLOCK_SOURCE:
            ((rpc_sockopt_value *)opt_val_buf)->v_mreq_source.type =
                OPT_MREQ_SOURCE;
            break;

        default:
            ;
    }

    RPC_AWAIT_IUT_ERROR(pco_iut);
    if (opt_name == RPC_SO_BINDTODEVICE ||
        opt_name == RPC_IP_OPTIONS ||
        opt_name == RPC_IP_PKTOPTIONS)
    {
        opt_len = sizeof(opt_val_buf);
        ret = rpc_getsockopt_raw(pco_iut, iut_fd, opt_name,
                                 opt_val_buf, &opt_len);
    }
    else
        ret = rpc_getsockopt(pco_iut, iut_fd, opt_name, opt_val_buf);
    if (ret != 0)
    {
        if (!is_pipe)
            TEST_VERDICT("getsockopt(%s, %s) unexpectedly failed with "
                         "errno %s", socklevel_rpc2str(opt_level),
                         sockopt_rpc2str(opt_name),
                         errno_rpc2str(RPC_ERRNO(pco_iut)));
        else if (RPC_ERRNO(pco_iut) != RPC_ENOTSOCK)
            RING_VERDICT("getsockopt(%s, %s) failed with unexpected "
                         "errno %s on pipe fd",
                         socklevel_rpc2str(opt_level),
                         sockopt_rpc2str(opt_name),
                         errno_rpc2str(RPC_ERRNO(pco_iut)));
    }
    else if (is_pipe)
        TEST_VERDICT("getsockopt(%s, %s) unexpectedly successeed "
                     "on pipe fd",
                     socklevel_rpc2str(opt_level),
                     sockopt_rpc2str(opt_name));
    TEST_SUCCESS;

cleanup:
    if (!is_pipe)
        CLEANUP_RPC_CLOSE(pco_iut, iut_fd);
    else
    {
        CLEANUP_RPC_CLOSE(pco_iut, pipefds[0]);
        CLEANUP_RPC_CLOSE(pco_iut, pipefds[1]);
    }
    TEST_END;
}
