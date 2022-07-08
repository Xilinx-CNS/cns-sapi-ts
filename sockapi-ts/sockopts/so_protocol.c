/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 *
 * $Id$
 */

/** @page sockopts-so_protocol SO_PROTOCOL option 
 *
 * @objective Check that @c SO_PROTOCOL option value is correct for
 *            @c SOCK_STREAM and @c SOCK_DGRAM sockets.
 *
 * @type conformance
 *
 * @param pco_iut    PCO on IUT
 * @param sock_type  Socket type: @c SOCK_DGRAM or @c SOCK_STREAM
 * @param use_zero   Whether to use zero value as protocol in @b socket()
 *                   call
 * @param use_bind   Whether to bind created socket
 *
 * @par Test sequence:
 *
 * -# Create @p sock_type socket according to @p use_zero parameter.
 * -# if @p use_bind is @c TRUE @b bind() created socket
 * -# Call @b getsockopt(@c SO_PROTOCOL) and check it returns
 *    @c IPPROTO_TCP or @c IPPROTO_UDP according to @p sock_type
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/so_protocol"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server          *pco_iut = NULL;
    const struct sockaddr   *iut_addr;
    rpc_socket_type          sock_type;
    int                      iut_s = -1;

    te_bool             use_zero = FALSE;
    te_bool             use_bind = FALSE;
    int                 opt_val;
    int                 proto;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(use_zero);
    TEST_GET_BOOL_PARAM(use_bind);

    proto = (sock_type == RPC_SOCK_STREAM) ? RPC_IPPROTO_TCP :
                RPC_IPPROTO_UDP;

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       sock_type, use_zero ? RPC_PROTO_DEF : proto);
    if (use_bind)
        rpc_bind(pco_iut, iut_s, iut_addr);
    rpc_getsockopt(pco_iut, iut_s, RPC_SO_PROTOCOL, &opt_val);

    if ((opt_val != RPC_IPPROTO_TCP && sock_type == RPC_SOCK_STREAM) ||
        (opt_val != RPC_IPPROTO_UDP && sock_type == RPC_SOCK_DGRAM))
        TEST_VERDICT("getsockopt(SO_PROTOCOL) returns incorrect protocol "
                     "(%d)", opt_val);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
