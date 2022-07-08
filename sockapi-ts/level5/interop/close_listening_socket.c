/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Interoperability of L5 stack with system stack.
 *
 * $Id$
 */

/** @page level5-interop-close_listening_socket Usage of system close() call on listening socket
 *
 * @objective Check that it is possible to use system provided @b close()
 *            function on listening L5 socket.
 *
 * @type interop
 *
 * @param pending    TRUE/FALSE for close listening socket with/without
 *                   pending connection
 *
 * @par Test sequence:
 * -# Create @p iut_s socket on @p pco_iut and bind it to @p iut_addr.
 * -# Call @b listen() on iut_s socket.
 * -# If @p pending parameter is @c TRUE create @p tst_s socket on @p
 *    pco_iut and call @b connect() on it with @p iut_addr.
 * -# Resolve @b close() function with system (libc) library.
 * -# Call @b close() function on @p iut_s socket.
 * -# Close @p tst_s socket.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/interop/close_listening_socket"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    const char             *syscall_method = NULL;

    int                     iut_s = -1;
    int                     tst_s = -1;

    const struct sockaddr  *iut_addr;

    te_bool                 pending;

    int                     sock;
    
    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_BOOL_PARAM(pending);
    TEST_GET_STRING_PARAM(syscall_method);

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_iut, iut_s, iut_addr);
    rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);

    if (pending)
    {
        tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(iut_addr),
                           RPC_SOCK_STREAM, RPC_PROTO_DEF);
        rpc_connect(pco_tst, tst_s, iut_addr);
    }
    
    sock = iut_s;
    pco_iut->use_libc_once = TRUE;
    rpc_close_alt(pco_iut, iut_s, syscall_method);
    iut_s = -1;
    CHECK_SOCKET_STATE(pco_iut, sock, NULL, -1, STATE_CLOSED);
    
    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    
    TEST_END;
}
