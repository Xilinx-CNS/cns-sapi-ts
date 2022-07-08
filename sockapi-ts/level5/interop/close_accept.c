/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Interoperability of L5 stack with system stack.
 *
 * $Id$
 */

/** @page level5-interop-close_accept Usage of system close() call on accepting socket
 *
 * @objective Check that it is possible to use system provided @b close()
 *            function on L5 socket when @b accept() started but havn't
 *            satisfied yet.
 *
 * @type interop
 *
 * @par Test sequence:
 * -# Create @c SOCK_STREAM sockets @p iut_s on @p pco_iut and @p tst_s on
 *    @p pco_tst.
 * -# @b bind() @p iut_s socket to @p iut_addr.
 * -# Call @b listen() on @p iut_s socket.
 * -# Call @b accept() on @p iut_s socket in @p pco_iut thread.
 * -# Call @b close() on @p iut_s socket in @p pco_aux thread.
 * -# Check that state of @p iut_s socket is @c STATE_CLOSED.
 * -# Call @b connect() on @p tst_s socket with @p iut_addr.
 * -# Wait for @b accept() function on @p pco_iut. If previous @b connect()
 *    returned @c 0 then call another @b accept() and check that it returns
 *    @c -1 and sets errno to @c EINVAL. If previous @b connect() returned
 *    @c -1 with errno @c ECONNREFUSED check that this @b accept() returns
 *    @c -1 and sets errno to @c EBADF.
 * -# Close sockets.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/interop/close_accept"

#include "sockapi-test.h"

#define DATA_BULK 1024
#define SLEEP_TIME 100

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_aux = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    
    int                     iut_s = -1;
    int                     tst_s = -1;

    const struct sockaddr  *iut_addr;

    int                     sock;
    int                     err;
    int                     acc_s = -1;
    const char             *syscall_method = NULL;
    
    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_aux);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_STRING_PARAM(syscall_method);

    iut_s = sock = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                              RPC_SOCK_STREAM, RPC_PROTO_DEF);
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_iut, iut_s, iut_addr);
    rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);
    
    pco_iut->op = RCF_RPC_CALL;
    acc_s = rpc_accept(pco_iut, iut_s, NULL, NULL);
    
    pco_iut->use_libc_once = TRUE;
    rpc_close_alt(pco_aux, iut_s, syscall_method);
    iut_s = -1;
    
    CHECK_SOCKET_STATE(pco_aux, sock, NULL, -1, STATE_CLOSED);
    
    RPC_AWAIT_IUT_ERROR(pco_tst);
    err = rpc_connect(pco_tst, tst_s, iut_addr);
    if (err == -1)
    {
        CHECK_RPC_ERRNO(pco_tst, RPC_ECONNREFUSED,
                        "connect() on tst_s failed");
        RPC_AWAIT_IUT_ERROR(pco_iut);
    }
    pco_iut->op = RCF_RPC_WAIT;
    acc_s = rpc_accept(pco_iut, sock, NULL, NULL);
    if ((err == -1) && (acc_s == -1))
    {
        CHECK_RPC_ERRNO(pco_iut, RPC_EBADF,
                        "accept() on iut_s failed");
    }
    else if ((err == 0) && (acc_s > 0))
    {
        if (acc_s != sock)
        {
            RPC_AWAIT_IUT_ERROR(pco_iut);
            rc = rpc_accept(pco_iut, sock, NULL, NULL);
            if (rc == -1)
                CHECK_RPC_ERRNO(pco_iut, RPC_EBADF,
                                "accept() on iut_s failed");
            else
                TEST_FAIL("accept() on closed socket returned %d", rc);
        }
    }
    else
        TEST_FAIL("connect() returned %d, but accept() returned %d",
                  err, acc_s);
    
    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, acc_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    
    TEST_END;
}
