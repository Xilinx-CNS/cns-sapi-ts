/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * IOCTL Requests
 *
 * $Id$
 */

/** @page fcntl-fcntl_on_accepted Inheritance of FD_CLOEXEC, O_NONBLOCK or O_ASYNC to accepted socket.
 *
 * @objective Check @c FD_CLOEXEC, @c O_NONBLOCK or @c O_ASYNC flags are
 *            not inherited by accepted socket.
 *
 * @type conformance
 *
 * @param pco_iut             PCO on IUT
 * @param pco_tst             Auxiliary PCO on TST
 * @param flag                @c FD_CLOEXEC, @c O_NONBLOCK or @c O_ASYNC
 * @param close_before_check  Close or do not close @p iut_s socket before
 *                            flags checking on accepted socket
 *
 * @par Test sequence:
 * -# Create @p iut_s socket of @c SOCK_STREAM type on @p pco_iut.
 * -# Create @p tst_s socket of type @c SOCK_STREAM on @p pco_tst.
 * -# @b bind() @p iut_s socket to a local address on @p pco_iut.
 * -# @b bind() @p tst_s socket to a local address on @p pco_tst.
 * -# Call @b listen() on @p iut_s on @p pco_iut.
 * -# Set @p flag on @p iut_s socket.
 * -# Call @b connect() on @p tst_s socket with @p iut_addr.
 * -# Call @b accept() on @p iut_s socket. @p acc_s socket will appear.
 * -# If @p close_before_check is @c TRUE close @p iut_s socket.
 * -# Check that @p flag is not set on @p acc_s socket.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#include "sockapi-test.h"

#define TE_TEST_NAME  "fcntl/fcntl_on_accepted"

int
main(int argc, char *argv[])
{

    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst = NULL;

    const char            *flag;

    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;

    int                    iut_s = -1;
    int                    tst_s = -1;
    int                    acc_s = -1;

    int                    old_flags;

    te_bool                close_before_check;

    TEST_START;

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_STRING_PARAM(flag);
    TEST_GET_BOOL_PARAM(close_before_check);

    iut_s = rpc_stream_server(pco_iut, RPC_PROTO_DEF, TRUE, iut_addr);
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr);

    if (strcmp(flag, "O_NONBLOCK") == 0)
    {
        old_flags = rpc_fcntl(pco_iut, iut_s, RPC_F_GETFL, RPC_O_NONBLOCK);
        rpc_fcntl(pco_iut, iut_s, RPC_F_SETFL, old_flags | RPC_O_NONBLOCK);
        if (!(rpc_fcntl(pco_iut, iut_s, RPC_F_GETFL, RPC_O_NONBLOCK) &
              RPC_O_NONBLOCK))
            TEST_FAIL("Could not set O_NONBLOCK flag.");
    }
    else if (strcmp(flag, "FD_CLOEXEC") == 0)
    {
        rpc_fcntl(pco_iut, iut_s, RPC_F_SETFD, 1);
        if (!rpc_fcntl(pco_iut, iut_s, RPC_F_GETFD, 0))
            TEST_FAIL("Could not set FD_CLOEXEC flag.");
    }
    else if (strcmp(flag, "O_ASYNC") == 0)
    {
        old_flags = rpc_fcntl(pco_iut, iut_s, RPC_F_GETFL, RPC_O_ASYNC);
        rpc_fcntl(pco_iut, iut_s, RPC_F_SETFL, old_flags | RPC_O_ASYNC);
        if (!(rpc_fcntl(pco_iut, iut_s, RPC_F_GETFL, RPC_O_ASYNC) &
              RPC_O_ASYNC))
            TEST_FAIL("Could not set O_ASYNC flag.");
    }
    else
        TEST_FAIL("Incorrect value of 'flag' parameter");

    rpc_connect(pco_tst, tst_s, iut_addr);
    if (strcmp(flag, "O_NONBLOCK") == 0)
        TAPI_WAIT_NETWORK;

    acc_s = rpc_accept(pco_iut, iut_s, NULL, NULL);

    if (close_before_check)
    {
        RPC_CLOSE(pco_iut, iut_s);
        TAPI_WAIT_NETWORK;
    }

    if (strcmp(flag, "O_NONBLOCK") == 0)
    {
        if (rpc_fcntl(pco_iut, acc_s, RPC_F_GETFL, RPC_O_NONBLOCK) &
            RPC_O_NONBLOCK)
            TEST_VERDICT("O_NONBLOCK flag is inherited by accepted "
                         "socket.");
    }
    else if (strcmp(flag, "FD_CLOEXEC") == 0)
    {
        if (rpc_fcntl(pco_iut, acc_s, RPC_F_GETFD, 0))
            TEST_VERDICT("FD_CLOEXEC flag is inherited by accepted "
                         "socket.");
    }
    else if (strcmp(flag, "O_ASYNC") == 0)
    {
        if (rpc_fcntl(pco_iut, acc_s, RPC_F_GETFL, RPC_O_NONBLOCK) &
            RPC_O_NONBLOCK)
            TEST_VERDICT("O_NONBLOCK flag is inherited by accepted "
                         "socket.");
    }
    else
        TEST_FAIL("Incorrect value of 'flag' parameter");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, acc_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
