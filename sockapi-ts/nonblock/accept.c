/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * NONBLOCK Requests
 *
 * $Id$
 */

/** @page nonblock-accept Using of accept() function with enabled FIONBIO or NONBLOCK request
 *
 * @objective Check that @c FIONBIO /@c O_NONBLOCK request affects accept() and
 *            accept4() functions called on @c SOCK_STREAM socket.
 *
 * @type conformance
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TESTER
 * @param func          Function used to accept connection:
 *                      - @b accept()
 *                      - @b accept4()
 * @param func_flag     Only for func=accept4. Possible flags:
 *                      - @b default
 *                      - @b nonblock
 *                      - @b cloexec
 * @param nonblock_func Function used to set nonblocking state to socket
 *                      ("fcntl", "ioctl")
 * @param use_libc      Use libc implementation of @b fcntl() or @b ioctl()
 *                      intead of Onload implementaion to set nonblocking state.
 * 
 * @par Test sequence:
 * -# Create @p iut_s socket of type @c SOCK_STREAM on @p pco_iut.
 * -# Bind @p iut_s socket to a local address.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b ioctl() or @b fcntl() on @p iut_s socket to set nonblock state.
 * -# Call @b listen() on @p iut_s socket.
 * -# Check the function returns @c 0.
 * -# Call @b accept() on @p iut_s socket.
 * -# Check that the function returns @c -1 and sets @b errno to @c EAGAIN.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Create @p tst_s socket of type @c SOCK_STREAM on @p pco_tst.
 * -# @b connect() @b tst_s socket to @p iut_s socket.
 * -# Call @b accept() on @b iut_s socket, and check that it
 *    successfully completes returning
 *    a new @p accepted_s socket descriptor.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b accept() on @p iut_s socket.
 * -# Check that the function returns @c -1 and sets @b errno to @c EAGAIN.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Close @p accepted_s, @p iut_s and @p tst_s sockets.
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "nonblock/accept"

#include "sockapi-test.h"
#include "sockapi-ts_tcp.h"

/**
 * Call @p func which is specified for current test
 *
 * @param pco_iut       RPC server handle
 * @param iut_s         Socket on IUT
 * @param func          Function to be called
 * @param func_flag     Flags for @p func if needed
 * @param await_err     If error is awaited
 *
 * @return              File descriptor from @p func
 */
int
fd_accept_accept4(rcf_rpc_server *pco_iut, int iut_s,
                  const char *func, int func_flag, te_bool await_err)
{
    int rc = 0;
    te_bool op_is_completed;

    if (await_err)
        pco_iut->op = RCF_RPC_CALL;

    if (strcmp(func, "accept") == 0)
        rc = rpc_accept(pco_iut, iut_s, NULL, NULL);
    else if (strcmp(func, "accept4") == 0)
        rc = rpc_accept4(pco_iut, iut_s, NULL, NULL, func_flag);
    else
        TEST_FAIL("Unknown function is tested");

    if (await_err)
    {
        if (rc != 0)
            TEST_VERDICT("accept() is unexpectedly failed to call");

        TAPI_WAIT_NETWORK;
        CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &op_is_completed));
        if (!op_is_completed)
            TEST_VERDICT("accept() is unexpectedly not completed");
        pco_iut->op = RCF_RPC_WAIT;
        RPC_AWAIT_IUT_ERROR(pco_iut);

        if (strcmp(func, "accept") == 0)
            rc = rpc_accept(pco_iut, iut_s, NULL, NULL);
        else if (strcmp(func, "accept4") == 0)
            rc = rpc_accept4(pco_iut, iut_s, NULL, NULL, func_flag);
    }

    return rc;
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server    *pco_iut = NULL;
    rcf_rpc_server    *pco_tst = NULL;
    int                iut_s = -1;
    int                tst_s = -1;
    int                accepted_s = -1;
    int                tmp_s = -1;

    const struct sockaddr   *iut_addr;
    const struct sockaddr   *tst_addr;

    const char              *func;
    int                      func_flag;

    te_bool use_libc = TRUE;
    fdflag_set_func_type_t nonblock_func = UNKNOWN_SET_FDFLAG;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    TEST_GET_STRING_PARAM(func);
    SOCKTS_GET_SOCK_FLAGS(func_flag);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_FDFLAG_SET_FUNC(nonblock_func);
    TEST_GET_BOOL_PARAM(use_libc);

    iut_s = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_STREAM,
                                       RPC_IPPROTO_TCP, TRUE, FALSE,
                                       iut_addr);

    /* Turn on nonblocking state on 'iut_s' socket */

    set_sock_non_block(pco_iut, iut_s, nonblock_func == FCNTL_SET_FDFLAG,
                       use_libc, TRUE);

    rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);

    accepted_s = fd_accept_accept4(pco_iut, iut_s, func, func_flag, TRUE);
    if (accepted_s != -1)
    {
        TEST_FAIL("%s() called on server socket with nonblock state "
                  "enabled returns %d, but so far there is no "
                  "pending connections it is expected to return -1",
                  func, accepted_s);
    }
    CHECK_RPC_ERRNO(pco_iut, RPC_EAGAIN,
            "%s() called on server socket with nonblock state "
            "enabled returns -1, but", func);

    /* Create a connection */
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_connect(pco_tst, tst_s, iut_addr);

    /* Wait a while to make sure that listening socket gets connection */
    TAPI_WAIT_NETWORK;

    accepted_s = fd_accept_accept4(pco_iut, iut_s, func, func_flag, FALSE);

    if ((rc = sockts_compare_sock_peer_name(pco_iut, accepted_s,
                                            pco_tst, tst_s)) < 0)
    {
        TEST_FAIL("Local name on 'accepted_s' socket is different from "
                  "peer name on 'tst_s' socket");
    }

    CHECK_RC(sockts_check_sock_flags(pco_iut, accepted_s, func_flag));

    tmp_s = fd_accept_accept4(pco_iut, iut_s, func, func_flag, TRUE);

    if (tmp_s != -1)
    {
        TEST_FAIL("%s() called on server socket with nonblock state "
                  "enabled returns %d, but so far there is no "
                  "pending connections it is expected to return -1",
                  func, accepted_s);
    }
    CHECK_RPC_ERRNO(pco_iut, RPC_EAGAIN,
            "%s() called on server socket with nonblock state "
            "enabled returns -1, but", func);

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, tmp_s);
    CLEANUP_RPC_CLOSE(pco_iut, accepted_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
