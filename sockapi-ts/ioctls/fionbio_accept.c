/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * IOCTL Requests
 * 
 * $Id$
 */

/** @page ioctls-fionbio_accept Using of accept() function with enabled FIONBIO request
 *
 * @objective Check that @c FIONBIO request affects accept() and accept4()
 *            functions called on @c SOCK_STREAM socket.
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
 * 
 * @par Test sequence:
 * -# Create @p iut_s socket of type @c SOCK_STREAM on @p pco_iut.
 * -# Bind @p iut_s socket to a local address.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b ioctl() on @p iut_s socket enabling @c FIONBIO.
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

#define TE_TEST_NAME  "ioctls/fionbio_accept"

#include "sockapi-test.h"
#include "sockapi-ts_tcp.h"

/**
 * Call @p func which is specified for current test
 *
 * @param pco_iut       RPC server handle
 * @param iut_s         Socket on IUT
 * @param func          Function to be called
 * @param func_flag     Flags for @p func if needed
 *
 * @return              File descriptor from @p func
 */
int
fd_accept_accept4(rcf_rpc_server *pco_iut, int iut_s,
		  const char *func, int func_flag)
{
    if (strcmp(func, "accept") == 0)
    {
	return rpc_accept(pco_iut, iut_s, NULL, NULL);
    }
    else if (strcmp(func, "accept4") == 0)
    {
	return rpc_accept4(pco_iut, iut_s, NULL, NULL, func_flag);
    }
    else
    {
	TEST_FAIL("Unknown function is tested");
    }
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
    int                      req_val;

    const char              *func;
    int                      func_flag;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    TEST_GET_STRING_PARAM(func);
    SOCKTS_GET_SOCK_FLAGS(func_flag);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    iut_s = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_STREAM,
                                       RPC_IPPROTO_TCP, TRUE, FALSE,
                                       iut_addr);

    /* Turn on FIONBIO request on 'iut_s' socket */
    req_val = TRUE;

    rpc_ioctl(pco_iut, iut_s, RPC_FIONBIO, &req_val);

    rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);

    RPC_AWAIT_IUT_ERROR(pco_iut);

    accepted_s = fd_accept_accept4(pco_iut, iut_s, func, func_flag);
    if (accepted_s != -1)
    {
        TEST_FAIL("%s() called on server socket with FIONBIO ioctl() "
                  "request enabled returns %d, but so far there is no "
                  "pending connections it is expected to return -1",
                  func, accepted_s);
    }
    CHECK_RPC_ERRNO(pco_iut, RPC_EAGAIN,
            "%s() called on server socket with FIONBIO ioctl() "
            "request enabled returns -1, but", func);

    /* Create a connection */
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr), 
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_connect(pco_tst, tst_s, iut_addr);

    /* Wait a while to make sure that listening socket gets connection */
    TAPI_WAIT_NETWORK;

    accepted_s = fd_accept_accept4(pco_iut, iut_s, func, func_flag);

    if ((rc = sockts_compare_sock_peer_name(pco_iut, accepted_s,
                                            pco_tst, tst_s)) < 0)
    {
        TEST_FAIL("Local name on 'accepted_s' socket is different from "
                  "peer name on 'tst_s' socket");
    }

    CHECK_RC(sockts_check_sock_flags(pco_iut, accepted_s, func_flag));

    RPC_AWAIT_IUT_ERROR(pco_iut);

    tmp_s = fd_accept_accept4(pco_iut, iut_s, func, func_flag);

    if (tmp_s != -1)
    {
        TEST_FAIL("%s() called on server socket with FIONBIO ioctl() "
                  "request enabled returns %d, but so far there is no "
                  "pending connections it is expected to return -1",
                  func, accepted_s);
    }
    CHECK_RPC_ERRNO(pco_iut, RPC_EAGAIN,
            "%s() called on server socket with FIONBIO ioctl() "
            "request enabled returns -1, but", func);

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, tmp_s);
    CLEANUP_RPC_CLOSE(pco_iut, accepted_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}

