/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * IOCTL Requests
 * 
 * $Id$
 */

/** @page ioctls-fionbio_thread_unblock_accept FIONBIO/NONBLOCK from thread when accept() operation is blocked
 *
 * @objective Try @c FIONBIO / @c NONBLOCK from thread when @b accept()
 *            operation is blocked in another thread.
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TESTER
 * @param iut_addr      IUT IP address
 * @param tst_addr      TESTER IP address 
 * @param tst_addr      TESTER IP address
 * @param nonblock_func Function used to get socket with NONBLOCK flag
 *                      ("fcntl", "ioctl")
 * @param use_libc      Use libc implementation of @b fcntl() or @b ioctl()
 *                      intead of Onload implementaion to set nonblocking state.
 *
 * @par Test sequence:
 * -# Create stream socket @p iut_s on @p pco_iut.
 * -# Create stream socket @p tst_s on @p pco_tst.
 * -# Run RPC server @p pco_iut_thread in thread on @p pco_iut.
 * -# Bind @p iut_s to @p iut_addr.
 * -# Listen @p iut_s.
 * -# Call @b accept(@p iut_s, ...) on @p pco_iut.
 * -# Call @b ioctl() or @b fcntl() on @p iut_s socket to set nonblock state
 *    from @p pco_iut_thread.
 * -# Check that @b accept(@p iut_s, ...) on @p pco_iut is not done.
 * -# Check that @b accept(@p iut_s, ...) on @p pco_iut_thread 
 *    fails with @b errno EAGAIN.
 * -# Call @b connect(@p tst_s, @p iut_addr) @p on pco_tst.
 * -# Check that @b accept(@p iut_s, ...) operation on @p pco_iut is unblocked.
 * 
 * @author Konstantin Petrov <Konstantin.Petrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ioctls/fionbio_thread_unblock_accept"

#include "sockapi-test.h"
#include "tapi_cfg.h"

int
main(int argc, char **argv)
{
    rcf_rpc_server                  *pco_iut = NULL;
    rcf_rpc_server                  *pco_tst = NULL;
    rcf_rpc_server                  *pco_iut_thread = NULL;
    const struct sockaddr           *iut_addr;
    const struct sockaddr           *tst_addr;
    int                              iut_s = -1;
    int                              tst_s = -1;
    int                              acc_s = -1;
    te_bool                          is_done;

    te_bool use_libc = TRUE;
    fdflag_set_func_type_t nonblock_func = UNKNOWN_SET_FDFLAG;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    TEST_GET_FDFLAG_SET_FUNC(nonblock_func);
    TEST_GET_BOOL_PARAM(use_libc);

    CHECK_RC(rcf_rpc_server_thread_create(pco_iut,
                                          "IUT_thread",
                                          &pco_iut_thread));
    
    iut_s = rpc_socket(pco_iut,
                       rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM,
                       RPC_IPPROTO_TCP);
    tst_s = rpc_socket(pco_tst,
                       rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_STREAM,
                       RPC_IPPROTO_TCP);
    
    rpc_bind(pco_iut, iut_s, iut_addr);
    rpc_listen(pco_iut, iut_s, 1);             
        
    pco_iut->op = RCF_RPC_CALL;
    rpc_accept(pco_iut, iut_s, NULL, NULL);

    set_sock_non_block(pco_iut_thread, iut_s,
                       nonblock_func == FCNTL_SET_FDFLAG, use_libc, TRUE);
    MSLEEP(100);
    
    CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &is_done));
    if (!is_done)
    {
        RPC_AWAIT_IUT_ERROR(pco_iut_thread);
        acc_s = rpc_accept(pco_iut_thread, iut_s, NULL, NULL);
        if (acc_s != -1)
            TEST_VERDICT("accept() on non-blocking socket returned "
                         "socket");
        CHECK_RPC_ERRNO(pco_iut_thread, RPC_EAGAIN,
                        "accept() on non-blocking socket failed");
        
        rpc_connect(pco_tst, tst_s, iut_addr);
        TAPI_WAIT_NETWORK;

        CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &is_done));
        if (is_done)
        {
            pco_iut->op = RCF_RPC_WAIT;
            acc_s = rpc_accept(pco_iut, iut_s, NULL, NULL);
            if (acc_s == -1)
                TEST_VERDICT("Blocked accept() failed unexpectedly");
        }
        else
        {
            TEST_VERDICT("Blocked accept() was not unblocked by "
                         "connect() from peer");
        }
    }
    else
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        pco_iut->op = RCF_RPC_WAIT;
        acc_s = rpc_accept(pco_iut, iut_s, NULL, NULL);
        if (acc_s == -1)
        {
            CHECK_RPC_ERRNO(pco_iut, RPC_EAGAIN,
                            "Listening socket was closed when accept() "
                            "was in progress");
            RING("accept() has failed with EAGAIN when listening socket "
                 "was closed from other thread");
        }
        else
            TEST_VERDICT("accept() returned valid socket instead of "
                         "failure");
    }

    TEST_SUCCESS;

cleanup:
    
    CLEANUP_RPC_CLOSE(pco_iut, acc_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    if (pco_iut_thread != NULL)
        CHECK_RC(rcf_rpc_server_destroy(pco_iut_thread));

    TEST_END;
}

