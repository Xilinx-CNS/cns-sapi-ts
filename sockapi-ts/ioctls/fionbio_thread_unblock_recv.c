/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * IOCTL Requests
 * 
 * $Id$
 */

/** @page ioctls-fionbio_thread_unblock_recv FIONBIO from thread when recv() operation is blocked
 *
 * @objective Try @c FIONBIO from thread when @b recv() operation
 *            is blocked in another thread.
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TESTER
 * @param iut_addr      IUT IP address
 * @param tst_addr      TESTER IP address 
 * @param sock_type     type of sockets (stream or dgram)
 *
 * @par Test sequence:
 * -# Create socket @p iut_s on @p pco_iut.
 * -# Create socket @p tst_s on @p pco_tst.
 * -# Run RPC server @p pco_iut_thread in thread on @p pco_iut.
 * -# Bind @p iut_s to @p iut_addr.
 * -# Bind @p tst_s to @p tst_addr.
 * -# Connect @p iut_s to @p tst_s (if @p sock_type = SOCK_STREAM).
 * -# Call @b recv(@p iut_s, ...) on @p pco_iut.
 * -# Make socket @p iut_s non-blocking using @c FIONBIO IOCTL request
 *    from @p pco_iut_thread.
 * -# Check that @b recv(@p iut_s, ...) on @p pco_iut is not done.
 * -# Check that @b recv(@p iut_s, ...) on @p pco_iut_thread
 *    failes with @b errno EAGAIN.
 * -# Call @b send(@p acc_s, ... ) @p on pco_tst 
 *    if @p sock_type = SOCK_STREAM.
 *    Call @b sendto(@p tst_s, ..., @p iut_addr)
 *    if @p sock_type = SOCK_DGRAM.
 * -# Check that @b recv(@p iut_s, ...) operation on @p pco_iut is unblocked.
 * 
 * @author Konstantin Petrov <Konstantin.Petrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ioctls/fionbio_thread_unblock_recv"

#include "sockapi-test.h"
#include "tapi_cfg.h"

#define BUF_LEN 1

static rpc_socket_type sock_type;

/**
 * How long wait in milliseconds for recv() call unbocking to determine if
 * it hangs.
 */
#define TIME_TO_WAIT 500

/* Delay in milliseconds between IUT calls. */
#define CALLS_DELAY 100

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
    int                              req_val;
    te_bool                          is_done;
    unsigned char                    tx_buf[BUF_LEN];
    unsigned char                    rx_buf[BUF_LEN];
    size_t                           tx_buf_len = BUF_LEN;
    size_t                           rx_buf_len = BUF_LEN;
    int                              waiting;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);

    CHECK_RC(rcf_rpc_server_thread_create(pco_iut,
                                          "IUT_thread",
                                          &pco_iut_thread));

    iut_s = rpc_create_and_bind_socket(pco_iut, sock_type,
                                       RPC_PROTO_DEF, TRUE, FALSE,
                                       iut_addr);
    tst_s = rpc_socket(pco_tst,
                       rpc_socket_domain_by_addr(tst_addr),
                       sock_type,
                       RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr);

    if (sock_type == RPC_SOCK_STREAM)
    {
        rpc_listen(pco_tst, tst_s, 1);
        rpc_connect(pco_iut, iut_s, tst_addr);
        if ( (acc_s = rpc_accept(pco_tst, tst_s, NULL, NULL)) == -1)
            TEST_FAIL("Unable to accept connection on pco_tst side");
    }

    pco_iut->op = RCF_RPC_CALL;
    rpc_recv(pco_iut, iut_s, rx_buf, rx_buf_len, 0);
    MSLEEP(CALLS_DELAY);

    req_val = TRUE;
    rpc_ioctl(pco_iut_thread, iut_s, RPC_FIONBIO, &req_val);
    MSLEEP(CALLS_DELAY);

    CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &is_done));
    if (!is_done)
    {
        pco_iut_thread->op = RCF_RPC_CALL;
        rpc_recv(pco_iut_thread, iut_s, rx_buf, rx_buf_len, 0);

        for (waiting = 0; waiting < TIME_TO_WAIT; waiting += CALLS_DELAY)
        {
            CHECK_RC(rcf_rpc_server_is_op_done(pco_iut_thread, &is_done));
            MSLEEP(CALLS_DELAY);
            if (is_done)
                break;
        }

        if (is_done)
        {
            RPC_AWAIT_IUT_ERROR(pco_iut_thread);
            if (rpc_recv(pco_iut_thread, iut_s, rx_buf, rx_buf_len, 0) != -1)
                TEST_VERDICT("recv() on non-blocking socket succeed");

            CHECK_RPC_ERRNO(pco_iut_thread, RPC_EAGAIN,
                            "recv() on non-blocking socket failed");
        }
        else
        {
            ERROR_VERDICT("Child thread was blocked in recv() call");
        }

        if (sock_type == RPC_SOCK_STREAM)
        {
            rpc_send(pco_tst, acc_s, tx_buf, tx_buf_len, 0);
        }
        else
        {
            rpc_sendto(pco_tst, tst_s, tx_buf, tx_buf_len, 0, iut_addr);
        }
        TAPI_WAIT_NETWORK;

        if (!is_done)
        {
            CHECK_RC(rcf_rpc_server_is_op_done(pco_iut_thread, &is_done));
            ERROR_VERDICT("Child thread was not unblocked even after data "
                          "transmission from tester");
        }

        CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &is_done));
        if (is_done)
        {
            pco_iut->op = RCF_RPC_WAIT;

            if (rpc_recv(pco_iut, iut_s, rx_buf, rx_buf_len, 0) == -1)
                TEST_VERDICT("Blocked recv() failed unexpectedly");
        }
        else
        {
            TEST_VERDICT("Blocked recv() was not unblocked by "
                         "send() from peer");
        }
    }
    else
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        pco_iut->op = RCF_RPC_WAIT;

        if (rpc_recv(pco_iut, iut_s, rx_buf, rx_buf_len, 0) == -1)
        {
            CHECK_RPC_ERRNO(pco_iut, RPC_EAGAIN,
                            "recv() on blocking socked failed");
        }
        else
            TEST_VERDICT("recv() on blocking socket "
                         "succeed instead of failure");
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    if (sock_type == RPC_SOCK_STREAM)
        CLEANUP_RPC_CLOSE(pco_tst, acc_s);

    if (pco_iut_thread != NULL)
        CHECK_RC(rcf_rpc_server_destroy(pco_iut_thread));

    TEST_END;
}

