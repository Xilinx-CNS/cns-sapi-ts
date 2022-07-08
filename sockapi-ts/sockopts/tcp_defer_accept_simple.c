/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 *
 * $Id$
 */

/** @page sockopts-tcp_defer_accept_simple TCP_DEFER_ACCEPT functionality
 *
 * @objective Check that @b accept() is unblocked when data arrive if
 *            there is @c TCP_DEFER_ACCEPT option on the socket.
 *
 * @type conformance
 *
 * @param pco_iut           PCO on IUT
 * @param iut_addr          Address/port on IUT to bind to
 * @param pco_tst           PCO on TESTER
 *
 * @par Test sequence:
 *
 * -# Create TCP socket @p iut_s on @p pco_iut and bind it to
 *    @p iut_addr address/port.
 * -# Set @c TCP_DEFER_ACCEPT option to random value from @c 5 to @c 10
 *    seconds (these values look most reasonable for TCP timeouts and
 *    allow to check it from the test). 
 * -# Get applied value of @c TCP_DEFER_ACCEPT option, since it may be
 *    adjust to TCP RTO algorithm. Check that the value is greater than
 *    zero.
 * -# Call @b listen() on @p iut_s socket.
 * -# Get @c TCP_DEFER_ACCEPT option value once more to check that it
 *    is not affected by @b listen() (Linux 2.6.14 and 2.6.16 have bug
 *    here).
 * -# Call @b accept() on @p iut_s socket.
 * -# Create TCP socket @p tst_s on @p pco_tst.
 * -# Connect @p tst_s socket to @p iut_addr address/port. It will not
 *    block and return success, since SYN-ACK is sent by listening
 *    socket.
 * -# Check that @b accept() is blocked.
 * -# Sleep for 1 second.
 * -# Check that @b accept() is still blocked.
 * -# Send some data from @p tst_s socket.
 * -# Check that @b accept() unblocked when sent data arrived.
 * -# Check that sent from @p tst_s socket data are available immediately
 *    (using @c MSG_DONTWAIT flag). Match received and sent data.
 * -# Close created sockets.
 *
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/tcp_defer_accept_simple"

#include "sockapi-test.h"
#include "rcvtimeo.h"

te_bool bad_val = FALSE;

#define CHECK_OPTVAL(opt_val_) \
    do {                                                                   \
        int opt = opt_val_;                                                \
        RPC_AWAIT_IUT_ERROR(pco_iut);                                      \
        ret = rpc_setsockopt(pco_iut, iut_s, RPC_TCP_DEFER_ACCEPT, &opt);  \
        if (ret != 0)                                                      \
        {                                                                  \
            TEST_VERDICT("setsockopt(SOL_TCP, TCP_DEFER_ACCEPT) failed "   \
                         "with errno %s",                                  \
                         errno_rpc2str(RPC_ERRNO(pco_iut)));               \
        }                                                                  \
        rpc_getsockopt(pco_iut, iut_s, RPC_TCP_DEFER_ACCEPT, &applied1);   \
        if ((applied1 < opt || opt * 3 < applied1) && !bad_val)            \
        {                                                                  \
            bad_val = TRUE;                                                \
            WARN("TCP_DEFER_ACCEPT value: set %d, got %d", opt,            \
                 applied1);                                                \
            ERROR_VERDICT("Got TCP_DEFER_ACCEPT option value is strange"); \
        }                                                                  \
    } while (0)

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             iut_s = -1;
    int             tst_s = -1;
    int             acc_s = -1;

    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;

    const struct if_nameindex   *iut_if = NULL;

    int                    opt_val;
    int                    applied1;
    int                    applied2;

    void                  *tx_buf = NULL;
    int                    tx_buf_len;
    void                  *rx_buf = NULL;
    size_t                 rx_buf_len;

    te_bool                done;
    te_bool                test_timeout;
    struct timeval         tv1;
    struct timeval         tv2;
    struct timeval         tv3;
    struct timeval         tv4;
    ssize_t                len;
    int                    ret;
    int                    cnt;
    uint64_t               expected;

    te_bool                big_packet;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    TEST_GET_IF(iut_if);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(test_timeout);
    TEST_GET_BOOL_PARAM(big_packet);
    TEST_GET_INT_PARAM(opt_val);

    if (big_packet)
    {
        CHECK_RC(tapi_cfg_base_if_get_mtu_u(pco_iut->ta, iut_if->if_name,
                                            &tx_buf_len));
        RING("tx_buf_len = %d", tx_buf_len);
        tx_buf_len *= 1.5;
        RING("tx_buf_len = %d", tx_buf_len);
        CHECK_NOT_NULL(tx_buf = te_make_buf_by_len(tx_buf_len));
    }
    else
        CHECK_NOT_NULL(tx_buf =
                       sockts_make_buf_stream((size_t *)&tx_buf_len));
    rx_buf = te_make_buf_min(tx_buf_len, &rx_buf_len);
    
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM, RPC_IPPROTO_TCP);
    rpc_bind(pco_iut, iut_s, iut_addr);

    CHECK_OPTVAL(opt_val + 1);
    CHECK_OPTVAL(opt_val);
    expected = applied1 * 1000000;

    rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);

    rpc_getsockopt(pco_iut, iut_s, RPC_TCP_DEFER_ACCEPT, &applied2);

    if (applied1 != applied2)
        TEST_VERDICT("TCP_DEFER_ACCEPT value unexpectedly changed by "
                     "listen()");

    pco_iut->op = RCF_RPC_CALL;
    gettimeofday(&tv1, NULL);
    acc_s = rpc_accept(pco_iut, iut_s, NULL, NULL);
    gettimeofday(&tv2, NULL);

    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_STREAM, RPC_IPPROTO_TCP);

    rpc_connect(pco_tst, tst_s, iut_addr);

    CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &done));
    if (done)
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        pco_iut->op = RCF_RPC_WAIT;
        acc_s = rpc_accept(pco_iut, iut_s, NULL, NULL);
        TEST_VERDICT("accept() done without any data from client");
    }
    MSLEEP(500);

    CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &done));
    if (done)
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        pco_iut->op = RCF_RPC_WAIT;
        acc_s = rpc_accept(pco_iut, iut_s, NULL, NULL);
        TEST_VERDICT("accept() done without any data from client");
    }

    if (!test_timeout)
    {
        gettimeofday(&tv3, NULL);
        RPC_SEND(rc, pco_tst, tst_s, tx_buf, tx_buf_len, 0);
        gettimeofday(&tv4, NULL);
    }

    CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &done));
    cnt = applied2 + 10;
    while (!done && cnt > 0)
    {
        SLEEP(1);
        CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &done));
        cnt--;
    }
    if (!done)
        TEST_VERDICT("accept() is still hanging");

    pco_iut->op = RCF_RPC_WAIT;
    acc_s = rpc_accept(pco_iut, iut_s, NULL, NULL);

    if (!test_timeout)
    {
        CHECK_CALL_DURATION_INT_GEN(pco_iut->duration,
                                    TST_TIME_INACCURACY * 2,
                                    TST_TIME_INACCURACY_MULTIPLIER,
                                    TIMEVAL_SUB(tv3, tv2),
                                    TIMEVAL_SUB(tv4, tv1),
                                    ERROR_VERDICT, ERROR_VERDICT, "", "");

        len = rpc_recv(pco_iut, acc_s, rx_buf, rx_buf_len, RPC_MSG_DONTWAIT);

        if (len != tx_buf_len)
             TEST_FAIL("recv() called on 'iut_s' returned %d instead %u",
                       (int)len, (unsigned)tx_buf_len);
        if (memcmp(tx_buf, rx_buf, tx_buf_len) != 0)
        {
            TEST_FAIL("Step1 The content of 'tx_buf' and 'rx_buf' are not the same");
        }
    }
    else
        CHECK_CALL_DURATION_INT_GEN(pco_iut->duration, 20000,
                                    TST_TIME_INACCURACY_MULTIPLIER,
                                    expected,
                                    /* Pure Linux has bad accuracy */
                                    expected + 3000000, ERROR,
                                    ERROR_VERDICT,
                                    "Precision is too low", "");

    RPC_SEND(rc, pco_tst, tst_s, tx_buf, tx_buf_len, 0);
    TAPI_WAIT_NETWORK;
    len = rpc_recv(pco_iut, acc_s, rx_buf, rx_buf_len, 0);

    if (len != tx_buf_len)
        TEST_FAIL("Step2 recv() called on 'iut_s' returned %d instead %u",
                  (int)len, (unsigned)tx_buf_len);
    if (memcmp(tx_buf, rx_buf, tx_buf_len) != 0)
    {
        TEST_FAIL("Step2 The content of 'tx_buf' and 'rx_buf' are not the same");
    }

    RPC_SEND(rc, pco_iut, acc_s, tx_buf, tx_buf_len, 0);
    TAPI_WAIT_NETWORK;
    len = rpc_recv(pco_tst, tst_s, rx_buf, rx_buf_len, 0);

    if (len != tx_buf_len)
        TEST_FAIL("recv() called on 'tst_s' returned %d instead %u",
                  (int)len, (unsigned)tx_buf_len);
    if (memcmp(tx_buf, rx_buf, tx_buf_len) != 0)
    {
        TEST_FAIL("The content of 'tx_buf' and 'rx_buf' are not the same");
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, acc_s);

    free(tx_buf);
    free(rx_buf);
    
    TEST_END;
}
