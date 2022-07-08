/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 *
 * $Id$
 */

/** @page sendrecv-blk_recv_two_threads Blocking recv() called in different threads on the same socket before data is arrived
 *
 * @objective Check that sum of data received by means of @b recv() is the
 *            same as sent if blocking @b recv() called in different threads
 *            on the same socket before data arrival. In the case of the
 *            @c SOCK_STREAM type connection first @b recv() called
 *            to get only part of data to guarantee swathing to the other 
 *            thread.
 *
 * @type Conformance, compatibility
 *
 * @reference @ref STEVENS Section 23.1
 *
 * @param pco_iut1      IUT thread #1
 * @param pco_iut2      IUT thread #2
 * @param pco_tst       Auxiliary IUT for other side network operations
 * @param func          Function to be used for data receiving: @b recv()
 *                      or @b aio_read() with blocking using @b aio_suspend()
 *
 * @par Scenario:
 *
 * -# Create socket @p iut_s on @p pco_iut1 of the @c SOCK_STREAM type.
 * -# @b bind() @p iut_s to the local address/port.
 * -# Create socket @p tst_s on @p pco_tst of the @c SOCK_STREAM type.
 * -# Call @b listen() on @p iut_s on @p pco_iut1.
 * -# @b connect() @p tst_s to the @p iut_s.
 * -# Call @b accept() on @p iut_s on @p pco_iut2 to get @p acc_s
 *    socket descriptor.
 * -# Call blocking @b recv() on @p acc_s on @p pco_iut1 to get only
 *    part of arrival data.
 * -# Call blocking @b recv() on @p acc_s on @p pco_iut2.
 * -# Call @b send() on @p tst_s to transmit prepared data to the
 *    @p acc_s.
 * -# Check that:
 *    TCP case - number of sent data is the same as sum of received in
 *               different threads;
 *    UDP case - number of data received in different threads is the
 *               same as sent.
 * -# Close all sockets.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendrecv/blk_recv_two_threads"

#include "sockapi-test.h"

#define DATA_BULK       1024  /**< Size of data to be sent */

int
main(int argc, char *argv[])
{
    rpc_socket_type         sock_type;

    rcf_rpc_server         *pco_iut1 = NULL;
    rcf_rpc_server         *pco_iut2 = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    rpc_recv_f              func;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    int    iut_s = -1;
    int    tst_s = -1;

    char   *tx_buf  = NULL;
    char   *rx_buf1 = NULL;
    char   *rx_buf2 = NULL;
    char   *rx_buf3 = NULL;

    size_t  buf_len;
    size_t  buf1_len;
    size_t  buf2_len;

    int                          sent, rest;
    int                          recv1;
    int                          recv2;
    int                          recv3;

    TEST_START;
    TEST_GET_RECV_FUNC(func);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_PCO(pco_iut1);
    TEST_GET_PCO(pco_iut2);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut1, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    
    tx_buf = te_make_buf(sock_type == RPC_SOCK_STREAM ? 2 : 1,
                         DATA_BULK, &buf_len);

    rx_buf1 = te_make_buf_by_len(buf_len);
    rx_buf2 = te_make_buf_by_len(buf_len);
    rx_buf3 = te_make_buf_by_len(buf_len);

    GEN_CONNECTION(pco_iut1, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    buf1_len = (sock_type == RPC_SOCK_DGRAM) ? buf_len : buf_len / 2;
    buf2_len = (sock_type == RPC_SOCK_DGRAM) ? buf_len : buf1_len;

    pco_iut1->op = RCF_RPC_CALL;
    func(pco_iut1, iut_s, rx_buf1, buf1_len,  0); 

    pco_iut2->op = RCF_RPC_CALL;
    func(pco_iut2, iut_s, rx_buf2, buf2_len, 0);

    if (sock_type == RPC_SOCK_STREAM)
    {
        RPC_SEND(sent, pco_tst, tst_s, tx_buf, buf_len, 0);
    }
    else
    {
        RPC_SEND(sent, pco_tst, tst_s, tx_buf, buf1_len, 0);
        RPC_SEND(sent, pco_tst, tst_s, tx_buf, buf2_len, 0);
    }
    recv1 = func(pco_iut1, iut_s, rx_buf1, buf1_len, 0);

    if (recv1 == 0)
    {
        TEST_FAIL("No data received in thread#1");
    }
    else
    {
        INFO("%d bytes received in thread#1", recv1);
    }

    recv2 = func(pco_iut2, iut_s, rx_buf2, buf2_len, 0);

    if (recv2 == 0)
    {
        TEST_FAIL("No data received in thread#2");
    }
    else
    {
        INFO("%d bytes received in thread#2", recv2);
    }

    if (sock_type == RPC_SOCK_STREAM)
    {
        /* The rest of data */
        rest = sent - recv1 - recv2;
        if (rest > 0)
        {
            recv3 = rpc_recv(pco_iut1, iut_s, rx_buf3, rest, 0);
            if (recv3 != rest)
            {
                TEST_FAIL("Number of data received in thread#1 as "
                          "the rest %d, instead of %d", recv3, rest);
            }
            else
            {
                INFO("%d bytes received in thread#1 as rest", recv3);
            }
        }
    }
    else
    {
        if ((recv1 != sent) && (recv2 != sent))
            TEST_FAIL("%d bytes received in thread#1 instead %d, "
                      "%d bytes received in thread#2 instead %d",
                      recv1, sent, recv2, sent);
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut1, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    free(tx_buf);
    free(rx_buf1);
    free(rx_buf2);
    free(rx_buf3);

    TEST_END;
}
