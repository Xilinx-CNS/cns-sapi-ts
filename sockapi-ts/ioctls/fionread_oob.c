/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * IOCTL Requests
 *
 * $Id$
 */

/** @page ioctls-fionread_oob Behaviour of FIONREAD request with sockets of the SOCK_STREAM type if OOB data sent
 *
 * @objective State @c FIONREAD request behaviour when it returns the number
 *            of receive queue bytes on the socket of the @c SOCK_STREAM type
 *            if OOB data exist. Such behaviour should be used to check
 *            conformance between main anderlying O/S and alternative
 *            TCP/IP stack.
 *
 * @type conformance
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TESTER
 * @param iut_s         TCP socket on @p pco_iut
 * @param tst_s         TCP socket on @p pco_tst
 * @param req           IOCTL request used in the test
 *                      (@c FIONREAD or @c SIOCINQ)
 * @param oob_inline    TRUE if @c SO_OOBINLINE should be applied
 *                      to the socket
 *
 * @note @c SIOCINQ request is an alias for @c FIONREAD
 * @pre Sockets @p iut_s and @p tst_s are connected.
 *
 * @par Test sequence:
 * -# Retrieve @p iut_s receive queue length by means of @c ioctl(FIONREAD)
 *    and @c recv(MSG_PEEK) and log it.
 * -# Send 1 byte by means of @c send(MSG_OOB) via @p tst_s.
 * -# Retrieve @p iut_s receive queue length by means of @c ioctl(FIONREAD)
 *    and @c recv(MSG_PEEK) and log it.
 * -# Send 10 byte by means of @c send(MSG_OOB) via @p tst_s.
 * -# Retrieve @p iut_s receive queue length by means of @c ioctl(FIONREAD)
 *    and @c recv(MSG_PEEK) and log it.
 * -# Send 20 byte by means of @c send(MSG_OOB) via @p tst_s.
 * -# Retrieve @p iut_s receive queue length by means of @c ioctl(FIONREAD)
 *    and @c recv(MSG_PEEK) and log it.
 * -# @c send() 5 bytes ordinary data via @p tst_s.
 * -# Retrieve @p iut_s receive queue length by means of @c ioctl(FIONREAD)
 *    and @c recv(MSG_PEEK) and log it.
 * -# Retrieve ordinary data by means of @c recv() and  and log the returned
 *    value.
 * -# Retrieve @p iut_s receive queue length by means of @c ioctl(FIONREAD)
 *    and @c recv(MSG_PEEK) and log it.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ioctls/fionread_oob"

#include "sockapi-test.h"

#define TST_BUF_LEN          48096

/** TRUE, if SO_OOBINLINE is set on the socket */
static te_bool oob_inline;

/** Request to use to discover number of bytes in receive queue */
static rpc_ioctl_code req;

/** Buffer for discovering of number of bytes in receive queue */
static void *peek_buf;

/** Length of peek_buf */
static int peek_buflen;


/**
 * Discover number of bytes in receive queue by different ways.
 */
static inline void
bytes_in_recv_queue(rcf_rpc_server *pco, int s)
{
    int     err;
    int     req_val = 0; 
    int     received;

    RPC_AWAIT_IUT_ERROR(pco);
    err = rpc_ioctl(pco, s, req, &req_val);
    if (err != 0)
    {
        TEST_FAIL("ioctl(%s) unexpectedly failed with errno %s",
                  ioctl_rpc2str(req), errno_rpc2str(RPC_ERRNO(pco)));
    }
    RING_VERDICT("ioctl(%s) returns %d bytes", ioctl_rpc2str(req), req_val);

    RPC_AWAIT_IUT_ERROR(pco);
    received = rpc_recv(pco, s, peek_buf, peek_buflen, RPC_MSG_PEEK);

    if (received == -1)
    {
        if (RPC_ERRNO(pco) != RPC_EAGAIN)
        {
            TEST_FAIL("recv() failed with unexpected errno");
        }
        RING_VERDICT("recv(MSG_PEEK) returns -1 and errno set to EAGAIN");
    }
    else
    {
        RING_VERDICT("recv(MSG_PEEK) returns %d bytes", received);
    }
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst = NULL;

    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;

    int                    req_val;

    int                    iut_s = -1;
    int                    tst_s = -1;

    int                    optval;

    void                  *tx_buf = NULL;
    void                  *rx_buf = NULL;
    int                    tst_buflen = TST_BUF_LEN;

    int                    sent;

    TEST_START;
    TEST_GET_IOCTL_REQ(req);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_BOOL_PARAM(oob_inline);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    if (req != RPC_FIONREAD && req != RPC_SIOCINQ)
    {
        TEST_FAIL("The test does not support requests other than "
                  "FIONREAD and SIOCINQ");
    }

    tx_buf = te_make_buf_by_len(tst_buflen);
    rx_buf = te_make_buf_by_len(tst_buflen);

    GEN_CONNECTION_FAKE(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                        tst_addr, iut_addr, &tst_s, &iut_s);

    /*
     * Make the socket non-blocking
     */
    req_val = 1;
    rpc_ioctl(pco_iut, iut_s, RPC_FIONBIO, &req_val);

    /* Get 'iut_s' received buffer length */
    rpc_getsockopt(pco_iut, iut_s, RPC_SO_RCVBUF, &peek_buflen);

    INFO("The length of 'iut_s' socket receive buffer is %d", peek_buflen);
    peek_buflen = peek_buflen / 2;

    peek_buf = te_make_buf_by_len(peek_buflen);

    if (oob_inline == TRUE)
    {
        optval = TRUE;
        rpc_setsockopt(pco_iut, iut_s, RPC_SO_OOBINLINE, &optval);
    }

    bytes_in_recv_queue(pco_iut, iut_s);

    /* Send only one byte with MSG_OOB flag */
    RPC_SEND(sent, pco_tst, tst_s, tx_buf, 1, RPC_MSG_OOB);
    MSLEEP(100);

    bytes_in_recv_queue(pco_iut, iut_s);

    /* Send 10 bytes with MSG_OOB flag */
    RPC_SEND(sent, pco_tst, tst_s, tx_buf, 10, RPC_MSG_OOB);
    MSLEEP(100);

    bytes_in_recv_queue(pco_iut, iut_s);

    /* Send 20 bytes with MSG_OOB flag */
    RPC_SEND(sent, pco_tst, tst_s, tx_buf, 20, RPC_MSG_OOB);
    MSLEEP(100);

    bytes_in_recv_queue(pco_iut, iut_s);

    /* Send 5 bytes without MSG_OOB flag */
    RPC_SEND(sent, pco_tst, tst_s, tx_buf, 5, 0);
    MSLEEP(100);

    bytes_in_recv_queue(pco_iut, iut_s);

    /* Retrieve all accessible ordinary data */
    rpc_recv(pco_iut, iut_s, rx_buf, tst_buflen, 0);

    /* Check the length of data rest in received buffer */
    bytes_in_recv_queue(pco_iut, iut_s);

    /* Retrieve all accessible ordinary data */
    rpc_recv(pco_iut, iut_s, rx_buf, tst_buflen, 0);

    bytes_in_recv_queue(pco_iut, iut_s);

    TEST_SUCCESS;

cleanup:

    CHECK_CLEAR_TRANSPARENT(iut_addr, pco_tst, tst_addr);

    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    free(peek_buf);
    free(tx_buf);
    free(rx_buf);

    TEST_END;
}
