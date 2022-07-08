/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * IOCTL Requests
 * 
 * $Id$
 */

/** @page ioctls-fionread_tcp Usage of FIONREAD request with sockets of the SOCK_STREAM type
 *
 * @objective Check that @c FIONREAD request returns the current number
 *            of receive queue bytes on the socket of the @c SOCK_STREAM type.
 *
 * @type conformance
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param pco_iut        PCO on IUT
 * @param pco_tst        PCO on TESTER
 * @param req            IOCTL request used in the test
 *                       (@c FIONREAD or @c SIOCINQ) * 
 *
 * @note @c SIOCINQ request is an alias for @c FIONREAD
 *
 * @par Test sequence:
 * -# Create network connection of sockets of the @c SOCK_STREAM type 
 *    by means of @c GEN_CONNECTION, obtain sockets @p iut_s on @p pco_iut and
 *    @p tst_s on @p pco_tst;
 * -# Check the connection validity by means of @c CHECK_SOCKET_STATE;
 * -# Retrieve @p iut_s receive queue length and divide it by @c 2 (see
 *    @ref ioctls_fionread_tcp "note");
 * -# Fill in @p iut_s receive queue sending data (data length is a random
 *    value in range) by means of @c send(), check the length of available
 *    data in @p iut_s received queue on each iteration by means of @c ioctl()
 *    @p req and @c recv(MSG_DONTWAIT|MSG_PEEK);
 * -# @c recv() data from @p iut_s sent on previous step. Perform data
 *    receiving in some iterations (data length is a random value in range).
 *    Check the length of data rest in @p iut_s received queue on each 
 *    iteration by means of @c ioctl() @p req and 
 *    @c recv(MSG_DONTWAIT|MSG_PEEK);
 * -# Delete all @p tx_buf, @p rx_buf buffers and @p peek_buf;
 * -# Close @p iut_s and @p tst_s sockets;
 *
 * @note 
 * -# @anchor ioctls_fionread_tcp
 *       This test performs only on half of received buffer to avoid
 *       some Linux problems if received buffer is filled in completely.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ioctls/fionread_tcp"

#include "sockapi-test.h"

#define IOCTL_CALL(_pco, _socket) \
    do {                                                                \
        int err;                                                        \
        RPC_AWAIT_IUT_ERROR(_pco);                                      \
        err = rpc_ioctl(_pco, _socket, req, &req_val);                  \
        if (err != 0)                                                   \
        {                                                               \
            TEST_VERDICT("ioctl(%s) unexpectedly failed with "          \
                         "errno %s", ioctl_rpc2str(req),                \
                         errno_rpc2str(RPC_ERRNO(_pco)));               \
        }                                                               \
    } while (0)

#define BYTES_IN_RECV_QUEUE(_pco, _socket, _expect) \
    do {                                                                \
        int               err;                                          \
        int               received;                                     \
                                                                        \
        IOCTL_CALL(_pco, _socket);                                      \
                                                                        \
        RPC_AWAIT_IUT_ERROR(_pco);                                      \
        received = rpc_recv(_pco, _socket, peek_buf, peek_buflen,       \
                            RPC_MSG_DONTWAIT | RPC_MSG_PEEK);           \
        if (received == -1)                                             \
        {                                                               \
            err = RPC_ERRNO(_pco);                                      \
            if (_expect == 0)                                           \
            {                                                           \
                received = 0;                                           \
                CHECK_RPC_ERRNO(_pco, RPC_EAGAIN,                       \
                                "recv() returns -1, but");              \
            }                                                           \
            else                                                        \
            {                                                           \
                TEST_FAIL("RPC recv() on IUT "                          \
                          "failed RPC_errno=%X", TE_RC_GET_ERROR(err)); \
            }                                                           \
        }                                                               \
        if ((req_val != _expect) || (received != _expect))              \
        {                                                               \
            if (req_val < _expect && received == _expect)               \
            {                                                           \
                IOCTL_CALL(_pco, _socket);                              \
                if (req_val != _expect)                                 \
                    TEST_FAIL("Expected number of data in "             \
                              "receive buffer of %d socket is %d: "     \
                              "ioctl(%s) returns %d: recv(MSG_PEEK)",   \
                              _socket, _expect, ioctl_rpc2str(req),     \
                              req_val, received);                       \
            }                                                           \
            else if (received < _expect && _expect - received < iut_mtu)\
            {                                                           \
                /*                                                      \
                 * If the difference is less than MTU, the test should  \
                 * sleep again and re-check. It is natural for TCP to   \
                 * delay the last partial segment.                      \
                 */                                                     \
                break;                                                  \
            }                                                           \
            else                                                        \
            {                                                           \
                ERROR("Expected number of data in "                     \
                      "receive buffer of %d socket is %d: "             \
                      "ioctl(%s) returns %d: recv(MSG_PEEK)"            \
                      " returns %d",                                    \
                      _socket, _expect, ioctl_rpc2str(req),             \
                      req_val, received);                               \
                TEST_VERDICT("Number of data in receive buffer is not " \
                             "equal to expected");                      \
            }                                                           \
        }                                                               \
    } while (0)


int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst = NULL;
    int                    iut_s = -1;
    int                    tst_s = -1;


    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;
    rpc_ioctl_code         req;
    int                    req_val;

    void                  *peek_buf = NULL;
    int                    peek_buflen;

    void                  *tx_buf = NULL;
    void                  *rx_buf = NULL;
    int                    offset = 0;
    int                    to_send;
    int                    to_read;
    int                    sent;
    int                    rcvd;
    int                    iut_mtu;

    /* Preambule */
    TEST_START;
    TEST_GET_IOCTL_REQ(req);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    if (req != RPC_FIONREAD && req != RPC_SIOCINQ)
    {
        TEST_FAIL("The test does not support requests other than "
                  "FIONREAD and SIOCINQ");
    }


    /* Scenario */
    GEN_CONNECTION_FAKE(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                        tst_addr, iut_addr, &tst_s, &iut_s);

    /* Get 'iut_s' received buffer length */
    rpc_getsockopt(pco_iut, iut_s, RPC_SO_RCVBUF, &peek_buflen);
    rpc_getsockopt(pco_iut, iut_s, RPC_IP_MTU, &iut_mtu);

    tx_buf = te_make_buf_by_len(peek_buflen);
    rx_buf = te_make_buf_by_len(peek_buflen);

    INFO("The length of 'iut_s' socket receive buffer is %d", peek_buflen);
    peek_buflen = peek_buflen / 2;

    peek_buf = te_make_buf_by_len(peek_buflen);

    BYTES_IN_RECV_QUEUE(pco_iut, iut_s, 0);
    do {
        to_send = rand_range(1, peek_buflen - offset);
        RPC_SEND(sent, pco_tst, tst_s, tx_buf + offset, to_send, 0);
        offset += to_send;
        TAPI_WAIT_NETWORK;
        BYTES_IN_RECV_QUEUE(pco_iut, iut_s, offset);
    } while (peek_buflen - offset != 0);

    offset = 0;
    do {
        to_read = rand_range(1, peek_buflen - offset);
        rcvd = rpc_recv(pco_iut, iut_s, rx_buf + offset, to_read, 0);
        offset += rcvd;
        BYTES_IN_RECV_QUEUE(pco_iut, iut_s, peek_buflen - offset);
    } while (peek_buflen - offset != 0);


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

