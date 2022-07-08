/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Advanced usage of send/receive functions
 * 
 * $Id$
 */

/** @page sendrecv-recv_peek_many_iovec MSG_PEEK flag works properly with many iovec
 *
 * @objective Check that @c MSG_PEEK flag works properly when @b recvmsg()
 *            is called with many iovecs.
 *
 * @type conformance
 *
 * @reference @ref STEVENS section 13.3
 *
 * @param pco_iut   PCO with IUT
 * @param iut_s     Socket on @p pco_iut
 * @param pco_tst   Tester PCO
 * @param tst_s     Socket on @p pco_tst
 *
 * @pre Sockets @p iut_s and @p tst_s are connected.
 *
 * -# Send the first portion of data from @p tst_s socket.
 * -# Call @b recvmsg() function on @p iut_s socket with many iovecs and
 *    @c MSG_PEEK flag to recieve data.
 * -# Check that this portion of data has been recieved correctly.
 * -# Send the second portion of data from @p tst_s socket.
 * -# Receive data from @p iut_s socket without @c MSG_PEEK flag. Check
 *    that the first and the second portions of data are received and there
 *    are no other data in the @b iut_s socket.
 *
 * @post Sockets @p iut_s and @p tst_s are kept connected.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendrecv/recv_peek_many_iovec"

#include "sockapi-test.h"
#include "rpc_sendrecv.h"

int
main(int argc, char *argv[])
{
    /* Environment variables */
    rpc_socket_type     sock_type;
    rcf_rpc_server     *pco_iut = NULL;
    rcf_rpc_server     *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    /* Auxiliary variables */
    int     iut_s = -1;
    int     tst_s = -1;
    size_t  pkt_len;
    size_t  min_len;
    size_t  rcv_len;
    size_t  len1;
    size_t  len2;
    ssize_t len;
    int     aux_len;

    int     i;

    rpc_msghdr        *msg = NULL;

    char *tx_buf1 = NULL;
    char *tx_buf2 = NULL;
    char *check_ptr = NULL;
    char *ptr;

    char *rx_buf;

    rpc_msg_read_f recv_f;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(pkt_len);
    TEST_GET_MSG_READ_FUNC(recv_f);

    rx_buf = malloc(pkt_len * 2); /* for both portions */
    min_len = pkt_len / 2;

    tx_buf1 = te_make_buf(min_len, pkt_len, &len1);
    tx_buf2 = te_make_buf(min_len, pkt_len, &len2);

    /* Prepare sockets */

    GEN_CONNECTION_WILD(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                        iut_addr, tst_addr, &iut_s, &tst_s, TRUE);

    if (rpc_write(pco_tst, tst_s, tx_buf1, len1) != (ssize_t)len1)
        TEST_FAIL("Cannot send a data from TST");
    MSLEEP(100);

    /* Prepare msghdr with multiple iovecs */
    do {
        sockts_free_msghdr(msg);
        CHECK_NOT_NULL(msg = sockts_make_msghdr(0, -1,
                                                (ssize_t *)&pkt_len, 0));
    } while (msg->msg_iovlen <= 1);

    RPC_AWAIT_ERROR(pco_iut);
    len = recv_f(pco_iut, iut_s, msg, RPC_MSG_PEEK);
    if (len < 0)
    {
        TEST_VERDICT("Call of receiving function with MSG_PEEK failed "
                     "with errno %r", RPC_ERRNO(pco_iut));
    }

    /* Check that data correctly recived by recvmsg() */
    if (len != (ssize_t)len1)
    {
        TEST_VERDICT("Call of receiving function with MSG_PEEK returned "
                     "incorrect number of bytes");
    }

    aux_len = len1;
    CHECK_NOT_NULL(check_ptr = malloc(aux_len));
    ptr = check_ptr;

    for (i = 0; i < (int)msg->msg_iovlen && aux_len > 0; ++i)
    {
        size_t copylen = ((int)msg->msg_iov[i].iov_len < aux_len) ?
            msg->msg_iov[i].iov_len : (size_t)aux_len;

        memcpy(ptr, msg->msg_iov[i].iov_base, copylen);
        ptr += copylen;
        aux_len -= copylen;
    }
    if (aux_len != 0)
        TEST_FAIL("Failed to read all the returned data from I/O vector");

    if (memcmp(check_ptr, tx_buf1, len1) != 0)
    {
        TEST_VERDICT("Call of receiving function with MSG_PEEK returned "
                     "incorrect data");
    }

    if (rpc_write(pco_tst, tst_s, tx_buf2, len2) != (ssize_t)len2)
        TEST_FAIL("Cannot send a data from TST");
    MSLEEP(100);

    rcv_len = pkt_len * 2;
    memset(rx_buf, 0, rcv_len);
    len = recv_by_func(rpc_msg_read_func_name(recv_f), pco_iut, iut_s,
                       rx_buf, rcv_len, 0);

    if (len != (ssize_t)(len1 + len2))
    {
        int len0 = len;

        /* Try to receive more */
        len = recv_by_func(rpc_msg_read_func_name(recv_f), pco_iut, iut_s,
                           rx_buf + len0, rcv_len - len0, 0);

        len += len0;

        if (len != (ssize_t)(len1 + len2))
        {
            INFO("%d bytes is received instead %u",
                 (int)len, (unsigned)(len1 + len2));
            TEST_VERDICT("Incorrect amount of data is received when "
                         "calling receiving function without MSG_PEEK");
        }
    }
    if (memcmp(tx_buf1, rx_buf, len1) != 0 ||
        memcmp(tx_buf2, rx_buf + len1, len2) != 0)
    {
        TEST_VERDICT("Incorrect data is received when calling receiving "
                     "function without MSG_PEEK");
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    free(tx_buf1);
    free(tx_buf2);
    free(check_ptr);

    TEST_END;
}
