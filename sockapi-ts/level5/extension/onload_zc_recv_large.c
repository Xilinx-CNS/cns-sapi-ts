/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 * 
 * $Id$
 */

/** @page extension-onload_zc_recv_large Receiving large packets with onload_zc_recv() function
 *
 * @objective Check onload_zc_recv() correctly receive packets that have
 *            length more then MTU.
 *
 * @type conformance
 *
 * @requirement REQ-1, REQ-2, REQ-3
 *
 * @reference @ref STEVENS section 13.4
 *
 * @param pco_iut       PCO with IUT
 * @param iut_s         Datagram socket on @p tx
 * @param length        Length of packet to be sent
 * @param packet_num    Number of packets to be sent
 *
 * -# Create two @c SOCK_DGRAM sockets on @p pco_iut and @p pco_tst,
 *    @b bind() them to @p iut_addr and @p tst_addr and connect the to
 *    @p tst_addr and @p iut_addr respectively.
 * -# Repeat the following @p packet_num number of times:
 *      - Send @p length of data from @p tst_s to @p iut_s
 *      - Call @b onload_zc_recv() on @p iut_s and receive the data.
 *      - Chech that data wasn't corrupted.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/extension/onload_zc_recv_large"

#include "sockapi-test.h"

#define TST_IOV_LEN 10

static char tx_buf[8192];
static char rx_buf[TST_IOV_LEN][2048];

int
main(int argc, char *argv[])
{
    static rcf_rpc_server *pco_iut = NULL;
    static rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    int                     iut_s = -1;
    int                     tst_s = -1;

    struct rpc_msghdr msg;
    struct rpc_iovec  rx_buf_vec[TST_IOV_LEN];

    int                     length;
    int                     packet_num;

    int                     i;
    int                     j;
    int                     tmp_len = 0;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(length);
    TEST_GET_INT_PARAM(packet_num);

    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_DGRAM, RPC_IPPROTO_UDP,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    rpc_write(pco_tst, tst_s, tx_buf, 255);
    rpc_read(pco_iut, iut_s, rx_buf, 255);

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = NULL;
    msg.msg_rnamelen = msg.msg_namelen = 0;
    for (i = 0; i < length / 1000; i++)
    {
        rx_buf_vec[i].iov_base = rx_buf[i];
        rx_buf_vec[i].iov_rlen = rx_buf_vec[i].iov_len = 2048;
    }
    msg.msg_iov = rx_buf_vec;
    msg.msg_riovlen = msg.msg_iovlen = length / 1000;
    te_fill_buf(tx_buf, length);
    for (i = 0; i < packet_num; i++)
    {
        for (j = 0; j < length / 1000; j++)
            rx_buf_vec[i].iov_rlen = rx_buf_vec[i].iov_len = 2048;
        msg.msg_riovlen = msg.msg_iovlen = length / 1000;
        if (rpc_write(pco_tst, tst_s, tx_buf, length) != length)
            TEST_FAIL("Cannot send a datagram from TST");

        rc = rpc_simple_zc_recv(pco_iut, iut_s, &msg, 0);
        if (rc != length)
            TEST_VERDICT("Incorrect amount of date is received");
        for (j = 0; j < (int)msg.msg_iovlen; j++)
        {
            if (memcmp(&tx_buf[tmp_len], rx_buf[j],
                       MIN(rx_buf_vec[j].iov_len, length - tmp_len)) != 0)
                TEST_FAIL("Data was corrupted.");
            tmp_len += rx_buf_vec[j].iov_len;

            /*
             * Data in iovecs beyond returned length should
             * be ignored.
             */
            if (tmp_len >= length)
                break;
        }
        tmp_len = 0;
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
