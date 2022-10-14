/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * IOCTL Requests
 * 
 * $Id$
 */

/** @page ioctls-siocatmark Usage of SIOCATMARK request
 *
 * @objective Check that @c SIOCATMARK correctly indicates about out-of-band
 *            data byte.
 * 
 * @type conformance
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TESTER
 * @param buf1_len      Length of buffer to be first sent with @c MSG_OOB flag
 *                      set (actually only the last byte of
 *                      the buffer is sent as out-of-band data)
 * @param buf2_len      Length of buffer to be sent with @c MSG_OOB flag set
 *                      in the second part of the test
 *
 * @par Test sequence:
 * -# Create connection of @p SOCK_STREAM type between @p pco_iut and
 *    @p pco_tst;
 * -# setsockopt(SO_OOBINLINE) to disable out-of-band data in-line;
 * -# Call @b ioctl() on @p iut_s socket with @c SIOCATMARK;
 * -# Log returned value as verdict;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# @b send() @p tx_buf1 contents with @c MSG_OOB flag from Tester to IUT;
 * -# Repeat (@p buf1_len @c - @c 1) times:
 *        - Call @b ioctl(SIOCATMARK) on @p iut_s and log returned value;
 *        - Call @b recv() on @p iut_s to get one byte of data
 *          from the data stream;
 *        .
 * -# Call @b ioctl(@c SIOCATMARK) on @p iut_s and log returned value;
 * -# Check that @b ioctl(@c SIOCATMARK) points to OOB marker;
 * -# Call @b recv() on @p iut_s to get one OOB byte;
 * -# Check that  byte returned by @b recv() equals to the last byte of
 *    @p tx_buf1 buffer;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b ioctl(@c SIOCATMARK) on @p iut_s and log returned value;
 * -# @b send() one byte of normal data from Tester;
 * -# Call @b ioctl(@c SIOCATMARK) on @p iut_s and log returned value;
 * -# Call @b recv() on IUT to get one byte of ordinary data;
 * -# Call @b ioctl(@c SIOCATMARK) on @p iut_s and log returned value;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# @b send() @p tx_buf2 content with @c MSG_OOB flag from Tester to IUT;
 * -# Repeat (@p buf2_len @c - @c 1) times:
 *        - Call @b recv() on IUT to get one byte of ordinary data;
 *        - Check that the content of @p rx_buf equals to @p tx_buf2{i};
 *        - Call @b ioctl(@c SIOCATMARK) on @p pco_iut socket and
 *          log returned value as verdict;
 *        .
 * -# Call @b ioctl(@c SIOCATMARK) on @p pco_iut socket and log returned
 *    value as verdict;
 * -# Call @b recv(@p iut_s, @p rx_buf, @c 1, @c MSG_OOB) - to get OOB byte;
 * -# Check that the content of @p rx_buf equals to the last byte of
 *    @p tx_buf2 buffer;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b ioctl(@c SIOCATMARK) on @p iut_s socket and log returned
 *    value as verdict;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Close created sockets and free allocated resources.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ioctls/siocatmark"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             iut_s = -1;
    int             tst_s = -1;

    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;
    int                    req_val;
    int                    i;

    void                  *tx_buf1 = NULL;
    int                    buf1_len;
    void                  *tx_buf2 = NULL;
    int                    buf2_len;
    unsigned char          rx_buf[1]; /* Buffer of size one byte */

    int                    rcv_flags = 0;
    te_bool                check_siocatmark;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(buf1_len);
    TEST_GET_INT_PARAM(buf2_len);


    check_siocatmark = 1;

    if (buf1_len < 1 || buf2_len < 1)
    {
        TEST_FAIL("Each buffer should be at least one byte length");
    }

    tx_buf1 = te_make_buf_by_len(buf1_len);
    tx_buf2 = te_make_buf_by_len(buf2_len);

    /*
     * To do VERDICTS predictable we should always fill the buffers
     * with the same content.
     */
    for (i = 0; i < buf1_len; i++)
        ((uint8_t*)tx_buf1)[i] = i + 1;
    for (i = 0; i < buf2_len; i++)
        ((uint8_t*)tx_buf2)[i] = i + 2;

    GEN_CONNECTION_FAKE(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                        tst_addr, iut_addr, &tst_s, &iut_s);

    {
        int optval = FALSE;
        rpc_setsockopt(pco_iut, iut_s, RPC_SO_OOBINLINE, &optval);
    }

    /* Get initial value of SIOCATMARK request */
    rpc_ioctl(pco_iut, iut_s, RPC_SIOCATMARK, &req_val);
    RING_VERDICT("when iut_s socket has no data %s(SIOCATMARK) returns %d",
                 "ioctl", req_val);

    RPC_SEND(rc, pco_tst, tst_s, tx_buf1, buf1_len, RPC_MSG_OOB);
    if (rc != buf1_len)
    {
        TEST_FAIL("Only %d bytes of data sent from 'tst_s' socket",
                  rc);
    }
    TAPI_WAIT_NETWORK;

    for (i = 0; i < (buf1_len - 1); i++)
    {
        rpc_ioctl(pco_iut, iut_s, RPC_SIOCATMARK, &req_val);
        RING_VERDICT("(tx_buf1) %s(SIOCATMARK) returns OOB marker %s",
                     "ioctl", req_val ? "set" : "cleared");

        rcv_flags = 0;
        rc = rpc_recv(pco_iut, iut_s, rx_buf, 1, rcv_flags);
        if (rc != 1)
        {
            TEST_FAIL("Cannot read %d byte of data", i);
        }

        RING_VERDICT("recv(%s) returned byte = %d",
                      rcv_flags ? "MSG_OOB" : "", rx_buf[0]);
        if (memcmp(rx_buf, tx_buf1 + i, 1) != 0)
        {
            TEST_FAIL("On receiving %d byte of data: "
                      "'rx_buf' = %u is different from 'tx_buf1{%d}' = %u",
                      i, rx_buf[0], i, ((unsigned char *)tx_buf1)[i]);
        }
    }

    /* At this place we expect to retrieve OOB byte */
    rpc_ioctl(pco_iut, iut_s, RPC_SIOCATMARK, &req_val);
    RING_VERDICT("(tx_buf1) %s(SIOCATMARK) returns OOB marker %s",
                 "ioctl", req_val ? "set" : "cleared");

    rcv_flags = (req_val == check_siocatmark) ? RPC_MSG_OOB : 0;
    rc = rpc_recv(pco_iut, iut_s, rx_buf, 1, rcv_flags);
    if (rc != 1)
    {
        TEST_FAIL("Cannot read byte of data");
    }
    if (memcmp(rx_buf, tx_buf1 + i, 1) != 0)
    {
        TEST_FAIL("received byte = %u is different from 'tx_buf1{%d}' = %u",
                  *rx_buf, i, ((unsigned char *)tx_buf1)[i]);
    }

    rpc_ioctl(pco_iut, iut_s, RPC_SIOCATMARK, &req_val);
    RING_VERDICT("(tx_buf1) %s(SIOCATMARK) returns OOB marker %s",
                 "ioctl", req_val ? "set" : "cleared");

    /* Send one byte of normal data */
    RPC_SEND(rc, pco_tst, tst_s, tx_buf1, 1, 0);
    if (rc != 1)
    {
        TEST_FAIL("Cannot send one byte of normal data from 'tst_s' socket");
    }
    MSLEEP(100);

    rpc_ioctl(pco_iut, iut_s, RPC_SIOCATMARK, &req_val);
    RING_VERDICT("(tx_buf1) %s(SIOCATMARK) returns OOB marker %s",
                 "ioctl", req_val ? "set" : "cleared");

    rcv_flags = 0;
    rc = rpc_recv(pco_iut, iut_s, rx_buf, 1, rcv_flags);
    if (rc != 1)
    {
        TEST_FAIL("Cannot read a byte of normal data");
    }
    if (memcmp(rx_buf, tx_buf1, 1) != 0)
    {
        TEST_FAIL("On receiving one byte of normal data: "
                  "'rx_buf' = %u is different from 'tx_buf1{0}' = %u",
                  *rx_buf, ((unsigned char *)tx_buf1)[0]);
    }

    rpc_ioctl(pco_iut, iut_s, RPC_SIOCATMARK, &req_val);
    RING_VERDICT("(tx_buf1) %s(SIOCATMARK) returns OOB marker %s",
                 "ioctl", req_val ? "set" : "cleared");

    /* Send OOB data once again */
    RPC_SEND(rc, pco_tst, tst_s, tx_buf2, buf2_len, RPC_MSG_OOB);
    if (rc != buf2_len)
    {
        TEST_FAIL("Only %d bytes of data sent from 'tst_s' socket",
                   rc);
    }
    TAPI_WAIT_NETWORK;

    for (i = 0; i < (buf2_len - 1); i++)
    {
        rcv_flags = 0;
        rc = rpc_recv(pco_iut, iut_s, rx_buf, 1, rcv_flags);
        if (rc != 1)
        {
            TEST_FAIL("Cannot read %d byte of data", i);
        }
        if (memcmp(rx_buf, tx_buf2 + i, 1) != 0)
        {
            TEST_FAIL("On receiving %d byte of data: "
                      "'rx_buf' = %u is different from 'tx_buf2{%d}' = %u",
                      i, *rx_buf, i, ((unsigned char *)tx_buf2)[i]);
        }

        rpc_ioctl(pco_iut, iut_s, RPC_SIOCATMARK, &req_val);
        RING_VERDICT("(tx_buf2) %s(SIOCATMARK) returns OOB marker %s",
                       "ioctl", req_val ? "set" : "cleared");
    }

    rpc_ioctl(pco_iut, iut_s, RPC_SIOCATMARK, &req_val);
    RING_VERDICT("(tx_buf2) %s(SIOCATMARK) returns OOB marker %s",
                 "ioctl", req_val ? "set" : "cleared");

    rcv_flags = (req_val == check_siocatmark) ? RPC_MSG_OOB : 0;
    rc = rpc_recv(pco_iut, iut_s, rx_buf, 1, rcv_flags);
    if (rc != 1)
    {
        TEST_FAIL("Cannot read OOB byte");
    }
    if (memcmp(rx_buf, tx_buf2 + i, 1) != 0)
    {
        TEST_FAIL("OOB byte = %u is different from 'tx_buf2{%d}' = %u",
                  *rx_buf, i, ((unsigned char *)tx_buf2)[i]);
    }

    rpc_ioctl(pco_iut, iut_s, RPC_SIOCATMARK, &req_val);
    RING_VERDICT("(tx_buf2) %s(SIOCATMARK) returns OOB marker %s",
                 "ioctl", req_val ? "set" : "cleared");

    TEST_SUCCESS;

cleanup:
    CHECK_CLEAR_TRANSPARENT(iut_addr, pco_tst, tst_addr);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    free(tx_buf1);
    free(tx_buf2);

    TEST_END;
}

