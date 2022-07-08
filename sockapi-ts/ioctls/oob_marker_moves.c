/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * IOCTL Requests
 *
 * $Id$
 */

/** @page ioctls-oob_marker_moves OOB marker is moved by new data
 *
 * @objective Check that @c OOB data marker moves when new
 *            @c OOB data comes
 *
 * @type conformance
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TESTER
 * @param oob_inline    TRUE/FALSE  - enable/disable  SO_OOBINLINE
 *
 * @par Test sequence:
 * -# Create connection of @p SOCK_STREAM type between @p pco_iut and 
 *    @p pco_tst;
 * -# setsockopt(SO_OOBINLINE) in accordance with @p oob_inline;
 * -# Send buffer1 with OOB data through @p tst_s to @p iut_s;
 * -# Send buffer2 with OOB data through @p tst_s to @p iut_s;
 * -# Check each byte in @p iut_s buffer by means of @b ioctl(SIOCATMARK);
 *    and log returned value;
 * -# Read byte by byte from @p iut_s by means of @b recv() with
 *    MSG_OOB set according to @p oob_inline and value that was returned by
 *    @b ioctl(SIOCATMARK);
 * -# Log value returned by means of @b recv();
 * -# Close @p iut_s and @p tst_s and free allocated resources.
 *
 * @author Igor.Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ioctls/oob_marker_moves"

#include "sockapi-test.h"

/*
 * Attention: DON'T CHANGE THESE.
 * next constants influence to TRC database verdicts.
 * Last bytes in both buffers should be interpreted as
 * OOB bytes when they are sent.
 */
#define TST_BUF1_LEN   3
#define TST_BUF2_LEN   4

int
main(int argc, char *argv[])
{
    int                    buf1_len = TST_BUF1_LEN;
    int                    buf2_len = TST_BUF2_LEN;

    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;

    int                     iut_s = -1;
    int                     tst_s = -1;

    /* ONLY bytes tx_buf1[2]=3 and tx_buf2[3] are OOB data */
    char   tx_buf1[TST_BUF1_LEN] = {1, 2, 3};
    char   tx_buf2[TST_BUF2_LEN] = {4, 5, 6, 7};

    int                    i;
    int                    req_val;
    unsigned char          rx_buf[100];

    int                    s_len1;
    int                    s_len2;

    int                    rcv_flags = 0;
    te_bool                oob_inline = FALSE;
    te_bool                check_siocatmark;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(oob_inline);


    check_siocatmark = 1;

    GEN_CONNECTION_FAKE(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                        tst_addr, iut_addr, &tst_s, &iut_s);

    {
        int optval = oob_inline;
        rpc_setsockopt(pco_iut, iut_s, RPC_SO_OOBINLINE, &optval);
    }

    rpc_ioctl(pco_iut, iut_s, RPC_SIOCATMARK, &req_val);
    RING_VERDICT("when iut_s socket has no data %s(SIOCATMARK) returns %d",
                 "ioctl", req_val);

    RPC_SEND(s_len1, pco_tst, tst_s, tx_buf1, buf1_len, RPC_MSG_OOB);

    RPC_SEND(s_len2, pco_tst, tst_s, tx_buf2, buf2_len, RPC_MSG_OOB);

    for (i = 0; i < buf1_len; i++)
    {
        rpc_ioctl(pco_iut, iut_s, RPC_SIOCATMARK, &req_val);
        RING_VERDICT("(tx_buf1) %s(SIOCATMARK) returns OOB marker %s",
                     "ioctl", req_val ? "set" : "cleared");

        if (oob_inline == TRUE)
            rcv_flags = 0;
        else
            rcv_flags = (req_val == check_siocatmark) ? RPC_MSG_OOB : 0;

        rc = rpc_recv(pco_iut, iut_s, rx_buf, 1, rcv_flags);
        if (rc != 1)
        {
            TEST_FAIL("Cannot read %d byte of data", i);
        }
        RING_VERDICT("recv(%s) returned byte = %d",
                     rcv_flags ? "MSG_OOB" : "", rx_buf[0]);
    }

    for (i = 0; i < buf2_len; i++)
    {
        rpc_ioctl(pco_iut, iut_s, RPC_SIOCATMARK, &req_val);
        RING_VERDICT("(tx_buf2) %s(SIOCATMARK) returns OOB marker %s",
                     "ioctl", req_val ? "set" : "cleared");

        if (oob_inline == TRUE)
            rcv_flags = 0;
        else
            rcv_flags = (req_val == check_siocatmark) ? RPC_MSG_OOB : 0;

        /*
         * If implementation keeps only one OOB byte
         * we should expect next call returns error.
         */
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_recv(pco_iut, iut_s, rx_buf, 1, rcv_flags);
        if (rcv_flags != RPC_MSG_OOB)
        {
            if (rc != 1)
            {
                TEST_FAIL("Cannot read %d byte data", i);
            }
            RING_VERDICT("recv() returned byte = %d", rx_buf[0]);
        }
        else
        {
            if (rc == -1)
                CHECK_RPC_ERRNO(pco_iut, RPC_EINVAL,
                        "recv(MSG_OOB) returns -1, but");
            else if (rc == 1)
                RING_VERDICT("(2): recv(MSG_OOB) returned value '%d'", rx_buf[0]);
            else
                RING_VERDICT("(2): recv(MSG_OOB) returned %d bytes", rc);
        }
    }
    TEST_SUCCESS;

cleanup:

    CHECK_CLEAR_TRANSPARENT(iut_addr, pco_tst, tst_addr);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}

