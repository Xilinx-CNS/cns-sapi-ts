/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Advanced usage of send/receive functions
 *
 * $Id$
 */

/** @page sendrecv-send_oob_data Reading OOB byte without reading ordinary data
 *
 * @objective Check that @c MSG_OOB byte can be read without reading
 *            ordinary bytes.
 *
 * @type conformance
 *
 * @reference @ref STEVENS section 13.3
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TESTER
 *
 * @pre Sockets @p iut_s and @p tst_s are connected.
 * -# Fill in both @c tx_buf1 and @c tx_buf2 with values known in advance;
 * -# @c send() @c tx_buf1 with @c MSG_OOB flag from @p iut_s socket;
 * -# @c recv() on @p tst_s socket with with @c MSG_OOB flag to get
 *    out-of-band data only;
 * -# Check that out-of-band data successfully obtained (the last byte
 *    of @c tx_buf1);
 * -# @c send @c tx_buf2 with @c MSG_OOB flag from @p iut_s socket;
 * -# @c recv() on @p tst_s socket with with @c MSG_OOB flag to get
 *    out-of-band data only (the last byte of @c tx_buf2);
 * -# Check that out-of-band data byte successfully obtained;
 * -# Attempt to retrieve the rest of data received through @p tst_s
 *    and check its correctness (See @c Note for details);
 * -# Close all opened sockets and free allocated resources.
 *
 * @note
 * -# @anchor sendrecv_send_OOB_data_1
 *    BSD excludes out-of-band data from receive buffer. Retrieved
 *    data should be tx_buf1[0..DATA_LEN - 2] and next
 *    tx_buf2[0..DATA_LEN - 2].
 * -# @anchor sendrecv_send_OOB_data_2
 *    Linux places unexpected byte between two blocks of ordinary
 *    data. Retrived data should be tx_buf1[0..DATA_LEN - 1] and
 *    next tx_buf2[0..DATA_LEN - 2].
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME "sendrecv/send_oob_data"

#include "sockapi-test.h"
#include "rpc_sendrecv.h"

/* Size of buffer */
#define DATA_LEN      31
#define RX_BUF_LEN    (DATA_LEN * 2)

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    int8_t                  tx_buf1[DATA_LEN];
    int8_t                  tx_buf2[DATA_LEN];
    int8_t                  rx_buf[RX_BUF_LEN];

    int8_t       oob1 = 0xFF;
    int8_t       oob2 = 0xFF;

    int iut_s = -1;
    int tst_s = -1;
    int sent;
    int rcv;

    /* Preambule */
    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    memset(rx_buf, 0, RX_BUF_LEN);
    te_fill_buf(tx_buf1, DATA_LEN);
    te_fill_buf(tx_buf2, DATA_LEN);

    /* Scenario */
    GEN_CONNECTION_FAKE(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_IPPROTO_TCP,
                        tst_addr, iut_addr, &tst_s, &iut_s);

    {
        int optval = FALSE;
        rpc_setsockopt(pco_iut, iut_s, RPC_SO_OOBINLINE, &optval);
    }

    RPC_SEND(sent, pco_tst, tst_s, tx_buf1, DATA_LEN, RPC_MSG_OOB);
    MSLEEP(100);

    /* Try to get OOB data before ordinary bytes */
    rcv = rpc_recv(pco_iut, iut_s, &oob1, 1, RPC_MSG_OOB);
    if (rcv <= 0)
        TEST_FAIL("Attempt to get OOB bytes before ordinary data failed");

    if (oob1 != tx_buf1[DATA_LEN - 1])
        TEST_FAIL("returned OOB byte %d is not the same as "
                  "it was expected %d", oob1, tx_buf1[DATA_LEN - 1]);

    /* Here, receive buffer has ordinary data yet */

    RPC_SEND(sent, pco_tst, tst_s, tx_buf2, DATA_LEN, RPC_MSG_OOB);
    MSLEEP(100);

    /* Try to get OOB data before ordinary bytes */
    rcv = rpc_recv(pco_iut, iut_s, &oob2, 1, RPC_MSG_OOB);
    if (rcv <= 0)
        TEST_FAIL("Attempt to get OOB bytes before ordinary data failed");

    if (oob2 != tx_buf2[DATA_LEN - 1])
        TEST_FAIL("returned OOB byte %d is not the same as "
                  "it was expected %d", oob2, tx_buf2[DATA_LEN - 1]);

    rcv = rpc_recv(pco_iut, iut_s, rx_buf, RX_BUF_LEN, 0);
    RING_VERDICT("recv() returned %d bytes (expected %d)", 
                 rcv, RX_BUF_LEN - 2);
                 
    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    CHECK_CLEAR_TRANSPARENT(iut_addr, pco_tst, tst_addr);

    TEST_END;
}
