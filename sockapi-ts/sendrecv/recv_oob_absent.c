/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Advanced usage of send/receive functions
 *
 * $Id$
 */

/** @page sendrecv-recv_oob_absent Behavior of the TCP socket if the process ask for out-of-band data that has not been sent yet
 *
 * @objective Check that TCP socket returns -1 and @b errno set to @c EINVAL
 *            if the process asks for out-of-band data that has not been 
 *            sent yet.
 *
 * @type conformance
 *
 * @requirement REQ-1, REQ-2, REQ-3
 *
 * @reference @ref STEVENS section 21
 *
 * @param pco_iut   PCO on IUT
 * @param pco_tst   PCO on TST
 *
 * -# Create connection of the @c SOCK_STREAM type between @p pco_iut and
 *    @p pco_tst by means of @c GEN_CONNECTION;
 * -# Call @b recv() with @c MSG_OOB flag on @p iut_s;
 * -# Check that @b recv() returns -1 and @e errno set to the @c EINVAL;
 * -# @b send() one byte data through @p tst_s with @c MSG_OOB flag;
 * -# Call @b recv() with @c MSG_OOB flag on @p iut_s;
 * -# Check that @b recv() returns 1;
 * -# Check that returned @e out-of-band data is the same as sent;
 * -# Call @b recv() with @c MSG_OOB flag on @p iut_s;
 * -# Check that @b recv() returns -1 and @e errno set to the @c EINVAL;
 * -# Close @p iut_s and @p tst_s sockets;
 *
 * @author Igor Vasilev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendrecv/recv_oob_absent"

#include "sockapi-test.h"

#define TST_BUF_SIZE            100

int
main(int argc, char *argv[])
{
    rcf_rpc_server              *pco_iut = NULL;
    rcf_rpc_server              *pco_tst = NULL;

    const struct sockaddr       *iut_addr;
    const struct sockaddr       *tst_addr;

    char                         tx_buf[TST_BUF_SIZE];
    char                         rx_buf[TST_BUF_SIZE];
    int                          iut_s = -1;
    int                          tst_s = -1;

    int                          req_val;
    int                          sent;
    int                          rcv;


    /* Test preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    /* Scenario */
    GEN_CONNECTION_FAKE(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_IPPROTO_TCP,
                        tst_addr, iut_addr, &tst_s, &iut_s);

    /* Try to retrieve OOB data with MSG_OOB flag set */
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rcv = rpc_recv(pco_iut, iut_s, rx_buf, 1, RPC_MSG_OOB);
    if (rcv != -1)
    {
        TEST_FAIL("It's expected to get -1, instead %d, because OOB "
                  "data is absent by this moment");
    }
    CHECK_RPC_ERRNO(pco_iut, RPC_EINVAL, "recv() returns -1, but");

    RPC_SEND(sent, pco_tst, tst_s, tx_buf, 1, RPC_MSG_OOB);
    MSLEEP(100);

    rpc_ioctl(pco_iut, iut_s, RPC_SIOCATMARK, &req_val);
    if (req_val != 1)
    {
        TEST_FAIL("ioctl(SIOCATMARK) does not return out-of-band data marker");
    }

    rcv = rpc_recv(pco_iut, iut_s, rx_buf, TST_BUF_SIZE, RPC_MSG_OOB);
    if (rcv != sent)
    {
        TEST_FAIL("Expected to recieve %d instead %d, because out-of-band "
                  "byte was sent", sent, recv);
    }
    if (memcmp(rx_buf, tx_buf, TST_BUF_SIZE) != 0)
    {
        TEST_FAIL("Data sent is not the same as received one");
    }

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rcv = rpc_recv(pco_iut, iut_s, rx_buf, 1, RPC_MSG_OOB);
    if (rcv != -1)
    {
        TEST_FAIL("It's expected to get -1, instead %d, because OOB "
                  "data is absent by this moment");
    }
    CHECK_RPC_ERRNO(pco_iut, RPC_EINVAL, "recv() returns -1, but");

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    CHECK_CLEAR_TRANSPARENT(iut_addr, pco_tst, tst_addr);

    TEST_END;
}

