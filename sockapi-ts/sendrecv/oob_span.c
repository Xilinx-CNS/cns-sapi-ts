/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Advanced usage of send/receive functions
 *
 * $Id$
 */

/** @page sendrecv-oob_span Check spanning of OOB data bytes on receiver side
 *
 * @objective Check that several OOB bytes sent one-by-one are not lost
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TESTER
 * @param iut_s         IUT TCP socket
 * @param tst_s         TESTER TCP socket
 * @param oobinline     if @c TRUE, @c SO_OOBINLINE should be set to TRUE
 *                      on @p iut_s
 *
 * @pre Sockets @p iut_s and @p tst_s are connected.
 *
 * @par Scenario
 * -# Set @c SO_OOBINLINE socket option on @p iut_s according to @p oobinline
 *    parameter.
 * -# Send 3 bulks of the length @p N of data with @c MSG-OOB flag via @p tst_s.
 * -# Call @b recv() on @p iut_s providing a buffer of the length
 *    N * 3. If @p oobinline is @c FALSE, flag @c MSG_OOB should be passed
 *    @b recv().
 * -# If @p oobinline is @c TRUE, @b recv() should return 3 - last bytes
 *    of each bulk.
 * -# Otherwise @b recv() should return N * 3.
 * -# If @p oobinline is @c TRUE call @b recv() again to get the rest of data.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 * @author Igor Baryshev <Igor.Baryshev@oktetlabs.ru>
 */

#define TE_TEST_NAME "sendrecv/oob_span"

#include "sockapi-test.h"
#include "rpc_sendrecv.h"

/* Size of buffer */
#define DATA_LEN      31
#define RX_BUF_LEN    (DATA_LEN * 3 * 10) /* x10: just want it roomy */

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;
    te_bool                 oobinline;

    int8_t                  tx_buf1[DATA_LEN];
    int8_t                  tx_buf2[DATA_LEN];
    int8_t                  tx_buf3[DATA_LEN];
    int8_t                  rx_buf[RX_BUF_LEN];
    int8_t                  *rx_p;
    rpc_send_recv_flags     flags = 0;

    int iut_s = -1;
    int tst_s = -1;
    int sent;
    int rcv;
    int optval;
    int rx_room;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(oobinline);
    
    optval = oobinline;
    
    if (!oobinline)
        flags = RPC_MSG_OOB;

    memset(rx_buf, 0, RX_BUF_LEN);
    te_fill_buf(tx_buf1, DATA_LEN);
    te_fill_buf(tx_buf2, DATA_LEN);
    te_fill_buf(tx_buf3, DATA_LEN);

    GEN_CONNECTION_FAKE(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_IPPROTO_TCP,
                        tst_addr, iut_addr, &tst_s, &iut_s);

    rpc_setsockopt(pco_iut, iut_s, RPC_SO_OOBINLINE, &optval);
        
    RPC_SEND(sent, pco_tst, tst_s, tx_buf1, DATA_LEN, RPC_MSG_OOB);
    RPC_SEND(sent, pco_tst, tst_s, tx_buf2, DATA_LEN, RPC_MSG_OOB);
    RPC_SEND(sent, pco_tst, tst_s, tx_buf3, DATA_LEN, RPC_MSG_OOB);
    
    MSLEEP(10);

    rcv = rpc_recv(pco_iut, iut_s, rx_buf, RX_BUF_LEN, flags);
    
    if (oobinline)
    {
        if (rcv == DATA_LEN * 3 - 1)
        {
            RING_VERDICT("All data except the last OOB are returned "
                         "by the first recv()");
                         
            if (rpc_recv(pco_iut, iut_s, rx_buf, RX_BUF_LEN, 0) != 1)
                TEST_VERDICT("Failed to get last OOB byte");
                
            TEST_SUCCESS;
        }

        if (rcv == DATA_LEN * 3)
        {
            if (memcmp(rx_buf, tx_buf1, DATA_LEN) != 0 || 
                memcmp(rx_buf + DATA_LEN, tx_buf2, DATA_LEN) != 0 || 
                memcmp(rx_buf + DATA_LEN * 2, tx_buf3, DATA_LEN) != 0)
            {
                TEST_FAIL("Data are reordered or corrupted");
            }
 
            RING_VERDICT("All data including the last OOB are returned "
                         "by the first recv()");
            TEST_SUCCESS;
        }
        
        if (rcv == DATA_LEN - 1)  /* Possibly Solaris behavior */
        {  /* just keep reading it all (error: if not Solaris) */
            rx_p = rx_buf;
            rx_room = RX_BUF_LEN;

            rx_p +=rcv;
            rx_room -=rcv;
            RPC_AWAIT_IUT_ERROR(pco_iut);
            rcv = rpc_recv(pco_iut, iut_s, rx_p, rx_room, 0);
            if (rcv != DATA_LEN) goto bad_oobinline;

            rx_p +=rcv;
            rx_room -=rcv;
            RPC_AWAIT_IUT_ERROR(pco_iut);
            rcv = rpc_recv(pco_iut, iut_s, rx_p, rx_room, 0);
            if (rcv != DATA_LEN) goto bad_oobinline;

            rx_p +=rcv;
            rx_room -=rcv;
            RPC_AWAIT_IUT_ERROR(pco_iut);
            rcv = rpc_recv(pco_iut, iut_s, rx_p, rx_room, 0);
            if (rcv != 1) goto bad_oobinline;

            if (memcmp(rx_buf, tx_buf1, DATA_LEN) == 0 &&
                memcmp(rx_buf + DATA_LEN, tx_buf2, DATA_LEN) == 0 && 
                memcmp(rx_buf + DATA_LEN * 2, tx_buf3, DATA_LEN) == 0)
            {
                RING_VERDICT("All (OOB and ordinary) data are returned "
                             "by a sequence of recv()'s");
                TEST_SUCCESS;
            }

            /* Solaris or not, but something is wrong: */
            goto bad_oobinline;
        }

bad_oobinline:        
        TEST_VERDICT("recv() does not return all (OOB and ordinary) data "
                         "whereas OOBINLINE is enabled");
    } /* The end of the oobinline iteration */


    if (rcv > 3)
        TEST_VERDICT("Ordinary data are received with OOB");

    if (rcv < 3)
        TEST_VERDICT("Some OOB data are no received");
        
    if (rx_buf[0] != tx_buf1[DATA_LEN - 1] ||
        rx_buf[1] != tx_buf2[DATA_LEN - 1] ||
        rx_buf[2] != tx_buf3[DATA_LEN - 1])
    {
        TEST_FAIL("OOB are re-ordered or corrupted");
    }
    if (rpc_recv(pco_iut, iut_s, rx_buf, RX_BUF_LEN, 0) != 
        DATA_LEN * 3 - 3)
    {
        TEST_FAIL("recv() for ordinary data returned unexpected value");
    }

    if (memcmp(rx_buf, tx_buf1, DATA_LEN - 1) != 0 || 
        memcmp(rx_buf + DATA_LEN - 1, tx_buf2, DATA_LEN - 1) != 0 || 
        memcmp(rx_buf + DATA_LEN * 2 - 2, tx_buf3, DATA_LEN - 1) != 0)
    {
        TEST_FAIL("Ordinary data are reordered or corrupted");
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    CHECK_CLEAR_TRANSPARENT(iut_addr, pco_tst, tst_addr);

    TEST_END;
}
