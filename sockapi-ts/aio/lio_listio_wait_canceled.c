/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-lio_listio_wait_canceled  Cancel a request posted by lio_listio(LIO_WAIT)
 *
 * @objective Check that @b lio_listio(@c LIO_WAIT) succeeds  
 *            if one of requests in the list is canceled.
 *
 * @param pco_iut   PCO with IUT
 * @param iut_s     Socket on @p pco_iut
 * @param pco_tst   Tester PCO
 * @param tst_s     Socket on @p pco_tst
 *
 * @pre Sockets @p iut_s and @p tst_s are connected.
 *
 * @par Scenario
 * -# Create 2 AIO read request control blocks on socket @p iut_s.
 * -# Post requests using @b lio_listio(@c LIO_WAIT).
 * -# Call @b aio_cancel() for the second request.
 * -# Check that @b lio_listio() is blocked yet.
 * -# Send 2 bulks of data via @p tst_s to satisfy both requests.
 * -# Check that @b lio_listio() is unblocked and returned 0.
 * -# Check using @b aio_error() that first request is satisfied while the 
 *    second one is canceled.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "aio/lio_listio_wait_canceled"
#include "sockapi-test.h"
#include "aio_internal.h"

#define DATA_BULK       1024                /**< Size of data to be sent */
#define LIST_LEN        2                   /**< Number of calls in the list */



int
main(int argc, char *argv[])
{
    /* Environment variables */
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    rcf_rpc_server         *pco_iut1 = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    /* Auxiliary variables */
    int                     iut_s = -1;
    int                     tst_s = -1;

    rpc_aiocb_p             lio_cb[LIST_LEN];
    rpc_ptr                 buf = RPC_NULL;
    int                     tx_buf[DATA_BULK];
    tarpc_sigevent          ev;
    int                     i;
    te_bool                 done;

    
    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);
    
    /* Allocate buffer on the pco_iut */
    buf = rpc_malloc(pco_iut, DATA_BULK);
    INIT_EV(&ev);

    lio_cb[0] = rpc_create_aiocb(pco_iut);
    rpc_fill_aiocb(pco_iut, lio_cb[0], iut_s, RPC_LIO_READ, 0, buf, 
                   DATA_BULK, &ev);
    lio_cb[1] = rpc_create_aiocb(pco_iut);
    rpc_fill_aiocb(pco_iut, lio_cb[1], iut_s, RPC_LIO_READ, 0, buf, 
                   DATA_BULK, &ev);
    rcf_rpc_server_thread_create(pco_iut, "pco_iut1", &pco_iut1);
    
    pco_iut->op = RCF_RPC_CALL;
    rpc_lio_listio(pco_iut, RPC_LIO_WAIT, lio_cb, LIST_LEN, &ev);

    if (rpc_aio_cancel(pco_iut1, iut_s, lio_cb[1]) == RPC_AIO_ALLDONE)
    {
        WARN("Did not manage to cancel second read request - "
             "test result is useless");
        TEST_SUCCESS;
    }
    
    rcf_rpc_server_is_op_done(pco_iut, &done);
    if (done != 0)
        TEST_FAIL("Unexpected behavior of lio_listio()");
    
    rpc_write(pco_tst, tst_s, tx_buf, DATA_BULK);
    rpc_write(pco_tst, tst_s, tx_buf, DATA_BULK);

    pco_iut->op = RCF_RPC_WAIT;
    rpc_lio_listio(pco_iut, RPC_LIO_WAIT, lio_cb, LIST_LEN, &ev);
    
    if ((rc = rpc_aio_error(pco_iut, lio_cb[0])) != 0)
        TEST_FAIL("aio_error() returned %r instead 0", rc);
    
    if ((rc = rpc_aio_error(pco_iut, lio_cb[1])) != RPC_ECANCELED)
        TEST_FAIL("aio_error() returned %r instead ECANCELED", rc);
    
    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    
    if (pco_iut1 != NULL)
    {
        if (rcf_rpc_server_destroy(pco_iut1) < 0)
            ERROR("Failed to destroy thread RPC server on the IUT");
    }

    for (i = 0; i < LIST_LEN; i++)
        CLEANUP_RPC_DELETE_AIOCB(pco_iut, lio_cb[i]);
    
    CLEANUP_RPC_FREE(pco_iut, buf);
    
    TEST_END;
}

