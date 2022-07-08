/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-aio_cancel_thread  Cancel request posted from other thread/process
 *
 * @objective Check that AIO request may be canceled from the other
 *            thread or process.
 *
 * @param pco_iut   PCO with IUT
 * @param iut_s     Socket on @p pco_iut
 * @param pco_tst   Tester PCO
 * @param tst_s     Socket on @p pco_tst
 * @param op        operation to be canceled ("read" or "write")
 *
 * @pre Sockets @p iut_s and @p tst_s are connected.
 *
 * @par Scenario
 * -# If @p op is "write", overfill transmit buffers of @p pco_iut.
 * -# Post two @p op AIO requests on socket @p iut_s.
 * -# Create thread @p pco_chld of @p pco_iut.
 * -# Call @b aio_cancel() for the second request in @p pco_chld context.
 * -# If @p op is "read", send two bulks of data to satisfy both requests.
 *    Otherwise read all data pending on socket @p tst_s after overfilling
 *    of @p iut_s transmit buffers.
 * -# Check using @b aio_error() that first request is satisfied completely
 *    while the second one is canceled.
 * -# Destroy @p pco_chld.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "aio/aio_cancel_thread"

#include "sockapi-test.h"
#include "aio_internal.h"

#define DATA_BULK       4096  /**< Size of data to be sent */

static char tx_buf[DATA_BULK];

int
main(int argc, char *argv[])
{
    /* Environment variables */
    const char         *op;

    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_chld = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    /* Auxiliary variables */
    int iut_s = -1;
    int tst_s = -1;

    rpc_aiocb_p  cb1 = RPC_NULL;
    rpc_aiocb_p  cb2 = RPC_NULL;
    rpc_ptr      buf1 = RPC_NULL;
    rpc_ptr      buf2 = RPC_NULL;
    
    tarpc_sigevent ev;

    uint64_t n;
     
    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_STRING_PARAM(op);
    
    memset(&ev, 0, sizeof(ev));
    ev.notify = RPC_SIGEV_NONE;
    
    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    te_fill_buf(tx_buf, DATA_BULK);

    /* Overfill buffers in specifed case. */
    if (strcmp(op, "write") == 0)
        rpc_overfill_buffers(pco_iut, iut_s, &n);

    /* Allocate buffer on the pco_iut */
    buf1 = rpc_malloc(pco_iut, DATA_BULK);
    buf2 = rpc_malloc(pco_iut, DATA_BULK);

    /* Create and fill aiocb */
    cb1 = rpc_create_aiocb(pco_iut);
    rpc_fill_aiocb(pco_iut, cb1, iut_s, 0, 0, buf1, DATA_BULK, &ev);
    cb2 = rpc_create_aiocb(pco_iut);
    rpc_fill_aiocb(pco_iut, cb2, iut_s, 0, 0, buf2, DATA_BULK, &ev);

    /* Post AIO requests */
    if (strcmp(op, "write") == 0)
    {
        rpc_aio_write(pco_iut, cb1);
        rpc_aio_write(pco_iut, cb2);
    }
    else
    {
        rpc_aio_read(pco_iut, cb1);
        rpc_aio_read(pco_iut, cb2);
    }
    
    /* Create child process. */
    CHECK_RC(rcf_rpc_server_thread_create(pco_iut, "IUT_thread",
                                          &pco_chld));

    /* Cancel request */
    if((rc = rpc_aio_cancel(pco_chld, iut_s, cb2)) != RPC_AIO_CANCELED)
        TEST_FAIL("aio_cancel() returned %r", rc);

    /* Set conditions for ending AIO requests. */
    if (strcmp(op, "write") == 0)
    {
        rpc_simple_receiver(pco_tst, tst_s, 0, &n);
    }
    else
    {
        rpc_write(pco_tst, tst_s, tx_buf, DATA_BULK);
        rpc_write(pco_tst, tst_s, tx_buf, DATA_BULK);
    }
    
    MSLEEP(10);
    
    /* Check errors. */
    if ((rc = rpc_aio_error(pco_iut, cb1)) != 0)
        TEST_FAIL("aio_error() returned %r for the first request", rc);
    if ((rc = rpc_aio_error(pco_iut, cb2)) != RPC_ECANCELED)
        TEST_FAIL("aio_error() returned %r instead ECANCELED "
                  "for the second request", rc);

    TEST_SUCCESS;
cleanup:
    if (pco_chld != NULL)
    {
        if (rcf_rpc_server_destroy(pco_chld) < 0)
            ERROR("Failed to destroy thread RPC server on the IUT");
    }
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_DELETE_AIOCB(pco_iut, cb1);
    CLEANUP_RPC_FREE(pco_iut, buf1);
    CLEANUP_RPC_DELETE_AIOCB(pco_iut, cb2);
    CLEANUP_RPC_FREE(pco_iut, buf2);
    
    TEST_END;
}
