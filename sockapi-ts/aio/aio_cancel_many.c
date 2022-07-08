/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-aio_cancel_many  Cancel all requests corresponding to socket
 *
 * @objective Check that @b aio_cancel() called with @c NULL control block
 *            cancels all requests associated with the socket.
 *
 * @param pco_iut   PCO with IUT
 * @param iut_s     Socket on @p pco_iut
 * @param pco_tst   Tester PCO
 * @param tst_s     Socket on @p pco_tst
 *
 * @pre Sockets @p iut_s and @p tst_s are connected.
 *
 * @par Scenario
 * -# Overfill transmit buffers on the socket @p iut_s.
 * -# Post several AIO read and write requests on socket @p iut_s using 
 *    @b aio_read() and @p aio_write() function.
 * -# Call @p aio_cancel() with parameters @p iut_s and @c NULL.
 * -# If @c AIO_CANCELED is returned, check that @b aio_error() returns
 *    @c ECANCELED for all AIO requests.
 * -# If @c AIO_NOTCANCELED is returned, check that @b aio_error() returns
 *    @c ECANCELED or @c EINPROGRESS for all AIO requests.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "aio/aio_cancel_many"

#include "sockapi-test.h"
#include "aio_internal.h"

#define DATA_BULK       4096  /**< Size of data to be sent */

int
main(int argc, char *argv[])
{
    /* Environment variables */

    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    /* Auxiliary variables */
    int iut_s = -1;
    int tst_s = -1;

    rpc_aiocb_p  cb_r1 = RPC_NULL;
    rpc_aiocb_p  cb_r2 = RPC_NULL;
    rpc_aiocb_p  cb_w1 = RPC_NULL;
    rpc_aiocb_p  cb_w2 = RPC_NULL;
    rpc_ptr      rx_buf1 = RPC_NULL;
    rpc_ptr      rx_buf2 = RPC_NULL;
    rpc_ptr      tx_buf1 = RPC_NULL;
    rpc_ptr      tx_buf2 = RPC_NULL;
    
    tarpc_sigevent ev;

    uint64_t n;
     
    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    
    memset(&ev, 0, sizeof(ev));
    ev.notify = RPC_SIGEV_NONE;
    
    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    rpc_overfill_buffers(pco_iut, iut_s, &n);

    /* Allocate buffer on the pco_iut */
    tx_buf1 = rpc_malloc(pco_iut, DATA_BULK);
    tx_buf2 = rpc_malloc(pco_iut, DATA_BULK);
    rx_buf1 = rpc_malloc(pco_iut, DATA_BULK);
    rx_buf2 = rpc_malloc(pco_iut, DATA_BULK);
    
    /* Create and fill aiocb */
    cb_w1 = rpc_create_aiocb(pco_iut);
    rpc_fill_aiocb(pco_iut, cb_w1, iut_s, 0, 0, tx_buf1, DATA_BULK, &ev);
    cb_w2 = rpc_create_aiocb(pco_iut);
    rpc_fill_aiocb(pco_iut, cb_w2, iut_s, 0, 0, tx_buf2, DATA_BULK, &ev);
    
    cb_r1 = rpc_create_aiocb(pco_iut);
    rpc_fill_aiocb(pco_iut, cb_r1, iut_s, 0, 0, rx_buf1, DATA_BULK, &ev);
    cb_r2 = rpc_create_aiocb(pco_iut);
    rpc_fill_aiocb(pco_iut, cb_r2, iut_s, 0, 0, rx_buf2, DATA_BULK, &ev);
    
    /* Post AIO requests */
    rpc_aio_write(pco_iut, cb_w1);
    rpc_aio_write(pco_iut, cb_w2);
    rpc_aio_read(pco_iut, cb_r1);
    rpc_aio_read(pco_iut, cb_r2);

    /* Cancel all request */
    rc = rpc_aio_cancel(pco_iut, iut_s, RPC_NULL);
    if ((rc == RPC_AIO_CANCELED) || (rc == RPC_AIO_NOTCANCELED))
    {
        if (rc == RPC_AIO_CANCELED)
        {
            rc = rpc_aio_error(pco_iut, cb_w1);
            if (rc != RPC_ECANCELED)
                TEST_FAIL("aio_error() for the first write request returned "
                          "%r instead ECANCELED", rc);
            rc = rpc_aio_error(pco_iut, cb_w2);
            if (rc != RPC_ECANCELED)
                TEST_FAIL("aio_error() for the second write request returned "
                          "%r instead ECANCELED", rc);
            rc = rpc_aio_error(pco_iut, cb_r1);
            if (rc != RPC_ECANCELED)
                TEST_FAIL("aio_error() for the first read request returned "
                          "%r instead ECANCELED", rc);
            rc = rpc_aio_error(pco_iut, cb_r2);
            if (rc != RPC_ECANCELED)
                TEST_FAIL("aio_error() for the second read request returned "
                          "%r instead ECANCELED", rc);
        }
        else
        {
            rc = rpc_aio_error(pco_iut, cb_w1);
            if ((rc != RPC_ECANCELED) && (rc != RPC_EINPROGRESS))
                TEST_FAIL("aio_error() for the first write request returned "
                          "unexpected errno %r", rc);
            rc = rpc_aio_error(pco_iut, cb_w2);
            if ((rc != RPC_ECANCELED) && (rc != RPC_EINPROGRESS))
                TEST_FAIL("aio_error() for the second write request returned "
                          "unexpected errno %r", rc);
            rc = rpc_aio_error(pco_iut, cb_r1);
            if ((rc != RPC_ECANCELED) && (rc != RPC_EINPROGRESS))
                TEST_FAIL("aio_error() for the first read request returned "
                          "unexpected errno %r", rc);
            rc = rpc_aio_error(pco_iut, cb_r2);
            if ((rc != RPC_ECANCELED) && (rc != RPC_EINPROGRESS))
                TEST_FAIL("aio_error() for the second read request returned "
                          "unexpected errno %r", rc);
        }
    }
    else
        TEST_FAIL("aio_cancel() returned %r", rc);

    TEST_SUCCESS;
    
cleanup:
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_AIO_CANCEL(pco_iut, iut_s, cb_w1);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    CLEANUP_RPC_DELETE_AIOCB(pco_iut, cb_w1);
    CLEANUP_RPC_DELETE_AIOCB(pco_iut, cb_w2);
    CLEANUP_RPC_DELETE_AIOCB(pco_iut, cb_r1);
    CLEANUP_RPC_DELETE_AIOCB(pco_iut, cb_r2);
    CLEANUP_RPC_FREE(pco_iut, rx_buf1);
    CLEANUP_RPC_FREE(pco_iut, rx_buf2);
    CLEANUP_RPC_FREE(pco_iut, tx_buf1);
    CLEANUP_RPC_FREE(pco_iut, tx_buf2);
    
    TEST_END;
}
