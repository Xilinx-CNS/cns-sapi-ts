/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-aio_cancel_write  Cancel write request
 *
 * @objective Check that write AIO request may be canceled.
 *
 * @param pco_iut   PCO with IUT
 * @param iut_s     Socket on @p pco_iut
 * @param pco_tst   Tester PCO
 * @param tst_s     Socket on @p pco_tst
 *
 * @pre Sockets @p iut_s and @p tst_s are connected.
 *
 * @par Scenario
 * -# Overfill transmit buffers of @p pco_iut.
 * -# Post 3 AIO write requests on socket @p iut_s using @b aio_write() function.
 * -# Call @b aio_cancel() for the second request.
 * -# Read all data pending on socket @p pco_tst after overfilling
 *    of @p iut_s transmit buffers.
 * -# Check using @b aio_error() that first and third requests are satisfied 
 *    completely while the second one is canceled.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "aio/aio_cancel_write"

#include "sockapi-test.h"
#include "aio_internal.h"

#define DATA_BULK       4096  /**< Size of data to be sent */

static uint8_t tx_buf[DATA_BULK];

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

    rpc_aiocb_p  cb1 = RPC_NULL;
    rpc_aiocb_p  cb2 = RPC_NULL;
    rpc_aiocb_p  cb3 = RPC_NULL;
    rpc_ptr      buf1 = RPC_NULL;
    rpc_ptr      buf2 = RPC_NULL;
    rpc_ptr      buf3 = RPC_NULL;
    
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
    
    /* Allocate buffers on the pco_iut */
    buf1 = rpc_malloc(pco_iut, DATA_BULK);
    rpc_set_buf(pco_iut, tx_buf, DATA_BULK, buf1);
    buf2 = rpc_malloc(pco_iut, DATA_BULK);
    rpc_set_buf(pco_iut, tx_buf, DATA_BULK, buf2);
    buf3 = rpc_malloc(pco_iut, DATA_BULK);
    rpc_set_buf(pco_iut, tx_buf, DATA_BULK, buf3);

    /* Create and fill aiocb for three AIO functions*/
    cb1 = rpc_create_aiocb(pco_iut);
    rpc_fill_aiocb(pco_iut, cb1, iut_s, 0, 0, buf1, DATA_BULK, &ev);
    cb2 = rpc_create_aiocb(pco_iut);
    rpc_fill_aiocb(pco_iut, cb2, iut_s, 0, 0, buf2, DATA_BULK, &ev);
    cb3 = rpc_create_aiocb(pco_iut);
    rpc_fill_aiocb(pco_iut, cb3, iut_s, 0, 0, buf3, DATA_BULK, &ev);
    
     /* Post AIO write requests */
    rpc_aio_write(pco_iut, cb1);
    rpc_aio_write(pco_iut, cb2);
    rpc_aio_write(pco_iut, cb3);

    /* Post AIO cancel request */
    if((rc = rpc_aio_cancel(pco_iut, iut_s, cb2)) != RPC_AIO_CANCELED)
        TEST_FAIL("aio_cancel() returned %r", rc);
    
    /* Read all information from the socket. */
    rpc_simple_receiver(pco_tst, tst_s, 0, &n);

    /* Check errors. */
    if ((rc = rpc_aio_error(pco_iut, cb1)) != 0)
        TEST_FAIL("aio_error() returned %r for the first request", rc);
    if ((rc = rpc_aio_error(pco_iut, cb2)) != RPC_ECANCELED)
        TEST_FAIL("aio_error() returned %r instead ECANCELED "
                  "for the second request", rc);
    if ((rc = rpc_aio_error(pco_iut, cb3)) != 0)
        TEST_FAIL("aio_error() returned %r for the third request", rc);
    
    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_DELETE_AIOCB(pco_iut, cb1);
    CLEANUP_RPC_FREE(pco_iut, buf1);
    CLEANUP_RPC_DELETE_AIOCB(pco_iut, cb2);
    CLEANUP_RPC_FREE(pco_iut, buf2);
    CLEANUP_RPC_DELETE_AIOCB(pco_iut, cb3);
    CLEANUP_RPC_FREE(pco_iut, buf3);
    
    TEST_END;
}
