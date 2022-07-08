/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-aio_cancel_read  Cancel read request
 *
 * @objective Check that read AIO request may be canceled.
 *
 * @param pco_iut   PCO with IUT
 * @param iut_s     Socket on @p pco_iut
 * @param pco_tst   Tester PCO
 * @param tst_s     Socket on @p pco_tst
 *
 * @pre Sockets @p iut_s and @p tst_s are connected.
 *
 * @par Scenario
 * -# Post 3 AIO read requests on socket @p iut_s using @b aio_read() function.
 * -# Call @b aio_cancel() for the second request.
 * -# Send 3 bulks of data to satisfy both requests.
 * -# Check using @b aio_error() that first and third requests are satisfied 
 *    completely while the second one is canceled.
 * -# Check that buffer of the second request has not been changed.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "aio/aio_cancel_read"
#include "sockapi-test.h"
#include "aio_internal.h"

#define DATA_BULK       1024  /**< Size of data to be sent */

static char tx_buf[DATA_BULK];
static char rx_buf_b[DATA_BULK + 1];
static char rx_buf_e[DATA_BULK + 1];

int
main(int argc, char *argv[])
{
    /* Environment variables */
    rpc_socket_type     sock_type;

    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    /* Auxiliary variables */
    int iut_s = -1;
    int tst_s = -1;

    int len;
    
    rpc_aiocb_p  cb1 = RPC_NULL;
    rpc_aiocb_p  cb2 = RPC_NULL;
    rpc_aiocb_p  cb3 = RPC_NULL;
    rpc_ptr      buf1 = RPC_NULL;
    rpc_ptr      buf2 = RPC_NULL;
    rpc_ptr      buf3 = RPC_NULL;
    
    tarpc_sigevent ev;
     
    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);

    memset(&ev, 0, sizeof(ev));
    ev.notify = RPC_SIGEV_NONE;

    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    /* Allocate buffer on the pco_iut */
    buf1 = rpc_malloc(pco_iut, DATA_BULK + 1);
    buf2 = rpc_malloc(pco_iut, DATA_BULK + 1);
    buf3 = rpc_malloc(pco_iut, DATA_BULK + 1);
    
    rpc_get_buf(pco_iut, buf2, DATA_BULK, (uint8_t *)rx_buf_b);
    
    /* Create and fill aiocb */
    cb1 = rpc_create_aiocb(pco_iut);
    rpc_fill_aiocb(pco_iut, cb1, iut_s, 0, 0, buf1, DATA_BULK + 1, &ev);
    cb2 = rpc_create_aiocb(pco_iut);
    rpc_fill_aiocb(pco_iut, cb2, iut_s, 0, 0, buf2, DATA_BULK + 1, &ev);
    cb3 = rpc_create_aiocb(pco_iut);
    rpc_fill_aiocb(pco_iut, cb3, iut_s, 0, 0, buf3, DATA_BULK + 1, &ev);

    /* Post AIO read requests */
    rpc_aio_read(pco_iut, cb1);
    rpc_aio_read(pco_iut, cb2);
    rpc_aio_read(pco_iut, cb3);

    /* Post AIO cancel request */
    if ((rc = rpc_aio_cancel(pco_iut, iut_s, cb2)) != RPC_AIO_CANCELED)
        TEST_FAIL("aio_cancel() returned %d instead AIO_CANCELED", rc);

    RPC_SEND(len, pco_tst, tst_s, tx_buf, DATA_BULK, 0);
    RPC_SEND(len, pco_tst, tst_s, tx_buf, DATA_BULK, 0);
    RPC_SEND(len, pco_tst, tst_s, tx_buf, DATA_BULK, 0);
    
    MSLEEP(10);

    /* Check errors */
    if (rpc_aio_error(pco_iut, cb1) != 0)
        TEST_FAIL("aio_error() for the first read request returned "
                  "unexpected errno %r", rc);
    if ((rc = rpc_aio_error(pco_iut, cb2)) != RPC_ECANCELED)
        TEST_FAIL("aio_error() for the second read request returned "
                  "unexpected errno %r", rc);
    if ((rc = rpc_aio_error(pco_iut, cb3)) != 0)
        TEST_FAIL("aio_error() for the third read request returned "
                  "unexpected errno %r", rc);

    /* Check buffer of the second AIO request */
    rpc_get_buf(pco_iut, buf2, DATA_BULK, (uint8_t *)rx_buf_e);
    if (memcmp(rx_buf_b, rx_buf_e, DATA_BULK) != 0)
        TEST_FAIL("Buffer corresponding to cancelled request is changed");
    
    TEST_SUCCESS;

cleanup:
        
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_AIO_CANCEL(pco_iut, iut_s, cb2);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    CLEANUP_RPC_DELETE_AIOCB(pco_iut, cb1);
    CLEANUP_RPC_DELETE_AIOCB(pco_iut, cb2);
    CLEANUP_RPC_DELETE_AIOCB(pco_iut, cb3);
    CLEANUP_RPC_FREE(pco_iut, buf1);
    CLEANUP_RPC_FREE(pco_iut, buf2);
    CLEANUP_RPC_FREE(pco_iut, buf3);

    TEST_END;
}
