/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-post_twice  Post the request twice
 *
 * @objective Check that two requests with the same control block
 *            may be posted twice.
 *
 * @param pco_iut   PCO with IUT
 * @param iut_s     Stream socket on @p pco_iut
 * @param pco_tst   Tester PCO
 * @param tst_s     Stream socket on @p pco_tst
 *
 * @pre Sockets @p iut_s and @p tst_s are connected.
 *
 * @par Scenario
 * -# Post two write requests using one control block @p cb with buffer of the
 *    length N and socket @p iut_s.
 * -# Read data via @p tst_s - 2 * N bytes should be received.
 * -# Call @b aio_error() for @p cb - it should return 0.
 * -# Call @b aio_return() for @p cb - it should return N.
 * -# Post two read requests using one control block via @p iut_s.
 * -# Send two bulks of data of length N via @p tst_s.
 * -# Check that second bulk of data is contained in receive buffer.
 * -# Call @b aio_error() for @p cb - it should return 0.
 * -# Call @b aio_return() for @p cb - it should return N.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "aio/post_twice"

#include "sockapi-test.h"
#include "aio_internal.h"

#define DATA_BULK       1024  /**< Size of data to be sent */

static uint8_t tx_buf[DATA_BULK];         /**< Auxiliary buffer */
static uint8_t rx_buf[DATA_BULK * 2];     /**< Buffer for receiving */

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
    
    rpc_aiocb_p cb;
    rpc_ptr     buf;
    
    tarpc_sigevent ev;
    
    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    
    INIT_EV(&ev);

    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    create_aiocb(pco_iut, iut_s, 0, &buf, DATA_BULK, 
                 DATA_BULK, NULL, &cb);

    te_fill_buf(tx_buf, DATA_BULK);
    rpc_set_buf(pco_iut, tx_buf, DATA_BULK, buf);
    
    rpc_aio_write(pco_iut, cb);
    rpc_aio_write(pco_iut, cb);
    MSLEEP(10);
    
    if ((rc = rpc_read(pco_tst, tst_s, rx_buf, sizeof(rx_buf))) != 
        2 * DATA_BULK)
    {
        TEST_FAIL("Unexpected amount of data is received: %d instead %d",
                  rc, DATA_BULK * 2);
    }
    
    if ((rc = rpc_aio_error(pco_iut, cb)) != 0)
        TEST_FAIL("aio_error() returned %r instead 0 after "
                  "request completion", rc);

    if ((rc = rpc_aio_return(pco_iut, cb)) != DATA_BULK)
        TEST_FAIL("aio_error() returned %d instead %d after "
                  "request completion", rc, DATA_BULK);
                  
    memset(rx_buf, 0, sizeof(rx_buf));                  
    rpc_set_buf(pco_iut, rx_buf, DATA_BULK, buf);
    rpc_aio_read(pco_iut, cb);
    rpc_aio_read(pco_iut, cb);
    
    te_fill_buf(tx_buf, DATA_BULK);
    rpc_write(pco_tst, tst_s, tx_buf, DATA_BULK);
    te_fill_buf(tx_buf, DATA_BULK);
    rpc_write(pco_tst, tst_s, tx_buf, DATA_BULK);

    MSLEEP(10);

    if ((rc = rpc_aio_error(pco_iut, cb)) != 0)
        TEST_FAIL("aio_error() returned %r instead 0 after "
                  "request completion", rc);

    if ((rc = rpc_aio_return(pco_iut, cb)) != DATA_BULK)
        TEST_FAIL("aio_error() returned %d instead %d after "
                  "request completion", rc, DATA_BULK);

    rpc_get_buf(pco_iut, buf, DATA_BULK, rx_buf);
    
    if (memcmp(tx_buf, rx_buf, DATA_BULK) != 0)
        TEST_FAIL("Receive buffer of AIO request contains wrong data");
    
    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    CLEANUP_AIO_CANCEL(pco_iut, iut_s, cb);
    CLEANUP_RPC_DELETE_AIOCB(pco_iut, cb);
    CLEANUP_RPC_FREE(pco_iut, buf);
    
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
                       
    TEST_END;
}
