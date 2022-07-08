/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-aio_write_blk_write  Simultaneous use AIO and blocking write
 *
 * @objective Check that asynchronous and synchronous write operations
 *            many be used simultaneously.
 *
 * @param pco_iut   PCO with IUT
 * @param iut_s     Socket on @p pco_iut
 * @param pco_tst   Tester PCO
 * @param tst_s     Socket on @p pco_tst
 *
 * @pre Sockets @p iut_s and @p tst_s are connected.
 *
 * @par Scenario
 * -# Post AIO write request on socket @p iut_s with buffer @p buf1.
 * -# Call @b write() function on @p iut_s with buffer @p buf2.
 * -# Verify that AIO request is satisfied using @p aio_error().
 * -# Call @b aio_return() for AIO control block - it should return length
 *    of the @p buf1.
 * -# Receive data via @p tst_s.
 * -# Verify that first bulk of data received via @p tst_s is equal to data
 *    stored in @p buf1 and second bulk of data is equal to data stored
 *    in @p buf2. Produce warning if second bulk of data is equal to data
 *    stored in @p buf1 and first bulk of data is equal to data stored in
 *    @p buf2.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "aio/aio_write_blk_write"
#include "sockapi-test.h"
#include "aio_internal.h"

#define DATA_BULK       1024  /**< Size of data to be sent */

static uint8_t rx_buf1[DATA_BULK];
static uint8_t rx_buf2[DATA_BULK];
static uint8_t tx_buf1[DATA_BULK];
static uint8_t tx_buf2[DATA_BULK];

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
    
    int size = -1;

    rpc_aiocb_p  cb = RPC_NULL;
    rpc_ptr      buf = RPC_NULL;

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

    te_fill_buf(tx_buf1, DATA_BULK);
    te_fill_buf(tx_buf2, DATA_BULK);

    /* Allocate buffer on the pco_iut */
    buf = rpc_malloc(pco_iut, DATA_BULK);
    rpc_set_buf(pco_iut, tx_buf1, DATA_BULK, buf);

    /* Create and fill aiocb */
    cb = rpc_create_aiocb(pco_iut);
    rpc_fill_aiocb(pco_iut, cb, iut_s, 0, 0, buf, DATA_BULK, &ev);

    /* Post AIO write request */
    rpc_aio_write(pco_iut, cb);
    
    /* Post blocking write request */
    size = rpc_write(pco_iut, iut_s, tx_buf2, DATA_BULK);
    if (size != DATA_BULK)
        TEST_FAIL("write() returned %d instead %d", rc, DATA_BULK);
        
    /* Recieve data */
    rc = rpc_recv(pco_tst, tst_s, rx_buf1, DATA_BULK, 0);
    if (rc != DATA_BULK)
        TEST_FAIL("First recv() returned %d instead %d", rc, DATA_BULK);
    rc = rpc_recv(pco_tst, tst_s, rx_buf2, DATA_BULK, 0);
    if (rc != DATA_BULK)
        TEST_FAIL("Second recv() returned %d instead %d", rc, DATA_BULK);
    
    /* Check errors */
    if ((rc = rpc_aio_error(pco_iut, cb)) != 0)
        TEST_FAIL("aio_error() returned %r after request finishing", rc);
    if ((rc = rpc_aio_return(pco_iut, cb)) != DATA_BULK)
        TEST_FAIL("aio_return() returned %d instead %d", rc, DATA_BULK);
        
    /* Compare buffers */
    if (memcmp(tx_buf1, rx_buf1, DATA_BULK) != 0)
    {
        if (memcmp(tx_buf1, rx_buf2, DATA_BULK) != 0)
            TEST_FAIL("Data sent using aio_write() are corrupted");
    
        if (memcmp(tx_buf2, rx_buf1, DATA_BULK) != 0)
            TEST_FAIL("Data sent using write() are corrupted");
            
        WARN("Bulks posted aio_write() and write() are sent "
             "in reverse order");
    }
    else if (memcmp(tx_buf2, rx_buf2, DATA_BULK) != 0)
        TEST_FAIL("Data sent using write() are corrupted");
    
    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_DELETE_AIOCB(pco_iut, cb);
    CLEANUP_RPC_FREE(pco_iut, buf);
    
    TEST_END;
}
