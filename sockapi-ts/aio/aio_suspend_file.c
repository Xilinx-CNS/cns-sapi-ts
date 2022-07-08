/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-aio_suspend_file  Suspending on asynchronous events on socket and file
 *
 * @objective Check that @b aio_suspend() works properly when it is called on
 *            AIO requests which operate with socket and file.
 *
 * @type conformance
 *
 * @param pco_iut   PCO with IUT
 * @param iut_s     Socket on @p pco_iut
 * @param pco_tst   Tester PCO
 * @param tst_s     Socket on @p pco_tst
 * @param op        Operation ("read" or "write")
 * 
 * @pre Sockets @p iut_s and @p tst_s are connected.
 *
 * -# Create @p f file with some data on @p pco_iut.
 * -# If @p op is "write", overfill transmit buffers of @p pco_iut.
 * -# Post two @p op AIO requests: one on @p iut_s socket and one on @p f
 *    file.
 * -# Suspend using @b aio_suspend() for list of posted requests and
 *    @c NULL timeout.
 * -# If @p op is "read" send data via @p tst_s socket.
 *    If @p op is "write" receive data via @p tst_s socket.
 *    After this action @b aio_suspend() should unblock.
 * -# Check that @b aio_error() returns @c 0 for each control block.
 * -# Check that @b aio_return() for each control block returns correct length.
 * -# Remove @p f file.
 *
 * @post Sockets @p iut_s and @p tst_s are kept connected.
 * 
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "aio/aio_suspend_file"

#include "sockapi-test.h"
#include "aio_internal.h"

#define DATA_BULK       1024  /**< Size of data to be sent */
#define FILENAME        "/tmp/te_aio_suspend_file"

static uint8_t tx_buf[DATA_BULK];

int
main(int argc, char *argv[])
{
    /* Environment variables */
    const char         *op;

    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    /* Auxiliary variables */
    int  iut_s = -1;
    int  fd = -1;
    int  tst_s = -1;
    int  len;
    char fname[128] = { 0, };

    uint64_t n;

    rpc_aiocb_p  cb[2] = { RPC_NULL, RPC_NULL };
    rpc_ptr      buf1 = RPC_NULL;
    rpc_ptr      buf2 = RPC_NULL;
    
    tarpc_sigevent ev;
    
    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_STRING_PARAM(op);
    
    INIT_EV(&ev);

    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    /* Overfill transmit buffer in specified case */
    if (strcmp(op, "write") == 0)
        rpc_overfill_buffers(pco_iut, iut_s, &n);

    /* Create and open file */
    TE_SPRINTF(fname, "%s_%d", FILENAME, rand_range(0, 100000));
    fd = rpc_open(pco_iut, fname, RPC_O_RDWR | RPC_O_CREAT,
                  RPC_S_IRWXU);
    rpc_write(pco_iut, fd, tx_buf, DATA_BULK);
    RPC_CLOSE(pco_iut, fd);
    fd = rpc_open(pco_iut, fname, RPC_O_RDWR, RPC_S_IRWXU);

    /* Post AIO requests */
    te_fill_buf(tx_buf, DATA_BULK);
        
    buf1 = rpc_malloc(pco_iut, DATA_BULK);
    buf2 = rpc_malloc(pco_iut, DATA_BULK);
    rpc_set_buf(pco_iut, tx_buf, DATA_BULK, buf1);
    rpc_set_buf(pco_iut, tx_buf, DATA_BULK, buf2);
     
    cb[0] = rpc_create_aiocb(pco_iut);
    cb[1] = rpc_create_aiocb(pco_iut);
    rpc_fill_aiocb(pco_iut, cb[0], fd, 0, 0, buf1, DATA_BULK, &ev);
    rpc_fill_aiocb(pco_iut, cb[1], iut_s, 0, 0, buf2, DATA_BULK, &ev);
    
    if (strcmp(op, "write") == 0)
    {
        rpc_aio_write(pco_iut, cb[0]);
        rpc_aio_write(pco_iut, cb[1]);
    }
    else
    {
        rpc_aio_read(pco_iut, cb[0]);
        rpc_aio_read(pco_iut, cb[1]);
    }

    /* Suspend on AIO requests */
    pco_iut->op = RCF_RPC_CALL;
    rpc_aio_suspend(pco_iut, cb, 2, NULL);

    /* Satisfy AIO requests */
    if (strcmp(op, "write") == 0)
        rpc_simple_receiver(pco_tst, tst_s, 0, &n);
    else
        rpc_write(pco_tst, tst_s, tx_buf, DATA_BULK);
    
    /* Check suspend status */
    if ((rc = rpc_aio_suspend(pco_iut, cb, 2, NULL)) != 0)
        TEST_FAIL("aio_suspend returned %r instead 0", rc);
        
    MSLEEP(10);

    /* Check errors */
    if ((rc = rpc_aio_error(pco_iut, cb[0])) != 0)
        TEST_FAIL("aio_error() returned %r after request finishing", rc);
        
    if ((len = rpc_aio_return(pco_iut, cb[0])) != DATA_BULK)
        TEST_FAIL("aio_return() returned %d instead %u", len, DATA_BULK);

    if ((rc = rpc_aio_error(pco_iut, cb[1])) != 0)
        TEST_FAIL("aio_error() returned %r after request finishing", rc);
        
    if ((len = rpc_aio_return(pco_iut, cb[1])) != DATA_BULK)
        TEST_FAIL("aio_return() returned %d instead %u", len, DATA_BULK);

    TEST_SUCCESS;
cleanup:
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    RPC_CLOSE(pco_iut, fd);
    CLEANUP_RPC_DELETE_AIOCB(pco_iut, cb[0]);
    CLEANUP_RPC_DELETE_AIOCB(pco_iut, cb[1]);
    CLEANUP_RPC_FREE(pco_iut, buf1);
    CLEANUP_RPC_FREE(pco_iut, buf2);
    
    if (*fname != 0)
        rcf_ta_del_file(pco_iut->ta, 0, fname);

    TEST_END;
}
