/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-lio_listio_file  Post asynchronous requests on socket and file using lio_listio()
 *
 * @objective Check that @b lio_listio() works properly when it posts
 *            AIO requests which operate with socket and file.
 *
 * @type conformance
 *
 * @param pco_iut   PCO with IUT
 * @param iut_s     Socket on @p pco_iut
 * @param pco_tst   Tester PCO
 * @param tst_s     Socket on @p pco_tst
 * @param rd        If @c TRUE, then operation "read" else "write"
 * @param wait      If @c TRUE / @c FALSE call @b lio_listio() with 
 *                  @c LIO_WAIT / @c LIO_NOWAIT
 * 
 * @pre Sockets @p iut_s and @p tst_s are connected.
 *
 * -# Create @p f file with some data on @p pco_iut.
 * -# If @p rd is "write", overfill transmit buffers of @p iut_s.
 * -# Create two @p op AIO control blocks: one for @p iut_s socket and one
 *    for @p f file.
 * -# Post theese requests using @b lio_listio(@c LIO_WAIT) 
 *    if @p wait is @c TRUE or @b lio_listio(@c LIO_NOWAIT) otherwise.
 * -# If @p rd is @c TRUE and @p wait is @c TRUE check that @b lio_listio()
 *    has not been unblocked yet.
 * -# If @p rd is @c TRUE send data via @p tst_s socket.
 *    If @p rd is @c FALSE receive data via @p tst_s socket.
 * -# Check that @b lio_listio() has been unblocked.
 * -# Check that @b aio_error() returns @c 0 for each control block.
 * -# Check that @b aio_return() for each control block returns correct
 *    length.
 * -# Check that transferred data are not corrupted.
 * -# Remove @p f file.
 *
 * @post Sockets @p iut_s and @p tst_s are kept connected.
 * 
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "aio/lio_listio_file" 

#include "sockapi-test.h"
#include "aio_internal.h"


#define DATA_BULK       1024                /**< Size of data to be sent */
#define LIST_LEN        2                   /**< Number of calls in the list */
#define FILENAME        "/tmp/te_lio_listio_file"

int
main(int argc, char *argv[])
{    
    te_bool                 rd;
    te_bool                 wait; 

    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    rcf_rpc_server         *pco_iut1 = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    /* Auxiliary variables */
    int                     iut_s = -1;
    int                     tst_s = -1;

    rpc_aiocb_p             lio_cb[LIST_LEN];
    rpc_ptr                 buf1 = RPC_NULL;
    rpc_ptr                 buf2 = RPC_NULL;
    
    uint8_t                 tx_buf1[DATA_BULK];
    uint8_t                 tx_buf2[DATA_BULK];
    uint8_t                 rx_buf2[DATA_BULK];
    uint8_t                 lio_buf1[DATA_BULK];
    uint8_t                 lio_buf2[DATA_BULK];   
    tarpc_sigevent          ev;
    int                     i;
    int                     fd;
    unsigned int            len = 2;
    tarpc_callback_item     list[len];
    char                    fname[128] = { 0, };
    uint64_t                n;
    
    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(rd);
    TEST_GET_BOOL_PARAM(wait);

    rpc_get_callback_list(pco_iut, NULL, NULL);
    
    INIT_EV(&ev);
    ev.notify = RPC_SIGEV_THREAD;
    ev.value.tarpc_sigval_u.sival_int = 1;
    ev.function = AIO_CALLBACK_NAME "1";
    
    rcf_rpc_server_thread_create(pco_iut, "pco_iut1", &pco_iut1);
    
    te_fill_buf(tx_buf1, DATA_BULK);
    te_fill_buf(tx_buf2, DATA_BULK);

    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    if (!rd)
        rpc_overfill_buffers(pco_iut, iut_s, &n);
    
    /* Allocate buffer on the pco_iut */
    buf1 = rpc_malloc(pco_iut, DATA_BULK);
    buf2 = rpc_malloc(pco_iut, DATA_BULK);
    if (!rd)
    {
        rpc_set_buf(pco_iut, tx_buf1, DATA_BULK, buf1);
        rpc_set_buf(pco_iut, tx_buf2, DATA_BULK, buf2);
    }
    TE_SPRINTF(fname, "%s_%d", FILENAME, rand_range(0, 100000));
    fd = rpc_open(pco_iut, fname, RPC_O_RDWR | RPC_O_CREAT, 0);
    if (rd)
        rpc_write(pco_iut, fd, tx_buf2, DATA_BULK);
    RPC_CLOSE(pco_iut, fd);
    fd = rpc_open(pco_iut, fname, RPC_O_RDWR, RPC_S_IRWXU);
    
    lio_cb[0] = rpc_create_aiocb(pco_iut);
    rpc_fill_aiocb(pco_iut, lio_cb[0], iut_s, rd ? RPC_LIO_READ : RPC_LIO_WRITE,
                   0, buf1, DATA_BULK, &ev);
    
    lio_cb[1] = rpc_create_aiocb(pco_iut);
    rpc_fill_aiocb(pco_iut, lio_cb[1], fd, rd ? RPC_LIO_READ : RPC_LIO_WRITE,
                   0, buf2, DATA_BULK, &ev);
    
    
    if (wait)
    {
        te_bool done;
        
        pco_iut->op = RCF_RPC_CALL;
        rpc_lio_listio(pco_iut, RPC_LIO_WAIT, lio_cb, LIST_LEN, &ev);
        
        rcf_rpc_server_is_op_done(pco_iut, &done);
        if (done != 0)
            TEST_FAIL("lio_listio() unblocked before completion "
                      "of all requests"); 
    }
    else
    {
        rpc_lio_listio(pco_iut, RPC_LIO_NOWAIT, lio_cb, LIST_LEN, &ev);
        len = 2;
        rpc_get_callback_list(pco_iut, list, &len);
        if (len > 0)
            TEST_FAIL("Notification is received before completion of "
                      "all requests");
    }
        
        
    if (rd)
        rpc_write(pco_tst, tst_s, tx_buf1, DATA_BULK);
    else
        rpc_simple_receiver(pco_tst, tst_s, 0, &n);
    
    if (wait)
        rpc_lio_listio(pco_iut, RPC_LIO_WAIT, lio_cb, LIST_LEN, &ev);
    else
    {
        MSLEEP(10);

        len = 2;
        rpc_get_callback_list(pco_iut, list, &len);
        if (len < 1)
            TEST_FAIL("Completion notification is not delivered");
        if (len > 1)
            TEST_FAIL("Completion notification is delivered twice");
    }                      
        
    for (i = 0; i < 2; i++)       
    {
        if ((rc = rpc_aio_error(pco_iut, lio_cb[i])) != 0)
            TEST_FAIL("aio_error() returned %r instead 0", rc);
            
        if ((rc = rpc_aio_return(pco_iut, lio_cb[i])) != DATA_BULK)
            TEST_FAIL("aio_return() returned %d instead %d", rc, DATA_BULK);
    }  
    
    if (rd)
    {
        rpc_get_buf(pco_iut, buf1, DATA_BULK, lio_buf1);
        rpc_get_buf(pco_iut, buf2, DATA_BULK, lio_buf2);
    
        if (memcmp(tx_buf1, lio_buf1, DATA_BULK) != 0)
            TEST_FAIL("Data sent from the Tester do not match data received "
                      "on the IUT");
        if (memcmp(tx_buf2, lio_buf2, DATA_BULK) != 0)
            TEST_FAIL("Data read from the file are incorrect");
    }
    else
    {
        /* Do not check data received on Tester - buffers were overfilled */
        RPC_CLOSE(pco_iut, fd);
        fd = rpc_open(pco_iut, fname, RPC_O_RDWR, RPC_S_IRWXU);
        rpc_read(pco_iut, fd, rx_buf2, sizeof(rx_buf2));
        if (memcmp(rx_buf2, tx_buf2, DATA_BULK) != 0)
            TEST_FAIL("Data put into the file are incorrect");
    }
    
    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, fd);
    if (pco_iut1 != NULL)
    {
        if (rcf_rpc_server_destroy(pco_iut1) < 0)
            ERROR("Failed to destroy thread RPC server on the IUT");
    }
    RPC_CLOSE(pco_iut, fd);
    
    for (i = 0; i < LIST_LEN; i++)
        CLEANUP_RPC_DELETE_AIOCB(pco_iut, lio_cb[i]);
    
    CLEANUP_RPC_FREE(pco_iut, buf1);
    CLEANUP_RPC_FREE(pco_iut, buf2);

    if (*fname != 0)
        rcf_ta_del_file(pco_iut->ta, 0, fname);
    
    TEST_END;
}


