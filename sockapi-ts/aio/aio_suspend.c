/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-aio_suspend  Suspending on asynchronous event(s)
 *
 * @objective Check that @b aio_read(), @b aio_error() and
 *            @b aio_return() work properly for simple use case.
 *
 * @type conformance
 *
 * @param pco_iut   PCO with IUT
 * @param iut_s     Stream socket on @p pco_iut
 * @param iut_s_aux Auxiliary datagram socket on @p pco_iut
 * @param pco_tst   Tester PCO
 * @param tst_s     Stream socket on @p pco_tst
 * @param op        operation ("read" or "write")
 * 
 * @pre Sockets @p iut_s and @p tst_s are connected.
 *
 * -# Create and bind auxiliary datagram socket @p iut_s_aux.
 * -# If @p op is "write", overfill transmit buffers of @p iut_s.
 * -# Post @p op AIO request for socket @p iut_s the @p pco_iut.
 * -# Call @b aio_read() for socket @p iut_s_aux and signal @p signum
 *    on the @p pco_iut.
 * -# Suspend using @b aio_suspend() for set { @p iut_s_aux, @c NULL,
 *    @p iut_s } list and timeout @c 1 second.
 * -# @b aio_suspend() should return @c -1 and errno @c EAGAIN.
 * -# Check that function was blocked during the timeout.
 * -# Suspend again with @p timeout @c 1 second.
 * -# Satisfy the request sending or receiving data via @p tst_s - 
 *    @b aio_suspend() should unblock and return 0.
 * -# Close @p iut_s_aux socket.
 *
 * @post Sockets @p iut_s and @p tst_s are kept connected.
 * 
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "aio/aio_suspend"

#include "sockapi-test.h"
#include "aio_internal.h"

#define DATA_BULK       1024  /**< Size of data to be sent */
#define TIMEOUT         2     /**< Timeout in seconds */

static uint8_t data_buf[DATA_BULK];

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
    int iut_s = -1;
    int iut_s_aux = -1;
    int tst_s = -1;
    
    rpc_aiocb_p  cb[2] = { RPC_NULL, RPC_NULL };
    rpc_ptr      buf = RPC_NULL;
    rpc_ptr      aux_buf = RPC_NULL;
    uint64_t     n;
    te_bool      wr;
    
    tarpc_sigevent ev;
    
    struct timespec tv = { TIMEOUT, 0 };
    
    struct tarpc_timeval t = { 0, 0 };
    
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
                   
    if ((wr = (strcmp(op, "write") == 0)) == TRUE)
        rpc_overfill_buffers(pco_iut, iut_s, &n);

    iut_s_aux = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                           RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);
    TAPI_SET_NEW_PORT(pco_iut, iut_addr);
    rpc_bind(pco_iut, iut_s_aux, iut_addr);
    
    /* Allocate buffer on the pco_iut */
    buf = rpc_malloc(pco_iut, DATA_BULK + 1);
    aux_buf = rpc_malloc(pco_iut, DATA_BULK + 1);
    
    /* Create and fill aiocb */
    cb[0] = rpc_create_aiocb(pco_iut);
    rpc_fill_aiocb(pco_iut, cb[0], iut_s, 0, 0, buf, DATA_BULK + 1, &ev);
    cb[1] = rpc_create_aiocb(pco_iut);
    rpc_fill_aiocb(pco_iut, cb[1], iut_s_aux, 0, 0, 
                   aux_buf, DATA_BULK + 1, &ev);
    
    /* Post AIO read requests */
    if (wr)
        rpc_aio_write(pco_iut, cb[0]);
    else
        rpc_aio_read(pco_iut, cb[0]);
    rpc_aio_read(pco_iut, cb[1]);
    
    /* Suspend first time */
    RPC_AWAIT_IUT_ERROR(pco_iut);
    if (rpc_aio_suspend(pco_iut, cb, 2, &tv) == 0)
        TEST_FAIL("aio_suspend() returned 0 with no request completed");

    CHECK_RPC_ERRNO(pco_iut, RPC_EAGAIN, "aio_suspend()");
    
    if (pco_iut->duration < TIMEOUT * 1000000)
        TEST_FAIL("aio_suspend() was sleeping %u milliseconds instead "
                  "%u seconds", pco_iut->duration, TIMEOUT);

    /* Suspend second time */
    te_fill_buf(data_buf, DATA_BULK);
    rpc_gettimeofday(pco_tst, &t, NULL);
    pco_tst->start = (t.tv_sec + 1) * 1000 + t.tv_usec / 1000;
    pco_tst->op = RCF_RPC_CALL;
    if (wr)
        rpc_simple_receiver(pco_tst, tst_s, 0, &n);
    else
        rpc_send(pco_tst, tst_s, data_buf, DATA_BULK, 0);
    
    rpc_aio_suspend(pco_iut, cb, 2, &tv);

    if (wr)
        rpc_simple_receiver(pco_tst, tst_s, 0, &n);
    else
        rpc_send(pco_tst, tst_s, data_buf, DATA_BULK, 0);

    if (pco_iut->duration >= TIMEOUT * 1000000)
        TEST_FAIL("aio_suspend() was not resumed after request completion");
    
    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    CLEANUP_AIO_CANCEL(pco_iut, iut_s, cb[0]);
    CLEANUP_AIO_CANCEL(pco_iut, iut_s_aux, cb[1]);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s_aux);
    CLEANUP_RPC_DELETE_AIOCB(pco_iut, cb[0]);
    CLEANUP_RPC_DELETE_AIOCB(pco_iut, cb[1]);
    CLEANUP_RPC_FREE(pco_iut, buf);
    CLEANUP_RPC_FREE(pco_iut, aux_buf);
    
    TEST_END;
}

