/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-aio_suspend_timeout  Pass negative and zero timeout to aio_suspend()
 *
 * @objective Check that aio_suspend() does not block if called with zero
 *            or negative timeout.
 *
 * @param pco_iut   PCO with IUT
 * @param iut_s     Socket on @p pco_iut
 * @param pco_tst   Tester PCO
 * @param tst_s     Socket on @p pco_tst
 * @param sec       tv_sec field value in timespec structure
 * @param nsec      tv_nsec field value in timespec structure
 * @param op        Request to be posted: "read" or "write"
 * 
 * @pre Sockets @p iut_s and @p tst_s are connected.
 *
 * @par Scenario
 * -# If @p op is "write", overfill transmit buffers of @p iut_s socket.
 * -# Post @p op request on @p iut_s socket.
 * -# Call @b aio_suspend() with specified timeout - it should return
 *    -1 with errno @c EAGAIN.
 * -# Satisfy the request by sending/receiving data via @p tst_s.
 * -# Call @b aio_suspend() with specified timeout - it should return 0.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "aio/aio_suspend_timeout"

#include "sockapi-test.h"
#include "aio_internal.h"

#define DATA_BULK       4096  /**< Size of data to be sent */
#define DELTA           10000 /**< Inaccuracy of blocking time 
                                   in microseconds */

static char tx_buf[DATA_BULK];

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
    int tst_s = -1;
    int sec;
    int nsec;

    rpc_aiocb_p  cb[1] = { RPC_NULL };
    rpc_ptr      buf = RPC_NULL;
    
    tarpc_sigevent ev;
    struct timespec tv;

    uint64_t n;
    
    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(sec);
    TEST_GET_INT_PARAM(nsec);
    TEST_GET_STRING_PARAM(op);

    memset(&ev, 0, sizeof(ev));
    ev.notify = RPC_SIGEV_NONE;

    tv.tv_sec = sec;
    tv.tv_nsec = 0; 
    
    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    te_fill_buf(tx_buf, DATA_BULK);

    /* Overfill buffers in specifed case. */
    if (strcmp(op, "write") == 0)
        rpc_overfill_buffers(pco_iut, iut_s, &n);

    /* Allocate buffer on the pco_iut */
    buf = rpc_malloc(pco_iut, DATA_BULK);

    /* Create and fill aiocb */
    cb[0] = rpc_create_aiocb(pco_iut);
    rpc_fill_aiocb(pco_iut, cb[0], iut_s, 0, 0, buf, DATA_BULK, &ev);

    /* Post AIO requests */
    if (strcmp(op, "write") == 0)
        rpc_aio_write(pco_iut, cb[0]);
    else
        rpc_aio_read(pco_iut, cb[0]);

    /* Suspend first time */
    RPC_AWAIT_IUT_ERROR(pco_iut);
    if (rpc_aio_suspend(pco_iut, cb, 1, &tv) == 0)
        TEST_FAIL("aio_suspend() returned 0 with no request completed");

    CHECK_RPC_ERRNO(pco_iut, RPC_EAGAIN, "aio_suspend()");
    if (sec <= 0 && pco_iut->duration > DELTA)
        TEST_FAIL("aio_suspend() was blocking too long time");
        
    if (sec > 0)
    {
        uint64_t duration = sec * 1000000 + nsec;
        uint64_t delta = duration > pco_iut->duration ? 
                         duration - pco_iut->duration :
                         pco_iut->duration - duration;
                         
        if (delta > DELTA)
            TEST_FAIL("Unexpected time of aui_suspend() blocking");
    }

    /* Set conditions for ending AIO requests. */
    if (strcmp(op, "write") == 0)
        rpc_simple_receiver(pco_tst, tst_s, 0, &n);
    else
        rpc_send(pco_tst, tst_s, tx_buf, DATA_BULK, 0);
        
    MSLEEP(10);

    /* Check errors */
    if ((rc = rpc_aio_error(pco_iut, cb[0])) != 0)
        TEST_FAIL("aio_error() returned %r for first request", rc);
    if ((rc = rpc_aio_suspend(pco_iut, cb, 1, &tv)) != 0)
        TEST_FAIL("aio_suspend() returned %d instead 0 ", rc);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_DELETE_AIOCB(pco_iut, cb[0]);
    CLEANUP_RPC_FREE(pco_iut, buf);
    
    TEST_END;
}
