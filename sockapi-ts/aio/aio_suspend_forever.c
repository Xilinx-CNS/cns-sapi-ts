/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-aio_suspend_forever  aio_suspend() with NULL timeout
 *
 * @objective Check that @b aio_suspend() blocks forever if @c NULL timeout
 *            is specified.
 *
 * @param pco_iut   PCO with IUT
 * @param iut_s     Socket on @p pco_iut
 * @param pco_tst   Tester PCO
 * @param tst_s     Socket on @p pco_tst
 * @param op        Request to be posted: read or write
 * 
 * @pre Sockets @p iut_s and @p tst_s are connected.
 *
 * @par Scenario
 * -# If @p op is "write", overfill transmit buffers of @p iut_s socket.
 * -# Post @p op request on @p iut_s socket.
 * -# Call @b aio_suspend() with pointer to control block corresponding to
 *    posted request and @c NULL timeout.
 * -# Satisfy the request by sending/receiving data via @p tst_s.
 * -# Check that @b aio_suspend() unblocked immediately after request
 *    completion.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "aio/aio_suspend_forever"
#include "sockapi-test.h"
#include "aio_internal.h"

#define DATA_BULK       1024  /**< Size of data to be sent */

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
    int iut_s = -1;
    int tst_s = -1;

    uint64_t n;
    te_bool  done = TRUE;
    
    rpc_aiocb_p  cb[1] = { RPC_NULL };
    rpc_ptr      buf = RPC_NULL;
    
    tarpc_sigevent ev;
    
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
    
    /* Overfill buffers in specifed case. */
    if (strcmp(op, "write") == 0)
        rpc_overfill_buffers(pco_iut, iut_s, &n);
    
    /* Allocate buffer on the pco_iut */
    buf = rpc_malloc(pco_iut, DATA_BULK);
    
    /* Create and fill aiocb */
    cb[0] = rpc_create_aiocb(pco_iut);
    rpc_fill_aiocb(pco_iut, cb[0], iut_s, 0, 0, buf, DATA_BULK, &ev);
    
    /* Post AIO read request */
    if (strcmp(op, "write") == 0)
        rpc_aio_write(pco_iut, cb[0]);
    else
        rpc_aio_read(pco_iut, cb[0]);
    
    pco_iut->op = RCF_RPC_CALL;
    rpc_aio_suspend(pco_iut, cb, 1, NULL);
    
    /* Check that it is not unblocked yet */
    SLEEP(1);

    CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &done));
    if (done)
        TEST_FAIL("aio_suspend() has unblocked before requests completion");
    
    /* Send data in the case of aio_read request */
    if (strcmp(op, "write") == 0)
        rpc_simple_receiver(pco_tst, tst_s, 0, &n);
    else
        rpc_write(pco_tst, tst_s, tx_buf, DATA_BULK);
    
    pco_iut->op = RCF_RPC_WAIT;
    if ((rc = rpc_aio_suspend(pco_iut, cb, 1, NULL)) != 0)
        TEST_FAIL("aio_suspend() returned %d instead 0", rc);
        
    TEST_SUCCESS;
cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_DELETE_AIOCB(pco_iut, cb[0]);
    CLEANUP_RPC_FREE(pco_iut, buf);
    
    TEST_END;
}
