/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-aio_suspend_thread  Wait request posted from other thread/process
 *
 * @objective Check that @b aio_suspend() may be used from the other
 *            thread/process.
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
 * -# Create thread @p pco_chld of @p pco_iut.
 * -# Call @b aio_suspend() on @p pco_chld with pointer to control block 
 *    corresponding to request posted from @p pco_iut.
 * -# Satisfy the request by sending/receiving data via @p tst_s.
 * -# Check that @b aio_suspend() unblocked immediately after request
 *    completion.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "aio/aio_suspend_thread"

#include "sockapi-test.h"
#include "aio_internal.h"

#define DATA_BULK       4096  /**< Size of data to be sent */
#define TIMEOUT         2    /**< Delay of suspend function */

static char tx_buf[DATA_BULK];

int
main(int argc, char *argv[])
{
    /* Environment variables */
    const char         *op;

    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_chld = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    /* Auxiliary variables */
    int iut_s = -1;
    int tst_s = -1;

    rpc_aiocb_p  cb[1] = { RPC_NULL };
    rpc_ptr      buf = RPC_NULL;
    
    tarpc_sigevent ev;

    uint64_t n;
    
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
    
    /* Create child process. */
    CHECK_RC(rcf_rpc_server_thread_create(pco_iut, "IUT_thread",
                                          &pco_chld));

    pco_chld->op = RCF_RPC_CALL;
    rpc_aio_suspend(pco_chld, cb, 1, NULL);

    /* Set conditions for ending AIO requests. */
    if (strcmp(op, "write") == 0)
        rpc_simple_receiver(pco_tst, tst_s, 0, &n);
    else
        rpc_write(pco_tst, tst_s, tx_buf, DATA_BULK);
    
    /* Check errors. */
    if ((rc = rpc_aio_suspend(pco_chld, cb, 1, NULL)) != 0)
        TEST_FAIL("aio_suspend() returned %d instead 0", rc);

    if (pco_iut->duration >= TIMEOUT * 1000000)
        TEST_FAIL("aio_suspend() was sleeping %u milliseconds",
                  pco_iut->duration);

    TEST_SUCCESS;
    
cleanup:
    if (pco_chld != NULL)
    {
        if (rcf_rpc_server_destroy(pco_chld) < 0)
            ERROR("Failed to destroy thread RPC server on the IUT");
    }
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_DELETE_AIOCB(pco_iut, cb[0]);
    CLEANUP_RPC_FREE(pco_iut, buf);
    
    TEST_END;
}
