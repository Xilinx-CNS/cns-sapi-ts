/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-aio_fork  Call aio_error() and aio_ruturn() for request posted from other process
 *
 * @objective Check that AIO requests are not inhereted after fork.
 *
 * @param pco_iut   PCO with IUT
 * @param iut_s     Socket on @p pco_iut
 * @param pco_tst   Tester PCO
 * @param tst_s     Socket on @p pco_tst
 * @param op        operation ("read" or "write")
 *
 * @pre Sockets @p iut_s and @p tst_s are connected.
 *
 * @par Scenario
 * -# If @p op is "write", overfill transmit buffers of @p pco_iut.
 * -# Post @p op AIO request on socket @p iut_s.
 * -# Create a child process @p pco_chld calling @b fork() on @p pco_iut.
 * -# Call @b aio_error() for AIO request in @p pco_chld context.
 * -# Call @b aio_error() for AIO request in @p pco_iut context.
 * -# Check theese results. It should be @c 0 for the first aio_error and
 *    @c EINPROGRESS for the second.
 * -# If @p op is read, send two bulks of data to satisfy AIO request.
 *    Otherwise read all data pending on socket @p tst_s after overfilling
 *    of @p iut_s transmit buffers.
 * -# Call @b aio_error() for AIO request in @p pco_chld context.
 * -# Call @b aio_error() for AIO request in @p pco_iut context.
 * -# Check theese results. It should be @c 0 for the first aio_error and
 *    @c 0 for the second.
 * -# Call @b aio_return() for AIO request in @p pco_chld context.
 * -# Call @b aio_return() for AIO request in @p pco_iut context.
 * -# Check theese results. It should be @c 0 for the first @b aio_return() and
 *    number of sent or recieved bytes for the second.
 * -# Destroy @p pco_chld.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */
#define TE_TEST_NAME  "aio/aio_fork"

#include "sockapi-test.h"
#include "aio_internal.h"

#define DATA_BULK       1024  /**< Size of data to be sent */

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

    rpc_aiocb_p  cb = RPC_NULL;
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
    cb = rpc_create_aiocb(pco_iut);
    rpc_fill_aiocb(pco_iut, cb, iut_s, 0, 0, buf, DATA_BULK, &ev);

    /* Post AIO requests */
    if (strcmp(op, "write") == 0)
        rpc_aio_write(pco_iut, cb);
    else
        rpc_aio_read(pco_iut, cb);
    
    /* Create child process. */
    CHECK_RC(rcf_rpc_server_fork(pco_iut, "Child", &pco_chld));

    /* Check errors. */
    if ((rc = rpc_aio_error(pco_iut, cb)) != RPC_EINPROGRESS)
        TEST_FAIL("aio_error() called from pco_iut returned %r", rc);
    if ((rc = rpc_aio_error(pco_chld, cb)) != 0)
        TEST_FAIL("aio_error() called from pco_chld returned %r", rc);
    rpc_aio_error(pco_chld, cb);
    /* Set conditions for ending AIO requests. */
    if (strcmp(op, "write") == 0)
    {
        rpc_simple_receiver(pco_tst, tst_s, 0, &n);
    }
    else
    {
        rpc_write(pco_tst, tst_s, tx_buf, DATA_BULK);
        rpc_write(pco_tst, tst_s, tx_buf, DATA_BULK);
    }
    MSLEEP(10);
    
    /* Check errors. */
    if ((rc = rpc_aio_error(pco_iut, cb)) != 0)
        TEST_FAIL("aio_error() called from pco_iut returned %r", rc);
    if ((rc = rpc_aio_error(pco_chld, cb)) != 0)
        TEST_FAIL("aio_error() called from pco_chld returned %r", rc);
    
    if ((rc = rpc_aio_return(pco_iut, cb)) != DATA_BULK)
        TEST_FAIL("aio_return() called from pco_iut returned %u instead %u",
                  rc, DATA_BULK);
    if ((rc = rpc_aio_return(pco_chld, cb)) != 0)
        TEST_FAIL("aio_return() called from pco_chld returned %u"
                  "instead %u", rc, DATA_BULK);

    TEST_SUCCESS;
cleanup:
    if (pco_chld != NULL)
    {
        if (rcf_rpc_server_destroy(pco_chld) < 0)
            ERROR("Failed to destroy thread RPC server on the IUT");
    }
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_DELETE_AIOCB(pco_iut, cb);
    CLEANUP_RPC_FREE(pco_iut, buf);
    
    TEST_END;
}
