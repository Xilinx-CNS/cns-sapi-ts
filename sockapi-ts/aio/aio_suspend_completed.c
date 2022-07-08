/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-aio_suspend_completed  aio_suspend() for completed request
 *
 * @objective Check that @b aio_suspend() handles properly completed request.
 *
 * @param pco_iut   PCO with IUT
 * @param iut_s     Socket on @p pco_iut
 * @param pco_tst   Tester PCO
 * @param tst_s     Socket on @p pco_tst
 * @param op        Request to be posted: "read" or "write"
 * 
 * @pre Sockets @p iut_s and @p tst_s are connected.
 *
 * @par Scenario
 * -# Post @p op request on @p iut_s socket.
 * -# If @p op is "read", write data via @p tst_s socket.
 * -# Call @b aio_error() to verify that request is completed.
 * -# Call @b aio_suspend() with pointer to control block corresponding to
 *    posted request and non-zero timeout.
 * -# Check that @b aio_suspend() unblocked immediately and returned 0.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "aio/aio_suspend_completed"

#include "sockapi-test.h"
#include "aio_internal.h"

#define DATA_BULK       1024  /**< Size of data to be sent */

static uint8_t tx_buf[DATA_BULK];

int
main(int argc, char *argv[])
{
    /* Environment variables */
    const char         *op;
    rpc_socket_type     sock_type;

    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    /* Auxiliary variables */
    int iut_s = -1;
    int tst_s = -1;
    int len;
    
    rpc_aiocb_p  cb[1] = { RPC_NULL };
    rpc_ptr      buf = RPC_NULL;
    
    tarpc_sigevent ev;
    
    struct timespec tv = { 2, 0 };
    
    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_STRING_PARAM(op);

    memset(&ev, 0, sizeof(ev));
    ev.notify = RPC_SIGEV_NONE;

    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);
    
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
    
    /* Send data in the case of aio_read request */
    if (strcmp(op, "read") == 0)
    {
        RPC_SEND(len, pco_tst, tst_s, tx_buf, DATA_BULK, 0);
        SLEEP(1);
    }
    
    MSLEEP(10);

    if ((rc = rpc_aio_error(pco_iut, cb[0])) != 0)
        TEST_FAIL("aio_error() returned %r after request finishing", rc);

    if ((rc = rpc_aio_suspend(pco_iut, cb, 1, &tv)) != 0)
        TEST_FAIL("aio_suspend() returned %d instead 0", rc);

    if (pco_iut->duration / 1000000 > 0)
        TEST_FAIL("aio_suspend() with list of completed requests "
                  "is not unblocked immediately");

    TEST_SUCCESS;
    
cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_DELETE_AIOCB(pco_iut, cb[0]);
    CLEANUP_RPC_FREE(pco_iut, buf);
    
    TEST_END;
}
