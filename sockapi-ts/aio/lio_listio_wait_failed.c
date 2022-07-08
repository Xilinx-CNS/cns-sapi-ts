/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-lio_listio_wait_failed  Call lio_listio(LIO_WAIT) for failed requests
 *
 * @objective Check that @b lio_listio(@c LIO_WAIT) returns -1 with errno 
 *            @c EIO if one of requests in the list is failed.
 *
 * @param pco_iut   PCO with IUT
 * @param iut_s     Stream socket on @p pco_iut
 * @param pco_tst   Tester PCO
 * @param tst_s     Stream socket on @p pco_tst
 *
 * @pre Sockets @p iut_s and @p tst_s are connected.
 *
 * @par Scenario
 * -# Create 2 AIO read request control blocks on socket @p iut_s.
 * -# Post requests using @b lio_listio(@c LIO_WAIT).
 * -# Send data via @p tst_s to satisfy the first request.
 * -# Check that @b lio_listio() is blocked yet.
 * -# Kill @p pco_tst process.
 * -# Check that @b lio_listio() is unblocked, returned -1 and set errno
 *    to @c EIO.
 * -# Check using @b aio_error() that first request is satisfied while the 
 *    second one is failed.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "aio/lio_listio_wait_failed"
#include "sockapi-test.h"

#define DATA_BULK       1024                /**< Size of data to be sent */
#define LIST_LEN        2                   /**< Number of calls in the list */

int
main(int argc, char *argv[])
{
    /* Environment variables */
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    rcf_rpc_server         *pco_killer = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    /* Auxiliary variables */
    int                     iut_s = -1;
    int                     tst_s = -1;
    pid_t                   pid;

    rpc_aiocb_p             lio_cb[LIST_LEN];
    rpc_ptr                 buf = RPC_NULL;
    int                     tx_buf[DATA_BULK];
    tarpc_sigevent          ev;
    te_bool                 done;

    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    memset(&ev, 0, sizeof(ev));
    ev.notify = RPC_SIGEV_NONE;

    rcf_rpc_server_fork(pco_tst, "pco_killer", &pco_killer);

    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);
    
    /* Provoke RST after Tester killing */
    rpc_write(pco_iut, iut_s, "Hello", sizeof("Hello"));
    
    /* Allocate buffer on the pco_iut */
    buf = rpc_malloc(pco_iut, DATA_BULK);

    lio_cb[0] = rpc_create_aiocb(pco_iut);
    rpc_fill_aiocb(pco_iut, lio_cb[0], iut_s, RPC_LIO_READ, 0, buf, 
                   DATA_BULK, &ev);
    lio_cb[1] = rpc_create_aiocb(pco_iut);
    rpc_fill_aiocb(pco_iut, lio_cb[1], iut_s, RPC_LIO_READ, 0, buf, 
                   DATA_BULK, &ev);

    pco_iut->op = RCF_RPC_CALL;
    rpc_lio_listio(pco_iut, RPC_LIO_WAIT, lio_cb, LIST_LEN, &ev);

    rpc_write(pco_tst, tst_s, tx_buf, DATA_BULK);
    rcf_rpc_server_is_op_done(pco_iut, &done);
    if (done != 0)
        TEST_FAIL("Unexpected behavior of lio_listio()");
    
    pid = rpc_getpid(pco_tst);
    rpc_kill(pco_killer, pid, RPC_SIGKILL);
    
    pco_iut->op = RCF_RPC_WAIT;
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_lio_listio(pco_iut, RPC_LIO_WAIT, lio_cb, LIST_LEN, &ev);

    if (rc != -1)
        TEST_FAIL("lio_listio() returned %d instead -1", rc);
        
    if (RPC_ERRNO(pco_iut) != RPC_EIO)
        TEST_FAIL("lio_listio() set errno to %r instead EIO", 
                  RPC_ERRNO(pco_iut));
    
    if ((rc = rpc_aio_error(pco_iut, lio_cb[0])) != 0)
        TEST_FAIL("aio_error() returned %r instead 0", rc);
    
    if ((rc = rpc_aio_error(pco_iut, lio_cb[1])) != RPC_ECONNRESET)
        TEST_FAIL("aio_error() returned %r instead ECONNRESET", rc);
        
    TEST_SUCCESS;

cleanup:
    rcf_rpc_server_restart(pco_tst);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    
    CLEANUP_RPC_DELETE_AIOCB(pco_iut, lio_cb[0]);
    CLEANUP_RPC_DELETE_AIOCB(pco_iut, lio_cb[1]);
    
    CLEANUP_RPC_FREE(pco_iut, buf);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    
    TEST_END;
}
    
