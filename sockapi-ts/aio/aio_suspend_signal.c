/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-aio_suspend_signal  Interrupt aio_suspend() by signal
 *
 * @objective Check that @b aio_suspend() may be interrupted using signal.
 *
 * @param pco_iut   PCO with IUT
 * @param iut_s     Socket on @p pco_iut
 * @param pco_tst   Tester PCO
 * @param tst_s     Socket on @p pco_tst
 * @param op        Request to be posted: read or write
 * @param own       If @c TRUE, signal should be initiated by request 
 *                  completion; otherwise signal should be sent from 
 *                  other process.
 * 
 * @pre Sockets @p iut_s and @p tst_s are connected.
 *
 * @par Scenario
 * -# If @p op is "write", overfill transmit buffers of @p iut_s socket.
 * -# Install signal handler for SIGUSR1.
 * -# Post @p op request on @p iut_s socket. If @p own is @b TRUE, specify
 *    notification via signal.
 * -# If @p own is @c TRUE, satisfy the request by sending/receiving data 
 *    via @p tst_s.
 * -# If @p own is @c FALSE, send SIGUSR1 to @p pco_iut.
 * -# Post @b aio_read() request.
 * -# Call @b aio_suspend() with pointer to control blocks corresponding to
 *    posted requests and @c NULL timeout.
 * -# Check that @b aio_suspend() is unblocked and returned -1 with 
 *    errno @c EINTR.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "aio/aio_suspend_signal"

#include "sockapi-test.h"
#include "aio_internal.h"

#define DATA_BULK       1024  /**< Size of data to be sent */
#define TIMEOUT         5     /**< Timeout in seconds */

static uint8_t tx_buf[10 * DATA_BULK];

int
main(int argc, char *argv[])
{
    /* Environment variables */
    te_bool             own;
    const char         *op;
    
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    rcf_rpc_server *pco_killer = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    /* Auxiliary variables */
    int     iut_s = -1;
    int     tst_s = -1;

    uint64_t n;
    
    pid_t pco_iut_pid;
    
    rpc_sigset_p set = RPC_NULL;
    rpc_aiocb_p  cb = RPC_NULL;
    rpc_ptr      buf = RPC_NULL;
    
    tarpc_sigevent ev;

    DEFINE_RPC_STRUCT_SIGACTION(old_act);
    te_bool                 restore_signal_handler = FALSE;
    
    struct timespec      tv = { TIMEOUT, 0 };
    struct tarpc_timeval t = { 0, 0 };
    
    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_STRING_PARAM(op);
    TEST_GET_BOOL_PARAM(own);
    
    pco_iut_pid = rpc_getpid(pco_iut);
    
    /* Create killer process. */
    if (!own)
        CHECK_RC(rcf_rpc_server_fork(pco_iut, "Killer", &pco_killer));
        
    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);
    
    /* Overfill buffers in specifed case. */
    if (strcmp(op, "write") == 0)
        rpc_overfill_buffers(pco_iut, iut_s, &n);
    
    /* Install signal handler */
    memset(&ev, 0, sizeof(ev));
    if (own)
    {
        ev.notify = RPC_SIGEV_SIGNAL;
        ev.signo = RPC_SIGUSR1;
    }
    else
    {
        ev.notify = RPC_SIGEV_NONE;
    }
    CHECK_RC(tapi_sigaction_simple(pco_iut, RPC_SIGUSR1,
                                   SIGNAL_REGISTRAR, &old_act));
    restore_signal_handler = TRUE;
    set = rpc_sigreceived(pco_iut);
    
    /* Allocate buffers on the pco_iut */
    buf = rpc_malloc(pco_iut, DATA_BULK);
    
    /* Create and fill aiocb */
    cb = rpc_create_aiocb(pco_iut);
    rpc_fill_aiocb(pco_iut, cb, iut_s, 0, 0, buf, DATA_BULK, &ev);
    
    /* Post AIO requests */
    if (strcmp(op, "write") == 0)
        rpc_aio_write(pco_iut, cb);
    else
        rpc_aio_read(pco_iut, cb);
    
    /* Set conditions for ending AIO requests */
    if (own)
    {
        rpc_gettimeofday(pco_tst, &t, NULL);
        pco_tst->start = (t.tv_sec + 1) * 1000 + t.tv_usec / 1000;
        pco_tst->op = RCF_RPC_CALL;
        if (strcmp(op, "write") == 0)
            rpc_simple_receiver(pco_tst, tst_s, 0, &n);
        else
            rpc_write(pco_tst, tst_s, tx_buf, DATA_BULK);
    }
    else
    {
        rpc_gettimeofday(pco_killer, &t, NULL);
        pco_killer->start = (t.tv_sec + 1) * 1000 + t.tv_usec / 1000;
        pco_killer->op = RCF_RPC_CALL;
        rpc_kill(pco_killer, pco_iut_pid, RPC_SIGUSR1);
    }
    
    /* Check errors */
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_aio_suspend(pco_iut, &cb, 1, &tv);

    if (own)
    {
        if (strcmp(op, "write") == 0)
            rpc_simple_receiver(pco_tst, tst_s, 0, &n);
        else
            rpc_write(pco_tst, tst_s, tx_buf, DATA_BULK);
    }
    else
        rpc_kill(pco_killer, pco_iut_pid, RPC_SIGUSR1);

    if (!own && rc != -1)
        TEST_FAIL("aio_suspend() returned %d unexpectedly", rc);
        
    if (rc == -1 && RPC_ERRNO(pco_iut) == RPC_EAGAIN)
        TEST_FAIL("aio_suspend() is not unblocked by the signal");
        
    if (rc == -1)
        CHECK_RPC_ERRNO(pco_iut, RPC_EINTR, "aio_suspend()");

    if (!rpc_sigismember(pco_iut, set, RPC_SIGUSR1))
            TEST_FAIL("Signal is not delivered");
    
    TEST_SUCCESS;

cleanup:
    if (pco_killer != NULL)
    {
        if (rcf_rpc_server_destroy(pco_killer) < 0)
            ERROR("Failed to destroy thread RPC server on the IUT");
    }
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    CLEANUP_AIO_CANCEL(pco_iut, iut_s, cb);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_DELETE_AIOCB(pco_iut, cb);
    CLEANUP_RPC_FREE(pco_iut, buf);
    
    /* Restore default signal handler */
    if (restore_signal_handler)
        CLEANUP_RPC_SIGACTION(pco_iut, RPC_SIGUSR1, &old_act, 
                              SIGNAL_REGISTRAR);
                       
    TEST_END;
}
