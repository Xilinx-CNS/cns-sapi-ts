/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-close_sock  Close the socket during AIO request processing
 *
 * @objective Check that socket is really closed only after AIO request 
 *            completion.
 *
 * @param pco_iut   PCO with IUT
 * @param iut_s     Socket on @p pco_iut
 * @param pco_tst   Tester PCO
 * @param tst_s     Socket on @p pco_tst
 * @param op        Request to be posted: read or write
 * @param notify    Notification type: signal, callback or none.
 *
 * @pre Sockets @p iut_s and @p tst_s are connected.
 *
 * @par Scenario
 * -# If @p op is "write", overfill transmit buffers of @p iut_s socket.
 * -# If @p notify is signal, install signal handler for @c SIGUSR1.
 * -# Post @p op request on @p iut_s socket with specified notification
 *    type.
 * -# Create a thread @p pco_chld on @p pco_iut.
 * -# Call @b aio_suspend() on @p pco_iut to block until request is completed.
 * -# Close @p iut_s from @p pco_chld.
 * -# If @p notify is signal, check that no signal is delivered.
 * -# If @p notify is callback, check that no callback was called.
 * -# Satisfy the request by sending/receiving data via @p tst_s.
 * -# Check that @b aio_suspend() unblocked only after request completion.
 * -# If @p notify is signal, check that signal is delivered.
 * -# If @p notify is callback, check that callback was called.
 * -# Call @b aio_error() - it should return 0.
 * -# Call @b aio_return() - it should return number of bytes transferred.
 * -# Check that sent data are not corrupted.
 * -# Destroy @p pco_chld.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "aio/close_sock"

#include "sockapi-test.h"
#include "aio_internal.h"

#define DATA_BULK       1024  /**< Size of data to be sent */

static char tx_buf[DATA_BULK];
static char rx_buf[DATA_BULK];

int
main(int argc, char *argv[])
{
    /* Environment variables */
    const char         *op;
    const char         *notify;

    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_chld = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    /* Auxiliary variables */
    int      iut_s = -1;
    int      tst_s = -1;
    uint32_t len;
    te_bool  done = TRUE;

    rpc_sigset_p set = RPC_NULL;
    rpc_aiocb_p  cb[1] = { RPC_NULL };
    rpc_ptr      buf = RPC_NULL;
    
    tarpc_sigevent ev;

    uint64_t n;
     
    tarpc_callback_item *list = NULL;

    DEFINE_RPC_STRUCT_SIGACTION(old_act);
    te_bool                 restore_signal_handler = FALSE;

    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_STRING_PARAM(op);
    TEST_GET_STRING_PARAM(notify);
    
    INIT_EV(&ev);
    
    if ((list = calloc(2, sizeof(tarpc_callback_item))) == NULL)
    {
        TEST_FAIL("Out of memory");
    }
    
    /* Reset callback list on IUT */
    len = 2;
    rpc_get_callback_list(pco_iut, list, &len);
   
    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    te_fill_buf(tx_buf, DATA_BULK);

    /* Overfill buffers in specifed case. */
    if (strcmp(op, "write") == 0)
        rpc_overfill_buffers(pco_iut, iut_s, &n);
    
    /* Constust specified event */
    if (strcmp(notify, "signal") == 0)
    {
        ev.notify = RPC_SIGEV_SIGNAL;
        ev.signo = RPC_SIGUSR1;
        CHECK_RC(tapi_sigaction_simple(pco_iut, RPC_SIGUSR1,
                                       SIGNAL_REGISTRAR, &old_act));
        restore_signal_handler = TRUE;
        set = rpc_sigreceived(pco_iut);
    }
    else if(strcmp(notify, "callback") == 0)
    {
        ev.notify = RPC_SIGEV_THREAD;
        ev.value.tarpc_sigval_u.sival_int = 1;
        ev.function = "aio_callback_1";
    }
    
    /* Post AIO request */
    buf = rpc_malloc(pco_iut, DATA_BULK);
    cb[0] = rpc_create_aiocb(pco_iut);
    rpc_fill_aiocb(pco_iut, cb[0], iut_s, 0, 0, buf, DATA_BULK, &ev);

    if (strcmp(op, "write") == 0)
        rpc_aio_write(pco_iut, cb[0]);
    else
        rpc_aio_read(pco_iut, cb[0]);
    
    /* Create child process. */
    CHECK_RC(rcf_rpc_server_thread_create(pco_iut, "IUT_thread",
                                          &pco_chld));
    
    /* Call suspend */
    pco_iut->op = RCF_RPC_CALL;
    rpc_aio_suspend(pco_iut, cb, 1, NULL);

    /* Close uit_s from pco_chld */
    RPC_CLOSE(pco_chld, iut_s);

    /* Check that notification has not been delivered */
    if (strcmp(notify, "signal") == 0)
    {
        if (rpc_sigismember(pco_chld, set, RPC_SIGUSR1))
            TEST_FAIL("Notification is delivered after socket closing but "
                      "before request completion");
    }
    else
    {
        len = 2;

        rpc_get_callback_list(pco_chld, list, &len);
        if (len > 0)
            TEST_FAIL("Notification is delivered after socket closing but "
                      "before request completion");
    }

    /* Check that suspend has not unblocked yet */
    CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &done));
    if (done)
        TEST_FAIL("Suspend has unblocked before requests completion");
    
    /* Satisfy AIO request */
    if (strcmp(op, "write") == 0)
        rpc_simple_receiver(pco_tst, tst_s, 0, &n);
    else
        rpc_write(pco_tst, tst_s, rx_buf, DATA_BULK);

    /* Check suspend status */
    rpc_aio_suspend(pco_iut, cb, 2, NULL);
    
    MSLEEP(10);
    
    /* Check that notification has been delivered */
    if (strcmp(notify, "signal") == 0)
    {
        if (!rpc_sigismember(pco_chld, set, RPC_SIGUSR1))
            TEST_FAIL("Signal is not delivered");
    }
    else if (strcmp(notify, "callback") == 0)
    {
        len = 2;
        rpc_get_callback_list(pco_chld, list, &len);
        if (len == 1)
        {
            if ((list->val != 1) || (list->callback_num != 1))
                TEST_FAIL("Wrong callback is delivered");
        }
        else
            TEST_FAIL("Wrong number of callbacks %d is delivered", len);
    }

    /* Check errors */
    if ((rc = rpc_aio_error(pco_iut, cb[0])) != 0)
        TEST_FAIL("aio_error() returned %r after request finishing", rc);
        
    if ((len = rpc_aio_return(pco_iut, cb[0])) != DATA_BULK)
        TEST_FAIL("aio_return() returned %u instead %u", len, DATA_BULK);

    if (strcmp(op, "read") == 0)
    {
        rpc_get_buf(pco_iut, buf, DATA_BULK, (uint8_t *)tx_buf);
        if (memcmp(tx_buf, rx_buf, DATA_BULK) != 0)
        TEST_FAIL("Data sent from the TST do not match data received "
                  "on the IUT");
    }

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
    if (restore_signal_handler)
        CLEANUP_RPC_SIGACTION(pco_iut, RPC_SIGUSR1, &old_act, 
                              SIGNAL_REGISTRAR);
    
    free(list);

    TEST_END;
}
