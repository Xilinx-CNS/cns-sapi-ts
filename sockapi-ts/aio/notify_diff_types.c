/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-notify_diff_types  Different notification types for different requests
 *
 * @objective Check that it's possible to specify different notification
 *            types for different requests.
 *
 * @param pco_iut   PCO with IUT
 * @param iut_s     Socket on @p pco_iut
 * @param pco_tst   Tester PCO
 * @param tst_s     Socket on @p pco_tst
 * @param op        Request to be posted: read or write
 * @param notify    "cb" if notification should be specified in
 *                  AIO control block or
 *                  "sig" if notification should be specified in @a sig 
 *                  parameter of lio_listio()       
 * 
 * @pre Sockets @p iut_s and @p tst_s are connected.
 *
 * @par Scenario
 * -# If @p op is "write', overfill transmit buffers of @p iut_s socket.
 * -# Install signal handler for @c SIGUSR1.
 * -# If @p op is "read", post two read requests using @b aio_read() 
 *    (if @p notify is "cb") or @b lio_listio(@c LIO_NOWAIT) (otherwise).
 * -# If @p op is "write", post two write requests using @b aio_write() 
 *    (if @p notify is "cb") or @b lio_listio(LIO_NOWAIT) (otherwise).
 * -# Notification type of the first request should be @c SIGEV_THREAD with
 *    some callback; notification type of the second request should be 
 *    @c SIGEV_SIGNAL with signal @c SIGUSR1.
 * -# Satisfy both requests sending or receiving data via @p tst_s.
 * -# Check that the callback is called and signal is delivered.
 * -# Using @b aio_error() and @b aio_return() check completion status
 *    of both requests.
 * -# Check that transferred data are not corrupted.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "aio/notify_diff_types"

#include "sockapi-test.h"
#include "aio_internal.h"

#define DATA_BULK       1024  /**< Size of data to be sent */

static uint8_t tx_buf[DATA_BULK];

int
main(int argc, char *argv[])
{
    /* Environment variables */
    rpc_socket_type     sock_type;

    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;
    
    te_bool rd;
    te_bool notify_cb;

    /* Auxiliary variables */
    int iut_s = -1;
    int tst_s = -1;
    
    uint64_t n;
    
    DEFINE_RPC_STRUCT_SIGACTION(oldsa);
    DEFINE_RPC_STRUCT_SIGACTION(sa);
    te_bool              restore = FALSE;
    
    rpc_aiocb_p  cb[2] = { RPC_NULL, RPC_NULL };
    rpc_ptr      buf[2] = { RPC_NULL, RPC_NULL };
    
    tarpc_sigevent ev[2];

    tarpc_callback_item list[3];
    
    te_bool cb_ok = FALSE, sh_ok = FALSE;
    
    unsigned int len;
    int i;
    
    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(rd);
    TEST_GET_BOOL_PARAM(notify_cb);

    /* Reset list */
    rpc_get_callback_list(pco_iut, NULL, NULL);
    
    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    strcpy(sa.mm_handler, AIO_SIGHANDLER_NAME "1");
    sa.mm_mask = rpc_sigset_new(pco_iut);
    rpc_sigemptyset(pco_iut, sa.mm_mask);
    sa.mm_flags = RPC_SA_SIGINFO;
    oldsa.mm_mask = rpc_sigset_new(pco_iut);
    rpc_sigaction(pco_iut, RPC_SIGUSR1, &sa, &oldsa);
    restore = TRUE;
                   
    if (sock_type == RPC_SOCK_STREAM && !rd)
        rpc_overfill_buffers(pco_iut, iut_s, &n);

    INIT_EV(ev);
    INIT_EV(ev + 1);
    
    ev[0].notify = RPC_SIGEV_SIGNAL;
    ev[0].value.tarpc_sigval_u.sival_int = 1;
    ev[0].signo = RPC_SIGUSR1;

    ev[1].notify = RPC_SIGEV_THREAD;
    ev[1].value.tarpc_sigval_u.sival_int = 2;
    ev[1].function = AIO_CALLBACK_NAME "1";

    create_aiocb(pco_iut, iut_s, rd ? RPC_LIO_READ : RPC_LIO_WRITE,
                 buf, DATA_BULK, DATA_BULK, 
                 notify_cb ? ev : NULL, cb);

    create_aiocb(pco_iut, iut_s, rd ? RPC_LIO_READ : RPC_LIO_WRITE,
                 buf + 1, DATA_BULK, DATA_BULK, 
                 notify_cb ? ev + 1 : NULL, cb + 1);

    if (rd)
        te_fill_buf(tx_buf, DATA_BULK);
    else
    {
        rpc_set_buf_pattern(pco_iut, TAPI_RPC_BUF_RAND, DATA_BULK, buf[0]);
        rpc_set_buf_pattern(pco_iut, TAPI_RPC_BUF_RAND, DATA_BULK, buf[1]);
    }

    if (!notify_cb)
    {
        rpc_lio_listio(pco_iut, RPC_LIO_NOWAIT, cb, 1, ev);
        rpc_lio_listio(pco_iut, RPC_LIO_NOWAIT, cb + 1, 1, ev + 1);
    }
    else if (rd)
    {
        rpc_aio_read(pco_iut, cb[0]);
        rpc_aio_read(pco_iut, cb[1]);
    }
    else
    {
        rpc_aio_write(pco_iut, cb[0]);
        rpc_aio_write(pco_iut, cb[1]);
    }
        
    if (rd || sock_type == RPC_SOCK_STREAM)
    {
        /* Check that notification is not received yet */
        SLEEP(1);
        len = sizeof(list) / sizeof(list[0]);
        rpc_get_callback_list(pco_iut, list, &len);
        if (len != 0)
            TEST_FAIL("Notification is received before request completion");
    }
        
    if (rd)
    {
        rpc_write(pco_tst, tst_s, tx_buf, DATA_BULK);
        rpc_write(pco_tst, tst_s, tx_buf, DATA_BULK);
        MSLEEP(10);
    }
    else
        rpc_simple_receiver(pco_tst, tst_s, 3, &n);

    len = sizeof(list) / sizeof(list[0]);
    rpc_get_callback_list(pco_iut, list, &len);
    
    for (i = 0; i < (int)len; i++)
    {
        if (list[i].signo == 0)
        {
            if (cb_ok)
                TEST_FAIL("Callback notification is received twice");
                
            if (list[i].val != 2)
                TEST_FAIL("Incorrect value is passed to the "
                          "completion callback");
                          
             cb_ok = TRUE;
        }
        else
        {
            if (sh_ok)
                TEST_FAIL("Signal notification is received twice");
                
            if (list[i].val != 1)
                TEST_FAIL("Incorrect value is passed to the "
                          "signal handler");
                          
            sh_ok = TRUE;
        }
    }
    
    if (!cb_ok)
        TEST_FAIL("Callback notification is not received");
        
    if (!sh_ok)
        TEST_FAIL("Signal notification is not received");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    if (result != 0)
    {
        CLEANUP_AIO_CANCEL(pco_iut, iut_s, cb[0]);
        CLEANUP_AIO_CANCEL(pco_iut, iut_s, cb[1]);
    }
    CLEANUP_RPC_DELETE_AIOCB(pco_iut, cb[0]);
    CLEANUP_RPC_DELETE_AIOCB(pco_iut, cb[1]);
    CLEANUP_RPC_FREE(pco_iut, buf[0]);
    CLEANUP_RPC_FREE(pco_iut, buf[1]);

    if (restore)
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        if (rpc_sigaction(pco_iut, RPC_SIGUSR1, &oldsa, NULL) < 0)
            result = -1;
    }
    CLEANUP_RPC_FREE(pco_iut, sa.mm_mask);
    CLEANUP_RPC_FREE(pco_iut, oldsa.mm_mask);

    TEST_END;
}
