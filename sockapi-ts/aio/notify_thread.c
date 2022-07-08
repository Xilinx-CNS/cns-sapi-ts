/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-notify_thread  Notification of the thread by the signal
 *
 * @objective Check that signal is delivered to the thread posted the request.
 *
 * @param pco_iut   PCO with IUT
 * @param iut_s     Socket on @p pco_iut
 * @param pco_tst   Tester PCO
 * @param tst_s     Socket on @p pco_tst
 * 
 * @pre Sockets @p iut_s and @p tst_s are connected.
 *
 * @par Scenario
 * -# Create a thread @p pco_child on the @p pco_iut.
 * -# Install signal handler on the @p pco_iut.
 * -# Post read AIO request on the @p pco_iut with signal completion 
 *    notification.
 * -# Block on @b select() with timeout 2 seconds on @p pco_iut.
 * -# Satisfy the request sending data via @p tst_s.
 * -# Check that @b select() unblocked immediately.
 * -# Post read AIO request on the @p pco_iut with signal completion 
 *    notification.
 * -# Block on @b select() with timeout 2 seconds on @p pco_child.
 * -# Satisfy the request sending data via @p tst_s.
 * -# Check that @b select() unblocked after timeout expiration.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "aio/notify_thread"

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
    rcf_rpc_server *pco_child = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    /* Auxiliary variables */
    int iut_s = -1;
    int tst_s = -1;
    
    DEFINE_RPC_STRUCT_SIGACTION(oldsa);
    DEFINE_RPC_STRUCT_SIGACTION(sa);
    te_bool              restore = FALSE;
    
    rpc_aiocb_p  cb = RPC_NULL;
    rpc_ptr      buf = RPC_NULL;
    
    tarpc_sigevent ev;

    tarpc_callback_item list[2];
    unsigned int        len;
    tarpc_timeval       tv = { 0, 0 };
    
    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);

    /* Reset list */
    rpc_get_callback_list(pco_iut, NULL, NULL);

    CHECK_RC(rcf_rpc_server_thread_create(pco_iut, "child",
                                          &pco_child));
    
    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    strcpy(sa.mm_handler, AIO_SIGHANDLER_NAME "1");
    sa.mm_mask = rpc_sigset_new(pco_iut);
    rpc_sigemptyset(pco_iut, sa.mm_mask);
    sa.mm_flags = RPC_SA_SIGINFO;
    oldsa.mm_mask = rpc_sigset_new(pco_iut);
    rpc_sigaction(pco_iut, RPC_SIGUSR1, &sa, &oldsa);
    restore = TRUE;
                   
    INIT_EV(&ev);
    ev.notify = RPC_SIGEV_SIGNAL;
    ev.value.tarpc_sigval_u.sival_int = rand_range(1, 100);
    ev.signo = RPC_SIGUSR1;

    create_aiocb(pco_iut, iut_s, RPC_LIO_READ, &buf, DATA_BULK, DATA_BULK, 
                 &ev, &cb);

    rpc_aio_read(pco_iut, cb);

    rpc_gettimeofday(pco_tst, &tv, NULL);
    pco_tst->start = (tv.tv_sec + 1) * 1000 + tv.tv_usec / 1000;
    pco_tst->op = RCF_RPC_CALL;
    rpc_write(pco_tst, tst_s, tx_buf, DATA_BULK);
    
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_select(pco_iut, 0, RPC_NULL, RPC_NULL, RPC_NULL, &tv);
    rpc_write(pco_tst, tst_s, tx_buf, DATA_BULK);
    
    if (rc != -1)
        TEST_FAIL("select() is not unblocked by the signal");

    len = 2;
    rpc_get_callback_list(pco_iut, list, &len);
    if (len == 0)
        TEST_FAIL("Signal notification is not received");

    rpc_aio_read(pco_iut, cb);

    rpc_gettimeofday(pco_tst, &tv, NULL);
    pco_tst->start = (tv.tv_sec + 1) * 1000 + tv.tv_usec / 1000;
    pco_tst->op = RCF_RPC_CALL;
    rpc_write(pco_tst, tst_s, tx_buf, DATA_BULK);
    
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    rc = rpc_select(pco_child, 0, RPC_NULL, RPC_NULL, RPC_NULL, &tv);
    rpc_write(pco_tst, tst_s, tx_buf, DATA_BULK);
    
    if (rc != 0)
        TEST_FAIL("select() is unblocked by the signal in the other thread");

    len = 2;
    rpc_get_callback_list(pco_iut, list, &len);
    if (len == 0)
        TEST_FAIL("Signal notification is not received");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    if (result != 0)
        CLEANUP_AIO_CANCEL(pco_iut, iut_s, cb);
    CLEANUP_RPC_DELETE_AIOCB(pco_iut, cb);
    CLEANUP_RPC_FREE(pco_iut, buf);

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

