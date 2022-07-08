/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-lio_listio_nowait  Posting several asynchronous requests
 *
 * @objective Check that several requests may be posted using @b lio_listio()
 *            in non-blocking mode.
 *
 * @param pco_iut     PCO with IUT
 * @param iut_s1      Socket on @p pco_iut
 * @param iut_s2      Socket on @p pco_iut
 * @param pco_tst     Tester PCO
 * @param tst_s1      Socket on @p pco_tst
 * @param tst_s2      Socket on @p pco_tst
 * @param notify      completion notification specified in @a sig parameter
 *                    of the @p lio_listio(): signal, callback, none, null
 *                    (null means that @a sig parameter of lio_listio() 
 *                    is @c NULL)
 *
 * @pre Sockets @p iut_s1 and @p tst_s1 are connected.
 * @pre Sockets @p iut_s2 and @p tst_s2 are connected.
 *
 * @par Scenario
 * -# Overfill transmit buffers of @p iut_s1 and @p iut_s2.
 * -# Create 2 read and 2 write AIO control blocks for socket @p iut_s1 with
 *    specified notification type.
 * -# Create 2 read and 2 write AIO control blocks for socket @p iut_s2 with
 *    specified notification type.
 * -# Post all requests using @b lio_listio(@c LIO_NOWAIT) with specified
 *    notification type.
 * -# Satisfy all requests sending/receiving data via @p tst_s1 and @p tst_s2.
 * -# Check that completion notification for whole @b lio_listio() 
 *    operation (if any) is delivered.
 * -# Check that @b aio_return() for each control block returns correct length.
 * -# Check that requests are completed in order specified in the list.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "aio/lio_listio_nowait"

#include "sockapi-test.h"
#include "aio_internal.h"

#define DATA_BULK       1024       /**< Size of data to be sent */
#define LIST_LEN        8          /**< Number of calls in the list */

static uint8_t tx_buf[LIST_LEN][DATA_BULK];
static uint8_t rx_buf[LIST_LEN][DATA_BULK];

int
main(int argc, char *argv[])
{
    /* Environment variables */
    rpc_socket_type         sock_type;
    const char             *notify;
    
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    
    const struct sockaddr  *iut1_addr;
    const struct sockaddr  *tst1_addr;
    const struct sockaddr  *iut2_addr;
    const struct sockaddr  *tst2_addr;

    /* Auxiliary variables */
    int                     iut_s1 = -1;
    int                     tst_s1 = -1;
    int                     iut_s2 = -1;
    int                     tst_s2 = -1;
    
    unsigned int            len = 2;
    tarpc_callback_item     list[len];
    rpc_aiocb_p             lio_cb[LIST_LEN];
    int                     i;
    rpc_ptr                 buf[LIST_LEN];
    tarpc_sigevent          ev, *pev = &ev;
    
    DEFINE_RPC_STRUCT_SIGACTION(oldsa);
    DEFINE_RPC_STRUCT_SIGACTION(sa);
    te_bool              restore = FALSE;

    TEST_START;
    
#define READ_REQ(i)    (i & 1)
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut1_addr);
    TEST_GET_ADDR(pco_tst, tst1_addr);    
    TEST_GET_ADDR(pco_iut, iut2_addr);
    TEST_GET_ADDR(pco_tst, tst2_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_STRING_PARAM(notify);

    rpc_get_callback_list(pco_iut, NULL, NULL);

    strcpy(sa.mm_handler, AIO_SIGHANDLER_NAME "1");
    sa.mm_mask = rpc_sigset_new(pco_iut);
    rpc_sigemptyset(pco_iut, sa.mm_mask);
    sa.mm_flags = RPC_SA_SIGINFO;
    oldsa.mm_mask = rpc_sigset_new(pco_iut);
    rpc_sigaction(pco_iut, RPC_SIGUSR1, &sa, &oldsa);
    restore = TRUE;
    
    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut1_addr, tst1_addr, &iut_s1, &tst_s1);

    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut2_addr, tst2_addr, &iut_s2, &tst_s2);

    for (i = 0; i < LIST_LEN; i++)
    {
        create_aiocb(pco_iut, i < LIST_LEN / 2 ? iut_s1 : iut_s2, 
                     READ_REQ(i) ? RPC_LIO_READ : RPC_LIO_WRITE,
                     buf + i, DATA_BULK, DATA_BULK, 
                     NULL, lio_cb + i);
        
        te_fill_buf(tx_buf[i], DATA_BULK);
        memset(rx_buf[i], 0, DATA_BULK);
        if (!READ_REQ(i))
            rpc_set_buf(pco_iut, tx_buf[i], DATA_BULK, buf[i]);
    }
    
    INIT_EV(&ev);
    if (strcmp(notify, "callback") == 0)
    {
        ev.notify = RPC_SIGEV_THREAD;
        ev.value.tarpc_sigval_u.sival_int = rand_range(1, 100);
        ev.function = AIO_CALLBACK_NAME "1";
    }
    else if (strcmp(notify, "signal") == 0)
    {
        ev.notify = RPC_SIGEV_SIGNAL;
        ev.value.tarpc_sigval_u.sival_int = rand_range(1, 100);
        ev.signo = RPC_SIGUSR1;
    }
    else if (strcmp(notify, "none") == 0)
        ev.notify = RPC_SIGEV_NONE;
    else if (strcmp(notify, "null") == 0)
        pev = NULL;
    else 
        TEST_FAIL("Incorrect notify parameter is specified");
    
    rpc_lio_listio(pco_iut, RPC_LIO_NOWAIT, lio_cb, LIST_LEN, pev);
    
    for (i = 0; i < LIST_LEN; i++)
    {
        len = 2;
        rpc_get_callback_list(pco_iut, list, &len);
        if (len > 0)
            TEST_FAIL("Notification is delivered before completion "
                      "of all requests");
            
        if (READ_REQ(i))
        {
            rpc_write(pco_tst, i < LIST_LEN / 2 ? tst_s1 : tst_s2, 
                      tx_buf[i], DATA_BULK);
        }
        else
        {
            rpc_read(pco_tst, i < LIST_LEN / 2 ? tst_s1 : tst_s2, 
                     rx_buf[i], DATA_BULK);
        }
    }
    MSLEEP(10);

    len = 2;
    rpc_get_callback_list(pco_iut, list, &len);
    if (pev == NULL || ev.notify == RPC_SIGEV_NONE)
    {
        if (len > 0)
            TEST_FAIL("Unexpected notification is delivered");
    }
    else 
    {
        if (len < 1)
            TEST_FAIL("No notification is delivered");
            
        if (len > 1)
            TEST_FAIL("Notification is delivered twice");
            
        if (ev.notify == RPC_SIGEV_SIGNAL && list[0].signo != RPC_SIGUSR1)
            TEST_FAIL("SIGUSR1 is not delivered");

        if (ev.notify == RPC_SIGEV_THREAD && list[0].signo != 0)
            TEST_FAIL("Signal is delivered instead callback calling");
            
        if (list[0].val != ev.value.tarpc_sigval_u.sival_int)
            TEST_FAIL("Incorrect value is provided to %s",
                      ev.notify == RPC_SIGEV_SIGNAL ? "signal handler "
                                                    : "callback");
    }
    
    for (i = 0; i < LIST_LEN; i++)       
    {
        if ((rc = rpc_aio_error(pco_iut, lio_cb[i])) != 0)
            TEST_FAIL("aio_error() returned %r instead 0", rc);
            
        if ((rc = rpc_aio_return(pco_iut, lio_cb[i])) != DATA_BULK)
            TEST_FAIL("aio_return() returned %d instead %d", rc, DATA_BULK);
    }
    
    for (i = 0; i < LIST_LEN; i++)
    {
        if (READ_REQ(i))
            rpc_get_buf(pco_iut, buf[i], DATA_BULK, rx_buf[i]);
            
        if (memcmp(rx_buf[i], tx_buf[i], DATA_BULK) != 0)
            TEST_FAIL("Data are corrupted during transmission");
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s1);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s2);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s1);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s2);
    
    for (i = 0; i < LIST_LEN; i++)
    {
        CLEANUP_RPC_DELETE_AIOCB(pco_iut, lio_cb[i]);
        CLEANUP_RPC_FREE(pco_iut, buf[i]);
    }

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
