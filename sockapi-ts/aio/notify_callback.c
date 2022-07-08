/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-notify_callback  AIO request completion notification using callback
 *
 * @objective Check that AIO request completion notification using callback
 *            is performed properly.
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
 * -# If @p op is "write", overfill transmit buffers of @p iut_s socket.
 * -# Construct AIO control block @p cb with @a aio_lio_opcode corresponding to
 *    @p op, @a aio_fildes equal to @p iut_s and correct @a aio_buf 
 *    and @a aio_nbytes.
 * -# Construct sigevent @p se with @a sigev_notify equal to @c SIGEV_THREAD,
 *    @a sigev_value equal to random number @c V and the callback which saves
 *    its parameter to the global variable @p X.
 * -# If @p notify is "cb", assign @p se value to @a aio_sigevent of @p cb.
 * -# Otherwise assign @a sigev_notify of @a aio_sigevent of @p cb to 
 *    @c SIGEV_NONE.
 * -# If @p notify is "sig", post the request using @b lio_listio(@c LIO_NOWAIT).
 * -# Otherwise if @p op is "write", post the request using either @b aio_write().
 * -# Otherwise if @p op is "read", post the request using either @b aio_read().
 * -# Satisfy the request sending or receiving data via @p tst_s.
 * -# Check that value of the variable @p X is @c V.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "aio/notify_callback"

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
    
    rpc_aiocb_p  cb = RPC_NULL;
    rpc_ptr      buf = RPC_NULL;
    
    tarpc_sigevent ev;

    tarpc_callback_item list[2];
    unsigned int        len;
    
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

    if (sock_type == RPC_SOCK_STREAM && !rd)
        rpc_overfill_buffers(pco_iut, iut_s, &n);

    INIT_EV(&ev);
    ev.notify = RPC_SIGEV_THREAD;
    ev.value.tarpc_sigval_u.sival_int = rand_range(1, 100);
    ev.function = AIO_CALLBACK_NAME "1";

    create_aiocb(pco_iut, iut_s, rd ? RPC_LIO_READ : RPC_LIO_WRITE,
                 &buf, DATA_BULK, DATA_BULK, 
                 notify_cb ? &ev : NULL, &cb);

    if (rd)
        te_fill_buf(tx_buf, DATA_BULK);
    else
        rpc_set_buf_pattern(pco_iut, TAPI_RPC_BUF_RAND, DATA_BULK, buf);

    if (!notify_cb)
        rpc_lio_listio(pco_iut, RPC_LIO_NOWAIT, &cb, 1, &ev);
    else if (rd)
        rpc_aio_read(pco_iut, cb);
    else
        rpc_aio_write(pco_iut, cb);
        
    if (rd || sock_type == RPC_SOCK_STREAM)
    {
        /* Check that notification is not received yet */
        SLEEP(1);
        len = 2;
        rpc_get_callback_list(pco_iut, list, &len);
        if (len != 0)
            TEST_FAIL("Notification is received before request completion");
    }
        
    if (rd)
    {
        rpc_write(pco_tst, tst_s, tx_buf, DATA_BULK);
        MSLEEP(10);
    }
    else
        rpc_simple_receiver(pco_tst, tst_s, 3, &n);

    len = 2;
    rpc_get_callback_list(pco_iut, list, &len);
    if (len > 1)
        TEST_FAIL("Notification is received twice");
        
    if (len == 0)
        TEST_FAIL("Callback notification is not received");
        
    if (list->val != ev.value.tarpc_sigval_u.sival_int)
        TEST_FAIL("Incorrect value is passed to callback: "
                  "%d instead %d", list->val, 
                  ev.value.tarpc_sigval_u.sival_int);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    if (result != 0)
        CLEANUP_AIO_CANCEL(pco_iut, iut_s, cb);
    CLEANUP_RPC_DELETE_AIOCB(pco_iut, cb);
    CLEANUP_RPC_FREE(pco_iut, buf);

    TEST_END;
}

