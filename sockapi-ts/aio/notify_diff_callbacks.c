/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-notify_diff_callbacks  Different callbacks for different requests
 *
 * @objective Check that correct callback is called when AIO request is
 *            completed.
 *
 * @param pco_iut   PCO with IUT
 * @param iut_s     Socket on @p pco_iut
 * @param pco_tst   Tester PCO
 * @param tst_s     Socket on @p pco_tst
 * 
 * @pre Sockets @p iut_s and @p tst_s are connected.
 *
 * @par Scenario
 * -# Overfill transmit buffers of @p iut_s socket.
 * -# Construct @p N sigevents @p se1, ... @p seN with 
 *    @a sigev_notify equal to @c SIGEV_THREAD, @a sigev_value equal to random 
 *    numbers @c V1, ... @c VN and different callbacks.
 * -# Construct @p N AIO control blocks with @c LIO_READ and @c LIO_WRITE
 *    operation codes.
 * -# Post requests using @b aio_read(), @b aio_write() or 
 *    @b lio_listio(@c LIO_NOWAIT). If @b lio_listio() is used for request 
 *    posting, corresponding @p se should be passed as parameter @a sig
 *    of @p lio_listio(); otherwise it should be copied to @a aio_sigevent
 *    of the corresponding control block.
 * -# Satisfy all requests sending/receiving data via @p tst_s.
 * -# Check that all callbacks are called with proper values.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#ifndef DOXYGEN_TEST_SPEC

#define TE_TEST_NAME  "aio/notify_diff_callbacks"

#include "sockapi-test.h"
#include "aio_internal.h"

#define DATA_BULK       1024  /**< Size of data to be sent */

static rcf_rpc_server *pco_iut = NULL;
static int iut_s = -1;            

static uint8_t aux_buf[DATA_BULK]; /**< Auxiliary buffer */

/** Type of the request to be posted */
typedef enum {
    REQ_AIO_READ,       /**< aio_read() */
    REQ_LIO_READ,       /**< lio_istio() with LIO_READ */
    REQ_AIO_WRITE,      /**< aio_write() */
    REQ_LIO_WRITE,      /**< lio_listio() with LIO_WRITE */
} req_type;

/** Four requests for each request type */
#define REQ_NUM         16

/** AIO request posted on pco_iut */
typedef struct posted_req {
    rpc_aiocb_p  cb;            /**< AIO control block handle */
    rpc_ptr      buf;           /**< TX/RX buffer */
    int          callback;      /**< Number of callback */
    te_bool      notify;        /**< If TRUE, the notification is
                                     received */
} posted_req;    

/** List of all posted requests */
static posted_req reqs[REQ_NUM];

/**
 * Create and post AIO request of specified type.
 *
 * @param type          type of the request (see req_type)
 * @param signo         signal to be used for completion notification
 */
static void
post_request(req_type type, int callback)
{
    static int  ind = 0;
    posted_req *tmp = reqs + ind;
    
    char function[32];
    
    tarpc_sigevent ev;
    
    if (tmp == NULL)
        TEST_FAIL("Out of memory");
        
    INIT_EV(&ev);
    ev.notify = RPC_SIGEV_THREAD;
    ev.value.tarpc_sigval_u.sival_int = ++ind;
    sprintf(function, AIO_CALLBACK_NAME "%d", callback);
    ev.function = function;
    tmp->callback = callback;
    
    create_aiocb(pco_iut, iut_s, 
                 (type == REQ_AIO_READ || type == REQ_LIO_READ) ?
                 RPC_LIO_READ : RPC_LIO_WRITE,
                 &tmp->buf, DATA_BULK, DATA_BULK, 
                 (type == REQ_AIO_READ || type == REQ_AIO_WRITE) ?
                 &ev : NULL, &tmp->cb);

    switch (type)
    {
        case REQ_AIO_READ:
            rpc_aio_read(pco_iut, tmp->cb);
            break;

        case REQ_AIO_WRITE:
            rpc_aio_write(pco_iut, tmp->cb);
            break;
            
        default:
            rpc_lio_listio(pco_iut, RPC_LIO_NOWAIT, &tmp->cb, 1, &ev);
            break;
    }
}

int
main(int argc, char *argv[])
{
    /* Environment variables */
    rpc_socket_type     sock_type;

    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;
    
    /* Auxiliary variables */
    int tst_s = -1;
    int i, k = 1;
    unsigned int len;

    tarpc_callback_item list[REQ_NUM + 1];
    
    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);

    /* Reset callback list on IUT */
    rpc_get_callback_list(pco_iut, NULL, NULL);
    
    te_fill_buf(aux_buf, DATA_BULK);
    
    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);
    
    if (sock_type != RPC_SOCK_DGRAM)
    {
        uint64_t sent;
        
        rpc_overfill_buffers(pco_iut, iut_s, &sent);
    }
    
    /* 
     * Post 8 requests with unique callback per request type and
     * 8 requests with the same callback but different values.
     */
    for (i = REQ_AIO_READ; i <= REQ_LIO_WRITE; i++)
    {
        post_request(i, k++);
        post_request(i, k++);
        post_request(i, 9);
        post_request(i, 9);
    }

    /* Satisfy read requests one-by-one */
    for (i = 0; i < REQ_NUM / 2; i++)
    {
        /* 
         * Due problem with Linux AIO write on TCP peer may block. 
         * This test checks the notification mechanism only, 
         * so forgive them their problems.
         */
        RPC_AWAIT_IUT_ERROR(pco_tst);
        rpc_send(pco_tst, tst_s, aux_buf, DATA_BULK, RPC_MSG_DONTWAIT);
        MSLEEP(10);
    }

    while (TRUE)
    {
        /* 
         * Due problem with Linux AIO some UDP datagrams are lost
         * (read on Tester may block for UDP).
         * This test checks the notification mechanism only, 
         * so forgive them their problems.
         */
        RPC_AWAIT_IUT_ERROR(pco_tst);
        if (rpc_recv(pco_tst, tst_s, aux_buf, DATA_BULK, 
                     RPC_MSG_DONTWAIT) < 0)
        {
            break;
        }
        MSLEEP(10);
    }
    
    len = sizeof(list) / sizeof(list[0]);
    rpc_get_callback_list(pco_iut, list, &len);

    for (i = 0; i < (int)len; i++)
    {
        if (list[i].val > REQ_NUM)
            TEST_FAIL("Unexpected notification is received: "
                      "callback %d signo %d value %d", 
                      list[i].callback_num, list[i].signo, list[i].val);

        posted_req *req = reqs + list[i].val - 1;
        
        if (req->notify)
            TEST_FAIL("Completion notification is received twice for "
                      "request %d", list[i].val); 
             
        if (list[i].callback_num != req->callback)
            TEST_FAIL("Unexpected callback is called: "
                      AIO_CALLBACK_NAME "%d instead "AIO_CALLBACK_NAME"%d "
                      "for request %d", list[i].callback_num, req->callback);
        
        req->notify = TRUE;
    }
    
    for (i = 0; i < REQ_NUM; i++)
        if (!reqs[i].notify)
            TEST_FAIL("Completion notification for request %d "
                      "is not received", i + 1);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    
    for (i = 0; i < REQ_NUM && reqs[i].cb != RPC_NULL; i++)
    {
        CLEANUP_AIO_CANCEL(pco_iut, iut_s, reqs[i].cb);
        CLEANUP_RPC_DELETE_AIOCB(pco_iut, reqs[i].cb);
        CLEANUP_RPC_FREE(pco_iut, reqs[i].buf);
    }
    
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

                       
    TEST_END;
}

#endif /* !DOXYGEN_TEST_SPEC */
