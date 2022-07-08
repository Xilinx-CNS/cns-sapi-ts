/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-notify_diff_signals  Different signals for different requests
 *
 * @objective Check that correct signal is sent when AIO request is
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
 * -# Overfill transmit buffers of @p iut_s socket (for stream sockets only).
 * -# Construct @p N sigevents @p se1, ... @p seN with 
 *    @a sigev_notify equal to @c SIGEV_SIGNAL, @a sigev_value equal to random 
 *    numbers @c V1, ... @c VN and different signal numbers.
 * -# Install signal handlers for all used signals calling @b sigaction() 
 *    with @a sa_flags @c SA_SIGINFO.
 * -# Construct @p N AIO control blocks with @c LIO_READ and @c LIO_WRITE
 *    operation codes.
 * -# Post requests using @b aio_read(), @b aio_write() or 
 *    @b lio_listio(@c LIO_NOWAIT). If @b lio_listio() is used for request 
 *    posting, corresponding @p se should be passed as parameter @a sig
 *    of @p lio_listio(); otherwise it should be copied to @a aio_sigevent
 *    of the corresponding control block.
 * -# Satisfy all requests sending/receiving data via @p tst_s.
 * -# Check that all signal handlers are called with proper values.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#ifndef DOXYGEN_TEST_SPEC

#define TE_TEST_NAME  "aio/notify_diff_signals"

#include "sockapi-test.h"
#include "aio_internal.h"

#define DATA_BULK       1024  /**< Size of data to be sent */

static rcf_rpc_server *pco_iut = NULL;
static int             iut_s = -1;            

static rcf_rpc_server *pco_tst = NULL;
static int             tst_s = -1;


static uint8_t aux_buf[DATA_BULK]; /**< Auxiliary buffer */

/** Type of the request to be posted */
typedef enum {
    REQ_AIO_READ,       /**< aio_read() */
    REQ_LIO_READ,       /**< lio_istio() with LIO_READ */
    REQ_AIO_WRITE,      /**< aio_write() */
    REQ_LIO_WRITE,      /**< lio_listio() with LIO_WRITE */
} req_type;

/** Four request for each request type */
#define REQ_NUM         16

/** AIO request posted on pco_iut */
typedef struct posted_req {
    rpc_aiocb_p  cb;            /**< AIO control block handle */
    rpc_ptr      buf;           /**< TX/RX buffer */
    rpc_signum   signo;         /**< Signal number */
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
post_request(req_type type, rpc_signum signo)
{
    static int  ind = 0;
    posted_req *tmp = reqs + ind;
    
    tarpc_sigevent ev;
    
    if (tmp == NULL)
        TEST_FAIL("Out of memory");
        
    INIT_EV(&ev);
    ev.notify = RPC_SIGEV_SIGNAL;
    ev.value.tarpc_sigval_u.sival_int = ++ind;
    tmp->signo = ev.signo = signo;
    
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

void
post_requests_and_satisfy_requests(req_type type)
{
    int i;
    int len;

    post_request(type, RPC_SIGUSR1);
    post_request(type, RPC_SIGUSR2);
    
    if (type == REQ_AIO_READ || type == REQ_LIO_READ)
        for (i = 0; i < REQ_NUM / 8; i++)
        {
            RPC_AWAIT_IUT_ERROR(pco_tst);
            rpc_send(pco_tst, tst_s, aux_buf, DATA_BULK, RPC_MSG_DONTWAIT);
        }

    else
        while (TRUE)
        {
            RPC_AWAIT_IUT_ERROR(pco_tst);
            if ((len = rpc_recv(pco_tst, tst_s, aux_buf, DATA_BULK,
                            RPC_MSG_DONTWAIT)) <= 0)
            {
                if (len == 0)
                    TEST_FAIL("recv() function returned 0 unexpectedly");
                break;
            }
        }
}

int
main(int argc, char *argv[])
{
    /* Environment variables */
    rpc_socket_type     sock_type;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;
    
    /* Auxiliary variables */
    int i;
    unsigned int len;

    tarpc_callback_item list[REQ_NUM + 1];

    DEFINE_RPC_STRUCT_SIGACTION(oldsa1);
    DEFINE_RPC_STRUCT_SIGACTION(oldsa2);
    DEFINE_RPC_STRUCT_SIGACTION(sa1);
    DEFINE_RPC_STRUCT_SIGACTION(sa2);
    
    te_bool restore1 = FALSE, restore2 = FALSE;
    
    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);

    /* Reset callback list on IUT */
    rpc_get_callback_list(pco_iut, NULL, NULL);
    
    /* Install signal handler */
    sa1.mm_mask = rpc_sigset_new(pco_iut);
    rpc_sigemptyset(pco_iut, sa1.mm_mask);
    rpc_sigaddset(pco_iut, sa1.mm_mask, RPC_SIGUSR1);
    rpc_sigaddset(pco_iut, sa1.mm_mask, RPC_SIGUSR2);
    sa1.mm_flags = RPC_SA_SIGINFO;
    sa2 = sa1;
    strcpy(sa1.mm_handler, AIO_SIGHANDLER_NAME "1");
    strcpy(sa2.mm_handler, AIO_SIGHANDLER_NAME "2");
    
    oldsa1.mm_mask = rpc_sigset_new(pco_iut);
    rpc_sigaction(pco_iut, RPC_SIGUSR1, &sa1, &oldsa1);
    restore1 = TRUE;

    oldsa2.mm_mask = rpc_sigset_new(pco_iut);
    rpc_sigaction(pco_iut, RPC_SIGUSR2, &sa2, &oldsa2);
    restore2 = TRUE;

    te_fill_buf(aux_buf, DATA_BULK);
    
    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);
    
    if (sock_type != RPC_SOCK_DGRAM)
    {
        uint64_t sent;
        
        rpc_overfill_buffers(pco_iut, iut_s, &sent);
    }
    
    for (i = REQ_AIO_READ; i <= REQ_LIO_WRITE; i++)
    {
        post_requests_and_satisfy_requests(i);
        post_requests_and_satisfy_requests(i);
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
             
        if (list[i].signo != req->signo)
            TEST_FAIL("Unexpected signal is received: %s instead %s for "
                      "request %d", 
                      signum_rpc2str(list[i].signo),
                      signum_rpc2str(req->signo), list[i].val);
        
        req->notify = TRUE;
    }
    
    for (i = 0; i < REQ_NUM; i++)
        if (!reqs[i].notify)
            TEST_FAIL("Completion notification for request %d "
                      "is not received", i + 1);

    TEST_SUCCESS;

cleanup:
    /* Restore signal handlers */
    if (restore1)
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        if (rpc_sigaction(pco_iut, RPC_SIGUSR1, &oldsa1, NULL) < 0)
            result = -1;
    }

    if (restore2)
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        if (rpc_sigaction(pco_iut, RPC_SIGUSR2, &oldsa2, NULL) < 0)
            result = -1;
    }
    CLEANUP_RPC_FREE(pco_iut, sa1.mm_mask);
    CLEANUP_RPC_FREE(pco_iut, oldsa1.mm_mask);
    CLEANUP_RPC_FREE(pco_iut, oldsa2.mm_mask);

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
