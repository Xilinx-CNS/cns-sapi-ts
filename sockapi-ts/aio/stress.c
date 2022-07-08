/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-stress  Post many aio requests for many sockets from different threads
 *
 * @objective Stress testing of asynchronous data sending/receiving.
 *
 * @param pco_iut   PCO with IUT
 * @param pco_tst   Tester PCO
 * @param T         Number of therads used on @p pco_iut
 * @param S         Number of sockets used on @p pco_iut
 * @param R         Number of AIO requests 
 *
 * @par Scenario
 * -# Create @p S connections between @p pco_iut and @p pco_tst 
 *    with randomly choosen socket types: @c SOCK_STREAM or @c SOCK_DGRAM.
 * -# Overfill transmit buffers for all @p pco_iut sockets (for stream
 *    sockets only).
 * -# Create @p T threads on @p pco_iut.
 * -# Construct @p R AIO control blocks. Choose for each randomly
 *    the @p pco_iut socket, operation (read/write), thread, notification type
 *    (callback, signal, none) and function to be used for posting:
 *    @b aio_read(), @b aio_write(), @b lio_listio().
 * -# Post all requests.
 * -# Send/receive a lot of data via all connections on @p pco_tst to
 *    satisfy all requests.
 * -# Check status of each request using @b aio_error() and @b aio_return().
 * -# Check that notification is delivered for all requests.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#ifndef DOXYGEN_TEST_SPEC

#define TE_TEST_NAME  "aio/stress"

#include "sockapi-test.h"
#include "aio_internal.h"

#define DATA_BULK       1024  /**< Maximum size of data to be sent */

/** A connection between PCO IUT and PCO TST */
typedef struct connection {
    rpc_socket_type sock_type;      /**< Stream or datagram */
    int             iut_s;          /**< Socket of the PCO IUT */
    int             tst_s;          /**< Socket on PCO Tester */
    uint64_t        sent_from_iut;  /**< Number of bytes sent from
                                         IUT during buffers overfilling
                                         and in AIO requests */
    uint64_t        rcvd_from_iut;  /**< Amount of data received from IUT */
    rcf_rpc_server *sender;         /**< Thread for data sending */
    rcf_rpc_server *receiver;       /**< Thread for data receiving */
} connection;

/** Array of created connections */
static connection *conns;

/** Array of threads on the pco_iut */
static rcf_rpc_server **threads;

typedef struct posted_req {
    int             index;      /**< Request index */
    connection     *conn;       /**< Connection for request posting */
    rpc_aiocb_p     cb;         /**< AIO control block */
    tarpc_sigevent  ev;         /**< Completion notification mode */
    rpc_ptr         buf;        /**< Remote buffer */
    int             len;        /**< aio_bytes value */
    te_bool         rd;         /**< If TRUE, read request is posted */
    te_bool         lio;        /**< If TRUE, request is posted using
                                     lio_listio() */
    te_bool         sig_lio;    /**< If TRUE, lio_listio() notification
                                     is requested */
    te_bool         notify;     /**< Completion notification is received */
} posted_req;

/** Array of posted requests */
static posted_req *reqs;

static uint32_t sock_num, threads_num, req_num;
    

/** Convert request index to request rescription */
static char *
req2str(posted_req *req)
{
    static char buf[128];
    
    sprintf(buf, "request %d on socket %d: %s, notification %s%s", 
            req->index, req->conn->iut_s, 
            req->lio ? (req->rd ? "lio_listio(LIO_READ)"
                                : "lio_listio(LIO_WRITE)") :
                       (req->rd ? "aio_read()" : "aio_write"),
            sigev_notify_rpc2str(req->ev.notify),
            req->sig_lio ? " in lio_listio() parameter" : "");
            
    return buf;            
}

/** Create and post AIO request. */
static void
post_request(int i)
{
    rcf_rpc_server *rpcs = threads[rand_range(0, threads_num - 1)];

    reqs[i].index = i + 1;
    reqs[i].conn = conns + rand_range(0, sock_num - 1);
    reqs[i].rd = rand_range(FALSE, TRUE);
    reqs[i].lio = rand_range(FALSE, TRUE);
//    reqs[i].sig_lio = reqs[i].lio && rand_range(FALSE, TRUE);
    reqs[i].sig_lio = reqs[i].lio;
    reqs[i].len = rand_range(1, DATA_BULK);
    
    /* Choose notification type */
    INIT_EV(&reqs[i].ev);
    reqs[i].ev.notify = rand_range(RPC_SIGEV_SIGNAL, RPC_SIGEV_THREAD);
    if (reqs[i].ev.notify == RPC_SIGEV_THREAD)
    {
        char fname[32];
    
        reqs[i].ev.value.tarpc_sigval_u.sival_int = i;
        TE_SPRINTF(fname, AIO_CALLBACK_NAME"%d", rand_range(1, 5));
        reqs[i].ev.function = strdup(fname);
        if (reqs[i].ev.function == NULL)
            TEST_FAIL("Out of memory");
    }
    else if (reqs[i].ev.notify == RPC_SIGEV_SIGNAL)
    {
        reqs[i].ev.value.tarpc_sigval_u.sival_int = i;
        reqs[i].ev.signo = rand_range(FALSE, TRUE) ? RPC_SIGUSR1 
                                                   : RPC_SIGUSR2;
    }

    create_aiocb(rpcs, reqs[i].conn->iut_s, 
                 reqs[i].rd ? RPC_LIO_READ : RPC_LIO_WRITE,
                 &reqs[i].buf, DATA_BULK, reqs[i].len, 
                 reqs[i].sig_lio ? NULL : &reqs[i].ev, &reqs[i].cb);

    if (!reqs[i].rd)
    {
        rpc_set_buf_pattern(rpcs, TAPI_RPC_BUF_RAND, 
                            reqs[i].len, reqs[i].buf);
        reqs[i].conn->sent_from_iut += reqs[i].len;
    }

    if (reqs[i].lio)
        rpc_lio_listio(rpcs, RPC_LIO_NOWAIT, &reqs[i].cb, 1, 
                       reqs[i].sig_lio ? &reqs[i].ev : NULL);
    else if (reqs[i].rd)
        rpc_aio_read(rpcs, reqs[i].cb);
    else
        rpc_aio_write(rpcs, reqs[i].cb);
        
    RING("Post %s", req2str(reqs + i));        
}

int
main(int argc, char *argv[])
{   
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    tarpc_callback_item *list = NULL;
    
    uint32_t len, i;

    DEFINE_RPC_STRUCT_SIGACTION(oldsa1);
    DEFINE_RPC_STRUCT_SIGACTION(oldsa2);
    DEFINE_RPC_STRUCT_SIGACTION(sa1);
    DEFINE_RPC_STRUCT_SIGACTION(sa2);
    
    te_bool restore1 = FALSE, restore2 = FALSE;
    
    uint64_t sent;
    
    tarpc_timeval tv = { 0, 0 };
    
    posted_req *req;
    
    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(sock_num);
    TEST_GET_INT_PARAM(threads_num);
    TEST_GET_INT_PARAM(req_num);

    /* Allocate and initialize arrays */
    if ((conns = calloc(sock_num, sizeof(connection))) == NULL ||
        (threads = calloc(threads_num, sizeof(void *))) == NULL ||
        (reqs =  calloc(req_num, sizeof(posted_req))) == NULL ||
        (list = calloc(req_num * 2, sizeof(tarpc_callback_item))) == NULL)
    {
        TEST_FAIL("Out of memory");
    }
    
    for (i = 0; i < sock_num; i++)
        conns[i].tst_s = conns[i].iut_s = -1;
    
    /* Reset callback list on IUT */
    len = req_num * 2;
    rpc_get_callback_list(pco_iut, list, &len);
    
    /* Install signal handler */
    sa1.mm_mask = rpc_sigset_new(pco_iut);
    sa1.mm_flags = RPC_SA_SIGINFO;
    rpc_sigemptyset(pco_iut, sa1.mm_mask);
    rpc_sigaddset(pco_iut, sa1.mm_mask, RPC_SIGUSR1);
    rpc_sigaddset(pco_iut, sa1.mm_mask, RPC_SIGUSR2);
    sa2 = sa1;
    strcpy(sa1.mm_handler, AIO_SIGHANDLER_NAME "1");
    strcpy(sa2.mm_handler, AIO_SIGHANDLER_NAME "2");
    
    oldsa1.mm_mask = rpc_sigset_new(pco_iut);
    rpc_sigaction(pco_iut, RPC_SIGUSR1, &sa1, &oldsa1);
    restore1 = TRUE;

    oldsa2.mm_mask = rpc_sigset_new(pco_iut);
    rpc_sigaction(pco_iut, RPC_SIGUSR2, &sa2, &oldsa2);
    restore2 = TRUE;

    /* Create all connections and overfill buffers */
    for (i = 0; i < sock_num; i++)
    {
        char name[16];
        int  req_val = TRUE;

        TAPI_SET_NEW_PORT(pco_iut, iut_addr);
        TAPI_SET_NEW_PORT(pco_tst, tst_addr);
        
        conns[i].sock_type = rand_range(0, 1) == 0 ? RPC_SOCK_DGRAM 
                                                   : RPC_SOCK_STREAM;
    
        GEN_CONNECTION(pco_iut, pco_tst, 
                       conns[i].sock_type, RPC_PROTO_DEF, 
                       iut_addr, tst_addr, 
                       &conns[i].iut_s, &conns[i].tst_s);

        rpc_ioctl(pco_tst, conns[i].tst_s, RPC_FIONBIO, &req_val);

        TE_SPRINTF(name, "sender_%u", i + 1);
        CHECK_RC(rcf_rpc_server_thread_create(pco_tst, name, 
                                              &conns[i].sender));

        TE_SPRINTF(name, "receiver_%u", i + 1);
        CHECK_RC(rcf_rpc_server_thread_create(pco_tst, name, 
                                              &conns[i].receiver));

        if (conns[i].sock_type == RPC_SOCK_STREAM)
        {
            rpc_overfill_buffers(pco_iut, conns[i].iut_s, 
                                 &conns[i].sent_from_iut);
        }
    }
    
    /* Create IUT threads */
    for (i = 0; i < threads_num; i++)
    {
        char name[16];
        
        TE_SPRINTF(name, "thr_%u", i + 1);
        
        CHECK_RC(rcf_rpc_server_thread_create(pco_iut, name, 
                                              threads + i));
    }
    
    /* Post all requests */
    for (i = 0; i < req_num; i++)
        post_request(i);
    
    /* Start Tester threads to satisfy requests */
    rpc_gettimeofday(pco_tst, &tv, NULL);
    for (i = 0; i < sock_num; i++)
    {
        conns[i].sender->start = conns[i].receiver->start =
            (tv.tv_sec + 2) * 1000 + tv.tv_usec / 1000;
        
        conns[i].sender->op = conns[i].receiver->op = RCF_RPC_CALL;
        
        rpc_simple_receiver(conns[i].receiver, conns[i].tst_s, 3, 
                            &conns[i].rcvd_from_iut);
                            
        rpc_simple_sender(conns[i].sender, conns[i].tst_s, 
                          DATA_BULK, DATA_BULK, TRUE,
                          1000, 1000, TRUE, 2, &sent, TRUE);
    }
    
    /* Wait for Tester sender and receiver completion */
    for (i = 0; i < sock_num; i++)
    {
        rpc_simple_receiver(conns[i].receiver, conns[i].tst_s, 3, 
                            &conns[i].rcvd_from_iut);
                            
        rpc_simple_sender(conns[i].sender, conns[i].tst_s, 
                          DATA_BULK, DATA_BULK, TRUE,
                          1000, 1000, TRUE, 2, &sent, TRUE);
    }
    
    /* Verify amount of data received from IUT */
    for (i = 0; i < sock_num; i++)
    {
        if (conns[i].sent_from_iut != conns[i].rcvd_from_iut)
        {
            if (conns[i].sock_type == RPC_SOCK_STREAM)
            {
                TEST_FAIL("Some data sent from IUT are lost: %llu bytes "
                          "instead %llu bytes are received via tester "
                          "TCP socket %d",
                          conns[i].rcvd_from_iut, conns[i].sent_from_iut,
                          conns[i].tst_s);
            }
            else
            {
                WARN("Some data sent from IUT are lost: %llu bytes instead"
                     " %llu bytes are received via tester UDP socket %d",
                     conns[i].rcvd_from_iut, conns[i].sent_from_iut,
                     conns[i].tst_s);
            }
        }
    }
    
    /* Verify notification */
    len = req_num * 2;
    rpc_get_callback_list(pco_iut, list, &len);
    for (i = 0; i < len; i++)
    {
        if (list[i].val >= (int)req_num)
            TEST_FAIL("Unexpected notification is received: "
                      "callback %d signo %d value %d", 
                      list[i].callback_num, list[i].signo, list[i].val);
                           
        
        req = reqs + list[i].val;
        
        if (req->notify)
            TEST_FAIL("Completion notification is received twice (%s)", 
                      req2str(req));
             
        switch (req->ev.notify)
        {
            case RPC_SIGEV_NONE:         
                TEST_FAIL("Unexpected completion notification (%s)", 
                          req2str(req));
                break;
                
            case RPC_SIGEV_THREAD:
                if (list[i].signo != 0)
                    TEST_FAIL("Completion is notified using signal "
                              "instead callback (%s)", req2str(req));
                          
                if (list[i].callback_num != atoi(req->ev.function +
                                                 strlen(AIO_CALLBACK_NAME)))
                {
                    TEST_FAIL("Incorrect callback function " 
                              AIO_CALLBACK_NAME "%d is called (%s)", 
                              list[i].callback_num, req2str(req));
                }
                break;
                
            case RPC_SIGEV_SIGNAL:
                if (list[i].signo == 0)
                {
                    TEST_FAIL("Completion is notified using callback "
                              "instead signal (%s)", req2str(req));
                }
                              
                if (list[i].signo != req->ev.signo)
                {
                    TEST_FAIL("Unexpected signal is received: %s "
                              "instead %s (%s)", 
                              signum_rpc2str(list[i].signo),
                              signum_rpc2str(req->ev.signo), req2str(req));
                }
                break;
        }
        
        req->notify = TRUE;
    }
    
    /* Check status of all requests */
    for (i = 0, req = reqs; i < req_num; i++, req++)
    {
        if ((rc = rpc_aio_error(pco_iut, req->cb)) != 0)
            TEST_FAIL("aio_error() returned %r instead 0 (%s)", 
                      rc, req2str(req));
    
        if ((rc = rpc_aio_return(pco_iut, req->cb)) <= 0 ||
            ((!req->rd || req->conn->sock_type != RPC_SOCK_STREAM) && 
             rc != req->len))
        {
            TEST_FAIL("aio_return() returned %d instead %d (%s)", 
                      rc, req->len, req2str(req));
        }
        
        if (req->ev.notify == RPC_SIGEV_THREAD && !req->notify)
            TEST_FAIL("No completion notification is received (%s)",
                       req2str(req));
                       
        /* 
         * Signal notifications may be lost if two signals are arrived
         * too fast (signal merging).
         */
    }
    
    TEST_SUCCESS;

cleanup:
    /* Close all tester sockets */
    if (conns != NULL)
        for (i = 0; i < sock_num && conns[i].sock_type != 0; i++)
            CLEANUP_RPC_CLOSE(pco_tst, conns[i].tst_s);
    
    /* Cancel all requests */
    if (reqs != NULL)
        for (i = 0; i < req_num; i++)
        {
            CLEANUP_AIO_CANCEL(pco_iut, reqs[i].conn->iut_s, reqs[i].cb);
            CLEANUP_RPC_DELETE_AIOCB(pco_iut, reqs[i].cb);
            CLEANUP_RPC_FREE(pco_iut, reqs[i].buf);
            free(reqs[i].ev.function);
        }
    
    /* Close all IUT sockets */
    if (conns != NULL)
        for (i = 0; i < sock_num && conns[i].sock_type != 0; i++)
            CLEANUP_RPC_CLOSE(pco_iut, conns[i].iut_s);

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
    
    free(conns);
    free(threads);
    free(reqs);
    free(list);
    
    /* Let's allow configurator remove excessive RPC servers */

    TEST_END;
}

#endif /* !DOXYGEN_TEST_SPEC */
