/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-aio_read_many_socks  Many AIO read requests on different sockets
 *
 * @objective Check that several AIO read requests may be posted on
 *            several sockets simultaneously.
 *
 * @param pco_iut   PCO with IUT
 * @param pco_tst   Tester PCO
 *
 * @par Scenario
 * -# Create @p N pairs of connected sockets (@p iut_s1, @p tst_s1), ...
 *    (@p iut_sN, tst_sN) on @p pco_iut and @p pco_tst.
 * -# Post AIO read request for sockets @p iut_s1, ... @p iut_sN
 *    with different notification types (callbacks, signals, none).
 * -# Send data via sockets @p tst_s1, ... @p tst_sN.
 * -# Call functions aio_error() and aio_return() for sockets
 *    @p iut_s1, ... @p iut_sN to verify that all requests are completed
 *    syccessfully.
 * -# Verify that all completion notifications are delivered.
 * -# Verify that all received data are correct.
 * -# Close all sockets created during the test.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "aio/aio_read_many_socks"


#include "sockapi-test.h"
#include "aio_internal.h"

#define DATA_BULK       1024  /**< Maximum size of data to be sent */
#define MAX_REQ         100   /**< Max number of requests */

static uint8_t tx_buf[MAX_REQ][DATA_BULK];
static uint8_t rx_buf[DATA_BULK];

int
main(int argc, char *argv[])
{   
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst = NULL;
    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;
    uint32_t               sock_num = 0;
    
    /** A connection between PCO IUT and PCO TST */
    struct connection {
        rpc_socket_type sock_type;      /**< Stream or datagram */
        int             iut_s;          /**< Socket of the PCO IUT */
        int             tst_s;          /**< Socket on PCO Tester */
    } *conns = NULL;

    struct posted_req {
        rpc_aiocb_p     cb;     /**< AIO control block */
        tarpc_sigevent  ev;     /**< Completion notification mode */
        rpc_ptr         buf;    /**< Remote buffer */
        int             sent;   /**< bytes sent for this request */
        te_bool         notify; /**< Completion notification is received */
    } *reqs = NULL, *req = NULL;
    
    DEFINE_RPC_STRUCT_SIGACTION(oldsa1);
    DEFINE_RPC_STRUCT_SIGACTION(oldsa2);
    DEFINE_RPC_STRUCT_SIGACTION(sa1);
    DEFINE_RPC_STRUCT_SIGACTION(sa2);
    
    te_bool restore1 = FALSE, restore2 = FALSE;
    
    tarpc_callback_item *list = NULL;
    
    uint32_t             i;
    uint32_t             len;
    
    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(sock_num);

    /* Allocate and initialize arrays */
    if ((conns = calloc(sock_num, sizeof(struct connection))) == NULL ||
        (reqs =  calloc(sock_num, sizeof(struct posted_req))) == NULL ||
        (list = calloc(sock_num * 2, sizeof(tarpc_callback_item))) == NULL)
    {
        TEST_FAIL("Out of memory");
    }

    for (i = 0; i < sock_num; i++)
        conns[i].tst_s = conns[i].iut_s = -1;

    /* Create all connections */
    for (i = 0; i < sock_num; i++)
    {
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
    }

    /* Reset callback list on IUT */
    len = sock_num * 2;
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
   
    /* Post all requests */
    for (i = 0; i < sock_num; i++)
    {
    
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
        
        /* Allocate buffer on the pco_iut */
        reqs[i].buf = rpc_malloc(pco_iut, DATA_BULK + 1);

        /* Create and fill aiocb */
        reqs[i].cb = rpc_create_aiocb(pco_iut);
        rpc_fill_aiocb(pco_iut, reqs[i].cb, conns[i].iut_s, 0, 0,
                       reqs[i].buf, DATA_BULK + 1, &reqs[i].ev);
        rpc_aio_read(pco_iut, reqs[i].cb);
    }

    /* Start sending data from Tester */
    for (i = 0; i < sock_num; i++)
    {
        te_fill_buf(tx_buf[i], DATA_BULK);
        reqs[i].sent = rand_range(1, DATA_BULK);
        RPC_SEND(len, pco_tst, conns[i].tst_s, tx_buf[i], reqs[i].sent, 0);
    }
    SLEEP(1);

    /* Verify notification */
    len = sock_num * 2;
    rpc_get_callback_list(pco_iut, list, &len);
    for (i = 0; i < len; i++)
    {
        if (list[i].val >= (int)sock_num)
            TEST_FAIL("Unexpected notification is received: "
                      "callback %d signo %d value %d", 
                      list[i].callback_num, list[i].signo, list[i].val);
        
        req = reqs + list[i].val;
        
        if (req->notify)
            TEST_FAIL("Completion notification is received twice (request"
                      "%d on socket %d, callback parameter: %d, "
                      "notification %s)", i, conns[(list[i].val)].iut_s,
                      list[i].val, sigev_notify_rpc2str(req->ev.notify));

        switch (req->ev.notify)
        {
            case RPC_SIGEV_NONE:         
                TEST_FAIL("Unexpected completion notification (request"
                          " %d on socket %d, callback parameter %d, "
                          "notification %s)", i, conns[(list[i].val)].iut_s, 
                          list[i].val, sigev_notify_rpc2str(req->ev.notify));
                break;
                
            case RPC_SIGEV_THREAD:
                if (list[i].signo != 0)
                    TEST_FAIL("Completion is notified using signal "
                              "instead callback (request %d on socket %d)", 
                               i, conns[(list[i].val)].iut_s);
                          
                if (list[i].callback_num != atoi(req->ev.function +
                                                 strlen(AIO_CALLBACK_NAME)))
                {
                    TEST_FAIL("Incorrect callback function " 
                              AIO_CALLBACK_NAME "%d is called (request"
                               " %d on socket %d)",
                              list[i].callback_num,
                              i, conns[(list[i].val)].iut_s);
                }
                break;
                
            case RPC_SIGEV_SIGNAL:
                if (list[i].signo == 0)
                {
                    TEST_FAIL("Completion is notified using callback "
                              "instead signal (request %d on socket %d)",
                               i, conns[(list[i].val)].iut_s);
                }
                              
                if (list[i].signo != req->ev.signo)
                {
                    TEST_FAIL("Unexpected signal is received: %s "
                              "instead %s (request %d on socket %d)",
                               signum_rpc2str(list[i].signo),
                               signum_rpc2str(req->ev.signo), 
                               i, conns[(list[i].val)].iut_s);
                }
                break;
        }
        
        req->notify = TRUE;
    }

    /* Check status of all requests */
    for (i = 0, req = reqs; i < sock_num; i++, req++)
    {
        if ((rc = rpc_aio_error(pco_iut, req->cb)) != 0)
            TEST_FAIL("aio_error() returned %r instead 0 (request %d on"
                      "socket %d)", 
                      rc, i, conns[(list[i].val)].iut_s);
    
        if ((rc = rpc_aio_return(pco_iut, req->cb)) <= 0 ||
             rc != req->sent)
        {
            TEST_FAIL("aio_return() returned %d instead %d (request %d on"
                      "socket %d)", rc, req->sent, i,
                      conns[(list[i].val)].iut_s);
        }
        
        rpc_get_buf(pco_iut, req->buf, DATA_BULK, rx_buf);
        if (memcmp(tx_buf[i], rx_buf, req->sent) != 0)
        TEST_FAIL("Data sent from the TST do not match data received "
                  "on the IUT in %d connection", i);
        
        if (req->ev.notify == RPC_SIGEV_THREAD && !req->notify)
            TEST_FAIL("No completion notification is received (request %d on"
                      "socket %d notification %s)", i, 
                      conns[(list[i].val)].iut_s,
                      sigev_notify_rpc2str(req->ev.notify));
                       
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
        for (i = 0; i < sock_num; i++)
        {
            CLEANUP_AIO_CANCEL(pco_iut, conns[i].iut_s, reqs[i].cb);
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
    free(reqs);
    free(list);
    
    TEST_END;
}
