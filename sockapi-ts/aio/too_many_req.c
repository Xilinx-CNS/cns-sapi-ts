/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-too_many_req  Post too many AIO requests
 *
 * @objective Check that posting of lot of requests does not lead
 *            to application/system crash.
 *
 * @param pco_iut   PCO with IUT
 * @param iut_s     Socket on @p pco_iut
 * @param pco_tst   Tester PCO
 * @param tst_s     Socket on @p pco_tst
 * @param mode      Read, write or read/write
 * @param num       Maximum number of requests to be posted
 *
 * @pre Sockets @p iut_s and @p tst_s are connected.
 *
 * @par Scenario
 * -# Overfill transmit buffers of @p iut_s socket (for stream sockets only).
 * -# While @p func does not return @c EAGAIN or until @p num requests
 *    are posted, post AIO requests for socket @p iut_s. 
 *    Choose function randomly:  @b aio_read(), @b aio_write(), 
 *    @b lio_listio(@c LIO_READ) or @b lio_listio(LIO_WRITE).
 *    If @p mode is "read", post only read requests. 
 *    If @p mode is "write", post only write requests. 
 * -# Satisfy all requests sending/receiving data via @p tst_s.
 * -# Check that all requests are completed using @b aio_error() and 
 *    @b aio_return().
 * -# Post AIO read request on socket @p iut_s using @b aio_read().
 * -# Post AIO write request on socket @p iut_s using @b aio_write().
 * -# Post AIO read request on socket @p iut_s using @b lio_listio(@c LIO_NOWAIT).
 * -# Post AIO write request on socket @p iut_s using @b lio_listio(@c LIO_NOWAIT).
 * -# Satisfy all requests sending/receiving data via @p tst_s.
 * -# Check that all requests are completed using @b aio_error() and 
 *    @b aio_return().
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#ifndef DOXYGEN_TEST_SPEC

#define TE_TEST_NAME  "aio/too_many_req"

#include "sockapi-test.h"
#include "aio_internal.h"

#define DATA_BULK       1024  /**< Size of data to be sent */

static const char     *mode;
static rpc_socket_type sock_type;

static rcf_rpc_server *pco_iut = NULL;
static int iut_s = -1;            

static uint8_t tx_buf[DATA_BULK]; /**< Auxiliary buffer */


/** Type of the request to be posted */
typedef enum {
    REQ_AIO_READ,       /**< aio_read() */
    REQ_LIO_READ,       /**< lio_istio() with LIO_READ */
    REQ_AIO_WRITE,      /**< aio_write() */
    REQ_LIO_WRITE,      /**< lio_listio() with LIO_WRITE */
} req_type;

/** AIO request posted on pco_iut */
typedef struct posted_req {
    struct posted_req *next;    /**< Next element in the list */
    
    rpc_aiocb_p  cb;            /**< AIO control block handle */
    rpc_ptr      buf;           /**< TX/RX buffer */
    int          len;           /**< Length of data to be transferred */
    te_bool      rd;            /**< TRUE for read requests */
} posted_req;    

/** List of all posted requests */
static posted_req *head;
static posted_req *tail;

static uint64_t sent;           /**< Amount of data sent from IUT */
static uint64_t received;       /**< Amount of data received on the tester */

static int posted_num[4];


/**
 * Create and post AIO request of specified type.
 *
 * @param type  type of the request (see req_type)
 *
 * @return TRUE is the request is posted of FALSE if too many requests are
 *         already posted
 */
static te_bool
post_request(req_type type)
{
    posted_req *tmp = (posted_req *)calloc(sizeof(posted_req), 1);
    
    tarpc_sigevent ev;
    
    int rc;
    
    posted_num[type]++;                  
    
    if (tmp == NULL)
        TEST_FAIL("Out of memory");
        
    INIT_EV(&ev);
    
    if (head == NULL)
    {
        head = tail = tmp;
    }
    else    
    {
        tail->next = tmp;
        tail = tmp;
    }
    tmp->rd = (type == REQ_AIO_READ || type == REQ_LIO_READ);

    tmp->len = rand_range(1, DATA_BULK);

    create_aiocb(pco_iut, iut_s, tmp->rd ? RPC_LIO_READ : RPC_LIO_WRITE,
                 &tmp->buf, DATA_BULK, tmp->len, &ev, &tmp->cb);

    if (!tmp->rd)
    {
        rpc_set_buf_pattern(pco_iut, TAPI_RPC_BUF_RAND, DATA_BULK, 
                            tmp->buf);
        sent += tmp->len;
    }

    RPC_AWAIT_IUT_ERROR(pco_iut);
    switch (type)
    {
        case REQ_AIO_READ:
            rc = rpc_aio_read(pco_iut, tmp->cb);
            break;

        case REQ_AIO_WRITE:
            rc = rpc_aio_write(pco_iut, tmp->cb);
            break;
            
        default:
            rc = rpc_lio_listio(pco_iut, RPC_LIO_NOWAIT, 
                                &tmp->cb, 1, &ev);
            break;
    }
    
    if (rc == -1 && RPC_ERRNO(pco_iut) != RPC_EAGAIN)
        TEST_FAIL("Posting of the request failed with errno %r "
                  "instead EAGAIN", rc);
                  
    return rc == 0;
}

/** Check request completion in the head of the list */
static void
check_request()
{
    int rc;
    
    posted_req *tmp = head;
    
    if ((rc = rpc_aio_error(pco_iut, head->cb)) != 0)
        TEST_FAIL("aio_error() returned %r instead 0", rc);
    
    if ((rc = rpc_aio_return(pco_iut, head->cb)) <= 0 ||
        ((!head->rd || sock_type != RPC_SOCK_STREAM) && rc != head->len))
    {
        TEST_FAIL("aio_return() returned %d instead %d", rc, head->len);
    }
        
    head = head->next;
        
    rpc_delete_aiocb(pco_iut, tmp->cb);
    rpc_free(pco_iut, tmp->buf);
    free(tmp);
}

static req_type
choose_type(void)
{
    return (strcmp(mode, "rd") == 0) ? 
               rand_range(REQ_AIO_READ, REQ_LIO_READ) :
           (strcmp(mode, "wr") == 0) ?
               rand_range(REQ_AIO_WRITE, REQ_LIO_WRITE):
               rand_range(REQ_AIO_READ, REQ_LIO_WRITE);
}

int
main(int argc, char *argv[])
{
    /* Environment variables */
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;
    
    int num;
    
    /* Auxiliary variables */
    posted_req *tmp;
    
    int tst_s = -1;
    int n;
    
    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_STRING_PARAM(mode);
    TEST_GET_INT_PARAM(num);

    te_fill_buf(tx_buf, DATA_BULK);
    
    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);
    
    if (sock_type != RPC_SOCK_DGRAM)
        rpc_overfill_buffers(pco_iut, iut_s, &sent);
    else
    {
        pco_tst->op = RCF_RPC_CALL;
        rpc_simple_receiver(pco_tst, tst_s, 20, &received);
    }

    /* Post all requests */
    for (n = 0; n < num && post_request(choose_type()); n++);
         
    RING("Posted:\n\tAIO_READ: %d\n\tLIO_READ: %d\n\tAIO_WRITE: %d\n\t"
         "LIO_WRITE: %d", posted_num[0], posted_num[1], posted_num[2],
         posted_num[3]);
    
    /* Satisfy write requests */
    rpc_simple_receiver(pco_tst, tst_s, 20, &received);

    if (sent != received)
        TEST_FAIL("%llu bytes are received on the tester instead %llu",
                  received, sent);

    /* Satisfy read requests */
    for (tmp = head; tmp != NULL; tmp = tmp->next)
    {
        if (tmp->rd)
        {
            RPC_AWAIT_IUT_ERROR(pco_tst);
            rc = rpc_send(pco_tst, tst_s, tx_buf, tmp->len, 
                          RPC_MSG_DONTWAIT);
            if (rc < 0)
                TEST_FAIL("Failed to satisfy read requests - "
                          "send operation blocks on Tester");
        }
    }
    MSLEEP(10);
        
    /* Check that all requests are completed */
    while (head != NULL)
        check_request();
    
    /* Check AIO usability */
    post_request(REQ_AIO_READ);
    post_request(REQ_AIO_WRITE);
    post_request(REQ_LIO_READ);
    post_request(REQ_LIO_WRITE);
    
    /* Satisfy read requests */
    for (tmp = head; tmp != NULL; tmp = tmp->next)
        if (tmp->rd)
            rpc_write(pco_tst, tst_s, tx_buf, tmp->len);

    MSLEEP(10);

    /* Check that all requests are completed */
    while (head != NULL)
        check_request();

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    
    while (head != NULL)
    {
        posted_req *tmp = head;
        
        head = head->next;

        CLEANUP_AIO_CANCEL(pco_iut, iut_s, tmp->cb);
        CLEANUP_RPC_DELETE_AIOCB(pco_iut, tmp->cb);
        CLEANUP_RPC_FREE(pco_iut, tmp->buf);
        free(tmp);
    }
    
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
                       
    TEST_END;
}

#endif /* !DOXYGEN_TEST_SPEC */
