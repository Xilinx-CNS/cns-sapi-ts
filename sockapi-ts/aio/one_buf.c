/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-one_buf  Using one buffer for several AIO requests
 *
 * @objective Check that IUT does not crash if one buffer is used for
 *            AIO requests.
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
 * -# Post several write and several read AIO requests using one buffer.
 * -# Start two threads on @p pco_tst: one for data sending via @p tst_s
 *    and another for data receiving via @p tst_s.
 * -# When requests are satisfied, check their completion statuses
 *    calling @b aio_error() and @b aio_return() for their control blocks.
 * -# Post read AIO request on @p iut_s. 
 * -# Send data via @p tst_s to satisfy the request.
 * -# Check that transferred data are not corrupted.
 * -# Post write AIO request on @p iut_s.
 * -# Read data via @p tst_s and check that they are not corrupted.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#ifndef DOXYGEN_TEST_SPEC

#define TE_TEST_NAME  "aio/one_buf"

#include "sockapi-test.h"
#include "aio_internal.h"

#define DATA_BULK       1024  /**< Size of data to be sent */

static uint8_t tx_buf[DATA_BULK]; /**< Auxiliary buffer */
static uint8_t rx_buf[DATA_BULK]; /**< Auxiliary buffer */

static rcf_rpc_server *pco_iut = NULL;
static rpc_ptr         rbuf = RPC_NULL;
static int             iut_s = -1; 
static rpc_socket_type sock_type;

/** AIO request posted on pco_iut */
typedef struct posted_req {
    struct posted_req *next;    /**< Next element in the list */
    
    rpc_aiocb_p  cb;            /**< AIO control block handle */
    te_bool      rd;            /**< TRUE for read requests */
} posted_req;    

/** List of all posted requests */
static posted_req *head;
static posted_req *tail;

/**
 * Create and post AIO request of specified type.
 *
 * @param rd  if TRUE, post read request
 */
static void
post_request(te_bool rd)
{
    posted_req *tmp = (posted_req *)calloc(sizeof(posted_req), 1);
    
    tarpc_sigevent ev;
    
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
    tmp->rd = rd;

    tmp->cb = rpc_create_aiocb(pco_iut);
    rpc_fill_aiocb(pco_iut, tmp->cb, iut_s, 0, 
                   tmp->rd ? RPC_LIO_READ : RPC_LIO_WRITE, 
                   rbuf, DATA_BULK, &ev);

    if (rd)
        rpc_aio_read(pco_iut, tmp->cb);
    else
        rpc_aio_write(pco_iut, tmp->cb);
}

/** Check request completion in the head of the list */
static int
check_request()
{
    int rc;
    
    posted_req *tmp = head;
    
    if ((rc = rpc_aio_error(pco_iut, head->cb)) != 0)
        TEST_FAIL("aio_error() returned %r instead 0", rc);
    
    if ((rc = rpc_aio_return(pco_iut, head->cb)) <= 0 ||
        ((!head->rd || sock_type != RPC_SOCK_STREAM) && rc != DATA_BULK))
    {
        TEST_FAIL("aio_return() on %s request returned %d instead %d", 
                  head->rd ? "read" : "write", rc, DATA_BULK);
    }
        
    head = head->next;
        
    rpc_delete_aiocb(pco_iut, tmp->cb);
    free(tmp);
    
    return rc;
}

int
main(int argc, char *argv[])
{
    /* Environment variables */

    rcf_rpc_server *pco_tst = NULL;
    rcf_rpc_server *pco_tst2 = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;
    
    int tst_s = -1;
    int req_val = TRUE;
    
    uint64_t sent, received;
    
    tarpc_timeval tv = { 0, 0 };
    
    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);

    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    rpc_ioctl(pco_tst, tst_s, RPC_FIONBIO, &req_val);
    
    rbuf = rpc_malloc(pco_iut, DATA_BULK);
    rpc_set_buf_pattern(pco_iut, TAPI_RPC_BUF_RAND, DATA_BULK, rbuf);

    CHECK_RC(rcf_rpc_server_fork(pco_tst, "Child", &pco_tst2));
    
    if (sock_type != RPC_SOCK_DGRAM)
        rpc_overfill_buffers(pco_iut, iut_s, &sent);

    /* Post all requests */
    post_request(TRUE);
    post_request(FALSE);
    post_request(TRUE);
    post_request(FALSE);
    post_request(TRUE);
    post_request(FALSE);
    post_request(TRUE);
    post_request(FALSE);

    /* Satisfy all requests */
    rpc_gettimeofday(pco_tst, &tv, NULL);
    pco_tst->start = pco_tst2->start = 
        (tv.tv_sec + 1) * 1000 + tv.tv_usec / 1000;
        
    pco_tst->op = RCF_RPC_CALL;
    rpc_simple_receiver(pco_tst, tst_s, 2, &received);

    rpc_simple_sender(pco_tst2, tst_s, DATA_BULK, DATA_BULK, TRUE,
                      1000, 1000, TRUE, 1, &sent, TRUE);

    rpc_simple_receiver(pco_tst, tst_s, 1, &received);

    /* Check that all requests are completed */
    while (head != NULL)
        check_request();

    /* Receive all data sent by the sender */
    rpc_simple_receiver(pco_iut, iut_s, 0, &received);
    
    /* Check AIO usability */
    
    /* Tester -> IUT */
    rpc_set_buf_pattern(pco_iut, 0, DATA_BULK, rbuf);
    post_request(TRUE);
    te_fill_buf(tx_buf, DATA_BULK);
    rpc_write(pco_tst, tst_s, tx_buf, DATA_BULK);
    MSLEEP(10);
    rc = check_request();
    rpc_get_buf(pco_iut, rbuf, DATA_BULK, rx_buf);
    if (memcmp(rx_buf, tx_buf, rc) != 0)
        TEST_FAIL("Data are corrupted during sending from Tester to IUT");
    
    /* IUT -> Tester */
    rpc_set_buf(pco_iut, tx_buf, DATA_BULK, rbuf);
    post_request(FALSE);
    MSLEEP(10);
    memset(rx_buf, 0, DATA_BULK);
    rc = rpc_read(pco_tst, tst_s, rx_buf, DATA_BULK);
    if (rc <= 0)
        TEST_FAIL("Failed to receive data from IUT");
    check_request();
    if (memcmp(rx_buf, tx_buf, rc) != 0)
        TEST_FAIL("Data are corrupted during sending from IUT to Tester");
    
    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    
    while (head != NULL)
    {
        posted_req *tmp = head;
        
        head = head->next;

        CLEANUP_AIO_CANCEL(pco_iut, iut_s, tmp->cb);
        CLEANUP_RPC_DELETE_AIOCB(pco_iut, tmp->cb);
        
        free(tmp);
    }
    
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    CLEANUP_RPC_FREE(pco_iut, rbuf);
                       
    TEST_END;
}

#endif /* !DOXYGEN_TEST_SPEC */
