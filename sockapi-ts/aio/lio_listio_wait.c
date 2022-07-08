/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-lio_listio_wait  Call lio_listio(LIO_WAIT) for successful requests
 *
 * @objective Check that several requests may be posted using @b lio_listio()
 *            in blocking mode.
 *
 * @param pco_iut     PCO with IUT
 * @param iut_s1      Socket on @p pco_iut
 * @param iut_s2      Socket on @p pco_iut
 * @param pco_tst     Tester PCO
 * @param tst_s1      Socket on @p pco_tst
 * @param tst_s2      Socket on @p pco_tst
 *
 * @pre Sockets @p iut_s1 and @p tst_s1 are connected.
 * @pre Sockets @p iut_s2 and @p tst_s2 are connected.
 *
 * @par Scenario
 * -# Create 2 read and 2 write AIO control blocks for socket @p iut_s1.
 * -# Create 2 read and 2 write AIO control blocks for socket @p iut_s2.
 * -# Post all requests using @b lio_listio(@c LIO_WAIT) with @a sig parameter
 *    with callback notification.
 * -# Satisfy all requests sending/receiving data via @p tst_s1 and @p tst_s2.
 * -# Check that @b lio_listio() unblocked only after satisfaction
 *    of all requests and returned 0.
 * -# Check that completion callback specified in sig parameter of
 *    @b lio_listio() is not called.
 * -# Check that @b aio_return() for each control block returns correct length.
 * -# Check that transferred data are not corrupted.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "aio/lio_listio_wait"
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
    tarpc_sigevent          ev;
    
    TEST_START;
    
#define WRITE_REQ(i)    (i & 1)
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut1_addr);
    TEST_GET_ADDR(pco_tst, tst1_addr);    
    TEST_GET_ADDR(pco_iut, iut2_addr);
    TEST_GET_ADDR(pco_tst, tst2_addr);
    TEST_GET_SOCK_TYPE(sock_type);

    rpc_get_callback_list(pco_iut, NULL, NULL);
    
    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut1_addr, tst1_addr, &iut_s1, &tst_s1);

    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut2_addr, tst2_addr, &iut_s2, &tst_s2);

    for (i = 0; i < LIST_LEN; i++)
    {
        create_aiocb(pco_iut, i < LIST_LEN / 2 ? iut_s1 : iut_s2, 
                     WRITE_REQ(i) ? RPC_LIO_WRITE : RPC_LIO_READ,
                     buf + i, DATA_BULK, DATA_BULK, 
                     NULL, lio_cb + i);
        
        te_fill_buf(tx_buf[i], DATA_BULK);
        memset(rx_buf[i], 0, DATA_BULK);
        if (WRITE_REQ(i))
            rpc_set_buf(pco_iut, tx_buf[i], DATA_BULK, buf[i]);
    }
    
    INIT_EV(&ev);
    ev.notify = RPC_SIGEV_THREAD;
    ev.value.tarpc_sigval_u.sival_int = 1;
    ev.function = AIO_CALLBACK_NAME "1";
    
    pco_iut->op = RCF_RPC_CALL;
    rpc_lio_listio(pco_iut, RPC_LIO_WAIT, lio_cb, LIST_LEN, &ev);
    
    for (i = 0; i < LIST_LEN; i++)
    {
        if (WRITE_REQ(i))
        {
            rpc_read(pco_tst, i < LIST_LEN / 2 ? tst_s1 : tst_s2, 
                     rx_buf[i], DATA_BULK);
        }
        else
        {
            rpc_write(pco_tst, i < LIST_LEN / 2 ? tst_s1 : tst_s2, 
                      tx_buf[i], DATA_BULK);
        }
    }

    rpc_lio_listio(pco_iut, RPC_LIO_WAIT, lio_cb, LIST_LEN, &ev);

    rpc_get_callback_list(pco_iut, list, &len);
    if (len > 0)
        TEST_FAIL("lio_listio(LIO_WAIT) does not ignore sig parameter");
    
    for (i = 0; i < LIST_LEN; i++)       
    {
        if ((rc = rpc_aio_error(pco_iut, lio_cb[i])) != 0)
            TEST_FAIL("aio_error() returned %r instead 0", rc);
            
        if ((rc = rpc_aio_return(pco_iut, lio_cb[i])) != DATA_BULK)
            TEST_FAIL("aio_return() returned %d instead %d", rc, DATA_BULK);
    }
    
    for (i = 0; i < LIST_LEN; i++)
    {
        if (!WRITE_REQ(i))
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
    
    TEST_END;
}
