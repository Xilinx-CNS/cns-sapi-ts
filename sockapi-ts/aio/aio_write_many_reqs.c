/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-aio_write_many_reqs  Many AIO write requests on one socket
 *
 * @objective Check that several AIO write requests may be posted 
 *            simultaneously on the one socket.
 *
 * @param pco_iut   PCO with IUT
 * @param iut_s     Socket on @p pco_iut
 * @param pco_tst   Tester PCO
 * @param tst_s     Socket on @p pco_tst
 *
 * @pre Sockets @p iut_s and @p tst_s are connected.
 *
 * @par Scenario
 * -# Post @p N AIO write request on socket @p iut_s using @b aio_write() function.
 * -# Receive @p N bulks of data via @p tst_s.
 * -# Call functions @b aio_error() and @b aio_return() for each requests
 *    to verify that all requests are successfully completed.
 * -# Check that data are received in correct sequence: first sent bulk
 *    is placed to buffer corresponding to the first posted request and so on.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "aio/aio_write_many_reqs"

#include "sockapi-test.h"

#define DATA_BULK       1024  /**< Size of data to be sent */

static uint8_t rx_buf[DATA_BULK];
static uint8_t tx_buf[DATA_BULK];

int
main(int argc, char *argv[])
{
    /* Environment variables */
    rpc_socket_type     sock_type;
    int                 req_num;
    
    struct posted_req {
        rpc_aiocb_p     cb;  /**< AIO control block */
        rpc_ptr         buf; /**< Remote buffer */
        int             len; /**< Buffers lenght */
    } *reqs = NULL;

    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    /* Auxiliary variables */
    int iut_s = -1;
    int tst_s = -1;
    int len;
    int index = 0;
    
    tarpc_sigevent ev;
    
    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_INT_PARAM(req_num);
   
    memset(&ev, 0, sizeof(ev));
    ev.notify = RPC_SIGEV_NONE;
    
    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);
    
    /* Create N AIO request. */
    reqs =  calloc(req_num, sizeof(struct posted_req));
    for (index = 0; index < req_num; index++)
    {
        reqs[index].len = rand_range(1, DATA_BULK);
        te_fill_buf(rx_buf, DATA_BULK);
        
        reqs[index].buf = rpc_malloc(pco_iut, reqs[index].len);
        rpc_set_buf(pco_iut, rx_buf, reqs[index].len, reqs[index].buf);

        reqs[index].cb = rpc_create_aiocb(pco_iut);
        rpc_fill_aiocb(pco_iut, reqs[index].cb , iut_s, 0, 0,
                       reqs[index].buf , reqs[index].len, &ev);

        /* Post AIO read request. */
        rpc_aio_write(pco_iut, reqs[index].cb);
    }
    
    /* Receive and check data */
    for (index = 0; index < req_num; index++)
    {
        len = rpc_recv(pco_tst, tst_s, tx_buf, reqs[index].len, 0);
        if (len != reqs[index].len)
            TEST_FAIL("%d recv() returned %d instead %d", len, reqs[index].len);
        
        rpc_get_buf(pco_iut, reqs[index].buf, reqs[index].len, rx_buf);
        if (memcmp(tx_buf, rx_buf, reqs[index].len) != 0)
        TEST_FAIL("Data sent from the TST do not match data received "
                  "on the IUT on %d request", index);
    }
    
    /* Check errors. */
    for (index = 0; index < req_num; index++)
    {
        if ((rc = rpc_aio_error(pco_iut, reqs[index].cb)) != 0)
            TEST_FAIL("aio_error() for %d request returned %r after request"
                      "finishing", index, rc);
        
        if ((len = rpc_aio_return(pco_iut, reqs[index].cb)) != reqs[index].len)
            TEST_FAIL("aio_return() for %d request returned %u instead %u",
                      index, len, reqs[index].len);
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    if (reqs != NULL)
        for (index = 0; index < req_num; index++)
        {
            CLEANUP_RPC_DELETE_AIOCB(pco_iut, reqs[index].cb);
            CLEANUP_RPC_FREE(pco_iut, reqs[index].buf);
        }
    
    free(reqs);

    TEST_END;
}
