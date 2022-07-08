/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-aio_read_many_reqs  Many AIO read requests on one socket
 *
 * @objective Check that several AIO read requests may be posted 
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
 * -# Post @p N AIO read request on socket @p iut_s using @b aio_read() function.
 * -# Send @p N bulks of data via @p tst_s to satisfy all requests.
 * -# Call functions @b aio_error() and @b aio_return() for each requests
 *    to verify that all requests are successfully completed.
 * -# Check that data are received in correct sequence: first sent bulk
 *    is placed to buffer corresponding to the first posted request and so on.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "aio/aio_read_many_reqs"

#include "sockapi-test.h"

#define DATA_BULK       1024  /**< Size of data to be sent */
#define MAX_REQ         100   /**< Max number of requests */

static uint8_t tx_buf[MAX_REQ][DATA_BULK];
static uint8_t rx_buf[DATA_BULK];

/** Structure for array of posted requests */
typedef struct posted_req {
    rpc_aiocb_p     cb;  /**< AIO control block */
    rpc_ptr         buf; /**< Remote buffer */
} posted_req;

int
main(int argc, char *argv[])
{
    /* Environment variables */
    rpc_socket_type     sock_type;
    int                 req_num = 0;
    posted_req         *reqs = NULL;

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
    reqs =  calloc(req_num, sizeof(posted_req));
    for (index = 0; index < req_num; index++)
    {
        te_fill_buf(tx_buf[index], DATA_BULK);
        
        reqs[index].buf = rpc_malloc(pco_iut, DATA_BULK);

        reqs[index].cb = rpc_create_aiocb(pco_iut);
        rpc_fill_aiocb(pco_iut, reqs[index].cb , iut_s, 0, 0,
                       reqs[index].buf , DATA_BULK, &ev);

        /* Post AIO read request. */
        rpc_aio_read(pco_iut, reqs[index].cb);
    }
    
    for (index = 0; index < req_num; index++)
        RPC_SEND(len, pco_tst, tst_s, tx_buf[index], DATA_BULK, 0);
    SLEEP(1);
    
    /* Check errors. */
    for (index = 0; index < req_num; index++)
    {
        if ((rc = rpc_aio_error(pco_iut, reqs[index].cb)) != 0)
            TEST_FAIL("aio_error() for %d request returned %r after request"
                      "finishing", index, rc);
        
        if ((len = rpc_aio_return(pco_iut, reqs[index].cb)) != DATA_BULK)
            TEST_FAIL("aio_return() for %d request returned %u instead %u",
                      index, len, DATA_BULK);

        rpc_get_buf(pco_iut, reqs[index].buf, DATA_BULK, rx_buf);
        if (memcmp(tx_buf[index], rx_buf, DATA_BULK) != 0)
        TEST_FAIL("Data sent from the TST do not match data received "
                  "on the IUT on %d request", index);
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    if (reqs != NULL)
    {
        for (index = 0; index < req_num; index++)
        {
            CLEANUP_RPC_DELETE_AIOCB(pco_iut, reqs[index].cb);
            CLEANUP_RPC_FREE(pco_iut, reqs[index].buf);
        }
        free(reqs);
    }

    TEST_END;
}
