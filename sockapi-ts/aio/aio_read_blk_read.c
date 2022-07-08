/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-aio_read_blk_read  Simultaneous use AIO and blocking read
 *
 * @objective Check that asynchronous and synchronous read operations
 *            many be used simultaneously.
 *
 * @param pco_iut   PCO with IUT
 * @param iut_s     Socket on @p pco_iut
 * @param pco_tst   Tester PCO
 * @param tst_s     Socket on @p pco_tst
 *
 * @pre Sockets @p iut_s and @p tst_s are connected.
 *
 * @par Scenario
 * -# Post AIO read request on socket @p iut_s with buffer @p buf1 and
 *    length @p len1.
 * -# Call @b read() function on @p iut_s with buffer @p buf2 and length 
 *    @p len2.
 * -# Send two bulks of data with lengths @p len1 and @p len2 via @p tst_s.
 * -# Verify that @b read() unblocked and returned @p len2.
 * -# Verify that AIO request is satisfied using @p aio_error().
 * -# Call @b aio_return() for AIO control block - it should return @p len1.
 * -# Verify that first bulk of data sent via @p tst_s is in @p buf1 and
 *    second bulk of data is in @p buf2.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "aio/aio_read_blk_read"
#include "sockapi-test.h"
#include "aio_internal.h"
#define DATA_BULK       1024  /**< Size of data to be sent */

static uint8_t tx_buf1[DATA_BULK];
static uint8_t tx_buf2[DATA_BULK];
static uint8_t rx_buf[DATA_BULK];

int
main(int argc, char *argv[])
{
    /* Environment variables */
    rpc_socket_type     sock_type;

    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    rcf_rpc_server *pco_tst2 = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    /* Auxiliary variables */
    int iut_s = -1;
    int tst_s = -1;
    
    int len1;
    int len2;

    int size = -1;

    rpc_aiocb_p  cb = RPC_NULL;
    rpc_ptr      buf = RPC_NULL;

    tarpc_sigevent ev;
    
    tarpc_timeval tv = { 0, 0 };
    
    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_INT_PARAM(len1);
    TEST_GET_INT_PARAM(len2);

    memset(&ev, 0, sizeof(ev));
    ev.notify = RPC_SIGEV_NONE;

    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    CHECK_RC(rcf_rpc_server_fork(pco_tst, "Child", &pco_tst2));

    te_fill_buf(tx_buf1, DATA_BULK);
    te_fill_buf(tx_buf2, DATA_BULK);

    /* Allocate buffer on the pco_iut */
    buf = rpc_malloc(pco_iut, DATA_BULK + 1);
    
    cb = rpc_create_aiocb(pco_iut);
    rpc_fill_aiocb(pco_iut, cb, iut_s, 0, 0, buf, len1, &ev);

    /* Post AIO read request */
    rpc_aio_read(pco_iut, cb);
    
    rpc_gettimeofday(pco_tst, &tv, NULL);
    pco_tst->start = (tv.tv_sec + 1) * 1000 + tv.tv_usec / 1000;
    pco_tst2->start = (tv.tv_sec + 2) * 1000 + tv.tv_usec / 1000;
        
    pco_tst->op = pco_tst2->op = RCF_RPC_CALL;
    
    rpc_write(pco_tst, tst_s, tx_buf1, len1);
    rpc_write(pco_tst2, tst_s, tx_buf2, len2);

    /* Post blocking read request */
    size = rpc_read(pco_iut, iut_s, rx_buf, len2);
    
    rpc_write(pco_tst, tst_s, tx_buf1, len1);
    rpc_write(pco_tst2, tst_s, tx_buf2, len2);

    if (size != len2)
        TEST_FAIL("read returned %d instead %d", size, len2);
    
    if ((rc = rpc_aio_error(pco_iut, cb)) != 0)
        TEST_FAIL("aio_error() returned %r after request finishing", rc);
    if ((rc = rpc_aio_return(pco_iut, cb)) != len1)
        TEST_FAIL("aio_return() returned %d instead %d", rc, len1);
    
    /* Compare buffers */
    if (memcmp(tx_buf2, rx_buf, len2) != 0)
        TEST_FAIL("Wrong recieved buffer for read");    
    rpc_get_buf(pco_iut, buf, len1, rx_buf);
    if (memcmp(tx_buf1, rx_buf, len1) != 0)
        TEST_FAIL("Wrong recieved buffer for aio_read");
    
    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_DELETE_AIOCB(pco_iut, cb);
    CLEANUP_RPC_FREE(pco_iut, buf);
    
    TEST_END;
}
 
