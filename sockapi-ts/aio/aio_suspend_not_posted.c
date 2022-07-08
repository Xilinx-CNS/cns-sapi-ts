/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-aio_suspend_not_posted  aio_suspend() for not posted request
 *
 * @objective Check that @b aio_suspend() does not block if called with
 *            not posted request in the list.
 *
 * @param pco_iut   PCO with IUT
 * @param iut_s     Socket on @p pco_iut
 * @param pco_tst   Tester PCO
 * @param tst_s     Socket on @p pco_tst
 * 
 * @pre Sockets @p iut_s and @p tst_s are connected.
 *
 * @par Scenario
 * -# Post AIO read request on @p iut_s socket.
 * -# Create AIO control block for @p iut_s, but not post it.
 * -# Call @b aio_suspend() with non-zero timeout and list of two requests.
 * -# @b aio_suspend() should unblock immediately and return 0.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "aio/aio_suspend_not_posted"

#include "sockapi-test.h"
#include "aio_internal.h"

#define DATA_BULK       1024  /**< Size of data to be sent */

int
main(int argc, char *argv[])
{
    /* Environment variables */
    rpc_socket_type     sock_type;

    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    /* Auxiliary variables */
    int iut_s = -1;
    int tst_s = -1;
    
    rpc_aiocb_p  cb[2] = { RPC_NULL, RPC_NULL };
    rpc_ptr      buf1 = RPC_NULL;
    rpc_ptr      buf2 = RPC_NULL;
    
    tarpc_sigevent ev;
    
    struct timespec tv = { 2, 0 };
    
    
    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    
    memset(&ev, 0, sizeof(ev));
    ev.notify = RPC_SIGEV_NONE;
    
    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    /* Allocate buffers on the pco_iut */
    buf1 = rpc_malloc(pco_iut, DATA_BULK);
    buf2 = rpc_malloc(pco_iut, DATA_BULK);
   
    /* Create and fill aiocb */
    cb[0] = rpc_create_aiocb(pco_iut);
    rpc_fill_aiocb(pco_iut, cb[0], iut_s, 0, 0, buf1, DATA_BULK, &ev);
    cb[1] = rpc_create_aiocb(pco_iut);
    rpc_fill_aiocb(pco_iut, cb[1], iut_s, 0, 0, buf2, DATA_BULK, &ev);

    /* Post AIO read request */
    rpc_aio_read(pco_iut, cb[0]);

    if ((rc = rpc_aio_suspend(pco_iut, cb, 2, &tv)) != 0)
        TEST_FAIL("aio_suspend() returned %d instead 0", rc);
    if (pco_iut->duration / 1000000 > 0)
        TEST_FAIL("aio_suspend() with the list containing not-posted "
                  "request is not unblocked immediately");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    CLEANUP_AIO_CANCEL(pco_iut, iut_s, cb[0]);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_DELETE_AIOCB(pco_iut, cb[0]);
    CLEANUP_RPC_DELETE_AIOCB(pco_iut, cb[1]);
    CLEANUP_RPC_FREE(pco_iut, buf1);
    CLEANUP_RPC_FREE(pco_iut, buf2);
    
    TEST_END;
}
