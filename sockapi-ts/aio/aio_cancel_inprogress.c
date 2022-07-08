/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-aio_cancel_inprogress  Cancel request in progress
 *
 * @objective Check that @b aio_cancel() returns @c AIO_NOTCANCELED if
 *            request cannot be canceled.
 *
 * @param pco_iut   PCO with IUT
 * @param iut_s     Socket on @p pco_iut
 * @param pco_tst   Tester PCO
 * @param tst_s     Socket on @p pco_tst
 *
 * @pre Sockets @p iut_s and @p tst_s are connected.
 *
 * @par Scenario
 * -# Post AIO read request on socket @p iut_s using @b aio_read() function.
 * -# Call @b aio_cancel() for the request.
 * -# If @c AIO_CANCELED is returned fail with error that test is not
 *    applicable for the IUT.
 * -# Check that @c AIO_NOTCANCELED is returned.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "aio/aio_cancel_inprogress"
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
            
    rpc_aiocb_p  cb = RPC_NULL;
    rpc_ptr      buf = RPC_NULL;

    tarpc_sigevent ev;
    
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
    
    /* Allocate buffer on the pco_iut */
    buf = rpc_malloc(pco_iut, DATA_BULK + 1);
    
    /* Create and fill aiocb */
    cb = rpc_create_aiocb(pco_iut);
    rpc_fill_aiocb(pco_iut, cb, iut_s, 0, 0, buf, DATA_BULK + 1, &ev);
    
    /* Post AIO read request */
    rpc_aio_read(pco_iut, cb);
    
    MSLEEP(10);

    if ((rc = rpc_aio_cancel(pco_iut, iut_s, cb)) != RPC_AIO_NOTCANCELED)
    {
        if (rc == RPC_AIO_CANCELED)
            TEST_FAIL("The test is not applicable for this IUT");
        else
            TEST_FAIL("aio_cancel() returned %r instead AIO_NOTCANCELED", 
                      rc);
    }
    
    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_AIO_CANCEL(pco_iut, iut_s, cb);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    CLEANUP_RPC_DELETE_AIOCB(pco_iut, cb);
    CLEANUP_RPC_FREE(pco_iut, buf);
 
    TEST_END;
}
