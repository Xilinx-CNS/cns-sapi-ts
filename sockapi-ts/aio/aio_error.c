/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-aio_error  Asynchronous error processing
 *
 * @objective Check that @b aio_error() works properly for simple use
 *            case.
 *
 * @type conformance
 *
 * @param pco_iut       PCO with IUT
 * 
 * @pre Sockets @p iut_s and @p tst_s are connected.
 *
 * -# Call @b aio_read() for socket @c -1. 
 * -# Call @b aio_error(). It should return @c EBADF.
 *
 * @post Sockets @p iut_s and @p tst_s are kept connected.
 * 
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "aio/aio_error"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    /* Environment variables */
    rcf_rpc_server *pco_iut = NULL;
    
    rpc_aiocb_p    cb = RPC_NULL;
    tarpc_sigevent ev;
    
    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    
    memset(&ev, 0, sizeof(ev));
    ev.notify = RPC_SIGEV_NONE;
    
    /* Create and fill aiocb */
    cb = rpc_create_aiocb(pco_iut);
    rpc_fill_aiocb(pco_iut, cb, -1, 0, 0, 0, 0, &ev);
    
    /* Post AIO read request */
    rpc_aio_read(pco_iut, cb);
    
    if ((rc = rpc_aio_error(pco_iut, cb)) != RPC_EBADF)
        TEST_FAIL("aio_error() returned %r instead EBADF", rc);
        
    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_DELETE_AIOCB(pco_iut, cb);

    TEST_END;
}

