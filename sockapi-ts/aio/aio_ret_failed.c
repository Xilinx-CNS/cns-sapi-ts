/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-aio_ret_failed  aio_error() and aio_return() for failed request
 *
 * @objective Check that aio_error() and aio_return() returns proper values
 *            if the request fails.
 *
 * @param pco_iut   PCO with IUT
 *
 * @par Scenario
 * -# Create @b STREAM socket on @p pco_iut.
 * -# Post aio_read() request for @p iut_s socket.
 * -# Call aio_error() - it should return ENOTCONN.
 * -# Call aio_return() - it should return -1.
 * -# Close @p iut_s.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "aio/aio_ret_failed"

#include "sockapi-test.h"

#define DATA_BULK       1024  /**< Size of data to be read */

int
main(int argc, char *argv[])
{
    /* Environment variables */
    rcf_rpc_server *pco_iut = NULL;

    /* Auxiliary variables */
    int iut_s = -1;
    int len;
    
    rpc_aiocb_p  cb = RPC_NULL;
    rpc_ptr      buf = RPC_NULL;
    
    tarpc_sigevent ev;
    
    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    
    memset(&ev, 0, sizeof(ev));
    ev.notify = RPC_SIGEV_NONE;
    
    iut_s = rpc_socket(pco_iut, RPC_PF_INET, RPC_SOCK_STREAM, 
                       RPC_PROTO_DEF);
    
    /* Allocate buffer on the pco_iut */
    buf = rpc_malloc(pco_iut, DATA_BULK + 1);
    
    /* Create and fill aiocb */
    cb = rpc_create_aiocb(pco_iut);
    rpc_fill_aiocb(pco_iut, cb, iut_s, 0, 0, buf, DATA_BULK + 1, &ev);
    
    /* Post AIO read request */
    rpc_aio_read(pco_iut, cb);
    SLEEP(1);

    if ((rc = rpc_aio_error(pco_iut, cb)) != RPC_ENOTCONN)
        TEST_FAIL("aio_error() returned %r after request finishing", rc);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    if ((len = rpc_aio_return(pco_iut, cb)) != -1)
        TEST_FAIL("aio_return() returned %u instead -1", len);
    CHECK_RPC_ERRNO(pco_iut, RPC_EOK,
                    "aio_return() called on pco_iut returns -1, but");

    TEST_SUCCESS;
cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_DELETE_AIOCB(pco_iut, cb);
    CLEANUP_RPC_FREE(pco_iut, buf);

    TEST_END;
}
