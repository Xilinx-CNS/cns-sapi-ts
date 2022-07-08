/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-not_posted_cb  Status/result of non-posted request
 *
 * @objective Check that @b aio_return() and @b aio_error() handle properly
 *            not posted request.
 *
 * @param pco_iut   PCO with IUT
 *
 * @par Scenario
 * -# Create socket on @p iut_s on @p pco_iut and bind it to wildcard address.
 * -# Construct AIO control block @p cb with correct @a aio_buf, @a aio_nbytes, 
 *    @a aio_fildes equal to @p iut_s and @c SIGEV_NONE notification.
 * -# Call @b aio_error() and @b aio_return() for @p cb. Both functions
 *    should return 0.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "aio/not_posted_cb"

#include "sockapi-test.h"
#include "aio_internal.h"

#define DATA_BULK       1024

int
main(int argc, char *argv[])
{
    /* Environment variables */
    rcf_rpc_server *pco_iut = NULL;

    const struct sockaddr  *iut_addr;
    
    /* Auxiliary variables */
    int iut_s = -1;
    
    rpc_aiocb_p  cb = RPC_NULL;
    rpc_ptr      buf = RPC_NULL;
    
    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);
    
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    rpc_bind(pco_iut, iut_s, iut_addr); 

    create_aiocb(pco_iut, iut_s, RPC_LIO_READ,
                 &buf, DATA_BULK, DATA_BULK, NULL, &cb);
                 
    if ((rc = rpc_aio_error(pco_iut, cb)) != 0)
        TEST_FAIL("aio_error() for not posted request returned %d instead "
                  "expected 0", rc);

    if ((rc = rpc_aio_return(pco_iut, cb)) != 0)
        TEST_FAIL("aio_return() for not posted request returned %d instead "
                  "expected 0", rc);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_DELETE_AIOCB(pco_iut, cb);
    CLEANUP_RPC_FREE(pco_iut, buf);

    TEST_END;
}

