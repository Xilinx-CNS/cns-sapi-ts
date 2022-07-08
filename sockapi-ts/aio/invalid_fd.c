/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-invalid_fd  Pass invalid file descriptors to aio functions
 *
 * @objective Check that AIO functions return error @c EBADF if called with
 *            incorrect file descriptor.
 *
 * @param pco_iut   PCO with IUT
 * @param func      function to be checked: @b aio_read(), @b aio_write(), 
 *                  @b lio_listio(), @b aio_cancel()
 *
 * @par Scenario
 * -# Open socket @p s on @p pco_iut and close it.
 * -# Create AIO control block @p cb and fill it by correct information.
 * -# Set @a aio_fildes field of @p cb to @p s.
 * -# Call @p func with the @p cb. If @p func is @b aio_cancel() it should
 *    return -1 and set errno to @c EBADF. Otherwise call @p aio_error()
 *    and check that it returned @c EBADF.
 * -# Repeat the previous step with @a aio_fildes equal to -1.
 *
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "aio/invalid_fd"
#include "sockapi-test.h"
#include "aio_internal.h"

#define DATA_BULK       1024  /**< Size of buffers */

int
main(int argc, char *argv[])
{
    /* Environment variables */
    const char         *func;
    
    rcf_rpc_server *pco_iut = NULL;

    /* Auxiliary variables */
    int s = -1, s_dup;
    
    rpc_aiocb_p  cb[1] ={ RPC_NULL };
    rpc_ptr      buf = RPC_NULL;

    tarpc_sigevent ev;
    tarpc_sigevent ev1;
    
    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_STRING_PARAM(func);
    
    INIT_EV(&ev);
    INIT_EV(&ev1);
    
    /* Open and close socket */
    s = rpc_socket(pco_iut, RPC_AF_INET, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    s_dup = s;
    RPC_CLOSE(pco_iut, s);

    /* Create and fill control block */
    buf = rpc_malloc(pco_iut, DATA_BULK);
    cb[0] = rpc_create_aiocb(pco_iut);
    rpc_fill_aiocb(pco_iut, cb[0], s_dup, 0, 0, buf, DATA_BULK, &ev);

    /* Call AIO function */
    if (strcmp(func, "cancel") == 0)
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        if ((rc = rpc_aio_cancel(pco_iut, s_dup, cb[0])) != -1)
            TEST_FAIL("aio_cancel() returned %r instead -1", rc);
        CHECK_RPC_ERRNO(pco_iut, RPC_EBADF, "aio_cancel()");
    }
    else
    {
        if (strcmp(func, "read") == 0)
            rpc_aio_read(pco_iut, cb[0]);
        else if (strcmp(func, "write") == 0)
            rpc_aio_write(pco_iut, cb[0]);
        else
            rpc_lio_listio(pco_iut, RPC_LIO_NOWAIT, cb, 1, &ev1);
        MSLEEP(10);
        if ((rc = rpc_aio_error(pco_iut, cb[0])) != RPC_EBADF)
            TEST_FAIL("aio_error() returned %r instead EBADF", rc);
    }

    /* Repeat previous step with -1 instead s socket */
    rpc_delete_aiocb(pco_iut, cb[0]);
    
    cb[0] = rpc_create_aiocb(pco_iut);
    rpc_fill_aiocb(pco_iut, cb[0], -1, 0, 0, buf, DATA_BULK, &ev);

    if (strcmp(func, "cancel") == 0)
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        if ((rc = rpc_aio_cancel(pco_iut, -1, cb[0])) == 0)
            TEST_FAIL("aio_cancel() returned 0 unexpectively");
        CHECK_RPC_ERRNO(pco_iut, RPC_EBADF, "aio_cancel()");
    }
    else
    {
        if (strcmp(func, "read") == 0)
            rpc_aio_read(pco_iut, cb[0]);
        else if (strcmp(func, "write") == 0)
            rpc_aio_write(pco_iut, cb[0]);
        else
            rpc_lio_listio(pco_iut, RPC_LIO_NOWAIT, cb, 1, &ev1);
        MSLEEP(10);
        if ((rc = rpc_aio_error(pco_iut, cb[0])) != RPC_EBADF)
            TEST_FAIL("aio_error() returned %r instead EBADF", rc);
    }

    TEST_SUCCESS;
    
cleanup:
    CLEANUP_RPC_DELETE_AIOCB(pco_iut, cb[0]);
    CLEANUP_RPC_FREE(pco_iut, buf);
    
    TEST_END;
}
