/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-bnb_cblist_nent  Boundary values of list parameters for aio_suspend() and lio_listio()
 *
 * @objective Check that @b aio_suspend() and @b lio_listio() handle properly
 *            @c NULL list and/or zero/negative number of list elements.
 *
 * @param pco_iut   PCO with IUT
 * @param list      List to be passed to function: @c NULL or not @c NULL
 * @param nent      Number of list elements to be passed to the function:
 *                  0, 1, 2 or -1
 * @param func      @b lio_listio(@c LIO_WAIT), 
 *                  @b lio_listio(@c LIO_NOWAIT) or @b aio_suspend()
 *
 * @par Scenario
 * -# Create socket on @p iut_s on @p pco_iut and bind it to wildcard address.
 * -# If @p list is not @c NULL:
 *   -# Construct AIO control block @p cb with correct @a aio_buf, 
 *      @a aio_nbytes, @a aio_fildes equal to @p iut_s, @c SIGEV_NONE 
 *      notification and @a aio_lio_opcode @c LIO_READ.
 *   -# Construct a list on max { 1, @p nent } elements. First element should
 *      be pointer to @p cb. Other elements should be @c NULL.
 *   -# If @p func is @b aio_suspend(), post request corresponding to 
 *      constructed control block using @b aio_read().
 * -# Call @p func with @c NULL or constructed list (depending on @p list
 *    parameter) and @p nent. 
 * -# @p func should return 0.
 * -# If @p func is not @b aio_suspend(), call @b aio_error() for @p cb.
 *    It should return 0.
 * -# Otherwise restart @p pco_iut process to cancel read request in progress.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "aio/bnb_cblist_nent"

#include "sockapi-test.h"
#include "aio_internal.h"

int
main(int argc, char *argv[])
{
    /* Environment variables */
    int         nent;
    te_bool     list;
    const char *func;

    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    /* Auxiliary variables */
    int iut_s = -1;
    int tst_s = -1;
    
    rpc_aiocb_p  cb = RPC_NULL;
    rpc_ptr      buf;
    
    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(nent);
    TEST_GET_BOOL_PARAM(list);
    TEST_GET_STRING_PARAM(func);
    
    if (list && nent > 0)
        TEST_FAIL("list and nent parameters shouldn't be both correct");
        
    if (!list && nent > 0)
        TEST_FAIL("NULL list and nent > 0 will crash the process");
    
    GEN_CONNECTION(pco_iut, pco_tst, SOCK_DGRAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    create_aiocb(pco_iut, iut_s, RPC_LIO_READ, &buf, 128, 128, NULL, &cb);
                 
    if (strcmp(func, "suspend") == 0)
    {
        rpc_aio_read(pco_iut, cb);
        rpc_aio_suspend(pco_iut, list ? &cb : NULL, nent, NULL);
    }
    else if (strcmp(func, "wait") == 0)
    {
        rpc_lio_listio(pco_iut, RPC_LIO_WAIT, 
                       list ? &cb : NULL, nent, NULL);
                       
        if (rpc_aio_error(pco_iut, cb) != 0)
            TEST_FAIL("Request is unexpectedly posted by lio_listio()");
    }
    else if (strcmp(func, "no_wait") == 0)
    {
        rpc_lio_listio(pco_iut, RPC_LIO_NOWAIT, 
                       list ? &cb : NULL, nent, NULL);
                       
        if (rpc_aio_error(pco_iut, cb) != 0)
            TEST_FAIL("Request is unexpectedly posted by lio_listio()");
    }
    else
        TEST_FAIL("Incorrect func parameter is specified");
        

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_AIO_CANCEL(pco_iut, iut_s, cb);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_DELETE_AIOCB(pco_iut, cb);
    CLEANUP_RPC_FREE(pco_iut, buf);

    TEST_END;
}
