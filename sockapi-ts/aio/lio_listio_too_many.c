/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-lio_listio_too_many  Pass too long cblist to lio_listio()
 *
 * @objective Check that @b lio_listio() returns @c EINVAL if too long
 *            list is passed.
 *
 * @param pco_iut     PCO with IUT
 *
 * @par Scenario
 * -# Assign @p N to 1.
 * -# Call @b lio_listio(@c LIO_NOWAIT) with list containing @p N @c NULL elements.
 * -# If 0 is returned, assign @p N to @p N * 2 and repeat the previous step.
 * -# Check that errno is set to @c EINVAL.
 * -# Call @b lio_listio(@c LIO_WAIT) with list containing @p N @c NULL elements.
 * -# Check that -1 is returned and errno is set to @c EINVAL.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "aio/lio_listio_too_many"
#include "sockapi-test.h"

#define MAX_REQ         0xFFFF /* Maximum number of requests to be tried */

int
main(int argc, char *argv[])
{
    /* Environment variables */
    rcf_rpc_server *pco_iut = NULL;

    /* Auxiliary variables */
    rpc_aiocb_p    *lio_ptr = (rpc_aiocb_p *)calloc(sizeof(rpc_aiocb_p), 
                                                    MAX_REQ);
    int             n;
    
    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    
    if (lio_ptr == NULL)
        TEST_FAIL("Out of memory");

    for (n = 1; n < MAX_REQ; n *= 2)
    {
         RPC_AWAIT_IUT_ERROR(pco_iut);

         if ((rc = rpc_lio_listio(pco_iut, RPC_LIO_NOWAIT, 
                                  lio_ptr, n, NULL) == 0) == -1)
             break;
    }
    
    if (n >= MAX_REQ)
        TEST_SUCCESS;
    
    if ((rc = RPC_ERRNO(pco_iut)) != RPC_EINVAL)
        TEST_FAIL("lio_listio(LIO_NOWAIT) did not set errno to EINVAL for "
                  "too long list", rc);
    
    RPC_AWAIT_IUT_ERROR(pco_iut);

    if ((rc = rpc_lio_listio(pco_iut, RPC_LIO_WAIT, lio_ptr, n, NULL)) != -1)
        TEST_FAIL("rpc_lio_listio(LIO_WAIT) returned 0 "
                  "instead expected -1");
        
    if ((rc = RPC_ERRNO(pco_iut)) != RPC_EINVAL)
        TEST_FAIL("lio_listio(LIO_WAIT) did not set errno to EINVAL for "
                  "too long list", rc);

    TEST_SUCCESS;
    
cleanup:    
    free(lio_ptr);
    TEST_END;
}

