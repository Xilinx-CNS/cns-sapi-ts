/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-aio_suspend_cblist_dummy  Pass cblist containing only NULL control blocks to aio_suspend()
 *
 * @objective Check that @b aio_suspend() works properly if only @c NULL pointers
 *            are specified in cblist.
 *
 * @param pco_iut   PCO with IUT
 *
 * @par Scenario
 * -# Call @b aio_suspend() with list of 3 @c NULL elements and non-zero timeout.
 * -# Check that @b aio_suspend() unblocked immediately and returned 0.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "aio/aio_suspend_cblist_dummy"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    /* Environment variables */
    rcf_rpc_server *pco_iut = NULL;

    rpc_aiocb_p  cb[3] = { RPC_NULL, RPC_NULL, RPC_NULL };
    
    struct timespec tv = { 2, 0 };
    
    TEST_START;
    TEST_GET_PCO(pco_iut);
    
    if ((rc = rpc_aio_suspend(pco_iut, cb, 3, &tv)) != 0)
        TEST_FAIL("aio_suspend() returned %d instead 0", rc);
        
    if (pco_iut->duration / 1000000 > 0)
        TEST_FAIL("aio_suspend() with list of only zero control blocks "
                  "is not unblocked immediately");
    
    TEST_SUCCESS;
cleanup:
                       
    TEST_END;
}
