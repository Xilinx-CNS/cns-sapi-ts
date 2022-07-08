/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-lio_listio_bad_mode  lio_listio() with incorrect mode
 *
 * @objective Check that @b lio_listio() called with incorrect mode
 *            returns -1 and sets errno to @c EINVAL.
 *
 * @param pco_iut   PCO with IUT
 *
 * @par Scenario
 * -# Create control block list with @c NULL pointers only.
 * -# Call @b lio_listio() with this list and the mode, which is not equal
 *    to @c LIO_WAIT and not equal to @c LIO_NOWAIT.
 * -# Check that @b lio_listio() returned -1 and set errno to @c EINVAL.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "aio/lio_listio_bad_mode"

#include "sockapi-test.h"

#define LIST_LEN 3  /**< Number of calls in the list */

int
main(int argc, char *argv[])
{
    /* Environment variables */
    rcf_rpc_server *pco_iut = NULL;

    /* Auxiliary variables */
    rpc_aiocb_p lio_cb[LIST_LEN];
    tarpc_sigevent ev;
    
    TEST_START;
    
    TEST_GET_PCO(pco_iut);

    memset(&lio_cb, RPC_NULL, LIST_LEN);
    
    memset(&ev, 0, sizeof(ev));
    ev.notify = RPC_SIGEV_NONE;
    
    RPC_AWAIT_IUT_ERROR(pco_iut);

    if ((rc = rpc_lio_listio(pco_iut, RPC_LIO_MODE_UNKNOWN, 
                             lio_cb, LIST_LEN, &ev)) != -1)
        TEST_FAIL("Incorrect behavior of rpc_lio_listio()");
    if ((rc = RPC_ERRNO(pco_iut)) != RPC_EINVAL)
        TEST_FAIL("aio_error() returned %r instead EINVAL", rc);

    TEST_SUCCESS;

cleanup:
    TEST_END;
}
