/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_select_all_zeros Using select() function with all fdsets set to NULL and zero timeout
 *
 * @objective Check that @b select() function successfully completes 
 *            when it is called with @a readset, @a writeset, 
 *            @a exceptset set to @c NULL and zero timeout.
 *
 * @type conformance, robustness
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param pco_iut   PCO on IUT
 *
 * @par Scenario:
 *
 * -# Prepare @c struct @c timeval as follows, it is referred as @p tv:
 *        - @a tv_sec - @c 0;
 *        - @a tv_usec - @c 0.
 *        .
 * -# Call @b select(@c 0, @c NULL, @c NULL, @c NULL, @c &tv), actually
 *    it does not matter which value has the first argument;
 * -# Check that the function returns @c 0 and does not update @b errno
 *    variable.
 * 
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_select_all_zeros"

#include "sockapi-test.h"
 

int 
main(int argc, char *argv[]) 
{ 
    rcf_rpc_server *pco_iut = NULL; 
    tarpc_timeval   timeout = { 0, 0 };
    
    TEST_START; 
    
    /* Preambule */ 
    TEST_GET_PCO(pco_iut); 

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_select(pco_iut, 0, RPC_NULL, RPC_NULL, RPC_NULL, &timeout); 
    if (rc == -1)
    {
        int err = RPC_ERRNO(pco_iut);
        
        TEST_VERDICT("select() returns (-1) and "
                     "errno is set to %s",
                     errno_rpc2str(err));
    }
    if (rc != 0)
    {
         TEST_FAIL("select() called on IUT with { 0, 0 } timeout "
                   "returns not 0 (%d)", rc);
    }
    /* Check that errno is not updated is done by the framework */

    TEST_SUCCESS; 
 
cleanup: 
    TEST_END; 
     
} 
