/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_select_negative_timeout Using select() function with negative timeout
 *
 * @objective Check that @b select() function reports an error while 
 *            using with negative timeout.
 *
 * @type conformance, robustness
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param pco_iut   PCO on IUT
 *
 * @note The test is run on @p pco_iut
 * 
 * @par Scenario:
 * -# Call @b select() with @c NULL descriptor sets.
 *    As the value of @a timeout parameter use the following
 *    combinations:
 * @table_start
 * @row_start
 *     @entry_start @a tv_sec @entry_end
 *     @entry_start @a tv_usec @entry_end
 * @row_end
 * @row_start
 *     @entry_start @c -1 @entry_end
 *     @entry_start @c  0 @entry_end
 * @row_end
 * @row_start
 *     @entry_start @c -1 @entry_end
 *     @entry_start @c  1 @entry_end
 * @row_end
 * @row_start
 *     @entry_start @c  0 @entry_end
 *     @entry_start @c -1 @entry_end
 * @row_end
 * @row_start
 *     @entry_start @c -1 @entry_end
 *     @entry_start @c -1 @entry_end
 * @row_end
 * @row_start
 *     @entry_start @c  1 @entry_end
 *     @entry_start @c -1 @entry_end
 * @row_end
 * @table_end
 * -# Check that @b select() returns @c -1 and sets @b errno to @c EINVAL;
 * 
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_select_negative_timeout"

#include "sockapi-test.h"

 
int 
main(int argc, char *argv[]) 
{ 
    unsigned int      i;
    rcf_rpc_server   *pco_iut = NULL; 
    tarpc_timeval     timeouts[] = { 
        { -1, 0 }, { -1, 1 }, { 0, -1 }, { -1, -1 }, {  1, -1 }  
    };  

    TEST_START; 
    
    /* Preambule */ 
    TEST_GET_PCO(pco_iut); 

    /* Scenario */ 
    for (i = 0; i < sizeof(timeouts) / sizeof(timeouts[0]); i++)
    {         
         RPC_AWAIT_IUT_ERROR(pco_iut); 
         rc = rpc_select(pco_iut, 0, RPC_NULL, RPC_NULL, RPC_NULL,
                         &timeouts[i]); 
         if (rc != -1)
         {
              TEST_FAIL("select() called  on IUT with %s timeout " 
                        "returns %d instead of -1",
                        tarpc_timeval2str(timeouts + i), rc);
         }     
         CHECK_RPC_ERRNO(pco_iut, RPC_EINVAL, 
                         "select() called on IUT returns -1"); 
    }
    
    TEST_SUCCESS; 
 
cleanup: 
    TEST_END;     
} 
 
