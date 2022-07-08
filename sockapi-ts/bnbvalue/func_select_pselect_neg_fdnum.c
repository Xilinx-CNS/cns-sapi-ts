/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_select_pselect_neg_fdnum Using select() and pselect() function with negative value of maxfd parameter
 *
 * @objective Check that @b select() and @b pselect() report an error when
 *            they are used with negative @a maxfd parameter.
 *
 * @type conformance, robustness
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param pco_iut - PCO on IUT
 * @param func    - Function used in the test (@b select or @b pselect)
 * 
 * @note The test is run on @p pco_iut
 *
 * @par Scenario:
 * -# Call @p func with all parameters set to @c NULL except for @a maxfd
 *    parameter, which is set to @c -1;
 * -# Check that the function returns @c -1 and sets @b errno to @c EINVAL.
 * -# Call @p func with all parameters set to @c NULL except for @a maxfd
 *    parameter, which is set to random negative value;
 * -# Check that the function returns @c -1 and sets @b errno to @c EINVAL.
 * 
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_select_pselect_neg_fdnum"

#include "sockapi-test.h"


/**
 * Call select or pselect IUT and check return 
 *
 * @param maxfd_    Highest file descriptor for select or pselect
 */
#define TST_XSELECT(maxfd_) \
    do {                                                                \
        RPC_AWAIT_IUT_ERROR(pco_iut);                                   \
        if (strcmp(func, "select") == 0)                                \
            rc = rpc_select(pco_iut, maxfd_, RPC_NULL, RPC_NULL,        \
                            RPC_NULL, NULL);                            \
        else if (strcmp(func, "pselect") == 0)                          \
            rc = rpc_pselect(pco_iut, maxfd_, RPC_NULL, RPC_NULL,       \
                             RPC_NULL, NULL, RPC_NULL);                 \
        else                                                            \
            TEST_FAIL("'%s' value of 'func' parameter is not "          \
                      "supported by the test", func);                   \
        if (rc != -1)                                                   \
        {                                                               \
             TEST_FAIL("%s() called  on IUT with negative 'maxfd' = %d "\
                    "returns %d instead of -1", func, maxfd_, rc);      \
        }                                                               \
                                                                        \
        CHECK_RPC_ERRNO(pco_iut, RPC_EINVAL,                            \
              "%s called on IUT with negative 'maxfd' = %d "            \
              "returns -1", func, maxfd_);                              \
     } while (0)  


int 
main(int argc, char *argv[]) 
{ 
    rcf_rpc_server  *pco_iut = NULL; 
    const char      *func;
    int              negative_maxfd;    
    
    TEST_START; 
    
    /* Preambule */ 
    TEST_GET_PCO(pco_iut); 
    TEST_GET_STRING_PARAM(func);
    negative_maxfd = rand_range(-1000, -1);
    
    /* Scenario */ 
    TST_XSELECT(-1);
    TST_XSELECT(negative_maxfd);
    
    TEST_SUCCESS; 
 
cleanup: 
    TEST_END;     
} 
 
