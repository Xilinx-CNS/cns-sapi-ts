/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 */

/** @page usecases-if_nameindex The name <-> index conversations
 *
 * @objective Test on reliability of the following operations:
 *            @b if_nameindex()/if_freenameindex() and
 *            @b if_nametoindex()/if_indextoname().
 *
 * @type use case
 *
 * @param env   Testing environment:
 *                  - @ref arg_types_env_iut_only
 *
 * @par Scenario:
 * -# Retrieve existed in system an array of pairs ifname/ifindex by means of
 *    @b if_nameindex();
 * -# Enumerate retrieved @p array to get actually @p array size;
 * -# Carry out the both @b if_nametoindex() and @b if_indextoname() for 
 *    each @p array element. Compare the index/name to be returned by means of 
 *    @b if_nametoindex()/if_indextoname() with @p if_nameindex @p array info;
 * -# Deallocate @p if_nameindex @p array by means of @b if_freenameindex();
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "usecases/if_nameindex"

#include "sockapi-test.h"


#define TST_MAX_IFNAME_LENGTH   255


int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    
    struct if_nameindex   *if_array = NULL, *head_array = NULL;
    int                    if_count;
    

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);

    head_array = if_array = rpc_if_nameindex(pco_iut);
    if (!if_array)
         TEST_FAIL("Interface list is empty");

    for (if_count = 0; if_array->if_index != 0; if_array++)
        if_count++;

    for (; if_count > 0; if_count--)
    {
        char          name[TST_MAX_IFNAME_LENGTH];
        unsigned int  index;
         
        if (!rpc_if_indextoname(pco_iut, 
                                head_array[if_count-1].if_index, name))
        {
            TEST_FAIL("if_indextoname() failure");
        }

        index = rpc_if_nametoindex(pco_iut, name);
        if (!index)
            TEST_FAIL("if_nametoindex() failure");

        if (strcmp(name, head_array[if_count - 1].if_name))
            TEST_FAIL("returned if_name is not validated");

        if (head_array[if_count-1].if_index != index)
            TEST_FAIL("returned if_index is not validated");
    }

    TEST_SUCCESS;

cleanup:
    rpc_if_freenameindex(pco_iut, head_array);

    TEST_END;
}   

