/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 * 
 * $Id$
 */

/** @page ext_stackname-set_stackname_null @b onload_set_stackname with NULL (DONT_ACCELERATE) stackname
 *
 * @objective Check that onload_is_present() function correctly handles NULL
 *            as stackname and disables the acceleration
 *
 * @type use case
 *
 * @param pco_iut       PCO on IUT
 *
 * @par Scenario:
 *
 * @author Konstantin Ushakov <Konstantin.Ushakov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/ext_stackname/set_stackname_null"

#include "sockapi-test.h"

#include "onload.h"

#include "extensions.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut           = NULL;
    const char     *object            = NULL;
    rcf_rpc_server *pco_first_thread  = NULL;
    rcf_rpc_server *pco_second_thread = NULL;
    int             s                 = -1;
    te_bool         all_threads;
    int             onload_stack_scope;
    te_bool         restore_stack_name = FALSE;
    char           *init_stack_name;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_STRING_PARAM(object);
    TEST_GET_BOOL_PARAM(all_threads);
    TEST_GET_ONLOAD_STACK_SCOPE(onload_stack_scope);

    init_stack_name = tapi_onload_get_cur_stackname(pco_iut);

    TEST_STEP("Check that @c EF_DONT_ACCELERATE is not set on the pco and "
              "the acceleration is enabled");
    if (!tapi_onload_acc_is_enabled(pco_iut))
        TEST_FAIL("Wrong initial value of EF_DONT_ACCELERATE");


    TEST_STEP("Create two new threads on @p pco_iut (@b pco_first_thread and "
              "@b pco_second_thread)");
    CHECK_RC(rcf_rpc_server_thread_create(pco_iut,
                   "first_thread", &pco_first_thread));
    CHECK_RC(rcf_rpc_server_thread_create(pco_iut,
                   "second_thread", &pco_second_thread));

    TEST_STEP("Call @b onload_set_stackname on @b pco_first_thread with 'who' "
              "set with respect to @p all_threads and 'stackname' equal to "
              "ONLOAD_DONT_ACCELERATE (which is in fact NULL).");
    rpc_onload_set_stackname(pco_first_thread,
                             all_threads ?
                                ONLOAD_ALL_THREADS : ONLOAD_THIS_THREAD,
                             onload_stack_scope,
                             ONLOAD_DONT_ACCELERATE);
    restore_stack_name = TRUE;

    TEST_STEP("Create an object of type @p object and check that it's accelerated (or not "
              "accelerated) in different threads on @b pco_iut depending on @p all_threads "
              "parameter.");
    TAPI_ONLOAD_CHKOBJ(pco_iut, object,
                       all_threads ? TAPI_FD_SYSTEM : TAPI_FD_ONLOAD);
    TAPI_ONLOAD_CHKOBJ(pco_first_thread, object, TAPI_FD_SYSTEM);
    TAPI_ONLOAD_CHKOBJ(pco_second_thread, object,
                       all_threads ? TAPI_FD_SYSTEM : TAPI_FD_ONLOAD);

    TEST_SUCCESS;
cleanup:
    if (restore_stack_name)
        rpc_onload_set_stackname(pco_iut, ONLOAD_ALL_THREADS,
                                 ONLOAD_SCOPE_GLOBAL, init_stack_name);

    CLEANUP_RPC_CLOSE(pco_iut, s);

    rcf_rpc_server_destroy(pco_first_thread);
    rcf_rpc_server_destroy(pco_second_thread);
    CLEANUP_CHECK_RC(tapi_onload_acc(pco_iut, TRUE));

    TEST_END;
}


