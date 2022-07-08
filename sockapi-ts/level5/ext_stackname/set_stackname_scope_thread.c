/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 * 
 * $Id$ 
 */

/** @page ext_stackname-set_stackname_scope_thread @c ONLOAD_SCOPE_THREAD for multi-threaded applications
 *
 * @objective Check that @b onload_set_stackname with scope @c ONLOAD_SCOPE_THREAD correctly
 *            configures OOL stack.
 *
 * @type use case
 *
 * @param pco_iut       PCO on IUT
 *
 * @par Scenario:
 *
 * @author Konstantin Ushakov <Konstantin.Ushakov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/ext_stackname/set_stackname_scope_thread"

#include "sockapi-test.h"

#include "onload.h"
#include "extensions.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    const char     *object  = NULL;
    rcf_rpc_server *pco_iut_thread = NULL;
    rcf_rpc_server *pco_iut_thread_aux = NULL;
    te_bool         all_threads;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_STRING_PARAM(object);
    TEST_GET_BOOL_PARAM(all_threads);

    TEST_STEP("Disable acceleration on @p pco_iut.");
    if (!tapi_onload_acc_is_enabled(pco_iut))
        TEST_FAIL("Wrong initial value of EF_DONT_ACCELERATE");
    CHECK_RC(tapi_onload_acc(pco_iut, FALSE));

    TEST_STEP("Create a thread on @b pco_iut, call it @b pco_iut_thread");
    CHECK_RC(rcf_rpc_server_thread_create(pco_iut,
                                          "pco_iut_thread",
                                          &pco_iut_thread));

    TEST_STEP("Call @b onload_set_stackname with @p who parameter set in accordance "
              "with @p all_threads and @p scope of @c ONLOAD_SCOPE_THREAD.");
    rpc_onload_set_stackname(pco_iut,
                             all_threads ?
                             ONLOAD_ALL_THREADS : ONLOAD_THIS_THREAD,
                             ONLOAD_SCOPE_THREAD,
                             "foo");

    TEST_STEP("Check that on @b pco_iut and @b pco_iut_thread "
              "the stackname is selected correctly.");
    TAPI_ONLOAD_CHKOBJ_STACK(pco_iut, object, TAPI_FD_ONLOAD, "foo");
    TAPI_ONLOAD_CHKOBJ_STACK(pco_iut_thread, object,
                             all_threads ? TAPI_FD_ONLOAD : TAPI_FD_SYSTEM,
                             "foo");

    TEST_STEP("Call @b onload_set_stackname() on @b pco_iut_thread and set stackname "
              "'foo' for this particular thread. Check that stackname prefix matches "
              "for @b pco_iut and @b pco_iut_thread, but stackname differs.");
    rpc_onload_set_stackname(pco_iut_thread,
                             ONLOAD_THIS_THREAD,
                             ONLOAD_SCOPE_THREAD,
                             "foo");
    CHECK_RC(tapi_onload_compare_stack_names(pco_iut, pco_iut_thread,
                                             object, "foo", FALSE));

    TEST_STEP("Create another thread on @b pco_iut, call it @b pco_thread_aux. "
              "Check that stackname in the newly create thread is selected "
              "correctly.");
    CHECK_RC(rcf_rpc_server_thread_create(pco_iut,
                                          "pco_iut_thread_aux",
                                          &pco_iut_thread_aux));
    TAPI_ONLOAD_CHKOBJ_STACK(pco_iut_thread_aux, object,
                             all_threads ?
                             TAPI_FD_ONLOAD : TAPI_FD_SYSTEM,
                             "foo");

    TEST_STEP("Call @b onload_set_stackname() on @b pco_iut_thread_aux to "
              "set a new name 'bar' for this particular thread in scope THREAD");
    rpc_onload_set_stackname(pco_iut_thread_aux,
                             ONLOAD_THIS_THREAD,
                             ONLOAD_SCOPE_THREAD,
                             "bar");
    TAPI_ONLOAD_CHKOBJ_STACK(pco_iut, object, TAPI_FD_ONLOAD, "foo");
    TAPI_ONLOAD_CHKOBJ_STACK(pco_iut_thread_aux, object, TAPI_FD_ONLOAD, "bar");

    TEST_STEP("Call @b onload_set_stackname() and set stackname 'bar' in scope "
              "@c ONLOAD_SCOPE_THREAD for all threads.");
    rpc_onload_set_stackname(pco_iut,
                             ONLOAD_ALL_THREADS,
                             ONLOAD_SCOPE_THREAD,
                             "bar");

    TEST_STEP("Check that in all three threads objects are accelerated, names "
              "of the stack have common prefix and appropriate suffix.");
    TAPI_ONLOAD_CHKOBJ_STACK(pco_iut, object, TAPI_FD_ONLOAD, "bar");
    TAPI_ONLOAD_CHKOBJ_STACK(pco_iut_thread, object, TAPI_FD_ONLOAD, "foo");
    TAPI_ONLOAD_CHKOBJ_STACK(pco_iut_thread_aux, object,
                             TAPI_FD_ONLOAD, "bar");

    TEST_SUCCESS;
cleanup:
    rcf_rpc_server_destroy(pco_iut_thread);
    rcf_rpc_server_destroy(pco_iut_thread_aux);

    CLEANUP_CHECK_RC(tapi_onload_acc(pco_iut, TRUE));

    TEST_END;
}


