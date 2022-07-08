/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 * 
 * $Id$ 
 */

/** @page ext_stackname-set_stackname_scope_who @p who parameter effect on stacknames in all scopes
 *
 * @objective Check that stack selected in scope process/user honors 'who'
 *            parameter.
 *
 * @type use case
 *
 * @param pco_iut              PCO on IUT
 * @param object               Object to check:
 *                                - TCP (TCP socket)
 *                                - UDP (UDP socket)
 *                                - pipe (pipe fd)
 *                                - epoll (epoll fd)
 * @param all_threads          Should we enable acceleration for all threads or
 *                             for a single one
 * @param onload_stack_scope   Scope for the main call
 *
 * @par Scenario:
 *
 * @author Konstantin Ushakov <Konstantin.Ushakov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/ext_stackname/set_stackname_scope_who"

#include "sockapi-test.h"

#if HAVE_PWD_H
#include <pwd.h>
#endif

#include "onload.h"

#include "extensions.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut        = NULL;
    rcf_rpc_server *pco_iut_thread = NULL;
    const char     *object         = NULL;
    te_bool         all_threads;
    int             onload_stack_scope;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_STRING_PARAM(object);
    TEST_GET_BOOL_PARAM(all_threads);
    TEST_GET_ONLOAD_STACK_SCOPE(onload_stack_scope);

    TEST_STEP("Disable accleration using EF_DONT_ACCELERATE");
    if (!tapi_onload_acc_is_enabled(pco_iut))
        TEST_FAIL("Wrong initial value of EF_DONT_ACCELERATE");
    CHECK_RC(tapi_onload_acc(pco_iut, FALSE));
    TAPI_ONLOAD_CHKOBJ(pco_iut, object, TAPI_FD_SYSTEM);

    TEST_STEP("Create a thread on @b pco_iut, call it @b pco_iut_thread");
    CHECK_RC(rcf_rpc_server_thread_create(pco_iut,
                                          "pco_iut_thread",
                                          &pco_iut_thread));

    TEST_STEP("Call @b onload_set_stackname() with @p who parameter set with "
              "respect to @p all_threads and @p scope parameter @p onload_stack_scope");
    rpc_onload_set_stackname(pco_iut,
                             all_threads ? ONLOAD_ALL_THREADS
                               : ONLOAD_THIS_THREAD,
                             onload_stack_scope,
                             "name");

    TEST_STEP("Check that depending on @p all_threads parameter this affected one or all "
              "threads (for all @b scope values).");
    TAPI_ONLOAD_CHKOBJ_STACK(pco_iut, object, TAPI_FD_ONLOAD, "name");
    TAPI_ONLOAD_CHKOBJ_STACK(pco_iut_thread, object,
                             all_threads ? TAPI_FD_ONLOAD : TAPI_FD_SYSTEM,
                             "name");


    TEST_SUCCESS;
cleanup:
    rcf_rpc_server_destroy(pco_iut_thread);
    CLEANUP_CHECK_RC(tapi_onload_acc(pco_iut, TRUE));

    TEST_END;
}


