/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 * 
 * $Id$
 */

/** @page ext_stackname-set_stackname_scope_process Scope @c ONLOAD_SCOPE_PROCESS interaction with @b fork() call
 *
 * @objective Check @b fork() call effects stack name selected with scope
 *            @c ONLOAD_SCOPE_PROCESS
 *
 * @type use case
 *
 * @param pco_iut       PCO on IUT
 * @param object        Object type to check
 * @param all_threads   Should calls for @b onload_set_stackname be for THIS or ALL threads
 * @param check_parent  Check @p pco_iut status prior to checking child's one
 *
 * @par Scenario:
 *
 * @author Konstantin Ushakov <Konstantin.Ushakov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/ext_stackname/set_stackname_scope_process"

#include "sockapi-test.h"

#if HAVE_PWD_H
#include <pwd.h>
#endif

#include "onload.h"

#include "extensions.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut      = NULL;
    rcf_rpc_server *pco_iut_fork = NULL;
    const char     *object       = NULL;
    te_bool         all_threads;
    te_bool         check_parent;
    char           *init_stack_name;
    te_bool         restore_stack_name = FALSE;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_STRING_PARAM(object);
    TEST_GET_BOOL_PARAM(all_threads);
    TEST_GET_BOOL_PARAM(check_parent);

    init_stack_name = tapi_onload_get_cur_stackname(pco_iut);

    TEST_STEP("Call @b onload_set_stackname() with @p who parameter set with "
              "respect to @p all_threads and @p scope parameter "
              "@c ONLOAD_SCOPE_PROCESS. It's clear that as we have one thread @p who "
              "parameter should not matter, but it's better to check.");
    rpc_onload_set_stackname(pco_iut,
                             all_threads ? ONLOAD_ALL_THREADS
                               : ONLOAD_THIS_THREAD,
                             ONLOAD_SCOPE_PROCESS,
                             "foo");

    restore_stack_name = TRUE;

    TEST_STEP("If @p check_parent is @c TRUE - "
              "check that depending on @p all_threads parameter this affected no "
              "or all threads");
    if (check_parent)
        TAPI_ONLOAD_CHKOBJ_STACK(pco_iut, object, TAPI_FD_ONLOAD, "foo");

    TEST_STEP("Fork @b pco_iut to get @b pco_iut_fork PCO");
    CHECK_RC(rcf_rpc_server_fork(pco_iut, "pco_iut_fork", &pco_iut_fork));

    TEST_STEP("Check that @p object is accelerated on @b pco_iut and @b pco_iut_fork and "
              "that stacknames have common prefix and different suffix");
    CHECK_RC(tapi_onload_compare_stack_names(pco_iut, pco_iut_fork,
                                             object, "foo", FALSE));

    TEST_STEP("Call @b onload_set_stackname with the same params but on "
              "@b pco_iut_fork. "
              "Note, that as we use @c ONLOAD_SCOPE_PROCESS - prefix of the "
              "name should be the same, but suffix should take process pid into account.");
    rpc_onload_set_stackname(pco_iut_fork,
                             all_threads ? ONLOAD_ALL_THREADS
                               : ONLOAD_THIS_THREAD,
                             ONLOAD_SCOPE_PROCESS,
                             "bar");
    TAPI_ONLOAD_CHKOBJ_STACK(pco_iut, object, TAPI_FD_ONLOAD, "foo");
    TAPI_ONLOAD_CHKOBJ_STACK(pco_iut_fork, object, TAPI_FD_ONLOAD, "bar");

    TEST_STEP("Call @b onload_set_stackname with the same params but on "
              "@b pco_iut_fork  and stackname @c ONLOAD_DONT_ACCELERATE");
    rpc_onload_set_stackname(pco_iut_fork,
                             all_threads ? ONLOAD_ALL_THREADS
                             : ONLOAD_THIS_THREAD,
                             ONLOAD_SCOPE_PROCESS,
                             ONLOAD_DONT_ACCELERATE);

    TEST_STEP("Check that now acceleration behaviour changed - @b pco_iut is "
              "still accelerated and @b pco_iut_fork is NOT");
    TAPI_ONLOAD_CHKOBJ_STACK(pco_iut, object, TAPI_FD_ONLOAD, "foo");
    TAPI_ONLOAD_CHKOBJ(pco_iut_fork, object, TAPI_FD_SYSTEM);


    TEST_SUCCESS;
cleanup:
    if (restore_stack_name)
        rpc_onload_set_stackname(pco_iut, ONLOAD_ALL_THREADS,
                                 ONLOAD_SCOPE_GLOBAL, init_stack_name);

    rcf_rpc_server_destroy(pco_iut_fork);
    CLEANUP_CHECK_RC(tapi_onload_acc(pco_iut, TRUE));

    TEST_END;
}


