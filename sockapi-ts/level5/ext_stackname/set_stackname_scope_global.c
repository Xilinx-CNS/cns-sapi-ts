/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 * 
 * $Id$
 */

/** @page ext_stackname-set_stackname_scope_global @c ONLOAD_SCOPE_GLOBAL versus fork/thread/setuid
 *
 * @objective Check that stackname specified in scope @c ONLOAD_SCOPE_GLOBAL holds agains
 *            fork()/thread creation/setuid().
 *
 * @type use case
 *
 * @param pco_iut       PCO on IUT
 *
 * @par Scenario:
 *
 * @author Konstantin Ushakov <Konstantin.Ushakov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/ext_stackname/set_stackname_scope_global"

#include "sockapi-test.h"

#if HAVE_PWD_H
#include <pwd.h>
#endif

#include "onload.h"

#include "extensions.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    const char     *object  = NULL;
    rcf_rpc_server *pco_iut_aux = NULL;
    const char     *action = NULL;
    te_bool         check_before_action;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_STRING_PARAM(object);
    TEST_GET_STRING_PARAM(action);
    TEST_GET_BOOL_PARAM(check_before_action);

    TEST_STEP("Call @b onload_set_stackname with @p who @c ONLOAD_ALL_THREADS "
              "and @p scope of @c ONLOAD_SCOPE_GLOBAL.");
    rpc_onload_set_stackname(pco_iut,
                             ONLOAD_ALL_THREADS,
                             ONLOAD_SCOPE_GLOBAL,
                             "foo");

    TEST_STEP("If @p check_before_action - check that the call has it's effect "
              "on @b pco_iut");
    if (check_before_action)
        TAPI_ONLOAD_CHKOBJ_STACK(pco_iut, object, TAPI_FD_ONLOAD, "foo");

    if (strcmp(action, "thread_create") == 0)
    {
        TEST_STEP("If @p action is 'thread_create' : create a thread on "
                  "@b pco_iut and ");
        CHECK_RC(rcf_rpc_server_thread_create(pco_iut,
                                              "pco_iut_thread",
                                              &pco_iut_aux));
    }
    else if (strcmp(action, "fork") == 0)
    {
        TEST_STEP("If @p aciton is 'fork' : fork @p pco_iut");
        CHECK_RC(rcf_rpc_server_fork(pco_iut, "pco_iut_fork", &pco_iut_aux));
    }
    else if (strcmp(action, "setuid") == 0)
    {
        TEST_STEP("If @p aciton is 'setuid' - fork @p pco-iut and "
                  "change active UID of the @b pco_iut_aux (newly created PCO).");
        CHECK_RC(rcf_rpc_server_fork(pco_iut, "pco_iut_fork", &pco_iut_aux));
        sockts_server_change_uid(pco_iut_aux);

        TEST_STEP("In case @p action is @b setuid two situations should "
                  "be checked. If we first create an @b object on @b pco_iut "
                  "and after that on @b pco_iut_aux - stack with name 'foo' will "
                  "be created and will belong to @b pco_iut process (which "
                  "is running under root). When @b pco_iut_aux will try "
                  "to create an @b object it will try to use newly created "
                  "stack 'foo' and will fail as it has no permissions - so "
                  "the @b object will be @b SYSTEM. But if @b pco_iut_aux tries "
                  "to create the object before! @b pco_iut - it will create the "
                  "stack and it will have it's user permissions - so root will "
                  "be able to use it! It's very bad, but it's OOL and nothing "
                  "can/will be done.");
        if (check_before_action) {
            TAPI_ONLOAD_CHKOBJ(pco_iut, object, TAPI_FD_ONLOAD);
            TAPI_ONLOAD_CHKOBJ(pco_iut_aux, object, TAPI_FD_SYSTEM);
        }
        else
        {
            TAPI_ONLOAD_CHKOBJ(pco_iut_aux, object, TAPI_FD_ONLOAD);
            TAPI_ONLOAD_CHKOBJ(pco_iut, object, TAPI_FD_ONLOAD);
        }

        TEST_SUCCESS;
    }

    TEST_STEP("In case of non-setuid action: check that names of the stacks for "
              "@p object in @b pco_iut and newly created PCO are equal.");
    CHECK_RC(tapi_onload_compare_stack_names(pco_iut, pco_iut_aux,
                                             object, "foo", TRUE));


    TEST_SUCCESS;
cleanup:
    rcf_rpc_server_destroy(pco_iut_aux);

    /* need to restart it as after our experiments the OOL configuration
     * is incorrect */
    rcf_rpc_server_restart(pco_iut);

    TEST_END;
}


