/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 * 
 * $Id$
 */

/** @page ext_stackname-set_stackname_scope_nochange Check that scope 'nochange' is handled properly by @b onload_set_stackname
 *
 * @objective Check that scope 'nochange' is handled properly by @b onload_set_stackname
 *
 * @type use case
 *
 * @param pco_iut              PCO on IUT
 * @param object               Object to check:
 *                                - TCP (TCP socket)
 *                                - UDP (UDP socket)
 *                                - pipe (pipe fd)
 *                                - epoll (epoll fd)
 * @param onload_stack_scope   Scope for the main call
 *
 * @par Scenario:
 *
 * @author Konstantin Ushakov <Konstantin.Ushakov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/ext_stackname/set_stackname_scope_nochange"

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
    int             onload_stack_scope;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_STRING_PARAM(object);
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

    TEST_STEP("Call @b onload_set_stackname() with scope @p onload_stack_scope and enable "
              "acceleration for @p pco_iut");
    rpc_onload_set_stackname(pco_iut,
                             ONLOAD_THIS_THREAD,
                             onload_stack_scope,
                             "name");

    TEST_STEP("Check that @b pco_iut is accelerated and @b pco_iut_thread is not");
    TAPI_ONLOAD_CHKOBJ_STACK(pco_iut, object, TAPI_FD_ONLOAD, "name");
    TAPI_ONLOAD_CHKOBJ(pco_iut_thread, object, TAPI_FD_SYSTEM);

    

    TEST_STEP("Try to call @b onload_set_stackname with @c ONLOAD_SCOPE_NOCHANGE and "
              "@c ONLOAD_THIS_THREAD - check that it fails with EINVAL as it's forbiden");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_onload_set_stackname(pco_iut,
                                  ONLOAD_THIS_THREAD,
                                  ONLOAD_SCOPE_NOCHANGE,
                                  ONLOAD_DONT_ACCELERATE);
    if (rc != -1)
        TEST_FAIL("Call to onload_set_stackname with invalid params succeeded");
    CHECK_RPC_ERRNO(pco_iut, RPC_EINVAL,
                    "onload_set_stackname() called with invalid params");

    TEST_STEP("Call @b onload_set_stackname() with scope @c ONLOAD_SCOPE_NOCHANGE and "
              "proper @b who to disable back acceleration on all threds");
    rpc_onload_set_stackname(pco_iut,
                             ONLOAD_ALL_THREADS,
                             ONLOAD_SCOPE_NOCHANGE,
                             ONLOAD_DONT_ACCELERATE);

    TEST_STEP("Check that acceleration is disabled on both PCOs");
    TAPI_ONLOAD_CHKOBJ(pco_iut, object, TAPI_FD_SYSTEM);
    TAPI_ONLOAD_CHKOBJ(pco_iut_thread, object, TAPI_FD_SYSTEM);

    TEST_SUCCESS;
cleanup:
    rcf_rpc_server_destroy(pco_iut_thread);
    CLEANUP_CHECK_RC(tapi_onload_acc(pco_iut, TRUE));

    TEST_END;
}


