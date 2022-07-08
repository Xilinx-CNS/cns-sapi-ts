/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 * 
 * $Id$
 */

/** @page ext_stackname-set_stackname_scope_process_ignore Check that stack in scope process ignores irrelevant changes.
 *
 * @objective Check that stack selected for the process honors 'who'
 *            parameter and is not affected by setuid system call.
 *
 * @type use case
 *
 * @param pco_iut       PCO on IUT
 *
 * @par Scenario:
 *
 * @author Konstantin Ushakov <Konstantin.Ushakov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/ext_stackname/set_stackname_scope_process_ignore"

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
    rcf_rpc_server *pco_iut_thread = NULL;
    const char     *object  = NULL;
    te_bool         all_threads;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_STRING_PARAM(object);
    TEST_GET_BOOL_PARAM(all_threads);

    TEST_STEP("Check that EF_DONT_ACCELERATE is not set on the pco_iut and "
              "the acceleration is enabled");
    if (!tapi_onload_acc_is_enabled(pco_iut))
        TEST_FAIL("Wrong initial value of EF_DONT_ACCELERATE");

    TEST_STEP("Disable accleration using EF_DONT_ACCELERATE");
    CHECK_RC(tapi_onload_acc(pco_iut, FALSE));

    TEST_STEP("Check that @p object is not accelerated");
    TAPI_ONLOAD_CHKOBJ(pco_iut, object, TAPI_FD_SYSTEM);

    TEST_STEP("Create a thread on @b pco_iut, call it @b pco_iut_thread");
    CHECK_RC(rcf_rpc_server_thread_create(pco_iut,
                                          "pco_iut_thread",
                                          &pco_iut_thread));

    TEST_STEP("Call @b onload_set_stackname() with @p who parameter set with "
              "respect to @p all_threads and @p scope parameter "
              "@c ONLOAD_SCOPE_USER. It's clear that as we have one thread @p who "
              "parameter should not matter, but it's better to check.");
    rpc_onload_set_stackname(pco_iut,
                             all_threads ? ONLOAD_ALL_THREADS
                               : ONLOAD_THIS_THREAD,
                             ONLOAD_SCOPE_PROCESS,
                             "proc");

    TEST_STEP("Check that depending on @p all_threads parameter this affected no or all "
              "threads");
    TAPI_ONLOAD_CHKOBJ(pco_iut, object, TAPI_FD_ONLOAD);
    TAPI_ONLOAD_CHKOBJ(pco_iut_thread, object,
                       all_threads ? TAPI_FD_ONLOAD :
                                     TAPI_FD_SYSTEM);

    TEST_STEP("Destroy the newly create @b pco_iut_thread thread.");
    CHECK_RC(rcf_rpc_server_destroy(pco_iut_thread));
    pco_iut_thread = NULL;

    TEST_STEP("Change UID on @b pco_iut or on @b pco_iut_thread (depending on "
              "@p thread_create) using @b rpc_setuid.");
    sockts_server_change_uid(pco_iut);

    TEST_STEP("Check that @p object is accelerated on @b pco_iut and this was not "
              "affected by @b setuid() call.");
    TAPI_ONLOAD_CHKOBJ(pco_iut, object, TAPI_FD_ONLOAD);

    TEST_SUCCESS;
cleanup:
    rcf_rpc_server_destroy(pco_iut_thread);
    CLEANUP_CHECK_RC(tapi_onload_acc(pco_iut, TRUE));

    TEST_END;
}


