/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 * 
 * $Id$
 */

/** @page ext_stackname-set_stackname_scope_user @c ONLOAD_SCOPE_USER and it's interaction with @b setuid() call
 *
 * @objective Check that after chaning user stack name with 'user'
 *            scope is not valid anymore.
 *
 * @type use case
 *
 * @param pco_iut       PCO on IUT
 * @param object               Object to check:
 *                                - TCP (TCP socket)
 *                                - UDP (UDP socket)
 *                                - pipe (pipe fd)
 *                                - epoll (epoll fd)
 * @param all_threads          Should we enable acceleration for all threads or
 *                             for a single one
 *
 * @par Scenario:
 *
 * @author Konstantin Ushakov <Konstantin.Ushakov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/ext_stackname/set_stackname_scope_user"

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
    struct passwd  *passwd       = getpwuid(getuid());
    tarpc_uid_t     uid          = 0;
    te_bool         all_threads;
    te_bool         check_parent;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_STRING_PARAM(object);
    TEST_GET_BOOL_PARAM(all_threads);
    TEST_GET_BOOL_PARAM(check_parent);

    TEST_STEP("Disable accleration using EF_DONT_ACCELERATE");
    if (!tapi_onload_acc_is_enabled(pco_iut))
        TEST_FAIL("Wrong initial value of EF_DONT_ACCELERATE");
    CHECK_RC(tapi_onload_acc(pco_iut, FALSE));

    TEST_STEP("Call @b onload_set_stackname() with @p who parameter set with "
              "respect to @p all_threads and @p scope parameter "
              "@c ONLOAD_SCOPE_USER. It's clear that as we have one thread @p who "
              "parameter should not matter, but it's better to check.");
    rpc_onload_set_stackname(pco_iut,
                             all_threads ? ONLOAD_ALL_THREADS
                               : ONLOAD_THIS_THREAD,
                             ONLOAD_SCOPE_USER,
                             "user");

    TEST_STEP("If @p check_parent - check that @p object is accelerated on @b pco_iut");
    if (check_parent)
        TAPI_ONLOAD_CHKOBJ_STACK(pco_iut, object, TAPI_FD_ONLOAD, "user");

    TEST_STEP("Fork @b pco_iut (getting @b pco_iut_fork) "
              "and check that in forked process acceleration is enabled as "
              "it's running under the same user");
    CHECK_RC(rcf_rpc_server_fork(pco_iut, "pco_iut_fork", &pco_iut_fork));

    TAPI_ONLOAD_CHKOBJ_STACK(pco_iut_fork, object, TAPI_FD_ONLOAD, "user");

    TEST_STEP("Change UID on @b pco_iut_fork using @b rpc_setuid. Verify that it was "
              "acutually changed.");
    RPC_FUNC_WITH_PTR_RETVAL(pco_iut_fork, passwd, getpwnam,
                             passwd->pw_name);
    rpc_setuid(pco_iut_fork, passwd->pw_uid);
    uid = rpc_getuid(pco_iut_fork);
    if (uid != passwd->pw_uid)
        TEST_FAIL("User ID change failed");

    TEST_STEP("Check that @p object is accelerated on @b pco_iut_fork and stackname "
              "is selected appropritely. It should differ from the one selected "
              "for pco_iut.");
    CHECK_RC(tapi_onload_compare_stack_names(pco_iut, pco_iut_fork,
                                                 object, "user", FALSE));

    TEST_STEP("Stop forked PCO");
    CHECK_RC(rcf_rpc_server_destroy(pco_iut_fork));
    pco_iut_fork = NULL;

    TEST_STEP("Fork once again, @b pco_iut_fork is the forked process");
    CHECK_RC(rcf_rpc_server_fork(pco_iut, "pco_iut_fork", &pco_iut_fork));

    TEST_STEP("Change UID on @b pco_iut_fork");
    rpc_setuid(pco_iut_fork, passwd->pw_uid);

    TEST_STEP("Call @b onload_set_stackname() one more time on pco_iut with "
              "'who' set with respect to @p all_threads and stackname set to "
              "@c ONLOAD_DONT_ACCELERATE");
    rpc_onload_set_stackname(pco_iut_fork,
                             all_threads ? ONLOAD_ALL_THREADS
                             : ONLOAD_THIS_THREAD,
                             ONLOAD_SCOPE_USER,
                             ONLOAD_DONT_ACCELERATE);

    TEST_STEP("Check that @b pco_iut is accelerated and @b pco_iut_fork is not "
              "regardless of @b all_threads");
    TAPI_ONLOAD_CHKOBJ_STACK(pco_iut, object, TAPI_FD_ONLOAD, "user");
    TAPI_ONLOAD_CHKOBJ(pco_iut_fork, object, TAPI_FD_SYSTEM);

    TEST_STEP("Call @b onload_set_stackname() on @b pco_iut_fork and set stackname "
              "'user' on this PCO. However, as we've called @b setuid() it should "
              "be in fact other name with the same prefix. Check that acceleration "
              "is back, prefix matches but full name does not!");
    rpc_onload_set_stackname(pco_iut_fork,
                             all_threads ? ONLOAD_ALL_THREADS
                             : ONLOAD_THIS_THREAD,
                             ONLOAD_SCOPE_USER,
                             "user");
    CHECK_RC(tapi_onload_compare_stack_names(pco_iut, pco_iut_fork,
                                             object, "user", FALSE));

    TEST_SUCCESS;
cleanup:
    rcf_rpc_server_destroy(pco_iut_fork);

    CLEANUP_CHECK_RC(tapi_onload_acc(pco_iut, TRUE));

    TEST_END;
}


