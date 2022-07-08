/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 * 
 * $Id$ 
 */

/** @page ext_stackname-set_stackname_scope_user_thread @c ONLOAD_SCOPE_USER in case of multi-threaded process.
 *
 * @objective fixme
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
 *
 * @par Scenario:
 *
 * @author Konstantin Ushakov <Konstantin.Ushakov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/ext_stackname/set_stackname_scope_user_threads"

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
    te_bool all_threads;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_STRING_PARAM(object);
    TEST_GET_BOOL_PARAM(all_threads);

    TEST_STEP("Disable accleration using EF_DONT_ACCELERATE");
    if (!tapi_onload_acc_is_enabled(pco_iut))
        TEST_FAIL("Wrong initial value of EF_DONT_ACCELERATE");
    CHECK_RC(tapi_onload_acc(pco_iut, FALSE));

    TEST_STEP("Create a thread on @b pco_iut, call it @b pco_iut_thread");
    CHECK_RC(rcf_rpc_server_thread_create(pco_iut,
                                          "pco_iut_thread",
                                          &pco_iut_thread));

    TEST_STEP("On @b pco_iut call @b onload_set_stackname() with @p who parameter "
              "set with respect to @p all_threads and @p scope parameter "
              "@c ONLOAD_SCOPE_USER");
    rpc_onload_set_stackname(pco_iut,
                             all_threads ? ONLOAD_ALL_THREADS
                               : ONLOAD_THIS_THREAD,
                             ONLOAD_SCOPE_USER,
                             "user");

    TEST_STEP("Check that @p object is accelerated on @b pco_iut and may be "
              "@b pco_iut_thread depending on the @b all_threads parameter");
    TAPI_ONLOAD_CHKOBJ_STACK(pco_iut, object, TAPI_FD_ONLOAD, "user");
    TAPI_ONLOAD_CHKOBJ_STACK(pco_iut_thread, object,
                             all_threads ? TAPI_FD_ONLOAD : TAPI_FD_SYSTEM,
                             "user");

    TEST_STEP("Change UID on @b pco_iut_thread using @b rpc_setuid. Verify that it was "
              "acutually changed.");
    sockts_server_change_uid(pco_iut_thread);

    TEST_STEP("Check that this changed nothing : known OOL stack behaviour");
    TAPI_ONLOAD_CHKOBJ_STACK(pco_iut, object, TAPI_FD_ONLOAD, "user");
    TAPI_ONLOAD_CHKOBJ_STACK(pco_iut_thread, object,
                             all_threads ? TAPI_FD_ONLOAD : TAPI_FD_SYSTEM,
                             "user");

    TEST_STEP("Call @b onload_set_stackname() one more time on @b pco_iut with "
              "'who' set with respect to @p all_threads and stackname set to "
              "@c ONLOAD_DONT_ACCELERATE");
    rpc_onload_set_stackname(pco_iut,
                             all_threads ? ONLOAD_ALL_THREADS
                               : ONLOAD_THIS_THREAD,
                             ONLOAD_SCOPE_USER,
                             ONLOAD_DONT_ACCELERATE);

    TEST_STEP("Check that objects on @b pco_iut and @b pco_iut_thread is accelerated "
              "properly (the behaviour has changed as we called @b onload_set_stackname "
              "once again).");
    TAPI_ONLOAD_CHKOBJ(pco_iut, object, TAPI_FD_SYSTEM);
    TAPI_ONLOAD_CHKOBJ(pco_iut_thread, object, TAPI_FD_SYSTEM);

    TEST_SUCCESS;
cleanup:
    rcf_rpc_server_destroy(pco_iut_thread);

    CLEANUP_CHECK_RC(tapi_onload_acc(pco_iut, TRUE));

    TEST_END;
}


