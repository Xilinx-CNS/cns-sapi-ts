/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 * 
 * $Id$
 */

/** @page ext_stackname-dont_acc_and_set_stackname Interaction between @b onload_set_stackname and @c EF_DONT_ACCELERATE
 *
 * @objective EF_DONT_ACCELERATE environment variable and it's actions should be
 *            overwritten by consequtive onload_set_stackname() function call.
 *
 * @type use case
 *
 * @param pco_iut       PCO on IUT
 * @param object        Object to check:
 *                         - TCP (TCP socket)
 *                         - UDP (UDP socket)
 *                         - pipe (pipe fd)
 *                         - epoll (epoll fd)
 * @param all_threads   Should we enable acceleration for all threads or
 *                      for a single one
 *
 * @par Scenario:
 *
 * @author Konstantin Ushakov <Konstantin.Ushakov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/ext_stackname/dont_acc_and_set_stackname"

#include "sockapi-test.h"

#include "onload.h"

#include "extensions.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_first_thread = NULL;
    rcf_rpc_server *pco_second_thread = NULL;
    int             s       = -1;
    int             f_s     = -1;
    int             s_s     = -1;
    const char     *object  = NULL;
    te_bool         onload;

    te_bool all_threads;

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
    if (tapi_onload_acc_is_enabled(pco_iut))
        TEST_FAIL("Acceleration is enabled after restart");
    s = tapi_onload_object_create(pco_iut, object);
    onload = tapi_onload_is_onload_fd(pco_iut, s);
    if (onload)
        TEST_FAIL("Acceleration is disabled but object is reported "
                  "as onload");
    rpc_close(pco_iut, s);

    TEST_STEP("Create two new threads on @p pco_iut");
    CHECK_RC(rcf_rpc_server_thread_create(pco_iut,
                                          "first_thread", &pco_first_thread));

    CHECK_RC(rcf_rpc_server_thread_create(pco_iut,
                                          "second_thread", &pco_second_thread));

    TEST_STEP("Call onload_set_stackname on @p pco_iut in thread number one with the "
              "following arguments: "
              "if @p all_threads is @c TRUE - @c ONLOAD_ALL_THREADS as "
              "@p 'who' parameter and @c ONLOAD_THIS_THREAD in case @p all_threads is "
              "@c FALSE. Scope should be @c ONLOAD_SCOPE_GLOBAL.");
    rpc_onload_set_stackname(pco_first_thread,
                             all_threads ? ONLOAD_ALL_THREADS :
                                ONLOAD_THIS_THREAD,
                             ONLOAD_SCOPE_GLOBAL,
                             "test");

    TEST_STEP("Create objects of type @p object in thread number one and "
              "thread number two.");
    f_s = tapi_onload_object_create(pco_first_thread, object);
    s_s = tapi_onload_object_create(pco_second_thread, object);

    TEST_STEP("Check that @p object is acclerated or not accelerated depending "
              "on @p all_threads. In the first thread it MUST be accelerated. In "
              "the second thread - depending on @p all_threads parameter.");
    onload = tapi_onload_is_onload_fd(pco_iut, f_s);
    if (!onload)
        TEST_FAIL("Object in thread for which onload_set_stackname was called "
                  "is not accelerated although it must be");
    onload = tapi_onload_is_onload_fd(pco_iut, s_s);
    if (all_threads && !onload)
        TEST_FAIL("Object in thread for which onload_set_stackname was notcalled "
                  "is not accelerated although it must be as ONLOAD_ALL_THREADS "
                  "was used");

    if (!all_threads && onload)
        TEST_FAIL("Object is accelerated although it should not be as ONLOAD_THIS_THREAD "
                  "was used");

    TEST_STEP("If @p all_threads is @c FALSE call onload_set_stackname() one more time "
              "with ONLOAD_ALL_THREADS and check that thread two changed it's behaviour and "
              "now @b object is accelerated.");
    if (!all_threads)
    {
        rpc_onload_set_stackname(pco_first_thread,
                                 ONLOAD_ALL_THREADS,
                                 ONLOAD_SCOPE_GLOBAL,
                                 "test");
        rpc_close(pco_iut, s_s);
        s_s = tapi_onload_object_create(pco_second_thread, object);
        onload = tapi_onload_is_onload_fd(pco_iut, s_s);
        if (!onload)
            TEST_FAIL("Object is not accelerated although ONLOAD_ALL_THREADS was "
                      "finaly used");
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, s);
    CLEANUP_RPC_CLOSE(pco_iut, f_s);
    CLEANUP_RPC_CLOSE(pco_iut, s_s);

    rcf_rpc_server_destroy(pco_first_thread);
    rcf_rpc_server_destroy(pco_second_thread);
    CLEANUP_CHECK_RC(tapi_onload_acc(pco_iut, TRUE));

    TEST_END;
}

