/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 * 
 * $Id$
 */

/** @page ext_stackname-set_stackname_restore_non_saved Try to call @b onload_stackname_restore() more times than @b onload_stockname_save()
 *
 * @objective Check that @b onload_stackname_restore() fails when we
 *            call it more times than @b onload_stackname_save()
 *
 * @type use case
 *
 * @param pco_iut              PCO on IUT
 * @param call_set_stackname   Whether to call @b onload_set_stackname()
 *                             in the beginning of the test or not
 * @param all_threads          If we call @b onload_set_stackname(), should
 *                             we use ONLOAD_ALL_THREADS or
 *                             ONLOAD_THIS_THREAD?
 * @param scope                If we call @b onload_set_stackname(), this
 *                             determines what scope we should use
 * @param call_stackname_save  Whether we should call
 *                             @b onload_stackname_save() or not
 * @param object               What object type (socket, pipe, etc) should
 *                             be used to check Onload stack
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/ext_stackname/set_stackname_restore_non_saved"

#include "sockapi-test.h"

#if HAVE_PWD_H
#include <pwd.h>
#endif

#include "onload.h"

#include "extensions.h"

#define STACK_NAME "foo"

#define MAX_RESTORE_CALLS 500

static int fd_aux = -1;

static inline te_bool check_restore(rcf_rpc_server *rpcs,
                                    unsigned int number_of_calls,
                                    unsigned int exp_number_of_calls,
                                    unsigned int max_number_of_calls,
                                    tarpc_onload_stat *ostat_before,
                                    const char *object)
{
    tarpc_onload_stat ostat_after;
    te_bool           result = TRUE;

    if (number_of_calls != exp_number_of_calls)
    {
        if (number_of_calls == max_number_of_calls)
            ERROR_VERDICT("It seems onload_stackname_restore() can "
                          "be called any number of times not depending "
                          "on how many times onload_stackname_save() was "
                          "called");
        else if (number_of_calls > exp_number_of_calls)
            ERROR_VERDICT("It seems onload_stackname_restore() can "
                          "be called more times than "
                          "onload_stackname_save() was called");
        else if (number_of_calls < exp_number_of_calls)
            ERROR_VERDICT("It seems onload_stackname_restore() can "
                          "be called less times than "
                          "onload_stackname_save() was called");

        result = FALSE;
    }

    fd_aux = tapi_onload_object_create(rpcs, object);
    rpc_onload_fd_stat(rpcs, fd_aux, &ostat_after);
    rpc_close(rpcs, fd_aux);
    fd_aux = -1;
    if (ostat_before->stack_name_null != ostat_after.stack_name_null)
    {
        ERROR_VERDICT("Initially Onload stack name was %snull, "
                      "after using onload_stackname_restore() it "
                      "became %snull",
                      ostat_before->stack_name_null ? "" : "not ",
                      ostat_after.stack_name_null ? "" : "not ");
        result = FALSE;
    }
    else if (!ostat_before->stack_name_null &&
             !ostat_after.stack_name_null &&
             strcmp(ostat_before->stack_name,
                    ostat_after.stack_name) != 0)
    {
        ERROR_VERDICT("Initially Onload stack name was %s, "
                      "after using onload_stackname_restore() it "
                      "became %s",
                      ostat_before->stack_name,
                      ostat_after.stack_name);
        result = FALSE;
    }

    return result;
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    te_bool         call_set_stackname = FALSE;
    te_bool         all_threads = FALSE;
    int             scope;
    te_bool         call_stackname_save = FALSE;
    te_bool         restore_called = FALSE;
    te_bool         restore_terminated = FALSE;
    const char     *object;
    unsigned int    i;
    unsigned int    successful_calls;
    te_bool         restore_stack_name = FALSE;
    char           *init_stack_name;

    tarpc_onload_stat ostat_before;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_BOOL_PARAM(call_set_stackname);
    if (call_set_stackname)
    {
        TEST_GET_BOOL_PARAM(all_threads);
        TEST_GET_ONLOAD_STACK_SCOPE(scope);
    }
    TEST_GET_BOOL_PARAM(call_stackname_save);
    TEST_GET_STRING_PARAM(object);

    init_stack_name = tapi_onload_get_cur_stackname(pco_iut);

    TEST_STEP("If @p call_set_stackname, call @b onload_set_stackname() "
              "with parameters defined according to @p all_threads, @p scope.");
    if (call_set_stackname)
        rpc_onload_set_stackname(pco_iut,
                                 all_threads ?
                                    ONLOAD_ALL_THREADS : ONLOAD_THIS_THREAD,
                                 scope, "foo");

    restore_stack_name = TRUE;

    TEST_STEP("Save the current state of Onload stack.");
    fd_aux = tapi_onload_object_create(pco_iut, object);
    rpc_onload_fd_stat(pco_iut, fd_aux, &ostat_before);
    rpc_close(pco_iut, fd_aux);
    fd_aux = -1;

    TEST_STEP("If @p call_stackname_save, call @b onload_stackname_save().");
    if (call_stackname_save)
        rpc_onload_stackname_save(pco_iut);

    TEST_STEP("Try to @b onload_stackname_restore() repeatedly many times until it "
              "fails.");
    successful_calls = 0;
    for (i = 0; i < MAX_RESTORE_CALLS; i++)
    {
        restore_called = TRUE;
        restore_terminated = FALSE;
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_onload_stackname_restore(pco_iut);
        restore_terminated = TRUE;
        if (rc != 0)
            break;
        successful_calls++;
    }

    TEST_STEP("Check that @b onload_stackname_restore() was called successfully "
              "an expected number of times.");
    if (!check_restore(pco_iut, successful_calls,
                       call_stackname_save ? 1 : 0,
                       MAX_RESTORE_CALLS, &ostat_before, object))
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    if (restore_called && !restore_terminated)
    {
        ERROR_VERDICT("Test terminated abnormally when calling "
                      "onload_stackname_restore");
        check_restore(pco_iut, successful_calls,
                      call_stackname_save ? 1 : 0,
                      MAX_RESTORE_CALLS, &ostat_before, object);
    }

    if (restore_stack_name)
        rpc_onload_set_stackname(pco_iut, ONLOAD_ALL_THREADS,
                                 ONLOAD_SCOPE_GLOBAL, init_stack_name);

    CLEANUP_RPC_CLOSE(pco_iut, fd_aux);

    TEST_END;
}
