/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 * 
 * $Id$
 */

/** @page ext_stackname-set_stackname_null_restore @c ONLOAD_DONT_ACCELERATE stack name interaction with @b onload_stackname_save()/@b onload_stackname_restore() calls
 *
 * @objective Check that @b onload_stackname_restore() can restore
 *            stack name = @c ONLOAD_DONT_ACCELERATE and also can restore
 *            previous stack state after @b onload_set_stackname() with
 *            stack name = @c ONLOAD_DONT_ACCELERATE was called.
 *
 * @type use case
 *
 * @param pco_iut       PCO on IUT
 * @param object        Object type to check
 * @param scope         Value of the scope parameter to be used
 *                      when calling @b onload_set_stackname()
 * @param all_threads   Whether @c ONLOAD_ALL_THREADS or
 *                      @c ONLOAD_THIS_THREAD should be used when
 *                      calling @b onload_set_stackname()
 * @param restore_null  Whether @b onload_stackname_restore() should
 *                      try to restore stack name =
 *                                          @c ONLOAD_DONT_ACCELERATE
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/ext_stackname/set_stackname_null_restore"

#include "sockapi-test.h"

#if HAVE_PWD_H
#include <pwd.h>
#endif

#include "onload.h"

#include "extensions.h"

#define STACK_NAME "foo"

static inline void
check_restore(rcf_rpc_server *pco_iut,
              const char *object,
              tarpc_onload_stat *ostat_before,
              te_bool *test_failed)
{
    int               fd;
    tarpc_onload_stat ostat_after;

    fd = tapi_onload_object_create(pco_iut, object);
    rpc_onload_fd_stat(pco_iut, fd, &ostat_after);
    rpc_close(pco_iut, fd);

    if (ostat_before->stack_name_null != ostat_after.stack_name_null ||
        (!ostat_before->stack_name_null &&
         strcmp(ostat_before->stack_name, ostat_after.stack_name) != 0))
    {
        ERROR("The moment we called onload_stackname_save(), stack name "
              "was '%s', but after onload_stackname_restore() stack "
              "name is '%s'",
              ostat_before->stack_name_null ? "null" :
                                             ostat_before->stack_name,
              ostat_after.stack_name_null ? "null" :
                                             ostat_after.stack_name);
        ERROR_VERDICT("onload_stackname_restore() failed to "
                      "restore stack name");
        *test_failed = TRUE;
    }
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    const char     *object = NULL;
    int             scope = 0;
    te_bool         restore_null = FALSE;
    te_bool         all_threads = FALSE;
    te_bool         restore_called = FALSE;
    te_bool         restore_terminated = FALSE;
    te_bool         test_failed = FALSE;
    int             fd;

    tarpc_onload_stat  ostat_before;
    tarpc_onload_stat  ostat_after;
    int                saved_errno;
    te_bool            restore_stack_name = FALSE;
    char              *init_stack_name;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_STRING_PARAM(object);
    TEST_GET_ONLOAD_STACK_SCOPE(scope);
    TEST_GET_BOOL_PARAM(restore_null);

    init_stack_name = tapi_onload_get_cur_stackname(pco_iut);

    TEST_STEP("Call @b onload_set_stackname() with parameters set "
              "according to @p scope, @p all_threads. if @p restore_null, "
              "use stack name value @c ONLOAD_DONT_ACCELERATE, "
              "else use @c STACK_NAME");
    rpc_onload_set_stackname(pco_iut,
                             all_threads ?
                                ONLOAD_ALL_THREADS : ONLOAD_THIS_THREAD,
                             scope,
                             restore_null ?
                                ONLOAD_DONT_ACCELERATE : STACK_NAME);
    restore_stack_name = TRUE;

    TEST_STEP("Obtain current stack name.");
    fd = tapi_onload_object_create(pco_iut, object);
    rpc_onload_fd_stat(pco_iut, fd, &ostat_before);
    rpc_close(pco_iut, fd);

    TEST_STEP("Call @b onload_stackname_save().");
    rpc_onload_stackname_save(pco_iut);

    TEST_STEP("Call @b onload_set_stackname() the second time with parameters set "
              "according to @p scope, @p all_threads. if not @p restore_null, "
              "use stack name value @c ONLOAD_DONT_ACCELERATE, "
              "else use @c STACK_NAME");
    rpc_onload_set_stackname(pco_iut,
                             all_threads ?
                                ONLOAD_ALL_THREADS : ONLOAD_THIS_THREAD,
                             scope,
                             restore_null ?
                                    STACK_NAME : ONLOAD_DONT_ACCELERATE);

    fd = tapi_onload_object_create(pco_iut, object);
    rpc_onload_fd_stat(pco_iut, fd, &ostat_after);
    rpc_close(pco_iut, fd);

    TEST_STEP("Call @b onload_stackname_restore().");
    restore_called = TRUE;
    RPC_AWAIT_IUT_ERROR(pco_iut);
    saved_errno = RPC_ERRNO(pco_iut);
    rc = rpc_onload_stackname_restore(pco_iut);
    restore_terminated = TRUE;
    if (rc != 0)
        TEST_VERDICT("onload_stackname_restore() failed with errno %s",
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    else if (saved_errno != RPC_ERRNO(pco_iut))
    {
        ERROR_VERDICT("Successful call of onload_stackname_restore() "
                      "changed errno to %s",
                      errno_rpc2str(RPC_ERRNO(pco_iut)));
        test_failed = TRUE;
    }

    TEST_STEP("Check that current stack name is the same as it was "
              "when we called @b onload_stackname_save().");
    check_restore(pco_iut, object, &ostat_before, &test_failed);

    if (test_failed)
        TEST_STOP;
    TEST_SUCCESS;
cleanup:

    if (restore_stack_name)
        rpc_onload_set_stackname(pco_iut, ONLOAD_ALL_THREADS,
                                 ONLOAD_SCOPE_GLOBAL, init_stack_name);

    if (restore_called && !restore_terminated)
    {
        ERROR_VERDICT("Test terminated unexpectedly when calling "
                      "onload_stackname_restore()");
        check_restore(pco_iut, object, &ostat_before, &test_failed);
    }

    TEST_END;
}
