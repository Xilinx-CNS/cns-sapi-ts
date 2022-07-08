/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 * 
 * $Id$
 */

/** @page ext_stackname-set_stackname_nochange_restore Scope @c ONLOAD_SCOPE_NOCHANGE interaction with @b onload_stackname_save()/@b onload_stackname_restore() calls
 *
 * @objective Check that if @b onload_stackname_save() was called after
 *            @b onload_set_stackname(@c ONLOAD_SCOPE_NOCHANGED), then
 *            @b onload_stackname_restore() actually restores the Onload
 *            stack name set when @b onload_stackname_save() was called.
 *
 * @type use case
 *
 * @param pco_iut       PCO on IUT
 * @param object        Object type to check
 * @param scope1        Value of the scope parameter for the first call
 *                      of @b onload_set_staclname()
 * @param scope2        Value of the scope parameter for the second call
 *                      of @b onload_set_staclname()
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/ext_stackname/set_stackname_nochange_restore"

#include "sockapi-test.h"

#if HAVE_PWD_H
#include <pwd.h>
#endif

#include "onload.h"

#include "extensions.h"

#define STACK_NAME1 "foo"
#define STACK_NAME2 "bar"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    const char     *object = NULL;
    int             scope1;
    int             scope2;
    int             fd;

    tarpc_onload_stat  ostat_before;
    tarpc_onload_stat  ostat_after;
    te_bool            restore_stack_name = FALSE;
    char              *init_stack_name;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_STRING_PARAM(object);
    TEST_GET_ONLOAD_STACK_SCOPE(scope1);
    TEST_GET_ONLOAD_STACK_SCOPE(scope2);

    init_stack_name = tapi_onload_get_cur_stackname(pco_iut);

    TEST_STEP("Call @b onload_set_stackname() with @p who parameter set to "
              "@c ONLOAD_ALL_THREADS, @p scope1 and @c STACK_NAME1.");
    rpc_onload_set_stackname(pco_iut,
                             ONLOAD_ALL_THREADS,
                             scope1,
                             STACK_NAME1);

    restore_stack_name = TRUE;

    TEST_STEP("Call @b onload_set_stackname() with @p who parameter set to "
              "@c ONLOAD_ALL_THREADS and @p scope set to "
              "@c ONLOAD_SCOPE_NOCHANGE.");
    rpc_onload_set_stackname(pco_iut,
                             ONLOAD_ALL_THREADS,
                             ONLOAD_SCOPE_NOCHANGE,
                             "");

    TEST_STEP("Obtain current stack name.");
    fd = tapi_onload_object_create(pco_iut, object);
    rpc_onload_fd_stat(pco_iut, fd, &ostat_before);
    rpc_close(pco_iut, fd);

    TEST_STEP("Call @b onload_stackname_save().");
    rpc_onload_stackname_save(pco_iut);

    TEST_STEP("Call @b onload_set_stackname() with @p who parameter set to "
              "@c ONLOAD_ALL_THREADS, @p scope2 and @c STACK_NAME2.");
    rpc_onload_set_stackname(pco_iut,
                             ONLOAD_ALL_THREADS,
                             scope2,
                             STACK_NAME2);

    TEST_STEP("Call @b onload_stackname_restore().");
    rpc_onload_stackname_restore(pco_iut);

    TEST_STEP("Obtain current stack name.");
    fd = tapi_onload_object_create(pco_iut, object);
    rpc_onload_fd_stat(pco_iut, fd, &ostat_after);
    rpc_close(pco_iut, fd);

    TEST_STEP("Check that current stack name is the same as it was "
              "when we called @b onload_stackname_save().");
    if (ostat_before.stack_name_null != ostat_after.stack_name_null ||
        (!ostat_before.stack_name_null &&
         strcmp(ostat_before.stack_name, ostat_after.stack_name) != 0))
    {
        ERROR("The moment we called onload_stackname_save(), stack name "
              "was '%s', but after onload_stackname_restore() stack "
              "name is '%s'",
              ostat_before.stack_name_null ? "null" :
                                             ostat_before.stack_name,
              ostat_after.stack_name_null ? "null" :
                                             ostat_after.stack_name);
        TEST_VERDICT("onload_stackname_restore() failed to "
                     "restore stack name");
    }

    TEST_SUCCESS;
cleanup:

    if (restore_stack_name)
        rpc_onload_set_stackname(pco_iut, ONLOAD_ALL_THREADS,
                                 ONLOAD_SCOPE_GLOBAL, init_stack_name);

    TEST_END;
}
