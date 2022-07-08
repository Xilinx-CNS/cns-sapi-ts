/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 * 
 * $Id$
 */

/** @page ext_stackname-set_stackname_caller_dead Validity of certain scopes if the caller died
 *
 * @objective Check that although @b onload_set_stackname called died the scope remains valid
 *
 * @type use case
 *
 * @param pco_iut       PCO on IUT
 * @param object        Object type to check
 * @param onload_stack_scope Scope for @b onload_set_stackname call
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
    int             onload_stack_scope;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_STRING_PARAM(object);
    TEST_GET_ONLOAD_STACK_SCOPE(onload_stack_scope);

    TEST_STEP("Call @b onload_set_stackname() with @p who parameter set to "
              "@c ONLOAD_ALL_THREADS and @p onload_stack_scope.");
    rpc_onload_set_stackname(pco_iut,
                             ONLOAD_ALL_THREADS,
                             onload_stack_scope,
                             "foo");
    TAPI_ONLOAD_CHKOBJ_STACK(pco_iut, object, TAPI_FD_ONLOAD, "foo");

    TEST_STEP("Fork @b pco_iut to get @b pco_iut_fork PCO");
    CHECK_RC(rcf_rpc_server_fork(pco_iut, "pco_iut_fork", &pco_iut_fork));
    TEST_STEP("Destroy @p pco_iut");
    CHECK_RC(rcf_rpc_server_restart(pco_iut));

    TEST_STEP("Check that stack name for @p object on "
              "@b pco_iut_fork matches expectations");
    TAPI_ONLOAD_CHKOBJ_STACK(pco_iut_fork, object, TAPI_FD_ONLOAD, "foo");

    TEST_SUCCESS;
cleanup:
    rcf_rpc_server_destroy(pco_iut_fork);
    CLEANUP_CHECK_RC(tapi_onload_acc(pco_iut, TRUE));

    TEST_END;
}


