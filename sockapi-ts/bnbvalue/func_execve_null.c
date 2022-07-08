/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_execve_null execve() with @c NULL as argv and envp
 *
 * @objective Check execve() function behavior with @c NULL as argv and/or
 *            envp.
 *
 * @type conformance
 *
 * @param pco_iut   PCO on IUT
 * @param params    Parameter identifier
 *
 * @par Scenario:
 * -# Call execve() with arguments in dependence on @a params
 * 
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_execve_null"

#include "sockapi-test.h"

/* Pathname of a program to be called */
#define TEST_EXEC_PROG "/bin/pwd"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    const char *params;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_STRING_PARAM(params);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    if (strcmp(params, "null") == 0)
        rpc_execve_gen(pco_iut, TEST_EXEC_PROG, NULL, NULL);
    else if (strcmp(params, "null_arr") == 0)
        rpc_execve_gen(pco_iut, TEST_EXEC_PROG,
                       (char *const []){NULL}, (char *const []){NULL});
    else
        TEST_FAIL("unknown parameters type %s", params);

    CFG_WAIT_CHANGES;

    if (TE_RC(TE_RCF_PCH, TE_ERPCDEAD) != pco_iut->_errno)
        TEST_FAIL("Unexpected errno %s", errno_rpc2str(RPC_ERRNO(pco_iut)));
    else
        rcf_rpc_server_restart(pco_iut);

    TEST_SUCCESS;

cleanup:
    TEST_END;
}
