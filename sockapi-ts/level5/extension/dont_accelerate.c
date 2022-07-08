/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 * 
 * $Id: 
 */

/** @page extension-dont_accelerate @c EF_DONT_ACCELERATE environment variable handling
 *
 * @objective Acceleration of certain object types and it's dependency upon
 *            EF_DONT_ACCELERATE environment variable.
 *
 * @type use case
 *
 * @param pco_iut       PCO on IUT
 * @param object        Object to check:
 *                         - TCP (TCP socket)
 *                         - UDP (UDP socket)
 *                         - pipe (pipe fd)
 *                         - epoll (epoll fd)
 *
 * @par Scenario:
 *
 * @author Konstantin Ushakov <Konstantin.Ushakov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/extension/dont_accelerate"

#include "sockapi-test.h"

#include "onload.h"

typedef int (*rpc_stat_f)(rcf_rpc_server *pco_iut, int fd, rpc_stat *buf);

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    int             s       = -1;
    const char     *object  = NULL;
    te_bool         onload;
    int             i;
    te_bool         expected;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_STRING_PARAM(object);

    TEST_STEP("Check that EF_DONT_ACCELERATE is not set on the pco");
    if (!tapi_onload_acc_is_enabled(pco_iut))
        TEST_FAIL("Wrong initial value of EF_DONT_ACCELERATE");

    expected = TRUE;
    for (i = 0; i < 3; i++)
    {
        s = tapi_onload_object_create(pco_iut, object);

        TEST_STEP("Check if the object is accelerated as expected. ");
        onload = tapi_onload_is_onload_fd(pco_iut, s);

        if ( (expected ^ onload) && TAPI_ONLOAD_EPOLL_ACC(object))
            TEST_FAIL("tapi_onload_is_our reported %d as %s",
                      s, onload ? "onload" : "system");

        TEST_STEP("Turn off onload acceleration using EF_DONT_ACCELERATE");
        rpc_setenv(pco_iut, EF_DONT_ACCELERATE, "1", 1);

        TEST_STEP("Check that the acceleration is actually off");
        if (tapi_onload_acc_is_enabled(pco_iut))
            TEST_FAIL("Failed to disable acceleration");

        if (i == 0) {
            TEST_STEP("Repeat the steps with acceleration disabled. Expect all fds "
                      "to be accelerated as changing environment on-fly does not affect "
                      "actuall OOL stack behaviour.");
            expected = TRUE;
        }
        else if (i == 1)
        {
            expected = FALSE;

            TEST_STEP("Restart pco_iut and repeat the steps. Expect that descriptor "
                      "will not be accelerated as now the application is running with "
                      "a new environment.");
            CHECK_RC(tapi_onload_acc(pco_iut, FALSE));
            if (tapi_onload_acc_is_enabled(pco_iut))
                TEST_FAIL("Acceleration is enabled after restart");

        }
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, s);
    CLEANUP_CHECK_RC(tapi_onload_acc(pco_iut, TRUE));

    TEST_END;
}
