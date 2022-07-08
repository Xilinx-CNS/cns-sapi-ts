/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 * 
 * $Id$
 */

/** @page extension-is_present onload_is_present() functionality
 *
 * @objective Check that onload_is_present() function correctly reports onload library
 *            presence.
 *
 * @type use case
 *
 * What should be noted is that we don't actually check that for the application
 * linked with onload library onload_is_present() function returns 1 - we check that
 * onload_is_present() function called with dlsym() returns 1.
 *
 * @param pco_iut       PCO on IUT
 *
 * @par Scenario:
 *
 * @author Konstantin Ushakov <Konstantin.Ushakov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/extension/is_present"

#include "sockapi-test.h"

#include "onload.h"

#include "extensions.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    int is_present;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);

    TEST_STEP("Check that @c EF_DONT_ACCELERATE is not set on the pco and the "
              "acceleration is enabled");
    if (!tapi_onload_acc_is_enabled(pco_iut))
        TEST_FAIL("Wrong initial value of EF_DONT_ACCELERATE");

    TEST_STEP("Call @b onload_is_present() and check that the stack presence "
              "is reported.");
    is_present = rpc_onload_is_present(pco_iut);
    if (is_present)
        RING("Onload stack is present!");
    else
        TEST_FAIL("Onload stack is not reported as 'present' "
                  "although it's expected to be");

    TEST_STEP("Disable acceleration on @b pco_iut");
    CHECK_RC(tapi_onload_acc(pco_iut, FALSE));

    TEST_STEP("Check that it had no effect on @b onload_is_present() result.");
    is_present = rpc_onload_is_present(pco_iut);
    if (is_present)
        RING("Onload stack is present!");
    else
        TEST_FAIL("Onload stack is not reported as 'present' "
                  "although it's expected to be");



    TEST_SUCCESS;
cleanup:
    CLEANUP_CHECK_RC(tapi_onload_acc(pco_iut, TRUE));

    TEST_END;
}


