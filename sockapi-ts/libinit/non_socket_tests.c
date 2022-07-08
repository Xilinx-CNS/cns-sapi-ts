/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Library _init() function tests
 *
 * $Id$
 */

/** @page libinit-non_socket_tests _init() function tests without sockets
 *
 * @objective Check the behavior of several functions used
 *            in terms of user-defined _init() library function.
 *
 * @type conformance
 *
 * @param pco_iut    PCO on IUT
 * @param lazy       Whether use @b dlopen() with RTLD_LAZY or RTLD_NOW
 * @param sequence   Sequence name. For more information see
 *                   @ref libinit-sequences_and_iterations
 * @param iteration  Iteration name. For more information see
 *                   @ref libinit-sequences_and_iterations
 *
 * @par Test sequence:
 *
 * @author Nikita Rastegaev <Nikita.Rastegaev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "libinit/non_socket_test"

#include "sockapi-test.h"

#include "init_lib.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    const char     *sequence;
    const char     *iteration;
    char           *sequence_str;
    rpc_dlhandle    handle;
    te_bool         lazy;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_BOOL_PARAM(lazy);
    TEST_GET_STRING_PARAM(sequence);
    TEST_GET_STRING_PARAM(iteration);

    TEST_STEP("Set @c LD_PRELOAD environment variable on @b pco_iut.");
    TEST_STEP("Configure test lib with @p sequence and iteration parameters "
              "to select current test scenario.");
    sequence_str = (char *)malloc(strlen(sequence)+strlen(iteration)+2);
    sprintf(sequence_str, "%s %s", sequence, iteration);
    libinit_set_agent_env(pco_iut, sequence_str);
    free(sequence_str);

    TEST_STEP("Exec @b pco_iut for configuration changes to take effect. Note, "
              "that as @c LD_PRELOAD was updated simple restart via Configurator "
              "is not enough.");
    CHECK_RC(rcf_rpc_server_exec(pco_iut));

    TEST_STEP("Call @b lt_do() function from libinit_test.so library on "
              "@b pco_iut. Check return code. Issue appropriate verdicts.");
    handle = libinit_dlopen(pco_iut, lazy);
    rc = rpc_dlsym_call(pco_iut, handle, "lt_do");

    if(rc != 0)
        TEST_FAIL("lt_do() call returned %d", rc);

    TEST_SUCCESS;

cleanup:
    rpc_dlclose(pco_iut, handle);

    TEST_END;
}
