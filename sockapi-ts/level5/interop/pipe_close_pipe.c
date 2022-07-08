/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Interoperability of L5 stack with system stack.
 *
 * $Id$
 */

/** @page level5-interop-pipe_close_pipe Usage of system close() call with pipe
 *
 * @objective Check that system close() call correctly closes pipe.
 *
 * @type interop
 *
 * @par Test sequence:
 * -# Create pipe.
 * -# Write data to it and then read data from it. Check that all is fine.
 * -# Close one or two end of the pipe according to @p close_end parameter.
 * -# Create one more pipe.
 * -# Write data to it and then read data from it. Check that all is fine.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/interop/close_fdopen_fclose"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server     *pco_iut = NULL;
    int                 pipefds1[2] = { -1, -1};
    int                 pipefds2[2] = { -1, -1};

    const char         *close_end;
    const char         *syscall_method = NULL;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_STRING_PARAM(syscall_method);
    TEST_GET_STRING_PARAM(close_end);

    rpc_pipe(pco_iut, pipefds1);

    tapi_check_pipe(pco_iut, pipefds1);

    pco_iut->use_libc_once = TRUE;
    if (strcmp(close_end, "read") == 0)
    {
        rpc_close_alt(pco_iut, pipefds1[0], syscall_method);
        pipefds1[0] = -1;
    }
    else if (strcmp(close_end, "write") == 0)
    {
        rpc_close_alt(pco_iut, pipefds1[1], syscall_method);
        pipefds1[1] = -1;
    }
    else if (strcmp(close_end, "both") == 0)
    {
        rpc_close_alt(pco_iut, pipefds1[0], syscall_method);
        rpc_close_alt(pco_iut, pipefds1[1], syscall_method);
        pipefds1[0] = -1;
        pipefds1[1] = -1;
    }
    else
        TEST_FAIL("Incorrect value of 'close_end' parameter.");

    rpc_pipe(pco_iut, pipefds2);

    tapi_check_pipe(pco_iut, pipefds2);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, pipefds1[0]);
    CLEANUP_RPC_CLOSE(pco_iut, pipefds1[1]);
    CLEANUP_RPC_CLOSE(pco_iut, pipefds2[0]);
    CLEANUP_RPC_CLOSE(pco_iut, pipefds2[1]);

    TEST_END;
}
