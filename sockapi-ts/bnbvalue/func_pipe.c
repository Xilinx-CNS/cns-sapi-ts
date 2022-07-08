/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_pipe Calling pipe()/pipe2() with incorrect arguments
 *
 * @objective Check that @b pipe() or @b pipe2 reports an appropriate error
 *            when it is called with incorrect arguments
 *
 * @type conformance, robustness
 *
 * @param pco_iut       PCO on IUT
 * @param use_pipe2     Whether to use @b pipe2() or @b pipe()
 * @param bad_pipefds   Whether to set pipefds parameter
 *                      incorrectly or not
 * @param bad_flags     @c "none" (flags to be set to 0),
 *                      @c "unexpected" (flags other than @c O_NONBLOCK or
 *                      @c O_CLOEXEC) or
 *                      @c "incorrect" (unknown flags) - this makes sense
 *                      only for @b pipe2()
 *
 * @par Scenario:
 *  -# Call tested function selected according to @p use_pipe2 with
 *     parameters set according to @p bad_pipefds and @p bad_flags.
 *  -# Check what happens.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_pipe"

#include "sockapi-test.h"

enum {
    FLAGS_NONE,
    FLAGS_UNEXPECTED,
    FLAGS_INCORRECT
};

#define PIPE2_FLAGS \
    {"none", FLAGS_NONE},               \
    {"unexpected", FLAGS_UNEXPECTED},   \
    {"incorrect", FLAGS_INCORRECT}

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;

    te_bool     use_pipe2 = FALSE;
    int         bad_flags;
    te_bool     bad_pipefds = FALSE;
    te_bool     pipe2_found = FALSE;
    int         pipefds[2];
    int         flags = 0;
    int         flags_proc = 0;
    int         i = 0;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_BOOL_PARAM(use_pipe2);
    TEST_GET_ENUM_PARAM(bad_flags, PIPE2_FLAGS);
    TEST_GET_BOOL_PARAM(bad_pipefds);

    if (rpc_find_func(pco_iut, "pipe2") == 0)
        pipe2_found = TRUE;
    if (use_pipe2 && !pipe2_found)
        TEST_VERDICT("Failed to find pipe2 on pco_iut");

    if (!bad_pipefds && (!use_pipe2 || bad_flags == FLAGS_NONE))
        TEST_FAIL("This test is not for correct arguments");

    srand(time(NULL));

    for (i = 0; i < 10000; i++)
    {
        flags = rand();
        flags_proc = fcntl_flags_h2rpc(
                              fcntl_flags_rpc2h(flags));

        if (bad_flags == FLAGS_NONE)
        {
            flags = 0;
            break;
        }
        else if (bad_flags == FLAGS_UNEXPECTED)
        {
            flags = flags_proc; 
            if ((flags & ~(RPC_O_NONBLOCK | RPC_O_CLOEXEC)) != 0)
                break;
        }
        else if (bad_flags == FLAGS_INCORRECT &&
                 flags_proc != flags &&
                 (~fcntl_flags_rpc2h(flags) & (~flags_proc & flags)) != 0)
            break;
    }

    if (i == 10000)
        TEST_FAIL("Failed to set flags parameter properly");

    pco_iut->op = RCF_RPC_CALL;
    if (use_pipe2)
        rpc_pipe2(pco_iut, bad_pipefds ? NULL : pipefds, flags);
    else
        rpc_pipe(pco_iut, bad_pipefds ? NULL : pipefds);

    TAPI_WAIT_NETWORK;
    if (!rcf_rpc_server_is_alive(pco_iut))
    {
        rcf_rpc_server_restart(pco_iut);
        TEST_VERDICT("RPC server is dead as a result of %s() call",
                     use_pipe2 ? "pipe2" : "pipe");
    }

    pco_iut->op = RCF_RPC_WAIT;
    RPC_AWAIT_IUT_ERROR(pco_iut);
    if (use_pipe2)
        rc = rpc_pipe2(pco_iut, bad_pipefds ? NULL : pipefds, flags);
    else
        rc = rpc_pipe(pco_iut, bad_pipefds ? NULL : pipefds);

    if (rc == 0)
        TEST_VERDICT("%s() unexpectedly successeed",
                     use_pipe2 ? "pipe2" : "pipe");
    else if (((!use_pipe2 ||
               (use_pipe2 && bad_flags == FLAGS_NONE))
               && RPC_ERRNO(pco_iut) != RPC_EFAULT) ||
             (use_pipe2 && bad_flags != FLAGS_NONE &&
              RPC_ERRNO(pco_iut) != RPC_EINVAL))
        RING_VERDICT("%s() failed with errno %s",
                     use_pipe2 ? "pipe2" : "pipe",
                     errno_rpc2str(RPC_ERRNO(pco_iut)));

    TEST_SUCCESS;

cleanup:

    TEST_END;
}
