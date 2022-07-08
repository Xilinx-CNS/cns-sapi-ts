/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Siute
 * Reliability Socket API in Normal Use
 */

/** @page basic-popen_multithread_flood @b popen() in multithreading
 *
 * @objective Repeatedly call functios popen()-fread()-pclose() in multiple
 *            threads, check that no deadlocks happen.
 *
 * @type conformance
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_iut_only
 * @param threads       Maximum number of parallel threads:
 *                      - 10
 * @param iterations    Summary number of threads to be launced:
 *                      - 10000
 * @param popen_iter    Iterations number of internal loop of a thread:
 *                      - 10
 *
 * @note Test logic is located in RPC @b popen_flooder()
 *
 * @par Scenario:
 * -# Start threads repeatedly in a genral loop.
 * -# Maximum number of parallel threads is @a threads.
 * -# Each thread make a sequence of calls popen()-fread()-pclose()
 *    in loop. The loop has random length from @c 0 to (@p popen_iter - 1)
 *    iterations.
 * -# When a thread is finished, it is restarted.
 * -# Test works until number @p iterations of threads is launched.
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/popen_multithread_flood"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server          *pco_iut = NULL;
    rcf_rpc_server          *pco_thread = NULL;

    int     threads;
    int     iterations;
    int     i;
    int     popen_iter;
    te_bool op_done;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_INT_PARAM(threads);
    TEST_GET_INT_PARAM(iterations);
    TEST_GET_INT_PARAM(popen_iter);

    rcf_rpc_server_thread_create(pco_iut, "iut_thread", &pco_thread);
    pco_thread->op = RCF_RPC_CALL;
    rpc_popen_flooder(pco_thread, threads, iterations, popen_iter, TRUE);

    rpc_popen_flooder_toggle(pco_iut, TRUE);

    RING("Wait while popen flooder is working");
    for (i = 0; i < 100; i++)
    {
        usleep(iterations * popen_iter * 3);
        CHECK_RC(rcf_rpc_server_is_op_done(pco_thread, &op_done));
        if (op_done)
            break;
    }

    rpc_popen_flooder_toggle(pco_iut, FALSE);

    pco_thread->op = RCF_RPC_WAIT;
    rpc_popen_flooder(pco_thread, threads, iterations, popen_iter, FALSE);

    TEST_SUCCESS;

cleanup:
    rcf_rpc_server_destroy(pco_thread);

    TEST_END;
}
