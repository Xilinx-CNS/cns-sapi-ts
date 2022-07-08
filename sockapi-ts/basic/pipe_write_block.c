/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-pipe_write_block Write operation on blocking pipes.
 *
 * @objective Check that @c write() operation hangs when called on full
 *            blocking pipe.
 *
 * @type Conformance, compatibility
 *
 * @param pco_iut   Private environment with two threads on IUT.
 * @param data_size Size of data to send:
 *                  - 512
 *
 * @par Scenario:
 *
 * -# Create @p pipefds pipe on pco_iut.
 * -# Overfill write buffer in pipe.
 * -# Call @b write() on write end of pipe.
 * -# Sleep awhile and then check that write hanges.
 * -# Read all data from the pipe.
 * -# Check that @b write() returned @p data_size.
 * -# Call @b write() one again and check that it returned @p data_size.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/pipe_write_block"

#include "sockapi-test.h"

#define BUF_SIZE 1024

int
main(int argc, char *argv[])
{
    rcf_rpc_server     *pco_iut = NULL;
    rcf_rpc_server     *pco_aux = NULL;
    int                 pipefds[2] = { -1, -1};

    int                 data_size;
    int                 buf[BUF_SIZE];
    int64_t             total_bytes = 0;

    te_bool             operation_done;

    rpc_send_f          send_f;
    rpc_recv_f          recv_f;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_aux);
    TEST_GET_INT_PARAM(data_size);
    TEST_GET_SEND_FUNC(send_f);
    TEST_GET_RECV_FUNC(recv_f);

    rpc_pipe(pco_iut, pipefds);

    rpc_overfill_fd(pco_iut, pipefds[1], (uint64_t *)&total_bytes);

    pco_iut->op = RCF_RPC_CALL;
    rc = send_f(pco_iut, pipefds[1], buf, data_size, 0);

    SLEEP(1);

    rcf_rpc_server_is_op_done(pco_iut, &operation_done);
    if (operation_done)
        TEST_FAIL("Write function doen't hang.");

    do {
        rc = recv_f(pco_aux, pipefds[0], buf, data_size, 0);
        total_bytes -= rc;
    } while (total_bytes > 0);
    RING("Read all data from overfill_fd + %"TE_PRINTF_64"d", -total_bytes);

    pco_iut->op = RCF_RPC_WAIT;
    rc = send_f(pco_iut, pipefds[1], buf, data_size, 0);
    if (rc != data_size)
        TEST_FAIL("%s() function that was blocked returned %d instead"
                  " of %d", rpc_send_func_name(send_f), rc, data_size);

    rc = send_f(pco_iut, pipefds[1], buf, data_size, 0);
    if (rc != data_size)
        TEST_FAIL("%s() function that wasn't blocked returned %d instead"
                  " of %d", rpc_send_func_name(send_f), rc, data_size);

    TAPI_WAIT_NETWORK;
    total_bytes += 2 * data_size;
    do {
        rc = recv_f(pco_aux, pipefds[0], buf, data_size, 0);
        total_bytes -= rc;
    } while (total_bytes != 0);

    RPC_CHECK_READABILITY(pco_aux, pipefds[0], FALSE);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, pipefds[0]);
    CLEANUP_RPC_CLOSE(pco_iut, pipefds[1]);

    TEST_END;
}
