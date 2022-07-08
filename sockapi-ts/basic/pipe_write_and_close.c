/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-pipe_write_and_close Blocking read, write and close on pipe.
 *
 * @objective Check that blocking @b read() operation returns correct
 *            result after @b write() and @b close() calls on the write
 *            end of a pipe.
 *
 * @type Conformance, compatibility
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_iut_only
 * @param data_size     Size of data to send:
 *                      - 512
 * @param use_fork      Create child RPC server using @b fork() if @c TRUE,
 *                      else create new thread.
 * @param parent_write  Write end of pipe should be accessed from the main
 *                      thread/process if @c TRUE, else - from the child.
 *
 * @par Scenario:
 * -# Create pipe @p pipefds.
 * -# If @p use_fork, create child RPC server @p pco_aux via @b fork(),
 *    otherwise do it using @b pthread_create().
 * -# Call blocking @b read() on the read end of the pipe.
 * -# Call @b write_and_close() on the write end of the pipe.
 * -# Check what was returned by @b read().
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/pipe_write_and_close"

#include "sockapi-test.h"

#define BUF_SIZE 1024

int
main(int argc, char *argv[])
{
    rcf_rpc_server     *pco_iut = NULL;
    rcf_rpc_server     *pco_aux = NULL;
    rcf_rpc_server     *pco_read = NULL;
    rcf_rpc_server     *pco_write = NULL;
    int                 pipefds[2] = { -1, -1};

    int                 data_size;
    int                 tx_buf[BUF_SIZE];
    int                 rx_buf[BUF_SIZE];

    te_bool             operation_done;

    te_bool             use_fork = FALSE;
    te_bool             parent_write = FALSE;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_INT_PARAM(data_size);
    TEST_GET_BOOL_PARAM(use_fork);
    TEST_GET_BOOL_PARAM(parent_write);

    if (data_size > BUF_SIZE)
        TEST_FAIL("Too big data_size parameter value");

    te_fill_buf(tx_buf, data_size);

    rpc_pipe(pco_iut, pipefds);

    if (use_fork)
        rcf_rpc_server_fork(pco_iut, "pco_iut_child", &pco_aux);
    else
        rcf_rpc_server_thread_create(pco_iut, "pco_iut_child", &pco_aux);

    if (parent_write)
    {
        pco_write = pco_iut;
        pco_read = pco_aux;
    }
    else
    {
        pco_write = pco_aux;
        pco_read = pco_iut;
    }

    if (use_fork)
    {
        rpc_close(pco_read, pipefds[1]);
        rpc_close(pco_write, pipefds[0]);
    }

    pco_read->op = RCF_RPC_CALL;
    rpc_read(pco_read, pipefds[0], rx_buf, data_size);

    SLEEP(1);

    rcf_rpc_server_is_op_done(pco_read, &operation_done);
    if (operation_done)
        TEST_FAIL("Read function doen't hang.");

    rpc_write_and_close(pco_write, pipefds[1], tx_buf, data_size);

    pco_read->op = RCF_RPC_WAIT;
    rc = rpc_read(pco_read, pipefds[0], rx_buf, data_size);
    if (rc != data_size)
        TEST_VERDICT("read() function that was blocked returned %d "
                     "instead of %d", rc, data_size);
    else if (memcmp(tx_buf, rx_buf, data_size) != 0)
        TEST_VERDICT("read() function returned incorrect data");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_read, pipefds[0]);

    rcf_rpc_server_destroy(pco_aux);

    TEST_END;
}
