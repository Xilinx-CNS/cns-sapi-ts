/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_pipe_wrong_fd IO from wrong pipe end 
 *
 * @objective Check that it is not possible to write to the read end
 *            of pipe or to read from the write end of it.
 *
 * @type conformance, robustness
 *
 * @param pco_iut       PCO on IUT
 * @param use_pipe2     Whether to use @b pipe2() or @b pipe()
 *
 * @par Scenario:
 *  -# Create a pipe.
 *  -# Try to write to the read end of pipe, check what happens.
 *  -# Try to read from the write end of pipe, check what happens.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_pipe_wrong_fd"

#include "sockapi-test.h"

#define BUF_SIZE 1024

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;

    te_bool     use_pipe2 = FALSE;
    te_bool     pipe2_found = FALSE;
    int         pipefds[2] = { -1, -1 };
    char       *tx_buf;
    char       *rx_buf;
    int         sent;
    int         received;
    te_bool     done = FALSE;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_BOOL_PARAM(use_pipe2);

    if (rpc_find_func(pco_iut, "pipe2") == 0)
        pipe2_found = TRUE;
    if (use_pipe2 && !pipe2_found)
        TEST_VERDICT("Failed to find pipe2 on pco_iut");

    CHECK_NOT_NULL(tx_buf = te_make_buf_by_len(BUF_SIZE));
    CHECK_NOT_NULL(rx_buf = te_make_buf_by_len(BUF_SIZE));
    if (use_pipe2)
        rpc_pipe2(pco_iut, pipefds, 0);
    else
        rpc_pipe(pco_iut, pipefds);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    sent = rpc_write(pco_iut, pipefds[0], tx_buf, BUF_SIZE);

    if (sent >= 0)
    {
        RING_VERDICT("Writing on the read end of pipe successeed");
        if (sent == 0)
            RING_VERDICT("No data was written");
        else if (sent != BUF_SIZE)
            RING_VERDICT("%s than expected was written",
                         sent < BUF_SIZE ? "less" : "greater");
    }
    else if (RPC_ERRNO(pco_iut) != RPC_EBADF)
        RING_VERDICT("Writing on the read end of pipe failed "
                     "with unexpected errno %s",
                     errno_rpc2str(RPC_ERRNO(pco_iut)));

    pco_iut->op = RCF_RPC_CALL;
    rpc_read(pco_iut, pipefds[1], rx_buf, BUF_SIZE);

    SLEEP(1);
    CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &done));
    if (!done)
    {
        ERROR_VERDICT("Reading from the write end of pipe blocks");
        rcf_rpc_server_restart(pco_iut);
        pipefds[0] = -1;
        pipefds[1] = -1;
        TEST_STOP;
    }

    pco_iut->op = RCF_RPC_WAIT;
    RPC_AWAIT_IUT_ERROR(pco_iut);
    received = rpc_read(pco_iut, pipefds[1], rx_buf, BUF_SIZE);
    if (received >= 0)
    {
        RING_VERDICT("Reading from the write end of pipe successeed");
        if (received == 0)
            RING_VERDICT("No data was read");
        else if (received != sent)
            TEST_VERDICT("%s than expected was read",
                         received < sent ? "less" : "greater");
        else if (memcmp(tx_buf, rx_buf, received) != 0)
            TEST_VERDICT("Incorrect data was read");
    }
    else if (RPC_ERRNO(pco_iut) != RPC_EBADF)
        RING_VERDICT("Reading from the write end of pipe failed "
                     "with unexpected errno %s",
                     errno_rpc2str(RPC_ERRNO(pco_iut)));

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, pipefds[0]);
    CLEANUP_RPC_CLOSE(pco_iut, pipefds[1]);
    free(rx_buf);
    free(tx_buf);

    TEST_END;
}
