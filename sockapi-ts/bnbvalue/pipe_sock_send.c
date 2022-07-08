/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_pipe_sock_send Using socket sending data functions with pipe
 *
 * @objective Check that it is not possible to use socket sending functions
 *            with pipe
 *
 * @type conformance, robustness
 *
 * @param env           Testing environment:
 *                      - @ref arg_types_env_iut_only
 * @param func          Sending function to be tested:
 *                      - @b send
 *                      - @b sendto
 *                      - @b sendmsg
 *                      - @b sendmmsg
 *                      - @b onload_zc_send
 *                      - @b onload_zc_send_user_buf
 *
 * @par Scenario:
 *  -# Create a pipe.
 *  -# Call @p func on its write end.
 *  -# If @p func successeed, check that data can be read from
 *     the read end of pipe.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/pipe_sock_send"

#include "sockapi-test.h"

#define BUF_SIZE 1024

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;

    int         pipefds[2] = { -1, -1 };
    rpc_send_f  func;
    char       *tx_buf;
    char       *rx_buf;
    int         sent;
    int         received;
    te_bool     done = FALSE;
    te_bool     is_failed = FALSE;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_SEND_FUNC(func);

    CHECK_NOT_NULL(tx_buf = te_make_buf_by_len(BUF_SIZE));
    CHECK_NOT_NULL(rx_buf = te_make_buf_by_len(BUF_SIZE));

    rpc_pipe(pco_iut, pipefds);

    RPC_AWAIT_ERROR(pco_iut);
    sent = func(pco_iut, pipefds[1], tx_buf, BUF_SIZE, 0);

    if (sent >= 0)
    {
        ERROR_VERDICT("%s() successeed on the write end of pipe",
                     rpc_send_func_name(func));
        is_failed = TRUE;
        if (sent == 0)
            RING_VERDICT("No data was written");
        else if (sent != BUF_SIZE)
            RING_VERDICT("%s than expected was written",
                         sent < BUF_SIZE ? "less" : "greater");
    }
    else if (RPC_ERRNO(pco_iut) != RPC_ENOTSOCK)
    {
        RING_VERDICT("%s() on the write end of pipe failed "
                     "with unexpected errno " RPC_ERROR_FMT,
                     rpc_send_func_name(func),
                     RPC_ERROR_ARGS(pco_iut));
    }

    if (sent > 0)
    {
        pco_iut->op = RCF_RPC_CALL;
        rpc_read(pco_iut, pipefds[0], rx_buf, BUF_SIZE);

        SLEEP(1);
        CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &done));
        if (!done)
        {
            ERROR_VERDICT("Reading from the read end of pipe blocks");
            rcf_rpc_server_restart(pco_iut);
            pipefds[0] = -1;
            pipefds[1] = -1;
            TEST_STOP;
        }

        pco_iut->op = RCF_RPC_WAIT;
        RPC_AWAIT_IUT_ERROR(pco_iut);
        received = rpc_read(pco_iut, pipefds[0], rx_buf, BUF_SIZE);
        if (received >= 0)
        {
            if (received == 0)
                RING_VERDICT("No data was read");
            else if (received != sent)
                TEST_VERDICT("%s than expected was read",
                             received < sent ? "less" : "greater");
            else if (memcmp(tx_buf, rx_buf, received) != 0)
                TEST_VERDICT("Incorrect data was read");
        }
        else
            TEST_VERDICT("Reading from the read end of pipe failed "
                         "with errno %s",
                         errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    if (is_failed)
        TEST_STOP;
    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, pipefds[0]);
    CLEANUP_RPC_CLOSE(pco_iut, pipefds[1]);
    free(rx_buf);
    free(tx_buf);

    TEST_END;
}
