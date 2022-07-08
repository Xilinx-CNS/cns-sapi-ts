/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 */

/** @page basic-many_pipes Write/read operations with different pipes
 *
 * @objective Open @p pipes_num pipes and close @p pipes_to_close of them.
 *            Transmit data using the rest opened pipes and check data.
 *
 * @type use case
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_iut_only
 * @param pipes_num       Number of pipes (in couples with @p pipes_to_close):
 *                        - 7
 *                        - 20
 * @param pipes_to_close  Number of pipes to be closed in each close-open
 *                        iteration:
 *                        - 3
 *                        - 4
 * @param close_open_iter Number of close-open iterations:
 *                        - 0
 *                        - 100
 *
 * @par Scenario:
 *
 * -# Create @p pipes_num pipes;
 * -# Create @p pco_child using @b fork();
 * -# if @p close_open_iter is greater then @c 0 do the following
 *    @p close_open_iter times:
 *      - Close @p pipes_to_close randomly chosen pipes;
 *      - Open @p pipes_to_close pipes.
 * -# Write random number of bytes from @p pco_iut or @p pco_child to each
 *    pipe.
 * -# Read data from each pipe and verify it.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/many_pipes"

#include "sockapi-test.h"

#include "tapi_sh_env.h"

#define MAX_PIPES    30
#define MIN_BUF_SIZE 1
#define MAX_BUF_SIZE 65536

int
main(int argc, char *argv[])
{
    rcf_rpc_server     *pco_iut = NULL;
    rcf_rpc_server     *pco_child = NULL;
    int                 pipefds[MAX_PIPES][2];

    int                 pipes_num;
    int                 pipes_created = 0;
    int                 pipes_to_close;
    int                 close_open_iter;

    void               *tx_buf[MAX_PIPES];
    void               *rx_buf[MAX_PIPES];
    size_t              buf_len[MAX_PIPES];

    int                 from_child;

    int i;
    int j;
    int count;

    rpc_send_f          send_f;
    rpc_recv_f          recv_f;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_INT_PARAM(pipes_num);
    TEST_GET_INT_PARAM(pipes_to_close);
    TEST_GET_INT_PARAM(close_open_iter);
    TEST_GET_SEND_FUNC(send_f);
    TEST_GET_RECV_FUNC(recv_f);

    CHECK_RC(tapi_sh_env_set(pco_iut, "EF_NO_FAIL", "0", TRUE, TRUE));

    /* set all fds to -1 so cleanup in case of
     * pipe call failed works fine */
    for (i = 0; i < pipes_num; i++)
    {
        pipefds[i][0] = -1;
        pipefds[i][1] = -1;
    }

    pipes_created = pipes_num;
    for (i = 0; i < pipes_num; i++)
    {
        tx_buf[i] = te_make_buf(MIN_BUF_SIZE, MAX_BUF_SIZE, &buf_len[i]);
        rx_buf[i] = te_make_buf_by_len(buf_len[i]);
        te_fill_buf(tx_buf[i], buf_len[i]);

        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_pipe(pco_iut, pipefds[i]);
        if (rc < 0)
        {
            RING_VERDICT("Creation of pipe number %d failed: %s",
                         i, errno_rpc2str(RPC_ERRNO(pco_iut)));
            pipes_created = i;
            break;
        }
        /* make writer nonblocking */
        rpc_fcntl(pco_iut, pipefds[i][1], RPC_F_SETFL, RPC_O_NONBLOCK);
    }

    for (i = 0; i < close_open_iter; i++)
    {
        /* Closing randomly chosen pipes */
        count = pipes_to_close;
        j = 0;
        while (count != 0)
        {
            for (; pipefds[j][0] == -1; j = (j + 1) % pipes_created);


            if (rand_range(FALSE, TRUE))
            {
                RPC_AWAIT_IUT_ERROR(pco_iut);
                rc = rpc_close(pco_iut, pipefds[j][0]);
                pipefds[j][0] = -1;
                if (rc < 0)
                    TEST_VERDICT("Closing of read end of %d pipe on %d "
                                 "iteration failed", j, i);
                RPC_AWAIT_IUT_ERROR(pco_iut);
                rc = rpc_close(pco_iut, pipefds[j][1]);
                pipefds[j][1] = -1;
                if (rc < 0)
                    TEST_VERDICT("Closing of write end of %d pipe on %d "
                                 "iteration failed", j, i);
                count--;
            }
            j = (j + 1) % pipes_created;
        }

        /* Open new pipes instead of closed pipes */
        for (j = 0; j < pipes_created; j++)
        {
            if (pipefds[j][0] != -1)
                continue;

            RPC_AWAIT_IUT_ERROR(pco_iut);
            rc = rpc_pipe(pco_iut, pipefds[j]);
            if (rc < 0)
                TEST_VERDICT("Creation of pipe number %d in %d iteration "
                             "failed: %s", i, j,
                             errno_rpc2str(RPC_ERRNO(pco_iut)));

        }
    }

    CHECK_RC(rcf_rpc_server_fork(pco_iut, "child_proc", &pco_child));

    for (i = 0; i < pipes_created; i++)
        rpc_fcntl(pco_iut, pipefds[i][1], RPC_F_SETFL, RPC_O_NONBLOCK);

    for (i = 0; i < pipes_created; i++)
    {
        from_child = rand_range(FALSE, TRUE);
        if ((rc = send_f((from_child) ? pco_child : pco_iut, pipefds[i][1],
                         tx_buf[i], buf_len[i], 0)) != (int)buf_len[i])
        {
            RING("%s() sent %d bytes instead of %d, probably the pipe "
                 "buffers we not allocated in required quantity.",
                 rpc_send_func_name(send_f), rc, buf_len[i]);
            buf_len[i] = rc;
        }
    }

    for (i = 0; i < pipes_created; i++)
    {
        from_child = rand_range(FALSE, TRUE);
        rc = recv_f((from_child) ? pco_child : pco_iut, pipefds[i][0],
                    rx_buf[i], buf_len[i], 0);
        if (rc != (int)buf_len[i])
        {
            WARN("%d bytes were sent, %d bytes were recieved", buf_len, rc);
            TEST_VERDICT("Incorrect number of bytes were recieved");
        }

        if (memcmp(tx_buf[i], rx_buf[i], buf_len[i]) != 0)
            TEST_VERDICT("Incorrect data were recieved");

    }

    TEST_SUCCESS;

cleanup:
    for (i = 0; i < pipes_num; i++)
    {
        CLEANUP_RPC_CLOSE(pco_iut, pipefds[i][0]);
        CLEANUP_RPC_CLOSE(pco_iut, pipefds[i][1]);
        CLEANUP_RPC_CLOSE(pco_child, pipefds[i][0]);
        CLEANUP_RPC_CLOSE(pco_child, pipefds[i][1]);
    }

    rcf_rpc_server_destroy(pco_child);

    CLEANUP_CHECK_RC(tapi_sh_env_unset(pco_iut, "EF_NO_FAIL",
                                       TRUE, TRUE));

    TEST_END;
}
