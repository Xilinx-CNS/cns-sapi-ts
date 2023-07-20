/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 */

/** @page basic-pipe_close_read Reading from the pipe with closed write end
 *
 * @objective Check that @p read() function returns @c 0 when it is called
 *            on pipe with closed read end.
 *
 * @type use case
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_iut_only
 * @param data_size Size of data to be sent:
 *                  - 512
 * @param create_child  Create or do not create child process.
 * @param from_child    Send data from child process if @c TRUE.
 * @param block_read    Block in @b read() call if @c TRUE.
 * @param sys_call      If the value is @c TRUE use @b write() using libc.
 * @param add_pipe      Open and read/write data to the additinal pipe if
 *                      @c TRUE.
 * @param kill_parent   If @c TRUE, kill @p pco_iut to close write end
 *                      of pipe.
 *
 * @par Scenario:
 *
 * -# Create @p pipefds pipe on pco_iut;
 * -# If @p create_child is @c TRUE create @p pco_child using @b fork();
 * -# If @p block_read is @c FALSE @b write() @p data_size of data to the
 *    pipe;
 * -# If @p block_read is @c FALSE close all write ends of the pipe
 *    (@b kill() @p pco_iut to do it in the parent process if
 *     @p kill_parent is @c TRUE);
 * -# If @p add_pipe is @c TRUE make the following:
 *      - Call @b pipe() function;
 *      - Write @p data_size of data to this pipe;
 *      - Read @p data_size from this pipe;
 *      - Close newly created pipe;
 * -# Call @b read() according to @p from_child parameter;
 * -# If @p block_read is @c TRUE close all write ends of the pipe
 *    (@b kill() @p pco_iut to do it in the parent process if
 *     @p kill_parent is @c TRUE);
 * -# If @p block_read is @c FALSE call @b read() and check that it returns
 *    @p data_size and check that received data are correct;
 * -# Call @b read() and check that is returns @c 0.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/pipe_close_read"

#include "sockapi-test.h"
#include "tapi_rpc.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server     *pco_iut = NULL;
    rcf_rpc_server     *pco_child = NULL;
    rcf_rpc_server     *pco_aux = NULL;
    rcf_rpc_server     *reader = NULL;
    int                 pipefds[2] = { -1, -1};
    int                 child_pipefds[2] = { -1, -1};
    int                 add_pipefds[2] = { -1, -1};

    void               *tx_buf = NULL;
    void               *rx_buf = NULL;
    void               *add_tx_buf = NULL;

    int                 data_size;
    te_bool             create_child;
    te_bool             block_read;
    te_bool             from_child;
    te_bool             add_pipe;
    te_bool             kill_parent;
    pid_t               iut_pid;

    rpc_send_f          send_f;
    rpc_recv_f          recv_f;

    te_bool             sys_call;
    te_bool             tmp_lib;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_INT_PARAM(data_size);
    TEST_GET_BOOL_PARAM(create_child);
    TEST_GET_BOOL_PARAM(from_child);
    TEST_GET_BOOL_PARAM(block_read);
    TEST_GET_BOOL_PARAM(add_pipe);
    TEST_GET_SEND_FUNC(send_f);
    TEST_GET_RECV_FUNC(recv_f);
    TEST_GET_BOOL_PARAM(sys_call);
    TEST_GET_BOOL_PARAM(kill_parent);

    if (kill_parent && (add_pipe || !from_child || !create_child))
        TEST_FAIL("Incorrect test parameters");

    tx_buf = te_make_buf_by_len(data_size);
    rx_buf = te_make_buf_by_len(data_size);
    te_fill_buf(tx_buf, data_size);
    add_tx_buf = te_make_buf_by_len(data_size);
    te_fill_buf(add_tx_buf, data_size);

    rpc_pipe(pco_iut, pipefds);

    if (create_child)
    {
        CHECK_RC(rcf_rpc_server_fork(pco_iut, "child_proc", &pco_child));
        child_pipefds[0] = pipefds[0];
        child_pipefds[1] = pipefds[1];
        if (kill_parent)
        {
            RPC_CLOSE(pco_child, child_pipefds[1]);
            RPC_CLOSE(pco_iut, pipefds[0]);
        }
    }
    reader = (from_child) ? pco_child : pco_iut;
    iut_pid = rpc_getpid(pco_iut);

    if (!block_read)
    {
        if ((rc = send_f(pco_iut, pipefds[1], tx_buf, data_size, 0)) !=
            data_size)
            TEST_FAIL("%s() sent %d bytes instead of %d", rc, data_size);

        if (!kill_parent)
        {
            RPC_CLOSE(pco_iut, pipefds[1]);
            if (pco_child != NULL)
                RPC_CLOSE(pco_child, child_pipefds[1]);
        }
        else
            rpc_kill(pco_child, iut_pid, RPC_SIGKILL);
    }

    if (add_pipe)
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_pipe(pco_iut, add_pipefds);
        if (tapi_check_pipe(pco_iut, add_pipefds))
            TEST_FAIL("Failed to exchange data on additional pipe");
        RPC_CLOSE(pco_iut, add_pipefds[0]);
        RPC_CLOSE(pco_iut, add_pipefds[1]);
    }

    if (block_read)
        CHECK_RC(rcf_rpc_server_thread_create(reader, "child_thread",
                                              &pco_aux));

    tmp_lib = reader->use_libc;
    reader->use_libc = sys_call;
    reader->op = RCF_RPC_CALL;
    recv_f(reader, reader == pco_iut ? pipefds[0] : child_pipefds[0],
           rx_buf, data_size, 0);

    if (block_read)
    {
        if (!kill_parent)
        {
            if (reader == pco_iut)
            {
                RPC_CLOSE(pco_aux, pipefds[1]);
                if (pco_child != NULL)
                    RPC_CLOSE(pco_child, child_pipefds[1]);
            }
            else
            {
                RPC_CLOSE(pco_iut, pipefds[1]);
                RPC_CLOSE(pco_aux, child_pipefds[1]);
            }
        }
        else
            rpc_kill(pco_aux, iut_pid, RPC_SIGKILL);
    }

    reader->op = RCF_RPC_WAIT;
    rc = recv_f(reader, reader == pco_iut ? pipefds[0] : child_pipefds[0],
                rx_buf, data_size, 0);
    reader->use_libc = tmp_lib;
    if (block_read)
    {
        if (rc != 0)
            TEST_FAIL("Read returned %d instead of 0 when all write "
                      "ends was closed.", rc);
    }
    else
    {
        if (rc != data_size)
            TEST_FAIL("There were %d bytes of data in the pipe but read "
                      "returns %d", data_size, rc);
        if ((rc = recv_f(reader,
                         reader == pco_iut ? pipefds[0] : child_pipefds[0],
                         rx_buf, data_size, 0)) != 0)
            TEST_FAIL("There were no data in the pipe and all write ends "
                      "were closed but %s() returns %d instead of 0",
                      rpc_recv_func_name(recv_f), rc);
    }
    TEST_SUCCESS;

cleanup:
    if (!kill_parent)
    {
        CLEANUP_RPC_CLOSE(pco_iut, pipefds[0]);
        CLEANUP_RPC_CLOSE(pco_iut, pipefds[1]);
        CLEANUP_RPC_CLOSE(pco_iut, add_pipefds[0]);
        CLEANUP_RPC_CLOSE(pco_iut, add_pipefds[1]);
    }
    else
    {
        CLEANUP_CHECK_RC(rcf_rpc_server_finished(pco_iut));
        CLEANUP_CHECK_RC(rcf_rpc_server_restart(pco_iut));
    }

    CLEANUP_RPC_CLOSE(pco_child, child_pipefds[0]);
    CLEANUP_RPC_CLOSE(pco_child, child_pipefds[1]);

    if (pco_aux != NULL)
        CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_aux));
    if (pco_child != NULL)
        rcf_rpc_server_destroy(pco_child);

    sockts_kill_zombie_stacks_if_many(pco_iut);

    TEST_END;
}
