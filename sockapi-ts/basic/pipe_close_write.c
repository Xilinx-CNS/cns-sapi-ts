/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 */

/** @page basic-pipe_close_write Writing to the pipe with closed read end
 *
 * @objective Check that @p write() function returns @c -1 and sets errno
 *            to @c EPIPE when it is called on pipe with closed read end.
 *
 * @type use case
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_iut_only
 * @param data_size Size of data to be sent:
 *                  - 512
 * @param create_child  Create or do not create child process.
 * @param from_child    Send data from child process if @c TRUE
 * @param block_write   Make conditions to block in @b write() call
 *                      if @c TRUE.
 * @param sys_call      If the value is @c TRUE use @b write() using libc.
 *
 * @par Scenario:
 *
 * -# Create @p pipefds pipe on pco_iut;
 * -# If @p create_child is @c TRUE create @p pco_child using @b fork();
 * -# If @p block_write is @c TRUE overfill pipe;
 * -# If @p block_write is @c FALSE close all read ends of the pipe;
 * -# Install signal handler on @p pco_iut to catch @c SIGPIPE signal;
 * -# If @p create child is @c TRUE install signal handler on @p pco_child
 *    to catch @c SIGPIPE signal;
 * -# Call @b write() according to @p from_child and @p sys_call parameters;
 * -# If @p block_write is @c TRUE close all read ends of the pipe;
 * -# Check that @b write() returns @c -1 and sets errno to @c EPIPE;
 * -# Check that @c SIGPIPE signal was caught only on the process on which
 *    @b write() was called.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/pipe_close_write"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server     *pco_iut = NULL;
    rcf_rpc_server     *pco_child = NULL;
    rcf_rpc_server     *pco_aux = NULL;
    rcf_rpc_server     *writer = NULL;
    int                 pipefds[2] = { -1, -1};
    int                 child_pipefds[2] = { -1, -1};

    void               *tx_buf = NULL;

    int                 data_size;
    te_bool             create_child;
    te_bool             block_write;
    te_bool             from_child;

    DEFINE_RPC_STRUCT_SIGACTION(old_act);
    DEFINE_RPC_STRUCT_SIGACTION(old_act_child);
    te_bool                 restore_signal_handler = FALSE;
    te_bool                 restore_signal_handler_child = FALSE;
    rpc_sigset_p            set = RPC_NULL;
    rpc_sigset_p            set_child = RPC_NULL;

    rpc_send_f          send_f;

    te_bool             sys_call;
    te_bool             tmp_sys_call;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_INT_PARAM(data_size);
    TEST_GET_BOOL_PARAM(create_child);
    TEST_GET_BOOL_PARAM(from_child);
    TEST_GET_BOOL_PARAM(block_write);
    TEST_GET_SEND_FUNC(send_f);
    TEST_GET_BOOL_PARAM(sys_call);

    tmp_sys_call = pco_iut->use_libc;

    tx_buf = te_make_buf_by_len(data_size);

    rpc_pipe(pco_iut, pipefds);

    if (create_child)
    {
        CHECK_RC(rcf_rpc_server_fork(pco_iut, "child_proc", &pco_child));
        child_pipefds[0] = pipefds[0];
        child_pipefds[1] = pipefds[1];
    }
    writer = (from_child) ? pco_child : pco_iut;

    if (!block_write)
    {
        RPC_CLOSE(pco_iut, pipefds[0]);
        if (pco_child != NULL)
            RPC_CLOSE(pco_child, child_pipefds[0]);
    }
    else
        rpc_overfill_fd(writer, pipefds[1], NULL);

    CHECK_RC(tapi_sigaction_simple(pco_iut, RPC_SIGPIPE,
                                   SIGNAL_REGISTRAR, &old_act));
    restore_signal_handler = TRUE;
    set = rpc_sigreceived(pco_iut);
    rpc_sigemptyset(pco_iut, set);

    if (create_child)
    {
        CHECK_RC(tapi_sigaction_simple(pco_child, RPC_SIGPIPE,
                                       SIGNAL_REGISTRAR, &old_act_child));
        restore_signal_handler_child = TRUE;
        set_child = rpc_sigreceived(pco_child);
        rpc_sigemptyset(pco_child, set_child);
    }

    if (block_write)
        CHECK_RC(rcf_rpc_server_thread_create(writer, "child_thread",
                                              &pco_aux));

    writer->use_libc = sys_call;
    writer->op = RCF_RPC_CALL;
    send_f(writer, pipefds[1], tx_buf, data_size, 0);

    if (block_write)
    {
        RPC_CLOSE((writer == pco_iut) ? pco_aux : pco_iut, pipefds[0]);
        if (pco_child != NULL)
            RPC_CLOSE((writer == pco_child) ? pco_aux : pco_child,
                      child_pipefds[0]);
    }

    RPC_AWAIT_IUT_ERROR(writer);
    writer->op = RCF_RPC_WAIT;
    rc = send_f(writer, pipefds[1], tx_buf, data_size, 0);

    if (rc != -1)
        TEST_FAIL("%s() returned %d instead of -1",
                  rpc_send_func_name(send_f), rc);
    CHECK_RPC_ERRNO(writer, RPC_EPIPE,
                    "%s() called with pipe in which all read ends "
                    "were closed returned -1", rpc_send_func_name(send_f));

    if (from_child)
    {
        if (rpc_sigismember(pco_child, set_child, RPC_SIGPIPE) == 0)
            TEST_VERDICT("Expected signal is not received on child");
        if (rpc_sigismember(pco_iut, set, RPC_SIGPIPE))
            TEST_VERDICT("Unexpected signal is received on parent");
    }
    else
    {
        if (rpc_sigismember(pco_iut, set, RPC_SIGPIPE) != 1)
            TEST_VERDICT("Expected signal is not received on pco_iut");
        if (create_child && rpc_sigismember(pco_child, set_child,
                                            RPC_SIGPIPE))
            TEST_VERDICT("Unexpected signal is received on child");
    }

    TEST_SUCCESS;

cleanup:
    writer->use_libc = tmp_sys_call;

    if (restore_signal_handler)
        CLEANUP_RPC_SIGACTION(pco_iut, RPC_SIGPIPE, &old_act,
                              SIGNAL_REGISTRAR);
    if (restore_signal_handler_child)
        CLEANUP_RPC_SIGACTION(pco_child, RPC_SIGPIPE, &old_act_child,
                              SIGNAL_REGISTRAR);

    CLEANUP_RPC_CLOSE(pco_iut, pipefds[0]);
    CLEANUP_RPC_CLOSE(pco_iut, pipefds[1]);
    if (pco_child != NULL)
    {
        CLEANUP_RPC_CLOSE(pco_child, child_pipefds[0]);
        CLEANUP_RPC_CLOSE(pco_child, child_pipefds[1]);
    }

    if (pco_aux != NULL)
        CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_aux));
    if (pco_child != NULL)
        rcf_rpc_server_destroy(pco_child);

    TEST_END;
}
