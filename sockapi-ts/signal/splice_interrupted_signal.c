/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Signals
 */

/**
 * @page signal-splice_interrupted_signal Check that splice() can be interrupted by signal.
 *
 * @objective Check that @b splice() returns @c -1, errno @c EINTR if it is
 *            interrupted by signal that is caught
 *
 * @param env           Testing environment
 * @param func_sig      Function to be used to set signal handler
 * @param restart       Set or not @c SA_RESTART for the signal
 * @param set_move      Whether to call splice with @c SPLICE_F_MOVE
 *                      flag or not.
 * @param additional    Describe additinal actions to be performed in the test.
 *                      It can @c second_signal or @c - .
 * @param to_socket     If @c TRUE, splice() should move data from pipe to
 *                      socket, else - the other way round.
 * @param block_on_read If @c TRUE, block splice() on "reading" else on "writing"
 *
 * @par Scenario:
 *
 * @author Artemii Morozov <Artemii.Morozov@oktetlabs.ru>
 */

#define TE_TEST_NAME "signal/splice_interrupted_signal"

#include "sockapi-test.h"
#include "ts_signal.h"

#define SEND_SIZE 10240

typedef struct splice_params {
    int fd_in;
    int fd_out;
    size_t len;
    int flags;
} splice_params;

#define CHECK_DATA(_buf, _buf_len, _got_buf, _got_buf_len) \
do {                                             \
    if (_got_buf_len != _buf_len)                \
        TEST_FAIL("Only part of data received"); \
    if (memcmp(_buf, _got_buf, _buf_len))        \
            TEST_FAIL("Invalid data received");  \
} while(0);

int
main(int argc, char *argv[])
{
    int iut_s = -1;
    int tst_s = -1;
    int pipefds[2] = {-1, -1};

    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_iut_aux = NULL;
    rcf_rpc_server *pco_killer = NULL;
    rcf_rpc_server *pco_tst = NULL;

    rcf_rpc_server *in_rpcs = NULL;
    rcf_rpc_server *out_rpcs = NULL;
    int in_fd;
    int out_fd;

    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;

    const char *func_sig;
    te_bool restart;
    const char *additional;
    te_bool set_move;
    te_bool to_socket;
    te_bool block_on_read;

    te_bool second_signal = FALSE;
    te_bool done;

    splice_params params;

    char tx_buf[SEND_SIZE];
    char rx_buf[SEND_SIZE];

    uint64_t overfill_bytes = 0;
    int total_expected_bytes = 0;
    int total_received_bytes = 0;
    int sent_bytes;
    te_dbuf read_data = TE_DBUF_INIT(0);
    te_dbuf payload = TE_DBUF_INIT(0);

    int rc2;

    sockts_sig_ctx ctx = SOCKTS_SIG_CTX_INIT;
    sockts_sig_state state = SOCKTS_SIG_STATE_INIT;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_killer);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_STRING_PARAM(func_sig);
    TEST_GET_BOOL_PARAM(restart);
    TEST_GET_BOOL_PARAM(set_move);
    TEST_GET_STRING_PARAM(additional);
    TEST_GET_BOOL_PARAM(to_socket);
    TEST_GET_BOOL_PARAM(block_on_read);

    te_fill_buf(tx_buf, SEND_SIZE);

    if (strcmp(additional, "second_signal") == 0)
        second_signal = TRUE;

    ctx.func_sig = func_sig;
    ctx.restart = restart;
    ctx.second_signal = second_signal;

    TEST_STEP("Create pipe on IUT");
    CHECK_RC(rpc_pipe(pco_iut, pipefds));

    TEST_STEP("Establish connection between IUT and tester.");
    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    TEST_STEP("Create a new @p pco_iut_aux process on IUT");
    CHECK_RC(rcf_rpc_server_fork(pco_iut, "pco_iut_chld1", &pco_iut_aux));

    TEST_STEP("Close unnecessary file descriptors on @p pco_iut "
              "and @p pco_iut_aux");
    CHECK_RC(rpc_close(pco_iut_aux, iut_s));
    if (to_socket)
    {
        CHECK_RC(rpc_close(pco_iut, pipefds[1]));
        CHECK_RC(rpc_close(pco_iut_aux, pipefds[0]));
    }
    else
    {
        CHECK_RC(rpc_close(pco_iut, pipefds[0]));
        CHECK_RC(rpc_close(pco_iut_aux, pipefds[1]));
    }

    TEST_STEP("Configure signal handlers on @p pco_iut according to "
              "@p restart and @p additional, using @p func_sig.");
    if (second_signal)
    {
        TEST_SUBSTEP("If @p additional is @c second_signal, firstly "
                     "configure a handler for @c SIGUSR2 which will "
                     "send @c SIGUSR1. Set or not set @c SA_RESTART "
                     "flag for it according to @p restart. After that "
                     "configure a handler for @c SIGUSR1, setting "
                     "@c SA_RESTART in the opposite way for it.");
    }
    else
    {
        TEST_SUBSTEP("If @p additional is not @c second_signal, "
                     "configure a handler for @c SIGUSR1, setting "
                     "or not @c SA_RESTART according to @p restart.");
    }

    sockts_sig_save_state(pco_iut, &ctx, &state);
    sockts_sig_register_handlers(pco_iut, &ctx, NULL);
    sockts_sig_set_target(pco_iut, &ctx);

    TEST_STEP("If @b splice() should be blocked on write operation, overfill "
              "FD to which it is expected to write but make some data ready "
              "on FD from which it is expected to read.");
    if (!block_on_read)
    {
        if (to_socket)
        {
            RPC_WRITE(sent_bytes, pco_iut_aux, pipefds[1], tx_buf, SEND_SIZE);
            rpc_overfill_buffers(pco_iut, iut_s, &overfill_bytes);
        }
        else
        {
            RPC_WRITE(sent_bytes, pco_tst, tst_s, tx_buf, SEND_SIZE);
            rpc_overfill_fd(pco_iut, pipefds[1], &overfill_bytes);
        }

        total_expected_bytes = sent_bytes + overfill_bytes;
    }

    TEST_STEP("Call RPC non-blocking @b splice() on @p pco_iut");
    params.fd_in = to_socket ? pipefds[0] : iut_s;
    params.fd_out = to_socket ?  iut_s : pipefds[1];
    params.len = SEND_SIZE;
    params.flags = set_move ? RPC_SPLICE_F_MOVE : 0;

    pco_iut->op = RCF_RPC_CALL;
    rpc_splice(pco_iut, params.fd_in, NULL, params.fd_out, NULL, params.len,
               params.flags);

    TAPI_WAIT_NETWORK;
    rcf_rpc_server_is_op_done(pco_iut, &done);

    if (done)
    {
        RPC_AWAIT_ERROR(pco_iut);
        rc = rpc_splice(pco_iut, params.fd_in, NULL, params.fd_out, NULL, params.len,
                        params.flags);
        if (rc >= 0)
        {
            TEST_VERDICT("Splice() function doesn't block %s",
                         rc == 0 ? "returning zero" :
                            (rc < SEND_SIZE ?
                                "moving less than expected" :
                                (rc == SEND_SIZE ?
                                    "but moves all the data" :
                                    "returning strange result")));
        }
        else
        {
            TEST_VERDICT("Splice() function unexpectedly terminated "
                         "with errno " RPC_ERROR_FMT " before the "
                         "signal was sent",
                         RPC_ERROR_ARGS(pco_iut));
        }
    }

    TEST_STEP("Send @c SIGUSR1 signal if @p additional is not @c "
              "second_signal or @c SIGUSR2 otherwise to @p pco_iut.");
    sockts_sig_send(pco_killer, &ctx);

    TAPI_WAIT_NETWORK;

    TEST_STEP("Check that the signal was received");
    sockts_sig_check_received(pco_killer, &ctx);
    if (!ctx.received)
        WARN_VERDICT("Signal is not received in time");

    TEST_STEP("Check that splice() is restarted when @c SA_RESTART flag was "
              "set for the first executed signal handler, and is not "
              "restarted otherwise.");
    rcf_rpc_server_is_op_done(pco_iut, &done);

    if (restart)
    {
        if (done)
        {
            RPC_AWAIT_ERROR(pco_iut);
            rc = rpc_splice(pco_iut, params.fd_in, NULL, params.fd_out,
                            NULL, params.len, params.flags);
            if (rc == -1)
            {
                TEST_VERDICT("splice() unexpectedly failed with errno %r",
                              RPC_ERRNO(pco_iut));
            }
            else
            {
                TEST_VERDICT("splice() unexpectedly succeeded");
            }
        }
    }
    else
    {
        if (!done)
        {
            ERROR_VERDICT("splice() was not interrupted");
        }
        else
        {
            RPC_AWAIT_ERROR(pco_iut);
            rc = rpc_splice(pco_iut, params.fd_in, NULL, params.fd_out, NULL, params.len,
                            params.flags);
            if (rc != -1)
                TEST_VERDICT("splice() unexpectedly successeed");

            CHECK_RPC_ERRNO(pco_iut, RPC_EINTR,
                            "Signal was sent when splice() was trying to move "
                            "data, it returns -1, but");

            pco_iut->op = RCF_RPC_CALL;
            rpc_splice(pco_iut, params.fd_in, NULL, params.fd_out, NULL, params.len,
                       params.flags);
        }
    }

    TEST_STEP("Unblock the @b splice() function call");
    if (to_socket)
    {
        in_rpcs = pco_iut_aux;
        in_fd = pipefds[1];
        out_rpcs = pco_tst;
        out_fd = tst_s;
    }
    else
    {
        in_rpcs = pco_tst;
        in_fd = tst_s;
        out_rpcs = pco_iut_aux;
        out_fd = pipefds[0];
    }

    if (block_on_read)
    {
        RPC_WRITE(sent_bytes, in_rpcs, in_fd, tx_buf, SEND_SIZE);
        total_expected_bytes += sent_bytes;
    }

    rpc_read_fd2te_dbuf(out_rpcs, out_fd, TAPI_WAIT_NETWORK_DELAY, 0, &read_data);
    te_dbuf_append(&payload, read_data.ptr + overfill_bytes,
                   read_data.len - overfill_bytes);

    TEST_STEP("If the signal was not handled before unblocking @b splice(), "
              "check that it is handled by now.");
    sockts_sig_check_received(pco_killer, &ctx);
    if (!ctx.received)
        TEST_VERDICT("Signal has not been received");

    TEST_STEP("Wait until non-blocking @b splice() is finished. @b splice() "
              "can move less data than there is in the FD buffer. To accept "
              "all the data, @b splice() must be called again");
    rc = rpc_splice(pco_iut, params.fd_in, NULL, params.fd_out, NULL, params.len,
                    params.flags);
    if (rc == -1)
    {
        TEST_VERDICT("splice() unexpectedly failed with errno %r",
                     RPC_ERRNO(pco_iut));
    }

    total_received_bytes += read_data.len;

    if (rc != SEND_SIZE)
    {
        rc2 = rpc_splice(pco_iut, params.fd_in, NULL, params.fd_out, NULL, params.len,
                        params.flags);
        if (rc2 != SEND_SIZE - rc)
            TEST_VERDICT("splice() returned unexpected value the second time");

        rc = rpc_read(out_rpcs, out_fd, rx_buf, SEND_SIZE);
        te_dbuf_append(&payload, rx_buf, rc);
        total_received_bytes += rc;
    }

    TEST_STEP("Check that total number of bytes sent is equal to received");
    RING("Total number of bytes sent %d; received %d", total_expected_bytes,
         total_received_bytes);
    if (total_received_bytes != total_expected_bytes)
    {
        TEST_VERDICT("The total number of bytes sent is not equal to the "
                     "number of bytes received");
    }

    CHECK_BUFS_EQUAL(tx_buf, payload.ptr, SEND_SIZE);

    TEST_STEP("At the end check that signal handlers did not change "
              "after receiving signals (unless @b sysv_signal() was used "
              "to set them, in which case they should be reset to "
              "default state).");

    sockts_sig_check_handlers_after_invoke(pco_iut, &ctx, NULL);

    TEST_STEP("Also check that calling @b siginterrupt() does not change "
              "signal handlers.");
    sockts_sig_siginterrupt(pco_iut, &ctx, 0);
    sockts_sig_check_handlers_after_invoke(pco_iut, &ctx,
                                           "After calling siginterrupt()");

    if (ctx.check_failed)
        TEST_STOP;
    TEST_SUCCESS;

cleanup:

    sockts_sig_cleanup(pco_iut, &state);

    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    if (to_socket)
    {
        rpc_close(pco_iut, pipefds[0]);
        rpc_close(pco_iut_aux, pipefds[1]);
    }
    else
    {
        rpc_close(pco_iut, pipefds[1]);
        rpc_close(pco_iut_aux, pipefds[0]);
    }

    CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_iut_aux));

    te_dbuf_free(&read_data);
    te_dbuf_free(&payload);

    TEST_END;
}
