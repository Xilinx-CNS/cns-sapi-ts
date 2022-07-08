/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Signals
 */

/** @page signal-write_interrupted_signal Check that write() can be interrupted by signal.
 *
 * @objective Check that writing function returns @c -1, errno @c EINTR
 *            if it is interrupted by signal that is caught, and the next
 *            function call returns success.
 *
 * @type conformance
 *
 * @reference @ref STEVENS
 *
 * @param env               Testing environment:
 *                          - environments similar to
 *                            @ref arg_types_env_peer2peer,
 *                            @ref arg_types_env_peer2peer_lo,
 *                            and @ref arg_types_env_peer2peer_tst
 *                            having additional RPC server
 *                            @p pco_killer on IUT to send signals.
 * @param restart           Set or not set @c SA_RESTART for the first
 *                          caught signal
 * @param additional        Describe additional actions to be performed
 *                          in the test:
 *                          - @c - (none)
 *                          - @c second_signal (send @c SIGUSR2, its
 *                            handler should then send @c SIGUSR1)
 *                          - @c timeout (set timeout with @c SO_SNDTIMEO
 *                            for the writing function)
 * @param func              Writing function to use:
 *                          - @ref arg_types_send_func_with_sys
 * @param func_sig          Function used to install signal handler:
 *                          - @c sigaction
 *                          - @c sigaction_siginfo (@b sigaction() with
 *                            @c SA_SIGINFO flag)
 *                          - @c bsd_signal_pre_siginterrupt
 *                            (@b bsd_signal(), call @b siginterrupt()
 *                             before it to configure restartability)
 *                          - @c bsd_signal_post_siginterrupt
 *                            (@b bsd_signal(), call @b siginterrupt()
 *                             after it to configure restartability)
 * @param small_buffers     If @c TRUE, reduce send and receive buffer
 *                          sizes so that @p func call will block,
 *                          otherwise overfill buffers before calling
 *                          @p func for this purpose.
 * @param multithread       Whether to set signal handler from
 *                          different thread or not
 * @param test_pipe         Whether to test pipe instead of sockets or not
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "signal/write_interrupted_signal"

#include "sockapi-test.h"
#include "ts_signal.h"

#define WRITE_TIMEOUT_SEC (20)
#define SEND_SIZE 1024
#define SMALL_SOCK_BUF 2000

static int buffs_sum_size = 0;

static int   buf_size = 0;
static char *rx_buf = NULL;
static char *tx_buf = NULL;

struct write_params {
    rcf_rpc_server         *pco;

    int         sock;
    int         rc;
    rpc_send_f  func;
};

static te_bool small_buffers = FALSE;
static te_bool thread_done = FALSE;

#define BYTES_TO_SEND \
      (small_buffers ? (buffs_sum_size * 2) : SEND_SIZE)

void *
do_call_write(void *arg)
{
    struct write_params *params = (struct write_params *)arg;

    RPC_AWAIT_ERROR(params->pco);
    params->pco->timeout = WRITE_TIMEOUT_SEC * 1000;
    params->rc = params->func(params->pco, params->sock, tx_buf,
                              BYTES_TO_SEND, 0);

    thread_done = TRUE;
    return NULL;
}

int
main(int argc, char *argv[])
{
    int                     tst_fd = -1;
    int                     iut_fd = -1;
    int                     pipefds[2] = {-1, -1};

    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_iut_handler = NULL;
    rcf_rpc_server         *pco_iut_blocked = NULL;
    rcf_rpc_server         *pco_killer = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    const char            *func_sig;

    te_bool     restart;
    const char *additional;
    te_bool     second_signal = FALSE;
    te_bool     has_timeout = FALSE;
    te_bool     is_restarted;
    rpc_send_f  func;

    struct write_params   params;
    pthread_t             thread;
    te_bool               thread_started = FALSE;
    uint64_t              total_bytes;
    int                   bytes_received;
    int                   additional_received;
    int                   payload_received;
    te_bool               iut_timed_out = FALSE;
    te_bool               multithread = FALSE;
    te_bool               test_pipe = FALSE;

    sockts_sig_ctx ctx = SOCKTS_SIG_CTX_INIT;
    sockts_sig_state init_state = SOCKTS_SIG_STATE_INIT;

    /* Test preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_killer);
    TEST_GET_BOOL_PARAM(test_pipe);
    if (!test_pipe)
    {
        TEST_GET_PCO(pco_tst);
        TEST_GET_ADDR(pco_tst, tst_addr);
        TEST_GET_ADDR(pco_iut, iut_addr);
    }
    TEST_GET_BOOL_PARAM(restart);
    TEST_GET_STRING_PARAM(additional);
    TEST_GET_BOOL_PARAM(small_buffers);
    TEST_GET_SEND_FUNC(func);
    TEST_GET_STRING_PARAM(func_sig);
    TEST_GET_BOOL_PARAM(multithread);

    if (strcmp(rpc_send_func_name(func), "template_send") == 0)
        sockts_kill_zombie_stacks(pco_iut);

    if (strcmp(additional, "second_signal") == 0)
        second_signal = TRUE;
    else if (strcmp(additional, "timeout") == 0)
        has_timeout = TRUE;

    ctx.func_sig = func_sig;
    ctx.restart = restart;
    ctx.second_signal = second_signal;
    ctx.multithread = multithread;

    /* Scenario */

    sockts_sig_save_state(pco_iut, &ctx, &init_state);

    if (multithread)
    {
       TEST_STEP("If @p multithread is @c TRUE, create IUT threads "
                 "@b pco_iut_handler (where to set signal handler) "
                 "and @p pco_iut_blocked (where to call blocking "
                 "writing function).");

        rcf_rpc_server_thread_create(pco_iut, "iut_handler",
                                     &pco_iut_handler);
        rcf_rpc_server_thread_create(pco_iut, "iut_blocked",
                                     &pco_iut_blocked);

        sockts_sig_set_ignore(pco_iut, &ctx, "Setting SIG_IGN handlers");
    }
    else
    {
        TEST_STEP("If @p multithread is @c FALSE, let "
                  "@b pco_iut_blocked = @b pco_iut_handler = @p pco_iut.");
        pco_iut_blocked = pco_iut_handler = pco_iut;
    }

    sockts_sig_set_target(pco_iut_blocked, &ctx);

    if (!multithread)
    {
        TEST_STEP("If @p multithread is @c FALSE, configure signal "
                  "handler(s) on @b pco_iut_handler according to "
                  "@p additional and @p restart, using @p func_sig.");

        sockts_sig_register_handlers(pco_iut_handler, &ctx,
                                     "Setting tested handlers");
    }

    TEST_STEP("Create a pipe (if @p test_pipe is @c TRUE) or "
              "establish TCP connection between IUT and Tester "
              "(if @p test_pipe is @c FALSE).");

    if (test_pipe)
    {
        rpc_pipe(pco_iut, pipefds);
        iut_fd = pipefds[1];
        tst_fd = pipefds[0];
        rcf_rpc_server_fork_exec(pco_iut, "pco_tst", &pco_tst);
        rpc_close(pco_iut, tst_fd);
        rpc_close(pco_tst, iut_fd);
    }
    else if (small_buffers)
    {
        TEST_SUBSTEP("If @p small_buffers is @c TRUE, set small "
                     "send buffer size for IUT socket and small "
                     "receive buffer size for Tester socket.");
        SOCKBUF_SET_GEN_CONN(pco_iut, pco_tst, iut_addr, tst_addr,
                             iut_fd, tst_fd, SMALL_SOCK_BUF,
                             buffs_sum_size, SEND_SIZE);
    }
    else
    {
        GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                       iut_addr, tst_addr, &iut_fd, &tst_fd);
    }

    buf_size = BYTES_TO_SEND * 1.5;
    tx_buf = calloc(1, buf_size);
    rx_buf = calloc(1, buf_size);

    if (has_timeout)
    {
        TEST_STEP("If @p additional is @c timeout, set @c SO_SNDTIMEO "
                  "option for the IUT socket.");

        tarpc_timeval t = {WRITE_TIMEOUT_SEC, 0};
        rpc_setsockopt(pco_iut, iut_fd, RPC_SO_SNDTIMEO, &t);
    }

    if (!small_buffers)
    {
        TEST_STEP("If @p small_buffers is @c FALSE, overfill send "
                  "buffer on IUT.");

        if (!test_pipe)
            rpc_overfill_buffers(pco_iut, iut_fd, &total_bytes);
        else
            rpc_overfill_fd(pco_iut, iut_fd, &total_bytes);
    }

    TEST_STEP("Call @p func on @b pco_iut_blocked to send some data. "
              "It should block.");
    params.pco = pco_iut_blocked;
    params.sock = iut_fd;
    params.func = func;
    pthread_create(&thread, NULL, do_call_write, &params);
    thread_started = TRUE;

    if (multithread)
    {
        TEST_STEP("If @p multithread is @c TRUE, configure signal "
                  "handler(s) on @p pco_iut_handler according to "
                  "@p additional and @p restart, using @p func_sig.");
        sockts_sig_register_handlers(pco_iut_handler, &ctx,
                                     "Setting tested handlers");
    }

    TEST_STEP("Wait for a while and then send a signal to "
              "@b pco_iut_blocked (@c SIGUSR2 if @p additional is "
              "@c second_signal, @c SIGUSR1 otherwise).");

    TAPI_WAIT_NETWORK;
    if (thread_done)
    {
        if (params.rc >= 0)
        {
            TEST_VERDICT("Writing function doesn't block %s",
                         params.rc == 0 ? "returning zero" :
                            (params.rc < BYTES_TO_SEND ?
                                "sending less than expected" :
                                (params.rc == BYTES_TO_SEND ?
                                    "but sends all the data" :
                                    "returning strange result")));
        }
        else
        {
            TEST_VERDICT("Writing function unexpectedly terminated "
                         "with errno " RPC_ERROR_FMT " before the "
                         "signal was sent",
                         RPC_ERROR_ARGS(pco_iut_blocked));
        }
    }

    sockts_sig_send(multithread ? pco_iut : pco_killer, &ctx);
    TAPI_WAIT_NETWORK;

    TEST_STEP("Check that @c SIGUSR1 signal was received on IUT.");
    sockts_sig_check_received(pco_killer, &ctx);
    if (!ctx.received)
        RING_VERDICT("Signal is not received in time");

    TEST_STEP("Receive all the available data on Tester.");
    RECV_ALL_DATA(pco_tst, tst_fd, bytes_received, rx_buf, buf_size);

    TEST_STEP("Check what previously called @p func on IUT returns. "
              "It should either succeed (if it is restarted) or fail "
              "with @c EINTR.");

    pthread_join(thread, NULL);
    thread_started = FALSE;
    if (params.rc == -1)
    {
        is_restarted = FALSE;
        if (TE_RC_GET_ERROR(RPC_ERRNO(pco_iut_blocked)) == TE_ERPCTIMEOUT)
        {
            iut_timed_out = TRUE;
            TEST_VERDICT("Writing function timed out");
        }

        CHECK_RPC_ERRNO(pco_iut_blocked, RPC_EINTR,
                        "Signal was sent when writing function was trying "
                        "to write some data on IUT, it returns -1, but");
    }
    else
    {
        is_restarted = TRUE;
        payload_received = (small_buffers ? bytes_received :
                                                  (bytes_received -
                                                     (int)total_bytes));
        if (params.rc > payload_received)
        {
            RING("Trying to receive lost data");
            RECV_ALL_DATA(pco_tst, tst_fd, additional_received, rx_buf,
                          buf_size);
            payload_received += additional_received;
        }

        if (params.rc != payload_received)
            RING_VERDICT("Value returned by writing function "
                         "is %s than the number of bytes received",
                         params.rc > payload_received ?
                                                "greater" : "less");
    }

    TEST_STEP("Check that @c SIGUSR1 signal was received on IUT by now "
              "if it was not received before.");

    sockts_sig_check_received(pco_killer, &ctx);
    if (!ctx.received)
        TEST_VERDICT("Signal has not been received");

    if (strcmp(func_sig, "sigaction_siginfo") == 0)
    {
        TEST_STEP("If @p func_sig is @c sigaction_siginfo, check "
                  "that siginfo structure received by @c SIGUSR1 "
                  "handler contains correct @b sig_pid and @b sig_uid.");

        sockts_sig_check_siginfo(pco_iut_blocked, &ctx);
    }

    if (params.rc == -1)
    {
        TEST_STEP("If @p func call failed due to interruption before, try "
                  "to call it again on @b pco_iut_blocked; now it should "
                  "succeed.");

        pthread_create(&thread, NULL, do_call_write, &params);
        thread_started = TRUE;
        RECV_ALL_DATA(pco_tst, tst_fd, bytes_received, rx_buf, buf_size);
        pthread_join(thread, NULL);
        thread_started = FALSE;

        if (params.rc < 0)
        {
            TEST_VERDICT("Writing function called the second time failed "
                         "with " RPC_ERROR_FMT, RPC_ERROR_ARGS(params.pco));
        }
        else if (params.rc != BYTES_TO_SEND)
        {
            TEST_VERDICT("Writing function called the second time returned "
                         "unexpected value");
        }
    }

    if (small_buffers)
    {
        TEST_STEP("If @p small_buffers is @c TRUE, check that the first "
                  "@p func call succeeded.");

        if (!is_restarted)
            TEST_VERDICT("Sending function unexpectedly failed with EINTR");
    }
    else
    {
        TEST_STEP("If @p small_buffers is @c FALSE, check that the first "
                  "@p func call was restarted if @p restart is @c TRUE, "
                  "and interrupted if @p restart is @c FALSE.");
        TAPI_CHECK_RESTART_CORRECTNESS(Write, restart, is_restarted,
                                       has_timeout);
    }

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

    if (thread_started)
    {
        rcf_rpc_server_restart(pco_iut_blocked);
        pthread_join(thread, NULL);
    }

    if (multithread)
    {
        rcf_rpc_server_destroy(pco_iut_handler);
        rcf_rpc_server_destroy(pco_iut_blocked);
    }

    if (!iut_timed_out)
    {
        sockts_sig_cleanup(pco_iut, &init_state);

        CLEANUP_RPC_CLOSE(pco_iut, iut_fd);
    }

    CLEANUP_RPC_CLOSE(pco_tst, tst_fd);

    if (test_pipe && pco_tst != NULL)
        rcf_rpc_server_destroy(pco_tst);

    free(tx_buf);
    free(rx_buf);

    TEST_END;
}
