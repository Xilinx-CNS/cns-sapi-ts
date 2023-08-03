/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Signals
 */

/** @page signal-read_interrupted_signal Check that reading function can be interrupted by signal.
 *
 * @objective Check that reading function returns @c -1, errno @c EINTR if
 *            it is interrupted by signal that is caught, and the next call
 *            returns success.
 *
 * @type conformance
 *
 * @reference @ref STEVENS
 *
 * @param env                   Testing environment:
 *                              - environments similar to
 *                                @ref arg_types_env_peer2peer,
 *                                @ref arg_types_env_peer2peer_lo,
 *                                and @ref arg_types_env_peer2peer_tst
 *                                having additional RPC server
 *                                @p pco_killer on IUT to send signals.
 * @param restart               Set or not set @c SA_RESTART for the first
 *                              caught signal
 * @param additional            Describe additional actions to be performed
 *                              in the test:
 *                              - @c - (none)
 *                              - @c second_signal (send @c SIGUSR2, its
 *                                handler should then send @c SIGUSR1)
 *                              - @c timeout (set timeout with @c SO_RCVTIMEO
 *                                for the reading function)
 * @param func                  Reading function to use:
 *                              - @ref arg_types_recv_func_with_sys
 * @param func_sig              Function used to install signal handler:
 *                              - @c sigaction
 *                              - @c sigaction_siginfo (@b sigaction() with
 *                                @c SA_SIGINFO flag)
 *                              - @c bsd_signal_pre_siginterrupt
 *                                (@b bsd_signal(), call @b siginterrupt()
 *                                 before it to configure restartability)
 *                              - @c bsd_signal_post_siginterrupt
 *                                (@b bsd_signal(), call @b siginterrupt()
 *                                 after it to configure restartability)
 * @param use_wildcard          If @c TRUE, bind IUT socket to wildcard
 *                              address.
 * @param signal_before_fd      Whether to set signal handler before
 *                              fd opening or after it
 * @param multithread           Whether to set signal handler from
 *                              different thread or not (if @c TRUE and
 *                              @p signal_before_fd is @c FALSE,
 *                              set it after start of blocking @p func call)
 * @param test_pipe             Whether to test pipe instead of socket or
 *                              not
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "signal/read_interrupted_signal"


#include "sockapi-test.h"
#include "ts_signal.h"

/* Maximum timeout for connect - 3 min */
#define READ_TIMEOUT_SEC (3 * 60)
#define BUF_SIZE 1024

static char rx_buf[BUF_SIZE];
static char tx_buf[BUF_SIZE];

struct read_params {
    rcf_rpc_server         *pco;

    int         sock;
    int         rc;
    rpc_recv_f  func;
};

void *
do_call_read(void *arg)
{
    struct read_params *params = (struct read_params *)arg;

    RPC_AWAIT_IUT_ERROR(params->pco);
    params->pco->timeout = READ_TIMEOUT_SEC * 1000;
    params->rc = params->func(params->pco, params->sock, rx_buf, BUF_SIZE, 0);

    return NULL;
}

#define CREATE_PIPE \
    do {                                                            \
        rpc_pipe(pco_iut, pipefds);                                 \
        iut_fd = pipefds[0];                                        \
        tst_fd = pipefds[1];                                        \
        rcf_rpc_server_fork_exec(pco_iut, "pco_tst", &pco_tst);     \
        rpc_close(pco_iut, tst_fd);                                 \
        rpc_close(pco_tst, iut_fd);                                 \
    } while (0)

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

    rpc_socket_type         sock_type;

    const char            *func_sig;

    te_bool     restart;
    const char *additional;
    te_bool     second_signal = FALSE;
    te_bool     has_timeout = FALSE;
    te_bool     test_pipe = FALSE;
    te_bool     is_restarted;
    rpc_recv_f  func;

    struct read_params    params;
    pthread_t             thread;
    te_bool               thread_started = FALSE;
    int                   rcv_bytes;

    te_bool         signal_before_fd;
    te_bool         multithread = FALSE;
    te_bool         use_wildcard = FALSE;

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
        TEST_GET_SOCK_TYPE(sock_type);
    }
    TEST_GET_BOOL_PARAM(restart);
    TEST_GET_STRING_PARAM(additional);
    TEST_GET_RECV_FUNC(func);
    TEST_GET_STRING_PARAM(func_sig);
    TEST_GET_BOOL_PARAM(signal_before_fd);
    TEST_GET_BOOL_PARAM(multithread);
    TEST_GET_BOOL_PARAM(use_wildcard);

    if (strcmp(additional, "second_signal") == 0)
        second_signal = TRUE;
    else if (strcmp(additional, "timeout") == 0)
        has_timeout = TRUE;

    /* Scenario */

    ctx.func_sig = func_sig;
    ctx.restart = restart;
    ctx.second_signal = second_signal;
    ctx.multithread = multithread;

    sockts_sig_save_state(pco_iut, &ctx, &init_state);

    if (multithread)
    {
       TEST_STEP("If @p multithread is @c TRUE, create IUT threads "
                 "@b pco_iut_handler (where to set signal handler) "
                 "and @p pco_iut_blocked (where to call blocking "
                 "read function).");
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

    if (!signal_before_fd)
    {
        TEST_STEP("If @p signal_before_fd is @c FALSE, establish TCP "
                  "connection between IUT and Tester (binding IUT socket "
                  "to wildcard address if @p use_wildcard is @c TRUE) or "
                  "create a pipe (if @p test_pipe is @c TRUE).");

        if (!test_pipe)
        {
            GEN_CONNECTION_WILD(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                                iut_addr, tst_addr, &iut_fd, &tst_fd,
                                use_wildcard);
        }
        else
        {
            CREATE_PIPE;
        }
    }

    if (!multithread || signal_before_fd)
    {
        TEST_STEP("If @p signal_before_fd is @c TRUE or @p multithread is "
                  "@c FALSE, configure signal handler(s) on "
                  "@b pco_iut_handler according to @p additional and "
                  "@p restart, using @p func_sig.");

        sockts_sig_register_handlers(pco_iut_handler, &ctx,
                                     "Setting tested handlers");
    }

    if (signal_before_fd)
    {
        TEST_STEP("If @p signal_before_fd is @c TRUE, establish TCP "
                  "connection between IUT and Tester (binding IUT socket "
                  "to wildcard address if @p use_wildcard is @c TRUE) or "
                  "create a pipe (if @p test_pipe is @c TRUE).");

        if (!test_pipe)
            GEN_CONNECTION_WILD(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                                iut_addr, tst_addr, &iut_fd, &tst_fd,
                                use_wildcard);
        else
            CREATE_PIPE;
    }

    if (has_timeout)
    {
        TEST_STEP("If @p additional is @c timeout, set @c SO_RCVTIMEO "
                  "option for the IUT socket.");

        tarpc_timeval t = {READ_TIMEOUT_SEC, 0};
        rpc_setsockopt(pco_iut, iut_fd, RPC_SO_RCVTIMEO, &t);
    }

    TEST_STEP("On @b pco_iut_blocked call @p func on the IUT socket; "
              "it should block.");
    params.pco = pco_iut_blocked;
    params.sock = iut_fd;
    params.func = func;
    pthread_create(&thread, NULL, do_call_read, &params);
    thread_started = TRUE;

    if (multithread && !signal_before_fd)
    {
        TEST_STEP("If @p signal_before_fd is @c FALSE and @p multithread "
                  "is @c TRUE, configure signal handler(s) on "
                  "@b pco_iut_handler according to @p additional and "
                  "@p restart, using @p func_sig.");

        sockts_sig_register_handlers(pco_iut_handler, &ctx,
                                     "Setting tested handlers");
    }

    TEST_STEP("Wait for a while and then send a signal to "
              "@b pco_iut_blocked (@c SIGUSR2 if @p additional is "
              "@c second_signal, @c SIGUSR1 otherwise).");
    TAPI_WAIT_NETWORK;
    sockts_sig_send(multithread ? pco_iut : pco_killer, &ctx);
    TAPI_WAIT_NETWORK;

    TEST_STEP("Check that @c SIGUSR1 signal was received on IUT.");
    sockts_sig_check_received(pco_killer, &ctx);
    if (!ctx.received)
        RING_VERDICT("Signal is not received in time");

    TEST_STEP("Write some data on peer to unblock @p func called on IUT.");
    RPC_WRITE(rc, pco_tst, tst_fd, tx_buf, BUF_SIZE);

    TEST_STEP("Check what previously called @p func on IUT returns. "
              "It should either succeed (if it is restarted) or fail "
              "with @c EINTR.");

    pthread_join(thread, NULL);
    thread_started = FALSE;
    if (params.rc == -1)
    {
        is_restarted = FALSE;
        CHECK_RPC_ERRNO(pco_iut_blocked, RPC_EINTR,
                        "Signal was sent when read() was trying to read "
                        "some data on IUT, it returns -1, but");
    }
    else
    {
        is_restarted = TRUE;
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

        RPC_AWAIT_ERROR(pco_iut_blocked);
        rcv_bytes = func(pco_iut_blocked, iut_fd, rx_buf, BUF_SIZE, 0);
        if (rcv_bytes < 0)
        {
            TEST_VERDICT("Receive function called the second time failed "
                         "with " RPC_ERROR_FMT,
                         RPC_ERROR_ARGS(pco_iut_blocked));
        }
        else if (rcv_bytes != BUF_SIZE)
        {
            ERROR("Receive function returned %d instead of %d",
                  rcv_bytes, BUF_SIZE);
            TEST_VERDICT("Receive function called the second time returned "
                         "unexpected number of bytes");
        }
    }

    TEST_STEP("Check that the first @p func call was or was not "
              "restarted as expected: it should have been restarted "
              "only if @p restart is @c TRUE and @p additional is not "
              "@c timeout.");

    TAPI_CHECK_RESTART_CORRECTNESS(Read, restart, is_restarted,
                                   has_timeout);
    if (!ctx.received)
        TEST_FAIL("Signal handler was postponed");

    TEST_STEP("At the end check that signal handlers did not change "
              "after receiving signals (unless @b sysv_signal() was used "
              "to set them, in which case they should be reset to "
              "default state).");
    TEST_STEP("Also check that calling @b siginterrupt() does not change "
              "signal handlers.");

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

    sockts_sig_cleanup(pco_iut, &init_state);

    if (multithread)
    {
        rcf_rpc_server_destroy(pco_iut_handler);
        rcf_rpc_server_destroy(pco_iut_blocked);
    }

    CLEANUP_RPC_CLOSE(pco_iut, iut_fd);
    CLEANUP_RPC_CLOSE(pco_tst, tst_fd);

    if (test_pipe && pco_tst != NULL)
        rcf_rpc_server_destroy(pco_tst);

    sockts_kill_zombie_stacks_if_many(pco_iut);

    TEST_END;
}
