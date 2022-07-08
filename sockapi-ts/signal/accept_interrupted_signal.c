/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Signals
 */

/** @page signal-accept_interrupted_signal Check that accept() can be interrupted by signal.
 *
 * @objective Check that @b accept() returns @c -1, errno @c EINTR if it is
 *            interrupted by signal that is caught, and the next @b accept()
 *            returns success.
 *
 * @type conformance
 *
 * @reference @ref STEVENS
 *
 * @param env           Testing environment:
 *                      - environments similar to @ref arg_types_env_peer2peer
 *                        and @ref arg_types_env_peer2peer_tst having
 *                        additional RPC server @p pco_killer on IUT to send
 *                        signals.
 * @param restart       Set or not set @c SA_RESTART for the first caught
 *                      signal
 * @param additional    Describe additinal actions to be performed in the
 *                      test:
 *                      - @c - (none)
 *                      - @c second_signal (send @c SIGUSR2, its handler
 *                        should then send @c SIGUSR1)
 *                      - @c timeout (set timeout with @c SO_RCVTIMEO
 *                        for @b accept())
 * @param func_sig      Function used to install signal handler:
 *                      - @c sigaction
 *                      - @c sigaction_siginfo (@b sigaction() with
 *                        @c SA_SIGINFO flag)
 *                      - @c bsd_signal_pre_siginterrupt (@b bsd_signal(),
 *                        call @b siginterrupt() before it to configure
 *                        restartability)
 *                      - @c bsd_signal_post_siginterrupt (@b bsd_signal(),
 *                        call @b siginterrupt() after it to configure
 *                        restartability)
 * @param use_wildcard  If @c TRUE, bind IUT socket to wildcard address.
 *
 * @par Scenario:
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "signal/accept_interrupted_signal"


#include "sockapi-test.h"
#include "ts_signal.h"

/* Maximum timeout for connect - 3 min */
#define ACCEPT_TIMEOUT_SEC (3 * 60)

struct accept_params {
    rcf_rpc_server         *pco;
    int                     sock;
    int                     rc;
};

void *
do_call_accept(void *arg)
{
    struct accept_params *params = (struct accept_params *)arg;

    RPC_AWAIT_IUT_ERROR(params->pco);
    params->pco->timeout = ACCEPT_TIMEOUT_SEC * 1000;
    params->rc = rpc_accept(params->pco, params->sock, NULL, NULL);
    return NULL;
}

int
main(int argc, char *argv[])
{
    int                     tst_s = -1;
    int                     iut_s = -1;
    int                     acc_s = -1;

    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_killer = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;

    const char            *func_sig;

    rpc_socket_domain domain;

    te_bool     restart;
    const char *additional;
    te_bool     second_signal = FALSE;
    te_bool     has_timeout = FALSE;
    te_bool     is_restarted;
    te_bool     use_wildcard = FALSE;

    struct accept_params params;
    pthread_t             thread;
    te_bool               thread_started = FALSE;

    sockts_sig_ctx ctx = SOCKTS_SIG_CTX_INIT;
    sockts_sig_state state = SOCKTS_SIG_STATE_INIT;

    /* Test preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_killer);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_BOOL_PARAM(restart);
    TEST_GET_STRING_PARAM(additional);
    TEST_GET_STRING_PARAM(func_sig);
    TEST_GET_BOOL_PARAM(use_wildcard);

    domain = rpc_socket_domain_by_addr(iut_addr);

    if (strcmp(additional, "second_signal") == 0)
        second_signal = TRUE;
    else if (strcmp(additional, "timeout") == 0)
        has_timeout = TRUE;

    /* Scenario */

    TEST_STEP("Configure signal handlers on IUT according to "
              "@p restart and @p additional.");
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

    ctx.func_sig = func_sig;
    ctx.restart = restart;
    ctx.second_signal = second_signal;

    sockts_sig_save_state(pco_iut, &ctx, &state);
    sockts_sig_register_handlers(pco_iut, &ctx, NULL);
    sockts_sig_set_target(pco_iut, &ctx);

    TEST_STEP("Create a TCP socket on Tester, bind it to @p tst_addr.");
    tst_s = rpc_socket(pco_tst, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr);

    TEST_STEP("Create a TCP socket on IUT, bind it to @p iut_addr "
              "(with address set to wildcard if @p use_wildcard is "
              "@c TRUE).");
    iut_s = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_STREAM,
                                       RPC_PROTO_DEF, use_wildcard, FALSE,
                                       iut_addr);
    if (has_timeout)
    {
        TEST_STEP("If @p additional is @c timeout, set @c SO_RCVTIMEO "
                  "option for the IUT socket.");
        tarpc_timeval t = {ACCEPT_TIMEOUT_SEC, 0};
        rpc_setsockopt(pco_iut, iut_s, RPC_SO_RCVTIMEO, &t);
    }

    TEST_STEP("Call @b listen() on the IUT socket.");
    rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);

    TEST_STEP("Call blocking @b accept() on IUT.");
    params.pco = pco_iut;
    params.sock = iut_s;
    pthread_create(&thread, NULL, do_call_accept, &params);
    thread_started = TRUE;

    TEST_STEP("Wait for a while and then send a signal to "
              "IUT process (@c SIGUSR2 if @p additional is "
              "@c second_signal, @c SIGUSR1 otherwise).");
    TAPI_WAIT_NETWORK;
    sockts_sig_send(pco_killer, &ctx);
    TAPI_WAIT_NETWORK;

    TEST_STEP("Check that @c SIGUSR1 signal was received on IUT.");
    sockts_sig_check_received(pco_killer, &ctx);
    if (!ctx.received)
        RING_VERDICT("Signal is not received in time");

    TEST_STEP("Call @b connect() to @p iut_addr on Tester.");
    rpc_connect(pco_tst, tst_s, iut_addr);

    TEST_STEP("Check what previously called @b accept() on IUT returns. "
              "It should either succeed (if it is restarted) or fail "
              "with @c EINTR.");

    pthread_join(thread, NULL);
    thread_started = FALSE;
    if (params.rc == -1)
    {
        is_restarted = FALSE;
        CHECK_RPC_ERRNO(pco_iut, RPC_EINTR,
                        "Signal was sent when accept() was trying to "
                        "establish a new TCP connection, it returns -1, "
                        "but");
    }
    else
    {
        acc_s = params.rc;
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

        sockts_sig_check_siginfo(pco_iut, &ctx);
    }

    if (acc_s == -1)
    {
        TEST_STEP("if @b accept() was interrupted, call it the "
                  "second time on IUT and check that it succeeds now.");
        RPC_AWAIT_IUT_ERROR(pco_iut);
        acc_s = rpc_accept(pco_iut, iut_s, NULL, NULL);
        if (acc_s < 0)
            TEST_VERDICT("accept() call the second time returned %d",
                         acc_s);
    }

    TEST_STEP("Check that the first @b accept() call was or was not "
              "restarted as expected: it should have been restarted "
              "only if @p restart is @c TRUE and @p additional is not "
              "@c timeout.");
    TAPI_CHECK_RESTART_CORRECTNESS(Accept, restart, is_restarted,
                                   has_timeout);
    if (!ctx.received)
        TEST_FAIL("Signal handler was postponed");

    TEST_STEP("At the end check that signal handlers did not change "
              "after receiving signals (unless @b sysv_signal() was used "
              "to set them, in which case they should be reset to "
              "default state).");
    sockts_sig_check_handlers_after_invoke(pco_iut, &ctx, NULL);

    if (ctx.check_failed)
        TEST_STOP;
    TEST_SUCCESS;

cleanup:

    if (thread_started)
        pthread_join(thread, NULL);

    sockts_sig_cleanup(pco_iut, &state);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, acc_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
