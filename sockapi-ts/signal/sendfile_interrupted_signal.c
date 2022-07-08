/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Signals
 */

/** @page signal-sendfile_interrupted_signal Check that sendfile() function can be interrupted by signal.
 *
 * @objective Check that sendfile() function provides the following
 *            behaviour if signal has been catched by process:
 *             - it is interrupted by signal and returns -1, errno EINTR
 *               if SA_RESTART flag is cleared for current signal handler;
 *             - it continues processing if SA_RESTART flag is set
 *               (default behaviour).
 *
 * @type conformance
 *
 * @param env               Testing environment:
 *                          - environment similar to
 *                            @ref arg_types_env_peer2peer,
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
 *                            for @b sendfile())
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
 * @param file_length       File length:
 *                          - @c 512
 *                          - @c 524288 (random value large enough
 *                            to overfill socket buffers)
 * @param small_buffers     If @c TRUE, reduce send and receive buffer
 *                          sizes so that @b sendfile() call will block,
 *                          otherwise overfill buffers before calling
 *                          @b sendfile() for this purpose.
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "signal/sendfile_interrupted_signal"

#include "sockapi-test.h"
#include "sendfile_common.h"
#include "ts_signal.h"

#define TST_BUF_LEN       4096
#define WRITE_TIMEOUT_SEC (3 * 60)

struct sendfile_params {
    rcf_rpc_server         *pco;

    int         sock;
    int         rc;
    int         src;
    tarpc_off_t offset;
    size_t      count;
};

static te_bool thread_done = FALSE;

void *
do_call_sendfile(void *arg)
{
    struct sendfile_params *params = (struct sendfile_params *)arg;

    RPC_AWAIT_IUT_ERROR(params->pco);
    params->pco->timeout = WRITE_TIMEOUT_SEC * 1000;
    params->rc = rpc_sendfile(params->pco, params->sock, params->src,
                              &params->offset, params->count, FALSE);
    thread_done = TRUE;
    return NULL;
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server               *pco_iut = NULL;
    rcf_rpc_server               *pco_tst = NULL;
    rcf_rpc_server               *pco_killer = NULL;

    const char                   *func_sig;

    const struct sockaddr        *iut_addr;
    const struct sockaddr        *tst_addr;

    int                           iut_s = -1;
    int                           tst_s = -1;
    int                           src = -1;

    te_bool     small_buffers = FALSE;
    te_bool     restart = TRUE;
    te_bool     second_signal = FALSE;
    te_bool     has_timeout = FALSE;
    const char *additional;
    te_bool     is_restarted;

    /* buffers for test purposes */
    uint8_t                      *unblk_buf = NULL;
    int                           optval = -1;
    struct sendfile_params        params;
    pthread_t                     thread;
    const char                   *file_iut = "sendfile.pco_iut";
    te_bool                       created_iut = FALSE;
    int                           file_length;
    int                           buffs_sum_size;
    int                           bytes_received;
    int                           payload_received;
    uint64_t                      total_filled = 0;

    sockts_sig_ctx ctx = SOCKTS_SIG_CTX_INIT;
    sockts_sig_state state = SOCKTS_SIG_STATE_INIT;

    /* Test preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_PCO(pco_killer);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(restart);
    TEST_GET_INT_PARAM(file_length);
    TEST_GET_STRING_PARAM(func_sig);
    TEST_GET_STRING_PARAM(additional);
    TEST_GET_BOOL_PARAM(small_buffers);

    if (strcmp(additional, "second_signal") == 0)
        second_signal = TRUE;
    else if (strcmp(additional, "timeout") == 0)
        has_timeout = TRUE;

    ctx.func_sig = func_sig;
    ctx.restart = restart;
    ctx.second_signal = second_signal;

    CREATE_REMOTE_FILE(pco_iut->ta, file_iut, 'M', file_length);
    created_iut = TRUE;

    RPC_FOPEN_D(src, pco_iut, file_iut, RPC_O_RDONLY, 0);

    TEST_STEP("Configure signal handlers on IUT according to "
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

    TEST_STEP("Establish TCP connection between IUT and Tester. If "
              "@p small_buffers is @c TRUE, set small send "
              "buffer size on the IUT socket and small receive buffer "
              "size on the Tester socket.");

    if (small_buffers)
    {
        SOCKBUF_SET_GEN_CONN(pco_iut, pco_tst, iut_addr, tst_addr,
                             iut_s, tst_s, 1500, buffs_sum_size, 0);
        if (file_length < buffs_sum_size)
            TEST_FAIL("Failed to reduce socket buffers size to "
                      "reasonable value");
    }
    else
    {
        GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                       iut_addr, tst_addr, &iut_s, &tst_s);
    }

    if (has_timeout)
    {
        TEST_STEP("If @p additional is @c timeout, set @c SO_SNDTIMEO "
                  "option for the IUT socket.");
        tarpc_timeval t = {WRITE_TIMEOUT_SEC, 0};
        rpc_setsockopt(pco_iut, iut_s, RPC_SO_SNDTIMEO, &t);
    }

    /* Prepare receive buffer with length equal to half of SO_RCVBUF */
    rpc_getsockopt(pco_tst, tst_s, RPC_SO_RCVBUF, &optval);
    RING("'tst_s' socket receive buffer length is %d", optval);
    optval = optval / 2;
    unblk_buf = te_make_buf_by_len(optval);

    if (!small_buffers)
    {
        TEST_STEP("If @p small_buffers is @c FALSE, overfill send "
                  "buffer on the IUT socket.");
        rpc_overfill_buffers(pco_iut, iut_s, &total_filled);
        RING("To overfill the both send and received buffers "
             "%d bytes are written", (unsigned int)total_filled);
    }

    TEST_STEP("Call @b sendfile() on the IUT socket. It should block.");
    params.pco = pco_iut;
    params.sock = iut_s;
    params.src = src;
    params.offset = 0;
    params.count = file_length;
    pthread_create(&thread, NULL, do_call_sendfile, &params);

    TEST_STEP("Wait for a while and then send a signal to "
              "IUT process (@c SIGUSR2 if @p additional is "
              "@c second_signal, @c SIGUSR1 otherwise).");

    TAPI_WAIT_NETWORK;
    if (thread_done)
    {
        if (params.rc >= 0)
        {
            TEST_VERDICT("sendfile() doesn't block");
        }
        else
        {
            TEST_VERDICT("sendfile() unexpectedly terminated with "
                         "errno %r before the signal was sent",
                         RPC_ERRNO(pco_iut));
        }
    }

    sockts_sig_send(pco_killer, &ctx);
    TAPI_WAIT_NETWORK;

    TEST_STEP("Check that @c SIGUSR1 signal was received on IUT.");
    sockts_sig_check_received(pco_killer, &ctx);
    if (!ctx.received)
        RING_VERDICT("Signal is not received in time");

    /* Prepare conditions for unblocking of the checked function */
    /*
     * It's not sufficient to read only one portion of data.
     * E.g. Linux does not update it's window until big enough
     * amount of data is read.
     */
    TEST_STEP("Read all the available data on Tester to unblock "
              "@b sendfile() if it still blocks.");
    RECV_ALL_DATA(pco_tst, tst_s, bytes_received, unblk_buf, optval);

    TEST_STEP("Check what previously called @b sendfile() on IUT returns. "
              "It should either succeed (if it is restarted) or fail "
              "with @c EINTR.");

    pthread_join(thread, NULL);
    if (params.rc == -1)
    {
        is_restarted = FALSE;
        CHECK_RPC_ERRNO(pco_iut, RPC_EINTR,
                        "Signal was sent when write() was trying to write "
                        "some data on IUT, it returns -1, but");
    }
    else
    {
        is_restarted = TRUE;
        payload_received = small_buffers ? bytes_received :
                                           (bytes_received -
                                                 (int)total_filled);
        if (params.rc != payload_received)
            RING_VERDICT("Value returned by sendfile() is %s"
                         " than the number of bytes received",
                         params.rc > payload_received ? "greater" : "less");
    }

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

    if (small_buffers)
    {
        TEST_STEP("If @p small_buffers is @c TRUE, check that the "
                  "first @b sendfile() call was not interrupted.");

        if (!is_restarted)
            TEST_VERDICT("sendfile() unexpectedly failed with EINTR");
    }

    if (params.rc == -1)
    {
        TEST_STEP("If the first @b sendfile() call failed due to "
                  "interruption before, try to call it again on "
                  "IUT; now it should succeed.");

        params.offset = 0;
        params.count = file_length;
        pthread_create(&thread, NULL, do_call_sendfile, &params);
        RECV_ALL_DATA(pco_tst, tst_s, bytes_received, unblk_buf, optval);
        pthread_join(thread, NULL);

        if (params.rc != file_length)
        {
            ERROR("sendfile() called the second time returned %d "
                  "instead of %d", params.rc, file_length);
            TEST_VERDICT("sendfile() called the second time returned "
                         "unexpected value");
        }
    }

    if (!small_buffers)
    {
        TEST_STEP("If @p small_buffers is @c FALSE, check that the "
                  "first @b sendfile() call was interrupted if "
                  "@p restart is @c FALSE and succeeded otherwise.");

        TAPI_CHECK_RESTART_CORRECTNESS(Sendfile, restart, is_restarted,
                                       has_timeout);
    }

    TEST_STEP("At the end check that signal handlers did not change "
              "after receiving signals (unless @b sysv_signal() was used "
              "to set them, in which case they should be reset to "
              "default state).");
    sockts_sig_check_handlers_after_invoke(pco_iut, &ctx, NULL);

    if (ctx.check_failed)
        TEST_STOP;
    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    sockts_sig_cleanup(pco_iut, &state);

    if (created_iut)
        REMOVE_REMOTE_FILE(pco_iut->ta, file_iut);

    free(unblk_buf);

    TEST_END;
}
