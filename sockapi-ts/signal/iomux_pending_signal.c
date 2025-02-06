/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Signals + Socket API
 *
 * $Id$
 */

/** @page signal-iomux_pending_signal Check iomux behaviour when both an event and a signal are ready before the call.
 *
 * @objective Check that @b pselect(), @b ppoll(), @b epoll_pwait() and
 *            @b epoll_pwait2()
 *            behave correctly when their signal mask unblocks some pending
 *            signal and also an event is ready by the time of a call.
 *
 * @type conformance
 *
 * @param pco_iut       PCO with IUT
 * @param pco_killer    PCO on the same host as @b pco_iut
 * @param pco_tst       Tester PCO
 * @param iut_addr      Network address on IUT
 * @param tst_addr      Network address on Tester
 * @param sock_type     Socket type used in the test
 * @param iomux         I/O multiplexer to use
 * @param use_epollet   Set @c EPOLLET flag (makes sense for
 *                      @b epoll_pwait() and @b epoll_pwait2() only)
 * @param func_sig      Function used to register a signal handler
 * @param sig_to_send   Signal to be sent
 * @param timeout       Timeout for @p iomux (in seconds; -1 means
 *                      not using timeout)
 *
 * @par Scenario:
 *
 * -# Block signal @p sig_to_send for @p pco_iut.
 * -# Send signal @p sig_to_send to @p pco_iut.
 * -# Call @p iomux function with a signal mask unblocking
 *    @p sig_to_send, waiting for an event on a socket on which
 *    this event already happened.
 * -# Check what @p iomux function returns.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "signal/iomux_pending_signal"

#include "sockapi-test.h"
#include "ts_signal.h"
#include "iomux.h"

#define DATA_LEN 1024
#define MSG_LEN 100

#define CHECK_IUT_SIGMASK(msg_...) \
    do {                                                            \
        rpc_sigprocmask(pco_iut, RPC_SIG_BLOCK,                     \
                        RPC_NULL, sigmask_after_iomux);             \
                                                                    \
        if (rpc_sigset_cmp(pco_iut, sigmask_after_iomux,            \
                           pco_sigmask) != 0)                       \
        {                                                           \
            if (rpc_sigset_cmp(pco_iut, sigmask_after_iomux,        \
                               iomux_sigmask) == 0)                 \
                ERROR_VERDICT("%ssigmask was not restored", msg_);  \
            else                                                    \
                ERROR_VERDICT("%ssigmask was not restored "         \
                              "correctly", msg_);                   \
            is_failed = TRUE;                                       \
        }                                                           \
    } while (0)

int
main(int argc, char *argv[])
{
    rcf_rpc_server  *pco_iut = NULL;
    rcf_rpc_server  *pco_killer = NULL;
    rcf_rpc_server  *pco_tst = NULL;

    iomux_call_type         iomux = IC_UNKNOWN;
    iomux_evt_fd            evt;
    struct rpc_epoll_event  epoll_evt;
    int                     epfd = -1;
    int                     timeout = -1;
    tarpc_timeval           timeval;
    te_bool                 use_epollet = FALSE;
    te_bool                 use_wildcard = FALSE;

    const struct sockaddr  *iut_addr, *tst_addr;
    rpc_socket_type         sock_type;

    const char             *func_sig;
    DEFINE_RPC_STRUCT_SIGACTION(old_sig_act);
    te_bool                 restore_sig_handler = FALSE;
    te_bool                 restore_sig_mask = FALSE;
    rpc_sigset_p            pco_sigmask = RPC_NULL;
    rpc_sigset_p            saved_sigmask = RPC_NULL;
    rpc_sigset_p            sigmask_after_iomux = RPC_NULL;
    rpc_sigset_p            iomux_sigmask = RPC_NULL;
    rpc_sigset_p            received_set = RPC_NULL;
    rpc_signum              sig_to_send;
    pid_t                   pco_iut_pid;
    te_bool                 was_handled = FALSE;
    int                     iut_errno = 0;

    int         tst_s = -1;
    int         iut_s = -1;
    te_bool     is_failed = FALSE;

    uint8_t     rx_buf[DATA_LEN];
    uint8_t     tx_buf[DATA_LEN];
    char        msg[MSG_LEN];

    tarpc_siginfo_t       siginfo;

    te_bool               third_call = FALSE;

    /* Test preambule */

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_killer);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_BOOL_PARAM(use_epollet);
    TEST_GET_BOOL_PARAM(use_wildcard);
    TEST_GET_STRING_PARAM(func_sig);
    TEST_GET_SIGNUM(sig_to_send);
    TEST_GET_INT_PARAM(timeout);

    /* Scenario */

    GEN_CONNECTION_WILD(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                        iut_addr, tst_addr, &iut_s, &tst_s, use_wildcard);
    te_fill_buf(tx_buf, DATA_LEN);

    /* Register signal handler */
    tapi_set_sighandler(pco_iut, sig_to_send,
                        (strcmp(func_sig, "sigaction_siginfo") == 0) ?
                            SIGNAL_REGISTRAR_SIGINFO :
                            SIGNAL_REGISTRAR, func_sig,
                        FALSE, &old_sig_act);
    restore_sig_handler = TRUE;

    pco_sigmask = rpc_sigset_new(pco_iut);
    rpc_sigemptyset(pco_iut, pco_sigmask);
    rpc_sigaddset(pco_iut, pco_sigmask, sig_to_send);
    saved_sigmask = rpc_sigset_new(pco_iut);
    sigmask_after_iomux = rpc_sigset_new(pco_iut);

    rpc_sigprocmask(pco_iut, RPC_SIG_BLOCK, pco_sigmask, saved_sigmask);
    restore_sig_mask = TRUE;

    iomux_sigmask = rpc_sigset_new(pco_iut);
    rpc_sigemptyset(pco_iut, iomux_sigmask);

    if (!use_epollet)
    {
        memset(&evt, 0, sizeof(evt));
        evt.fd = iut_s;
        evt.events = EVT_RD;
    }
    else
    {
        epfd = rpc_epoll_create(pco_iut, 1);
        rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_ADD,
                             iut_s, RPC_EPOLLIN | RPC_EPOLLET);
    }

    timeval.tv_sec = timeout;
    timeval.tv_usec = 0;

    rpc_send(pco_tst, tst_s, tx_buf, DATA_LEN, 0);
    TAPI_WAIT_NETWORK;

    received_set = rpc_sigreceived(pco_iut);
    pco_iut_pid = rpc_getpid(pco_iut);
    rpc_kill(pco_killer, pco_iut_pid, sig_to_send);
    TAPI_WAIT_NETWORK;

    rc = rpc_sigismember(pco_iut, received_set, sig_to_send);
    if (rc != FALSE)
        TEST_FAIL("Blocked signal %s was received",
                  signum_rpc2str(sig_to_send));

    RPC_AWAIT_IUT_ERROR(pco_iut);
    if (!use_epollet)
        rc = iomux_call_signal(iomux, pco_iut, &evt, 1, &timeval,
                               iomux_sigmask);
    else
    {
        rc = iomux_epoll_pwait_call(iomux, pco_iut, epfd, &epoll_evt, 1,
                                    TE_SEC2MS(timeout), iomux_sigmask);
        if (rc == 1)
            evt.revents = tapi_iomux_epoll_to_evt(epoll_evt.events);
    }

    iut_errno = RPC_ERRNO(pco_iut);
    snprintf(msg, MSG_LEN, "The first %s() call: ",
             iomux_call_en2str(iomux));
    CHECK_IUT_SIGMASK(msg);
    rpc_sigprocmask(pco_iut, RPC_SIG_BLOCK, RPC_NULL, pco_sigmask);

    if (rc == -1)
        RING_VERDICT("The first %s() call failed with errno %s",
                     iomux_call_en2str(iomux),
                     errno_rpc2str(iut_errno));
    else if (rc != 1 && rc != 0)
    {
        ERROR_VERDICT("The first %s() call returned strange result",
                      iomux_call_en2str(iomux));
        is_failed = TRUE;
    }
    else
    {
        if (rc == 0)
        {
            ERROR_VERDICT("The first %s() call returned 0",
                          iomux_call_en2str(iomux));
            is_failed = TRUE;
        }
        else if (evt.revents != EVT_RD)
            RING_VERDICT("The first %s() call successeed returning "
                         "events %s",
                         iomux_call_en2str(iomux),
                         iomux_event_rpc2str(evt.revents));

        rc = rpc_sigismember(pco_iut, received_set, sig_to_send);
        if (rc)
        {
            ERROR_VERDICT("The first %s() call was not interrupted "
                          "but signal was handled",
                          iomux_call_en2str(iomux));
            is_failed = TRUE;
            was_handled = TRUE;
            if (strcmp(func_sig, "sigaction_siginfo") == 0)
            {
                rpc_siginfo_received(pco_iut, &siginfo);
                if (siginfo.sig_pid != rpc_getpid(pco_killer) ||
                siginfo.sig_uid != rpc_getuid(pco_killer))
                RING_VERDICT("siginfo structure is corrupted.");
            }
        }
        else
        {
            if (!use_epollet)
            {
                rc = rpc_recv(pco_iut, iut_s, rx_buf, DATA_LEN, 0);
                if (rc != DATA_LEN || memcmp(tx_buf, rx_buf, DATA_LEN) != 0)
                    TEST_FAIL("Data was not received correctly");
            }

            RPC_AWAIT_IUT_ERROR(pco_iut);
            if (!use_epollet)
                rc = iomux_call_signal(iomux, pco_iut, &evt, 1, &timeval,
                                       iomux_sigmask);
            else
                rc = iomux_epoll_pwait_call(iomux, pco_iut, epfd, &epoll_evt, 1,
                                            TE_SEC2MS(timeout), iomux_sigmask);

            iut_errno = RPC_ERRNO(pco_iut);
            snprintf(msg, MSG_LEN, "The second %s() call: ",
                     iomux_call_en2str(iomux));
            CHECK_IUT_SIGMASK(msg);

            if (rc == 1 && use_epollet)
            {
                third_call = TRUE;
                RING_VERDICT("The second %s() call returned %d "
                              "instead of -1",
                              iomux_call_en2str(iomux), rc);
                RPC_AWAIT_IUT_ERROR(pco_iut);
                rc = iomux_epoll_pwait_call(iomux, pco_iut, epfd, &epoll_evt, 1,
                                            TE_SEC2MS(timeout), iomux_sigmask);
                iut_errno = RPC_ERRNO(pco_iut);
            }
            if (rc != -1)
            {
                ERROR_VERDICT("The %s %s() call returned %d "
                              "instead of -1",
                              (third_call) ? "third" : "second",
                              iomux_call_en2str(iomux), rc);
                is_failed = TRUE;
            }
            else if (iut_errno != RPC_EINTR)
            {
                ERROR_VERDICT("The %s %s() call returned unexpected "
                              "errno %s",
                              (third_call) ? "third" : "second",
                              iomux_call_en2str(iomux),
                              errno_rpc2str(iut_errno));
                is_failed = TRUE;
            }
        }
    }

    if (!was_handled)
    {
        rc = rpc_sigismember(pco_iut, received_set, sig_to_send);
        if (!rc)
            RING_VERDICT("Signal unblocked when calling %s() "
                         "was not handled",
                         iomux_call_en2str(iomux));
        else if (strcmp(func_sig, "sigaction_siginfo") == 0)
        {
            rpc_siginfo_received(pco_iut, &siginfo);
            if (siginfo.sig_pid != rpc_getpid(pco_killer) ||
            siginfo.sig_uid != rpc_getuid(pco_killer))
            RING_VERDICT("siginfo structure is corrupted.");
        }
    }

    if (is_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, epfd);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    if (restore_sig_mask)
        rpc_sigprocmask(pco_iut, RPC_SIG_SETMASK, saved_sigmask, RPC_NULL);

    if (restore_sig_handler)
        CLEANUP_RPC_SIGACTION(pco_iut, sig_to_send, &old_sig_act,
                              (strcmp(func_sig, "sigaction_siginfo") == 0) ?
                                SIGNAL_REGISTRAR_SIGINFO :
                                SIGNAL_REGISTRAR);

    rpc_signal_registrar_cleanup(pco_iut);

    if (saved_sigmask != RPC_NULL)
        rpc_sigset_delete(pco_iut, saved_sigmask);
    if (iomux_sigmask != RPC_NULL)
        rpc_sigset_delete(pco_iut, iomux_sigmask);
    if (pco_sigmask != RPC_NULL)
        rpc_sigset_delete(pco_iut, pco_sigmask);
    if (sigmask_after_iomux != RPC_NULL)
        rpc_sigset_delete(pco_iut, sigmask_after_iomux);

    TEST_END;
}
