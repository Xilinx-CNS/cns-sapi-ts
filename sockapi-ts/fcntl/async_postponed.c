/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * IOCTL Requests
 *
 * $Id$
 */

/** @page fcntl-async_postponed Checking correctness of siginfo for posponed signals
 *
 * @objective Check that signal sending enabled by @c O_ASYNC request
 *            sends the signal with correct siginfo in case when the
 *            signal is postponed.
 *
 * @type conformance
 *
 * @param pco_iut             PCO on IUT
 * @param pco_tst             PCO on TESTER
 * @param sock_type           Type of socket to be used (@c SOCK_STREAM or
 *                            @c SOCK_DGRAM)
 * @param use_fioasync        Use @c FIOASYNC or @c SET_FL at first
 * @param use_siocspgrp       Use @c SIOCSPGRP or @c F_SETOWN
 * @param sig_to_set          Use the signal in @c F_SETSIG
 *
 * @par Test sequence:
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#include "sockapi-test.h"

#define TE_TEST_NAME  "fcntl/async_postponed"

#include "sockapi-test.h"
#include "iomux.h"

#define CALL_IOMUX \
    do {                                                                \
        tv.tv_sec = 5;                                                  \
        tv.tv_usec = 0;                                                 \
                                                                        \
        RPC_AWAIT_IUT_ERROR(pco_iut);                                   \
        if (!use_epollet)                                               \
            iomux_rc = iomux_call_signal(iomux, pco_iut, &evt, 1, &tv,  \
                                         iomux_sigmask);                \
        else                                                            \
            iomux_rc = rpc_epoll_pwait(pco_iut, epfd, &epoll_evt, 1,    \
                                       tv.tv_sec * 1000 +               \
                                                    tv.tv_usec / 1000,  \
                                       iomux_sigmask);                  \
        iomux_errno = RPC_ERRNO(pco_iut);                               \
    } while (0)

#define CHECK_IOMUX_RC(msg_, intr_exp_) \
    do {                                                                \
        if (iomux_rc == 0)                                              \
        {                                                               \
            ERROR_VERDICT("%s%s() timed out when an event and a "       \
                          "signal arrived simultaneously", msg_,        \
                          iomux_call_en2str(iomux));                    \
        }                                                               \
        else if (iomux_rc == -1)                                        \
        {                                                               \
            if (iomux_errno != RPC_EINTR)                               \
            {                                                           \
                ERROR_VERDICT("%s%s() returned stange errno %s",        \
                              msg_, iomux_call_en2str(iomux),           \
                              errno_rpc2str(iomux_errno));              \
            }                                                           \
            else                                                        \
            {                                                           \
                if (!intr_exp_)                                         \
                    RING_VERDICT("%s%s() interrupted", msg_,            \
                                 iomux_call_en2str(iomux));             \
                                                                        \
                rc = rpc_sigismember(pco_iut, iut_sigmask,              \
                                     exp_sig_num);                      \
                if (!rc)                                                \
                {                                                       \
                    ERROR_VERDICT("%s%s() interrupted but no signal "   \
                                  "catched", msg_,                      \
                                  iomux_call_en2str(iomux));            \
                }                                                       \
            }                                                           \
        }                                                               \
        else if (iomux_rc == 1)                                         \
        {                                                               \
            if (use_epollet)                                            \
                evt.revents = tapi_iomux_epoll_to_evt(epoll_evt.events); \
            if (evt.revents != EVT_RD)                                  \
                RING_VERDICT("%s%s() call successeed returning "        \
                             "events %s", msg_,                         \
                             iomux_call_en2str(iomux),                  \
                             iomux_event_rpc2str(evt.revents));         \
            if (intr_exp_)                                              \
                RING_VERDICT("%s%s() returned event(s)", msg_,          \
                             iomux_call_en2str(iomux));                 \
        }                                                               \
        else                                                            \
        {                                                               \
            ERROR_VERDICT("%s%s() returned strange result",             \
                          msg_, iomux_call_en2str(iomux));              \
        }                                                               \
        if (iomux_rc != -1 || iomux_errno != RPC_EINTR)                 \
        {                                                               \
                rc = rpc_sigismember(pco_iut, iut_sigmask,              \
                                     exp_sig_num);                      \
                if (rc)                                                 \
                {                                                       \
                    ERROR_VERDICT("%s%s() was not interrupted but "     \
                                  "a signal catched", msg_,             \
                                  iomux_call_en2str(iomux));            \
                }                                                       \
        }                                                               \
    } while (0)

#define RECV_CHECK_DATA \
    do {                                                                \
        rc = rpc_recv(pco_iut, iut_s, rx_buf, buf_len, 0);              \
        if (rc != (int)buf_len || memcmp(tx_buf, rx_buf, buf_len) != 0) \
            TEST_FAIL("The content of 'tx_buf' and 'rx_buf' "           \
                      "are not the same");                              \
        /* Reset RX buffer */                                           \
        memset(rx_buf, 0, buf_len);                                     \
    } while (0)

int
main(int argc, char *argv[])
{
    rpc_socket_type    sock_type;
    rcf_rpc_server    *pco_iut = NULL;
    rcf_rpc_server    *pco_tst = NULL;
    int                iut_s = -1;
    int                tst_s = -1;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;
    void                   *tx_buf = NULL;
    void                   *rx_buf = NULL;
    size_t                  buf_len;
    int                     old_flag = -1;
    int                     req_val;
    rpc_sigset_p            iut_sigmask = RPC_NULL;
    DEFINE_RPC_STRUCT_SIGACTION(old_act);
    te_bool                 restore_signal_handler = FALSE;

    te_bool                 use_fioasync = FALSE;
    te_bool                 use_siocspgrp = FALSE;
    te_bool                 active = FALSE;
    int                     sig_num_to_set = -1;

    te_bool                 gen_signal_before_iomux = FALSE;

    const char             *sig_to_set = NULL;
    char                   *str_end;

    tarpc_siginfo_t         siginfo;
    rpc_signum              exp_sig_num = RPC_SIGUNKNOWN;
    rpc_sigset_p            pco_sigmask = RPC_NULL;
    rpc_sigset_p            saved_sigmask = RPC_NULL;
    rpc_sigset_p            iomux_sigmask = RPC_NULL;

    iomux_call_type iomux;
    te_bool         use_epollet = FALSE;
    iomux_evt_fd            evt;
    struct rpc_epoll_event  epoll_evt;
    int                     epfd = -1;
    int                     iomux_rc = -1;
    te_errno                iomux_errno;
    struct tarpc_timeval    tv;

    te_bool                 restore_sig_mask = FALSE;

    struct param_map_entry signum_map[] = {
        SIGNUM_MAPPING_LIST,
        { NULL, 0}
    };

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(active);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(use_fioasync);
    TEST_GET_BOOL_PARAM(use_siocspgrp);
    TEST_GET_STRING_PARAM(sig_to_set);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_BOOL_PARAM(use_epollet);
    TEST_GET_BOOL_PARAM(gen_signal_before_iomux);

    TEST_STEP("Create connected sockets");
    if (active)
        GEN_CONNECTION(pco_tst, pco_iut, sock_type, RPC_PROTO_DEF,
                       tst_addr, iut_addr, &tst_s, &iut_s);
    else
        GEN_CONNECTION_WILD(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                            iut_addr, tst_addr, &iut_s, &tst_s, TRUE);

    sig_num_to_set = strtol(sig_to_set, &str_end, 10);
    if (*str_end != '\0')
    {
        if (test_map_param_value("sig_to_set", signum_map, sig_to_set,
                                 &sig_num_to_set) != 0)
            TEST_STOP;
    }

    if (sig_num_to_set > 0)
        exp_sig_num = sig_num_to_set;
    else
        exp_sig_num = RPC_SIGIO;

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

    pco_sigmask = rpc_sigset_new(pco_iut);
    rpc_sigemptyset(pco_iut, pco_sigmask);
    rpc_sigaddset(pco_iut, pco_sigmask, exp_sig_num);
    saved_sigmask = rpc_sigset_new(pco_iut);
    iomux_sigmask = rpc_sigset_new(pco_iut);

    TEST_STEP("Block signal according to @p sig_num_to_set parameter");
    rpc_sigprocmask(pco_iut, RPC_SIG_BLOCK, pco_sigmask, saved_sigmask);
    restore_sig_mask = TRUE;

    CHECK_NOT_NULL((tx_buf = sockts_make_buf_dgram(&buf_len)));
    rx_buf = te_make_buf_by_len(buf_len);

    TEST_STEP("Register 'pco_iut' on receiving the signal");
    CHECK_RC(tapi_sigaction_simple(pco_iut, exp_sig_num,
                                   SIGNAL_REGISTRAR_SIGINFO, &old_act));
    restore_signal_handler = TRUE;

    TEST_STEP("Set asynchronous mode on @p iut_s using @c FIOASYNC or @c F_SETFL "
              "according to @p use_fioasync_first parameter");
    old_flag = rpc_fcntl(pco_iut, iut_s, RPC_F_GETFL, 0);
    RING("Current flags set on the 'iut_s' are %x", old_flag);
    if (use_fioasync)
    {
        req_val = 1;
        rpc_ioctl(pco_iut, iut_s, RPC_FIOASYNC, &req_val);
    }
    else
    {
        rc = rpc_fcntl(pco_iut, iut_s, RPC_F_SETFL, RPC_O_ASYNC);
    }

    TEST_STEP("Set @c F_SETSIG according to @p sig_num_to_set parameter");
    if (sig_num_to_set != -1)
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_fcntl(pco_iut, iut_s, RPC_F_SETSIG,
                       sig_num_to_set);
        if (rc != 0)
        {
            RING_VERDICT("fcntl(F_SETSIG) failed with errno %s",
                         errno_rpc2str(RPC_ERRNO(pco_iut)));
        }
    }

    TEST_STEP("Set @c SIOCSPGRP or @c F_SETOWN accroding to @p use_siocspgrp "
              "parameter to id of @p pco_iut");
    req_val = rpc_getpid(pco_iut);
    if (use_siocspgrp)
        rpc_ioctl(pco_iut, iut_s, RPC_SIOCSPGRP, &req_val);
    else
        rc = rpc_fcntl(pco_iut, iut_s, RPC_F_SETOWN, req_val);

    if (gen_signal_before_iomux)
    {
        TEST_STEP("Send some data from Tester to generate signal on IUT");
        RPC_SEND(rc, pco_tst, tst_s, tx_buf, buf_len, 0);
        TAPI_WAIT_NETWORK;
    }

    TEST_STEP("Call @p iomux function first time to get in event");
    iut_sigmask = rpc_sigreceived(pco_iut);
    if (!gen_signal_before_iomux)
        pco_iut->op = RCF_RPC_CALL;
    CALL_IOMUX;
    if (!gen_signal_before_iomux)
    {
        TAPI_WAIT_NETWORK;
        TEST_STEP("Send some data from Tester to generate signal on IUT");
        RPC_SEND(rc, pco_tst, tst_s, tx_buf, buf_len, 0);
        TAPI_WAIT_NETWORK;
        pco_iut->op = RCF_RPC_WAIT;
        CALL_IOMUX;
    }
    CHECK_IOMUX_RC("The first call: ", FALSE);
    if (iomux_rc == 1)
        RECV_CHECK_DATA;
    rpc_sigdelset(pco_iut, iut_sigmask, exp_sig_num);
    TEST_STEP("Call @p iomux function first time to get -1 with @c EINTR");
    CALL_IOMUX;
    CHECK_IOMUX_RC("The second call: ", TRUE);
    if (iomux_rc == 1)
        RECV_CHECK_DATA;

    TEST_STEP("Check that the signal is delivered to the process -  "
              "it is the owner of 'iut_s'.");
    rc = rpc_sigismember(pco_iut, iut_sigmask, exp_sig_num);
    if (rc != TRUE)
    {
        TEST_VERDICT("%s signal is not delivered to the pco_iut, "
                     "although O_ASYNC is enabled and there is an "
                     "owner of 'iut_s'",
                     signum_rpc2str(exp_sig_num));
    }
    else
    {
        TEST_STEP("Check that 'si_signo', 'si_code' and 'si_fd' are set "
                  "correctly");
        rpc_siginfo_received(pco_iut, &siginfo);

        if (siginfo.sig_signo != (int)exp_sig_num)
            TEST_FAIL("Unexpected value %s of si_signo field of "
                      "siginfo_t structure",
                      signum_rpc2str(exp_sig_num));

        if (sig_num_to_set <= 0)
        {
            if (siginfo.sig_code != RPC_SI_KERNEL)
            {
                RING_VERDICT("si_code field of siginfo_t structure is "
                             "equal to %s instead of SI_KERNEL",
                             si_code_rpc2str(siginfo.sig_code));

                if (siginfo.sig_fd != 0)
                    RING_VERDICT("si_fd field of siginfo_t structure is "
                                 "not zero as expected and is%s socket fd",
                                 siginfo.sig_fd == iut_s ?
                                            "" : " not");
            }
        }
        else
        {
            if (siginfo.sig_code != RPC_POLL_IN)
                RING_VERDICT("si_code field of siginfo_t structure is "
                             "equal to %s instead of POLL_IN",
                             si_code_rpc2str(siginfo.sig_code));

            if (siginfo.sig_fd == 0)
                RING_VERDICT("si_fd field of siginfo_t structure is "
                             "zero unexpectedly");
            else if (siginfo.sig_fd != iut_s)
            {
                RING_VERDICT("si_fd field of siginfo_t structure is "
                             "not equal to socket fd");
            }
        }
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    if (use_epollet)
        CLEANUP_RPC_CLOSE(pco_iut, epfd);

    if (restore_sig_mask)
        rpc_sigprocmask(pco_iut, RPC_SIG_SETMASK, saved_sigmask, RPC_NULL);

    if (restore_signal_handler)
        CLEANUP_RPC_SIGACTION(pco_iut, exp_sig_num, &old_act,
                              SIGNAL_REGISTRAR_SIGINFO);

    rpc_signal_registrar_cleanup(pco_iut);

    if (saved_sigmask != RPC_NULL)
        rpc_sigset_delete(pco_iut, saved_sigmask);
    if (iomux_sigmask != RPC_NULL)
        rpc_sigset_delete(pco_iut, iomux_sigmask);
    if (pco_sigmask != RPC_NULL)
        rpc_sigset_delete(pco_iut, pco_sigmask);

    free(tx_buf);
    free(rx_buf);

    sockts_kill_zombie_stacks_if_many(pco_iut);

    TEST_END;
}
