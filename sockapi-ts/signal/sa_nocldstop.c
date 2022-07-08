/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 *
 * $Id$
 */

/** @page signal-sa_nocldstop SA_NOCLDSTOP flag
 *
 * @objective Check that signal handler for @c SIGCHLD installed with
 *            @c SA_NOCLDSTOP flag will not be invoked when child process
 *            is stopped or resumed.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param pco_iut2      PCO on the same host as @p pco_iut
 * @param sig_to_send   Signal to be sent to stop child process
 * @param set_flag      Whether to set @c SA_NOCLDSTOP flag or not
 * @param drop_stack    Close socket (drop Onload stack) if @c TRUE
 * @param socket_after_sigaction  Open socket after sigaction() call
 *
 * @par Scenario:
 *  -# Install signal hander for @c SIGCHLD with @c SA_NOCLDSTOP flag
 *     set/unset according to @p set_flag.
 *  -# @b fork() @p pco_child process from @p pco_iut.
 *  -# Send @p sig_to_send signal to @p pco_child process.
 *  -# Check that @c SIGCHLD was received or not depending on
 *     @p set_flag.
 *  -# Send @p SIGCONT signal to @p pco_child process.
 *  -# Check that @c SIGCHLD was received or not depending on
 *     @p set_flag.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "signal/sa_nocldstop"

#include "sockapi-test.h"
#include "ts_signal.h"

#define SEND_CHECK_SIGNAL(sig_, code_, str_) \
    do {                                                            \
        rpc_kill(pco_iut2, pco_child_pid, (sig_));                \
        MSLEEP(500);                                                \
        iut_sig_rcvd = rpc_sigreceived(pco_iut);                    \
        rc = rpc_sigismember(pco_iut, iut_sig_rcvd, RPC_SIGCHLD);   \
                                                                    \
        if (!rc && !set_flag)                                       \
        {                                                           \
            ERROR_VERDICT("SIGCHLD was not received when child "    \
                          "process was %s", (str_));                \
            is_failed = TRUE;                                       \
        }                                                           \
        else if (rc && set_flag)                                    \
        {                                                           \
            ERROR_VERDICT("SIGCHLD was received when child "        \
                          "process was %s and SA_NOCLDSTOP "        \
                          "flag was set for a signal handler",      \
                          (str_));                                  \
            is_failed = TRUE;                                       \
        }                                                           \
        if (rc)                                                     \
        {                                                           \
            rpc_siginfo_received(pco_iut, &siginfo);                \
            if (siginfo.sig_pid != pco_child_pid)                   \
            {                                                       \
                ERROR_VERDICT("Wrong PID is specified in siginfo "  \
                              "structure");                         \
                is_failed = TRUE;                                   \
            }                                                       \
            if (siginfo.sig_code != (code_))                        \
            {                                                       \
                ERROR_VERDICT("Wrong signal code %s is specified "  \
                              "in siginfo structure",               \
                              si_code_rpc2str(siginfo.sig_code));   \
                is_failed = TRUE;                                   \
            }                                                       \
        }                                                           \
    } while (0)

#define COMMON_WAITPID(status_, str_) \
    do {                                                                   \
        RPC_AWAIT_IUT_ERROR(pco_iut);                                      \
        rc = rpc_waitpid(pco_iut, pco_child_pid, &status,                  \
                         RPC_WUNTRACED | RPC_WCONTINUED |                  \
                         RPC_WSYSTEM);                                     \
        if (rc < 0)                                                        \
        {                                                                  \
            ERROR_VERDICT("waitpid() waited for %s child failed "          \
                          "with errno %s", (str_),                         \
                          errno_rpc2str(RPC_ERRNO(pco_iut)));              \
            is_failed = TRUE;                                              \
        }                                                                  \
        else                                                               \
        {                                                                  \
            if (rc != pco_child_pid)                                       \
            {                                                              \
                ERROR_VERDICT("waitpid() returned wrong PID waiting for "  \
                              "%s child", (str_));                         \
                is_failed = TRUE;                                          \
            }                                                              \
            if (status.flag != (status_))                                  \
            {                                                              \
                ERROR_VERDICT("waitpid() waiting for %s child "            \
                              "reported it as %s", (str_),                 \
                              wait_status_flag_rpc2str(status.flag));      \
                is_failed = TRUE;                                          \
            }                                                              \
        }                                                                  \
    } while (0)

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_iut2 = NULL;
    rcf_rpc_server         *pco_child = NULL;
    DEFINE_RPC_STRUCT_SIGACTION(old_sig_act);
    DEFINE_RPC_STRUCT_SIGACTION(new_sig_act);
    DEFINE_RPC_STRUCT_SIGACTION(current_sig_act);
    rpc_signum              sig_to_send;
    te_bool                 set_flag = FALSE;
    te_bool                 socket_after_sigaction;
    te_bool                 drop_stack;
    te_bool                 is_failed = FALSE;
    pid_t                   pco_child_pid;
    te_bool                 incorrect_flags = FALSE;
    te_bool                 incorrect_mask = FALSE;
    te_bool                 incorrect_handler = FALSE;
    te_bool                 restore_sigact = FALSE;
    rpc_sigset_p            iut_sig_rcvd = RPC_NULL;
    tarpc_siginfo_t         siginfo;
    rpc_wait_status         status;
    int                     iut_s = -1;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_iut2);
    TEST_GET_SIGNUM(sig_to_send);
    TEST_GET_BOOL_PARAM(set_flag);
    TEST_GET_BOOL_PARAM(socket_after_sigaction);
    TEST_GET_BOOL_PARAM(drop_stack);

    rpc_sigaction_init(pco_iut, &old_sig_act);
    rpc_sigaction_init(pco_iut, &new_sig_act);
    rpc_sigaction_init(pco_iut, &current_sig_act);

    strcpy(new_sig_act.mm_handler, "signal_registrar_siginfo");
    new_sig_act.mm_flags = (set_flag ? RPC_SA_NOCLDSTOP : 0) |
                           RPC_SA_SIGINFO;

    SIGACT_SET_CHECK(pco_iut, RPC_SIGCHLD, new_sig_act, old_sig_act,
                     current_sig_act, is_failed,
                     incorrect_flags, incorrect_mask,
                     incorrect_handler, restore_sigact,
                     "sigaction", socket_after_sigaction, iut_s);

    CHECK_RC(rcf_rpc_server_fork(pco_iut, "iut_child", &pco_child));
    pco_child_pid = rpc_getpid(pco_child);

    SEND_CHECK_SIGNAL(sig_to_send, RPC_CLD_STOPPED,
                      "stopped");

    COMMON_WAITPID(RPC_WAIT_STATUS_STOPPED, "stopped");
    if (rc >= 0 && status.flag == RPC_WAIT_STATUS_STOPPED &&
        status.value != sig_to_send)
    {
        ERROR_VERDICT("waitpid() returned %s instead of %s "
                      "signal as caused child stop",
                      signum_rpc2str(status.value),
                      signum_rpc2str(sig_to_send));
        is_failed = TRUE;
    }

    SEND_CHECK_SIGNAL(RPC_SIGCONT, RPC_CLD_CONTINUED,
                      "resumed");

    COMMON_WAITPID(RPC_WAIT_STATUS_RESUMED, "resumed");

    drop_onload_stack(pco_iut, &iut_s, RPC_SIGCHLD, &new_sig_act,
                      &current_sig_act, drop_stack);

    if (is_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:
    if (restore_sigact)
        CLEANUP_RPC_SIGACTION(pco_iut, RPC_SIGCHLD, &old_sig_act, NULL);

    rpc_signal_registrar_cleanup(pco_iut);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    if (pco_child != NULL)
        rcf_rpc_server_destroy(pco_child);

    rpc_sigaction_release(pco_iut, &old_sig_act);
    rpc_sigaction_release(pco_iut, &new_sig_act);
    rpc_sigaction_release(pco_iut, &current_sig_act);

    TEST_END;
}
