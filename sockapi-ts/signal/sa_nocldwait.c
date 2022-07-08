/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 *
 * $Id$
 */

/** @page signal-sa_nocldwait SA_NOCLDWAIT flag
 *
 * @objective Check that if signal handler for @c SIGCHLD is installed with
 *            @c SA_NOCLDWAIT flag, child process will not be turned into
 *            zombie after termination.
 *
 * @type conformance
 *
 * @param pco_iut                 PCO on IUT
 * @param pco_iut2                PCO on the same host as @p pco_iut
 * @param set_flag                Whether to set @c SA_NOCLDWAIT flag or not
 * @param socket_after_sigaction  Open socket after sigaction() call
 * @param drop_stack              Close socket (drop Onload stack) if
 *                                @c TRUE
 *
 * @par Scenario:
 *  -# Install signal hander for @c SIGCHLD with @c SA_NOCLDWAIT flag
 *     set/unset according to @p set_flag.
 *  -# @b fork() @p pco_child process from @p pco_iut.
 *  -# Send @p SIGKILL to @p pco_child process.
 *  -# Check that @c SIGCHLD was received on @p pco_iut.
 *  -# Check that @b waitpid() result is in accordance to @p set_flag.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "signal/sa_nocldwait"

#include "sockapi-test.h"
#include "ts_signal.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_iut2 = NULL;
    rcf_rpc_server         *pco_child = NULL;
    DEFINE_RPC_STRUCT_SIGACTION(old_sig_act);
    DEFINE_RPC_STRUCT_SIGACTION(new_sig_act);
    DEFINE_RPC_STRUCT_SIGACTION(current_sig_act);
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
    TEST_GET_BOOL_PARAM(set_flag);
    TEST_GET_BOOL_PARAM(socket_after_sigaction);
    TEST_GET_BOOL_PARAM(drop_stack);

    rpc_sigaction_init(pco_iut, &old_sig_act);
    rpc_sigaction_init(pco_iut, &new_sig_act);
    rpc_sigaction_init(pco_iut, &current_sig_act);

    strcpy(new_sig_act.mm_handler, "signal_registrar_siginfo");
    new_sig_act.mm_flags = (set_flag ? RPC_SA_NOCLDWAIT : 0) |
                           RPC_SA_SIGINFO;

    SIGACT_SET_CHECK(pco_iut, RPC_SIGCHLD, new_sig_act, old_sig_act,
                     current_sig_act, is_failed,
                     incorrect_flags, incorrect_mask,
                     incorrect_handler, restore_sigact,
                     "sigaction", socket_after_sigaction, iut_s);

    CHECK_RC(rcf_rpc_server_fork(pco_iut, "iut_child", &pco_child));
    pco_child_pid = rpc_getpid(pco_child);
    rpc_kill(pco_iut2, pco_child_pid, RPC_SIGKILL);
    MSLEEP(500);
    CHECK_RC(rcf_rpc_server_finished(pco_child));

    iut_sig_rcvd = rpc_sigreceived(pco_iut);
    rc = rpc_sigismember(pco_iut, iut_sig_rcvd, RPC_SIGCHLD);
    if (!rc)
    {
        ERROR_VERDICT("SIGCHLD was not received");
        is_failed = TRUE;
    }
    else
    {
        rpc_siginfo_received(pco_iut, &siginfo);
        if (siginfo.sig_pid != pco_child_pid)
        {
            ERROR_VERDICT("Wrong PID is specified in siginfo structure");
            is_failed = TRUE;
        }
        if (siginfo.sig_code != RPC_CLD_KILLED)
        {
            ERROR_VERDICT("Wrong signal code %s is specified in "
                          "siginfo structure",
                          si_code_rpc2str(siginfo.sig_code));
            is_failed = TRUE;
        }
    }

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_waitpid(pco_iut, pco_child_pid, &status,
                     RPC_WNOHANG | RPC_WSYSTEM);
    if (set_flag)
    {
        if (rc >= 0)
        {
            ERROR_VERDICT("waitpid() successed when SA_NOCLDWAIT flag "
                          "was set");
            is_failed = TRUE;
        }
        else if (RPC_ERRNO(pco_iut) != RPC_ECHILD)
            RING_VERDICT("waitpid() returned strange errno %s",
                         errno_rpc2str(RPC_ERRNO(pco_iut)));
    }
    else
    {
        if (rc < 0)
        {
            ERROR_VERDICT("waitpid() failed with errno %s when "
                          "SA_NOCLDWAIT flag was not set",
                          errno_rpc2str(RPC_ERRNO(pco_iut)));
            is_failed = TRUE;
        }
        else
        {
            if (rc != pco_child_pid)
            {
                ERROR_VERDICT("waitpid() returned incorred PID");
                is_failed = TRUE;
            }
            if (status.flag != RPC_WAIT_STATUS_SIGNALED)
            {
                ERROR_VERDICT("waitpid() returned incorrect status %s",
                              wait_status_flag_rpc2str(status.flag));
                is_failed = TRUE;
            }
            else if (status.value != RPC_SIGKILL)
            {
                ERROR_VERDICT("waitpid() returned incorrect signal %s",
                              signum_rpc2str(status.value));
                is_failed = TRUE;
            }
        }
    }

    drop_onload_stack(pco_iut, &iut_s, RPC_SIGCHLD, &new_sig_act,
                      &current_sig_act, drop_stack);

    if (is_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    if (pco_child != NULL)
        rcf_rpc_server_destroy(pco_child);

    if (restore_sigact)
        rpc_sigaction(pco_iut, RPC_SIGCHLD, &old_sig_act, NULL);
    rpc_sigaction_release(pco_iut, &old_sig_act);
    rpc_sigaction_release(pco_iut, &new_sig_act);
    rpc_sigaction_release(pco_iut, &current_sig_act);

    TEST_END;
}
