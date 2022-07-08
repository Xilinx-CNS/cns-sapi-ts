/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 *
 * $Id$
 */

/** @page signal-sa_resethand SA_RESETHAND flag
 *
 * @objective Check that signal handler installed with @c SA_RESETHAND flag
 *            will be reset to default after receiving a signal
 *
 * @type conformance
 *
 * @param pco_iut                 PCO on IUT
 * @param pco_iut2                PCO on the same host as @p pco_iut
 * @param sig_to_send             Signal to be sent
 * @param set_flag                Whether to set @c SA_RESETHAND flag or not
 * @param func_sig                @c "sigaction", @c "bsd_signal" or
 *                                @c "sysv_signal"
 * @param socket_after_sigaction  Open socket after sigaction() call
 * @param drop_stack              Close socket (drop Onload stack) if
 *                                @c TRUE
 *
 * @par Scenario:
 *  -# Set signal handler for @p sig_to_send signal with @c SA_RESETHAND
 *     flag set/unset according to @p set_flag.
 *  -# Send @p sig_to_send signal and check that signal was reseived and
 *     signal action was reset to default if flag @c SA_RESETHAND was set.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "signal/sa_resethand"

#include "sockapi-test.h"
#include "ts_signal.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_iut2 = NULL;
    DEFINE_RPC_STRUCT_SIGACTION(old_sig_act);
    DEFINE_RPC_STRUCT_SIGACTION(new_sig_act);
    DEFINE_RPC_STRUCT_SIGACTION(current_sig_act);
    rpc_signum              sig_to_send;
    te_bool                 set_flag;
    te_bool                 socket_after_sigaction;
    te_bool                 drop_stack;
    const char             *func_sig = NULL;
    te_bool                 is_failed = FALSE;
    pid_t                   pco_iut_pid;
    tarpc_pthread_t         pco_iut_tid;
    te_bool                 incorrect_flags = FALSE;
    te_bool                 incorrect_mask = FALSE;
    te_bool                 incorrect_handler = FALSE;
    te_bool                 restore_sigact = FALSE;
    int                     iut_s = -1;

    /* Test preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_iut2);
    TEST_GET_SIGNUM(sig_to_send);
    TEST_GET_BOOL_PARAM(set_flag);
    TEST_GET_STRING_PARAM(func_sig);
    TEST_GET_BOOL_PARAM(socket_after_sigaction);
    TEST_GET_BOOL_PARAM(drop_stack);

    rpc_sigaction_init(pco_iut, &old_sig_act);
    rpc_sigaction_init(pco_iut, &new_sig_act);
    rpc_sigaction_init(pco_iut, &current_sig_act);

    if (strcmp(func_sig, "bsd_signal") == 0)
        rpc_sigaddset(pco_iut, new_sig_act.mm_mask,
                      sig_to_send);
    new_sig_act.mm_flags = strcmp(func_sig, "sysv_signal") == 0 ?
                            (RPC_SA_RESETHAND | RPC_SA_NODEFER) :
                            (strcmp(func_sig, "bsd_signal") == 0 ?
                             (RPC_SA_RESTART) :
                             (set_flag ? RPC_SA_RESETHAND : 0));
    strcpy(new_sig_act.mm_handler, "sighandler_createfile");

    SIGACT_SET_CHECK(pco_iut, sig_to_send, new_sig_act, old_sig_act,
                     current_sig_act, is_failed,
                     incorrect_flags, incorrect_mask,
                     incorrect_handler, restore_sigact, func_sig,
                     socket_after_sigaction, iut_s);

    pco_iut_pid = rpc_getpid(pco_iut);
    pco_iut_tid = rpc_pthread_self(pco_iut);

    rpc_kill(pco_iut2, pco_iut_pid, sig_to_send);
    MSLEEP(500);
    if (!rpc_thrd_sighnd_crtfile_exists_unlink(pco_iut2,
                                               sig_to_send,
                                               pco_iut_pid,
                                               pco_iut_tid))
    {
        ERROR_VERDICT("Signal was not received");
        is_failed = TRUE;
    }

    rpc_sigaction_reinit(pco_iut, &current_sig_act);
    rpc_sigaction(pco_iut, sig_to_send, NULL, &current_sig_act);
    if (strcmp(current_sig_act.mm_handler, "SIG_DFL") != 0)
    {
        if (set_flag)
        {
            ERROR_VERDICT("Signal action was not reset to default after "
                          "signal receiving");
            is_failed = TRUE;
        }
    }
    else
    {
        if (!set_flag)
        {
            ERROR_VERDICT("Signal action was reset to default after "
                          "signal receiving when SA_RESETHAND flag was "
                          "not set");
            is_failed = TRUE;
        }
        if (current_sig_act.mm_flags != 0)
        RING_VERDICT("After reseting handler to default flags are not 0 "
                     "but %s",
                     sigaction_flags_rpc2str(current_sig_act.mm_flags));
    }

    drop_onload_stack(pco_iut, &iut_s, sig_to_send, &new_sig_act,
                      &current_sig_act, drop_stack);

    if (is_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    if (restore_sigact)
        rpc_sigaction(pco_iut, sig_to_send, &old_sig_act, NULL);

    rpc_sigaction_release(pco_iut, &old_sig_act);
    rpc_sigaction_release(pco_iut, &new_sig_act);
    rpc_sigaction_release(pco_iut, &current_sig_act);

    TEST_END;
}
