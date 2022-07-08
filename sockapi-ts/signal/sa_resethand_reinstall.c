/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Signals + Socket API
 *
 * $Id$
 */

/** @page signal-sa_resethand_reinstall SA_RESETHAND handler installing another signal handler
 *
 * @objective Check that signal handler installed with @c SA_RESETHAND flag
 *            can install another signal handler
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param pco_killer    PCO on the same host as @p pco_iut
 * @param sig_to_send   Signal to be sent
 * @param drop_stack    Close socket (drop Onload stack) if @c TRUE
 * @param socket_after_sigaction  Open socket after sigaction() call
 *
 * @par Scenario:
 *  -# On @p pco_iut, set signal handler for @p sig_to_send signal with
 *     @c SA_RESETHAND flag set that will reinstall another signal handler
 *     for the same signal.
 *  -# Create a socket.
 *  -# Send @p sig_to_send two times to @p pco_iut, check that correct
 *     signal handlers were invoked.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "signal/sa_resethand_reinstall"

#include "sockapi-test.h"
#include "ts_signal.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_killer = NULL;
    DEFINE_RPC_STRUCT_SIGACTION(old_sig_act);
    DEFINE_RPC_STRUCT_SIGACTION(new_sig_act);
    DEFINE_RPC_STRUCT_SIGACTION(current_sig_act);
    rpc_signum              sig_to_send;
    te_bool                 socket_after_sigaction;
    te_bool                 drop_stack;

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
    TEST_GET_PCO(pco_killer);
    TEST_GET_SIGNUM(sig_to_send);
    TEST_GET_BOOL_PARAM(socket_after_sigaction);
    TEST_GET_BOOL_PARAM(drop_stack);

    rpc_sigaction_init(pco_iut, &old_sig_act);
    rpc_sigaction_init(pco_iut, &new_sig_act);
    rpc_sigaction_init(pco_iut, &current_sig_act);

    new_sig_act.mm_flags = RPC_SA_RESETHAND;
    strcpy(new_sig_act.mm_handler, "sighandler_resethand_reinstall");

    SIGACT_SET_CHECK(pco_iut, sig_to_send, new_sig_act, old_sig_act,
                     current_sig_act, is_failed,
                     incorrect_flags, incorrect_mask,
                     incorrect_handler, restore_sigact, "sigaction",
                     socket_after_sigaction, iut_s);

    pco_iut_pid = rpc_getpid(pco_iut);
    pco_iut_tid = rpc_pthread_self(pco_iut);

    rpc_kill(pco_killer, pco_iut_pid, sig_to_send);
    MSLEEP(500);

    rpc_sigaction_reinit(pco_iut, &current_sig_act);
    rpc_sigaction(pco_iut, sig_to_send, NULL, &current_sig_act);

    if (strcmp(current_sig_act.mm_handler, "SIG_DFL") == 0)
        TEST_VERDICT("Signal handler was reset to default instead of "
                     "being reinstalled");
    else if (strcmp(current_sig_act.mm_handler,
                    "sighandler_createfile") != 0)
        TEST_VERDICT("Signal handler was reinstalled to strange value");

    rpc_kill(pco_killer, pco_iut_pid, sig_to_send);
    MSLEEP(500);

    if (!rpc_thrd_sighnd_crtfile_exists_unlink(pco_killer,
                                               sig_to_send,
                                               pco_iut_pid,
                                               pco_iut_tid))
    {
        ERROR_VERDICT("The second signal handler was not invoked");
        is_failed = TRUE;
    }

    if (drop_stack)
    {
        rcf_rpc_server *pco_iut_child = NULL;

        rcf_rpc_server_create_process(pco_iut, "pco_iut_child", 0,
                                      &pco_iut_child);
        rcf_rpc_server_destroy(pco_iut_child);
        RPC_CLOSE(pco_iut, iut_s);
        TAPI_WAIT_NETWORK;
    }

    rpc_sigaction_reinit(pco_iut, &current_sig_act);
    rpc_sigaction(pco_iut, sig_to_send, NULL, &current_sig_act);
    if (strcmp(current_sig_act.mm_handler, "SIG_DFL") == 0)
    {
        ERROR_VERDICT("Signal action was reset to default after "
                      "the signal was received the second time");
        is_failed = TRUE;
    }
    else if (strcmp(current_sig_act.mm_handler,
                    "sighandler_createfile") != 0)
    {
        ERROR_VERDICT("Signal handler was reset to strange value after "
                      "the signal was received the second time");
        is_failed = TRUE;
    }

    if (is_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    if (restore_sigact)
        rpc_sigaction(pco_iut, sig_to_send, &old_sig_act, NULL);
    rpc_sigaction_release(pco_iut, &old_sig_act);
    rpc_sigaction_release(pco_iut, &new_sig_act);
    rpc_sigaction_release(pco_iut, &current_sig_act);

    TEST_END;
}
