/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 *
 * $Id$
 */

/** @page signal-sa_nodefer SA_NODEFER flag
 *
 * @objective Check that signal handler installed with @c SA_NODEFER flag
 *            can be interrupted by the same signal for which it was
 *            installed.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param pco_iut2    PCO on the same host as @p pco_iut
 * @param sig_to_send   Signal to be sent
 * @param set_flag      Whether to set @c SA_NODEFER flag or not
 * @param func_sig      @c "sigaction", @c "bsd_signal" or
 *                      @c "sysv_signal"
 * @param drop_stack    Close socket (drop Onload stack) if @c TRUE
 * @param socket_after_sigaction  Open socket after sigaction() call
 *
 * @par Scenario:
 *  -# Set signal handler for @p sig_to_send signal with @c SA_NODEFER
 *     flag set / not set according to @p set_flag.
 *  -# Send @p sig_to_send signal and check that signal handler
 *     behaves according to @p set_flag parameter.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "signal/sa_nodefer"

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
    te_bool                 set_flag = FALSE;
    te_bool                 drop_stack;
    te_bool                 socket_after_sigaction;

    const char             *func_sig = NULL;
    te_bool                 is_failed = FALSE;
    pid_t                   pco_iut_pid;
    te_bool                 incorrect_flags = FALSE;
    te_bool                 incorrect_mask = FALSE;
    te_bool                 incorrect_handler = FALSE;
    te_bool                 restore_sigact = FALSE;
    int                     iut_bool_size;
    int                     iut_int_size;
    uint64_t                iut_val;
    rpc_sigset_p            iut_sig_rcvd = RPC_NULL;
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

    iut_bool_size = rpc_get_sizeof(pco_iut, "te_bool");
    iut_int_size = rpc_get_sizeof(pco_iut, "int");

    if (strcmp(func_sig, "bsd_signal") == 0)
        rpc_sigaddset(pco_iut, new_sig_act.mm_mask,
                      sig_to_send);
    new_sig_act.mm_flags = strcmp(func_sig, "sysv_signal") == 0 ?
                            (RPC_SA_RESETHAND | RPC_SA_NODEFER) :
                            (strcmp(func_sig, "bsd_signal") == 0 ?
                             (RPC_SA_RESTART) :
                             (set_flag ? RPC_SA_NODEFER : 0));
    strcpy(new_sig_act.mm_handler, "signal_registrar_nodefer");

    SIGACT_SET_CHECK(pco_iut, sig_to_send, new_sig_act, old_sig_act,
                     current_sig_act, is_failed,
                     incorrect_flags, incorrect_mask,
                     incorrect_handler, restore_sigact,
                     func_sig, socket_after_sigaction, iut_s);

    iut_val = FALSE;
    rpc_set_var(pco_iut, "nodefer_called_twice", iut_bool_size, iut_val);
    rpc_set_var(pco_iut, "nodefer_reset", iut_bool_size, iut_val);
    iut_val = 0;
    rpc_set_var(pco_iut, "nodefer_calls_count", iut_int_size, iut_val);

    pco_iut_pid = rpc_getpid(pco_iut);

    rpc_kill(pco_iut2, pco_iut_pid, sig_to_send);
    MSLEEP(500);
    iut_sig_rcvd = rpc_sigreceived(pco_iut);
    rc = rpc_sigismember(pco_iut, iut_sig_rcvd, sig_to_send);
    if (!rc)
    {
        ERROR_VERDICT("Signal was not received");
        is_failed = TRUE;
    }

    iut_val = rpc_get_var(pco_iut, "nodefer_reset", iut_bool_size);
    if (!(new_sig_act.mm_flags & RPC_SA_RESETHAND) && iut_val)
    {
        ERROR_VERDICT("Signal handler was reset to default when it "
                      "was called");
        is_failed = TRUE;
    }

    iut_val = rpc_get_var(pco_iut, "nodefer_calls_count", iut_int_size);
    if (iut_val == 1)
    {
        if ((new_sig_act.mm_flags & RPC_SA_RESETHAND) == 0)
        {
            ERROR_VERDICT("Signal handler was called only once");
            is_failed = TRUE;
        }
    }
    else
    {
        iut_val = rpc_get_var(pco_iut, "nodefer_called_twice",
                              iut_bool_size);
        if (!iut_val && set_flag)
            TEST_VERDICT("SA_NODEFER does not work");
        else if (iut_val && !set_flag)
            TEST_VERDICT("SA_NODEFER was not set but works");
    }

    drop_onload_stack(pco_iut, &iut_s, sig_to_send, &new_sig_act,
                      &current_sig_act, drop_stack);

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
