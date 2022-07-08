/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 *
 * $Id$
 */

/** @page signal-sa_onstack SA_ONSTACK flag
 *
 * @objective Check that signal handler installed with @c SA_ONSTACK flag
 *            is called on an alternate signal stack
 *
 * @type conformance
 *
 * @param pco_iut                 PCO on IUT
 * @param pco_iut2                PCO on the same host as @p pco_iut
 * @param sig_to_send             Signal to be sent
 * @param set_alt_stack           Whether to set alternate signal stack
 *                                or not
 * @param set_flag                Whether to set @c SA_ONSTACK flag or not
 * @param socket_after_sigaction  Open socket after sigaction() call
 * @param drop_stack              Close socket (drop Onload stack) if
 *                                @c TRUE
 *
 * @par Scenario:
 *  -# Check that alternate signal stack is disabled by default.
 *  -# Set alternate signal stack if required.
 *  -# Create socket now or after sigcation() call in dependence on
 *     @p socket_after_sigaction
 *  -# Set signal handler for @p sig_to_send with @c SA_ONSTACK
 *     set/unset according to @p set_flag.
 *  -# Send signal, check obtained results.
 *  -# Close socket (drop Onload stack) if @p drop_stack is @c TRUE
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "signal/sa_onstack"

#include "sockapi-test.h"
#include "ts_signal.h"

#define STACK_SIZE 8192

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_iut2 = NULL;
    DEFINE_RPC_STRUCT_SIGACTION(new_sig_act);
    DEFINE_RPC_STRUCT_SIGACTION(old_sig_act);
    DEFINE_RPC_STRUCT_SIGACTION(current_sig_act);
    rpc_signum              sig_to_send;
    te_bool                 set_alt_stack;
    te_bool                 set_flag;
    te_bool                 socket_after_sigaction;
    te_bool                 drop_stack;
    te_bool                 is_failed = FALSE;
    pid_t                   pco_iut_pid;
    tarpc_stack_t           ss;
    tarpc_stack_t           oss;
    tarpc_stack_t           cur_ss;
    te_bool                 incorrect_flags = FALSE;
    te_bool                 incorrect_mask = FALSE;
    te_bool                 incorrect_handler = FALSE;
    int                     iut_bool_size;
    int                     iut_ll_size;
    uint64_t                iut_val;
    rpc_sigset_p            iut_sig_rcvd = RPC_NULL;
    rpc_ptr                 stack_head = RPC_NULL;
    uint64_t                head_addr = 0;
    te_bool                 restore_sigact = FALSE;
    te_bool                 restore_stack = FALSE;
    int                     iut_s = -1;

    /* Test preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_iut2);
    TEST_GET_SIGNUM(sig_to_send);
    TEST_GET_BOOL_PARAM(set_alt_stack);
    TEST_GET_BOOL_PARAM(set_flag);
    TEST_GET_BOOL_PARAM(socket_after_sigaction);
    TEST_GET_BOOL_PARAM(drop_stack);

    rpc_sigaction_init(pco_iut, &old_sig_act);
    rpc_sigaction_init(pco_iut, &new_sig_act);
    rpc_sigaction_init(pco_iut, &current_sig_act);

    memset(&ss, 0, sizeof(ss));
    memset(&oss, 0, sizeof(oss));
    memset(&cur_ss, 0, sizeof(cur_ss));

    RPC_AWAIT_IUT_ERROR(pco_iut);
    if (set_alt_stack)
    {
        ss.ss_sp = stack_head = rpc_malloc(pco_iut, STACK_SIZE); 
        ss.ss_size = STACK_SIZE;
        ss.ss_flags = 0;
        rc = rpc_sigaltstack(pco_iut, &ss, &oss);
        if (rc >= 0)
            restore_stack = TRUE;
    }
    else
        rc = rpc_sigaltstack(pco_iut, NULL, &oss);

    if (rc < 0)
        TEST_VERDICT("sigaltstack() failed with errno %s",
                     errno_rpc2str(RPC_ERRNO(pco_iut)));

    if (oss.ss_sp != RPC_NULL || oss.ss_flags != RPC_SS_DISABLE ||
        oss.ss_size != 0)
        RING_VERDICT("At the beginning alternate stack has state "
                     "ss_sp=%s ss_flags=%s ss_size=%s",
                     oss.ss_sp != 0 ? "non-null" : "null",
                     sigaltstack_flags_rpc2str(oss.ss_flags),
                     oss.ss_size != 0 ? "non-null" : "null");

    if (set_alt_stack)
    {
        rpc_sigaltstack(pco_iut, NULL, &cur_ss);
        if (cur_ss.ss_sp != ss.ss_sp ||
            cur_ss.ss_flags != ss.ss_flags ||
            cur_ss.ss_size != ss.ss_size)
            TEST_VERDICT("Returned alternate stack state is different "
                         "than we set");
    }

    iut_bool_size = rpc_get_sizeof(pco_iut, "te_bool");
    iut_ll_size = rpc_get_sizeof(pco_iut, "long long");
    iut_val = FALSE;
    rpc_set_var(pco_iut, "was_onstack", iut_bool_size, iut_val);
    iut_val = 0;
    rpc_set_var(pco_iut, "onstack_addr", iut_ll_size, iut_val);

    new_sig_act.mm_flags = set_flag ? RPC_SA_ONSTACK : 0;
    strcpy(new_sig_act.mm_handler, "signal_registrar_onstack");

    SIGACT_SET_CHECK(pco_iut, sig_to_send, new_sig_act, old_sig_act,
                     current_sig_act, is_failed,
                     incorrect_flags, incorrect_mask,
                     incorrect_handler, restore_sigact,
                     "sigaction", socket_after_sigaction, iut_s);

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
    else
    {
        iut_val = rpc_get_var(pco_iut, "was_onstack", iut_bool_size);

        if (!iut_val && set_alt_stack && set_flag)
        {
            ERROR_VERDICT("SS_ONSTACK was not retrieved in signal "
                          "handler set with SA_ONSTACK flag");
            is_failed = TRUE;
        }
        else if (iut_val && (!set_alt_stack || !set_flag))
        {
            ERROR_VERDICT("SS_ONSTACK was retrieved in signal "
                          "handler when %s%s%s",
                          !set_alt_stack ?
                                "alternate stack was not set" : "",
                          !set_alt_stack && !set_flag ?
                                " and " : "",
                          !set_flag ? "SA_ONSTACK was not set" : "");
            is_failed = TRUE;
        }

        if (stack_head != RPC_NULL)
        {
            iut_val = rpc_get_var(pco_iut, "onstack_addr", iut_ll_size);
            head_addr = rpc_get_addr_by_id(pco_iut, stack_head);
            if (iut_val > head_addr &&
                iut_val - head_addr < STACK_SIZE &&
                (!set_alt_stack || !set_flag))
            {
                ERROR_VERDICT("Signal handler was executed on alternate "
                              "stack when %s%s%s",
                              !set_alt_stack ?
                                    "alternate stack was not set" : "",
                              !set_alt_stack && !set_flag ?
                                    " and " : "",
                              !set_flag ? "SA_ONSTACK was not set" : "");
                is_failed = TRUE;
            }
        }
    }

    drop_onload_stack(pco_iut, &iut_s, sig_to_send, &new_sig_act,
                      &current_sig_act, drop_stack);

    if (set_alt_stack)
    {
        ss.ss_flags = RPC_SS_DISABLE;
        rpc_sigaltstack(pco_iut, &ss, NULL);
        rpc_sigaltstack(pco_iut, NULL, &cur_ss);
        if (cur_ss.ss_flags != RPC_SS_DISABLE)
            TEST_VERDICT("Failed to disable alternate signal stack");
    }

    if (is_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    if (restore_stack)
        CLEANUP_CHECK_RC(rpc_sigaltstack(pco_iut, &oss, NULL));
    if (restore_sigact)
        CLEANUP_CHECK_RC(rpc_sigaction(pco_iut, sig_to_send,
                                       &old_sig_act, NULL));
    rpc_sigaction_release(pco_iut, &old_sig_act);
    rpc_sigaction_release(pco_iut, &new_sig_act);
    rpc_sigaction_release(pco_iut, &current_sig_act);

    if (set_alt_stack)
        rpc_free(pco_iut, stack_head);

    rcf_rpc_server_restart(pco_iut);

    TEST_END;
}
