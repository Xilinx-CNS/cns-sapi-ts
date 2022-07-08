/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 *
 * $Id$
 */

/** @page signal-default_signal Check that default signal handler is SIG_DFL
 *
 * @objective Check that default signal handler is @c SIG_DFL.
 *
 * @type conformance
 *
 * @reference @ref STEVENS
 *
 * @param pco_iut    PCO with IUT
 * 
 * @par Scenario:
 * -# Get default signal handler for @c SIGUSR1 on @p pco_iut, check that
 *    it is @c SIG_DFL.
 * -# Install new signal handler on @p pco_iut using @b sigaction(), check
 *    that old signal handler is @c SIG_DFL.
 * -# Restore @c SIG_DFL on @p pco_iut using @b sigaction(), check
 *    that old signal handler is that was installed in the previous step.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "signal/default_signal"

#include "sockapi-test.h"
#include "ts_signal.h"

#define SIG_DFL_STR "SIG_DFL"

int
main(int argc, char *argv[])
{
    int                     iut_s = -1;

    rcf_rpc_server         *pco_iut = NULL;
    rpc_signum              sig;

    DEFINE_RPC_STRUCT_SIGACTION(sig_act);
    DEFINE_RPC_STRUCT_SIGACTION(new_act);

    te_bool                 restore_sig_handler = FALSE;

    /* Test preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_SIGNUM(sig);

    rpc_sigaction_init(pco_iut, &new_act);
    rpc_sigaction_init(pco_iut, &sig_act);
    strcpy(new_act.mm_handler, SIGNAL_REGISTRAR);

    iut_s = rpc_socket(pco_iut, RPC_PF_INET, RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    rpc_sigaction(pco_iut, sig, NULL, &sig_act);
    if (strcmp(SIG_DFL_STR, sig_act.mm_handler) != 0)
        TEST_VERDICT("Default signal handler is %s", sig_act.mm_handler);

    rpc_sigaction_reinit(pco_iut, &sig_act);
    rpc_sigaction(pco_iut, sig, &new_act, &sig_act);
    if (strcmp(SIG_DFL_STR, sig_act.mm_handler) != 0)
        TEST_VERDICT("Default signal handler is %s on the second call of "
                     "sigaction()", sig_act.mm_handler);
    restore_sig_handler = TRUE;

    TEST_SUCCESS;

cleanup:
    if (restore_sig_handler)
        CLEANUP_RPC_SIGACTION(pco_iut, sig, &sig_act,
                              SIGNAL_REGISTRAR);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    rpc_sigaction_release(pco_iut, &sig_act);
    rpc_sigaction_release(pco_iut, &new_act);

    TEST_END;
}
