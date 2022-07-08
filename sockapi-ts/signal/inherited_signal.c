/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 *
 * $Id$
 */

/** @page signal-inherited_signal Inheritence of the signal handlers after fork()
 *
 * @objective Checks that signal handlers are properly inherited after
 *            @b fork()
 *
 * @type conformance
 *
 * @reference @ref STEVENS
 *
 * @param pco_iut    PCO with IUT
 * 
 * @par Scenario:
 * -# Install @c SIGNAL_RESIGTRAR signal handler for @c SIGUSR1.
 * -# Create child process using @b fork().
 * -# According to @p check_before_socket create or don't create socket
 *    using @p pco_child.
 * -# Check @c SIGNAL_REGISTRAR is signal handler for @c SIGUSR1 signal on
 *    @p pco_child.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "signal/inherited_signal"

#include "sockapi-test.h"
#include "ts_signal.h"

int
main(int argc, char *argv[])
{
    int                     iut_s = -1;

    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_child = NULL;

    DEFINE_RPC_STRUCT_SIGACTION(sig_act);
    DEFINE_RPC_STRUCT_SIGACTION(check_act);

    te_bool                 restore_sig_handler = FALSE;
    te_bool                 check_before_socket;

    const char             *func_sig;

    /* Test preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_STRING_PARAM(func_sig);
    TEST_GET_BOOL_PARAM(check_before_socket);

    rpc_sighandler_createfile_cleanup(pco_iut, RPC_SIGUSR1);
    tapi_set_sighandler(pco_iut, RPC_SIGUSR1, SIGNAL_REGISTRAR,
                        func_sig, FALSE, &sig_act);
    restore_sig_handler = TRUE;

    CHECK_RC(rcf_rpc_server_fork(pco_iut, "child_proc", &pco_child));

    if (!check_before_socket)
        iut_s = rpc_socket(pco_child, RPC_PF_INET, RPC_SOCK_DGRAM,
                           RPC_PROTO_DEF);

    rpc_sigaction_init(pco_child, &check_act);
    rpc_sigaction(pco_child, RPC_SIGUSR1, NULL, &check_act);
    if (strcmp(check_act.mm_handler, SIGNAL_REGISTRAR) != 0)
        TEST_VERDICT("Value returned from rpc_sigaction() is not the same "
                     "as expected");

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_child, iut_s);
    if (restore_sig_handler)
        CLEANUP_RPC_SIGACTION(pco_iut, RPC_SIGUSR1, &sig_act,
                              SIGNAL_REGISTRAR);

    rpc_sigaction_release(pco_iut, &sig_act);
    rpc_sigaction_release(pco_child, &check_act);

    rcf_rpc_server_destroy(pco_child);

    TEST_END;
}
