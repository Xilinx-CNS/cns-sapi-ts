/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Signals
 *
 * $Id$
 */

/** @page signal-signal_stacks_closed Test signal handlers when all stacks are closed
 *
 * @objective Check that signal handlers when all stacks are closed work properly
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param signal        Signal to be sent
 *
 * @par Scenario:
 *  -# Create a socket @p iut_s.
 *  -# Set up signal handler for SIGUSR1.
 *  -# Send the signal @p signal and check that handler worked.
 *  -# Call @b fork, new RPC @p pco_child.
 *  -# Close the socket @p iut_s in child.
 *  -# Check signal handler by @b sigaction for @p pco_child.
 *  -# Send the signal SIGUSR1 to child by @p pco_child and check it
 *     was handled.
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "signal/signal_stacks_closed"

#include "sockapi-test.h"
#include "ts_signal.h"

#define HANDLER_SIGACTION_SIGINFO "sigaction_siginfo"

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_child = NULL;
    rcf_rpc_server         *pco_killer = NULL;
    int                     iut_s = -1;

    sockts_sig_ctx ctx = SOCKTS_SIG_CTX_INIT;
    sockts_sig_state state = SOCKTS_SIG_STATE_INIT;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_killer);

    iut_s = rpc_socket(pco_iut, RPC_PF_INET,
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    ctx.func_sig = HANDLER_SIGACTION_SIGINFO;
    sockts_sig_save_state(pco_iut, &ctx, &state);
    sockts_sig_register_handlers(pco_iut, &ctx, NULL);
    sockts_sig_set_target(pco_iut, &ctx);

    sockts_sig_send(pco_killer, &ctx);
    TAPI_WAIT_NETWORK;

    sockts_sig_check_received(pco_killer, &ctx);
    if (!ctx.received)
        TEST_VERDICT("Signal handler for SIGUSR1 was not called");

    rcf_rpc_server_fork(pco_iut, "iut_child", &pco_child);

    RPC_CLOSE(pco_child, iut_s);

    sockts_sig_check_handlers_after_invoke(pco_child, &ctx,
                                           "In the child process");
    if (ctx.check_failed)
        TEST_STOP;

    sockts_sig_set_target(pco_child, &ctx);
    sockts_sig_send(pco_killer, &ctx);

    TAPI_WAIT_NETWORK;

    sockts_sig_check_received(pco_killer, &ctx);
    if (!ctx.received)
    {
        TEST_VERDICT("Signal handler for SIGUSR1 was not called in the "
                     "child process");
    }

    TEST_SUCCESS;

cleanup:
    rcf_rpc_server_destroy(pco_child);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    sockts_sig_cleanup(pco_iut, &state);

    TEST_END;
}
