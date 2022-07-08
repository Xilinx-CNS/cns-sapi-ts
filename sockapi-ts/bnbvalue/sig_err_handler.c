/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-sig_err_handler Setting signal handler to SIG_ERR
 *
 * @objective Check what happens if signal handler is set to SIG_ERR.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param pco_killer    PCO on IUT from which signal to @p pco_iut
 *                      can be sent
 * @param sig           Signal to be sent
 * @param func_sig      Function used to set a handler for the signal
 *
 * @par Scenario:
 *
 * -# Set signal handler to @c SIG_IGN for @p sig signal to prevent RPC
 *    server termination in case of delivering this signal to @p pco_iut.
 * -# Try to set signal handler for @p sig signal to @c SIG_ERR on @p
 *    pco_iut, check returned value.
 * -# Send @p sig signal to @p pco_iut, check whether it is dead or not.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/sig_err_handler"

#include "sockapi-test.h"

/**
 * How long to wait after calling kill() before checking
 * whether RPC server is dead, in milliseconds.
 */
#define WAIT_AFTER_KILL 1000

int
main(int argc, char *argv[])
{
    int                     iut_s = -1;

    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_killer = NULL;
    rpc_signum              sig;

    DEFINE_RPC_STRUCT_SIGACTION(old_act);
    DEFINE_RPC_STRUCT_SIGACTION(new_act);
    te_bool                 restore_sig_handler = FALSE;
    const char             *func_sig;
    tarpc_pid_t             pid;
    char                   *str_rc = NULL;
    te_bool                 rpc_was_restarted = FALSE;

    /* Test preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_killer);
    TEST_GET_SIGNUM(sig);
    TEST_GET_STRING_PARAM(func_sig);

    rpc_sigaction_init(pco_iut, &new_act);
    rpc_sigaction_init(pco_iut, &old_act);

    iut_s = rpc_socket(pco_iut, RPC_PF_INET, RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    strcpy(new_act.mm_handler, "SIG_IGN");
    rpc_sigaction(pco_iut, sig, &new_act, &old_act);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    if (strcmp(func_sig, "signal") == 0)
        str_rc = rpc_signal(pco_iut, sig, "SIG_ERR");
    else if (strcmp(func_sig, "sysv_signal") == 0)
        str_rc = rpc_sysv_signal(pco_iut, sig, "SIG_ERR");
    else if (strcmp(func_sig, "bsd_signal") == 0)
        str_rc = rpc_bsd_signal(pco_iut, sig, "SIG_ERR");
    else if (strcmp(func_sig, "sigaction") == 0)
    {
        strcpy(new_act.mm_handler, "SIG_ERR");
        rc = rpc_sigaction(pco_iut, sig, &new_act, NULL);
    }

    if (rc == 0 && (str_rc == NULL || strcmp(str_rc, "SIG_ERR") != 0))
    {
        RING_VERDICT("%s() successes setting SIG_ERR signal handler",
                     func_sig);
        restore_sig_handler = TRUE;
    }
    else if (RPC_ERRNO(pco_iut) != RPC_EINVAL)
        RING_VERDICT("%s() returned strange errno %s trying to set "
                     "SIG_ERR signal handler");

    if (!rcf_rpc_server_is_alive(pco_iut))
    {
        rcf_rpc_server_restart(pco_iut);
        rpc_was_restarted = TRUE;
        TEST_VERDICT("RPC server is dead after setting signal handler");
    }

    pid = rpc_getpid(pco_iut);
    rpc_kill(pco_killer, pid, sig);

    MSLEEP(WAIT_AFTER_KILL);

    if (!rcf_rpc_server_is_alive(pco_iut))
    {
        rcf_rpc_server_restart(pco_iut);
        rpc_was_restarted = TRUE;
        TEST_VERDICT("RPC server is dead as a result of "
                     "receiving signal");
    }

    TEST_SUCCESS;

cleanup:
    if (!rpc_was_restarted)
    {
        if (restore_sig_handler)
            CLEANUP_RPC_SIGACTION(pco_iut, sig, &old_act,
                                  "SIG_DFL");
        CLEANUP_RPC_CLOSE(pco_iut, iut_s);

        rpc_sigaction_release(pco_iut, &new_act);
        rpc_sigaction_release(pco_iut, &old_act);
    }

    TEST_END;
}
