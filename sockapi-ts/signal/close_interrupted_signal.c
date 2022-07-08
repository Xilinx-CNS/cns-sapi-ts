/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 *
 * $Id: write_interrupted_signal.c 65713 2010-08-26 11:54:03Z yuran $
 */

/** @page signal-close_interrupted_signal Check that close() can be interrupted by signal.
 *
 * @objective Check that @b close() return @c -1, errno @c EINTR if it is
 *            interrupted by signal that is caught and next @b close()
 *            return success.
 *
 * @type conformance
 *
 * @reference @ref STEVENS
 *
 * @param pco_iut    PCO with IUT
 * @param pco_killer PCO on the same host as @b pco_iut
 * @param pco_tst    Tester PCO
 * @param restart    Set or not @c SA_RESTART for the first signal
 * 
 * @par Scenario:
 * -# On @p pco_iut PCO install signal handler
 *    for @p sig signal using @b signal() function with @c SA_RESTART flag
 *    if @p restart value is @c TRUE;
 * -# Generate @c SOCK_STREAM connection between @p pco_iut and @pco_tst.
 *    @p iut_s and @p tst_s will be created.
 * -# Set SO_LINGER socket option on @p iut_s.
 * -# Call @b rpc_overfill_buffers() on @b iut_s socket.
 * -# Call @b close() on @p iut_s socket.
 * -# On @p pco_killer PCO call @b kill() function with @p pco_iut PCO's
 *    PID and @p sig signal.
 * -# If @c SA_RESTART flag was not set check that @b close() function
 *    returns @c -1 and @c EINTR @b errno.
 * -# Read all data from @p tst_s.
 * -# Check that test signal @p sig was received by set handler.
 * -# If previous @b close() returned @c -1 call @b close() function once
 *    again on @p iut_s and check that it returns @c 0.
 * -# Restore signals handlers on @p pco_iut PCO.
 * -# Close opened sockets.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "signal/close_interrupted_signal"


#include "sockapi-test.h"
#include "ts_signal.h"

/* Maximum timeout for connect - 3 min */
#define CLOSE_TIMEOUT_SEC (3 * 60)

struct close_params {
    rcf_rpc_server         *pco;
    int                     sock;
    int                     rc;
};

void *
do_call_close(void *arg)
{
    struct close_params *params = (struct close_params *)arg;

    RPC_AWAIT_IUT_ERROR(params->pco);
    params->pco->timeout = CLOSE_TIMEOUT_SEC * 1000;
    params->rc = rpc_close(params->pco, params->sock);
    return NULL;
}

int
main(int argc, char *argv[])
{
    int                     tst_s = -1;
    int                     iut_s = -1;

    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_killer = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    rpc_sigset_p            received_set;
    tarpc_linger            opt_val;

    DEFINE_RPC_STRUCT_SIGACTION(old_sig_act);
    te_bool                restore_sig_handler = FALSE;
    
    te_bool     restart;

    struct close_params   params;
    pthread_t             thread;
    te_bool               thread_started = FALSE;
    uint64_t              total_bytes;

    pid_t pco_iut_pid;

    const char           *func_sig;

    tarpc_siginfo_t       siginfo;

    /* Test preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_killer);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_BOOL_PARAM(restart);
    TEST_GET_STRING_PARAM(func_sig);

    pco_iut_pid = rpc_getpid(pco_iut);

    /* Scenario */

    /* Register signal handler */
    tapi_set_sighandler(pco_iut, RPC_SIGUSR1,
                        (strcmp(func_sig, "sigaction_siginfo") == 0) ?
                            SIGNAL_REGISTRAR_SIGINFO :
                            SIGNAL_REGISTRAR,
                        func_sig, restart, &old_sig_act);
    restore_sig_handler = TRUE;

    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

     /* Switch on SO_LINGER socket option */
     opt_val.l_onoff  = 1;
     opt_val.l_linger = CLOSE_TIMEOUT_SEC;
     rpc_setsockopt(pco_iut, iut_s, RPC_SO_LINGER, &opt_val);

    rpc_overfill_buffers(pco_iut, iut_s, &total_bytes);

    /* Start connection establishment to be interrupted by signal */
    params.pco = pco_iut;
    params.sock = iut_s;
    pthread_create(&thread, NULL, do_call_close, &params);
    thread_started = TRUE;

    /* Wait for a while and then send signal */
    TAPI_WAIT_NETWORK;
    rpc_kill(pco_killer, pco_iut_pid, RPC_SIGUSR1);
    TAPI_WAIT_NETWORK;

    if (pthread_tryjoin_np(thread, NULL) != 0)
        TEST_VERDICT("Close was not interrupted by signal");
    thread_started = FALSE;

    if (params.rc != 0)
    {
        if (params.rc == -1)
        {
            CHECK_RPC_ERRNO(pco_iut, RPC_EINTR,
                            "Interrupted close returned -1, but");
            RING_VERDICT("Close returned -1(EINTR)");
        }
        else
            TEST_VERDICT("close() call returned %d instead of 0", rc);
    }
    iut_s = -1;

    if (strcmp(func_sig, "sigaction_siginfo") == 0)
    {
        rpc_siginfo_received(pco_iut, &siginfo);
        if (siginfo.sig_pid != rpc_getpid(pco_killer) ||
            siginfo.sig_uid != rpc_getuid(pco_killer))
            RING_VERDICT("siginfo structure is corrupted.");
    }

    /* Check that signal was received */
    received_set = rpc_sigreceived(pco_iut);
    if (rpc_sigismember(pco_iut, received_set, RPC_SIGUSR1) == 0)
        TEST_VERDICT("No signal has been recieved");

    TEST_SUCCESS;

cleanup:

    if (thread_started)
        pthread_join(thread, NULL);

    if (restore_sig_handler)
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rpc_siginterrupt(pco_iut, RPC_SIGUSR1, 0);
        CLEANUP_RPC_SIGACTION(pco_iut, RPC_SIGUSR1, &old_sig_act,
                              (strcmp(func_sig, "sigaction_siginfo") == 0) ?
                              SIGNAL_REGISTRAR_SIGINFO :
                              SIGNAL_REGISTRAR);
    }
    if (old_sig_act.mm_mask != RPC_NULL)
        rpc_sigset_delete(pco_iut, old_sig_act.mm_mask);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
