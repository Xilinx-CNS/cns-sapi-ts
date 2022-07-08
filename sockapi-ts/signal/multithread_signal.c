/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Signals
 *
 * $Id$
 */

/** @page multithread_signal Check that signal sended to a specific thread is delivered to and only to this thread
 *
 * @objective Check that @b pthread_kill() delivers signal
 *            exactly to a given thread.
 *
 * @type conformance
 *
 * @param pco_iut           PCO with IUT
 * @param threads_num       Number of threads
 * @param sig_to_send       Signal to be sended.
 * @param thread_to_send    Number of thread to which signal will be sended
 * @param func_sig          Which function should be used to change action
 *                          on receipt of @p sig_to_send signal.
 * 
 * @par Scenario:
 * -# Create @p threads_num threads.
 * -# Set @b sighandler_createfile() signal
 *    handler for @p sig_to_send signal for @p pco_iut process.
 * -# Send @p sig_to_send signal to @p thread_to_send thread.
 * -# Check whether the signal was delivered to and only to @p thread_to_send
 *    thread.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "signal/multithread_signal"

#include "sockapi-test.h"
#include "ts_signal.h"

#define MAX_THREADS_NUM 1000

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *iut_threads[MAX_THREADS_NUM] = { NULL, };
    DEFINE_RPC_STRUCT_SIGACTION(old_sig_act);
    int                     threads_num = 0;
    int                     thread_to_send = 0;
    char                    thread_name[RCF_RPC_NAME_LEN];
    const char             *func_sig = NULL;

    rpc_signum            sig_to_send;
    te_bool               is_failed = FALSE;

    int     j;

    int sock = -1;
    te_bool socket_before_handler;

    /* Test preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_INT_PARAM(threads_num);
    TEST_GET_SIGNUM(sig_to_send);
    TEST_GET_INT_PARAM(thread_to_send);
    TEST_GET_STRING_PARAM(func_sig);
    TEST_GET_BOOL_PARAM(socket_before_handler);

    if (socket_before_handler)
        sock = rpc_socket(pco_iut, RPC_PF_INET, RPC_SOCK_DGRAM,
                          RPC_PROTO_DEF);

    for (j = 0; j < threads_num; j++)
    {
        snprintf(thread_name, RCF_RPC_NAME_LEN, "IUT_thread_%d", j + 1);
        CHECK_RC(rcf_rpc_server_thread_create(pco_iut, thread_name,
                                              &(iut_threads[j])));
        rpc_sighandler_createfile_cleanup(iut_threads[j], sig_to_send);
    }

    tapi_set_sighandler(pco_iut, sig_to_send,
                        "sighandler_createfile",
                        func_sig, FALSE, &old_sig_act);

    if (!socket_before_handler)
        sock = rpc_socket(pco_iut, RPC_PF_INET, RPC_SOCK_DGRAM,
                          RPC_PROTO_DEF);

    rpc_pthread_kill(pco_iut,
                     rpc_pthread_self(iut_threads[thread_to_send - 1]),
                     sig_to_send);

    for (j = 0; j < threads_num; j++)
    {
       if (rpc_sighandler_createfile_exists_unlink(iut_threads[j],
                                                   sig_to_send))
       {
            if (j != thread_to_send - 1)
            {
                RING_VERDICT("Signal was delivered to wrong thread %d",
                             j + 1);
                is_failed = TRUE;
            }
       }
       else
       {
            if (j == thread_to_send - 1)
            {
                RING_VERDICT("Signal wasn't delivered to thread %d "
                             "as requested", thread_to_send);
                is_failed = TRUE;
            }
       }
    }

    if (is_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_SIGACTION(pco_iut, sig_to_send, &old_sig_act, NULL);

    CLEANUP_RPC_CLOSE(pco_iut, sock);

    for (j = 0; j < threads_num; j++)
    {
        if (iut_threads[j] != NULL)
            rcf_rpc_server_destroy(iut_threads[j]);
    }

    TEST_END;
}
