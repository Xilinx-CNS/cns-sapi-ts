/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */


/** @page basic-vfork_sig_exec sigaction()/sigpcrocmask()/signal()/siginterrupt() after vfork() but before execve()
 *
 * @objective Check behaviour of @b sigaction()/@b sigpcrocmask()/
 *            @b signal()/ @b siginterrupt() after @b vfork() but before
 *            @b execve().
 *
 * @type conformance
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_iut_only
 * @param func  Function to be tested:
 *              - sigaction
 *              - signal
 *              - siginterrupt
 *              - sigprocmask
 * @param vfork_mode    Set Onload environment @c EF_VFORK_MODE to:
 *                      0: replace vfork() with fork();
 *                      1: replace vfork() with fork() and block parent till
 *                         child exits/execs;
 *                      2: replace vfork() with vfork().
 * @param domain        Protocol domain to be used for socket creation:
 *                      - PF_INET
 *                      - PF_INET6
 *
 * @par Test sequence:
 *
 * -# Call @b vfork() in @p pco_iut to create @p pco_child.
 * -# Call @b func in @p pco_child, check its return value.
 * -# Call execve() in @p pco_child and terminate it.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/vfork_sig_exec"

#include "sockapi-test.h"

enum {
    FUNC_SIGACTION = 1,
    FUNC_SIGNAL,
    FUNC_SIGPROCMASK,
    FUNC_SIGINTERRUPT
};

#define FUNC_MAPPING_LIST \
    {"sigaction", FUNC_SIGACTION},      \
    {"signal", FUNC_SIGNAL},            \
    {"sigprocmask", FUNC_SIGPROCMASK},  \
    {"siginterrupt", FUNC_SIGINTERRUPT}

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_child = NULL;
    vfork_thread_data      data;
    pthread_t              thread_id;
    int                    func;
    int                    iut_s;
    te_bool                is_failed = FALSE;
    rpc_sigset_p           sig_set = RPC_NULL;
    rpc_sigset_p           sig_get = RPC_NULL;
    rpc_sigset_p           sig_aux = RPC_NULL;
    rpc_sigset_p           sig_parent = RPC_NULL;
    rpc_socket_domain      domain;
    DEFINE_RPC_STRUCT_SIGACTION(act);
    DEFINE_RPC_STRUCT_SIGACTION(act_parent);

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_ENUM_PARAM(func, FUNC_MAPPING_LIST);
    TEST_GET_DOMAIN(domain);

    iut_s = rpc_socket(pco_iut, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);

    if (func != FUNC_SIGPROCMASK)
        rpc_sigaction(pco_iut, RPC_SIGUSR1, NULL, &act_parent);
    else
        sig_parent = rpc_sigset_new(pco_iut);

    data.rpcs = pco_iut;
    data.name = "iut_child";
    /* 
     * This wait may be not necessary - it is done to prevent
     * parent and child from executing simultaneously in case
     * of vfork() not blocking parent until exec().
     */
    data.time_to_wait = 3000;

    CHECK_RC(rcf_rpc_server_vfork_in_thread(&data, &thread_id,
                                            &pco_child));

    if (func == FUNC_SIGACTION)
        rc = tapi_sigaction_simple(pco_child, RPC_SIGUSR1,
                                   SIGNAL_REGISTRAR, NULL);
    else if (func == FUNC_SIGNAL)
        rpc_signal(pco_child, RPC_SIGUSR1, SIGNAL_REGISTRAR);
    else if (func == FUNC_SIGINTERRUPT)
        rc = rpc_siginterrupt(pco_child, RPC_SIGUSR1, 0);
    else if (func == FUNC_SIGPROCMASK)
    {
        sig_set = rpc_sigset_new(pco_child);
        sig_get = rpc_sigset_new(pco_child);
        rpc_sigaddset(pco_child, sig_set, RPC_SIGUSR1);
        rc = rpc_sigprocmask(pco_child, RPC_SIG_SETMASK, sig_set, RPC_NULL);
    }

    if (func == FUNC_SIGPROCMASK)
        rcf_rpc_server_exec(pco_child);

    if (func == FUNC_SIGACTION || func == FUNC_SIGNAL ||
        func == FUNC_SIGINTERRUPT)
    {
        rpc_sigaction(pco_child, RPC_SIGUSR1, NULL, &act);
        if (func == FUNC_SIGACTION || func == FUNC_SIGNAL)
        {
            if (strcmp(act.mm_handler, SIGNAL_REGISTRAR) != 0)
            {
                ERROR_VERDICT("Signal handler is set incorrectlu for "
                              "SIGUSR1 in child process");
                is_failed = TRUE;
            }
        }
        else
        {
            if (!(act.mm_flags & RPC_SA_RESTART))
            {
                ERROR_VERDICT("Flags in signal handler is set "
                              "incorrectly for SIGUSR1 in child process");
                is_failed = TRUE;
            }
        }
    }
    else
    {
        rpc_sigprocmask(pco_child, RPC_SIG_SETMASK, RPC_NULL, sig_get);
        if (rpc_sigset_cmp(pco_child, sig_set, sig_get) != 0)
        {
            ERROR_VERDICT("Signal mask is set incorrectly in the "
                          "child process");
            is_failed = TRUE;
        }

        sig_aux = rpc_sigset_new(pco_iut);
        rpc_sigprocmask(pco_iut, RPC_SIG_SETMASK, RPC_NULL, sig_aux);
        if (rpc_sigset_cmp(pco_iut, sig_parent, sig_aux) != 0)
        {
            ERROR_VERDICT("Changing signal mask on child process "
                          "affects the parent process");
            is_failed = TRUE;
        }
    }

    if (func != FUNC_SIGPROCMASK)
    {
        rcf_rpc_server_exec(pco_child);
        rpc_sigaction(pco_iut, RPC_SIGUSR1, NULL, &act);
    }

    if (func == FUNC_SIGACTION || func == FUNC_SIGNAL)
    {
        if (strcmp(act.mm_handler, act_parent.mm_handler) != 0)
        {
            ERROR_VERDICT("Changing signal handler on child process "
                          "affects the parent process");
            is_failed = TRUE;
        }
    }
    else if (func == FUNC_SIGINTERRUPT)
    {
        if (act.mm_flags != act_parent.mm_flags)
        {
            ERROR_VERDICT("Changing signal handler flags on child process "
                          "affects the parent process");
            is_failed = TRUE;
        }
    }

    if (is_failed)
        TEST_STOP;
    TEST_SUCCESS;

cleanup:
    if (func == FUNC_SIGPROCMASK)
    {
        rpc_sigset_delete(pco_child, sig_get);
        rpc_sigset_delete(pco_child, sig_set);
        rpc_sigset_delete(pco_iut, sig_parent);
        rpc_sigset_delete(pco_iut, sig_aux);
    }

    rcf_rpc_server_destroy(pco_child);
    pthread_join(thread_id, NULL);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
