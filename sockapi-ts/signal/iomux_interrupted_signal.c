/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Signals + Socket API
 *
 * $Id$
 */

/** @page signal-iomux_interrupted_signal Check that I/O multiplexer can be interrupted by signal.
 *
 * @objective Check that I/O multiplexers return @c -1, errno @c EINTR
 *            if it is interrupted by signal that is caught.
 *
 * @type conformance
 *
 * @param pco_iut    PCO with IUT
 * @param pco_killer PCO on the same host as @b pco_iut
 * @param pco_tst    Tester PCO
 * @param sock_type  Socket type used in the test
 * @param restart    Set or not @c SA_RESTART for the first signal
 * @param iomux      I/O multiplexer to use
 * @param test_pipe  Whether to test pipe instead of sockets or not
 *
 * @par Scenario:
 * I do not believe in writing C code in English.
 *
 * @author Alexandra Kossovsky <Alexandra.Kossovsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "signal/iomux_interrupted_signal"

#include "sockapi-test.h"
#include "ts_signal.h"
#include "iomux.h"


struct iomux_params {
    rcf_rpc_server         *pco;
    iomux_call_type         iomux;
    iomux_evt_fd            event;
    struct rpc_epoll_event  epevt;
    int                     epfd;
    rpc_sigset_p            sigmask;
    int                     rc;
};

void *
do_call_iomux(void *arg)
{
    struct iomux_params *params = (struct iomux_params *)arg;
    RPC_AWAIT_IUT_ERROR(params->pco);

    switch (params->iomux)
    {
        case IC_EPOLL:
            params->rc = rpc_epoll_wait(params->pco, params->epfd,
                                        &params->epevt, 1, -1);
            break;

        case IC_OO_EPOLL:
        {
            rpc_onload_ordered_epoll_event oo_ev;

            params->rc = rpc_onload_ordered_epoll_wait(params->pco,
                params->epfd, &params->epevt, &oo_ev, 1, -1);
            break;
        }

        case IC_EPOLL_PWAIT:
        case IC_EPOLL_PWAIT2:
            params->rc = iomux_epoll_pwait_call(
                             params->iomux, params->pco, params->epfd,
                             &params->epevt, 1, -1, params->sigmask);
            break;

        default:
            params->rc = iomux_call_signal(params->iomux, params->pco,
                                           &params->event, 1, NULL,
                                           params->sigmask);
    }
    return NULL;
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server  *pco_iut = NULL;
    rcf_rpc_server  *pco_killer = NULL;
    rcf_rpc_server  *pco_tst = NULL;
    const char      *func_sig;
    const char      *sock_type_add = "";
    iomux_call_type  iomux;
    rpc_sigset_p     received_set;

    const struct sockaddr *iut_addr, *tst_addr;
    rpc_socket_type        sock_type = RPC_SOCK_UNSPEC;
    DEFINE_RPC_STRUCT_SIGACTION(old_sig_act);
    te_bool                restore_sig_handler = FALSE;
    struct iomux_params    params;

    pthread_t   thread;
    te_bool     restart;
    te_bool     thread_started;
    te_bool     test_pipe;
    te_bool     use_wildcard;

    rpc_sigset_p iomux_sigmask = RPC_NULL;

    pid_t pco_iut_pid;
    int   tst_fd = -1;
    int   iut_fd = -1;
    int   pipefds[2];

    tarpc_siginfo_t       siginfo;

    /* Test preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_killer);
    TEST_GET_BOOL_PARAM(test_pipe);
    if (!test_pipe)
    {
        TEST_GET_PCO(pco_tst);
        TEST_GET_ADDR(pco_tst, tst_addr);
        TEST_GET_ADDR(pco_iut, iut_addr);
        TEST_GET_SOCK_TYPE(sock_type);
    }
    TEST_GET_BOOL_PARAM(restart);
    TEST_GET_STRING_PARAM(func_sig);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_BOOL_PARAM(use_wildcard);

    /* Scenario */

    params.epfd = -1;
    /* Register signal handler */
    tapi_set_sighandler(pco_iut, RPC_SIGUSR1,
                        (strcmp(func_sig, "sigaction_siginfo") == 0) ?
                            SIGNAL_REGISTRAR_SIGINFO :
                            SIGNAL_REGISTRAR, func_sig,
                        restart, &old_sig_act);
    restore_sig_handler = TRUE;

    if (sock_type == RPC_SOCK_STREAM)
    {
        TEST_GET_STRING_PARAM(sock_type_add);
        if (strcmp(sock_type_add, "listen") == 0)
        {
            iut_fd = rpc_stream_server(pco_iut, RPC_PROTO_DEF, use_wildcard,
                                       iut_addr);
        }
        else if (strcmp(sock_type_add, "passive") == 0)
        {
            GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                           iut_addr, tst_addr, &iut_fd, &tst_fd);

        }
        else {
            GEN_CONNECTION(pco_tst, pco_iut, sock_type, RPC_PROTO_DEF,
                           tst_addr, iut_addr, &tst_fd, &iut_fd);
        }
    }
    else if (!test_pipe)
        GEN_CONNECTION_WILD(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                            iut_addr, tst_addr, &iut_fd, &tst_fd,
                            use_wildcard);
    else
    {
        rpc_pipe(pco_iut, pipefds);
        iut_fd = pipefds[0];
        tst_fd = pipefds[1];
        rcf_rpc_server_fork_exec(pco_iut, "pco_tst", &pco_tst);
        rpc_close(pco_iut, tst_fd);
        rpc_close(pco_tst, iut_fd);
    }

    pco_iut_pid = rpc_getpid(pco_iut);

    if (IOMUX_IS_P_IOMUX(iomux))
    {
        iomux_sigmask = rpc_sigset_new(pco_iut);
        rpc_sigemptyset(pco_iut, iomux_sigmask);
        rpc_sigaddset(pco_iut, iomux_sigmask, RPC_SIGPIPE);
    }
    params.pco = pco_iut;
    params.event.fd = iut_fd;
    params.event.events = EVT_RD;
    params.iomux = iomux;
    params.sigmask = iomux_sigmask;
    if (iomux == IC_EPOLL || iomux == IC_EPOLL_PWAIT ||
        iomux == IC_EPOLL_PWAIT2 || iomux == IC_OO_EPOLL)
    {
        params.epfd = rpc_epoll_create(pco_iut, 1);
        rpc_epoll_ctl_simple(pco_iut, params.epfd, RPC_EPOLL_CTL_ADD,
                             iut_fd, RPC_EPOLLIN);
    }
    pthread_create(&thread, NULL, do_call_iomux, &params);
    thread_started = TRUE;

    /* Wait for a while and then send signal */
    TAPI_WAIT_NETWORK;
    rpc_kill(pco_killer, pco_iut_pid, RPC_SIGUSR1);
    TAPI_WAIT_NETWORK;

    if (pthread_tryjoin_np(thread, NULL) != 0)
        TEST_VERDICT("Iomux was not interrupted by signal");
    thread_started = FALSE;

    if (params.rc == -1)
    {
        CHECK_RPC_ERRNO(pco_iut, RPC_EINTR,
                        "Interrupted iomux returned -1, but");
    }
    else
        TEST_VERDICT("iomux call returned %d instead of -1", rc);

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

    /* Now restart iomux and unblock it by sending data */
    params.pco = pco_iut;
    params.event.fd = iut_fd;
    params.event.events = EVT_RD;
    params.iomux = iomux;
    pthread_create(&thread, NULL, do_call_iomux, &params);
    thread_started = TRUE;
    TAPI_WAIT_NETWORK;

    if (strcmp(sock_type_add, "listen") == 0)
    {
        tst_fd = rpc_socket(pco_tst, rpc_socket_domain_by_addr(iut_addr),
                           sock_type, RPC_PROTO_DEF);
        rpc_connect(pco_tst, tst_fd, iut_addr);
    }
    else
    {
#define BUF_SIZE 1024
        char tx_buf[BUF_SIZE];
        memset(tx_buf, 0, sizeof(tx_buf));
        RPC_WRITE(rc, pco_tst, tst_fd, tx_buf, BUF_SIZE);
#undef BUF_SIZE
    }
    TAPI_WAIT_NETWORK;

    if (pthread_tryjoin_np(thread, NULL) != 0)
        TEST_VERDICT("Second call to iomux does not work");
    thread_started = FALSE;

    if (params.rc != 1)
        TEST_VERDICT("Second call to iomux failed");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, params.epfd);
    if (IOMUX_IS_P_IOMUX(iomux))
        rpc_sigset_delete(pco_iut, iomux_sigmask);
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

    CLEANUP_RPC_CLOSE(pco_iut, iut_fd);
    CLEANUP_RPC_CLOSE(pco_tst, tst_fd);
    
    if (test_pipe && pco_tst != NULL)
        rcf_rpc_server_destroy(pco_tst);

    TEST_END;
}
