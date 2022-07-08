/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Siute
 * Reliability Socket API in Normal Use
 */

/** @page basic-terminate_waitpid waitpid() after termination by exit() call or a signal
 *
 * @objective Check that @b waitpid() returns expected status after
 *            termination of multithreading process by @b exit() or by a
 *            signal.
 *
 * @type use case
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_peer2peer
 *              - @ref arg_types_env_peer2peer_ipv6
 * @param func  How to terminate tested process:
 *              - exit
 *              - _exit
 *              - tgkill
 * @param sig           If @p func is @b tgkill(),
 *                      @p sig is number of signal to send:
 *                      - SIGKILL
 *                      - SIGUSR1
 * @param sa_resethand  Register a signal handler if @c TRUE, makes sense
 *                      if @p func is @b tgkill().
 * @param exit_status   If @p term_func is @b exit() or @b _exit(),
 *                      @p exit_status is status value to be passed to
 *                      this function:
 *                      - 11
 * @param quit_other_thread Quit from the main process thread or from other
 *                          thread.
 * @param share_stack       Create another process which shares the same
 *                          Onload stack.
 * @param send_data         Send data data flow at exit time.
 * @param sock_type         Socket type:
 *                          - @c SOCK_STREAM
 *                          - @c SOCK_DGRAM
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/terminate_waitpid"

#include "sockapi-test.h"
#include "iomux.h"
#include "terminate_waitpid_prologue.h"

enum {
    EXIT_FUNC = 0,
    _EXIT_FUNC,
    TGKILL_FUNC
};

#define THREAD3_FUNCS \
    {"exit", EXIT_FUNC}, \
    {"_exit", _EXIT_FUNC}, \
    {"tgkill", TGKILL_FUNC}

#define PKTSIZE 1000
#define TIME2RUN 5
#define TIME2WAIT 1

/**
 * Helper macro to verify muxer() return result for TCP
 * connection if Tester is a sender.
 */
#define FLOODER_TCP_EXPECTED_COND(_pco) \
    ((RPC_ERRNO(_pco) == RPC_EPIPE || RPC_ERRNO(_pco) == RPC_ECONNRESET) && \
    sock_type == RPC_SOCK_STREAM)

/**
 * Helper macro to verify muxer() return result for UDP
 * connection if Tester is a sender.
 */
#define FLOODER_UDP_EXPECTED_COND(_pco) \
    (RPC_ERRNO(_pco) == RPC_ECONNREFUSED && sock_type == RPC_SOCK_DGRAM)

int
main (int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    rcf_rpc_server         *pco_tst_aux = NULL;
    rcf_rpc_server         *pco_child = NULL;
    rcf_rpc_server         *pco_child_thrd1 = NULL;
    rcf_rpc_server         *pco_child_thrd2 = NULL;
    rcf_rpc_server         *pco_child_thrd3 = NULL;
    rcf_rpc_server         *pco_iut1 = NULL;
    int                     iut_s1 = -1;
    int                     iut_s2 = -1;
    int                     iut_s3 = -1;
    int                     tst_s1 = -1;
    int                     tst_s2 = -1;
    int                     tst_s3 = -1;
    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    struct sockaddr_storage iut_addr2;
    struct sockaddr_storage tst_addr2;
    struct sockaddr_storage iut_addr3;
    struct sockaddr_storage tst_addr3;

    uint64_t                tx1 = 0;
    uint64_t                tx2 = 0;
    uint64_t                rx1 = 0;
    uint64_t                rx2 = 0;

    int                 func = 0;
    te_bool             sa_resethand = FALSE;
    te_bool             quit_other_thread = FALSE;
    te_bool             share_stack = FALSE;
    int                 exit_status = 0;
    rpc_signum          sig = 0;
    pid_t               child_pid;
    tarpc_pthread_t     child_tid = -1;
    rpc_wait_status     status;
    te_bool             send_data;
    rpc_socket_type     sock_type;
    cfg_val_type        counter_val_type = CVT_INTEGER;
    int                 ev_counter = 0;

    DEFINE_RPC_STRUCT_SIGACTION(new_sig_act);

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ENUM_PARAM(func, THREAD3_FUNCS);
    TEST_GET_BOOL_PARAM(quit_other_thread);
    TEST_GET_BOOL_PARAM(share_stack);
    TEST_GET_BOOL_PARAM(send_data);
    TEST_GET_SOCK_TYPE(sock_type);

    CHECK_RC(tapi_sockaddr_clone(pco_iut, iut_addr, &iut_addr2));
    CHECK_RC(tapi_sockaddr_clone(pco_tst, tst_addr, &tst_addr2));

    if (func == TGKILL_FUNC)
    {
        TEST_GET_SIGNUM(sig);
        TEST_GET_BOOL_PARAM(sa_resethand);
    }
    else if (func == EXIT_FUNC || func == _EXIT_FUNC)
    {
        TEST_GET_INT_PARAM(exit_status);
    }

    TEST_STEP("Reset counter of \"Stack released with lock stuck\" messages "
              "to ensure that we don't process events from previous "
              "iterations.");
    CHECK_RC(cfg_set_instance_fmt(CFG_VAL(INTEGER, 0),
             TERM_WAITPID_PARSER_CONFSTR_EV"/counter:"));

    TEST_STEP("Create @b pco_child as child process of @b pco_iut and "
              "@b pco_tst_aux as child process of @b pco_tst.");
    rcf_rpc_server_fork(pco_iut, "iut_child", &pco_child);
    rcf_rpc_server_fork(pco_tst, "tst_child", &pco_tst_aux);

    child_pid = rpc_getpid(pco_child);

    TEST_STEP("Create threads @b pco_child_thrd1 and @b pco_child_thrd2 "
              "on @b pco_child.");
    rcf_rpc_server_thread_create(pco_child, "iut_child_thrd1",
                                 &pco_child_thrd1);
    rcf_rpc_server_thread_create(pco_child, "iut_child_thrd2",
                                 &pco_child_thrd2);

    if (quit_other_thread)
    {
        TEST_STEP("Create thread @b pco_child_thrd3 if @p quit_other_thread "
                  "is @c TRUE.");
        rcf_rpc_server_thread_create(pco_child, "iut_child_thrd3",
                                     &pco_child_thrd3);
        child_tid = rpc_gettid(pco_child_thrd3);
    }
    else
    {
        child_tid = rpc_gettid(pco_child);
    }

    if (sa_resethand)
    {
        TEST_STEP("Register a signal handler if @p sa_resethand is @c TRUE.");
        memset(&new_sig_act, 0, sizeof(new_sig_act));
        new_sig_act.mm_mask = rpc_sigset_new(pco_child);
        new_sig_act.mm_flags = RPC_SA_RESETHAND;
        strcpy(new_sig_act.mm_handler, "signal_registrar");
        rpc_sigaction(pco_child, sig, &new_sig_act, NULL);
        rpc_sigset_delete(pco_child, new_sig_act.mm_mask);
    }

    TEST_STEP("Establish TCP connection between @b pco_child_thrd1 and "
              "@b pco_tst, and between @b pco_child_thrd2 and "
              "@b pco_tst_aux.");
    GEN_CONNECTION(pco_child_thrd1, pco_tst, sock_type,
                   RPC_PROTO_DEF, iut_addr, tst_addr, &iut_s1, &tst_s1);
    GEN_CONNECTION(pco_child_thrd2, pco_tst_aux, sock_type,
                   RPC_PROTO_DEF, SA(&iut_addr2), SA(&tst_addr2), &iut_s2,
                   &tst_s2);

    if (share_stack)
    {
        TEST_STEP("If @p share_stack is @c TRUE, create another process which "
                  "owns a connection from the same Onload stack.");
        CHECK_RC(tapi_sockaddr_clone(pco_iut, iut_addr, &iut_addr3));
        CHECK_RC(tapi_sockaddr_clone(pco_tst_aux, tst_addr, &tst_addr3));
        GEN_CONNECTION(pco_child, pco_tst_aux, sock_type,
                       RPC_PROTO_DEF, SA(&iut_addr3), SA(&tst_addr3),
                       &iut_s3, &tst_s3);
        CHECK_RC(rcf_rpc_server_fork_exec(pco_child, "pco_iut1", &pco_iut1));
    }

    TEST_STEP("Start data traffic via created connections by means "
              "of @b rpc_iomux_flooder().");
    pco_child_thrd1->op = RCF_RPC_CALL;
    rpc_iomux_flooder(pco_child_thrd1, &iut_s1, send_data ? 1 : 0, NULL, 0,
                      PKTSIZE, TIME2RUN, TIME2WAIT, IC_DEFAULT, NULL, NULL);
    pco_tst->op = RCF_RPC_CALL;
    rpc_iomux_flooder(pco_tst, NULL, 0, &tst_s1, send_data ? 1 : 0,
                      PKTSIZE, TIME2RUN, TIME2WAIT, IC_DEFAULT, &tx1, &rx1);
    pco_child_thrd2->op = RCF_RPC_CALL;
    rpc_iomux_flooder(pco_child_thrd2, NULL, 0, &iut_s2, send_data ? 1 : 0,
                      PKTSIZE, TIME2RUN, TIME2WAIT, IC_DEFAULT, NULL, NULL);
    pco_tst_aux->op = RCF_RPC_CALL;
    rpc_iomux_flooder(pco_tst_aux, &tst_s2, send_data ? 1 : 0, NULL, 0,
                      PKTSIZE, TIME2RUN, TIME2WAIT, IC_DEFAULT, &tx2, &rx2);

    TEST_STEP("Terminate tested process according to @p func.");
    switch (func)
    {
        case EXIT_FUNC:
            rpc_exit(quit_other_thread ? pco_child_thrd3 : pco_child,
                     exit_status);
            break;

        case _EXIT_FUNC:
            rpc__exit(quit_other_thread ? pco_child_thrd3 : pco_child,
                      exit_status);
            break;

        case TGKILL_FUNC:
            if (sa_resethand)
            {
                rpc_tgkill(pco_iut, child_pid, child_tid, sig);
                MSLEEP(500);
            }
            rpc_tgkill(pco_iut, child_pid, child_tid, sig);
            break;
    }

    /* 
     * Let configurator know that all these RPC servers
     * are completely terminated, so only associated data
     * structures should be released in TA
     */
    rcf_rpc_server_finished(pco_child);
    rcf_rpc_server_finished(pco_child_thrd1);
    rcf_rpc_server_finished(pco_child_thrd2);
    if (quit_other_thread)
        rcf_rpc_server_finished(pco_child_thrd3);

    TEST_STEP("Check the status of @b rpc_iomux_flooder() calls.");
    RPC_AWAIT_IUT_ERROR(pco_tst);
    pco_tst->op = RCF_RPC_WAIT;
    rc = rpc_iomux_flooder(pco_tst, NULL, 0, &tst_s1, send_data ? 1 : 0,
                           PKTSIZE, TIME2RUN, TIME2WAIT, IC_DEFAULT,
                           &tx1, &rx1);
    if (rc < 0 && RPC_ERRNO(pco_tst) != RPC_ECONNRESET)
    {
        RING_VERDICT("Terminating iut_child_thrd1 resulted in strange "
                     "errno %s from data receiving operation on a peer",
                     errno_rpc2str(RPC_ERRNO(pco_tst)));
    }

    RPC_AWAIT_IUT_ERROR(pco_tst_aux);
    pco_tst_aux->op = RCF_RPC_WAIT;
    rc = rpc_iomux_flooder(pco_tst_aux, &tst_s2, send_data ? 1 : 0, NULL, 0,
                           PKTSIZE, TIME2RUN, TIME2WAIT, IC_DEFAULT,
                           &tx2, &rx2);

    if (rc < 0 &&
        !FLOODER_TCP_EXPECTED_COND(pco_tst_aux) &&
        !FLOODER_UDP_EXPECTED_COND(pco_tst_aux))
    {
        RING_VERDICT("Terminating iut_child_thrd2 resulted in strange "
                     "errno %s from data sending operation on a peer",
                     errno_rpc2str(RPC_ERRNO(pco_tst_aux)));
    }

    TEST_STEP("Call @b waitpid() and check returned status.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_waitpid(pco_iut, (tarpc_pid_t) child_pid, &status, 0);

    if (rc < 0)
    {
        TEST_VERDICT("waitpid() failed with errno %s",
                        errno_rpc2str(RPC_ERRNO(pco_iut)));
    }
    else
    {
        switch (status.flag)
        {
            case RPC_WAIT_STATUS_EXITED:
                RING_VERDICT("Child process exited with status %d",
                                status.value);
                break;

            case RPC_WAIT_STATUS_SIGNALED:
            case RPC_WAIT_STATUS_CORED:
                RING_VERDICT("Child process was %s by "
                                "the signal %s",
                                status.flag == RPC_WAIT_STATUS_SIGNALED ?
                                "terminated" : "cored",
                                signum_rpc2str(status.value));
                break;

            default:
                RING_VERDICT("waitpid() returned unexpected status %s",
                                wait_status_flag_rpc2str(status.flag));
        }
    }

    if (share_stack)
    {
        TEST_STEP("If @p share_stack is @c TRUE, check that the "
                  "previously-created connection is not affected by "
                  "the exit.");
        rc = sockts_test_send(pco_iut1, iut_s3, pco_tst_aux, tst_s3,
                              NULL, NULL, RPC_PF_UNSPEC, FALSE,
                              "Send from IUT");
        if (rc == 0)
        {
            sockts_test_send(pco_tst_aux, tst_s3, pco_iut1, iut_s3,
                             NULL, NULL, RPC_PF_UNSPEC, FALSE,
                             "Send from Tester");
        }

        TEST_SUBSTEP("Kill RPC server process, which shares the stack.");
        rcf_rpc_server_destroy(pco_iut1);
        pco_iut1 = NULL;
    }

    TEST_STEP("Check whether serial parser caught Onload errors.");
    TAPI_WAIT_NETWORK;
    /*
     * Use "counter" node here since "/agent/parser/event/status" is reset
     * by Tester after handling the parser event.
     */
    CHECK_RC(cfg_get_instance_fmt(&counter_val_type, &ev_counter,
             TERM_WAITPID_PARSER_CONFSTR_EV"/counter:"));
    if (ev_counter > 0)
        TEST_VERDICT("Stack released with lock stuck");

    TEST_SUCCESS;

cleanup:

    rcf_rpc_server_destroy(pco_child_thrd1);
    rcf_rpc_server_destroy(pco_child_thrd2);
    if (quit_other_thread)
        rcf_rpc_server_destroy(pco_child_thrd3);
    if (share_stack)
        rcf_rpc_server_destroy(pco_iut1);

    rcf_rpc_server_destroy(pco_child);
    rcf_rpc_server_destroy(pco_tst_aux);

    TEST_END;
}
