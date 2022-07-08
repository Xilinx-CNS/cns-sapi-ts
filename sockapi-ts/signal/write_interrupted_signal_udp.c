/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Signals
 *
 * $Id$
 */

/** @page signal-write_interrupted_signal_udp  Interrupt a datagram transmission by signal
 *
 * @objective  Interrupt UDP write operation by signal.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TESTER
 * @param func          Function to send data flow
 * @param length        Datagram langth
 * @param restart       Set SA_RESTART flag for signal handling
 * @param change_route  Change route to send datagram to TST interface
 *
 * @par Test sequence:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "signal/write_interrupted_signal_udp"

#include "sockapi-test.h"
#include "ts_signal.h"
#include  <pthread.h>

/* Packet content to determine transmission finish. */
#define LAST_PACKET "bye!"

/* Last packet length. */
#define LAST_PACKET_LEN strlen(LAST_PACKET)

/* Signal. */
#define TEST_SIGNAL RPC_SIGUSR1

/* Data transmission duration. */
#define DURATION 3000

/* Maximum attempts sending datagrams to stop receiving in tester RPC. */
#define STOP_MAX_ATTEMPTS 10

/* Flag to stop sending signals. */
static te_bool stop_do_kill = FALSE;

typedef struct kill_args {
    rcf_rpc_server *rpcs;
    pid_t pid;
} kill_args;

/**
 * Aux thread for passing signal to IUT.
 * 
 * @param arg_void Argument with kill_args structure.
 */
void *
do_kill(void *arg_void)
{
    kill_args *arg = (kill_args *)arg_void;

    TAPI_WAIT_NETWORK;

    RING("Start repeatedly send signal %s", signum_rpc2str(TEST_SIGNAL));
    while (!stop_do_kill)
    {
        arg->rpcs->silent = TRUE;
        rpc_kill(arg->rpcs, arg->pid, TEST_SIGNAL);
        usleep(1000);
    }
    RING("Stop signal sending");

    return NULL;
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_iut2 = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    rcf_rpc_server         *pco_tst1 = NULL;
    rcf_rpc_server         *pco_tst2 = NULL;
    const struct sockaddr *tst1_addr;
    const struct sockaddr *tst2_addr;
    const struct if_nameindex *iut_if1;
    const struct if_nameindex *iut_if2;
    const struct if_nameindex *tst1_if;
    const struct if_nameindex *tst2_if;
    const char *func;
    te_bool     change_route;

    pthread_t              thread;
    te_bool                thread_started = FALSE;
    DEFINE_RPC_STRUCT_SIGACTION(old_sig_act);
    const char            *func_sig = NULL;
    rpc_sigset_p           received_set;
    te_bool                restore_sig_handler = FALSE;
    te_bool                restart = FALSE;
    kill_args              args;
    cfg_handle             rt_handle = CFG_HANDLE_INVALID;
    cfg_handle             ah = CFG_HANDLE_INVALID;
    te_bool                done = FALSE;

    int iut_s = -1;
    int tst_s = -1;
    int length_min;
    int length_max;
    int mtu;
    int i;

    te_saved_mtus   iut_mtus = LIST_HEAD_INITIALIZER(iut_mtus);
    te_saved_mtus   tst_mtus = LIST_HEAD_INITIALIZER(tst_mtus);

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_iut2);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_ADDR(pco_tst1, tst1_addr);
    TEST_GET_ADDR(pco_tst2, tst2_addr);
    TEST_GET_IF(iut_if1);
    TEST_GET_IF(iut_if2);
    TEST_GET_IF(tst1_if);
    TEST_GET_IF(tst2_if);
    TEST_GET_STRING_PARAM(func);
    TEST_GET_INT_PARAM(mtu);
    TEST_GET_INT_PARAM(length_min);
    TEST_GET_INT_PARAM(length_max);
    TEST_GET_STRING_PARAM(func_sig);
    TEST_GET_BOOL_PARAM(restart);
    TEST_GET_BOOL_PARAM(change_route);

    if (change_route)
        pco_tst = pco_tst2;
    else
        pco_tst = pco_tst1;

    TEST_STEP("Set requested MTU.");
    if (mtu != 0)
    {
        CHECK_RC(tapi_set_if_mtu_smart2(pco_iut->ta, iut_if1->if_name, mtu,
                                        &iut_mtus));
        CHECK_RC(tapi_set_if_mtu_smart2(pco_tst->ta, tst1_if->if_name, mtu,
                                        &tst_mtus));
    }

    TEST_STEP("Register signal handler.");
    tapi_set_sighandler(pco_iut, TEST_SIGNAL,
                        (strcmp(func_sig, "sigaction_siginfo") == 0) ?
                        SIGNAL_REGISTRAR_SIGINFO : SIGNAL_REGISTRAR,
                        func_sig, restart, &old_sig_act);
    restore_sig_handler = TRUE;

    args.pid = rpc_getpid(pco_iut);

    TEST_STEP("Create, bind and connect sockets on IUT and tester.");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(tst1_addr),
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst1_addr),
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    rpc_connect(pco_iut, iut_s, tst1_addr);

    if (change_route)
    {
        CHECK_RC(tapi_cfg_del_if_ip4_addresses(pco_tst2->ta, tst2_if->if_name,
                                               tst2_addr));
        CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_tst2->ta, tst2_if->if_name,
                                               tst1_addr, 24, FALSE, &ah));

        CHECK_RC(tapi_cfg_add_route(pco_iut->ta, SA(tst1_addr)->sa_family, 
                 te_sockaddr_get_netaddr(tst1_addr), 32, NULL,
                 iut_if2->if_name, NULL, 0, 0, 0, 0, 0, 0, &rt_handle));
        CFG_WAIT_CHANGES;
    }

    rpc_bind(pco_tst, tst_s, tst1_addr);

    TEST_STEP("Repeatedly receive datagrams on tester.");
    pco_tst->op = RCF_RPC_CALL;
    rpc_many_recv(pco_tst, tst_s, length_max, -1, DURATION * 2, LAST_PACKET,
                  LAST_PACKET_LEN, FALSE, NULL);

    TEST_STEP("Create aux thread in the test to send a signal to IUT process.");
    args.rpcs = pco_iut2;
    CHECK_RC(pthread_create(&thread, NULL, do_kill, &args));
    thread_started = TRUE;

    TEST_STEP("Repeatedly send datagrams from IUT with funcion @p func.");
    if (!restart)
        RPC_AWAIT_IUT_ERROR(pco_iut);
    pco_iut->timeout = DURATION + 10000;
    rc = rpc_many_send_num_func(pco_iut, iut_s, length_min, length_max, -1,
                                DURATION, func, TRUE, FALSE, NULL);
    stop_do_kill = TRUE;
    CHECK_RC(pthread_join(thread, NULL));
    thread_started = FALSE;

    TEST_STEP("Check that the send operation was interrupted.");
    if (!restart)
    {
        if (rc != -1)
            ERROR("Send operation was not interrupted");
        else if (RPC_ERRNO(pco_iut) != RPC_EINTR)
            TEST_VERDICT("Send operation failed with unexpected errno %r",
                         RPC_ERRNO(pco_iut));
    }

    for (i = 0; i < STOP_MAX_ATTEMPTS; i++)
    {
        rpc_send(pco_iut, iut_s, LAST_PACKET, LAST_PACKET_LEN, 0);
        rcf_rpc_server_is_op_done(pco_tst, &done);
        if (done)
            break;

        TAPI_WAIT_NETWORK;
    }

    pco_tst->timeout = DURATION * 2 + 10000;
    rpc_many_recv(pco_tst, tst_s, length_max, -1, DURATION * 2, LAST_PACKET,
                  LAST_PACKET_LEN, FALSE, NULL);

    TEST_STEP("Check that signal was received.");
    received_set = rpc_sigreceived(pco_iut);
    if (rpc_sigismember(pco_iut, received_set, RPC_SIGUSR1) == 0)
        TEST_VERDICT("No signal has been recieved");

    TEST_SUCCESS;

cleanup:
    stop_do_kill = TRUE;
    if (thread_started)
        pthread_join(thread, NULL);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    if (restore_sig_handler)
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rpc_siginterrupt(pco_iut, TEST_SIGNAL, 0);
        CLEANUP_RPC_SIGACTION(pco_iut, TEST_SIGNAL, &old_sig_act,
                              (strcmp(func_sig, "sigaction_siginfo") == 0) ?
                              SIGNAL_REGISTRAR_SIGINFO :
                              SIGNAL_REGISTRAR);
    }

    if (old_sig_act.mm_mask != RPC_NULL)
        rpc_sigset_delete(pco_iut, old_sig_act.mm_mask);

    CLEANUP_CHECK_RC(tapi_set_if_mtu_smart2_rollback(&iut_mtus));
    CLEANUP_CHECK_RC(tapi_set_if_mtu_smart2_rollback(&tst_mtus));

    TEST_END;
}
