/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-threads_system Call system() in multithreaded application
 *
 * @objective Create multiple threads which send/receive traffic and check
 *            that a system() call from one of the thread does not hang.
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_peer2peer
 *              - @ref arg_types_env_peer2peer_ipv6
 *
 * @par Test sequence:
 *
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#define TE_TEST_NAME "basic/threads_system"

#include "sockapi-test.h"
#include "iomux.h"

#define PKTSIZE 1000
#define TIME2RUN 10
#define TIME2WAIT 1

int
main (int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    rcf_rpc_server         *pco_tst_aux = NULL;
    rcf_rpc_server         *pco_child = NULL;
    rcf_rpc_server         *pco_child_thrd1 = NULL;
    rcf_rpc_server         *pco_child_thrd2 = NULL;
    int                     iut_s1 = -1;
    int                     iut_s2 = -1;
    int                     tst_s1 = -1;
    int                     tst_s2 = -1;
    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;
    struct sockaddr_storage iut_addr2;
    struct sockaddr_storage tst_addr2;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    CHECK_RC(tapi_sockaddr_clone(pco_iut, iut_addr, &iut_addr2));
    CHECK_RC(tapi_sockaddr_clone(pco_tst, tst_addr, &tst_addr2));

    TEST_STEP("Create child processes of IUT and Tester RPC servers.");
    CHECK_RC(rcf_rpc_server_fork(pco_iut, "iut_child", &pco_child));
    CHECK_RC(rcf_rpc_server_fork(pco_tst, "tst_child", &pco_tst_aux));

    TEST_STEP("Create two threads on IUT child process.");
    CHECK_RC(rcf_rpc_server_thread_create(pco_child, "iut_child_thrd1",
                                          &pco_child_thrd1));
    CHECK_RC(rcf_rpc_server_thread_create(pco_child, "iut_child_thrd2",
                                          &pco_child_thrd2));

    TEST_STEP("Establish TCP connection between IUT threads and Tester main "
              "and child processes.");
    GEN_CONNECTION(pco_child_thrd1, pco_tst, RPC_SOCK_STREAM,
                   RPC_PROTO_DEF, iut_addr, tst_addr, &iut_s1, &tst_s1);
    GEN_CONNECTION(pco_child_thrd2, pco_tst_aux, RPC_SOCK_STREAM,
                   RPC_PROTO_DEF, SA(&iut_addr2), SA(&tst_addr2), &iut_s2,
                   &tst_s2);

    TEST_STEP("Start data traffic via created connections by means "
              "of @b rpc_iomux_flooder().");
    pco_child_thrd1->op = RCF_RPC_CALL;
    rpc_iomux_flooder(pco_child_thrd1, &iut_s1, 1, NULL, 0,
                      PKTSIZE, TIME2RUN, TIME2WAIT, IC_DEFAULT, NULL, NULL);
    pco_tst->op = RCF_RPC_CALL;
    rpc_iomux_flooder(pco_tst, NULL, 0, &tst_s1, 1,
                      PKTSIZE, TIME2RUN, TIME2WAIT, IC_DEFAULT, NULL, NULL);
    pco_child_thrd2->op = RCF_RPC_CALL;
    rpc_iomux_flooder(pco_child_thrd2, NULL, 0, &iut_s2, 1,
                      PKTSIZE, TIME2RUN, TIME2WAIT, IC_DEFAULT, NULL, NULL);
    pco_tst_aux->op = RCF_RPC_CALL;
    rpc_iomux_flooder(pco_tst_aux, &tst_s2, 1, NULL, 0,
                      PKTSIZE, TIME2RUN, TIME2WAIT, IC_DEFAULT, NULL, NULL);

    TEST_STEP("Call system(\"pwd\") on IUT.");
    SLEEP(1);
    rpc_system(pco_child, "pwd");

    TEST_STEP("Check the status of @b rpc_iomux_flooder() calls.");
    pco_tst->op = RCF_RPC_WAIT;
    rpc_iomux_flooder(pco_tst, NULL, 0, &tst_s1, 1,
                      PKTSIZE, TIME2RUN, TIME2WAIT, IC_DEFAULT,
                      NULL, NULL);

    pco_tst_aux->op = RCF_RPC_WAIT;
    rpc_iomux_flooder(pco_tst_aux, &tst_s2, 1, NULL, 0,
                      PKTSIZE, TIME2RUN, TIME2WAIT, IC_DEFAULT,
                      NULL, NULL);

    TEST_SUCCESS;

cleanup:

    CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_child_thrd1));
    CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_child_thrd2));
    CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_child));
    CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_tst_aux));

    TEST_END;
}
