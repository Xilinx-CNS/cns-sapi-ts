/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * UDP tests
 *
 * $Id$
 */

/** @page udp-udp_fork_distrib  Datagrams distribution between two processes
 *
 * @objective  Check that the child and parent get more-or-less the same
 *             number of datagrams.
 *
 * @type conformance
 *
 * @param pco_iut  PCO on IUT
 * @param pco_tst  PCO on TESTER
 * @param block    Use blocking or non-blocking recv
 * @param num      Datagrams number to be sent
 * @param length   Datagram length
 *
 * @par Test sequence:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "udp/udp_fork_distrib"

#include "sockapi-test.h"

/* Packet content to determine transmission finish. */
#define LAST_PACKET "bye!"

/* Last packet length. */
#define LAST_PACKET_LEN strlen(LAST_PACKET)

/* Determines allowed difference in received packets. */
#define DEVIATION 0.4

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_iut_child = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;
    te_bool                block;
    int                    num;
    int                    length;

    int iut_s = -1;
    int tst_s = -1;
    int cnt1 = 0;
    int cnt2 = 0;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(block);
    TEST_GET_INT_PARAM(num);
    TEST_GET_INT_PARAM(length);

    TEST_STEP("Create UDP sockets on IUT and tester, bind and connect them.");
    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_DGRAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    TEST_STEP("Do IUT socket non-blocking if @p block is @c FALSE.");
    if (!block)
        rpc_fcntl(pco_iut, iut_s, RPC_F_SETFL, RPC_O_NONBLOCK);

    TEST_STEP("Fork IUT process.");
    CHECK_RC(rcf_rpc_server_thread_create(pco_iut, "pco_iut_child",
                                          &pco_iut_child));

    TEST_STEP("Receive and count packets on both IUT processes.");
    pco_iut->op = RCF_RPC_CALL;
    cnt1 = rpc_many_recv(pco_iut, iut_s, length, num, -1, LAST_PACKET,
                         LAST_PACKET_LEN, FALSE, NULL);
    pco_iut_child->op = RCF_RPC_CALL;
    cnt2 = rpc_many_recv(pco_iut_child, iut_s, length, num, -1, LAST_PACKET,
                         LAST_PACKET_LEN, FALSE, NULL);

    TEST_STEP("Send @p num packets from tester.");
    rpc_many_send_num(pco_tst, tst_s, length, num, -1, TRUE, FALSE, NULL);

    rpc_send(pco_tst, tst_s, LAST_PACKET, strlen(LAST_PACKET), 0);
    rpc_send(pco_tst, tst_s, LAST_PACKET, strlen(LAST_PACKET), 0);

    cnt1 = rpc_many_recv(pco_iut, iut_s, length, num, -1, LAST_PACKET,
                         LAST_PACKET_LEN, FALSE, NULL);
    cnt2 = rpc_many_recv(pco_iut_child, iut_s, length, num, -1, LAST_PACKET,
                         LAST_PACKET_LEN, FALSE, NULL);

    RING("Received datagrams %d:%d, div %f", cnt1, cnt2, cnt1 / (num * 1.0));

    TEST_STEP("Both IUT processes must receive packets.");
    if ((cnt1 / (num * 1.0) < 0.5 - DEVIATION) ||
        (cnt1 / (num * 1.0) > 0.5 + DEVIATION))
        TEST_VERDICT("Too much difference in received packets between "
                     "processes");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_iut_child));

    TEST_END;
}
