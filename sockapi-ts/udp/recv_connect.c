/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * UDP tests
 *
 * $Id$
 */

/** @page udp-recv_connect  Connect UDP socket with non-empty recv queue
 *
 * @objective  Perform connect() to non-Onload destination on UDP socket with
 *             non-empty recv queue.
 *
 * @type conformance
 *
 * @param pco_iut           PCO on IUT
 * @param pco_tst1          First PCO on TESTER
 * @param pco_tst1          Second PCO on TESTER
 * @param packetsize_min    Minimum packet size
 * @param packetsize_max    Maximum packet size
 *
 * @par Test sequence:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "udp/recv_connect"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst1 = NULL;
    rcf_rpc_server         *pco_tst2 = NULL;
    const struct sockaddr *iut_addr1;
    const struct sockaddr *tst1_addr;
    const struct sockaddr *tst2_addr;
    int                    packetsize_min;
    int                    packetsize_max;

    char  *sendbuf = NULL;
    char  *recvbuf = NULL;
    size_t buflen  = 0;
    int    iut_s = -1;
    int    tst_s = -1;
    int    i;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_ADDR(pco_tst1, tst1_addr);
    TEST_GET_ADDR(pco_tst2, tst2_addr);
    TEST_GET_INT_PARAM(packetsize_min);
    TEST_GET_INT_PARAM(packetsize_max);

    sendbuf = te_make_buf(packetsize_min, packetsize_max, &buflen);
    recvbuf = te_calloc_fill(1, buflen, 0);

    TEST_STEP("Create UDP sockets on IUT and tester, bind them.");
    GEN_CONNECTION(pco_iut, pco_tst1, RPC_SOCK_DGRAM, RPC_PROTO_DEF,
                   iut_addr1, tst1_addr, &iut_s, &tst_s);

    rpc_fcntl(pco_iut, iut_s, RPC_F_SETFL, RPC_O_NONBLOCK);

    TEST_STEP("Send a one packet from tester, which length depends on parameters "
              "@p packetsize_min and @p packetsize_max.");
    /** Send the datagram twice because the first one may be lost if IUT
     * address is not resolved in ARP table and the datagram is splitted
     * to a few IP fragments. */
    for (i = 0; i < 2; i++)
    {
        if (rpc_send(pco_tst1, tst_s, sendbuf, buflen, 0) != (int)buflen)
            TEST_FAIL("Data was not transmitted completely");
        TAPI_WAIT_NETWORK;
    }

    TEST_STEP("Check that data is received by IUT but don't read it.");
    if (rpc_recv(pco_iut, iut_s, sendbuf, buflen,
                 RPC_MSG_PEEK) != (int)buflen)
        TEST_VERDICT("IUT receive buffer keeps less data than it was sent");

    TEST_STEP("Perform connect to non-Onload address.");
    rpc_connect(pco_iut, iut_s, tst2_addr);

    TEST_STEP("Try to read the old data.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    if ((rc = rpc_recv(pco_iut, iut_s, recvbuf, buflen, 0)) != (int)buflen)
    {
        if (RPC_ERRNO(pco_iut) == RPC_EAGAIN)
            TEST_VERDICT("Received data on IUT was lost after connect()");
        TEST_VERDICT("Unexpected recv failure with errno %s",
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    TEST_STEP("Verify received data.");
    if (memcmp(recvbuf, sendbuf, buflen) != 0)
        TEST_VERDICT("Sent and received data are different");

    TEST_SUCCESS;

cleanup:
    free(sendbuf);
    free(recvbuf);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst1, tst_s);

    TEST_END;
}
