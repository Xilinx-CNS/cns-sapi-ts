/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * I/O Multiplexing
 *
 * $Id$
 */

/** @page iomux-udp_send_flooding Overfill outgoing UDP buffer
 *
 * @objective Continously transmit data over UDP socket during a time.
 *            Check that a send call occasionally fails with @c EAGAIN, then
 *            a multiplexer call declares the socket unwritable, but after a
 *            time it is writable again.
 *
 * @param pco_iut       PCO on IUT.
 * @param pco_tst       Auxiliary PCO.
 * @param iomux         Iomux function used in the test.
 * @param send_func     Send function.
 * @param blocking      Use blocking or not send operation.
 * @param msg_dontwait  Use @b MSG_DONTWAIT or non-blocking socket.
 *
 * @par Test scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME "iomux/udp_send_flooding"

#include "sockapi-test.h"
#include "tapi_sockets.h"
#include "iomux.h"

/* The flooder execution time, milliseconds. */
#define FLOODER_DURATION 10000

/* Data size to be sent by the call, bytes. */
#define FLOODER_DATA_SIZE 1000

/* How long wait for the rest of data, seconds. */
#define FLOODER_RECV_TIME2WAIT 2

/* Allowed percentage of packets loss. */
/* Note! Onload transmits datagrams much faster than linux and linux is
 * too slow to process such datagram flow. So it is expected that a lot
 * of datagrams are lost for accelerated sockets. See bugs 65544 and 74969
 * for details. */
#define ALLOWED_LOSS 98

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;
    iomux_call_type         iomux;
    te_bool                 blocking;
    te_bool                 msg_dontwait;
    tarpc_send_function     send_func;

    int                     iut_s = -1;
    int                     tst_s = -1;
    uint32_t                errors   = 0;
    uint64_t                received = 0;
    uint64_t                sent     = 0;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_BOOL_PARAM(blocking);
    TEST_GET_BOOL_PARAM(msg_dontwait);
    TEST_GET_SOCK_SEND_FUNC(send_func);

    TEST_STEP("Create UDP sockets on IUT and tester, bind and connect them.");
    GEN_CONNECTION(pco_tst, pco_iut, RPC_SOCK_DGRAM, RPC_PROTO_DEF,
                   tst_addr, iut_addr, &tst_s, &iut_s);

    TEST_STEP("Make IUT socket non-blocking if both @p msg_dontwait and @p blocking "
              "are @c FALSE.");
    if (!blocking && !msg_dontwait)
        rpc_fcntl(pco_iut, iut_s, RPC_F_SETFL, RPC_O_NONBLOCK);

    TEST_STEP("Continuously receive all data on tester.");
    pco_tst->op = RCF_RPC_CALL;
    rpc_iomux_flooder(pco_tst, NULL, 0, &tst_s, 1, FLOODER_DATA_SIZE,
                      FLOODER_DURATION / 1000, FLOODER_RECV_TIME2WAIT,
                      IC_DEFAULT, NULL, &received);

    TEST_STEP("On IUT, on TA side: "
              "-# add THE SOCKET to iomux; "
              "-# send data in a loop until a send function fails with @c EAGAIN; "
              "-# ensure that iomux does not show @c POLLOUT event; "
              "-# wait on iomux for @c POLLOUT event; "
              "-# go to the send loop until the timeout is expired.");
    pco_iut->timeout = pco_iut->def_timeout + FLOODER_DURATION;
    rpc_send_flooder_iomux(pco_iut, iut_s, iomux, send_func, msg_dontwait,
                           FLOODER_DATA_SIZE, FLOODER_DURATION, &sent,
                           &errors);

    rpc_iomux_flooder(pco_tst, NULL, 0, &tst_s, 1, FLOODER_DATA_SIZE,
                      FLOODER_DURATION / 1000, FLOODER_RECV_TIME2WAIT,
                      IC_DEFAULT, NULL, &received);

    received /= FLOODER_DATA_SIZE;
    RING("Sent/received packets number: %llu, %llu", sent, received);

    TEST_STEP("Print the verdict if the test fails to get @c EAGAIN error on "
              "non-blocking send. But no errors should be with blocking send.");
    if (blocking)
    {
        if (errors > 0)
            TEST_VERDICT("Send calls unexpetedly failed");
    }
    else if (errors == 0)
        TEST_VERDICT("Send operation has not failed with EAGAIN");

    TEST_STEP("Compair sent and received packets number, report a verdict if too "
              "many packets were lost.");
    TEST_ARTIFACT("Percentage of packet loss: %d",
                  (int)(100 - received * 100 / sent));
    if (100 - received * 100 / sent > ALLOWED_LOSS)
        TEST_VERDICT("Too many packets were lost");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
