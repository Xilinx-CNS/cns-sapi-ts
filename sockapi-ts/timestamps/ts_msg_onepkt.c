/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Timestamps
 */

/** @page timestamps-ts_msg_onepkt Retrieve TCP RX timestamps with ONLOAD_MSG_ONEPKT flag
 *
 * @objective Check that with @c ONLOAD_MSG_ONEPKT flag @b recvmsg()
 *            retrieves TCP packets as they were received and with
 *            matching timestamps.
 *
 * @type Conformance.
 *
 * @param env               Testing environment:
 *                          - @ref arg_types_env_peer2peer
 *                          - @ref arg_types_env_peer2peer_ipv6
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "timestamps/ts_msg_onepkt"

#include "sockapi-test.h"
#include "timestamps.h"
#include "iomux.h"
#include "onload.h"

/** Minimum number of packets to send */
#define MIN_PKTS 5
/** Maximum number of packets to send */
#define MAX_PKTS 20

/** Minimum delay after sending a packet, in ms */
#define MIN_DELAY 50
/** Maximum delay after sending a packet, in ms */
#define MAX_DELAY 2000

/** Sent TCP packet */
typedef struct test_pkt {
    char buf[SOCKTS_MSG_STREAM_MAX];  /**< Payload */
    int len;                          /**< Payload length */

    tarpc_timeval send_ts;            /**< Sending timestamp */
} test_pkt;

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;

    test_pkt pkts[MAX_PKTS];
    int pkts_num;
    int i;

    struct rpc_msghdr msg;

    struct timespec ts = {0, 0};
    struct timespec ts_o = {0, 0};

    int iut_s = -1;
    int tst_s = -1;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    TEST_STEP("Create a pair of connected TCP sockets on IUT and Tester.");
    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    TEST_STEP("Enable @c TCP_NODELAY socket option on the Tester socket "
              "to ensure that TCP packets of specified size are sent.");
    rpc_setsockopt_int(pco_tst, tst_s, RPC_TCP_NODELAY, 1);

    TEST_STEP("Enable RX timestamps on the IUT socket with "
              "@c SO_TIMESTAMPING option.");
    rpc_setsockopt_int(pco_iut, iut_s, RPC_SO_TIMESTAMPING,
                       RPC_SOF_TIMESTAMPING_SYS_HARDWARE |
                       RPC_SOF_TIMESTAMPING_RAW_HARDWARE |
                       RPC_SOF_TIMESTAMPING_RX_HARDWARE |
                       RPC_SOF_TIMESTAMPING_SOFTWARE);

    TEST_STEP("Send a few packets from the Tester socket.");
    pkts_num = rand_range(MIN_PKTS, MAX_PKTS);
    for (i = 0; i < pkts_num; i++)
    {
        pkts[i].len = rand_range(1, SOCKTS_MSG_STREAM_MAX);
        te_fill_buf(pkts[i].buf, pkts[i].len);

        RPC_SEND(rc, pco_tst, tst_s, pkts[i].buf, pkts[i].len, 0);
        rpc_gettimeofday(pco_iut, &pkts[i].send_ts, NULL);

        if (i < pkts_num - 1)
            MSLEEP(rand_range(MIN_DELAY, MAX_DELAY));
    }

    TAPI_WAIT_NETWORK;

    TEST_STEP("Receive all the packets on the IUT socket, using "
              "@b recvmsg() with @c ONLOAD_MSG_ONEPKT flag. "
              "Check that each @b recvmsg() call receives payload "
              "of the single packet and correct timestamp for it.");
    for (i = 0; i < pkts_num; i++)
    {
        ts_init_msghdr(FALSE, &msg, SOCKTS_MSG_STREAM_MAX * 2);

        RPC_AWAIT_ERROR(pco_iut);
        rc = rpc_recvmsg(pco_iut, iut_s, &msg, RPC_MSG_ONEPKT);
        if (rc < 0)
        {
            TEST_VERDICT("recvmsg() failed unexpectedly with error %r",
                         RPC_ERRNO(pco_iut));
        }

        ts_check_cmsghdr(&msg, rc, pkts[i].len, pkts[i].buf, FALSE,
                         RPC_SOCK_STREAM, FALSE, FALSE, &ts_o, &ts);

        sockts_release_msghdr(&msg);
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
