/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * I/O Multiplexing
 * 
 * $Id$
 */

/** @page iomux-pair_bidir_perf Bidirectional performance with two nodes
 *
 * @objective Measure performance of the connection using I/O
 *            multiplexing.
 *
 * @type stress, performance
 *
 * @requirement REQ-4, REQ-6
 *
 * @param sock_type     Type of the socket (@c SOCK_DGRAM, @c SOCK_STREAM, etc)
 * @param pco_iut1      The first PCO on IUT
 * @param iut1_addr     Address/port to be used to connect to @p pco_iut1
 * @param iomux1        I/O multiplexing function to be tested on @p pco_iut1
 * @param pco_iut2      The second PCO on IUT
 * @param iut2_addr     Address/port to be used to connect to @p pco_iut2
 * @param iomux2        I/O multiplexing function to be tested on @p pco_iut2
 * @param time2run      How long run the test
 *
 * @par Scenario:
 * -# Create connection between @p pco_iut1 and @p pco_iut2 using
 *    @ref lib-gen_connection algorithm with the following parameters:
 *      - @a srvr: @p pco_iut1;
 *      - @a clnt: @p pco_iut2;
 *      - @a sock_type: @p sock_type;
 *      - @a proto: @c 0;
 *      - @a srvr_addr: @p iut1_addr;
 *      - @a clnt_addr: @p iut2_addr;
 *      - @a srvr_s: stored in @p iut1_s;
 *      - @a clnt_s: stored in @p iut2_s;
 * -# Simultaneously run @ref iomux-flooder on both PCOs with the
 *    following parameters:
 *      -# @p pco_iut1, { @p node1_s }, { @p node1_s }, @c 1000, @c 300, @p iomux1;
 *      -# @p pco_iut2, { @p node2_s }, { @p node2_s }, @c 1100, @c 300, @p iomux2;
 *
 * @par Pass/Fail Criteria:
 * Remote routines return no errors and PCOs didn't fail.
 *
 * This test must be run when @p pco_iut1 and @p pco_iut2 are:
 * - different threads in one process and connected via loopback;
 * - different threads in one process and connected via unicast address;
 * - different processes on one node and connected via loopback;
 * - different processes on one node and connected via unicast address;
 * - located on different network hosts connected via unicast address.
 *
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "iomux/pair_bidir_perf"

#include "sockapi-test.h"
#include "iomux.h"

int
main(int argc, char *argv[])
{
    rpc_socket_type         sock_type;
    iomux_call_type         iomux1;
    iomux_call_type         iomux2;

    int                     time2run;

    rcf_rpc_server         *pco_iut1 = NULL;
    rcf_rpc_server         *pco_iut2 = NULL;

    const struct sockaddr  *iut1_addr;
    const struct sockaddr  *iut2_addr;

    int                     iut1_s = -1;
    int                     iut2_s = -1;

    uint64_t                sent1 = 0;
    uint64_t                received1 = 0;
    uint64_t                sent2 = 0;
    uint64_t                received2 = 0;

    tarpc_timeval           tv = {0, 0};


    /* Preambule */
    TEST_START;
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_IOMUX_FUNC(iomux1);
    TEST_GET_IOMUX_FUNC(iomux2);
    TEST_GET_INT_PARAM(time2run);
    TEST_GET_PCO(pco_iut1);
    TEST_GET_PCO(pco_iut2);
    TEST_GET_ADDR(pco_iut1, iut1_addr);
    TEST_GET_ADDR(pco_iut2, iut2_addr);

    GEN_CONNECTION(pco_iut1, pco_iut2, sock_type, RPC_PROTO_DEF,
                   iut1_addr, iut2_addr, &iut1_s, &iut2_s);

    rpc_gettimeofday(pco_iut1, &tv, NULL);
    pco_iut1->start = pco_iut2->start =
        (tv.tv_sec + 2) * 1000 + tv.tv_usec / 1000;
    pco_iut1->timeout = pco_iut2->timeout = (time2run + 20) * 1000;

    pco_iut1->op = RCF_RPC_CALL;
    if (rpc_iomux_flooder(pco_iut1, &iut1_s, 1, &iut1_s, 1, 1000, time2run, 2,
                          iomux1, &sent1, &received1) != 0)
    {
        TEST_FAIL("Unexpected rpc_flooder() failure on pco_iut1");
    }

    if (rpc_iomux_flooder(pco_iut2, &iut2_s, 1, &iut2_s, 1, 1000, time2run, 2,
                          iomux2, &sent2, &received2) != 0)
    {
        TEST_FAIL("Unexpected rpc_flooder() failure on pco_iut2");
    }

    pco_iut1->op = RCF_RPC_WAIT;
    if (rpc_iomux_flooder(pco_iut1, &iut1_s, 1, &iut1_s, 1, 1000, time2run, 2,
                          iomux1, &sent1, &received1) != 0)
    {
        TEST_FAIL("Unexpected rpc_flooder() failure on pco_iut1");
    }

    if ((sent1 != received2) || (sent2 != received1))
    {
        if (sock_type == RPC_SOCK_STREAM)
        {
            TEST_FAIL("Part of data are lost: %u vs %u (lost %d), "
                      "%u vs %u (lost %d)",
                      (unsigned int)sent1, (unsigned int)received2,
                      (int)(sent1 - received2),
                      (unsigned int)sent2, (unsigned int)received1,
                      (int)(sent2 - received1));
        }
        else
        {
            INFO("Part of data are lost: %u vs %u (lost %d), "
                 "%u vs %u (lost %d)",
                 (unsigned int)sent1, (unsigned int)received2,
                 (int)(sent1 - received2),
                 (unsigned int)sent2, (unsigned int)received1,
                 (int)(sent2 - received1));
        }
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut1, iut1_s);
    CLEANUP_RPC_CLOSE(pco_iut2, iut2_s);

    TEST_END;
}
