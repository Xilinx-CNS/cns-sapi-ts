/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * I/O Multiplexing
 * 
 * $Id$
 */

/** @page iomux-trio_bidir_perf Bidirectional performance with three nodes
 *
 * @objective Measure performance of the connection using I/O
 *            multiplexing. Check robustness under high loads.
 *
 * @type stress, performance
 *
 * @requirement REQ-4, REQ-6
 *
 * @param sock_type_12  Type of connection between @p pco_iut1 and @p pco_iut2
 * @param sock_type_23  Type of connection between @p pco_iut2 and @p pco_iut3
 * @param sock_type_13  Type of connection between @p pco_iut1 and @p pco_iut3
 * @param pco_iut1      The first PCO on IUT
 * @param iut1_addr     Address/port to be used to connect to @p pco_iut1
 * @param iomux1        I/O multiplexing function to be tested on @p pco_iut1
 * @param pco_iut2      The second PCO on IUT
 * @param iut2_addr     Address/port to be used to connect to @p pco_iut2
 * @param iomux2        I/O multiplexing function to be tested on @p pco_iut2
 * @param pco_iut3      The third PCO on IUT
 * @param iut3_addr     Address/port to be used to connect to @p pco_iut3
 * @param iomux3        I/O multiplexing function to be tested on @p pco_iut3
 * @param time2run      How long run the test
 *
 * @par Scenario:
 * -# Create connections between @p iutX and @p iutY
 *    ( (X,Y) = { (1,2), (2,3), (1,3) } ) using
 *    @ref lib-gen_connection algorithm with the following parameters:
 *      - @a srvr: @p iutX;
 *      - @a clnt: @p iutY;
 *      - @a sock_type: @p sock_type_XY;
 *      - @a proto: @c 0;
 *      - @a srvr_addr: @p iutX_addr;
 *      - @a clnt_addr: @p iutY_addr;
 *      - @a srvr_s: stored in @p iutXY_s;
 *      - @a clnt_s: stored in @p iutYX_s;
 * -# Simultaneously run @ref iomux-flooder on each PCO with the
 *    following parameters:
 *      -# @p pco_iut1, { @p iut12_s, @p iut13_s }, { @p iut12_s, @p iut13_s },
 *         @c 1000, @c 300, @p iomux1;
 *      -# @p pco_iut2, { @p iut21_s, @p iut23_s }, { @p iut21_s, @p iut23_s },
 *         @c 1100, @c 200, @p iomux2;
 *      -# @p pco_iut3, { @p iut31_s, @p iut32_s }, { @p iut31_s, @p iut32_s },
 *         @c 1200, @c 100, @p iomux3;
 *
 * @par Pass/Fail Criteria:
 * Remote routines return no errors and PCOs didn't fail.
 * 
 * This test must be run when:
 * - @p pco_iut1 and @p pco_iut2 are different threads in one process and 
 *   connected via loopback;
 * - @p pco_iut3 is a different process on the same host and connected 
 *   to @p pco_iut1 and @p pco_iut2 using unicast address(es);
 * - One connection type is stream, other connections type is datagram.
 * 
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "iomux/trio_bidir_perf"

#include "sockapi-test.h"
#include "iomux.h"

int
main(int argc, char *argv[])
{

    rpc_socket_type         sock_type_12;
    rpc_socket_type         sock_type_23;
    rpc_socket_type         sock_type_31;

    iomux_call_type         iomux1;
    iomux_call_type         iomux2;
    iomux_call_type         iomux3;

    int                     time2run;

    rcf_rpc_server         *pco_iut1 = NULL;
    rcf_rpc_server         *pco_iut2 = NULL;
    rcf_rpc_server         *pco_iut3 = NULL;

    const struct sockaddr  *iut12_addr = NULL;
    const struct sockaddr  *iut13_addr = NULL;
    const struct sockaddr  *iut21_addr = NULL;
    const struct sockaddr  *iut23_addr = NULL;
    const struct sockaddr  *iut31_addr = NULL;
    const struct sockaddr  *iut32_addr = NULL;

    int                     iut12_s = -1;
    int                     iut21_s = -1;
    int                     iut13_s = -1;
    int                     iut31_s = -1;
    int                     iut23_s = -1;
    int                     iut32_s = -1;

    int                     flood1[2] = { 0, };
    int                     flood2[2] = { 0, };
    int                     flood3[2] = { 0, };

    tarpc_timeval           tv = {0, 0};


    /* Preambule */
    TEST_START;
    TEST_GET_SOCK_TYPE(sock_type_12);
    TEST_GET_SOCK_TYPE(sock_type_23);
    TEST_GET_SOCK_TYPE(sock_type_31);
    TEST_GET_IOMUX_FUNC(iomux1);
    TEST_GET_IOMUX_FUNC(iomux2);
    TEST_GET_IOMUX_FUNC(iomux3);
    TEST_GET_INT_PARAM(time2run);
    TEST_GET_PCO(pco_iut1);
    TEST_GET_PCO(pco_iut2);
    TEST_GET_PCO(pco_iut3);
    TEST_GET_ADDR(pco_iut1, iut12_addr);
    TEST_GET_ADDR(pco_iut1, iut13_addr);
    TEST_GET_ADDR(pco_iut2, iut21_addr);
    TEST_GET_ADDR(pco_iut2, iut23_addr);
    TEST_GET_ADDR(pco_iut3, iut31_addr);
    TEST_GET_ADDR(pco_iut3, iut32_addr);


    GEN_CONNECTION(pco_iut1, pco_iut2, sock_type_12, RPC_PROTO_DEF,
                   iut12_addr, iut21_addr, &iut12_s, &iut21_s);

    GEN_CONNECTION(pco_iut2, pco_iut3, sock_type_23, RPC_PROTO_DEF,
                   iut23_addr, iut32_addr, &iut23_s, &iut32_s);

    GEN_CONNECTION(pco_iut3, pco_iut1, sock_type_31, RPC_PROTO_DEF,
                   iut31_addr, iut13_addr, &iut31_s, &iut13_s);

    /* Prepare sets of descriptors */
    flood1[0] = iut12_s; flood1[1] = iut13_s;
    flood2[0] = iut21_s; flood2[1] = iut23_s;
    flood3[0] = iut31_s; flood3[1] = iut32_s;

    rpc_gettimeofday(pco_iut1, &tv, NULL);
    pco_iut1->start = (tv.tv_sec + 3) * 1000 + tv.tv_usec / 1000;
    pco_iut2->start = (tv.tv_sec + 3) * 1000 + tv.tv_usec / 1000;
    pco_iut3->start = (tv.tv_sec + 3) * 1000 + tv.tv_usec / 1000;

    pco_iut1->op = RCF_RPC_CALL;
    rpc_iomux_flooder(pco_iut1,
                      flood1, sizeof(flood1) / sizeof(*flood1),
                      flood1, sizeof(flood1) / sizeof(*flood1),
                      1000, time2run, 1, iomux1, NULL, NULL);

    pco_iut2->op = RCF_RPC_CALL;
    rpc_iomux_flooder(pco_iut2,
                      flood2, sizeof(flood2) / sizeof(*flood2),
                      flood2, sizeof(flood2) / sizeof(*flood2),
                      1100, time2run, 1, iomux2, NULL, NULL);

    rpc_iomux_flooder(pco_iut3,
                      flood3, sizeof(flood3) / sizeof(*flood2),
                      flood3, sizeof(flood3) / sizeof(*flood2),
                      1200, time2run, 1, iomux3, NULL, NULL);

    pco_iut1->op = RCF_RPC_WAIT;
    if (rpc_iomux_flooder(pco_iut1,
                          flood1, sizeof(flood1) / sizeof(*flood1),
                          flood1, sizeof(flood1) / sizeof(*flood1),
                          1000, time2run, 1, iomux1, NULL, NULL) != 0)
    {
        TEST_FAIL("Unexpected rpc_flooder() failure on pco_iut1");
    }

    pco_iut2->op = RCF_RPC_WAIT;
    if (rpc_iomux_flooder(pco_iut2,
                          flood2, sizeof(flood2) / sizeof(*flood2),
                          flood2, sizeof(flood2) / sizeof(*flood2),
                          1100, time2run, 1, iomux2, NULL, NULL) != 0)
    {
        TEST_FAIL("Unexpected rpc_flooder() failure on pco_iut2");
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut1, iut12_s);
    CLEANUP_RPC_CLOSE(pco_iut1, iut13_s);
    CLEANUP_RPC_CLOSE(pco_iut2, iut21_s);
    CLEANUP_RPC_CLOSE(pco_iut2, iut23_s);
    CLEANUP_RPC_CLOSE(pco_iut3, iut31_s);
    CLEANUP_RPC_CLOSE(pco_iut3, iut32_s);

    TEST_END;
}
