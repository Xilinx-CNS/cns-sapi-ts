/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 */

/** @page basic-tcp_udp_two_threads Manipulate with UDP socket when TCP socket is busy in another thread
 *
 * @objective Check that there is no crash when the test operates with TCP
 *            connection in one thread and sends some data via UDP socket in
 *            another thread.
 *
 * @type use case
 *
 * @param env   Private testing environment set, similar to:
 *              - @ref arg_types_env_peer2peer;
 *              - @ref arg_types_env_peer2peer_lo;
 *              - @ref arg_types_env_peer2peer_ipv6;
 *              - @ref arg_types_env_peer2peer_lo_ipv6;
 *              but with two threads on IUT
 * @param time2run  How long to perform continuous data transmission in
 *                  seconds:
 *                  - 10
 * @param iter_num  Number of send() calls to perform using UDP socket:
 *                  - 10
 *
 * @par Scenario:
 * -# Create TCP connection between @p pco_iut and @p pco_tst.
 * -# Start @b iomux_flooder() on @p pco_iut and @p iomux_echoer() on
 *    @p pco_tst according to @p time2run parameter.
 * -# Create UDP socket @p udp_s using @p pco_iut_aux.
 * -# Bind @p udp_s socket to some address.
 * -# Send @p iter_num number of packets from @p udp_s socket to some
 *    address on @p pco_tst.
 * -# Check that @b iomux_flooder() and @p iomux_echoer() return no error.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/tcp_udp_two_threads"

#include "sockapi-test.h"
#include "iomux.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server     *pco_iut = NULL;
    rcf_rpc_server     *pco_iut_aux = NULL;
    rcf_rpc_server     *pco_tst = NULL;

    const struct sockaddr     *iut_addr1 = NULL;
    const struct sockaddr     *iut_addr2 = NULL;
    const struct sockaddr     *tst_addr = NULL;
    const struct sockaddr     *tst_addr_aux = NULL;

    void               *buf  = NULL;
    size_t              buf_len;

    int                 iut_s = -1;
    int                 tst_s = -1;
    int                 udp_s = -1;

    int i;

    int                 time2run;
    int                 iter_num;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_iut_aux);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_ADDR(pco_iut, tst_addr_aux);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(time2run);
    TEST_GET_INT_PARAM(iter_num);

    rcf_rpc_setlibname(pco_iut_aux, pco_iut->nv_lib);
    CHECK_NOT_NULL(buf = sockts_make_buf_dgram(&buf_len));

    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr1, tst_addr, &iut_s, &tst_s);

    pco_iut->timeout = TE_SEC2MS(2 * time2run + 60);
    pco_iut->op = RCF_RPC_CALL;
    if (rpc_iomux_flooder(pco_iut, &iut_s, 1, &iut_s, 1, 1000, time2run, 1,
                          IC_DEFAULT, NULL, NULL) != 0)
    {
        TEST_FAIL("Unexpected rpc_iomux_flooder() failure on pco_iut");
    }

    MSLEEP(100);
    pco_tst->op = RCF_RPC_CALL;
    if (rpc_iomux_echoer(pco_tst, &tst_s, 1, time2run, IC_DEFAULT,
                         NULL, NULL) != 0)
    {
        TEST_FAIL("Unexpected rpc_iomux_echoer() failure on pco_tst");
    }

    MSLEEP(100);
    udp_s = rpc_socket(pco_iut_aux, rpc_socket_domain_by_addr(iut_addr1),
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    rpc_bind(pco_iut_aux, udp_s, iut_addr2);

    for (i = 0; i < iter_num; i++)
        RPC_SENDTO(rc, pco_iut_aux, udp_s, buf, buf_len, 0, tst_addr_aux);

    pco_iut->op = RCF_RPC_WAIT;
    if (rpc_iomux_flooder(pco_iut, &iut_s, 1, &iut_s, 1, 1000, time2run, 1,
                          IC_DEFAULT, NULL, NULL) != 0)
    {
        TEST_FAIL("Unexpected rpc_iomux_flooder() failure on pco_iut");
    }
    pco_tst->op = RCF_RPC_WAIT;
    if (rpc_iomux_echoer(pco_tst, &tst_s, 1, time2run, IC_DEFAULT,
                         NULL, NULL) != 0)
    {
        TEST_FAIL("Unexpected rpc_iomux_echoer() failure on pco_tst");
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut_aux, udp_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
