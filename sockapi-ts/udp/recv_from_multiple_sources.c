/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * UDP tests
 */

/**
 * @page udp-recv_from_multiple_sources Receiving datagrams from multiple sources
 *
 * @objective Check that a single UDP socket can receive datagrams
 *            from multiple sources.
 *
 * @param env             Testing environment:
 *                        - @ref arg_types_env_peer2peer
 *                        - @ref arg_types_env_peer2peer_ipv6
 * @param peers_num       Number of peers sending datagrams:
 *                        - @c 10
 *                        - @c 5
 * @param max_data_len    Maximum length of payload in a datagram:
 *                        - @c 1400
 *                        - @c 20000
 * @param diff_addrs      If @c TRUE, peers should be bound to different
 *                        addresses (not just different ports)
 * @param recv_func       Receive function to check:
 *                        - @ref arg_types_recv_func
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "udp/recv_from_multiple_sources"

#include "sockapi-test.h"
#include "udp_multisrc.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;
    const struct if_nameindex *tst_if = NULL;
    tapi_env_net *net = NULL;

    udp_multisrc_peer *peers = NULL;
    int iut_s = -1;
    int i;

    int peers_num;
    int max_data_len;
    te_bool diff_addrs;
    int recv_func;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_NET(net);
    TEST_GET_IF(tst_if);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(peers_num);
    TEST_GET_INT_PARAM(max_data_len);
    TEST_GET_BOOL_PARAM(diff_addrs);
    SOCKTS_GET_RECV_FUNC_ID(recv_func);

    TEST_STEP("Create a @c SOCK_DGRAM socket on IUT, bind it to "
              "@p iut_addr.");
    TEST_STEP("Create @p peers_num sockets on Tester, bind each "
              "to a different port or address/port (according to "
              "@p diff_addrs). Connect every socket to @p iut_addr.");

    peers = tapi_calloc(peers_num, sizeof(*peers));
    udp_multisrc_create_peers(pco_iut, pco_tst, NULL, net, NULL,
                              tst_if, NULL, iut_addr, NULL,
                              tst_addr, NULL, diff_addrs, max_data_len,
                              &iut_s, peers, peers_num);

    TEST_STEP("From every Tester socket send a packet.");
    TEST_STEP("Receive all packets on IUT socket using @p recv_func. "
              "Check that all the sent packets were received. If "
              "@p recv_func reports source address, check "
              "its correctness for each received packet.");

    udp_multisrc_send_receive(pco_iut, iut_s, peers, peers_num,
                              max_data_len, recv_func);

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    if (peers != NULL)
    {
        for (i = 0; i < peers_num; i++)
        {
            CLEANUP_RPC_CLOSE(pco_tst, peers[i].s);
        }

        free(peers);
    }

    TEST_END;
}
