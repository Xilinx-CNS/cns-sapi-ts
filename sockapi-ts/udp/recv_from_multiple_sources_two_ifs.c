/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * UDP tests
 */

/**
 * @page udp-recv_from_multiple_sources_two_ifs Receiving datagrams from multiple sources over two interfaces
 *
 * @objective Check that a single UDP socket can receive datagrams
 *            from multiple sources over two interfaces.
 *
 * @param env             Testing environment:
 *                        - @ref arg_types_env_two_nets_all
 *                        - @ref arg_types_env_peer2peer_two_links
 *                        - @ref arg_types_env_peer2peer_two_links_ipv6
 * @param peers_num       Number of peers sending datagrams:
 *                        - @c 10
 *                        - @c 5
 * @param max_data_len    Maximum length of payload in a datagram:
 *                        - @c 1400
 *                        - @c 20000
 * @param recv_func       Receive function to check:
 *                        - @b recv()
 *                        - @b recvmsg()
 *                        - @b onload_zc_recv()
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "udp/recv_from_multiple_sources_two_ifs"

#include "sockapi-test.h"
#include "udp_multisrc.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst1 = NULL;
    rcf_rpc_server *pco_tst2 = NULL;
    const struct sockaddr *iut_addr1 = NULL;
    const struct sockaddr *iut_addr2 = NULL;
    const struct sockaddr *tst1_addr = NULL;
    const struct sockaddr *tst2_addr = NULL;
    const struct if_nameindex *tst1_if = NULL;
    const struct if_nameindex *tst2_if = NULL;
    tapi_env_net *net1 = NULL;
    tapi_env_net *net2 = NULL;

    int peers_num;
    int max_data_len;
    int recv_func;

    udp_multisrc_peer *peers = NULL;
    int iut_s = -1;
    int i;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_ADDR(pco_tst1, tst1_addr);
    TEST_GET_ADDR(pco_tst2, tst2_addr);
    TEST_GET_NET(net1);
    TEST_GET_NET(net2);
    TEST_GET_IF(tst1_if);
    TEST_GET_IF(tst2_if);
    TEST_GET_INT_PARAM(peers_num);
    TEST_GET_INT_PARAM(max_data_len);
    SOCKTS_GET_RECV_FUNC_ID(recv_func);

    TEST_STEP("Create a @c SOCK_DGRAM socket on IUT, bind it to "
              "the wildcard address.");
    TEST_STEP("Create @p peers_num sockets on Tester hosts, bind each "
              "to a different address/port. Connect every socket to "
              "@p iut_addr1 or @p iut_addr2 (depending on the Tester "
              "host) with port to which IUT socket was bound.");

    peers = tapi_calloc(peers_num, sizeof(*peers));
    udp_multisrc_create_peers(pco_iut, pco_tst1, pco_tst2, net1, net2,
                              tst1_if, tst2_if, iut_addr1, iut_addr2,
                              tst1_addr, tst2_addr, TRUE,
                              max_data_len, &iut_s, peers, peers_num);

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
            CLEANUP_RPC_CLOSE(peers[i].rpcs, peers[i].s);
        }

        free(peers);
    }

    TEST_END;
}
