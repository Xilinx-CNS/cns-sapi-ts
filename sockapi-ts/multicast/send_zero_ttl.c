/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Multicasting in IP
 * 
 * $Id$
 */

/** @page multicast-send_zero_ttl Sending multicast packets with zero TTL
 *
 * @objective Test multicast packets transmision behavior in dependence on
 *            IP_MULTICAST_TTL, IP_MULTICAST_LOOP and EF_MCAST_SEND options
 *            combinations.
 *
 * @type conformance
 *
 * @param pco_iut           PCO on IUT
 * @param pco_tst           PCO on TESTER
 * @param iut_if            Interface name/index on IUT
 * @param tst_if            Interface name/index on TESTER
 * @param mcast_addr        Multicast address used in the test
 * @param method            Method to join multicasting group
 * @param ip_multicast_loop Set IP_MULTICAST_LOOP to 0 if @c FALSE
 * @param ip_multicast_ttl  Set IP_MULTICAST_TTL to 0 if @c FALSE
 * @param wildcard          Bind socket to wildcard address
 * @param force_loop        Set env EF_FORCE_SEND_MULTICAST
 * @param packet_number     Packets number to be sent via pure linux
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "multicast/send_zero_ttl"

#include "sockapi-test.h"
#include "mcast_lib.h"
#include "multicast.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server  *pco_iut1  = NULL;
    rcf_rpc_server  *pco_iut2  = NULL;
    rcf_rpc_server  *pco_iut3  = NULL;
    rcf_rpc_server  *pco_tst  = NULL;
    mcast_listener_t listener  = CSAP_INVALID_HANDLE;

    const struct if_nameindex *iut_if     = NULL;
    const struct if_nameindex *tst_if     = NULL;
    const struct sockaddr     *iut_addr   = NULL;
    const struct sockaddr     *mcast_addr = NULL;
    struct sockaddr            wild_addr;
    tarpc_joining_method       method;
    int                        ef_mcast_send;
    te_bool                    ip_multicast_loop;
    te_bool                    ip_multicast_ttl;
    te_bool                    wildcard;
    te_bool                    force_loop;
    cmp_results_type           rx_res[2] = {{FALSE, FALSE}, };
    cmp_results_type           tx_res = {FALSE, FALSE};
    cmp_results_type           tst_res = {FALSE, FALSE};

    char   *sendbuf;
    size_t  buflen;
    int     tx_s = -1;
    int     rx_s1 = -1;
    int     rx_s2 = -1;
    int     tst_s = -1;
    int     i;
    int     packet_number;

    TEST_START;

    TEST_GET_PCO(pco_iut1);
    TEST_GET_PCO(pco_iut2);
    TEST_GET_PCO(pco_iut3);
    TEST_GET_PCO(pco_tst);

    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_ADDR(pco_iut1, iut_addr);
    TEST_GET_ADDR(pco_iut1, mcast_addr);
    TEST_GET_ADDR(pco_tst, iut_addr);
    TEST_GET_MCAST_METHOD(method);
    TEST_GET_BOOL_PARAM(ip_multicast_loop);
    TEST_GET_BOOL_PARAM(ip_multicast_ttl);
    TEST_GET_BOOL_PARAM(wildcard);
    TEST_GET_BOOL_PARAM(force_loop);
    TEST_GET_INT_PARAM(packet_number);

    TEST_STEP("Set EF_MCAST_SEND env to determine loopback mode");
    rc = rpc_getenv_int(pco_iut1, "EF_MCAST_SEND", &ef_mcast_send);
    if (rc != 0)
        ef_mcast_send = 0;

    TEST_STEP("Share socket betwee @p pco_iut1 and @p pco_iut2");
    CHECK_RC(tapi_sh_env_set(pco_iut1, "EF_NAME", "st", TRUE, TRUE));
    CHECK_RC(tapi_sh_env_set(pco_iut2, "EF_NAME", "st", TRUE, TRUE));

    sendbuf = sockts_make_buf_dgram(&buflen);

    memcpy(&wild_addr, mcast_addr, te_sockaddr_get_size(mcast_addr));
    if (wildcard)
        te_sockaddr_set_wildcard(&wild_addr);

    TEST_STEP("Create socket to transmit and receive multicast packets, bind it, "
              "set IP_MULTICAST_IF option and join to the multicast group");
    tx_s = rpc_socket(pco_iut1, rpc_socket_domain_by_addr(mcast_addr),
                      RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);

    rpc_setsockopt_int(pco_iut1, tx_s, RPC_SO_REUSEADDR, 1);
    rpc_bind(pco_iut1, tx_s, &wild_addr);
    set_ip_multicast_if(pco_iut1, tx_s, iut_addr);
    rpc_mcast_join(pco_iut1, tx_s, mcast_addr, iut_if->if_index,
                   TARPC_MCAST_JOIN_LEAVE);

    TEST_STEP("Set IP_MULTICAST_LOOP option to 0 if @p ip_multicast_loop is "
              "@c FALSE");
    if (!ip_multicast_loop)
        rpc_setsockopt_int(pco_iut1, tx_s, RPC_IP_MULTICAST_LOOP, 0);

    TEST_STEP("Set IP_MULTICAST_TTL option to 0 if @p ip_multicast_ttl is "
              "@c FALSE");
    if (!ip_multicast_ttl)
        rpc_setsockopt_int(pco_iut1, tx_s, RPC_IP_MULTICAST_TTL, 0);

    TEST_STEP("Create two sockets on other IUT processes and one on tester, bind "
              "them and join to multicast group to receive packets");
    rx_s1 = create_joined_socket(pco_iut2, iut_if, &wild_addr, mcast_addr, method);
    rx_s2 = create_joined_socket(pco_iut3, iut_if, &wild_addr, mcast_addr, method);
    tst_s = create_joined_socket(pco_tst, tst_if, &wild_addr, mcast_addr, method);

    TEST_STEP("Multicast listener to make sure that packets have accelerated "
              "path");
    listener = mcast_listener_init(pco_iut1, iut_if, mcast_addr, NULL, 0);

    TEST_STEP("Pure linux can drop some packets, but accelerated loopback should "
              "not have such problems.");
    if (force_loop)
        packet_number = 1;

    mcast_listen_start(pco_iut1, listener);

    for (i = 0; i < packet_number; i++)
    {
        TEST_STEP("Send multicast packet");
        rpc_sendto(pco_iut1, tx_s, sendbuf, buflen, 0, mcast_addr);

        TEST_STEP("Check readability and read packets");
        tx_res.got |= read_check_pkt(pco_iut1, tx_s, sendbuf, buflen);
        rx_res[0].got |= read_check_pkt(pco_iut2, rx_s1, sendbuf, buflen);
        rx_res[1].got |= read_check_pkt(pco_iut3, rx_s2, sendbuf, buflen);
        tst_res.got |= read_check_pkt(pco_tst, tst_s, sendbuf, buflen);
    }

    TEST_STEP("Stop multicast listener, check that no packets received");
    if (mcast_listen_stop(pco_iut1, listener, NULL) != 0)
        RING_VERDICT("System detects multicast packets, acceleration is "
                     "not achieved");

    TEST_STEP("Determine expected results in dependence on parameters "
              "combination");
    switch (ef_mcast_send)
    {
        case 0:
            TEST_STEP("No loopback packets should be received   "
                      "if EF_MCAST_SEND is 0 or unspecified");
            break;

        case 1:
            if (ip_multicast_loop)
                rx_res[0].exp = TRUE;
            break;

        case 2:
            if (ip_multicast_ttl)
                rx_res[1].exp = TRUE;
            break;

        case 3:
            if (ip_multicast_loop)
                rx_res[0].exp = TRUE;
            if (ip_multicast_ttl)
                rx_res[1].exp = TRUE;
            break;

        default:
            TEST_FAIL("Unknown EF_MCAST_SEND value");
    }

    if (tx_res.got != rx_res[0].got)
        RING_VERDICT("Two sockets, which share stack, have different "
                     "reading results");
    tx_res.exp = rx_res[0].exp;

    TEST_STEP("Tester should receive packets if ttl > 0");
    if (ip_multicast_ttl)
        tst_res.exp = TRUE;

    if (!force_loop)
        tx_res.exp = rx_res[0].exp = rx_res[1].exp = ip_multicast_loop ?
                                                     TRUE : FALSE;

    TEST_STEP("Compare expected results with actual obtained");
    cmp_exp_results(&tx_res, "Transmitter");
    cmp_exp_results(rx_res, "First receiver");
    cmp_exp_results(rx_res + 1, "Second receiver");
    cmp_exp_results(&tst_res, "Tester receiver");

    TEST_SUCCESS;

cleanup:
    mcast_listener_fini(pco_iut1, listener);

    CLEANUP_RPC_CLOSE(pco_iut1, tx_s);
    CLEANUP_RPC_CLOSE(pco_iut2, rx_s1);
    CLEANUP_RPC_CLOSE(pco_iut3, rx_s2);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    CLEANUP_CHECK_RC(tapi_sh_env_unset(pco_iut1, "EF_MCAST_SEND", TRUE,
                                       FALSE));
    CLEANUP_CHECK_RC(tapi_sh_env_unset(pco_iut1, "EF_NAME", TRUE, TRUE));
    CLEANUP_CHECK_RC(tapi_sh_env_unset(pco_iut2, "EF_NAME", TRUE, FALSE));

    TEST_END;
}
