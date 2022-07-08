/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 *
 *
 * $Id$
 */

/** @page arp-no_outgoing_traffic Local communication between two sockets
 *
 * @objective Create two sockets on the same host and bind them to
 *            addresses of different interfaces. Send a packet from
 *            one socket to another one. Check that nothing is
 *            sent to network.
 *
  * @type conformance
 *
 * @param sock_type       @c SOCK_DGRAM or @c SOCK_STREAM
 * @param pco_iut         PCO on IUT on iut_host
 * @param pco_tst1        PCO on TESTER on tst1_host
 * @param pco_tst2        PCO on TESTER on tst2_host
 *
 * @par Test sequence:
 * -# Create @p iut1_s socket of @p sock_type on @p pco_iut;
 * -# @b bind() @p iut1_s socket to the @p iut_addr1;
 * -# Create @p iut2_s socket of @p sock_type on @p pco_iut;
 * -# @b bind() @p iut2_s socket to the @p iut_addr2;
 * -# In the case of @c SOCK_STREAM socket type call @b listen()
 *    on @p iut2_s socket;
 * -# Run filters on @p pco_tst1 and @p pco_tst2 to catch possible
 *    traffic;
 * -# In case of:
 *    - @c SOCK_STREAM socket type call @b connect() on @p iut1_s
 *      socket to @p iut_addr2;
 *    - @c SOCK_DGRAM socket type call @b sendto() on @p iut1_s
 *      socket to @p iut_addr2;
 * -# In case of:
 *    - @c SOCK_STREAM socket type call @b accept() on @p iut2_s
 *      socket;
 *    - @c SOCK_DGRAM socket type call @b recv() on @p iut2_s
 *      socket;
 * -# Stop filters catching traffic and check the absence of
 *    of any traffic on wires;
 * -# Close all involved sockets and free allocated resources.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "arp/no_outgoing_traffic"

#include "sockapi-test.h"
#include "tapi_tad.h"
#include "tapi_tcp.h"
#include "tapi_cfg.h"
#include "tapi_cfg_base.h"
#include "arp_test_macros.h"
#include "arp_send_recv.h"

#define TST_BUF_LEN           1024

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst1 = NULL;
    rcf_rpc_server        *pco_tst2 = NULL;

    int                    iut1_s = -1;
    int                    iut2_s = -1;
    int                    acc_s = -1;

    const struct sockaddr   *iut_addr1 = NULL;
    const struct sockaddr   *iut_addr2 = NULL;

    const struct if_nameindex  *tst1_if = NULL;
    const struct if_nameindex  *tst2_if = NULL;

    void     *tx_buf;
    void     *rx_buf;

    rpc_socket_type     sock_type;
    rpc_socket_domain   domain;

    csap_handle_t       arp_tst1_handle = CSAP_INVALID_HANDLE;
    csap_handle_t       arp_tst2_handle = CSAP_INVALID_HANDLE;
    csap_handle_t       ip_catch1_csap = CSAP_INVALID_HANDLE;
    csap_handle_t       ip_catch2_csap = CSAP_INVALID_HANDLE;

    unsigned int        arp_tst1_packets;
    unsigned int        arp_tst2_packets;
    unsigned int        ip1_pkts;
    unsigned int        ip2_pkts;

    TEST_START;
    TEST_GET_SOCK_TYPE(sock_type);

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);

    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_ADDR(pco_iut, iut_addr2);

    TEST_GET_IF(tst1_if);
    TEST_GET_IF(tst2_if);

    tx_buf = te_make_buf_by_len(TST_BUF_LEN);
    rx_buf = te_make_buf_by_len(TST_BUF_LEN);

    CHECK_RC(tapi_cfg_del_neigh_dynamic(pco_iut->ta, NULL));

    domain = rpc_socket_domain_by_addr(iut_addr1);

    /* Create server on pco_iut listen on iut2_s */
    iut2_s = rpc_socket(pco_iut, domain, sock_type, RPC_PROTO_DEF);
    rpc_bind(pco_iut, iut2_s, iut_addr2);
    if (sock_type == RPC_SOCK_STREAM)
        rpc_listen(pco_iut, iut2_s, SOCKTS_BACKLOG_DEF);

    iut1_s = rpc_socket(pco_iut, domain, sock_type, RPC_PROTO_DEF);
    rpc_bind(pco_iut, iut1_s, iut_addr1);

    /*
     * Try catch some ARP activity on wires of both:
     * 'iut1_if - tst1_if' and 'iut2_if - tst2_if'
     */
    START_ARP_FILTER_WITH_HDR(pco_tst1->ta, tst1_if->if_name,
                              NULL, NULL,
                              ARPOP_REQUEST,
                              TAD_ETH_RECV_DEF | TAD_ETH_RECV_NO_PROMISC,
                              NULL, NULL,
                              CVT_PROTO_ADDR(iut_addr2),  NULL,
                              0, arp_tst1_handle);

    START_ARP_FILTER_WITH_HDR(pco_tst2->ta, tst2_if->if_name,
                              NULL, NULL,
                              ARPOP_REQUEST,
                              TAD_ETH_RECV_DEF | TAD_ETH_RECV_NO_PROMISC,
                              NULL, NULL,
                              CVT_PROTO_ADDR(iut_addr2),  NULL,
                              0, arp_tst2_handle);
    /*
     * Try catch some TCP/IP activity on wires of both:
     * 'iut1_if - tst1_if' and 'iut2_if - tst2_if'
     */
    CHECK_RC(tapi_ip4_eth_csap_create(pco_tst1->ta, 0, tst1_if->if_name,
                                      TAD_ETH_RECV_DEF |
                                      TAD_ETH_RECV_NO_PROMISC,
                                      NULL, NULL, INADDR_ANY,
                                      SIN(iut_addr2)->sin_addr.s_addr,
                                      -1, &ip_catch1_csap));
    CHECK_RC(tapi_tad_trrecv_start(pco_tst1->ta, 0, ip_catch1_csap, NULL,
                                   TAD_TIMEOUT_INF, 0, RCF_TRRECV_PACKETS));

    CHECK_RC(tapi_ip4_eth_csap_create(pco_tst2->ta, 0, tst2_if->if_name,
                                      TAD_ETH_RECV_DEF |
                                      TAD_ETH_RECV_NO_PROMISC,
                                      NULL, NULL, INADDR_ANY,
                                      SIN(iut_addr2)->sin_addr.s_addr,
                                      -1, &ip_catch2_csap));
    CHECK_RC(tapi_tad_trrecv_start(pco_tst2->ta, 0, ip_catch2_csap, NULL,
                                   TAD_TIMEOUT_INF, 0, RCF_TRRECV_PACKETS));

    if (sock_type == RPC_SOCK_STREAM)
        rpc_connect(pco_iut, iut1_s, iut_addr2);
    else
        rc = rpc_sendto(pco_iut, iut1_s, tx_buf, TST_BUF_LEN,
                        0, iut_addr2);

    if (sock_type == RPC_SOCK_STREAM)
    {
        acc_s = rpc_accept(pco_iut, iut2_s, NULL, NULL);
    }
    else
    {
        rc = rpc_recv(pco_iut, iut2_s, rx_buf, TST_BUF_LEN, 0);
    }

    STOP_ETH_FILTER(pco_tst1->ta, arp_tst1_handle, arp_tst1_packets);

    STOP_ETH_FILTER(pco_tst2->ta, arp_tst2_handle, arp_tst2_packets);

    CHECK_RC(tapi_tad_trrecv_stop(pco_tst1->ta, 0, ip_catch1_csap,
                                  NULL, &ip1_pkts));

    CHECK_RC(tapi_tad_trrecv_stop(pco_tst2->ta, 0, ip_catch2_csap,
                                  NULL, &ip2_pkts));

    if (arp_tst1_packets != 0)
        TEST_FAIL("%d: ARP filter on 'pco_tst1' caught %d packets, "
                  "expected to catch none of them",
                  __LINE__, arp_tst1_packets);

    if (arp_tst2_packets != 0)
        TEST_FAIL("%d: ARP filter on 'pco_tst2' caught %d packets, "
                  "expected to catch none of them",
                  __LINE__, arp_tst2_packets);

    if (ip1_pkts != 0)
        TEST_FAIL("%d: TCP filter on 'pco_tst1' caught %d packets, "
                  "expected to catch none of them",
                  __LINE__, ip1_pkts);

    if (ip2_pkts != 0)
        TEST_FAIL("%d: TCP filter on 'pco_tst2' caught %d packets, "
                  "expected to catch none of them",
                  __LINE__, ip2_pkts);

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut1_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut2_s);
    CLEANUP_RPC_CLOSE(pco_iut, acc_s);

    if (pco_tst1 != NULL)
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst1->ta, 0,
                                             arp_tst1_handle));
    if (pco_tst2 != NULL)
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst2->ta, 0,
                                             arp_tst2_handle));

    if (pco_tst1 != NULL)
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst1->ta, 0,
                                             ip_catch1_csap));
    if (pco_tst2 != NULL)
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst2->ta, 0,
                                             ip_catch2_csap));

    free(tx_buf);
    free(rx_buf);
    TEST_END;
}
