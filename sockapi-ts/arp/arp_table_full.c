/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * ARP table
 *
 * $Id$
 */

/** @page arp-arp_table_full Fill ARP table with many entries, check whether this disrupts network traffic
 *
 * @objective Create a connected pair of sockets on IUT and Tester.
 *            Start sending data from IUT to Tester. While this is
 *            being done, fill ARP table on IUT with a lot of entries
 *            by sending many ARP requests to IUT from different
 *            addresses. After that check that data sent from IUT
 *            can be received on Tester (or, in case of UDP, not
 *            too many packets are lost).
 *
 * @type conformance
 *
 * @reference @ref COMER, chapter 5
 *
 * @param pco_iut           PCO on IUT
 * @param pco_tst           PCO on TESTER
 * @param iut_addr          Network address on IUT
 * @param tst_addr          Network address on Tester
 * @param net               Network to which host addresses belong
 * @param iut_if            Network interface on IUT
 * @param tst_if            Network interface on Tester
 * @param num_of_req        Number of ARP requests to be sent to @p pco_iut
 * @param sock_type         @c SOCK_DGRAM or @c SOCK_STREAM
 *
 * @par Test sequence:
 * -# If there is @p tst_addr ARP entry in IUT,
 *    delete it;
 * -# Create @p client_addr_list - @p num_of_req IP addresses
 *    from network @p net mapped to MAC addresses;
 * -# Initiate @p sock_type connection between @p pco_iut and @p pco_tst,
 *    using @p pco_iut as client;
 * -# Send traffic from @p pco_iut to @p pco_tst in background
 *    using the connection;
 * -# Create and launch @p arp_request_sender
 *    ARP request sender on Tester.
 *    This sender generate ARP request
 *    for @p iut_addr for each mapping from
 *    @p client_addr_list, using these addresses as sender
 *    IP and MAC addresses;
 * -# Waiting for traffic completion. Check that number of bytes sent
 *    is equal to number of bytes received;
 * -# Once again send/receive traffic using the connection;
 *    Check that number of bytes sent is equal to them of received and
 *    that it is not equal to zero;
 *    This step is requered because traffic
 *    sending/receiving may finish before
 *    something is broken by receiving many ARP requests.
 *
 * @author Renata Sayakhova <Renata.Sayakhova@oktetlabs.ru>
 */
#define TE_TEST_NAME "arp/arp_table_full"

#include "sockapi-test.h"
#include "arp_test_macros.h"
#include "arp_send_recv.h"


int
main(int argc, char *argv[])
{
    tapi_env_net   *net = NULL;
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    int                     sock_type;

    const struct if_nameindex  *iut_if = NULL;
    const struct if_nameindex  *tst_if = NULL;

    proto2hw_addr_map *fake_addr_list = NULL;
    int                req_nums;

    int iut_s = -1;
    int tst_s = -1;

    uint64_t  received = 0;
    uint64_t  sent     = 0;

    /* Preambule */
    TEST_START;

    TEST_GET_NET(net);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);

    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_INT_PARAM(req_nums);

    /* Scenario */
    CHECK_RC(tapi_cfg_del_neigh_entry(pco_iut->ta, iut_if->if_name,
                                      tst_addr));
    CHECK_RC(tapi_cfg_del_neigh_dynamic(pco_iut->ta, NULL));

    CFG_WAIT_CHANGES;

    GENERATE_MAP_LIST(net, req_nums, fake_addr_list, TRUE, FALSE);

    GEN_CONNECTION(pco_tst, pco_iut, sock_type, RPC_PROTO_DEF,
                   tst_addr, iut_addr, &tst_s, &iut_s);

    pco_tst->op = RCF_RPC_CALL;
    rpc_simple_receiver(pco_tst, tst_s, 0, &received);
    pco_iut->op = RCF_RPC_CALL;
    rpc_simple_sender(pco_iut, iut_s, 1, 10, 0, 0, 10000, 1, 20, &sent, 0);

    START_ARP_SENDER(pco_tst->ta, tst_if->if_name, NULL, NULL,
                     ARPOP_REQUEST, NULL, NULL,
                     CVT_PROTO_ADDR(iut_addr), NULL,
                     req_nums, fake_addr_list);

    rpc_simple_sender(pco_iut, iut_s, 1, 10, 0, 0, 10000, 1, 20, &sent, 0);
    rpc_simple_receiver(pco_tst, tst_s, 0, &received);
    TEST_CHECK_PKTS_LOST((sock_type == SOCK_DGRAM) ? TRUE : FALSE,
                         sent, received);

    /* Call once again sender and receiver */
    pco_tst->op = RCF_RPC_CALL;
    rpc_simple_receiver(pco_tst, tst_s, 0, &received);
    rpc_simple_sender(pco_iut, iut_s, 1, 10, 0, 0, 10000, 1, 20, &sent, 0);
    rpc_simple_receiver(pco_tst, tst_s, 0, &received);
    TEST_CHECK_PKTS_LOST((sock_type == SOCK_DGRAM) ? TRUE : FALSE,
                         sent, received);
    if (sent == 0)
        TEST_FAIL("%d: Number of bytes sent is 0", __LINE__);

    TEST_SUCCESS;

cleanup:
    if (fake_addr_list != NULL)
        free(fake_addr_list);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    sockts_restart_if(pco_iut, iut_if->if_name);

    TEST_END;
}
