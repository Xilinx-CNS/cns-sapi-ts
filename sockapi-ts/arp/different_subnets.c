/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * ARP table
 *
 * $Id$
 */

/** @page arp-different_subnets ARP entries for hosts from different subnets in ARP table
 *
 * @objective Check that different subnets handled correctly
 *
 * @type conformance
 *
 * @reference @ref COMER chapter 5
 *
 * @param iut_host        IUT host
 * @param tester_1        The first Tester host
 * @param tester_2        The second Tester host
 * @param pco_iut         PCO on IUT on @p iut_host
 * @param pco_tst1        PCO on TESTER on @p tester_1
 * @param pco_tst2        PCO on TESTER on @p tester_2
 * @param iut_if1         Network interface on IUT connecting it
 *                        with the first tester host
 * @param iut_if2         Network interface on IUT connecting it
 *                        with the second tester host
 * @param tst1_if         Network interface on the first Tester host
 * @param tst2_if         Network interface on the second Tester host
 * @param iut_addr1       IP address assigned to @p iut_if1
 * @param tst1_addr       IP address assigned to @p tst1_if
 * @param iut_addr2       IP address assigned to @p iut_if2
 * @param tst2_addr       IP address assigned to @p tst2_if
 * @param sock_type       @c SOCK_STREAM or @c SOCK_DGRAM
 *
 * @par Test sequence:
 * -# Add @p iut_alias_addr alias address on @p iut_if1,
 *    add @p tst1_alias_addr alias address on @p tst1_if,
 *    @p iut_alias_addr and @p tst1_alias_addr are from
 *    the same network;
 * -# Launch Ethernet sniffers on @p tester_1 and @p tester_2;
 * -# Add static @p tst1_addr ARP entry on @p iut_host ARP table;
 * -# Add static @p tst2_addr ARP entry on @p iut_host ARP table;
 * -# Add static @p tst1_alias_addr ARP entry on @p iut_host ARP table;
 * -# Initiate @p sock_type connection between
 *    @p pco_iut and @p pco_tst1,
 *    using @p pco_iut as client, using @p iut_addr1 and
 *    @p tst1_addr;
 * -# Initiate @p sock_type connection between
 *    @p pco_iut and @p pco_tst1,
 *    using @p pco_iut as client, using @p iut_alias_addr and
 *    @p tst1_alias_addr;
 * -# Initiate @p sock_type connection between
 *    @p pco_iut and @p pco_tst2,
 *    using @p pco_iut as client, using @p iut_addr2 and
 *    @p tst2_addr;
 * -# Stop Ethernet sniffers, check that no ARP request was issued
 *    by @p pco_iut;
 *
 * @author Renata Sayakhova <Renata.Sayakhova@oktetlabs.ru>
 */

#define TE_TEST_NAME    "arp/different_subnets"

#include "sockapi-test.h"
#include "arp_test_macros.h"
#include "arp_send_recv.h"
#include "tapi_route_gw.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server            *pco_iut = NULL;
    rcf_rpc_server            *pco_tst1 = NULL;
    rcf_rpc_server            *pco_tst2 = NULL;

    const struct if_nameindex *iut_if1 = NULL;
    const struct if_nameindex *iut_if2 = NULL;
    const struct if_nameindex *tst1_if = NULL;
    const struct if_nameindex *tst2_if = NULL;

    tapi_env_host         *iut_host = NULL;
    tapi_env_host         *tester_1 = NULL;
    tapi_env_net          *net1 = NULL;

    const struct sockaddr *iut_addr1 = NULL;
    const struct sockaddr *iut_addr2 = NULL;
    const struct sockaddr *tst1_addr = NULL;
    const struct sockaddr *tst2_addr = NULL;
    struct sockaddr       *iut_alias_addr = NULL;
    struct sockaddr       *tst1_alias_addr = NULL;

    tapi_cfg_net_assigned  net_handle = {CFG_HANDLE_INVALID, NULL};

    const struct sockaddr *tst1_hwaddr = NULL;
    const struct sockaddr *tst2_hwaddr = NULL;

    csap_handle_t          handle1 = CSAP_INVALID_HANDLE;
    csap_handle_t          handle2 = CSAP_INVALID_HANDLE;
    csap_handle_t          handle3 = CSAP_INVALID_HANDLE;
    unsigned int           arp_packets;

    rpc_socket_type        sock_type;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);

    TEST_GET_NET(net1);
    TEST_GET_HOST(iut_host);
    TEST_GET_HOST(tester_1);

    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_ADDR(pco_tst1, tst1_addr);
    TEST_GET_ADDR(pco_tst2, tst2_addr);

    TEST_GET_LINK_ADDR(tst1_hwaddr);
    TEST_GET_LINK_ADDR(tst2_hwaddr);

    TEST_GET_IF(iut_if1);
    TEST_GET_IF(iut_if2);
    TEST_GET_IF(tst1_if);
    TEST_GET_IF(tst2_if);

    TEST_GET_SOCK_TYPE(sock_type);

    CHECK_RC(tapi_cfg_net_assign_ip(AF_INET, net1->cfg_net, &net_handle));
    CHECK_RC(tapi_env_get_net_host_addr(&env, net1, iut_host, AF_INET,
                                        &net_handle, &iut_alias_addr, NULL));

    CHECK_RC(tapi_env_get_net_host_addr(&env, net1, tester_1, AF_INET,
                                        &net_handle, &tst1_alias_addr, NULL));

    START_ARP_FILTER_WITH_HDR(pco_tst1->ta, tst1_if->if_name,
                              NULL,
                              mac_broadcast,
                              ARPOP_REQUEST,
                              TAD_ETH_RECV_DEF | TAD_ETH_RECV_NO_PROMISC,
                              CVT_PROTO_ADDR(tst1_addr), NULL,
                              CVT_PROTO_ADDR(iut_addr1), NULL,
                              0, handle1);

    START_ARP_FILTER_WITH_HDR(pco_tst2->ta, tst2_if->if_name,
                              NULL,
                              mac_broadcast,
                              ARPOP_REQUEST,
                              TAD_ETH_RECV_DEF | TAD_ETH_RECV_NO_PROMISC,
                              CVT_PROTO_ADDR(tst2_addr), NULL,
                              CVT_PROTO_ADDR(iut_addr2), NULL,
                              0, handle2);

    START_ARP_FILTER_WITH_HDR(pco_tst1->ta, tst1_if->if_name,
                              NULL,
                              mac_broadcast,
                              ARPOP_REQUEST,
                              TAD_ETH_RECV_DEF | TAD_ETH_RECV_NO_PROMISC,
                              CVT_PROTO_ADDR(tst1_alias_addr), NULL,
                              CVT_PROTO_ADDR(iut_alias_addr), NULL,
                              0, handle3);

    CHECK_RC(tapi_update_arp(pco_iut->ta, iut_if1->if_name, NULL, NULL,
                             tst1_addr, CVT_HW_ADDR(tst1_hwaddr), TRUE));
    CHECK_RC(tapi_update_arp(pco_iut->ta, iut_if2->if_name, NULL, NULL,
                             tst2_addr, CVT_HW_ADDR(tst2_hwaddr), TRUE));
    CHECK_RC(tapi_update_arp(pco_iut->ta, iut_if1->if_name, NULL, NULL,
                             tst1_alias_addr, CVT_HW_ADDR(tst1_hwaddr), TRUE));

    CFG_WAIT_CHANGES;

    TEST_PROVOKE_ARP_REQ(pco_tst1, pco_iut, sock_type,
                         tst1_addr, iut_addr1, TRUE);
    TEST_PROVOKE_ARP_REQ(pco_tst1, pco_iut, sock_type,
                         tst1_alias_addr, iut_alias_addr, TRUE);
    TEST_PROVOKE_ARP_REQ(pco_tst2, pco_iut, sock_type,
                         tst2_addr, iut_addr2, TRUE);

    STOP_ETH_FILTER(pco_tst1->ta, handle1, arp_packets);
    if (arp_packets != 0)
    {
        TEST_FAIL("ARP filter on tester_1 caught %d arp requests, "
                  "expected to catch none of them");
    }

    STOP_ETH_FILTER(pco_tst1->ta, handle3, arp_packets);
    if (arp_packets != 0)
    {
        TEST_FAIL("ARP filter on tester_2 caught %d arp requests, "
                  "expected to catch none of them");
    }

   STOP_ETH_FILTER(pco_tst2->ta, handle2, arp_packets);
    if (arp_packets != 0)
    {
        TEST_FAIL("ARP filter on tester_2 caught %d arp requests, "
                  "expected to catch none of them");
    }
    TEST_SUCCESS;

cleanup:
    if (pco_tst1 != NULL)
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst1->ta, 0, handle1));
    if (pco_tst2 != NULL)
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst2->ta, 0, handle2));
    TEST_END;
}
