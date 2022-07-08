/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Routing table
 * 
 * $Id$
 */

/** @page arp-if_scope_check ARP entry interface scope check
 *
 * @objective Add static ARP entry for an IP address for the first
 *            interface. Configure a route to that IP address via the
 *            second interface. Connect TCP socket to the IP address
 *            and check that packets are sent only via the second
 *            interface.
 *
 * @type conformance
 *
 * @param pco_iut     PCO on @p IUT
 * @param pco_tst1    PCO on @p TESTER1
 * @param pco_tst2    PCO on @p TESTER2
 * @param iut_if1     Network interface name on @p IUT physically connected 
 *                    with @p TESTER1
 * @param iut_if2     Network interface name on @p IUT physically connected 
 *                    with @p TESTER2
 * @param alien_addr  Some network address not assigned to any station that 
 *                    takes part in the test
 *
 * @note The test assumes that @p iut_if1 (@p iut_if2) has network address 
 *       that from the same subnetwork as the address assigned to the 
 *       interface of @p TESTER1 (@p TESTER2).
 *
 * @par Test sequence:
 *
 * -# Add @p alien_addr network address to the interface of @p TESTER1 that
 *    is attached to the same subnetwork as @p iut_if1;
 * -# Add @p alien_addr network address to the interface of @p TESTER2 that
 *    is attached to the same subnetwork as @p iut_if2;
 * -# Start waiting for ARP traffic on @p tst2_if interface;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Add direct route to @p alien_addr via iut_if1 interface on @p pco_iut;
 * -# Add static ARP entry for @p alien_addr (it belongs to @p iut_if1
 *    interface);
 * -# Delete direct route to @p alien_addr via iut_if1 interface on @p
 *    pco_iut;
 * -# Add direct route to @p alien_addr via iut_if2 interface on @p
 *    pco_iut;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Start capturing any traffic on @p tst1_if interface;
 * -# Create @p SOCK_STREAM socket @p iut_s on @p pco_iut;
 * -# Create @p SOCK_STREAM socket @p tst_s on @p pco_tst2 and 
 *    bind it to @p alien_addr;
 * -# Call @b listen() on @p tst_s socket.
 * -# Call @b connect() on @p iut_s socket.
 * -# Call @b accept() on @p tst_s socket. @p acc_s socket should appear.
 * -# Check that @p iut_s and @p acc_s sockets are connected.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Check that there was no traffic generated from @p iut_if1 interface
 *    (there should be no Ethernet frames received on @p tst1_if interface);
 * -# Check that there was ARP request;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Delete all the routes;
 * -# Close @p iut_s, @p tst_s and @p acc_s sockets;
 * -# Remove @p alien_addr network address from @p TESTER1 and @p TESTER2.
 * 
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "arp/if_scope_check"

#include <net/ethernet.h>

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "tapi_cfg_base.h"
#include "tapi_eth.h"
#include "tapi_arp.h"
#include "tapi_route_gw.h"

int 
main(int argc, char **argv)
{
    rcf_rpc_server            *pco_iut = NULL;
    rcf_rpc_server            *pco_tst1 = NULL;
    rcf_rpc_server            *pco_tst2 = NULL;
    const struct if_nameindex *iut_if1;
    const struct if_nameindex *iut_if2;
    const struct if_nameindex *tst1_if;
    const struct if_nameindex *tst2_if;
    
    const struct sockaddr *alien_addr;
    tapi_env_net          *net1;

    const struct sockaddr *tst1_hwaddr = NULL;
    
    cfg_handle             tst1_addr_hndl = CFG_HANDLE_INVALID;
    cfg_handle             tst2_addr_hndl = CFG_HANDLE_INVALID;
    cfg_handle             rt_hndl = CFG_HANDLE_INVALID;

    uint8_t                iut_if_mac1[ETHER_ADDR_LEN];
    size_t                 iut_if_mac1_len = sizeof(iut_if_mac1);
    uint8_t                iut_if_mac2[ETHER_ADDR_LEN];
    size_t                 iut_if_mac2_len = sizeof(iut_if_mac2);

    asn_value             *pkt_pattern1 = NULL;
    asn_value             *pkt_pattern2 = NULL;
    csap_handle_t          tst_csap1;
    te_bool                tst_csap1_created = FALSE;
    csap_handle_t          tst_csap2;
    te_bool                tst_csap2_created = FALSE;
    
    int                    iut_s = -1;
    int                    tst_s = -1;
    int                    acc_s = -1;
    int                    af;
    int                    route_prefix;

    unsigned int           pkt_nums1 = 0;
    unsigned int           pkt_nums2 = 0;

    rpc_socket_domain domain;

    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);

    TEST_GET_NET(net1);
    TEST_GET_IF(iut_if1);
    TEST_GET_IF(iut_if2);
    TEST_GET_IF(tst1_if);
    TEST_GET_IF(tst2_if);

    TEST_GET_ADDR(pco_iut, alien_addr);
    TEST_GET_LINK_ADDR(tst1_hwaddr);

    domain = rpc_socket_domain_by_addr(alien_addr);

    af = addr_family_rpc2h(sockts_domain2family(domain));
    route_prefix = te_netaddr_get_size(addr_family_rpc2h(
                       sockts_domain2family(domain))) * 8;

    /*
     * Remove ARP table entries for @p alien_addr on IUT,
     * if they are present.
     */
    CHECK_RC(tapi_cfg_del_neigh_entry(pco_iut->ta, iut_if1->if_name,
                                      alien_addr));
    CHECK_RC(tapi_cfg_del_neigh_entry(pco_iut->ta, iut_if2->if_name,
                                      alien_addr));

    /* Add alien_addr to TESTER1 and TESTER2 */
    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_tst1->ta, tst1_if->if_name,
                                           alien_addr, net1->ip4pfx, FALSE,
                                           &tst1_addr_hndl));
    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_tst2->ta, tst2_if->if_name,
                                           alien_addr, net1->ip4pfx, FALSE,
                                           &tst2_addr_hndl));

    /* Get hardware addresses of iut_if1 and iut_if2 interfaces */
    CHECK_RC(tapi_cfg_get_hwaddr(pco_iut->ta, iut_if1->if_name,
                                 iut_if_mac1, &iut_if_mac1_len));
    CHECK_RC(tapi_cfg_get_hwaddr(pco_iut->ta, iut_if2->if_name,
                                 iut_if_mac2, &iut_if_mac2_len));

    /*
     * Create Ethernet CSAP on TESTER2 to check that IUT sends
     * the ARP requests. We do this before adding routes because
     * Onload can send request when a route is added.
     */
    CHECK_RC(tapi_arp_eth_csap_create_ip4(pco_tst2->ta, 0, tst2_if->if_name,
                                          (TAD_ETH_RECV_DEF &
                                           ~TAD_ETH_RECV_OTHER) |
                                          TAD_ETH_RECV_NO_PROMISC,
                                          iut_if_mac2, NULL, &tst_csap2));
    tst_csap2_created = TRUE;

    {
        uint16_t opcode = ARPOP_REQUEST;
        uint8_t  bcast_mac[ETHER_ADDR_LEN];

        memset(bcast_mac, 0xff, sizeof(bcast_mac));

        CHECK_RC(tapi_arp_add_pdu_eth_ip4(&pkt_pattern2, TRUE,
                      &opcode, iut_if_mac2, NULL, NULL, NULL));
        CHECK_RC(tapi_eth_add_pdu(&pkt_pattern2, NULL, TRUE,
                                  NULL, iut_if_mac2, NULL,
                                  TE_BOOL3_ANY /* tagged/untagged */,
                                  TE_BOOL3_ANY /* Ethernet2/LLC */));
    }

    CHECK_RC(tapi_tad_trrecv_start(pco_tst2->ta, 0, tst_csap2, pkt_pattern2,
                                   TAD_TIMEOUT_INF, 0, RCF_TRRECV_PACKETS));

    /* Add direct route to 'alien_addr' via 'iut_if1' interface on IUT */
    if (tapi_cfg_add_route(pco_iut->ta, af,
            te_sockaddr_get_netaddr(alien_addr), route_prefix,
            NULL, iut_if1->if_name, NULL,
            0, 0, 0, 0, 0, 0, &rt_hndl) != 0)
    {
        TEST_FAIL("Cannot add route to 'alien_addr' via 'iut_if1'");
    }
    CFG_WAIT_CHANGES;

    /* Add static ARP entry */
    CHECK_RC(tapi_update_arp(pco_iut->ta, iut_if1->if_name, NULL, NULL,
                             alien_addr, CVT_HW_ADDR(tst1_hwaddr), TRUE));

    CFG_WAIT_CHANGES;

    /* Delete direct route to 'alien_addr' via 'iut_if1' interface on IUT */
    if (tapi_cfg_del_route(&rt_hndl) != 0)
    {
        TEST_FAIL("Failed to delete route");    
    }
    CFG_WAIT_CHANGES;
    rt_hndl = CFG_HANDLE_INVALID;
    
    /* Add direct route to 'alien_addr' via 'iut_if2' interface on IUT */
    if (tapi_cfg_add_route(pco_iut->ta, af, 
            te_sockaddr_get_netaddr(alien_addr), route_prefix,
            NULL, iut_if2->if_name, NULL,
            0, 0, 0, 0, 0, 0, &rt_hndl) != 0)
    {
        TEST_FAIL("Cannot add route to 'alien_addr' via 'iut_if2'");
    }
    CFG_WAIT_CHANGES;

    /* Create Ethernet CSAP on TESTER1 to check that IUT sends nothing */
    CHECK_RC(tapi_eth_csap_create(pco_tst1->ta, 0, tst1_if->if_name,
                                  TAD_ETH_RECV_DEF |
                                  TAD_ETH_RECV_NO_PROMISC,
                                  iut_if_mac1, NULL, NULL, &tst_csap1));
    tst_csap1_created = TRUE;
                         
    CHECK_RC(tapi_eth_add_pdu(&pkt_pattern1, NULL, TRUE, NULL, NULL, NULL,
                              TE_BOOL3_ANY /* tagged/untagged */,
                              TE_BOOL3_ANY /* Ethernet2/LLC */));
    
    CHECK_RC(tapi_tad_trrecv_start(pco_tst1->ta, 0, tst_csap1, pkt_pattern1,
                                   TAD_TIMEOUT_INF, 0, RCF_TRRECV_PACKETS));

    /* Create connection between IUT and TESTER2 */
    iut_s = rpc_socket(pco_iut, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
        
    tst_s = rpc_socket(pco_tst2, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_tst2, tst_s, alien_addr);

    rpc_listen(pco_tst2, tst_s, SOCKTS_BACKLOG_DEF);

    rpc_connect(pco_iut, iut_s, alien_addr);

    acc_s = rpc_accept(pco_tst2, tst_s, NULL, NULL);

    CHECK_SOCKET_STATE(pco_iut, iut_s, pco_tst2, acc_s,
                       STATE_CONNECTED);
    
    /* Check number of recieved packets */

    /* For the first CSAP */
    CHECK_RC(rcf_ta_trrecv_stop(pco_tst1->ta, 0, tst_csap1,
                                NULL, NULL, &pkt_nums1));
    if (pkt_nums1 != 0)
    {
        TEST_FAIL("TESTER1 (Agent %s) recieved some traffic from IUT ",
                  pco_tst1->ta);
    }
    
    /* For the second CSAP */
    CHECK_RC(tapi_tad_trrecv_stop(pco_tst2->ta, 0, tst_csap2, NULL,
                                  &pkt_nums2));
    if (pkt_nums2 != 1)
    {
        TEST_FAIL("IUT sends %d ARP requests but expected 1", pkt_nums2);
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst2, tst_s);
    CLEANUP_RPC_CLOSE(pco_tst2, acc_s);

    if (tst_csap1_created)
        tapi_tad_csap_destroy(pco_tst1->ta, 0, tst_csap1);
    if (tst_csap2_created)
        tapi_tad_csap_destroy(pco_tst2->ta, 0, tst_csap2);
    
    if (rt_hndl != CFG_HANDLE_INVALID)
        cfg_del_instance(rt_hndl, FALSE);
    
    if (tst1_addr_hndl != CFG_HANDLE_INVALID)
        cfg_del_instance(tst1_addr_hndl, FALSE);
    if (tst2_addr_hndl != CFG_HANDLE_INVALID)
        cfg_del_instance(tst2_addr_hndl, FALSE);
    
    if (pco_iut != NULL && alien_addr != NULL)
        CLEANUP_CHECK_RC(tapi_cfg_del_neigh_entry(pco_iut->ta, 
                                                  iut_if1->if_name, 
                                                  alien_addr));

    CFG_WAIT_CHANGES;

    TEST_END;
}
