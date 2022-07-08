/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite. Control Plane.
 *
 * $Id$
 */

/** @page arp-new_broadcast_arp  ARP resolution uses changed hardware broadcast address for processing
 *
 * @objective Check that after changing hardware broadcast address of
 *            outgoing interface it is used for arp resolution.
 *
 * @type conformance
 *
 * @param pco_iut         PCO on IUT
 * @param pco_tst         PCO on Tester
 * @param iut_addr        Network address on IUT
 * @param tst_addr        Network address on Tester
 * @param iut_lladdr      Ethernet address on IUT
 * @param tst_lladdr      Ethernet address on Tester
 * @param iut_if          Network interface name on IUT
 * @param tst_if          Network interface name on Tester
 * @param hw_broadcast    New hardware broadcast address to be set
 *                        to linked interfaces of both
 *                        IUT and Tester
 * @par Scenario:
 *
 * -# Set new @p hw_broadcast  hardware broadcast address to linked
 *    interfaces of both IUT and Tester;
 * -# Create @p iut_s socket of the @c SOCK_STREAM type on the IUT;
 * -# Create @p tst_s socket of the @c SOCK_STREAM type on the Tester;
 * -# @b bind() @p tst_s socket to the local address/port (Tester
 *    interface);
 * -# Call @b listen() on the @p tst_s socket;
 * -# @b bind() @p iut_s socket to the local address/port (IUT
 *    interface);
 * -# Delete ARP entries on both IUT and Tester for corresponding
 *    addresses;
 * -# Try @b connect() @p iut_s socket to the @p tst_s;
 * -# Check that @p hw_broadcast address is used for ARP resolution;
 * -# Check that @c SOCK_STREAM type connection is established successfully;
 * -# Close opened sockets and release allocated resources.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#include "te_config.h"
#define TE_TEST_NAME    "arp/new_broadcast_arp"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "tapi_cfg_base.h"
#include "arp_test_macros.h"
#include "arp_send_recv.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server            *pco_iut = NULL;
    rcf_rpc_server            *pco_tst = NULL;

    const struct if_nameindex *iut_if = NULL;
    const struct if_nameindex *tst_if = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    struct sockaddr         cache_hwaddr;

    int                    iut_s = -1;
    int                    tst_s = -1;

    const char            *hw_broadcast = NULL;
    uint8_t                bcast_hwaddr [ETHER_ADDR_LEN] = { 0, };
    const struct sockaddr *iut_lladdr = NULL;
    const struct sockaddr *tst_lladdr = NULL;

    csap_handle_t          arp_catcher = CSAP_INVALID_HANDLE;
    csap_handle_t          ip_catcher = CSAP_INVALID_HANDLE;
    unsigned int           arp_frames = 0;
    unsigned int           ip_frames = 0;
    int                    arp_flags;
    te_bool                arp_entry_exist;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_LINK_ADDR(iut_lladdr);
    TEST_GET_LINK_ADDR(tst_lladdr);
    TEST_GET_STRING_PARAM(hw_broadcast);

    /*
     * Convert hardware address provided in ascii (XX:XX:XX:XX:XX:XX) to
     * binary presentation
     */
    rc = lladdr_a2n(hw_broadcast, bcast_hwaddr, ETHER_ADDR_LEN);
    if (rc == -1)
        TEST_FAIL("%s():%u: lladdr_a2n failed", __FUNCTION__, __LINE__);

    /*
     * Set new link layer broadcast addresses to interfaces of pco_iut
     * and pco_tst
     */

    CHECK_RC(tapi_cfg_base_if_down(pco_iut->ta, iut_if->if_name));
    CHECK_RC(tapi_cfg_base_if_down(pco_tst->ta, tst_if->if_name));
    CFG_WAIT_CHANGES;

    CHECK_RC(tapi_cfg_set_bcast_hwaddr(pco_iut->ta, iut_if->if_name,
                                       bcast_hwaddr, ETHER_ADDR_LEN));
    CHECK_RC(tapi_cfg_set_bcast_hwaddr(pco_tst->ta, tst_if->if_name,
                                       bcast_hwaddr, ETHER_ADDR_LEN));

    CHECK_RC(tapi_cfg_base_if_up(pco_iut->ta, iut_if->if_name));
    CHECK_RC(tapi_cfg_base_if_up(pco_tst->ta, tst_if->if_name));

    CHECK_RC(sockts_wait_for_if_up(pco_iut, iut_if->if_name));
    CHECK_RC(sockts_wait_for_if_up(pco_tst, tst_if->if_name));
    CFG_WAIT_CHANGES;

    /*
     * Prepare client (iut_s) and server (tst_s) sockets for new
     * connection establishing
     */
    iut_s = rpc_socket(pco_iut, RPC_AF_INET, RPC_SOCK_STREAM, RPC_PROTO_DEF);

    tst_s = rpc_socket(pco_tst, RPC_AF_INET, RPC_SOCK_STREAM, RPC_PROTO_DEF);

    rpc_bind(pco_iut, iut_s, iut_addr);

    rpc_bind(pco_tst, tst_s, tst_addr);

    rpc_listen(pco_tst, tst_s, SOCKTS_BACKLOG_DEF);

    /*
     * Remove appropriate ARP entries on pco_iut and pco_tst to provoke
     * ARP resolution procedure
     */
    CHECK_RC(tapi_cfg_del_neigh_entry(pco_iut->ta, iut_if->if_name,
                                      tst_addr));
    CHECK_RC(tapi_cfg_del_neigh_entry(pco_tst->ta, tst_if->if_name,
                                      iut_addr));
    CFG_WAIT_CHANGES;

    /* ARP response catcher */
    START_ARP_FILTER_WITH_HDR(pco_tst->ta, tst_if->if_name,
                              CVT_HW_ADDR(iut_lladdr), bcast_hwaddr,
                              ARPOP_REQUEST,
                              TAD_ETH_RECV_DEF,
                              CVT_PROTO_ADDR(iut_addr),
                              CVT_HW_ADDR(iut_lladdr),
                              CVT_PROTO_ADDR(tst_addr), NULL,
                              0, arp_catcher);

    /* IP packet catcher */
    START_ETH_FILTER(pco_tst->ta, tst_if->if_name,
                     (TAD_ETH_RECV_DEF & ~TAD_ETH_RECV_OTHER) |
                     TAD_ETH_RECV_NO_PROMISC,
                     CVT_HW_ADDR(iut_lladdr), CVT_HW_ADDR(tst_lladdr),
                     ETHERTYPE_IP,
                     0, ip_catcher);

    rpc_connect(pco_iut, iut_s, tst_addr);

    TAPI_WAIT_NETWORK;

    /* Stop ARP catcher on TST side */
    STOP_ETH_FILTER(pco_tst->ta, arp_catcher, arp_frames);

    /* Stop IP catcher on TST side */
    STOP_ETH_FILTER(pco_tst->ta, ip_catcher, ip_frames);

    /* Check the absence of ARP requests */
    if (arp_frames == 0)
        TEST_FAIL("Test waits for IUT side ARP request with changed hardware"
                  "broadcast interface address but it is absent");

    if (ip_frames == 0)
        TEST_FAIL("Test waits for IUT side IP packets but these are absent");

    TEST_GET_ARP_ENTRY(pco_tst, iut_addr, tst_if->if_name,
                       &cache_hwaddr, arp_flags, arp_entry_exist);
    if ((arp_entry_exist == FALSE) || !(arp_flags & ATF_COM))
    {
        TEST_FAIL("Failed to get ARP entry on TST "
                  "(it's expected to have got dynamic ARP entry)");
    }

    if (memcmp(CVT_HW_ADDR(iut_lladdr), cache_hwaddr.sa_data,
               ETHER_ADDR_LEN) != 0)
        TEST_FAIL("ARP cache entry with unexpected LL address");

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
