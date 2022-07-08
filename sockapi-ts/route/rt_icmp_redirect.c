/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Routing table
 * 
 * $Id$
 */

/** @page route-rt_icmp_redirect Affection of ICMP redirect on the routing table
 *
 * @objective Check that ICMP redirect message affects the routing table.
 *
 * @type conformance
 *
 * @param pco_iut     PCO on @p IUT
 * @param pco_tst     PCO on @p TESTER
 * @param gw1_addr    Some network address from the same subnet 
 *                    where @p IUT and @p TESTER attached
 * @param gw2_addr    Some network address from the same subnet 
 *                    where @p IUT and @p TESTER attached
 *                    (different from @p gw1_addr)
 * @param alien_addr  Some network address not assigned to any station that
 *                    takes part in the test
 * @param alien_mac   Some fake MAC address not assigned to any NIC 
 *                    involved in the test
 *
 * @par Test sequence:
 *
 * -# Configure @p TESTER:
 *    - Add @p gw1_addr network address to the network interface attached to
 *      the network with @p IUT;
 *    - Add indirect route to @p alien_addr via gateway @p gw2_addr;
 *    - Add static ARP entry @p gw2_addr -> @p alien_mac;
 *    - Enable forwarding;
 * -# Configure @p IUT:
 *    - Add static ARP entry @p gw1_addr -> MAC address of @p TESTER interface;
 *    - Add indirect route to @p alien_addr via gateway @p gw1_addr;
 *      \n @htmlonly &nbsp; @endhtmlonly
 * -# Create @p SOCK_DGRAM socket @p iut_s on @p pco_iut;
 * -# Send a datagram from @p iut_s socket to @p alien_addr address
 *    (the datagram is sent to @p TESTER that in turn forwards it to
 *     the best router and sends ICMP redirect to the @p IUT that means:
 *     use @p gw2_addr while sending to @p alien_addr);
 *     \n @htmlonly &nbsp; @endhtmlonly
 * -# On @p IUT:
 *    - Delete ARP entry for @p gw1_addr;
 * -# On @p TESTER:
 *    - Delete ARP entry for @p gw2_addr;
 *    - Delete route to @p alien_addr via gateway @p gw2_addr;
 *    - Delete @p gw1_addr network address from the network interface;
 *    - Add @p gw2_addr network address to the network interface;
 *    - Add @p alien_addr network address to the network interface;
 *      \n @htmlonly &nbsp; @endhtmlonly
 * -# Create @p SOCK_DGRAM socket @p tst_s on @p pco_tst and bind it to 
 *    @p alien_addr address;
 * -# Send a datagram from @p iut_s socket to @p alien_addr address
 *    (the datagram should go directly to @p gw2_addr address gateway);
 * -# Check that the datagram is received on @p tst_s socket;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Delete all the routes and ARP entries created in the test;
 * -# Close @p iut_s and @p tst_s sockets.
 * 
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#include <net/ethernet.h>

#define TE_TEST_NAME  "route/rt_icmp_redirect"

#include "ts_route.h"
#include "tapi_route_gw.h"
 
int 
main(int argc, char **argv)
{
    tapi_env_host             *iut_host = NULL;
    rcf_rpc_server            *pco_iut = NULL;
    rcf_rpc_server            *pco_tst = NULL;
    const struct if_nameindex *iut_if = NULL;
    const struct if_nameindex *tst_if = NULL;

    const struct sockaddr *gw1_addr = NULL;
    const struct sockaddr *gw2_addr = NULL;
    const struct sockaddr *alien_addr = NULL;
    const void            *alien_mac = NULL;
    tapi_env_net          *net1;
    
    
    cfg_handle             tst_addr_hndl = CFG_HANDLE_INVALID;
    cfg_handle             alien_addr_hndl = CFG_HANDLE_INVALID;

    cfg_handle             rt_tst_hndl = CFG_HANDLE_INVALID;
    cfg_handle             rt_iut_hndl = CFG_HANDLE_INVALID;
    te_bool                tst_arp_added = FALSE;
    te_bool                iut_arp_added = FALSE;
    
    uint8_t                tst_if_mac[ETHER_ADDR_LEN];
    size_t                 tst_if_mac_len = sizeof(tst_if_mac);

    int                    iut_s = -1;
    int                    tst_s = -1;
    int                    af;
    int                    route_prefix;

    uint8_t buf[10] = { };
    int     buf_len = sizeof(buf);

#if 1
    const struct sockaddr *tst_addr;
    struct sockaddr_in addr_x;
    struct sockaddr_in addr_y;
#endif

    rpc_socket_domain domain;

    TEST_START;
    
    TEST_GET_HOST(iut_host);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    TEST_GET_NET(net1);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);

#if 0
    TEST_GET_ADDR(pco_gw1, gw1_addr);
    TEST_GET_ADDR(pco_gw2, gw2_addr);
#else
    TEST_GET_ADDR(pco_tst, tst_addr);

    memcpy(&addr_x, tst_addr, sizeof(addr_x));
    addr_x.sin_addr.s_addr = htonl((ntohl(addr_x.sin_addr.s_addr) + 10));
    gw1_addr = (struct sockaddr *)&addr_x;

    memcpy(&addr_y, tst_addr, sizeof(addr_y));
    addr_y.sin_addr.s_addr = htonl((ntohl(addr_y.sin_addr.s_addr) + 20));
    gw2_addr = (struct sockaddr *)&addr_y;
#endif

    TEST_GET_ADDR(pco_tst, alien_addr);
    TEST_GET_LINK_ADDR(alien_mac);

    GET_DOMAIN_AF_PREFIX(alien_addr, domain, af, route_prefix);
    
    /* Get hardware adderss of tst_if interface */
    CHECK_RC(tapi_cfg_get_hwaddr(pco_tst->ta, tst_if->if_name,
                                 tst_if_mac, &tst_if_mac_len));


    /* Configure TESTER: */
    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_tst->ta, tst_if->if_name,
                                           gw1_addr, net1->ip4pfx, FALSE,
                                           &tst_addr_hndl));

    if (tapi_cfg_add_route(pco_tst->ta, af, 
            te_sockaddr_get_netaddr(alien_addr), route_prefix,
            te_sockaddr_get_netaddr(gw2_addr), NULL, NULL,
            0, 0, 0, 0, 0, 0, &rt_tst_hndl) != 0)
    {
        TEST_FAIL("Cannot add route to 'alien_addr' via 'gw2_addr'");
    }

    CHECK_RC(tapi_update_arp(pco_tst->ta, tst_if->if_name, NULL, NULL,
                             gw2_addr, CVT_HW_ADDR(alien_mac), TRUE));

    tst_arp_added = TRUE;

    /* Enable forwarding */
    CHECK_RC(tapi_cfg_sys_set_int(pco_tst->ta, 1, NULL,
                                  "net/ipv4/ip_forward"));

    /* Configure IUT: */
    CHECK_RC(tapi_update_arp(pco_iut->ta, iut_if->if_name, NULL, NULL,
                             gw1_addr, tst_if_mac, TRUE));
    iut_arp_added = TRUE;

    if (tapi_cfg_add_route(pco_iut->ta, af, 
            te_sockaddr_get_netaddr(alien_addr), route_prefix,
            te_sockaddr_get_netaddr(gw1_addr), NULL, NULL,
            0, 0, 0, 0, 0, 0, &rt_iut_hndl) != 0)
    {
        TEST_FAIL("Cannot add route to 'alien_addr' via 'gw1_addr'");
    }

    CFG_WAIT_CHANGES;


    /* Create sockets on IUT, TESTER1 & TESTER2 */
    iut_s = rpc_socket(pco_iut, domain, RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    /*
     * Send a datagram from @p iut_s socket to @p alien_addr address
     * (the datagram is sent to @p TESTER that in turn forwards it to
     * the best router and sends ICMP redirect to the @p IUT that means:
     * use @p gw2_addr while sending to @p alien_addr);
     */
    RPC_SENDTO(rc, pco_iut, iut_s, buf, buf_len, 0, alien_addr);

    /* Update configuration on IUT: */
    CHECK_RC(tapi_cfg_del_neigh_entry(pco_iut->ta, iut_if->if_name, gw1_addr));
    iut_arp_added = FALSE;

    /* Update configuration on TESTER */
    CHECK_RC(tapi_cfg_del_neigh_entry(pco_tst->ta, tst_if->if_name, gw2_addr));
    tst_arp_added = FALSE;

    CHECK_RC(tapi_cfg_del_route(&rt_tst_hndl));

    CHECK_RC(cfg_del_instance(tst_addr_hndl, FALSE));
    tst_addr_hndl = CFG_HANDLE_INVALID;

    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_tst->ta, tst_if->if_name,
                                           gw2_addr, net1->ip4pfx, FALSE,
                                           &tst_addr_hndl));

    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_tst->ta, tst_if->if_name,
                                           alien_addr, net1->ip4pfx, FALSE,
                                           &alien_addr_hndl));

    CFG_WAIT_CHANGES;

    /* Create socket on 'pco_tst' */
    tst_s = rpc_socket(pco_tst, domain, RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, alien_addr);


    RPC_SENDTO(rc, pco_iut, iut_s, buf, buf_len, 0, alien_addr);
    
    /* Check that the data is delivered to 'tst_s' */
    RPC_CHECK_READABILITY(pco_tst, tst_s, TRUE);
    rc = rpc_recv(pco_tst, tst_s, buf, buf_len, 0);

    TEST_SUCCESS;

cleanup:

    tapi_cfg_del_route(&rt_tst_hndl);
    tapi_cfg_del_route(&rt_iut_hndl);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    if (alien_addr_hndl != CFG_HANDLE_INVALID)
        cfg_del_instance(alien_addr_hndl, FALSE);
    if (tst_addr_hndl != CFG_HANDLE_INVALID)
        cfg_del_instance(tst_addr_hndl, FALSE);

    if (iut_arp_added)
        tapi_cfg_del_neigh_entry(pco_iut->ta, iut_if->if_name, gw1_addr);

    if (tst_arp_added)
        tapi_cfg_del_neigh_entry(pco_tst->ta, tst_if->if_name, gw2_addr);

    TEST_END;
}
